//! Serve this node's own certificates.
//!
//! A validator that meets Data this node signed follows its KeyLocator (the
//! key name, `/<id>/KEY/<key-id>`) and fetches the newest valid certificate
//! under it with CanBePrefix. The namespace CA serves every certificate it
//! issued, but only where routing reaches the CA; by NDN convention a
//! producer also makes its own certificate retrievable, so a relay that
//! routes a device's prefix toward the device resolves the chain there as
//! well. This serves, on one in-process face with a FIB entry per key name:
//!
//! - every valid certificate the PIB stores beside a key
//!   (`keys/*/certs/`, what `ndn-fwd enroll` stores), and one that
//!   `security/enroll` or a renewal ([`crate::renewal`]) adds while the
//!   daemon runs (a renewed certificate has its own name, so the old one
//!   stays retrievable by name while the key name resolves to the new one);
//! - on the root device, the CA's and the device's certificates
//!   (`ca/ca-cert.data`, `ca/device-cert.data`, written by `ndn-fwd init`);
//! - every valid certificate the engine's key store caches for the key this
//!   node signs with, PIB-backed or not: an ephemeral identity (no PIB)
//!   serves its self-signed certificate, so a verifier resolves its
//!   KeyLocator by fetching it here.
//!
//! An Interest naming one certificate exactly gets that certificate; a
//! CanBePrefix Interest gets the newest valid certificate under its name
//! (else the newest one, so an expired certificate reads as expired rather
//! than missing). A certificate that a held trust context revokes (its key,
//! or the certificate itself) is not served, and is withdrawn once a context
//! version revoking it is adopted.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, PoisonError, RwLock};

use bytes::Bytes;
use ndn_app::Producer;
use ndn_engine::ForwarderEngine;
use ndn_face::local::InProcFace;
use ndn_packet::{Data, Interest, NackReason, Name};
use ndn_security::cert_name::key_name_of;
use ndn_security::{Certificate, FilePib, Keyring, SecurityManager};
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

/// The certificates this node serves, by certificate name.
pub(crate) struct OwnCertificates {
    engine: ForwarderEngine,
    face_id: FaceId,
    certs: RwLock<HashMap<Name, Served>>,
}

struct Served {
    cert: Certificate,
    wire: Bytes,
}

impl OwnCertificates {
    /// Serve the certificates stored in `pib` (none without a PIB) and the
    /// ones the engine's key store caches for `signing_key` (the key the node
    /// signs with) that `keyring` does not revoke, now and as long as
    /// `cancel` runs, and withdraw each one a context adopted later revokes.
    pub(crate) fn spawn(
        engine: &ForwarderEngine,
        pib: Option<&FilePib>,
        signing_key: Option<&Name>,
        keyring: &Keyring,
        cancel: CancellationToken,
    ) -> Arc<Self> {
        let face_id = engine.faces().alloc_id();
        let (face, handle) = InProcFace::new(face_id, 64);
        engine.add_face(face, cancel);
        let own = Arc::new(Self {
            engine: engine.clone(),
            face_id,
            certs: RwLock::new(HashMap::new()),
        });
        let running = signing_key
            .zip(engine.security())
            .map(|(key, mgr)| running_certificates(&mgr, key))
            .unwrap_or_default();
        for wire in pib.map(stored_certificates).unwrap_or_default().into_iter().chain(running) {
            match Data::decode(wire.clone()) {
                Ok(cert) if keyring.context_for(&cert.name).is_revoked(&cert.name) => {
                    tracing::info!(
                        target: "security",
                        certificate = %cert.name,
                        "not serving a certificate the held trust context revokes"
                    );
                }
                Ok(_) => own.serve(wire),
                Err(e) => tracing::warn!(
                    target: "security",
                    error = %e,
                    "not serving an undecodable stored certificate"
                ),
            }
        }
        let weak = Arc::downgrade(&own);
        keyring.on_revocation(move |ctx, _| {
            if let Some(own) = weak.upgrade() {
                own.withdraw_where(|name| ctx.is_revoked(name));
            }
        });
        let served = Arc::downgrade(&own);
        let producer = Producer::from_handle(handle, Name::root());
        tokio::spawn(async move {
            let result = producer
                .serve(|interest, responder| {
                    let reply = served.upgrade().and_then(|own| own.answer(&interest));
                    async move {
                        let _ = match reply {
                            Some(wire) => responder.respond_bytes(wire).await,
                            None => responder.nack(NackReason::NoRoute).await,
                        };
                    }
                })
                .await;
            if let Err(e) = result {
                tracing::error!(target: "security", error = %e, "certificate server exited");
            }
        });
        own
    }

    /// Serve the certificate Data `wire` from now on, beside the other
    /// certificates of its key.
    pub(crate) fn serve(&self, wire: Bytes) {
        let cert = match Data::decode(wire.clone())
            .map_err(|e| e.to_string())
            .and_then(|data| Certificate::decode(&data).map_err(|e| e.to_string()))
        {
            Ok(cert) => cert,
            Err(e) => {
                tracing::warn!(target: "security", error = %e, "not serving an undecodable certificate");
                return;
            }
        };
        let name = (*cert.name).clone();
        self.engine
            .fib()
            .add_nexthop(&key_name_of(&name), self.face_id, 0);
        tracing::info!(target: "security", certificate = %name, "serving this node's certificate");
        self.certs
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(name, Served { cert, wire });
    }

    fn withdraw_where(&self, revoked: impl Fn(&Name) -> bool) {
        let mut certs = self.certs.write().unwrap_or_else(PoisonError::into_inner);
        let mut withdrawn = Vec::new();
        certs.retain(|name, _| {
            if !revoked(name) {
                return true;
            }
            tracing::info!(
                target: "security",
                certificate = %name,
                "revoked: no longer serving this node's certificate"
            );
            withdrawn.push(key_name_of(name));
            false
        });
        for key in withdrawn {
            if !certs.keys().any(|name| key_name_of(name) == key) {
                self.engine.fib().remove_nexthop(&key, self.face_id);
            }
        }
    }

    /// The certificate `interest` asks for: by exact name, or with
    /// CanBePrefix the newest valid certificate under it (else the newest).
    fn answer(&self, interest: &Interest) -> Option<Bytes> {
        let certs = self.certs.read().unwrap_or_else(PoisonError::into_inner);
        if let Some(served) = certs.get(interest.name.as_ref()) {
            return Some(served.wire.clone());
        }
        if !interest.selectors().can_be_prefix {
            return None;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        certs
            .iter()
            .filter(|(name, _)| name.has_prefix(&interest.name))
            .max_by(|(a, x), (b, y)| {
                (x.cert.is_valid_at(now), x.cert.valid_from, *a)
                    .cmp(&(y.cert.is_valid_at(now), y.cert.valid_from, *b))
            })
            .map(|(_, served)| served.wire.clone())
    }
}

/// The certificate Data the PIB at `pib` stores: every valid certificate of
/// each key, plus a root device's CA and device certificates.
fn stored_certificates(pib: &FilePib) -> Vec<Bytes> {
    let mut certs: Vec<Bytes> = pib
        .list_keys()
        .unwrap_or_default()
        .iter()
        .flat_map(|key| pib.valid_cert_wires(key).unwrap_or_default())
        .collect();
    let ca_dir = pib.root().join("ca");
    for file in ["ca-cert.data", "device-cert.data"] {
        if let Some(wire) = read_if_present(&ca_dir.join(file)) {
            certs.push(wire);
        }
    }
    certs
}

/// The certificate Data the engine's key store caches for `key`: every
/// valid one (an ephemeral identity's self-signed certificate, or one
/// issued for a PIB key).
fn running_certificates(mgr: &SecurityManager, key: &Name) -> Vec<Bytes> {
    mgr.cert_cache()
        .all(key)
        .iter()
        .filter(|cert| cert.is_valid_now())
        .filter_map(Certificate::data_wire)
        .collect()
}

fn read_if_present(path: &Path) -> Option<Bytes> {
    match std::fs::read(path) {
        Ok(bytes) => Some(Bytes::from(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            tracing::warn!(
                target: "security",
                path = %path.display(),
                error = %e,
                "cannot read a stored certificate to serve"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ndn_app::{EngineAppExt, ShutdownHandle};
    use ndn_engine::{EngineBuilder, EngineConfig};
    use ndn_packet::encode::InterestBuilder;
    use ndn_security::{CertCache, SecurityProfile, Validator};

    use super::*;

    /// An engine whose validator dispatches against `keyring` (as the
    /// daemon's does), serving the certificates in `pib`.
    async fn node(
        pib: &FilePib,
        keyring: &Arc<Keyring>,
        cancel: &CancellationToken,
    ) -> (ForwarderEngine, ShutdownHandle, Arc<OwnCertificates>) {
        let validator = Validator::with_keyring(
            Arc::clone(keyring),
            Arc::new(CertCache::new()),
            None,
            5,
        );
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .security_profile(SecurityProfile::Custom(Arc::new(validator)))
            .build()
            .await
            .unwrap();
        // Answers come from the server, not the content store.
        engine.cs().set_serve(false);
        let own = OwnCertificates::spawn(&engine, Some(pib), None, keyring, cancel.child_token());
        (engine, shutdown, own)
    }

    /// Fetch `name`; `by_key` sends CanBePrefix (how a verifier resolves a
    /// key-name KeyLocator).
    async fn fetch_as(
        engine: &ForwarderEngine,
        name: &Name,
        by_key: bool,
        cancel: &CancellationToken,
    ) -> Option<Bytes> {
        let mut interest = InterestBuilder::new(name.clone()).lifetime(Duration::from_millis(500));
        if by_key {
            interest = interest.can_be_prefix();
        }
        engine
            .app_consumer(cancel.child_token())
            .fetch_with(interest)
            .await
            .ok()
            .map(|d| d.raw().clone())
    }

    async fn fetch(engine: &ForwarderEngine, key: &Name, cancel: &CancellationToken) -> Option<Bytes> {
        fetch_as(engine, key, true, cancel).await
    }

    /// A node serves the certificates its PIB holds, by certificate name and
    /// by key name (the newest valid one: a renewed certificate wins while
    /// the old stays retrievable by its name), and never one that a trust
    /// context it holds revokes: every certificate of a revoked key is
    /// withdrawn on adopting the version that revokes it, and not served
    /// again after a restart.
    #[tokio::test]
    async fn serves_its_certificates_but_never_a_revoked_one() {
        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        let ns = ndn_cert::init_namespace_in_pib(&pib, &"/home/bob".parse().unwrap(), "desk", false)
            .unwrap();
        let device_cert = Bytes::from(std::fs::read(&ns.device_cert_path).unwrap());
        let ca_cert = Bytes::from(std::fs::read(&ns.ca_cert_path).unwrap());
        let keyring = Arc::new(Keyring::new());
        ndn_cert::load_persisted_contexts(dir.path(), &keyring).unwrap();
        let cancel = CancellationToken::new();

        let (engine, shutdown, own) = node(&pib, &keyring, &cancel).await;
        assert_eq!(fetch(&engine, &ns.device_key, &cancel).await, Some(device_cert.clone()));
        assert_eq!(fetch(&engine, &ns.ca_key, &cancel).await, Some(ca_cert.clone()));
        assert_eq!(
            fetch_as(&engine, &ns.device_cert.name, false, &cancel).await,
            Some(device_cert.clone()),
            "by its certificate name"
        );
        assert_eq!(fetch_as(&engine, &ns.device_key, false, &cancel).await, None, "a key is not a certificate");

        // A renewal: a second certificate of the device key, issued later.
        let device_pub = pib.get_signer(&ns.device_key).unwrap().public_key().unwrap();
        let ca_signer = pib.get_signer(&ns.ca_key).unwrap();
        let renewed_name =
            ndn_security::cert_name::new_cert_name(&ns.device_key, ndn_security::cert_name::NDNCERT_ISSUER);
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let renewed = ndn_security::encode_cert_data(
            &renewed_name,
            &device_pub,
            ca_signer.as_ref(),
            now_ns,
            now_ns + 3_600_000_000_000,
        )
        .await
        .unwrap();
        own.serve(renewed.clone());
        assert_eq!(fetch(&engine, &ns.device_key, &cancel).await, Some(renewed.clone()), "newest wins");
        assert_eq!(
            fetch_as(&engine, &ns.device_cert.name, false, &cancel).await,
            Some(device_cert),
            "the old certificate stays retrievable by name"
        );
        let bump = ndn_cert::bump_context_revoking(&pib, &ns.init.context_data, &[ns.device_key.clone()])
            .unwrap()
            .expect("a new version");
        keyring.adopt_update(Arc::new(bump.context)).unwrap();
        assert_eq!(fetch(&engine, &ns.device_key, &cancel).await, None, "withdrawn");
        assert_eq!(fetch_as(&engine, &renewed_name, false, &cancel).await, None, "every certificate of the key");
        assert_eq!(fetch(&engine, &ns.ca_key, &cancel).await, Some(ca_cert.clone()));
        shutdown.shutdown().await;

        let (restarted, shutdown, _own) = node(&pib, &keyring, &cancel).await;
        assert_eq!(fetch(&restarted, &ns.device_key, &cancel).await, None, "not served at start");
        assert_eq!(fetch(&restarted, &ns.ca_key, &cancel).await, Some(ca_cert));
        cancel.cancel();
        shutdown.shutdown().await;
    }

    /// An ephemeral identity (no PIB) serves the self-signed certificate of
    /// the key it signs with: a CanBePrefix fetch of the key name — how a
    /// verifier resolves its KeyLocator — returns it.
    #[tokio::test]
    async fn an_ephemeral_identity_serves_its_certificate() {
        let kc = ndn_security::KeyChain::ephemeral_ecdsa("/lab/eph").unwrap();
        let mgr = kc.manager_arc();
        let keyring = Arc::clone(mgr.keyring());
        let validator =
            Validator::with_keyring(Arc::clone(&keyring), Arc::new(CertCache::new()), None, 5);
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .security(mgr)
            .security_profile(SecurityProfile::Custom(Arc::new(validator)))
            .build()
            .await
            .unwrap();
        engine.cs().set_serve(false);
        let cancel = CancellationToken::new();
        let _own = OwnCertificates::spawn(&engine, None, Some(kc.key_name()), &keyring, cancel.child_token());

        let served = fetch(&engine, kc.key_name(), &cancel).await.expect("served by key name");
        let cert_name = kc.cert_name().expect("a self-signed certificate");
        assert_eq!(*Data::decode(served).unwrap().name, cert_name);
        cancel.cancel();
        shutdown.shutdown().await;
    }
}
