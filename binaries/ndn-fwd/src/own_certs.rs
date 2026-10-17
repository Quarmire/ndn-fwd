//! Serve this node's own certificates by name.
//!
//! A validator that meets Data this node signed follows its KeyLocator to a
//! certificate name and fetches that certificate. The namespace CA serves
//! every certificate it issued, but only where routing reaches the CA; by NDN
//! convention a producer also makes its own certificate retrievable, so a
//! relay that routes a device's prefix toward the device resolves the chain
//! there as well. This serves, on one in-process face with a FIB entry per
//! certificate name:
//!
//! - every issued certificate the PIB stores beside a key
//!   (`keys/*/cert.data`, what `ndn-fwd enroll` stores), and one that
//!   `security/enroll` adds while the daemon runs;
//! - on the root device, the CA's and the device's certificates
//!   (`ca/ca-cert.data`, `ca/device-cert.data`, written by `ndn-fwd init`).
//!
//! A certificate that a held trust context revokes is not served, and is
//! withdrawn once a context version revoking it is adopted.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, PoisonError, RwLock};

use bytes::Bytes;
use ndn_app::Producer;
use ndn_engine::ForwarderEngine;
use ndn_face::local::InProcFace;
use ndn_packet::{Data, Interest, NackReason, Name};
use ndn_security::{FilePib, Keyring};
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

/// The certificates this node serves, by Data name.
pub(crate) struct OwnCertificates {
    engine: ForwarderEngine,
    face_id: FaceId,
    certs: RwLock<HashMap<Name, Bytes>>,
}

impl OwnCertificates {
    /// Serve the certificates stored in `pib` (none without a PIB) that
    /// `keyring` does not revoke, now and as long as `cancel` runs, and
    /// withdraw each one a context adopted later revokes.
    pub(crate) fn spawn(
        engine: &ForwarderEngine,
        pib: Option<&FilePib>,
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
        for wire in pib.map(stored_certificates).unwrap_or_default() {
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

    /// Serve the certificate Data `wire` from now on.
    pub(crate) fn serve(&self, wire: Bytes) {
        let name = match Data::decode(wire.clone()) {
            Ok(cert) => (*cert.name).clone(),
            Err(e) => {
                tracing::warn!(target: "security", error = %e, "not serving an undecodable certificate");
                return;
            }
        };
        self.engine.fib().add_nexthop(&name, self.face_id, 0);
        tracing::info!(target: "security", certificate = %name, "serving this node's certificate");
        self.certs
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(name, wire);
    }

    fn withdraw_where(&self, revoked: impl Fn(&Name) -> bool) {
        let mut certs = self.certs.write().unwrap_or_else(PoisonError::into_inner);
        certs.retain(|name, _| {
            if !revoked(name) {
                return true;
            }
            self.engine.fib().remove_nexthop(name, self.face_id);
            tracing::info!(
                target: "security",
                certificate = %name,
                "revoked: no longer serving this node's certificate"
            );
            false
        });
    }

    /// The certificate `interest` asks for: by exact name, or with
    /// CanBePrefix any certificate under it.
    fn answer(&self, interest: &Interest) -> Option<Bytes> {
        let certs = self.certs.read().unwrap_or_else(PoisonError::into_inner);
        if let Some(wire) = certs.get(interest.name.as_ref()) {
            return Some(wire.clone());
        }
        if !interest.selectors().can_be_prefix {
            return None;
        }
        certs
            .iter()
            .find(|(name, _)| name.has_prefix(&interest.name))
            .map(|(_, wire)| wire.clone())
    }
}

/// The certificate Data the PIB at `pib` stores: one per key holding an
/// issued certificate, plus a root device's CA and device certificates.
fn stored_certificates(pib: &FilePib) -> Vec<Bytes> {
    let mut certs: Vec<Bytes> = pib
        .list_keys()
        .unwrap_or_default()
        .iter()
        .filter_map(|key| pib.get_issued_cert(key).ok().flatten())
        .collect();
    let ca_dir = pib.root().join("ca");
    for file in ["ca-cert.data", "device-cert.data"] {
        if let Some(wire) = read_if_present(&ca_dir.join(file)) {
            certs.push(wire);
        }
    }
    certs
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
        let own = OwnCertificates::spawn(&engine, Some(pib), keyring, cancel.child_token());
        (engine, shutdown, own)
    }

    async fn fetch(engine: &ForwarderEngine, name: &Name, cancel: &CancellationToken) -> Option<Bytes> {
        engine
            .app_consumer(cancel.child_token())
            .fetch_with(InterestBuilder::new(name.clone()).lifetime(Duration::from_millis(500)))
            .await
            .ok()
            .map(|d| d.raw().clone())
    }

    /// A node serves the certificates its PIB holds by name, and never one
    /// that a trust context it holds revokes: withdrawn on adopting the
    /// version that revokes it, and not served again after a restart.
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

        let (engine, shutdown, _own) = node(&pib, &keyring, &cancel).await;
        assert_eq!(fetch(&engine, &ns.device_key, &cancel).await, Some(device_cert));
        assert_eq!(fetch(&engine, &ns.ca_key, &cancel).await, Some(ca_cert.clone()));

        let bump = ndn_cert::bump_context_revoking(&pib, &ns.init.context_data, &[ns.device_key.clone()])
            .unwrap()
            .expect("a new version");
        keyring.adopt_update(Arc::new(bump.context)).unwrap();
        assert_eq!(fetch(&engine, &ns.device_key, &cancel).await, None, "withdrawn");
        assert_eq!(fetch(&engine, &ns.ca_key, &cancel).await, Some(ca_cert.clone()));
        shutdown.shutdown().await;

        let (restarted, shutdown, _own) = node(&pib, &keyring, &cancel).await;
        assert_eq!(fetch(&restarted, &ns.device_key, &cancel).await, None, "not served at start");
        assert_eq!(fetch(&restarted, &ns.ca_key, &cancel).await, Some(ca_cert));
        cancel.cancel();
        shutdown.shutdown().await;
    }
}
