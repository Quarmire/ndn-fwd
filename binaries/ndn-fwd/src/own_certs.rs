//! Serve this node's own certificates: [`ndn_namespace::publish::OwnCertificates`]
//! over what the PIB stores —
//!
//! - every valid certificate the PIB stores beside a key (`keys/*/certs/`,
//!   what `ndn-fwd enroll` stores);
//! - on the root device, the CA's and the device's certificates
//!   (`ca/ca-cert.data`, `ca/device-cert.data`, written by `ndn-fwd init`);
//! - the issuer certificates of this node's certificates, kept at
//!   enrollment and renewal (`issuers/`, [`ndn_cert::issuers`]);
//!
//! and every valid certificate the engine's key store caches for the key
//! this node signs with (an ephemeral identity has no PIB).

use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use ndn_engine::ForwarderEngine;
use ndn_packet::Name;
use ndn_security::{FilePib, Keyring};
use tokio_util::sync::CancellationToken;

pub(crate) use ndn_namespace::publish::OwnCertificates;

/// Serve the certificates stored in `pib` (none without a PIB) and the
/// ones the engine's key store caches for `signing_key`, as
/// [`OwnCertificates::spawn`] does.
pub(crate) fn spawn(
    engine: &ForwarderEngine,
    pib: Option<&FilePib>,
    signing_key: Option<&Name>,
    keyring: &Keyring,
    cancel: CancellationToken,
) -> Arc<OwnCertificates> {
    let stored = pib.map(stored_certificates).unwrap_or_default();
    OwnCertificates::spawn(engine, stored, signing_key, keyring, cancel)
}

/// The certificate Data the PIB at `pib` stores: every valid certificate of
/// each key, a root device's CA and device certificates, and the issuer
/// certificates kept beside the PIB.
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
    certs.extend(ndn_cert::issuers::stored_issuer_certs(pib.root()));
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
    use ndn_packet::Data;
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
        let own = spawn(&engine, Some(pib), None, keyring, cancel.child_token());
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
        let ns = ndn_cert::init_namespace_in_pib(
            &pib,
            &"/home/bob".parse().unwrap(),
            "desk",
            false,
            &ndn_cert::NewRootStore::File,
        )
        .await
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
        let root = ndn_cert::RootStore::open(&pib).unwrap().unwrap();
        let root = root.signer(None).await.unwrap();
        let bump = ndn_cert::bump_context_revoking(
            root.as_ref(),
            &ns.init.context_data,
            &[ns.device_key.clone()],
        )
        .await
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
        let _own = spawn(&engine, None, Some(kc.key_name()), &keyring, cancel.child_token());

        let served = fetch(&engine, kc.key_name(), &cancel).await.expect("served by key name");
        let cert_name = kc.cert_name().expect("a self-signed certificate");
        assert_eq!(*Data::decode(served).unwrap().name, cert_name);
        cancel.cancel();
        shutdown.shutdown().await;
    }
}
