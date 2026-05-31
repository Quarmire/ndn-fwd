//! Dashboard-held operator signing keyring — the "gate on provisioned key".
//!
//! This is where the dashboard begins holding its OWN signing identity instead
//! of delegating all key custody to the forwarder. When an operator key is
//! provisioned here, mgmt commands are signed through a [`CustodianSigner`]
//! backed by an in-page custodian; until then [`command_signer`] is `None` and
//! the client falls back to `DigestSha256` (today's behaviour) — that fallback
//! is the gate.
//!
//! v1 holds a single Ed25519 operator key in an [`InPageCustodian`]. OS-keyring
//! / fob custodians plug into the same seam (build a different `CustodianSigner`
//! over a different `Custodian`). The provisioning *source* — depositing the
//! key from a decrypted SafeBag or an enrollment — is the remaining wire-up;
//! [`provision_ed25519`] is its single entry point.
//
// `provision_ed25519` / `is_provisioned` are the provisioning + status entry
// points, not yet called by a live source (SafeBag/enrollment deposit is the
// next wire-up); and the whole module is unused on the web build, whose command
// path is `WsMgmtClient`, not `MgmtClient`. Both are exercised by the unit test.
#![allow(dead_code)]

use std::sync::{Arc, OnceLock, RwLock};

use bytes::Bytes;
use ndn_custodian::{CustodianSigner, InPageCustodian, KeyId};
use ndn_packet::{Name, SignatureType};
use ndn_security::{Ed25519Signer, Signer};

struct OperatorKeyring {
    custodian: Arc<InPageCustodian>,
    /// The provisioned key's id + public key, or `None` (gate closed).
    active: RwLock<Option<(KeyId, Bytes)>>,
}

fn keyring() -> &'static OperatorKeyring {
    static K: OnceLock<OperatorKeyring> = OnceLock::new();
    K.get_or_init(|| OperatorKeyring {
        custodian: Arc::new(InPageCustodian::new()),
        active: RwLock::new(None),
    })
}

/// Provision the operator's Ed25519 signing key into the dashboard-held
/// custodian. After this the gate opens: [`command_signer`] returns a signer
/// and mgmt commands carry the operator's signature instead of `DigestSha256`.
pub fn provision_ed25519(key_name: Name, seed: &[u8; 32]) {
    let kr = keyring();
    let signer = Ed25519Signer::from_seed(seed, key_name.clone());
    let pk = Bytes::copy_from_slice(&signer.public_key_bytes());
    let key_id = KeyId(key_name);
    kr.custodian.insert(key_id.clone(), signer);
    *kr.active.write().expect("operator keyring lock") = Some((key_id, pk));
}

/// Whether an operator key is provisioned (the gate is open).
pub fn is_provisioned() -> bool {
    keyring()
        .active
        .read()
        .expect("operator keyring lock")
        .is_some()
}

/// The mgmt-command signer when an operator key is provisioned, else `None`
/// (the client then signs `DigestSha256`, as today).
pub fn command_signer() -> Option<Arc<dyn Signer>> {
    let kr = keyring();
    let guard = kr.active.read().expect("operator keyring lock");
    let (key_id, pk) = guard.as_ref()?;
    Some(Arc::new(CustodianSigner::new(
        kr.custodian.clone(),
        key_id.clone(),
        SignatureType::SignatureEd25519,
        Some(pk.clone()),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_opens_after_provisioning() {
        // Note: keyring() is process-global; this test owns provisioning in
        // this binary's test run.
        assert!(
            command_signer().is_none(),
            "gate closed before provisioning"
        );
        let name: Name = "/op/dash/KEY/k1".parse().unwrap();
        provision_ed25519(name.clone(), &[5u8; 32]);
        assert!(is_provisioned());
        let signer = command_signer().expect("gate open after provisioning");
        assert_eq!(signer.sig_type(), SignatureType::SignatureEd25519);
        assert_eq!(signer.key_name().to_string(), "/op/dash/KEY/k1");
    }
}
