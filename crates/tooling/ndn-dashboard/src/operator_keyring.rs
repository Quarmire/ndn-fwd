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
use ndn_security::{EcdsaP256Signer, Ed25519Signer, Signer};

/// The provisioned key's id + signature metadata (gate open), or `None`.
struct Active {
    key_id: KeyId,
    /// Operator certificate name, advertised in the command KeyLocator so the
    /// forwarder can resolve the signing cert to its trust anchor.
    cert_name: Option<Name>,
    sig_type: SignatureType,
    public_key: Option<Bytes>,
}

struct OperatorKeyring {
    custodian: Arc<InPageCustodian>,
    active: RwLock<Option<Active>>,
}

fn keyring() -> &'static OperatorKeyring {
    static K: OnceLock<OperatorKeyring> = OnceLock::new();
    K.get_or_init(|| OperatorKeyring {
        custodian: Arc::new(InPageCustodian::new()),
        active: RwLock::new(None),
    })
}

/// Core: hold `signer` as the operator key and open the gate. The signature
/// metadata is read off the signer, so any algorithm works (Ed25519, ECDSA).
fn provision_signer(key_name: Name, cert_name: Option<Name>, signer: Arc<dyn Signer>) {
    let kr = keyring();
    let sig_type = signer.sig_type();
    let public_key = signer.public_key();
    let key_id = KeyId(key_name);
    kr.custodian.insert_signer(key_id.clone(), signer);
    *kr.active.write().expect("operator keyring lock") = Some(Active {
        key_id,
        cert_name,
        sig_type,
        public_key,
    });
}

/// Provision a freshly-seeded Ed25519 operator key (used by tests / generate).
pub fn provision_ed25519(key_name: Name, seed: &[u8; 32]) {
    provision_signer(
        key_name.clone(),
        None,
        Arc::new(Ed25519Signer::from_seed(seed, key_name)),
    );
}

/// Provision from a decrypted **Ed25519** PKCS#8 key — a SafeBag the operator
/// imported (the dashboard decrypts it in-browser).
///
/// OS-keyring / fob / remote custodians are *not* fed this way — their key
/// never enters the dashboard; they would `insert_signer` a delegating
/// custodian into the registry instead, once those impls are functional.
pub fn provision_ed25519_pkcs8(
    key_name: Name,
    cert_name: Option<Name>,
    pkcs8_der: &[u8],
) -> Result<(), String> {
    let signer = Ed25519Signer::from_pkcs8_der(pkcs8_der, key_name.clone())
        .map_err(|e| format!("operator key load (ed25519): {e}"))?;
    provision_signer(key_name, cert_name, Arc::new(signer));
    Ok(())
}

/// Provision from a decrypted **ECDSA P-256** PKCS#8 key (the other algorithm a
/// SafeBag can carry).
pub fn provision_ecdsa_p256_pkcs8(
    key_name: Name,
    cert_name: Option<Name>,
    pkcs8_der: &[u8],
) -> Result<(), String> {
    let signer = EcdsaP256Signer::from_pkcs8_der(pkcs8_der, key_name.clone())
        .map_err(|e| format!("operator key load (ecdsa-p256): {e}"))?;
    provision_signer(key_name, cert_name, Arc::new(signer));
    Ok(())
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
    let active = guard.as_ref()?;
    let mut signer = CustodianSigner::new(
        kr.custodian.clone(),
        active.key_id.clone(),
        active.sig_type,
        active.public_key.clone(),
    );
    if let Some(cert_name) = active.cert_name.clone() {
        signer = signer.with_cert_name(cert_name);
    }
    Some(Arc::new(signer))
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test (not several) because keyring() is process-global — separate
    // #[test]s would race on it. Steps run sequentially here.
    #[test]
    fn gate_opens_after_provisioning() {
        // Ed25519 opens the gate with the Ed25519 sig type.
        let name: Name = "/op/dash/KEY/k1".parse().unwrap();
        provision_ed25519(name.clone(), &[5u8; 32]);
        assert!(is_provisioned());
        let signer = command_signer().expect("gate open after ed25519");
        assert_eq!(signer.sig_type(), SignatureType::SignatureEd25519);
        assert_eq!(signer.key_name().to_string(), "/op/dash/KEY/k1");

        // An ECDSA P-256 key (via PKCS#8) opens it with the ECDSA sig type —
        // proving the keyring is algorithm-agnostic, not Ed25519-only.
        let ec_name: Name = "/op/dash/KEY/ec".parse().unwrap();
        let ec = ndn_security::EcdsaP256Signer::from_seed(&[6u8; 32], ec_name.clone())
            .expect("ecdsa key");
        let pkcs8 = ec.to_pkcs8_der().expect("ecdsa pkcs8");
        // Provision with a cert name and confirm it surfaces as the signer's
        // cert_name (which the mgmt client uses for the command KeyLocator).
        let cert_name: Name = "/op/dash/KEY/ec/self/v=0".parse().unwrap();
        provision_ecdsa_p256_pkcs8(ec_name, Some(cert_name.clone()), &pkcs8)
            .expect("provision ecdsa");
        let signer = command_signer().expect("gate open after ecdsa");
        assert_eq!(signer.sig_type(), SignatureType::SignatureSha256WithEcdsa);
        assert_eq!(signer.cert_name(), Some(&cert_name));
    }
}
