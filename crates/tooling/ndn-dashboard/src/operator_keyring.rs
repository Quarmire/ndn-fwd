//! Dashboard-held operator signing keyring — the operator's *own*, portable
//! signing identities, independent of any forwarder.
//!
//! The dashboard holds a **set** of operator identities (generated in-page or
//! imported from a SafeBag) in an [`InPageCustodian`], with one marked
//! *active*. Management commands are signed through a [`CustodianSigner`] over
//! the active identity; with none active, [`command_signer`] is `None` and the
//! client falls back to `DigestSha256` — that fallback is the "gate".
//!
//! This module is deliberately Dioxus-free so it stays unit-testable and is
//! shared verbatim by the native and wasm builds. UI reactivity is handled at
//! the call sites via [`crate::app_shared::bump_keyring_gen`] after a mutation;
//! views that render keyring state subscribe by reading `KEYRING_GEN`.
//!
//! OS-keyring / fob / remote custodians plug into the same seam (insert a
//! delegating `Custodian` instead of an in-page signer); local persistence of
//! the in-page identities is layered on top (see `operator_keyring_store`).
#![allow(dead_code)]

use std::sync::{Arc, OnceLock, RwLock};

use bytes::Bytes;
use ndn_custodian::{CustodianSigner, InPageCustodian, KeyId};
use ndn_packet::{Name, SignatureType};
use ndn_security::{EcdsaP256Signer, Ed25519Signer, Signer};

/// One identity the dashboard holds and can sign as.
#[derive(Clone)]
struct Held {
    key_id: KeyId,
    /// Operator certificate name, advertised in the command KeyLocator so the
    /// forwarder can resolve the signing cert to its trust anchor.
    cert_name: Option<Name>,
    sig_type: SignatureType,
    public_key: Option<Bytes>,
    /// Present for identities the dashboard fully holds (generated in-page, or
    /// imported with the key): the private key + certificate Data needed to
    /// re-emit a SafeBag and to persist the identity locally.
    exportable: Option<Exportable>,
}

/// Material needed to export / persist a dashboard-held identity as a SafeBag.
#[derive(Clone)]
struct Exportable {
    pkcs8: Vec<u8>,
    cert_wire: Bytes,
}

struct OperatorKeyring {
    custodian: Arc<InPageCustodian>,
    identities: RwLock<Vec<Held>>,
    /// The key id of the active identity (the one that signs), if any.
    active: RwLock<Option<KeyId>>,
}

fn keyring() -> &'static OperatorKeyring {
    static K: OnceLock<OperatorKeyring> = OnceLock::new();
    K.get_or_init(|| OperatorKeyring {
        custodian: Arc::new(InPageCustodian::new()),
        identities: RwLock::new(Vec::new()),
        active: RwLock::new(None),
    })
}

/// A public, render-friendly summary of a held identity (no secrets).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentitySummary {
    /// Identity name (`/op/alice`) — the key name with `/KEY/…` stripped.
    pub identity: String,
    /// Full key name (`/op/alice/KEY/<id>`).
    pub key_name: String,
    /// Certificate name, when known.
    pub cert_name: Option<String>,
    /// Algorithm label (`Ed25519` / `ECDSA P-256`).
    pub algorithm: String,
    /// Short public-key fingerprint (SHA-256 hex, first 16 chars) — the trust
    /// property, distinct from the navigation name.
    pub fingerprint: String,
    /// Whether the dashboard fully holds this identity (can export / persist).
    pub exportable: bool,
    /// Whether this is the active signing identity.
    pub active: bool,
}

fn identity_of(key_name: &str) -> String {
    key_name
        .split_once("/KEY/")
        .map(|(id, _)| id.to_string())
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| key_name.to_string())
}

fn algorithm_label(t: SignatureType) -> String {
    match t {
        SignatureType::SignatureEd25519 => "Ed25519",
        SignatureType::SignatureSha256WithEcdsa => "ECDSA P-256",
        SignatureType::SignatureSha256WithRsa => "RSA",
        _ => "other",
    }
    .to_string()
}

fn fingerprint_of(pk: Option<&Bytes>) -> String {
    use sha2::{Digest, Sha256};
    match pk {
        Some(pk) => {
            let digest = Sha256::digest(pk);
            digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
        }
        None => "unknown".to_string(),
    }
}

/// Core: add (or replace) `held` in the keyring and make it active. The
/// custodian gains the signer. Callers from the UI should follow with
/// [`crate::app_shared::bump_keyring_gen`].
fn provision_inner(
    key_name: Name,
    cert_name: Option<Name>,
    signer: Arc<dyn Signer>,
    exportable: Option<Exportable>,
) {
    let kr = keyring();
    let sig_type = signer.sig_type();
    let public_key = signer.public_key();
    let key_id = KeyId(key_name);
    kr.custodian.insert_signer(key_id.clone(), signer);

    let held = Held {
        key_id: key_id.clone(),
        cert_name,
        sig_type,
        public_key,
        exportable,
    };
    {
        let mut ids = kr.identities.write().expect("operator keyring lock");
        if let Some(slot) = ids.iter_mut().find(|h| h.key_id == key_id) {
            *slot = held;
        } else {
            ids.push(held);
        }
    }
    *kr.active.write().expect("operator keyring lock") = Some(key_id);
}

/// Provision a generated identity (in-page key + self-signed cert) as the
/// active signer, retaining the material to export / persist it.
pub fn provision_generated(
    key_name: Name,
    cert_name: Name,
    signer: Arc<dyn Signer>,
    pkcs8: Vec<u8>,
    cert_wire: Bytes,
) {
    provision_inner(
        key_name,
        Some(cert_name),
        signer,
        Some(Exportable { pkcs8, cert_wire }),
    );
}

/// Provision a freshly-seeded Ed25519 operator key (tests / quick generate).
pub fn provision_ed25519(key_name: Name, seed: &[u8; 32]) {
    provision_inner(
        key_name.clone(),
        None,
        Arc::new(Ed25519Signer::from_seed(seed, key_name)),
        None,
    );
}

/// Build a `dyn Signer` from a decrypted PKCS#8 key of either supported
/// algorithm, dispatching on the algorithm OID via the concrete signers.
fn signer_from_pkcs8(key_name: &Name, pkcs8_der: &[u8]) -> Result<Arc<dyn Signer>, String> {
    if let Ok(s) = Ed25519Signer::from_pkcs8_der(pkcs8_der, key_name.clone()) {
        return Ok(Arc::new(s));
    }
    EcdsaP256Signer::from_pkcs8_der(pkcs8_der, key_name.clone())
        .map(|s| Arc::new(s) as Arc<dyn Signer>)
        .map_err(|e| format!("operator key load: {e}"))
}

/// Provision a fully-held imported identity (key + the certificate Data it
/// arrived with), so it can be re-exported and persisted like a generated one.
/// Algorithm is dispatched from the PKCS#8 OID.
pub fn provision_imported(
    key_name: Name,
    cert_name: Name,
    pkcs8_der: &[u8],
    cert_wire: Bytes,
) -> Result<(), String> {
    let signer = signer_from_pkcs8(&key_name, pkcs8_der)?;
    provision_inner(
        key_name,
        Some(cert_name),
        signer,
        Some(Exportable {
            pkcs8: pkcs8_der.to_vec(),
            cert_wire,
        }),
    );
    Ok(())
}

/// Decode + decrypt a SafeBag wire and provision it as a fully-held active
/// identity. Derives the key and certificate names from the embedded cert, so
/// it's the single entry point for both SafeBag import and unlocking a
/// persisted identity. Returns the identity name on success.
pub fn provision_from_safebag(wire: &[u8], passphrase: &[u8]) -> Result<String, String> {
    let bag = ndn_safebag::SafeBag::decode(wire).map_err(|e| format!("SafeBag decode: {e}"))?;
    let pkcs8 = bag
        .decrypt_pkcs8(passphrase)
        .map_err(|e| format!("decrypt failed (wrong passphrase?): {e}"))?;
    let cert_data = ndn_packet::Data::decode(bag.certificate.clone())
        .map_err(|e| format!("certificate decode: {e:?}"))?;
    let cert_name = (*cert_data.name).clone();
    let key_name = key_name_from_cert(&cert_name);
    provision_imported(key_name, cert_name, &pkcs8, bag.certificate)?;
    active_identity_name().ok_or_else(|| "provision succeeded but no active identity".into())
}

/// Reduce a certificate name to its key name: keep components up to and
/// including the key id (`…/KEY/<keyid>`), dropping issuer + version.
fn key_name_from_cert(cert_name: &Name) -> Name {
    use ndn_packet::tlv_type::NAME_COMPONENT;
    let comps = cert_name.components();
    let key_idx = comps
        .iter()
        .position(|c| c.typ == NAME_COMPONENT && c.value.as_ref() == b"KEY");
    match key_idx {
        // identity.../KEY/<keyid> → keep through keyid.
        Some(i) if i + 1 < comps.len() => {
            Name::from_components(comps[..=i + 1].iter().cloned())
        }
        _ => cert_name.clone(),
    }
}

/// Every identity the dashboard holds, with the active one flagged.
pub fn list_identities() -> Vec<IdentitySummary> {
    let kr = keyring();
    let active = kr.active.read().expect("operator keyring lock").clone();
    kr.identities
        .read()
        .expect("operator keyring lock")
        .iter()
        .map(|h| {
            let key_name = h.key_id.as_name().to_string();
            IdentitySummary {
                identity: identity_of(&key_name),
                cert_name: h.cert_name.as_ref().map(|n| n.to_string()),
                algorithm: algorithm_label(h.sig_type),
                fingerprint: fingerprint_of(h.public_key.as_ref()),
                exportable: h.exportable.is_some(),
                active: active.as_ref() == Some(&h.key_id),
                key_name,
            }
        })
        .collect()
}

/// Make the identity with key name `key_name` the active signer. Returns true
/// when it was found. Follow with [`crate::app_shared::bump_keyring_gen`].
pub fn set_active(key_name: &str) -> bool {
    let kr = keyring();
    let found = kr
        .identities
        .read()
        .expect("operator keyring lock")
        .iter()
        .find(|h| h.key_id.as_name().to_string() == key_name)
        .map(|h| h.key_id.clone());
    match found {
        Some(key_id) => {
            *kr.active.write().expect("operator keyring lock") = Some(key_id);
            true
        }
        None => false,
    }
}

/// Forget a held identity. If it was active, signing closes until another is
/// activated. Returns true when removed.
pub fn remove_identity(key_name: &str) -> bool {
    let kr = keyring();
    let mut ids = kr.identities.write().expect("operator keyring lock");
    let before = ids.len();
    ids.retain(|h| h.key_id.as_name().to_string() != key_name);
    let removed = ids.len() != before;
    drop(ids);
    if removed {
        let mut active = kr.active.write().expect("operator keyring lock");
        if active.as_ref().map(|k| k.as_name().to_string()).as_deref() == Some(key_name) {
            *active = None;
        }
    }
    removed
}

fn with_active<T>(f: impl FnOnce(&Held) -> T) -> Option<T> {
    let kr = keyring();
    let active = kr.active.read().expect("operator keyring lock").clone()?;
    let ids = kr.identities.read().expect("operator keyring lock");
    ids.iter().find(|h| h.key_id == active).map(f)
}

/// Encrypt the active identity into a SafeBag wire under `passphrase`, when the
/// active identity is fully held. `None` when nothing is active or it isn't
/// exportable.
pub fn export_active_safebag(passphrase: &[u8]) -> Option<Result<Vec<u8>, String>> {
    let exp = with_active(|h| h.exportable.clone())??;
    Some(encrypt_safebag(&exp, passphrase))
}

/// Encrypt a specific held identity (by key name) into a SafeBag wire.
pub fn export_safebag_for(key_name: &str, passphrase: &[u8]) -> Option<Result<Vec<u8>, String>> {
    let kr = keyring();
    let ids = kr.identities.read().expect("operator keyring lock");
    let exp = ids
        .iter()
        .find(|h| h.key_id.as_name().to_string() == key_name)?
        .exportable
        .clone()?;
    Some(encrypt_safebag(&exp, passphrase))
}

fn encrypt_safebag(exp: &Exportable, passphrase: &[u8]) -> Result<Vec<u8>, String> {
    ndn_safebag::SafeBag::encrypt(exp.cert_wire.clone(), &exp.pkcs8, passphrase)
        .map(|bag| bag.encode().to_vec())
        .map_err(|e| format!("SafeBag encrypt: {e}"))
}

/// Whether the active identity can be exported as a SafeBag.
pub fn active_is_exportable() -> bool {
    with_active(|h| h.exportable.is_some()).unwrap_or(false)
}

/// Whether an operator key is active (the gate is open).
pub fn is_provisioned() -> bool {
    keyring()
        .active
        .read()
        .expect("operator keyring lock")
        .is_some()
}

/// The active operator's identity name (`/op/alice`), or `None`.
pub fn active_identity_name() -> Option<String> {
    with_active(|h| identity_of(&h.key_id.as_name().to_string()))
}

/// The active identity's certificate Data wire — what a forwarder needs as a
/// trust anchor to accept this identity's commands. `None` unless the active
/// identity is fully held (its cert is available).
pub fn active_cert_wire() -> Option<Vec<u8>> {
    with_active(|h| h.exportable.as_ref().map(|e| e.cert_wire.to_vec())).flatten()
}

/// The mgmt-command signer for the active identity, else `None`.
pub fn command_signer() -> Option<Arc<dyn Signer>> {
    let kr = keyring();
    with_active(|h| {
        let mut signer = CustodianSigner::new(
            kr.custodian.clone(),
            h.key_id.clone(),
            h.sig_type,
            h.public_key.clone(),
        );
        if let Some(cert_name) = h.cert_name.clone() {
            signer = signer.with_cert_name(cert_name);
        }
        Arc::new(signer) as Arc<dyn Signer>
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // keyring() is process-global, so all steps run in one sequential test.
    #[test]
    fn keyring_holds_multiple_and_switches_active() {
        // Provision an Ed25519 identity → active.
        let ed: Name = "/op/dash/KEY/k1".parse().unwrap();
        provision_ed25519(ed.clone(), &[5u8; 32]);
        assert!(is_provisioned());
        assert_eq!(command_signer().unwrap().key_name().to_string(), "/op/dash/KEY/k1");

        // Provision an ECDSA identity with a cert name → becomes active, and
        // its cert name surfaces in the signer (the command KeyLocator).
        let ec_name: Name = "/op/dash/KEY/ec".parse().unwrap();
        let ec = EcdsaP256Signer::from_seed(&[6u8; 32], ec_name.clone()).unwrap();
        let pkcs8 = ec.to_pkcs8_der().unwrap();
        let cert_name: Name = "/op/dash/KEY/ec/self/v=0".parse().unwrap();
        provision_imported(ec_name, cert_name.clone(), &pkcs8, Bytes::new()).unwrap();
        let signer = command_signer().unwrap();
        assert_eq!(signer.sig_type(), SignatureType::SignatureSha256WithEcdsa);
        assert_eq!(signer.cert_name(), Some(&cert_name));

        // Both identities are held.
        let ids = list_identities();
        assert!(ids.iter().any(|i| i.key_name == "/op/dash/KEY/k1"));
        assert!(ids.iter().any(|i| i.key_name == "/op/dash/KEY/ec" && i.active));
        assert_eq!(ids.iter().filter(|i| i.active).count(), 1);

        // Switch back to the Ed25519 identity.
        assert!(set_active("/op/dash/KEY/k1"));
        assert_eq!(command_signer().unwrap().key_name().to_string(), "/op/dash/KEY/k1");
        assert_eq!(active_identity_name().as_deref(), Some("/op/dash"));

        // Forget it → active clears.
        assert!(remove_identity("/op/dash/KEY/k1"));
        assert!(!is_provisioned());
    }
}
