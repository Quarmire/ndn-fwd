//! Local persistence for the operator keyring.
//!
//! Identities are saved as **encrypted SafeBags** alongside public metadata
//! (names, algorithm, fingerprint) — the private key is never written in the
//! clear. On launch the dashboard lists saved identities as *locked*; the
//! operator unlocks one with its passphrase to load it into the signing
//! keyring. This keeps "my identity follows me across restarts" without
//! storing decrypted keys at rest.
//!
//! Storage mirrors `settings.rs`: a JSON blob under
//! `~/.config/ndn-dashboard/` on desktop, `localStorage` on web. (Seamless
//! no-passphrase unlock via the OS keychain is a future enhancement; the
//! on-disk shape here is unaffected by it.)
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// A persisted identity: public metadata + its passphrase-encrypted SafeBag
/// (base64). The fingerprint is the stable key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SavedIdentity {
    pub identity: String,
    pub key_name: String,
    pub cert_name: String,
    pub algorithm: String,
    pub fingerprint: String,
    /// Encrypted SafeBag wire, base64. Decrypts only with the passphrase the
    /// operator chose when saving.
    pub safebag_b64: String,
}

/// All saved identities, or empty when nothing has been persisted.
pub fn load_saved() -> Vec<SavedIdentity> {
    load_blob().unwrap_or_default()
}

/// Add or replace (by fingerprint) a saved identity and persist.
pub fn upsert(item: SavedIdentity) -> Result<(), String> {
    let mut all = load_saved();
    if let Some(slot) = all.iter_mut().find(|s| s.fingerprint == item.fingerprint) {
        *slot = item;
    } else {
        all.push(item);
    }
    save_blob(&all)
}

/// Remove a saved identity by fingerprint and persist.
pub fn remove(fingerprint: &str) -> Result<(), String> {
    let mut all = load_saved();
    let before = all.len();
    all.retain(|s| s.fingerprint != fingerprint);
    if all.len() != before {
        save_blob(&all)?;
    }
    Ok(())
}

/// Whether an identity with this fingerprint is persisted.
pub fn is_saved(fingerprint: &str) -> bool {
    load_saved().iter().any(|s| s.fingerprint == fingerprint)
}

// ── Platform storage ──────────────────────────────────────────────────────

#[cfg(feature = "desktop")]
fn store_path() -> std::path::PathBuf {
    dirs_next::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("ndn-dashboard")
        .join("operator-keyring.json")
}

#[cfg(feature = "desktop")]
fn load_blob() -> Option<Vec<SavedIdentity>> {
    let content = std::fs::read_to_string(store_path()).ok()?;
    serde_json::from_str(&content).ok()
}

#[cfg(feature = "desktop")]
fn save_blob(all: &[SavedIdentity]) -> Result<(), String> {
    let path = store_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(all).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())
}

#[cfg(all(feature = "web", not(feature = "desktop")))]
fn load_blob() -> Option<Vec<SavedIdentity>> {
    use gloo_storage::{LocalStorage, Storage};
    LocalStorage::get("ndn-dashboard-operator-keyring").ok()
}

#[cfg(all(feature = "web", not(feature = "desktop")))]
fn save_blob(all: &[SavedIdentity]) -> Result<(), String> {
    use gloo_storage::{LocalStorage, Storage};
    LocalStorage::set("ndn-dashboard-operator-keyring", all).map_err(|e| format!("{e:?}"))
}

#[cfg(not(any(feature = "desktop", feature = "web")))]
fn load_blob() -> Option<Vec<SavedIdentity>> {
    None
}

#[cfg(not(any(feature = "desktop", feature = "web")))]
fn save_blob(_all: &[SavedIdentity]) -> Result<(), String> {
    Ok(())
}
