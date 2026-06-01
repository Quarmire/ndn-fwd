//! KeyGuardian — the second factor that seals an operator identity.
//!
//! An operator identity is always persisted as a passphrase-encrypted SafeBag.
//! The *guardian* decides where that passphrase comes from:
//!
//! - [`GuardKind::Passphrase`]: a human-typed passphrase (portable fallback).
//! - [`GuardKind::OsKeychain`]: a random secret sealed in the OS keychain
//!   (Touch ID / Windows Hello / Secret Service) — passwordless, device-bound.
//!   Releasing it is gated by the OS (login / biometric), the "second factor".
//!
//! Future variants (`WebAuthnPrf`, `RemoteFob`) plug into this same seam.
//!
//! This module owns only the OS-keychain secret; the SafeBag crypto stays in
//! `operator_keyring`. Everything degrades gracefully: if the keychain is
//! unavailable, OS-keychain seal/release returns an error and the operator
//! falls back to a passphrase.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// Which second factor protects a persisted identity's key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum GuardKind {
    /// Human-typed passphrase (the portable default).
    #[default]
    #[serde(rename = "passphrase")]
    Passphrase,
    /// A random secret held in the OS keychain; release is OS-gated.
    #[serde(rename = "os-keychain")]
    OsKeychain,
}

impl GuardKind {
    pub fn label(self) -> &'static str {
        match self {
            GuardKind::Passphrase => "passphrase",
            GuardKind::OsKeychain => "this device",
        }
    }
}

/// Whether the OS keychain backend is usable on this build/platform.
pub fn os_keychain_available() -> bool {
    cfg!(feature = "desktop")
}

const KEYCHAIN_SERVICE: &str = "ndn-dashboard-operator-keyring";

/// Generate a fresh random secret, seal it in the OS keychain under
/// `fingerprint`, and return it for one-time use as the SafeBag passphrase.
/// The plaintext secret is never persisted by the dashboard — only the
/// keychain holds it.
pub fn os_keychain_seal(fingerprint: &str) -> Result<String, String> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).map_err(|_| "rng failure".to_string())?;
    let secret: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    keychain_set(fingerprint, &secret)?;
    Ok(secret)
}

/// Release the keychain-held secret for `fingerprint` (the OS gates this with
/// login / biometric). Returns the SafeBag passphrase.
pub fn os_keychain_release(fingerprint: &str) -> Result<String, String> {
    keychain_get(fingerprint)
}

/// Remove the keychain secret for `fingerprint` (on Forget).
pub fn os_keychain_forget(fingerprint: &str) {
    keychain_delete(fingerprint);
}

#[cfg(feature = "desktop")]
fn keychain_entry(fingerprint: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(KEYCHAIN_SERVICE, fingerprint)
        .map_err(|e| format!("OS keychain unavailable: {e}"))
}

#[cfg(feature = "desktop")]
fn keychain_set(fingerprint: &str, secret: &str) -> Result<(), String> {
    keychain_entry(fingerprint)?
        .set_password(secret)
        .map_err(|e| format!("OS keychain write failed: {e}"))
}

#[cfg(feature = "desktop")]
fn keychain_get(fingerprint: &str) -> Result<String, String> {
    keychain_entry(fingerprint)?
        .get_password()
        .map_err(|e| format!("OS keychain read failed: {e}"))
}

#[cfg(feature = "desktop")]
fn keychain_delete(fingerprint: &str) {
    if let Ok(entry) = keychain_entry(fingerprint) {
        let _ = entry.delete_credential();
    }
}

#[cfg(not(feature = "desktop"))]
fn keychain_set(_fingerprint: &str, _secret: &str) -> Result<(), String> {
    Err("OS keychain is only available on the desktop build".into())
}

#[cfg(not(feature = "desktop"))]
fn keychain_get(_fingerprint: &str) -> Result<String, String> {
    Err("OS keychain is only available on the desktop build".into())
}

#[cfg(not(feature = "desktop"))]
fn keychain_delete(_fingerprint: &str) {}
