//! UI-agnostic core for `ndn-dashboard`.
//!
//! The data models, operator keyring/custodian, trust/audit chains, identity
//! logic, and forwarder-profile selection the dashboard proved out — extracted
//! so *any* UI builds on the same logic: the Dioxus dashboard (desktop + web)
//! today, native Swift/Kotlin (via `ndn-boltffi`) for the mobile app next.
//!
//! **Deliberately Dioxus-free.** Nothing here depends on a UI framework; state
//! is held in plain `RwLock`/`OnceLock` singletons and pure functions, so the
//! same logic is unit-testable headless and FFI-friendly.
//!
//! Platform branches use the `desktop` / `web` features (mirrored from the
//! dashboard) so the moved modules' `cfg(feature = …)` gates keep resolving.

#![allow(clippy::result_large_err)]

pub mod forwarder_profile;
pub mod identity_axis;
pub mod keyguard;
pub mod operator_keyring;
pub mod operator_keyring_store;
pub mod preprovision;
pub mod security_chains;
pub mod signed_data_chain;
pub mod types;
