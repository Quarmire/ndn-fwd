//! Library target for `ndn-dashboard`.
//!
//! The dashboard's production code lives behind the `[[bin]]` target
//! (`src/main.rs`). This `lib.rs` exists for the `witness-export`
//! feature: under that feature it carries the wasm-bindgen surface the
//! browser-side witness (`testbed/tests/browser/wsmgmt_wire.spec.ts`)
//! loads via `wasm-pack build`. Off-feature, the lib compiles to an
//! empty crate so the bin build is unaffected.

#![allow(non_snake_case)]

// `ws_mgmt.rs` is part of the bin (declared in `main.rs`). Re-declare
// it here under `#[path]` so the lib target can pull the same source
// without moving it. Two compilations of the same code is fine — they
// land in separate crate units (`ndn_dashboard` lib vs `ndn-dashboard`
// bin) and the witness only links the lib.
#[cfg(all(target_arch = "wasm32", feature = "witness-export"))]
#[path = "ws_mgmt.rs"]
pub mod ws_mgmt;

#[cfg(all(target_arch = "wasm32", feature = "witness-export"))]
pub mod witness_export;
