//! Library target for `ndn-dashboard`, used by the `witness-export` feature
//! to expose a wasm-bindgen surface for browser-side witnesses.

#![allow(non_snake_case)]

#[cfg(all(target_arch = "wasm32", feature = "witness-export"))]
#[path = "ws_mgmt.rs"]
pub mod ws_mgmt;

#[cfg(all(target_arch = "wasm32", feature = "witness-export"))]
pub mod witness_export;
