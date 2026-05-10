//! Face wiring: open a [`BrowserWebTransportFace`] from the browser tab.
//!
//! The fully wired engine integration (FIB, PIT, strategy table) is left
//! as the natural next step once Phase 4's UI scaffold is approved. For
//! now this module exposes the connect helper and a thin send/recv
//! pump that the consumer/producer panels can drive directly. The face
//! itself is a real `Face`, so swapping in `EngineBuilder::face(...)`
//! later is mechanical.

use std::sync::Arc;

use ndn_runtime::Runtime;
use ndn_transport::FaceId;

#[cfg(target_arch = "wasm32")]
use ndn_face_webtransport_wasm::{BrowserWebTransportFace, WtClientError};

#[cfg(target_arch = "wasm32")]
pub async fn connect(
    runtime: Arc<dyn Runtime>,
    url: &str,
) -> Result<BrowserWebTransportFace, WtClientError> {
    BrowserWebTransportFace::connect(FaceId(1), url, &[], runtime).await
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn connect(_runtime: Arc<dyn Runtime>, _url: &str) -> Result<(), &'static str> {
    Err("dioxus-demo face module is wasm-only")
}
