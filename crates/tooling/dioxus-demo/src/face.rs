//! Tab-side helper that opens a [`BrowserWebTransportFace`].

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
