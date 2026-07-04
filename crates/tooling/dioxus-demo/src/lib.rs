//! In-browser ndn-rs demo: a Dioxus web app driving a real
//! `BrowserWebTransportFace` against a forwarder, with optional
//! SharedWorker-hosted engine, WebRTC transit, and an NDNCERT join client.
//! All async work routes through [`ndn_runtime::default_runtime`]; the
//! render path never calls `spawn_local` directly.

#![allow(non_snake_case)]

// The demo is wasm-targeted (Dioxus web + WebTransport face +
// WasmEngineBuilder). Native builds compile to an empty crate surface.
#[cfg(target_arch = "wasm32")]
pub mod app;
#[cfg(target_arch = "wasm32")]
pub mod engine;
#[cfg(target_arch = "wasm32")]
pub mod enroll;
#[cfg(target_arch = "wasm32")]
pub mod face;
pub mod state;

#[cfg(all(target_arch = "wasm32", feature = "shared-engine"))]
pub mod worker;

#[cfg(all(target_arch = "wasm32", feature = "shared-engine"))]
pub mod shared_client;

#[cfg(all(target_arch = "wasm32", feature = "shared-engine"))]
pub mod transit;
#[cfg(all(target_arch = "wasm32", feature = "shared-engine"))]
pub mod webrtc_adapter;

// Tab-side bridge for the WebRTC worker-bridge pattern: forwards
// `RTCPeerConnection` traffic into a SharedWorker, since `RTCPeerConnection`
// isn't exposed to workers (W3C).
#[cfg(all(target_arch = "wasm32", feature = "shared-engine"))]
pub mod transit_bridge;

// Onboarding client: used by the shared-engine bundle (JS-facing JoinClient)
// and by the `web` tab build's Join panel.
#[cfg(all(
    target_arch = "wasm32",
    any(feature = "web", feature = "shared-engine")
))]
pub mod join;

#[cfg(all(target_arch = "wasm32", feature = "web"))]
pub fn launch() {
    console_error_panic_hook::set_once();
    dioxus::launch(app::App);
}
