//! Phase 4 in-browser demo: ndn-rs WebTransport face inside Dioxus.
//!
//! Three panels: face status, consumer, producer. The face is a real
//! [`ndn_face_webtransport_wasm::BrowserWebTransportFace`] dialled out
//! to a configurable forwarder URL. The consumer panel encodes
//! Interests on click, sends them through the face, decodes the
//! returned NDNLPv2-wrapped Data, and renders wire-level fields.
//!
//! Engine wiring routes spawn calls through
//! [`ndn_runtime::default_runtime`] — no `wasm_bindgen_futures::spawn_local`
//! on the render path, per `feedback_dioxus_ndn_native` and
//! `feedback_wasm_no_js`.

#![allow(non_snake_case)]

// The demo's app/engine/enroll/face are inherently wasm-targeted
// (Dioxus web UI + WebTransport face + ForwarderEngine via the
// wasm-only WasmEngineBuilder). Native builds skip them entirely;
// `cargo build -p dioxus-demo` on host produces an empty crate
// surface, which is what the workspace expects (the crate is not in
// default-members, native builds are compile-checks only).
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

// Phase 7 browser-as-transit witness — wasm-bindgen TransitHost +
// TransitPeer entrypoints + the WebRTC Face-trait adapter that lets
// the engine treat a wasm WebRtcFace like any other Face.
#[cfg(all(target_arch = "wasm32", feature = "shared-engine"))]
pub mod transit;
#[cfg(all(target_arch = "wasm32", feature = "shared-engine"))]
pub mod webrtc_adapter;

// Critical-path #4 onboarding-link client — JoinClient wasm-bindgen
// entrypoint that drives NDNCERT TokenChallenge enrollment + IdbPib
// persistence so a "click the URL → enrolled in <30s" UX works and
// reloads short-circuit the flow.
#[cfg(all(target_arch = "wasm32", feature = "shared-engine"))]
pub mod join;

#[cfg(all(target_arch = "wasm32", feature = "web"))]
pub fn launch() {
    console_error_panic_hook::set_once();
    dioxus::launch(app::App);
}
