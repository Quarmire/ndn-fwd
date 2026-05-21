//! Face-trait adapter for the wasm [`WebRtcFace`].
//!
//! On wasm, [`ndn_face_webrtc::WebRtcFace`] holds an
//! `Rc<WasmRtcChannel>` and an `RtcPeerConnection`, both `!Send`.
//! The engine's [`Face`](ndn_transport::Face) trait requires
//! `Send + Sync + 'static`. Same channel-actor pattern as
//! `SharedWorkerProxyFace` solves it: spawn a single pump that
//! owns the `!Send` handles, expose two `mpsc` channels that the
//! face struct holds.

use std::rc::Rc;
use std::sync::Arc;

use bytes::Bytes;
use ndn_face_webrtc::{RtcChannel, WasmRtcChannel, WebRtcFace as RtcInnerFace};
use ndn_runtime::Runtime;
use ndn_transport::{FaceError, FaceId, FaceKind, Transport};
use tokio::sync::{Mutex, mpsc};
use tracing::warn;
use web_sys::RtcPeerConnection;

/// `Face`-implementing wrapper around the wasm
/// [`WebRtcFace`](ndn_face_webrtc::WebRtcFace).
///
/// Owns nothing `!Send`; the JS handles live inside the pump task.
/// Drop on the wrapper closes the outbound channel; the pump exits
/// and the underlying `RtcPeerConnection` is dropped (closing the
/// SCTP/DTLS session via the JS GC path).
pub struct WebRtcFaceAdapter {
    id: FaceId,
    tx_out: mpsc::Sender<Bytes>,
    rx_in: Mutex<mpsc::Receiver<Bytes>>,
}

impl WebRtcFaceAdapter {
    /// Wrap an already-connected `WebRtcFace` and spawn the pump.
    pub fn new(id: FaceId, face: RtcInnerFace, runtime: Arc<dyn Runtime>) -> Self {
        let (tx_out, rx_out) = mpsc::channel::<Bytes>(64);
        let (tx_in, rx_in) = mpsc::channel::<Bytes>(64);

        let channel = face.channel();
        // The pump owns both the channel (Rc<WasmRtcChannel>) and the
        // bare `WebRtcFace` (which holds the `RtcPeerConnection`)
        // inside the `move` closure. Together they keep the JS
        // peer-connection alive for the pump's whole lifetime.
        runtime.spawn(Box::pin(pump(face, channel, rx_out, tx_in)));

        Self {
            id,
            tx_out,
            rx_in: Mutex::new(rx_in),
        }
    }
}

impl Transport for WebRtcFaceAdapter {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::WebRtc
    }
    fn remote_uri(&self) -> Option<String> {
        Some(format!("webrtc-adapter://peer/{}", self.id.0))
    }
    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        let mut rx = self.rx_in.lock().await;
        rx.recv().await.ok_or(FaceError::Closed)
    }
    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.tx_out.send(pkt).await.map_err(|_| FaceError::Closed)
    }
}

async fn pump(
    _face: RtcInnerFace,
    channel: Rc<WasmRtcChannel>,
    mut rx_out: mpsc::Receiver<Bytes>,
    tx_in: mpsc::Sender<Bytes>,
) {
    // Spawn a parallel task on the same single-threaded runtime
    // that drains inbound bytes and pushes them into tx_in.
    // RtcChannel::recv on wasm is `?Send` and holds a `RefMut`
    // across the await; we can't poll it inside a `select!` that
    // also drives the outbound branch without re-entrancy issues.
    // Two separate `spawn_local`-driven loops are simpler and
    // correct on a single-threaded runtime.
    let recv_channel = Rc::clone(&channel);
    wasm_bindgen_futures::spawn_local(async move {
        loop {
            match recv_channel.recv().await {
                Ok(b) => {
                    if tx_in.send(b).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    while let Some(pkt) = rx_out.recv().await {
        if let Err(e) = channel.send(pkt).await {
            warn!(target: "demo.webrtc-adapter", error=?e, "send failed; closing pump");
            break;
        }
    }
}

// Suppress unused imports warning when only some platform code-paths
// are active during compilation.
#[allow(dead_code)]
fn _peer_connection_marker(_: RtcPeerConnection) {}
