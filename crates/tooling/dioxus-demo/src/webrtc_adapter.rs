//! `Send + Sync` adapter around the wasm [`WebRtcFace`]. The inner face
//! owns `!Send` JS handles (`Rc<WasmRtcChannel>`, `RtcPeerConnection`);
//! this wrapper moves them into a pump task and exposes two `mpsc`
//! channels that satisfy the engine's [`Face`] trait bounds.

use std::rc::Rc;
use std::sync::Arc;

use bytes::Bytes;
use ndn_face_webrtc::{RtcChannel, WasmRtcChannel, WebRtcFace as RtcInnerFace};
use ndn_runtime::Runtime;
use ndn_transport::{FaceError, FaceId, FaceKind, Transport};
use tokio::sync::{Mutex, mpsc};
use tracing::warn;

/// Dropping closes the outbound mpsc, the pump exits, and JS GC tears down
/// the underlying `RtcPeerConnection` (closing SCTP/DTLS).
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
        // Pump owns both the channel and the bare `WebRtcFace`, which keeps
        // the `RtcPeerConnection` alive for the pump's lifetime.
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
    // `RtcChannel::recv` on wasm is `?Send` and holds a `RefMut` across
    // await, so polling it inside a `select!` with the outbound branch
    // would re-enter. Use two separate `spawn_local` loops on the
    // single-threaded runtime instead.
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
