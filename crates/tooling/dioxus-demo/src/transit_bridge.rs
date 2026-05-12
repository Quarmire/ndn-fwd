//! WebRTC ↔ SharedWorker tab-side bridge (the worker-bridge pattern
//! from `crates/extension/ndn-face-webrtc/docs/worker-bridge.md`).
//!
//! ## Topology
//!
//! ```text
//!   peer tab                  bridge tab                       SharedWorker
//!   ┌──────────────┐          ┌─────────────────────┐          ┌──────────────────┐
//!   │ TransitPeer  │ ─ WebRTC ┼─▶ WebRtcFaceAdapter │          │  ForwarderEngine │
//!   │ (window ctx)  │ datachan │       ↕             │ ↓ ports  │  (mgmt + CS +    │
//!   │               │          │   byte pump (2x)   │ ←──────▶ │   producer)      │
//!   │               │          │       ↕             │          │                  │
//!   │               │          │  SharedWorkerProxy │          │  /cache-test     │
//!   └──────────────┘          └─────────────────────┘          │   AppFace        │
//!                                                              └──────────────────┘
//! ```
//!
//! The bridge tab doesn't run its own engine — it's just a byte pump
//! between two faces.  The SharedWorker treats the bridge's
//! `WorkerPortFace` like any other tab; FIB routes, CS lookups, and
//! the mgmt dispatcher all apply.  Each end-to-end Interest takes
//! exactly one detour through the bridge tab's JS event loop, which
//! is the minimum the W3C-imposed window-scoped `RTCPeerConnection`
//! constraint allows.
//!
//! See the doc file for the rationale and a code sketch that this
//! module reifies.

#![cfg(all(target_arch = "wasm32", feature = "shared-engine"))]

use std::cell::RefCell;
use std::sync::Arc;

use ndn_face_shared_worker::SharedWorkerProxyFace;
use ndn_face_webrtc::{IceServers, PendingFace, SessionDescription, WebRtcConnector};
use ndn_runtime::{Runtime, default_runtime};
use ndn_transport::{Face, FaceId};
use wasm_bindgen::prelude::*;

use crate::webrtc_adapter::WebRtcFaceAdapter;

fn bridge_log(msg: &str) {
    web_sys::console::log_1(&format!("[transit-bridge] {msg}").into());
}

/// A tab-side WebRTC ↔ SharedWorker byte pump.
///
/// Lifecycle:
/// 1. `new(worker_url, worker_name)` connects to the SharedWorker
///    via a [`SharedWorkerProxyFace`] (registering the bridge as a
///    new face inside the worker's engine).
/// 2. `accept_offer(offer_json)` accepts an SDP offer from a peer
///    and returns the SDP answer to forward back.
/// 3. `start()` finalizes the WebRTC channel and spawns the two
///    pump tasks (`rtc → worker` and `worker → rtc`).  After this
///    the bridge runs until either face errors / closes.
///
/// The bridge holds no engine — it owns two faces and the two
/// background tasks that pump between them.
#[wasm_bindgen]
pub struct TransitBridge {
    connector: WebRtcConnector,
    pending: RefCell<Option<PendingFace>>,
    worker_face: Arc<SharedWorkerProxyFace>,
    runtime: Arc<dyn Runtime>,
}

#[wasm_bindgen]
impl TransitBridge {
    #[wasm_bindgen(constructor)]
    pub fn new(worker_url: String, worker_name: Option<String>) -> Result<TransitBridge, JsValue> {
        console_error_panic_hook::set_once();
        let runtime = default_runtime();
        let worker_face = SharedWorkerProxyFace::connect(
            FaceId(1),
            &worker_url,
            worker_name.as_deref(),
            Arc::clone(&runtime),
        )
        .map_err(|e| JsValue::from_str(&format!("worker connect: {e}")))?;

        let connector = WebRtcConnector::new(IceServers::default())
            .map_err(|e| JsValue::from_str(&format!("connector: {e}")))?;

        bridge_log(&format!(
            "connected to SharedWorker ({worker_url}); awaiting peer offer"
        ));

        Ok(TransitBridge {
            connector,
            pending: RefCell::new(None),
            worker_face: Arc::new(worker_face),
            runtime,
        })
    }

    /// Accept an SDP offer from a peer; return the SDP answer.
    /// The WebRTC channel is materialised lazily by [`start`].
    pub async fn accept_offer(&self, offer_json: String) -> Result<String, JsValue> {
        let offer: SessionDescription = serde_json::from_str(&offer_json)
            .map_err(|e| JsValue::from_str(&format!("parse offer: {e}")))?;
        let (answer, pending) = self
            .connector
            .accept_offer(offer)
            .await
            .map_err(|e| JsValue::from_str(&format!("accept_offer: {e}")))?;
        *self.pending.borrow_mut() = Some(pending);
        bridge_log("accepted offer; pending channel open");
        serde_json::to_string(&answer)
            .map_err(|e| JsValue::from_str(&format!("serialise answer: {e}")))
    }

    /// Block until the WebRTC channel is open, then spawn the
    /// rtc↔worker pumps and return.  After this call the bridge
    /// runs in the background until either face closes.
    pub async fn start(&self) -> Result<(), JsValue> {
        let pending = self
            .pending
            .borrow_mut()
            .take()
            .ok_or_else(|| JsValue::from_str("no pending peer; call accept_offer first"))?;
        let rtc_face = self
            .connector
            .finalize_pending(pending)
            .await
            .map_err(|e| JsValue::from_str(&format!("finalize: {e}")))?;
        let rtc: Arc<WebRtcFaceAdapter> = Arc::new(WebRtcFaceAdapter::new(
            FaceId(2),
            rtc_face,
            Arc::clone(&self.runtime),
        ));
        let worker = Arc::clone(&self.worker_face);

        // peer → worker: every Interest from the peer goes into the
        // worker's engine through the bridge's WorkerPortFace.
        let r = Arc::clone(&rtc);
        let w = Arc::clone(&worker);
        self.runtime.spawn(Box::pin(async move {
            loop {
                match Face::recv(&*r).await {
                    Ok(bytes) => {
                        if Face::send(&*w, bytes).await.is_err() {
                            bridge_log("worker face send closed; rtc→worker pump exits");
                            break;
                        }
                    }
                    Err(e) => {
                        bridge_log(&format!("rtc recv error: {e:?}; rtc→worker pump exits"));
                        break;
                    }
                }
            }
        }));

        // worker → peer: every Data the engine forwards out through
        // the bridge's face goes back over the WebRTC datachannel.
        let r = Arc::clone(&rtc);
        let w = Arc::clone(&worker);
        self.runtime.spawn(Box::pin(async move {
            loop {
                match Face::recv(&*w).await {
                    Ok(bytes) => {
                        if Face::send(&*r, bytes).await.is_err() {
                            bridge_log("rtc face send closed; worker→rtc pump exits");
                            break;
                        }
                    }
                    Err(e) => {
                        bridge_log(&format!("worker recv error: {e:?}; worker→rtc pump exits"));
                        break;
                    }
                }
            }
        }));

        bridge_log("bridge active — pumping bytes both directions");
        Ok(())
    }
}
