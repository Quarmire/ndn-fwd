//! Tab-side WebRTC ↔ SharedWorker bridge. The bridge tab runs no engine of
//! its own; it owns two faces (a [`WebRtcFaceAdapter`] to the peer and a
//! [`SharedWorkerProxyFace`] to the worker) and two background pumps that
//! shuttle bytes between them. Each Interest detours once through the
//! window's JS event loop — the minimum the W3C window-scoped
//! `RTCPeerConnection` rule allows.

#![cfg(all(target_arch = "wasm32", feature = "shared-engine"))]

use std::cell::RefCell;
use std::sync::Arc;

use ndn_face_shared_worker::SharedWorkerProxyFace;
use ndn_face_webrtc::{IceServers, PendingFace, SessionDescription, WebRtcConnector};
use ndn_runtime::{Runtime, default_runtime};
use ndn_transport::{FaceId, Transport};
use wasm_bindgen::prelude::*;

use crate::webrtc_adapter::WebRtcFaceAdapter;

fn bridge_log(msg: &str) {
    web_sys::console::log_1(&format!("[transit-bridge] {msg}").into());
}

/// Lifecycle: `new` connects the worker face, `accept_offer` produces the
/// SDP answer, `start` finalizes the WebRTC channel and spawns the two
/// pump tasks. Runs until either face closes.
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

    /// The WebRTC channel itself is materialised lazily by `start`.
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

    /// Await the WebRTC channel, spawn both pumps, return.
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

        // peer → worker
        let r = Arc::clone(&rtc);
        let w = Arc::clone(&worker);
        self.runtime.spawn(Box::pin(async move {
            loop {
                match Transport::recv_bytes(&*r).await {
                    Ok(bytes) => {
                        if Transport::send_bytes(&*w, bytes).await.is_err() {
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

        // worker → peer
        let r = Arc::clone(&rtc);
        let w = Arc::clone(&worker);
        self.runtime.spawn(Box::pin(async move {
            loop {
                match Transport::recv_bytes(&*w).await {
                    Ok(bytes) => {
                        if Transport::send_bytes(&*r, bytes).await.is_err() {
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
