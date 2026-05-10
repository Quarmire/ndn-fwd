//! Phase 7 browser-as-transit witness: host + peer wasm-bindgen entrypoints.
//!
//! ## Topology
//!
//! ```text
//!   transit-peer-tab        WebRTC datachannel        transit-host-tab
//!   ┌──────────────┐    ┌─────────────────────────┐  ┌──────────────────┐
//!   │ TransitPeer  │ ←─ │  out-of-band signaling  │ →│ TransitHost      │
//!   │   create_offer│   │  (Playwright as conduit) │  │   accept_offer  │
//!   │   set_answer  │   └─────────────────────────┘  │   ↓ adds wrt face│
//!   │   express     │  ───── DTLS / SCTP ──────────── │  to engine       │
//!   └──────────────┘                                  │ ForwarderEngine  │
//!                                                     │   /transit-test  │
//!                                                     │     producer     │
//!                                                     └──────────────────┘
//! ```
//!
//! Tab 3 (`transit-peer`) talks to tab A (`transit-host`) over a
//! single peer-to-peer WebRTC datachannel. Tab A has a real
//! `ForwarderEngine` with two faces: an internal `AppFace` (serving
//! the `/transit-test` producer) and the inbound `WebRtcFaceAdapter`
//! that wraps tab 3's channel. When tab 3 expresses an Interest
//! for `/transit-test/counter`, tab A's engine pipeline:
//!
//! 1. receives on `WebRtcFaceAdapter`, opens a PIT entry,
//! 2. CS lookup — miss on the first call, hit on subsequent calls,
//! 3. FIB lookup — `/transit-test → AppFace`,
//! 4. forwards to AppFace; demo's app pump synthesises the Data,
//! 5. PIT match → satisfy → Data goes back over the WebRTC face
//!    to tab 3.
//!
//! This is the engine's *transit* path — the same forwarding chain
//! native `ndn-fwd` runs.

use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use js_sys::Uint8Array;
use ndn_face_webrtc::{IceServers, PendingFace, SessionDescription, WebRtcConnector};
use ndn_packet::lp::LpPacket;
use ndn_packet::{Data, Interest, Name};
use ndn_runtime::default_runtime;
use ndn_transport::{Face, FaceError, FaceId};
use std::collections::HashMap;
use tokio::sync::{Mutex, oneshot};
use wasm_bindgen::prelude::*;

use crate::engine::Engine;
use crate::webrtc_adapter::WebRtcFaceAdapter;

fn host_log(msg: &str) {
    web_sys::console::log_1(&format!("[transit-host] {msg}").into());
}

fn peer_log(msg: &str) {
    web_sys::console::log_1(&format!("[transit-peer] {msg}").into());
}

/// Tab-A entrypoint. Hosts a real `ForwarderEngine` with one local
/// producer prefix (`/transit-test`). Exposes `accept_offer` for
/// the WebRTC handshake driven by Playwright.
#[wasm_bindgen]
pub struct TransitHost {
    engine: Arc<Engine>,
    /// Connector kept alive for the host's lifetime — accept_offer
    /// uses it to negotiate each incoming peer.
    connector: WebRtcConnector,
    /// Pending face state stashed between accept_offer and the
    /// channel actually opening (the open future runs as a separate
    /// awaiter in finalize_pending).
    pending: RefCell<Option<PendingFace>>,
}

#[wasm_bindgen]
impl TransitHost {
    /// Construct a host engine. `producers` is a comma-separated
    /// list of prefixes registered locally; the demo's app pump
    /// serves `<prefix>/counter` Data with a monotonically
    /// increasing payload, the same as the SharedWorker entrypoint.
    #[wasm_bindgen(constructor)]
    pub async fn new(producers: String) -> Result<TransitHost, JsValue> {
        console_error_panic_hook::set_once();
        let runtime = default_runtime();
        let engine = Arc::new(Engine::new(runtime, None));

        for raw in producers.split(',') {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            match trimmed.parse::<Name>() {
                Ok(prefix) => {
                    engine.register_producer_local(prefix.clone()).await;
                    host_log(&format!("registered producer {prefix}"));
                }
                Err(_) => host_log(&format!("skipped invalid prefix {trimmed:?}")),
            }
        }

        let connector = WebRtcConnector::new(IceServers::default())
            .map_err(|e| JsValue::from_str(&format!("connector: {e}")))?;

        Ok(TransitHost {
            engine,
            connector,
            pending: RefCell::new(None),
        })
    }

    /// Accept an SDP offer (JSON-encoded) from a peer and return
    /// the host's SDP answer (JSON-encoded). The actual
    /// `WebRtcFace` is materialised by `finalize_peer` once the
    /// peer reports the channel open on its end.
    pub async fn accept_offer(&self, offer_json: String) -> Result<String, JsValue> {
        let offer: SessionDescription = serde_json::from_str(&offer_json)
            .map_err(|e| JsValue::from_str(&format!("parse offer: {e}")))?;
        let (answer, pending) = self
            .connector
            .accept_offer(offer)
            .await
            .map_err(|e| JsValue::from_str(&format!("accept_offer: {e}")))?;
        *self.pending.borrow_mut() = Some(pending);
        host_log("accepted offer; pending channel open");
        serde_json::to_string(&answer)
            .map_err(|e| JsValue::from_str(&format!("serialise answer: {e}")))
    }

    /// Block until the SCTP channel is open, then add the resulting
    /// `WebRtcFace` to the engine.
    pub async fn finalize_peer(&self) -> Result<(), JsValue> {
        let pending = self
            .pending
            .borrow_mut()
            .take()
            .ok_or_else(|| JsValue::from_str("no pending peer; call accept_offer first"))?;
        let face = self
            .connector
            .finalize_pending(pending)
            .await
            .map_err(|e| JsValue::from_str(&format!("finalize: {e}")))?;
        let id = self.engine.forwarder().faces().alloc_id();
        let runtime = default_runtime();
        let adapter = WebRtcFaceAdapter::new(id, face, runtime);
        self.engine.add_face(adapter);
        host_log(&format!("WebRTC face #{} added to engine", id.0));
        Ok(())
    }
}

/// Tab-3 entrypoint. Drives a single WebRtcConnector from the
/// offerer side, negotiates with the host via Playwright, then
/// pushes Interests through the channel + reads Data back.
#[wasm_bindgen]
pub struct TransitPeer {
    connector: WebRtcConnector,
    pending: RefCell<Option<PendingFace>>,
    face: RefCell<Option<Arc<WebRtcFaceAdapter>>>,
    pending_data: Arc<PendingMap>,
}

type PendingMap = Mutex<HashMap<String, oneshot::Sender<Bytes>>>;

#[wasm_bindgen]
impl TransitPeer {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<TransitPeer, JsValue> {
        console_error_panic_hook::set_once();
        let connector = WebRtcConnector::new(IceServers::default())
            .map_err(|e| JsValue::from_str(&format!("connector: {e}")))?;
        Ok(TransitPeer {
            connector,
            pending: RefCell::new(None),
            face: RefCell::new(None),
            pending_data: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Generate a fresh SDP offer (JSON-encoded) for the host.
    pub async fn create_offer(&self) -> Result<String, JsValue> {
        let (offer, pending) = self
            .connector
            .create_offer()
            .await
            .map_err(|e| JsValue::from_str(&format!("create_offer: {e}")))?;
        *self.pending.borrow_mut() = Some(pending);
        peer_log("created offer");
        serde_json::to_string(&offer)
            .map_err(|e| JsValue::from_str(&format!("serialise offer: {e}")))
    }

    /// Accept the host's SDP answer and finalize the channel.
    /// After this returns, `express` is usable.
    pub async fn set_answer(&self, answer_json: String) -> Result<(), JsValue> {
        let answer: SessionDescription = serde_json::from_str(&answer_json)
            .map_err(|e| JsValue::from_str(&format!("parse answer: {e}")))?;
        let pending = self
            .pending
            .borrow_mut()
            .take()
            .ok_or_else(|| JsValue::from_str("no pending; call create_offer first"))?;
        let face = self
            .connector
            .finalize_with_answer(pending, answer)
            .await
            .map_err(|e| JsValue::from_str(&format!("finalize: {e}")))?;

        let runtime = default_runtime();
        let adapter = Arc::new(WebRtcFaceAdapter::new(
            FaceId(1),
            face,
            Arc::clone(&runtime),
        ));
        *self.face.borrow_mut() = Some(Arc::clone(&adapter));

        // Spawn the recv pump that reads Data back from the host
        // and wakes `express` callers.
        let pending_data = Arc::clone(&self.pending_data);
        runtime.spawn(Box::pin(async move {
            loop {
                let raw = match Face::recv(&*adapter).await {
                    Ok(b) => b,
                    Err(_) => break,
                };
                let inner = LpPacket::decode(raw.clone())
                    .ok()
                    .and_then(|lp| lp.fragment)
                    .unwrap_or(raw);
                if let Ok(data) = Data::decode(inner) {
                    let key = data.name.to_string();
                    if let Some(tx) = pending_data.lock().await.remove(&key) {
                        let payload = data.content().cloned().unwrap_or_default();
                        let _ = tx.send(payload);
                    }
                }
            }
        }));

        peer_log("answer set; channel up");
        Ok(())
    }

    /// Express an Interest over the WebRTC channel and resolve
    /// to the matching Data's `content` bytes.
    pub async fn express(&self, name: String, lifetime_ms: u32) -> Result<Uint8Array, JsValue> {
        let parsed: Name = name.parse().map_err(|_| JsValue::from_str("bad name"))?;
        let key = parsed.to_string();
        let lifetime = Duration::from_millis(lifetime_ms as u64);
        let wire = encode_interest(&parsed, lifetime);

        let (tx, rx) = oneshot::channel();
        self.pending_data.lock().await.insert(key.clone(), tx);

        let face = self
            .face
            .borrow()
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| JsValue::from_str("face not connected; call set_answer first"))?;
        peer_log(&format!("express {key}"));
        Face::send(&*face, wire)
            .await
            .map_err(|e: FaceError| JsValue::from_str(&format!("send: {e:?}")))?;

        let runtime = default_runtime();
        let timeout = runtime.sleep(lifetime + Duration::from_millis(500));
        tokio::select! {
            biased;
            res = rx => {
                let bytes = res.map_err(|_| JsValue::from_str("recv channel closed"))?;
                let arr = Uint8Array::new_with_length(bytes.len() as u32);
                arr.copy_from(&bytes);
                Ok(arr)
            }
            _ = timeout => {
                self.pending_data.lock().await.remove(&key);
                Err(JsValue::from_str("timeout"))
            }
        }
    }
}

fn encode_interest(name: &Name, lifetime: Duration) -> Bytes {
    use ndn_packet::tlv_type;
    use ndn_tlv::TlvWriter;

    let mut nonce = [0u8; 4];
    let _ = getrandom::getrandom(&mut nonce);
    let lifetime_ms = lifetime.as_millis().min(u64::MAX as u128) as u64;
    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::INTEREST, |w| {
        w.write_nested(tlv_type::NAME, |w| {
            for comp in name.components() {
                w.write_tlv(comp.typ, &comp.value);
            }
        });
        w.write_tlv(tlv_type::NONCE, &nonce);
        let (buf, len) = nni_bytes(lifetime_ms);
        w.write_tlv(tlv_type::INTEREST_LIFETIME, &buf[..len]);
    });
    w.finish()
}

fn nni_bytes(val: u64) -> ([u8; 8], usize) {
    let be = val.to_be_bytes();
    if val <= 0xFF {
        ([be[7], 0, 0, 0, 0, 0, 0, 0], 1)
    } else if val <= 0xFFFF {
        ([be[6], be[7], 0, 0, 0, 0, 0, 0], 2)
    } else if val <= 0xFFFF_FFFF {
        ([be[4], be[5], be[6], be[7], 0, 0, 0, 0], 4)
    } else {
        (be, 8)
    }
}

// Anchor unused imports to silence lints when only one of host/peer
// paths is exercised under a given build.
#[allow(dead_code)]
fn _anchor(_: Interest) {}
