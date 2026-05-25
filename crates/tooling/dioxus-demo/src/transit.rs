//! Browser-as-transit witness: wasm-bindgen [`TransitHost`] and
//! [`TransitPeer`] entry points. The peer dials a WebRTC datachannel to the
//! host, whose `ForwarderEngine` exercises its full PIT/FIB/CS pipeline
//! between the inbound [`WebRtcFaceAdapter`] and an internal `AppFace`
//! producer.

use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use js_sys::Uint8Array;
use ndn_face_webrtc::{IceServers, PendingFace, SessionDescription, WebRtcConnector};
use ndn_packet::lp::LpPacket;
use ndn_packet::{Data, Name};
use ndn_runtime::default_runtime;
use ndn_transport::{FaceError, FaceId, Transport};
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

/// Host-tab entry point: a real `ForwarderEngine` plus a connector that
/// negotiates each incoming peer.
#[wasm_bindgen]
pub struct TransitHost {
    engine: Arc<Engine>,
    connector: WebRtcConnector,
    /// Set by `accept_offer`, consumed by `finalize_peer` when the channel
    /// opens.
    pending: RefCell<Option<PendingFace>>,
}

#[wasm_bindgen]
impl TransitHost {
    /// `producers` is a comma-separated list of prefixes registered
    /// locally. The app pump serves `<prefix>/counter` Data with a
    /// monotonically increasing payload.
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

    /// Accept a JSON-encoded SDP offer and return the JSON-encoded answer.
    /// The `WebRtcFace` itself is materialised by `finalize_peer`.
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

    /// Await the SCTP channel and add the resulting `WebRtcFace` to the engine.
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

/// Peer-tab entry point: drives the WebRtcConnector from the offerer side
/// and expresses Interests over the resulting channel.
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

    /// Accept the host's SDP answer and finalize the channel; `express`
    /// becomes usable afterwards.
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

        let pending_data = Arc::clone(&self.pending_data);
        runtime.spawn(Box::pin(async move {
            loop {
                let raw = match Transport::recv_bytes(&*adapter).await {
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
        Transport::send_bytes(&*face, wire)
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
