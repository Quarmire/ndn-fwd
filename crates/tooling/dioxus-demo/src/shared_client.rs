//! Tab-side SharedWorker client (Phase 6 witness driver).
//!
//! Exposed as a `#[wasm_bindgen]` class so a Playwright spec can
//! instantiate it from JS and drive Interest expression directly,
//! bypassing the Dioxus UI. The class wraps a
//! [`SharedWorkerProxyFace`] talking to the per-origin worker; every
//! Interest goes over the shared engine, so two tabs of the same
//! origin observe the worker's PIT and CS.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use js_sys::Uint8Array;
use ndn_face_shared_worker::SharedWorkerProxyFace;
use ndn_packet::lp::LpPacket;
use ndn_packet::{Data, Interest, Name};
use ndn_runtime::default_runtime;
use ndn_transport::{Face, FaceError, FaceId};
use tokio::sync::{Mutex, oneshot};
use wasm_bindgen::prelude::*;

fn client_log(msg: &str) {
    web_sys::console::log_1(&format!("[shared-client] {msg}").into());
}

type PendingMap = Mutex<HashMap<String, oneshot::Sender<Bytes>>>;

#[wasm_bindgen]
pub struct SharedClient {
    face: Arc<SharedWorkerProxyFace>,
    pending: Arc<PendingMap>,
}

#[wasm_bindgen]
impl SharedClient {
    /// Connect to the per-origin SharedWorker at `worker_url` (joining
    /// the existing instance if other tabs are already connected) and
    /// install a recv pump that wakes pending [`SharedClient::express_interest`]
    /// callers as Data arrives back through the proxy face.
    #[wasm_bindgen(constructor)]
    pub fn new(worker_url: String, worker_name: Option<String>) -> Result<SharedClient, JsValue> {
        console_error_panic_hook::set_once();
        let runtime = default_runtime();
        let face = SharedWorkerProxyFace::connect(
            FaceId(1),
            &worker_url,
            worker_name.as_deref(),
            Arc::clone(&runtime),
        )
        .map_err(|e| JsValue::from_str(&format!("proxy connect: {e}")))?;
        let face = Arc::new(face);
        let pending: Arc<PendingMap> = Arc::new(Mutex::new(HashMap::new()));

        let face_pump = Arc::clone(&face);
        let pending_pump = Arc::clone(&pending);
        runtime.spawn(Box::pin(async move {
            loop {
                let raw = match Face::recv(&*face_pump).await {
                    Ok(b) => b,
                    Err(_) => break,
                };
                let inner = LpPacket::decode(raw.clone())
                    .ok()
                    .and_then(|lp| lp.fragment)
                    .unwrap_or(raw);
                if let Ok(data) = Data::decode(inner.clone()) {
                    // Longest-prefix match against pending Interests so
                    // dataset responses (Data named `<base>/v=.../seg=N`)
                    // satisfy the bare `<base>` Interest the witness or
                    // mgmt client issued.
                    let mut pending_lock = pending_pump.lock().await;
                    let best: Option<String> = pending_lock
                        .keys()
                        .filter_map(|k| {
                            let n: Name = k.parse().ok()?;
                            if data.name.has_prefix(&n) {
                                Some((n.len(), k.clone()))
                            } else {
                                None
                            }
                        })
                        .max_by_key(|(len, _)| *len)
                        .map(|(_, k)| k);
                    if let Some(k) = best
                        && let Some(tx) = pending_lock.remove(&k)
                    {
                        drop(pending_lock);
                        // Deliver the full Data wire so callers can
                        // either decode it themselves (e.g. a witness
                        // verifying SignatureInfo) or use the
                        // express_interest convenience that strips out
                        // the Content for them.
                        let _ = tx.send(inner);
                    }
                }
            }
        }));

        Ok(SharedClient { face, pending })
    }

    /// Send an Interest for `name`, wait up to `lifetime_ms` for the
    /// matching Data, and resolve to its `content` bytes. Rejects with
    /// "timeout" when no Data arrives.
    pub async fn express_interest(
        &self,
        name: String,
        lifetime_ms: u32,
    ) -> Result<Uint8Array, JsValue> {
        let wire = self.express_interest_wire(name, lifetime_ms).await?;
        // Decode the full Data wire and extract just the Content for
        // back-compat with callers that only want the payload.
        let bytes = bytes::Bytes::copy_from_slice(&wire.to_vec());
        let data =
            Data::decode(bytes).map_err(|e| JsValue::from_str(&format!("decode Data: {e:?}")))?;
        let payload = data.content().cloned().unwrap_or_default();
        let arr = Uint8Array::new_with_length(payload.len() as u32);
        arr.copy_from(&payload);
        Ok(arr)
    }

    /// Like [`Self::express_interest`] but returns the **full Data
    /// wire** (post-NDNLPv2 unwrap) — Name + MetaInfo + Content +
    /// SignatureInfo + SignatureValue.  Witnesses that need to
    /// verify the signature on the mgmt response use this.
    pub async fn express_interest_wire(
        &self,
        name: String,
        lifetime_ms: u32,
    ) -> Result<Uint8Array, JsValue> {
        let parsed: Name = name.parse().map_err(|_| JsValue::from_str("bad name"))?;
        let key = parsed.to_string();
        let lifetime = Duration::from_millis(lifetime_ms as u64);
        let wire = encode_interest(&parsed, lifetime);

        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(key.clone(), tx);

        client_log(&format!("express {key}"));
        Face::send(&*self.face, wire)
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
                self.pending.lock().await.remove(&key);
                Err(JsValue::from_str("timeout"))
            }
        }
    }
}

/// Minimal Interest encoder mirroring the one in `crate::engine` —
/// duplicated here to keep this module self-contained and avoid
/// pulling the engine module into the SharedClient build path.
///
/// Always sets `CanBePrefix` and `MustBeFresh` so dataset responses
/// (NFD `*/list` verbs) — whose Data names carry a `/v=/seg=` suffix
/// and FreshnessPeriod=0 — can satisfy this Interest. Exact-name
/// producers are unaffected.
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
        w.write_tlv(tlv_type::CAN_BE_PREFIX, &[]);
        w.write_tlv(tlv_type::MUST_BE_FRESH, &[]);
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

// Suppress unused_imports for Interest under a possible compile path.
#[allow(dead_code)]
fn _interest_anchor(_: Interest) {}
