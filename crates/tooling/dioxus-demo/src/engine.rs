//! In-browser ndn-rs node — phase 7: real `ForwarderEngine`.
//!
//! Replaces the phase-4..phase-6 hand-rolled mini-engine with the
//! actual `ndn_engine::ForwarderEngine` driven by [`WasmEngineBuilder`].
//! What lives in this module now is the application-tier glue:
//!
//! - an internal [`AppFace`] that bridges the engine's pipeline with the
//!   demo's consumer/producer state via two mpsc channels,
//! - a pending-Interest map keyed by Data name (for `Engine::express`),
//! - a producer registry (for `Engine::register_producer_local`) that
//!   serves `/<prefix>/counter` Data,
//! - the same external API the rest of the crate already uses
//!   ([`Engine::connect`], [`Engine::new`], [`Engine::add_face`],
//!   [`Engine::express`], [`Engine::register_producer*`]) so the
//!   Dioxus UI, the SharedWorker entrypoint, and the SharedClient
//!   wasm-bindgen wrapper compile unchanged.
//!
//! The PIT, FIB, CS, strategy chain, dispatcher, expiry tasks all
//! live inside `ForwarderEngine`. This module no longer carries
//! its own.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_engine::{
    FibNexthop, ForwarderEngine, ShutdownHandle, WasmEngineBuilder, WasmEngineConfig,
};
use ndn_packet::lp::LpPacket;
use ndn_packet::{Data, Interest, Name, SignatureType};
use ndn_runtime::Runtime;
use ndn_security::{Signer, Validator};
use ndn_tlv::TlvWriter;
use ndn_transport::{ErasedFace, Face, FaceError, FaceId, FaceKind};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::warn;
use web_time::Instant;

#[cfg(target_arch = "wasm32")]
use ndn_face_webtransport_wasm::{BrowserWebTransportFace, WtClientError};

#[cfg(target_arch = "wasm32")]
fn engine_log(msg: &str) {
    web_sys::console::log_1(&format!("[engine] {msg}").into());
}
#[cfg(not(target_arch = "wasm32"))]
fn engine_log(_msg: &str) {}

#[derive(Debug)]
pub enum EngineError {
    #[cfg(target_arch = "wasm32")]
    Connect(WtClientError),
    #[cfg(not(target_arch = "wasm32"))]
    Connect(String),
    Send(String),
    Timeout,
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Connect(e) => write!(f, "connect: {e:?}"),
            EngineError::Send(e) => write!(f, "send: {e}"),
            EngineError::Timeout => write!(f, "timeout"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DataResponse {
    pub data: Arc<Data>,
    pub rtt: Duration,
}

type PendingMap = Mutex<HashMap<String, oneshot::Sender<DataResponse>>>;

/// One registered producer prefix; counter served at `/<prefix>/counter`.
struct Producer {
    counter: Arc<AtomicU64>,
}

/// Internal [`Face`] that bridges the demo's consumer/producer state
/// with the [`ForwarderEngine`] pipeline.
///
/// The face is added to the engine's face table during construction.
/// The engine reads from `from_demo` (Interests + Data the demo
/// pushes) and writes to `to_demo` (Interests + Data the engine
/// dispatches to this face). The demo holds the inverse channel
/// ends.
struct AppFace {
    id: FaceId,
    /// Engine reads here (demo→engine). Wrapped in Mutex because
    /// `Face::recv` takes `&self` and the underlying mpsc receiver
    /// needs &mut.
    from_demo: Mutex<mpsc::Receiver<Bytes>>,
    /// Engine writes here (engine→demo).
    to_demo: mpsc::Sender<Bytes>,
}

impl Face for AppFace {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::App
    }
    fn local_uri(&self) -> Option<String> {
        Some(format!("appface://demo/{}", self.id.0))
    }
    async fn recv(&self) -> Result<Bytes, FaceError> {
        let mut rx = self.from_demo.lock().await;
        rx.recv().await.ok_or(FaceError::Closed)
    }
    async fn send(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.to_demo.send(pkt).await.map_err(|_| FaceError::Closed)
    }
}

/// Phase-7 engine: thin wrapper around `ForwarderEngine` plus the
/// demo's consumer/producer state.
pub struct Engine {
    inner: ForwarderEngine,
    /// Drop drives the engine's cancellation; held so the engine
    /// outlives this struct exactly. Wrapped in Mutex<Option> so
    /// `Drop` can take it for `shutdown().await`-less cleanup —
    /// the engine's tasks observe the CancellationToken and exit.
    _shutdown: ShutdownHandle,
    runtime: Arc<dyn Runtime>,
    /// Demo-side end of the AppFace channel pair.
    to_engine: mpsc::Sender<Bytes>,
    /// AppFace's id inside the engine's face table — used to point
    /// FIB entries at AppFace for locally-served prefixes.
    app_face_id: FaceId,
    /// Optional upstream face id — populated when `connect()` dialed
    /// out a WebTransport face. Default-FIB route `/ → upstream` is
    /// installed at construction.
    upstream_face_id: Option<FaceId>,
    pending: Arc<PendingMap>,
    producers: Arc<RwLock<HashMap<String, Arc<Producer>>>>,
}

impl Engine {
    /// Construct an engine. If `upstream` is `Some`, that face is
    /// installed and a default FIB route (`/ → upstream`) is added so
    /// `Engine::express` reaches the host forwarder. If `None`, the
    /// engine is producer-only / cache-only — typical for the
    /// SharedWorker entrypoint that hosts the engine for tabs.
    pub fn new(runtime: Arc<dyn Runtime>, upstream: Option<Arc<dyn ErasedFace>>) -> Self {
        Self::new_with_security(runtime, upstream, None, None)
    }

    /// Construct the engine with an optional [`Validator`] (for
    /// inbound Data verification) and an optional [`Signer`] (for
    /// mgmt-response Data signing).  Both come from `IdbPib` in the
    /// SharedWorker flow; both default to `None` in test harnesses.
    ///
    /// - `validator = Some(v)` → engine's `ValidationStage` enforces
    ///   signatures against the validator's trust anchors.
    /// - `signer = Some(s)` → mgmt responses on `/localhost/nfd/...`
    ///   are signed by `s` with a real `KeyLocator` rather than the
    ///   fallback `DigestSha256`.
    pub fn new_with_security(
        runtime: Arc<dyn Runtime>,
        upstream: Option<Arc<dyn ErasedFace>>,
        validator: Option<Arc<Validator>>,
        mgmt_response_signer: Option<Arc<dyn Signer>>,
    ) -> Self {
        // Suppress unused-variable warnings on non-wasm builds where
        // mount_management is gated out.
        #[cfg(not(target_arch = "wasm32"))]
        let _ = &mgmt_response_signer;
        let mut builder =
            WasmEngineBuilder::new(WasmEngineConfig::default()).with_runtime(Arc::clone(&runtime));
        if let Some(face) = upstream.as_ref() {
            builder = builder.add_face(Arc::clone(face));
        }
        if let Some(v) = validator.as_ref() {
            builder = builder.with_validator(Arc::clone(v));
        }
        let (engine, shutdown) = builder.build().expect("WasmEngineBuilder build");

        // AppFace channels.
        let (to_engine_tx, to_engine_rx) = mpsc::channel::<Bytes>(64);
        let (from_engine_tx, from_engine_rx) = mpsc::channel::<Bytes>(64);
        let app_face_id = engine.faces().alloc_id();
        let app_face = AppFace {
            id: app_face_id,
            from_demo: Mutex::new(to_engine_rx),
            to_demo: from_engine_tx,
        };
        engine.add_face(app_face, CancellationToken::new());

        let upstream_face_id = upstream.as_ref().map(|f| f.id());
        if let Some(up_id) = upstream_face_id {
            engine.fib().set_nexthops(
                &Name::root(),
                vec![FibNexthop {
                    face_id: up_id,
                    cost: 1,
                }],
            );
        }

        let pending: Arc<PendingMap> = Arc::new(Mutex::new(HashMap::new()));
        let producers = Arc::new(RwLock::new(HashMap::new()));

        spawn_app_recv_pump(
            Arc::clone(&runtime),
            from_engine_rx,
            Arc::clone(&pending),
            Arc::clone(&producers),
            to_engine_tx.clone(),
        );

        // Mount NFD-compatible management — `/localhost/nfd/...` Interests
        // now reach a real dispatcher inside the wasm engine (status,
        // rib/list, faces/list, fib/list, etc.).
        #[cfg(target_arch = "wasm32")]
        {
            let mgmt_cancel = CancellationToken::new();
            let mgmt_config = Arc::new(ndn_config::ForwarderConfig::default());
            let mgmt_handles = ndn_mgmt::MgmtHandles {
                security_is_ephemeral: true,
                command_validator: None,
                localhop_command_validator: None,
                require_signed_commands: false,
                command_replay_cache: None,
                // N.12 — sign control responses with the persisted
                // identity when one exists (worker_main passes a
                // Signer reconstructed from IdbPib's SafeBag).
                // Falls back to DigestSha256 when None.
                command_response_signer: mgmt_response_signer,
                log_inspector: None,
            };
            let fut = ndn_mgmt::mount_management(&engine, mgmt_cancel, mgmt_config, mgmt_handles);
            runtime.spawn(Box::pin(fut));
        }

        Self {
            inner: engine,
            _shutdown: shutdown,
            runtime,
            to_engine: to_engine_tx,
            app_face_id,
            upstream_face_id,
            pending,
            producers,
        }
    }

    /// Tab-side convenience constructor — dial WebTransport upstream,
    /// wrap as the upstream face.
    pub async fn connect(runtime: Arc<dyn Runtime>, url: &str) -> Result<Self, EngineError> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (runtime, url);
            return Err(EngineError::Send("native build path unsupported".into()));
        }

        #[cfg(target_arch = "wasm32")]
        {
            let (clean_url, cert_hashes) = parse_cert_query(url);
            let face = BrowserWebTransportFace::connect(
                FaceId(1),
                &clean_url,
                &cert_hashes,
                Arc::clone(&runtime),
            )
            .await
            .map_err(EngineError::Connect)?;
            let face: Arc<dyn ErasedFace> = Arc::new(face);
            Ok(Self::new(runtime, Some(face)))
        }
    }

    /// Attach an inbound face to the engine. The engine spawns its
    /// own per-face reader + sender tasks. Used by the SharedWorker
    /// entrypoint to register each tab `MessagePort` as a face.
    pub fn add_face<F: Face + 'static>(&self, face: F) {
        self.inner.add_face(face, CancellationToken::new());
    }

    /// Express an Interest, returning the matching Data when it
    /// arrives. Routes through the engine's PIT/FIB/CS pipeline; if
    /// the upstream FIB route is configured, the Interest reaches
    /// the host forwarder.
    pub async fn express(
        &self,
        name: Name,
        lifetime: Duration,
    ) -> Result<DataResponse, EngineError> {
        let key = name.to_string();
        let wire = encode_interest(&name, lifetime, None);

        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(key.clone(), tx);

        let started = Instant::now();
        self.to_engine
            .send(wire)
            .await
            .map_err(|_| EngineError::Send("app face closed".into()))?;

        let timeout = self.runtime.sleep(lifetime + Duration::from_millis(500));
        tokio::select! {
            biased;
            res = rx => {
                let mut resp = res.map_err(|_| EngineError::Timeout)?;
                resp.rtt = started.elapsed();
                Ok(resp)
            }
            _ = timeout => {
                self.pending.lock().await.remove(&key);
                engine_log(&format!("timeout waiting for '{key}'"));
                Err(EngineError::Timeout)
            }
        }
    }

    /// Send a pre-encoded Interest wire. The PIT key must equal the
    /// name the response Data will carry.
    pub async fn express_wire(
        &self,
        wire: Bytes,
        pending_key: String,
        lifetime: Duration,
    ) -> Result<DataResponse, EngineError> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(pending_key.clone(), tx);

        let started = Instant::now();
        self.to_engine
            .send(wire)
            .await
            .map_err(|_| EngineError::Send("app face closed".into()))?;

        let timeout = self.runtime.sleep(lifetime + Duration::from_millis(500));
        tokio::select! {
            biased;
            res = rx => {
                let mut resp = res.map_err(|_| EngineError::Timeout)?;
                resp.rtt = started.elapsed();
                Ok(resp)
            }
            _ = timeout => {
                self.pending.lock().await.remove(&pending_key);
                Err(EngineError::Timeout)
            }
        }
    }

    /// Register a producer prefix locally — adds a FIB entry pointing
    /// `prefix` at the AppFace so inbound Interests for that prefix
    /// reach the demo's recv pump for producer dispatch. Returns the
    /// shared `AtomicU64` backing the `<prefix>/counter` Data.
    pub async fn register_producer_local(&self, prefix: Name) -> Arc<AtomicU64> {
        let counter = Arc::new(AtomicU64::new(0));
        self.producers.write().await.insert(
            prefix.to_string(),
            Arc::new(Producer {
                counter: Arc::clone(&counter),
            }),
        );
        self.inner.fib().set_nexthops(
            &prefix,
            vec![FibNexthop {
                face_id: self.app_face_id,
                cost: 1,
            }],
        );
        counter
    }

    /// Register a producer + send the legacy `/localhost/nfd/rib/register`
    /// Interest upstream. Tab-side use: the demo CA's host forwarder
    /// sees the route announcement.
    pub async fn register_producer(&self, prefix: Name) -> Result<Arc<AtomicU64>, EngineError> {
        let counter = self.register_producer_local(prefix.clone()).await;

        // Splice ControlParameters into the Interest name (legacy NFD form,
        // matching the existing tab-side path).
        let params_blob = encode_control_parameters(&prefix);
        let mut cmd_name: Name = "/localhost/nfd/rib/register"
            .parse()
            .expect("static rib/register name");
        cmd_name = cmd_name.append_component(ndn_packet::NameComponent::generic(params_blob));
        let wire = encode_interest(&cmd_name, Duration::from_millis(2000), None);

        // Fire-and-forget — we don't await the management response, the
        // local registration is what matters for the demo.
        let _ = self.to_engine.send(wire).await;
        Ok(counter)
    }

    /// Spec-compliant signed prefix registration via `/localhop/nfd/rib/register`.
    pub async fn register_producer_signed(
        &self,
        prefix: Name,
        identity: &crate::enroll::EnrolledIdentity,
    ) -> Result<Arc<AtomicU64>, EngineError> {
        use ndn_packet::encode::InterestBuilder;

        let counter = self.register_producer_local(prefix.clone()).await;

        let params_blob = encode_control_parameters(&prefix);
        let cmd_name: Name = "/localhop/nfd/rib/register"
            .parse()
            .expect("static rib/register name");

        let signer = Arc::clone(&identity.signer);
        let key_locator = Some(identity.cert_name.clone());
        let sig_type = signer.sig_type();
        let wire = InterestBuilder::new(cmd_name)
            .lifetime(Duration::from_millis(2000))
            .must_be_fresh()
            .app_parameters(params_blob.to_vec())
            .sign_fallible::<_, _, ndn_security::error::TrustError>(
                sig_type,
                key_locator.as_ref(),
                move |region| {
                    let signer = Arc::clone(&signer);
                    let region = region.to_vec();
                    async move { signer.sign(&region).await }
                },
            )
            .await
            .map_err(|e| EngineError::Send(format!("sign: {e}")))?;

        let _ = self.to_engine.send(wire).await;
        Ok(counter)
    }

    pub fn forwarder(&self) -> &ForwarderEngine {
        &self.inner
    }

    pub fn upstream_face_id(&self) -> Option<FaceId> {
        self.upstream_face_id
    }
}

// ── App-face recv pump ────────────────────────────────────────────────────────

/// Dispatch packets the engine sends to the AppFace. Interests
/// arrive when a registered producer prefix matched; Data arrives
/// when an `Engine::express` resolved through the engine pipeline.
fn spawn_app_recv_pump(
    runtime: Arc<dyn Runtime>,
    mut from_engine: mpsc::Receiver<Bytes>,
    pending: Arc<PendingMap>,
    producers: Arc<RwLock<HashMap<String, Arc<Producer>>>>,
    to_engine: mpsc::Sender<Bytes>,
) {
    runtime.spawn(Box::pin(async move {
        loop {
            let raw = match from_engine.recv().await {
                Some(b) => b,
                None => break,
            };
            let inner = match LpPacket::decode(raw.clone()) {
                Ok(lp) => lp.fragment.unwrap_or(raw),
                Err(_) => raw,
            };

            if let Ok(data) = Data::decode(inner.clone()) {
                let key = data.name.to_string();
                if let Some(tx) = pending.lock().await.remove(&key) {
                    let _ = tx.send(DataResponse {
                        data: Arc::new(data),
                        rtt: Duration::ZERO,
                    });
                }
                continue;
            }

            if let Ok(interest) = Interest::decode(inner) {
                let registry = producers.read().await;
                let key_str = interest.name.to_string();
                let matched = registry
                    .iter()
                    .find(|(prefix, _)| key_str.starts_with(prefix.as_str()))
                    .map(|(_, p)| Arc::clone(p));
                drop(registry);
                if let Some(producer) = matched {
                    let n = producer.counter.fetch_add(1, Ordering::Relaxed) + 1;
                    let payload = n.to_string();
                    // 60s FreshnessPeriod so the engine's CS keeps the Data
                    // long enough to satisfy subsequent Interests (the
                    // phase-6 cache-hit witness needs this).
                    let wire = encode_data_digest_sha256(
                        &interest.name,
                        payload.as_bytes(),
                        Duration::from_secs(60),
                    );
                    if let Err(e) = to_engine.send(wire).await {
                        warn!(target: "demo.engine", error=?e, "produce reply send failed");
                    }
                }
            }
        }
    }));
}

// ── Wire encoders (wasm-friendly: pure-Rust SHA-256, no ring) ────────────────

fn encode_interest(name: &Name, lifetime: Duration, app_params: Option<&[u8]>) -> Bytes {
    use ndn_packet::tlv_type;

    let mut nonce = [0u8; 4];
    let _ = getrandom::getrandom(&mut nonce);
    let lifetime_ms = lifetime.as_millis().min(u64::MAX as u128) as u64;

    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::INTEREST, |w| {
        if let Some(params) = app_params {
            let mut params_tlv = TlvWriter::new();
            params_tlv.write_tlv(tlv_type::APP_PARAMETERS, params);
            let params_wire = params_tlv.finish();
            let digest = Sha256::digest(&params_wire);

            w.write_nested(tlv_type::NAME, |w| {
                for comp in name.components() {
                    w.write_tlv(comp.typ, &comp.value);
                }
                w.write_tlv(tlv_type::PARAMETERS_SHA256, digest.as_slice());
            });
            w.write_tlv(tlv_type::NONCE, &nonce);
            write_nni(w, tlv_type::INTEREST_LIFETIME, lifetime_ms);
            w.write_tlv(tlv_type::APP_PARAMETERS, params);
        } else {
            w.write_nested(tlv_type::NAME, |w| {
                for comp in name.components() {
                    w.write_tlv(comp.typ, &comp.value);
                }
            });
            w.write_tlv(tlv_type::NONCE, &nonce);
            write_nni(w, tlv_type::INTEREST_LIFETIME, lifetime_ms);
        }
    });
    w.finish()
}

fn encode_data_digest_sha256(name: &Name, content: &[u8], freshness: Duration) -> Bytes {
    use ndn_packet::tlv_type;

    let mut inner = TlvWriter::new();
    inner.write_nested(tlv_type::NAME, |w| {
        for comp in name.components() {
            w.write_tlv(comp.typ, &comp.value);
        }
    });
    inner.write_nested(tlv_type::META_INFO, |w| {
        write_nni(w, tlv_type::FRESHNESS_PERIOD, freshness.as_millis() as u64);
    });
    inner.write_tlv(tlv_type::CONTENT, content);
    let inner_bytes = inner.finish();

    let mut sig_info = TlvWriter::new();
    sig_info.write_nested(tlv_type::SIGNATURE_INFO, |w| {
        write_nni(
            w,
            tlv_type::SIGNATURE_TYPE,
            SignatureType::DigestSha256.code(),
        );
    });
    let sig_info_bytes = sig_info.finish();

    let mut signed_region = Vec::with_capacity(inner_bytes.len() + sig_info_bytes.len());
    signed_region.extend_from_slice(&inner_bytes);
    signed_region.extend_from_slice(&sig_info_bytes);
    let sig_value = Sha256::digest(&signed_region);

    let mut w = TlvWriter::new();
    w.write_nested(tlv_type::DATA, |w| {
        w.write_raw(&signed_region);
        w.write_tlv(tlv_type::SIGNATURE_VALUE, sig_value.as_slice());
    });
    w.finish()
}

fn encode_control_parameters(name: &Name) -> Bytes {
    use ndn_packet::tlv_type;
    const CONTROL_PARAMETERS: u64 = 0x68;

    let mut w = TlvWriter::new();
    w.write_nested(CONTROL_PARAMETERS, |w| {
        w.write_nested(tlv_type::NAME, |w| {
            for comp in name.components() {
                w.write_tlv(comp.typ, &comp.value);
            }
        });
    });
    w.finish()
}

fn write_nni(w: &mut TlvWriter, typ: u64, val: u64) {
    let (buf, len) = nni_bytes(val);
    w.write_tlv(typ, &buf[..len]);
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

#[cfg(target_arch = "wasm32")]
fn parse_cert_query(url: &str) -> (String, Vec<[u8; 32]>) {
    let Some((base, query)) = url.split_once('?') else {
        return (url.to_owned(), Vec::new());
    };
    let mut hashes = Vec::new();
    let mut keep = Vec::new();
    for pair in query.split('&') {
        if let Some(hex) = pair.strip_prefix("cert=")
            && let Some(h) = decode_sha256_hex(hex)
        {
            hashes.push(h);
            continue;
        }
        if !pair.is_empty() {
            keep.push(pair);
        }
    }
    let clean = if keep.is_empty() {
        base.to_owned()
    } else {
        format!("{base}?{}", keep.join("&"))
    };
    (clean, hashes)
}

#[cfg(target_arch = "wasm32")]
fn decode_sha256_hex(hex: &str) -> Option<[u8; 32]> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in bytes.chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}
