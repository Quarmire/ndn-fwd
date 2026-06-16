//! In-page WASM ndn-engine integration. Gated on `--features browser-engine`;
//! the dashboard hosts its own [`ndn_engine::ForwarderEngine`] in the browser
//! tab and answers `/localhost/nfd/...` over an internal app face.

#![cfg(all(target_arch = "wasm32", feature = "browser-engine"))]

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use bytes::Bytes;
use ndn_engine::{ForwarderEngine, ShutdownHandle, WasmEngineBuilder, WasmEngineConfig};
use ndn_runtime::{Runtime, default_runtime};
use ndn_transport::{FaceError, FaceId, FaceKind, Transport};
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

pub struct LocalMgmtChannels {
    /// App→engine (Interests).
    pub to_engine: mpsc::Sender<Bytes>,
    /// Engine→app (Data).
    pub from_engine: mpsc::Receiver<Bytes>,
}

fn elog(msg: &str) {
    web_sys::console::log_1(&format!("[browser-engine] {msg}").into());
}

static HANDLE: OnceLock<EngineHandle> = OnceLock::new();

#[derive(Clone)]
pub struct EngineHandle {
    inner: Arc<EngineInner>,
}

struct EngineInner {
    engine: ForwarderEngine,
    /// Keeps engine tasks alive until the page closes.
    _shutdown: ShutdownHandle,
    app_face_id: FaceId,
    runtime: Arc<dyn Runtime>,
    /// Kept as a keepalive so the engine's AppFace `recv` doesn't observe a
    /// closed channel before the dashboard takes a handle.
    to_engine_tx: mpsc::Sender<Bytes>,
    /// Taken once by the local mgmt client; further callers see `None`.
    from_engine_rx: Mutex<Option<mpsc::Receiver<Bytes>>>,
}

struct AppFace {
    id: FaceId,
    rx: Mutex<mpsc::Receiver<Bytes>>,
    tx: mpsc::Sender<Bytes>,
}

impl Transport for AppFace {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::App
    }
    fn local_uri(&self) -> Option<String> {
        Some(format!("appface://dashboard/{}", self.id.0))
    }
    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.rx.lock().await.recv().await.ok_or(FaceError::Closed)
    }
    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.tx.send(pkt).await.map_err(|_| FaceError::Closed)
    }
}

/// Initialize the in-page engine. Idempotent.
pub fn init() -> EngineHandle {
    if let Some(h) = HANDLE.get() {
        return h.clone();
    }
    let runtime: Arc<dyn Runtime> = default_runtime();

    let rl_table: ndn_ratelimit::SharedPolicyTable =
        Arc::new(ndn_ratelimit::RateLimitPolicyTable::new());
    let rl_hook: ndn_engine::SharedRateLimitHook = Arc::new(
        ndn_ratelimit::EngineRateLimitHook::new(Arc::clone(&rl_table)),
    );
    let rl_handler = Arc::new(ndn_ratelimit::RateLimitMgmtHandler::new(Arc::clone(
        &rl_table,
    )));

    let (engine, shutdown) = WasmEngineBuilder::new(WasmEngineConfig::default())
        .with_runtime(Arc::clone(&runtime))
        .with_rate_limit_hook(Some(Arc::clone(&rl_hook)))
        .build()
        .expect("WasmEngineBuilder build");

    let (to_engine_tx, to_engine_rx) = mpsc::channel::<Bytes>(64);
    let (from_engine_tx, from_engine_rx) = mpsc::channel::<Bytes>(64);
    let app_face_id = engine.faces().alloc_id();
    let app_face = AppFace {
        id: app_face_id,
        rx: Mutex::new(to_engine_rx),
        tx: from_engine_tx,
    };
    engine.add_face(app_face, CancellationToken::new());

    // FEC pipeline stages aren't wired in-page yet; installing the handler
    // means mgmt verbs answer correctly instead of `STATUS 404`.
    let coding_table: ndn_coding::SharedPolicyTable =
        Arc::new(ndn_coding::CodingPolicyTable::new());
    let coding_handler = Arc::new(ndn_coding::CodingMgmtHandler::new(coding_table));

    // Mount the NFD-compatible mgmt server so the dashboard issues
    // `/localhost/nfd/...` over its app face.
    {
        let mgmt_cancel = CancellationToken::new();
        let mgmt_config = Arc::new(ndn_config::ForwarderConfig::default());
        let replay_cache: ndn_mgmt::CommandReplayCache = Arc::new(StdMutex::new(HashMap::new()));
        let mgmt_handles = ndn_mgmt::MgmtHandles {
            extra_modules: Vec::new(),
            face_provisioners: Vec::new(),
            control_surfaces: Vec::new(),
            security_is_ephemeral: true,
            command_validator: None,
            localhop_command_validator: None,
            require_signed_commands: false,
            command_replay_cache: Some(replay_cache),
            command_response_signer: None,
            log_inspector: None,
            coding_handler: Some(coding_handler as Arc<dyn ndn_mgmt::CodingHandler>),
            rate_limit_handler: Some(rl_handler as Arc<dyn ndn_mgmt::RateLimitMgmtBackend>),
            compute_handler: None,
            webtransport_status_handler: None,
            ble_handler: None,
            approval_handler: None,
        };
        let fut = ndn_mgmt::mount_management(&engine, mgmt_cancel, mgmt_config, mgmt_handles);
        runtime.spawn(Box::pin(fut));
    }

    let handle = EngineHandle {
        inner: Arc::new(EngineInner {
            engine,
            _shutdown: shutdown,
            app_face_id,
            runtime,
            to_engine_tx,
            from_engine_rx: Mutex::new(Some(from_engine_rx)),
        }),
    };
    elog(&format!(
        "engine started; app face id={}",
        handle.inner.app_face_id.0
    ));
    let _ = HANDLE.set(handle.clone());
    handle
}

pub fn handle() -> Option<EngineHandle> {
    HANDLE.get().cloned()
}

pub fn is_active() -> bool {
    HANDLE.get().is_some()
}

impl EngineHandle {
    pub fn engine(&self) -> &ForwarderEngine {
        &self.inner.engine
    }
    pub fn runtime(&self) -> Arc<dyn Runtime> {
        Arc::clone(&self.inner.runtime)
    }
    pub fn app_face_id(&self) -> FaceId {
        self.inner.app_face_id
    }

    /// Single-consumer — the first caller wins; subsequent calls return `None`.
    pub async fn take_mgmt_channels(&self) -> Option<LocalMgmtChannels> {
        let rx = self.inner.from_engine_rx.lock().await.take()?;
        Some(LocalMgmtChannels {
            to_engine: self.inner.to_engine_tx.clone(),
            from_engine: rx,
        })
    }

    /// Open a Web Bluetooth central face and attach it to the in-page engine.
    ///
    /// Pops the browser device chooser, so it must run under a user gesture.
    /// Requires the dashboard wasm bundle to be built with
    /// `--cfg=web_sys_unstable_apis`; otherwise the face reports `Unsupported`.
    pub async fn connect_ble(&self) -> Result<FaceId, String> {
        let id = self.inner.engine.faces().alloc_id();
        // `None` framing → auto-select via the capability characteristic.
        let face = ndn_face_webble::WebBleFace::connect(id, Arc::clone(&self.inner.runtime), None)
            .await
            .map_err(|e| e.to_string())?;
        self.inner.engine.add_face(face, CancellationToken::new());
        elog(&format!("BLE face connected id={}", id.0));
        Ok(id)
    }
}

/// Fire-and-forget BLE connect for UI click handlers. Spawns on the local
/// runtime; transient activation from the originating click stays valid for
/// the `requestDevice` chooser. No-op (logged) if the in-page engine is off.
pub fn spawn_connect_ble() {
    let Some(h) = handle() else {
        elog("connect_ble: no in-page engine (run with ?engine=local)");
        return;
    };
    wasm_bindgen_futures::spawn_local(async move {
        match h.connect_ble().await {
            Ok(id) => elog(&format!("BLE connect ok; face id={}", id.0)),
            Err(e) => elog(&format!("BLE connect failed: {e}")),
        }
    });
}
