//! In-page WASM ndn-engine integration (Phase 7).
//!
//! When the dashboard is loaded with `?engine=local` (web build,
//! `--features browser-engine`), it hosts its own
//! [`ndn_engine::ForwarderEngine`] in the browser tab via
//! `WasmEngineBuilder` instead of speaking WebSocket to a remote
//! forwarder. The dashboard *is* the forwarder — PIT, FIB, CS,
//! strategy chain, dispatcher, expiry tasks all run in the page.
//!
//! # What's wired
//!
//! - [`init`] starts the engine, mounts `ndn_mgmt::mount_management`,
//!   wires an `AppFace` for the dashboard's local mgmt client, and
//!   stores the handle in a process-wide [`OnceLock`].
//! - [`EngineHandle::take_mgmt_channels`] hands the (Sender,
//!   Receiver) pair for that app face to the local-transport
//!   variant of [`crate::ws_mgmt::WsMgmtClient`].  The dashboard
//!   then issues `/localhost/nfd/...` Interests over the same wire
//!   path it uses against a remote forwarder — no introspection
//!   short-circuit anymore.
//! - [`is_active`] tells the rest of the dashboard whether the
//!   in-page engine is running.
//!
//! # What's deferred
//!
//! - **Mgmt-protocol wire parity.** The full NFD-spec mgmt server
//!   (~3.5k LOC in `binaries/spec/ndn-fwd/src/mgmt_ndn.rs`) is
//!   not ported. Mutations from the dashboard while in
//!   browser-engine mode go through the engine's API directly
//!   (`engine.fib().add_nexthop`, etc.) — short-circuiting the
//!   wire layer is fine because the dashboard owns the engine.
//! - **Upstream face dialing** (WebTransport / WebRTC / Shared-
//!   Worker connect-out) is not wired. The in-page engine starts
//!   cache-only / app-face-only. Reference impl for adding an
//!   upstream WT face: `crates/tooling/dioxus-demo/src/engine.rs`
//!   (`Engine::connect`).

#![cfg(all(target_arch = "wasm32", feature = "browser-engine"))]

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use bytes::Bytes;
use ndn_engine::{ForwarderEngine, ShutdownHandle, WasmEngineBuilder, WasmEngineConfig};
use ndn_runtime::{Runtime, default_runtime};
use ndn_transport::{Face, FaceError, FaceId, FaceKind};
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

/// Channel pair an `ndn_mgmt::MgmtHandles`-backed client uses to speak
/// the NFD management protocol against the in-page engine over the
/// dashboard's internal app face.
pub struct LocalMgmtChannels {
    /// Sender for app→engine packets (Interests).
    pub to_engine: mpsc::Sender<Bytes>,
    /// Receiver for engine→app packets (Data).
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
    /// Holding the shutdown handle keeps the engine alive for the
    /// lifetime of the page. Drop on tab close cancels the engine
    /// tasks via the `CancellationToken` it owns.
    _shutdown: ShutdownHandle,
    app_face_id: FaceId,
    runtime: Arc<dyn Runtime>,
    /// App→engine sender used by the dashboard's local mgmt client.
    /// Cloned out via [`EngineHandle::mgmt_tx`]; kept here as the
    /// keepalive so the engine's AppFace `recv` never observes a
    /// closed channel before the dashboard takes a handle.
    to_engine_tx: mpsc::Sender<Bytes>,
    /// Engine→app receiver — taken once by the local mgmt client.
    /// Wrapped in `Mutex<Option<_>>` so `take` works through a
    /// shared `Arc`. After the take, further callers see `None`.
    from_engine_rx: Mutex<Option<mpsc::Receiver<Bytes>>>,
}

/// Internal app-face — bridges the engine's pipeline with future
/// dashboard-internal producers (e.g. a `/dashboard/...` namespace
/// that publishes engine status as Data). Today it's installed
/// but quiescent.
struct AppFace {
    id: FaceId,
    rx: Mutex<mpsc::Receiver<Bytes>>,
    tx: mpsc::Sender<Bytes>,
}

impl Face for AppFace {
    fn id(&self) -> FaceId {
        self.id
    }
    fn kind(&self) -> FaceKind {
        FaceKind::App
    }
    fn local_uri(&self) -> Option<String> {
        Some(format!("appface://dashboard/{}", self.id.0))
    }
    async fn recv(&self) -> Result<Bytes, FaceError> {
        self.rx.lock().await.recv().await.ok_or(FaceError::Closed)
    }
    async fn send(&self, pkt: Bytes) -> Result<(), FaceError> {
        self.tx.send(pkt).await.map_err(|_| FaceError::Closed)
    }
}

/// Initialize the in-page engine. Idempotent.
pub fn init() -> EngineHandle {
    if let Some(h) = HANDLE.get() {
        return h.clone();
    }
    let runtime: Arc<dyn Runtime> = default_runtime();

    // ── Rate-limit table + engine hook ──────────────────────────────
    // Empty table at boot; the dashboard can install cells at runtime
    // via `/localhost/nfd/rate-limit/set`. The same `Arc` is shared
    // between the pipeline hook (which consults the table on every
    // packet) and the mgmt handler (which mutates the table).
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

    // ── Coding policy table + handler ───────────────────────────────
    // Same shape as rate-limit: empty table at boot, populated at
    // runtime via `/localhost/nfd/coding/set`. The in-page engine
    // doesn't ship FEC encode/decode stages yet (the pipeline hook
    // wiring is a follow-up), but installing the handler now means
    // mgmt verbs answer correctly instead of `STATUS 404`.
    let coding_table: ndn_coding::SharedPolicyTable =
        Arc::new(ndn_coding::CodingPolicyTable::new());
    let coding_handler = Arc::new(ndn_coding::CodingMgmtHandler::new(coding_table));

    // Mount NFD-compatible management on the engine so the dashboard
    // (and any other in-page consumer) can issue `/localhost/nfd/...`
    // Interests through its app face. `mount_management` returns the
    // handler future; we spawn it on the engine's runtime so it
    // shares the same task scheduler as the pipeline.
    {
        let mgmt_cancel = CancellationToken::new();
        let mgmt_config = Arc::new(ndn_config::ForwarderConfig::default());
        // N.10 — replay-protection cache. Cheap to keep enabled; only
        // touched when a signed command actually validates, which is
        // never in the default in-page config (no trust anchors).
        // Wiring it in now means signed-command support is a one-line
        // flip when the dashboard grows a trust-anchor flow.
        let replay_cache: ndn_mgmt::CommandReplayCache = Arc::new(StdMutex::new(HashMap::new()));
        let mgmt_handles = ndn_mgmt::MgmtHandles {
            // The in-page engine has no persistent identity (no FilePib
            // on wasm). Marks the security identity as ephemeral so the
            // `security/identity/status` verb reports it correctly.
            security_is_ephemeral: true,
            // No trust anchors in the page — commands run unauthenticated.
            // Operators who care about isolation should run the engine
            // out-of-process and connect over WebSocket.
            command_validator: None,
            localhop_command_validator: None,
            require_signed_commands: false,
            command_replay_cache: Some(replay_cache),
            // No daemon identity to sign responses with; falls back to
            // DigestSha256 which all ndn-rs clients accept.
            command_response_signer: None,
            // `log/*` verbs need a tracing_subscriber reload handle the
            // page doesn't own. Wiring an in-page log inspector is
            // tracked separately.
            log_inspector: None,
            coding_handler: Some(coding_handler as Arc<dyn ndn_mgmt::CodingHandler>),
            rate_limit_handler: Some(rl_handler as Arc<dyn ndn_mgmt::RateLimitMgmtBackend>),
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

    /// Take the (Sender, Receiver) pair that wraps the in-page engine's
    /// app face. Single-consumer — the first caller wins; subsequent
    /// calls return `None`. The dashboard's `WsMgmtClient::new_local`
    /// is the canonical caller.
    pub async fn take_mgmt_channels(&self) -> Option<LocalMgmtChannels> {
        let rx = self.inner.from_engine_rx.lock().await.take()?;
        Some(LocalMgmtChannels {
            to_engine: self.inner.to_engine_tx.clone(),
            from_engine: rx,
        })
    }
}
