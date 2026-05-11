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
//! - [`init`] starts the engine, installs an internal `AppFace`
//!   for future producer registration, and stores the handle in
//!   a process-wide [`OnceLock`].
//! - [`introspect_faces`] / [`introspect_fib`] / [`introspect_cs`]
//!   read the engine's tables directly via `engine.faces()` /
//!   `engine.fib()` / `engine.cs()` and return the dashboard's
//!   view types (`FaceInfo`, `FibEntry`, `CsInfo`).
//! - [`is_active`] tells the rest of the dashboard whether the
//!   in-page engine is running, so the WS poll loop can yield.
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

use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use ndn_engine::{ForwarderEngine, ShutdownHandle, WasmEngineBuilder, WasmEngineConfig};
use ndn_runtime::{Runtime, default_runtime};
use ndn_transport::{Face, FaceError, FaceId, FaceKind};
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use crate::types::{CsInfo, FaceInfo, FibEntry, NextHop};

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
    let (engine, shutdown) = WasmEngineBuilder::new(WasmEngineConfig::default())
        .with_runtime(Arc::clone(&runtime))
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

    // Mount NFD-compatible management on the engine so the dashboard
    // (and any other in-page consumer) can issue `/localhost/nfd/...`
    // Interests through its app face. `mount_management` returns the
    // handler future; we spawn it on the engine's runtime so it
    // shares the same task scheduler as the pipeline.
    {
        let mgmt_cancel = CancellationToken::new();
        let mgmt_config = Arc::new(ndn_config::ForwarderConfig::default());
        let mgmt_handles = ndn_mgmt::MgmtHandles {
            security_is_ephemeral: true,
            command_validator: None,
            localhop_command_validator: None,
            require_signed_commands: false,
            command_replay_cache: None,
            command_response_signer: None,
            log_inspector: None,
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

// ── Introspection — engine state → dashboard view types ─────────────

pub fn introspect_faces() -> Vec<FaceInfo> {
    let Some(h) = handle() else {
        return Vec::new();
    };
    h.engine()
        .faces()
        .face_info()
        .into_iter()
        .map(|fi| FaceInfo {
            face_id: fi.id.0 as u64,
            remote_uri: fi.remote_uri,
            local_uri: fi.local_uri,
            persistency: "Persistent".to_string(),
            kind: Some(format!("{:?}", fi.kind)),
            face_scope: 1,
            link_type: 0,
            mtu: None,
            n_in_interests: 0,
            n_out_interests: 0,
            n_in_data: 0,
            n_out_data: 0,
            n_in_bytes: 0,
            n_out_bytes: 0,
            n_in_nacks: 0,
            n_out_nacks: 0,
        })
        .collect()
}

pub fn introspect_fib() -> Vec<FibEntry> {
    let Some(h) = handle() else {
        return Vec::new();
    };
    h.engine()
        .fib()
        .dump()
        .into_iter()
        .map(|(name, entry)| FibEntry {
            prefix: name.to_string(),
            nexthops: entry
                .nexthops
                .iter()
                .map(|nh| NextHop {
                    face_id: nh.face_id.0 as u64,
                    cost: nh.cost,
                })
                .collect(),
        })
        .collect()
}

pub fn introspect_cs() -> CsInfo {
    let Some(h) = handle() else {
        return CsInfo {
            capacity_bytes: 0,
            n_entries: 0,
            used_bytes: 0,
            hits: 0,
            misses: 0,
            variant: "(no engine)".to_string(),
        };
    };
    let cs = h.engine().cs();
    let stats = cs.stats();
    CsInfo {
        capacity_bytes: cs.capacity().max_bytes as u64,
        n_entries: cs.len() as u64,
        used_bytes: cs.current_bytes() as u64,
        hits: stats.hits,
        misses: stats.misses,
        variant: cs.variant_name().to_string(),
    }
}
