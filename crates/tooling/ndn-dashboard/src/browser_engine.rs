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
    /// Held to prevent the AppFace recv side from observing
    /// channel-closed; the dashboard reuses this sender when it
    /// later wants to publish into the engine.
    _to_engine_keepalive: mpsc::Sender<Bytes>,
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
    let (from_engine_tx, _from_engine_rx) = mpsc::channel::<Bytes>(64);
    let app_face_id = engine.faces().alloc_id();
    let app_face = AppFace {
        id: app_face_id,
        rx: Mutex::new(to_engine_rx),
        tx: from_engine_tx,
    };
    engine.add_face(app_face, CancellationToken::new());

    let handle = EngineHandle {
        inner: Arc::new(EngineInner {
            engine,
            _shutdown: shutdown,
            app_face_id,
            runtime,
            _to_engine_keepalive: to_engine_tx,
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
