//! Types shared between the desktop (`app.rs`) and web (`app_web.rs`) modules.
//!
//! Views reference these types via `use crate::app_shared::*` (or re-exports).
//! This module compiles on both native and wasm32 targets.

use std::collections::{HashMap, VecDeque};

use dioxus::prelude::*;

use crate::types::*;
use crate::views::View;

// ── Global reactive state ────────────────────────────────────────────────────

pub static ROUTER_LOG: GlobalSignal<VecDeque<LogEntry>> = Signal::global(VecDeque::new);
pub static LOG_FILTER: GlobalSignal<String> = Signal::global(String::new);
pub static ROUTER_RUNNING: GlobalSignal<bool> = Signal::global(|| false);
pub static PENDING_LOG_FILTER: GlobalSignal<Option<String>> = Signal::global(|| None);
pub static LAST_LOG_SEQ: GlobalSignal<u64> = Signal::global(|| 0);
pub static LOG_SPLIT_MODE: GlobalSignal<u8> = Signal::global(|| 0u8);
pub static LOG_SPLIT_RATIO: GlobalSignal<u32> = Signal::global(|| 50u32);
pub static CONFIG_PRESETS: GlobalSignal<Vec<(String, String)>> = Signal::global(Vec::new);
pub static ACTIVE_VIEW: GlobalSignal<View> = Signal::global(|| View::Overview);
pub static DARK_MODE: GlobalSignal<bool> = Signal::global(|| true);

// ── Toast notifications ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum ToastLevel {
    Info,
    Success,
    Warning,
    Error,
}

impl ToastLevel {
    pub fn css_class(self) -> &'static str {
        match self {
            ToastLevel::Info => "toast-info",
            ToastLevel::Success => "toast-success",
            ToastLevel::Warning => "toast-warning",
            ToastLevel::Error => "toast-error",
        }
    }
    pub fn icon(self) -> &'static str {
        match self {
            ToastLevel::Info => "ℹ",
            ToastLevel::Success => "✓",
            ToastLevel::Warning => "⚠",
            ToastLevel::Error => "✕",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Toast {
    pub id: u64,
    pub message: String,
    pub level: ToastLevel,
    pub created: std::time::Instant,
}

pub static TOASTS: GlobalSignal<VecDeque<Toast>> = Signal::global(VecDeque::new);
static TOAST_ID: GlobalSignal<u64> = Signal::global(|| 0u64);

pub fn push_toast(msg: impl Into<String>, level: ToastLevel) {
    let mut id = TOAST_ID.write();
    *id += 1;
    TOASTS.write().push_back(Toast {
        id: *id,
        message: msg.into(),
        level,
        created: std::time::Instant::now(),
    });
}

// ── Commands ─────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum DashCmd {
    FaceCreate(String),
    FaceDestroy(u64),
    RouteAdd { prefix: String, face_id: u64, cost: u64 },
    RouteRemove { prefix: String, face_id: u64 },
    StrategySet { prefix: String, strategy: String },
    StrategyUnset(String),
    CsCapacity(u64),
    CsErase(String),
    Shutdown,
    Reconnect,
    RefreshConfig,
    RecordStart,
    RecordStop,
    RecordClear,
    ReplaySession,
    SecurityGenerate(String),
    SecurityKeyDelete(String),
    SecurityEnroll { ca_prefix: String, challenge_type: String, challenge_param: String },
    SecurityTokenAdd(String),
    YubikeyDetect,
    YubikeyGeneratePiv(String),
    DiscoveryConfigSet(String),
    DvrConfigSet(String),
    SchemaRuleAdd(String),
    SchemaRuleRemove(u64),
    SchemaSet(String),
}

#[derive(Debug)]
pub enum RouterCmd {
    Start(Option<String>),
    Stop,
}

// ── Connection state ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ConnState {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

impl ConnState {
    pub fn badge_class(&self) -> &'static str {
        match self {
            ConnState::Connected => "badge badge-green",
            ConnState::Connecting => "badge badge-yellow",
            ConnState::Disconnected => "badge badge-gray",
            ConnState::Error(_) => "badge badge-red",
        }
    }
    pub fn label(&self) -> String {
        match self {
            ConnState::Connected => "Connected".into(),
            ConnState::Connecting => "Connecting…".into(),
            ConnState::Disconnected => "Disconnected".into(),
            ConnState::Error(e) => format!("Error: {e}"),
        }
    }
}

// ── Shared context ───────────────────────────────────────────────────────────

#[cfg(feature = "desktop")]
use crate::tool_runner::ToolCmd;

// Stub for web builds where tool_runner doesn't exist
#[cfg(not(feature = "desktop"))]
#[derive(Debug)]
pub enum ToolCmd {}

#[derive(Clone, Copy)]
pub struct AppCtx {
    #[allow(dead_code)]
    pub conn: Signal<ConnState>,
    pub status: Signal<Option<ForwarderStatus>>,
    pub faces: Signal<Vec<FaceInfo>>,
    pub routes: Signal<Vec<FibEntry>>,
    pub rib_entries: Signal<Vec<RibEntryInfo>>,
    pub cs: Signal<Option<CsInfo>>,
    pub strategies: Signal<Vec<StrategyEntry>>,
    pub counters: Signal<Vec<FaceCounter>>,
    pub measurements: Signal<Vec<MeasurementEntry>>,
    pub config_toml: Signal<String>,
    pub throughput: Signal<VecDeque<ThroughputSample>>,
    #[allow(dead_code)]
    pub prev_counters: Signal<ThroughputSample>,
    pub session_log: Signal<Vec<SessionEntry>>,
    pub recording: Signal<bool>,
    pub neighbors: Signal<Vec<NeighborInfo>>,
    pub security_keys: Signal<Vec<SecurityKeyInfo>>,
    pub security_anchors: Signal<Vec<AnchorInfo>>,
    pub ca_info: Signal<Option<CaInfo>>,
    pub schema_rules: Signal<Vec<SchemaRuleInfo>>,
    pub yubikey_status: Signal<Option<String>>,
    pub identity_name: Signal<String>,
    pub identity_is_ephemeral: Signal<bool>,
    pub identity_pib_path: Signal<Option<String>>,
    pub cs_hit_history: Signal<VecDeque<f64>>,
    pub face_throughput: Signal<HashMap<u64, VecDeque<ThroughputSample>>>,
    pub discovery_status: Signal<Option<DiscoveryStatus>>,
    pub dvr_status: Signal<Option<DvrStatus>>,
    pub router_cmd: Coroutine<RouterCmd>,
    pub cmd: Coroutine<DashCmd>,
    pub tool_cmd: Coroutine<ToolCmd>,
}
