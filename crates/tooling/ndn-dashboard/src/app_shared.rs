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
    RouteAdd {
        prefix: String,
        face_id: u64,
        cost: u64,
    },
    RouteRemove {
        prefix: String,
        face_id: u64,
    },
    StrategySet {
        prefix: String,
        strategy: String,
    },
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
    SecurityEnroll {
        ca_prefix: String,
        challenge_type: String,
        challenge_param: String,
    },
    SecurityTokenAdd(String),
    YubikeyDetect,
    YubikeyGeneratePiv(String),
    DiscoveryConfigSet(String),
    DvrConfigSet(String),
    SchemaRuleAdd(String),
    SchemaRuleRemove(u64),
    SchemaSet(String),
}

// Desktop-only: there is no `ndn-fwd` subprocess to manage on web.
// (Also declared in `app.rs`; the duplication predates the workspace
// split and is left alone here to keep #5 scope tight.)
#[cfg(feature = "desktop")]
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

/// Shared context provided to every view. Coroutine fields that drive
/// out-of-process subprocesses (`router_cmd` — `ndn-fwd` lifecycle;
/// `tool_cmd` — ping/iperf/peek/put runners) are desktop-only since the
/// web build has no subprocess substrate. Views that need them are
/// already cfg-gated to desktop in `views/mod.rs`.
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
    /// Active cert's `valid_until` in Unix-epoch seconds. `None`
    /// when there's no cert (ephemeral identity) or the cert is
    /// flagged permanent. Drives the §3.1 IdentityChip's
    /// Expired / ExpiringSoon transitions and the §2.3 gate panel.
    pub cert_valid_until_unix_s: Signal<Option<u64>>,
    /// Live mgmt-access posture's `require_signed_commands` flag.
    /// `None` until the first `/localhost/nfd/security/policy-get`
    /// poll lands; `Some(false)` drives the UnsignedMgmt chip state.
    pub mgmt_signed_commands_required: Signal<Option<bool>>,
    pub cs_hit_history: Signal<VecDeque<f64>>,
    pub face_throughput: Signal<HashMap<u64, VecDeque<ThroughputSample>>>,
    pub discovery_status: Signal<Option<DiscoveryStatus>>,
    pub dvr_status: Signal<Option<DvrStatus>>,
    pub cmd: Coroutine<DashCmd>,
    #[cfg(feature = "desktop")]
    pub router_cmd: Coroutine<RouterCmd>,
    #[cfg(feature = "desktop")]
    pub tool_cmd: Coroutine<ToolCmd>,
}
