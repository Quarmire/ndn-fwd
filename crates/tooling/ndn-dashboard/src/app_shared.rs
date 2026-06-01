//! Types shared between the desktop (`app.rs`) and web (`app_web.rs`) modules;
//! compiles on both native and wasm32 targets.

use std::collections::{HashMap, VecDeque};

use dioxus::prelude::*;

use crate::types::*;
use crate::views::View;

pub static ROUTER_LOG: GlobalSignal<VecDeque<LogEntry>> = Signal::global(VecDeque::new);
pub static LOG_FILTER: GlobalSignal<String> = Signal::global(String::new);
pub static ROUTER_RUNNING: GlobalSignal<bool> = Signal::global(|| false);
pub static PENDING_LOG_FILTER: GlobalSignal<Option<String>> = Signal::global(|| None);
pub static LAST_LOG_SEQ: GlobalSignal<u64> = Signal::global(|| 0);
pub static LOG_SPLIT_MODE: GlobalSignal<u8> = Signal::global(|| 0u8);
pub static LOG_SPLIT_RATIO: GlobalSignal<u32> = Signal::global(|| 50u32);
pub static CONFIG_PRESETS: GlobalSignal<Vec<(String, String)>> = Signal::global(Vec::new);
pub static ACTIVE_VIEW: GlobalSignal<View> = Signal::global(|| View::Overview);
/// Deep-link target the Security view consumes one-shot when set.
pub static ACTIVE_SECURITY_TAB: GlobalSignal<Option<u8>> = Signal::global(|| None);
/// Reactive generation counter for the (Dioxus-free) operator keyring. Views
/// that render keyring state read it to subscribe; UI mutation handlers call
/// [`bump_keyring_gen`] so those views re-render after generate/import/switch.
pub static KEYRING_GEN: GlobalSignal<u32> = Signal::global(|| 0);

/// Whether the operator dismissed the trust-status banner. Reset whenever the
/// keyring changes (see [`bump_keyring_gen`]) so the banner re-evaluates after
/// any identity action instead of staying hidden forever.
pub static TRUST_BANNER_DISMISSED: GlobalSignal<bool> = Signal::global(|| false);

/// Set true to open the "trust this identity on the forwarder" (pre-provision)
/// flow; the Identities tab consumes it.
pub static PREPROVISION_OPEN: GlobalSignal<bool> = Signal::global(|| false);

/// Bump [`KEYRING_GEN`] so keyring-displaying views re-render. Call from a
/// component/event context after mutating `operator_keyring`.
pub fn bump_keyring_gen() {
    let next = KEYRING_GEN.peek().wrapping_add(1);
    *KEYRING_GEN.write() = next;
    // A keyring change is a meaningful posture change — re-show the banner.
    *TRUST_BANNER_DISMISSED.write() = false;
}
pub static SAFEBAG_IMPORT_STATE: GlobalSignal<crate::views::safebag_import::SafeBagImportState> =
    Signal::global(crate::views::safebag_import::SafeBagImportState::default);
pub static ENROLLMENT_WIZARD_STATE: GlobalSignal<
    crate::views::enrollment_wizard::EnrollmentWizardState,
> = Signal::global(crate::views::enrollment_wizard::EnrollmentWizardState::default);
pub static KEY_ROTATION_STATE: GlobalSignal<crate::views::key_rotation::KeyRotationState> =
    Signal::global(crate::views::key_rotation::KeyRotationState::default);
/// §5.5 CA pending-approvals list state. Populated by
/// `DashCmd::CaListApprovals`'s handler after `ca/list-approvals`.
pub static CA_APPROVALS_STATE: GlobalSignal<crate::views::ca_approvals::CaApprovalsState> =
    Signal::global(crate::views::ca_approvals::CaApprovalsState::default);
/// Mobile-only: whether the hamburger-triggered sidebar drawer is
/// open. Ignored on desktop (the sidebar is always present there).
pub static SIDEBAR_OPEN: GlobalSignal<bool> = Signal::global(|| false);
/// Mobile-only: whether the conn-bar's URL field + Connect button
/// are expanded. Default false so the bar only shows status
/// indicators; tap the connection-state badge to expand.
pub static CONN_FIELD_OPEN: GlobalSignal<bool> = Signal::global(|| false);
/// §5.2 enrollment-wizard live result state. The Issue button
/// transitions the wizard to step 5 (Result) and the
/// `DashCmd::SecurityEnroll` handler writes the CA's response (or
/// error) here. The wizard reads this signal to render outcome.
pub static ENROLLMENT_RESULT: GlobalSignal<
    Option<crate::views::enrollment_wizard::EnrollmentResult>,
> = Signal::global(|| None);
pub static DARK_MODE: GlobalSignal<bool> = Signal::global(|| true);

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
}

pub static TOASTS: GlobalSignal<VecDeque<Toast>> = Signal::global(VecDeque::new);
static TOAST_ID: GlobalSignal<u64> = Signal::global(|| 0u64);

pub fn push_toast(msg: impl Into<String>, level: ToastLevel) {
    // Wasm has no monotonic clock by default — `std::time::Instant::now()`
    // *panics* on wasm32, which previously killed Dioxus reactivity for
    // the rest of the page lifetime on every `push_toast` call. The
    // `created` field was dead code (no auto-dismiss consumer read it),
    // so removing it eliminates the panic without needing `web-time` as
    // a non-optional dep. If/when auto-dismiss lands, swap to
    // `web_time::Instant` which has the same API and works on both.
    let mut id = TOAST_ID.write();
    *id += 1;
    TOASTS.write().push_back(Toast {
        id: *id,
        message: msg.into(),
        level,
    });
}

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
    /// Poll immediately (out of the 3s cadence). Sent by the live event
    /// subscriber (`run_ws_subscriber`) so external changes show up at once.
    RefreshNow,
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
    SecurityPolicySet(MgmtAccessPolicySnapshot),
    SecurityValidateTrace(String),
    SecurityAnchorAdd {
        name: String,
        fingerprint_hex: String,
        cert_wire_hex: String,
    },
    SecurityAnchorRemove {
        name: String,
    },
    SecuritySafebagImport {
        name: String,
        safebag_wire: Vec<u8>,
        passphrase: String,
    },
    /// §5.5 list pending CA device-approval requests.
    CaListApprovals,
    /// §5.5 approve a pending request.
    CaApprove {
        request_id: String,
    },
    /// §5.5 deny a pending request with a reason.
    CaDeny {
        request_id: String,
        reason: String,
    },
}

#[cfg(feature = "desktop")]
#[derive(Debug)]
pub enum RouterCmd {
    Start(Option<String>),
    Stop,
}

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

#[cfg(feature = "desktop")]
use crate::tool_runner::ToolCmd;

/// `router_cmd` / `tool_cmd` are desktop-only (no subprocess substrate on web).
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
    /// `None` when ephemeral or flagged permanent.
    pub cert_valid_until_unix_s: Signal<Option<u64>>,
    /// `None` until the first `policy-get` poll lands.
    pub mgmt_signed_commands_required: Signal<Option<bool>>,
    /// `None` until the first `policy-get` response lands.
    pub mgmt_access_policy: Signal<Option<MgmtAccessPolicySnapshot>>,
    /// `Some(false)` ⇒ NFD / YaNFD; degrade to `Unsupported` posture.
    pub security_surface_supported: Signal<Option<bool>>,
    pub validation_stats: Signal<Option<ValidationStats>>,
    pub validation_history: Signal<VecDeque<(u64, u64)>>,
    pub trust_validation: Signal<Option<(String, TrustValidationResult)>>,
    pub trust_inspector_open: Signal<bool>,
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
