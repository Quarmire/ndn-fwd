use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use dioxus::html::HasFileData as _;
use dioxus::prelude::*;
use futures::StreamExt as _;
use ndn_ipc::MgmtClient;

use crate::forwarder_proc;
use crate::security_chains::SchemaJournalKind;
use crate::tool_runner::{
    TOOL_INSTANCES, TOOL_RESULTS, ToolCmd, ToolInstanceState, ToolParams, ToolResultEntry,
    build_result_entry, chrono_now, next_result_id,
};
use crate::tray;

use crate::{
    settings::DASH_SETTINGS,
    styles::CSS,
    types::*,
    views::{
        View,
        config::Config,
        dashboard_config::DashboardConfig,
        fleet::Fleet,
        logs::Logs,
        modals::StartRouterModal,
        onboarding::{Onboarding, is_onboarded},
        overview::Overview,
        radio::Radio,
        routing::Routing,
        security::Security,
        session::Session,
        strategy::Strategy,
        tools::Tools,
    },
};

pub static ROUTER_LOG: GlobalSignal<VecDeque<LogEntry>> = Signal::global(VecDeque::new);
pub static LOG_FILTER: GlobalSignal<String> = Signal::global(String::new);
pub static ROUTER_RUNNING: GlobalSignal<bool> = Signal::global(|| false);
pub static PENDING_LOG_FILTER: GlobalSignal<Option<String>> = Signal::global(|| None);
/// Reset to 0 on each new connection so that the first poll fetches all buffered lines.
pub static LAST_LOG_SEQ: GlobalSignal<u64> = Signal::global(|| 0);
/// 0=Single, 1=Horizontal, 2=Vertical.
pub static LOG_SPLIT_MODE: GlobalSignal<u8> = Signal::global(|| 0u8);
/// Percent for the first pane, 20–80.
pub static LOG_SPLIT_RATIO: GlobalSignal<u32> = Signal::global(|| 50u32);
pub static CONFIG_PRESETS: GlobalSignal<Vec<(String, String)>> = Signal::global(Vec::new);

pub static ACTIVE_VIEW: GlobalSignal<crate::views::View> =
    Signal::global(|| crate::views::View::Overview);

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
    pub created: std::time::Instant,
}

pub static TOASTS: GlobalSignal<std::collections::VecDeque<Toast>> =
    Signal::global(std::collections::VecDeque::new);
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

/// Operations sent to the background polling coroutine.
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
    /// Poll the forwarder immediately (out of the 3s cadence). Sent by the
    /// live face-event subscriber (`notify_sub`) so external changes show up
    /// at once.
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
    /// `params` is a URL query string (`"hello_interval_base_ms=5000&liveness_miss_count=3"`).
    DiscoveryConfigSet(String),
    /// `params` is a URL query string (`"update_interval_ms=30000&route_ttl_ms=90000"`).
    DvrConfigSet(String),
    /// `rule` is `"<data_pattern> => <key_pattern>"`.
    SchemaRuleAdd(String),
    SchemaRuleRemove(u64),
    /// `rules` is newline-separated rule strings; empty input clears all rules.
    SchemaSet(String),
    SecurityPolicySet(MgmtAccessPolicySnapshot),
    SecurityValidateTrace(String),
    /// `cert_wire_hex` may be empty, in which case the handler journals intent only.
    SecurityAnchorAdd {
        name: String,
        fingerprint_hex: String,
        cert_wire_hex: String,
    },
    /// Fires `/localhost/nfd/security/anchor-remove`; `name` is the anchor's
    /// cert key name.
    SecurityAnchorRemove {
        name: String,
    },
    /// Fires `/localhost/nfd/security/safebag-import`; `safebag_wire` is raw TLV bytes
    /// (the client method hex-encodes both halves of the wire envelope).
    SecuritySafebagImport {
        name: String,
        safebag_wire: Vec<u8>,
        passphrase: String,
    },
    /// §5.5 — fire `/localhost/nfd/ca/list-approvals` and push the
    /// decoded rows into `CA_APPROVALS_STATE`. Operator-driven (no
    /// auto-poll); see `views/ca_approvals.rs` for the rationale.
    CaListApprovals,
    /// §5.5 — fire `/localhost/nfd/ca/approve` for a single pending
    /// request. The handler refreshes the approvals list on success.
    CaApprove {
        request_id: String,
    },
    /// §5.5 — fire `/localhost/nfd/ca/deny` for a pending request.
    /// `reason` defaults to "denied" when empty.
    CaDeny {
        request_id: String,
        reason: String,
    },
}

/// Commands sent to the router-management coroutine.
#[derive(Debug)]
pub enum RouterCmd {
    /// `None` uses built-in defaults; `Some(path)` passes `--config <path>`.
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

/// All reactive state exposed to child view components via `use_context`.
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
    /// May be the ephemeral name when no PIB is loaded.
    pub identity_name: Signal<String>,
    pub identity_is_ephemeral: Signal<bool>,
    /// `None` when ephemeral.
    pub identity_pib_path: Signal<Option<String>>,
    /// `None` when ephemeral or the cert is flagged permanent.
    pub cert_valid_until_unix_s: Signal<Option<u64>>,
    /// `None` until the first `policy-get` poll lands.
    pub mgmt_signed_commands_required: Signal<Option<bool>>,
    /// Does the connected forwarder implement ndn-rs's `security/*` mgmt extensions?
    /// `None` ⇒ unknown; `Some(false)` ⇒ NFD / YaNFD returned 404.
    pub security_surface_supported: Signal<Option<bool>>,
    /// `None` until the first `policy-get` response lands.
    pub mgmt_access_policy: Signal<Option<MgmtAccessPolicySnapshot>>,
    /// `None` until the first `security/validation-stats` poll returns.
    pub validation_stats: Signal<Option<ValidationStats>>,
    /// 60-sample (3-min @ 3 s) sparkline history of `(verified_per_sec, rejected_per_sec)`.
    pub validation_history: Signal<VecDeque<(u64, u64)>>,
    /// Last `security/validate` result keyed by the cert name the operator clicked.
    pub trust_validation: Signal<Option<(String, TrustValidationResult)>>,
    pub trust_inspector_open: Signal<bool>,
    pub cs_hit_history: Signal<VecDeque<f64>>,
    /// 60 samples × 3 s = 3 min window.
    pub face_throughput: Signal<HashMap<u64, VecDeque<ThroughputSample>>>,
    /// `None` if router does not support.
    pub discovery_status: Signal<Option<DiscoveryStatus>>,
    /// `None` if DVR is not active.
    pub dvr_status: Signal<Option<DvrStatus>>,
    pub router_cmd: Coroutine<RouterCmd>,
    pub cmd: Coroutine<DashCmd>,
    pub tool_cmd: Coroutine<ToolCmd>,
}

/// Process a single tool event synchronously so the `select!` loop can drain a
/// burst into a single Dioxus render cycle, avoiding edit-notification overflow
/// on the WebView under iperf load.
fn process_tool_event(
    inst_id: u32,
    ev_opt: Option<ndn_tools_core::common::ToolEvent>,
    handles: &mut HashMap<u32, tokio::task::AbortHandle>,
    srv_ping_id: u32,
    srv_iperf_id: u32,
) {
    use ndn_tools_core::common::ToolData;
    match ev_opt {
        None => {
            handles.remove(&inst_id);
            if inst_id != srv_ping_id && inst_id != srv_iperf_id {
                let ts = chrono_now();
                let max_results = DASH_SETTINGS.peek().results_max_entries.max(1);
                let mut insts = TOOL_INSTANCES.write();
                if let Some(inst) = insts.get_mut(&inst_id) {
                    inst.running = false;
                    let has_data = inst.iperf_summary.is_some()
                        || inst.ping_summary.is_some()
                        || !inst.tp_history.is_empty();
                    if has_data {
                        let entry = build_result_entry(inst, &ts);
                        let mut results = TOOL_RESULTS.write();
                        results.push_front(entry);
                        while results.len() > max_results {
                            results.pop_back();
                        }
                    }
                }
            }
        }
        Some(ev) => {
            if inst_id == srv_iperf_id {
                if let Some(ToolData::IperfClientConnected {
                    flow_id,
                    duration_secs,
                    sign_mode,
                    payload_size,
                    reverse,
                }) = &ev.structured
                {
                    let ts = chrono_now();
                    let mode = if *reverse { "reverse" } else { "forward" };
                    let entry = ToolResultEntry {
                        id: next_result_id(),
                        ts,
                        tool: "iperf-server",
                        label: format!("session {flow_id}"),
                        run_summary: format!(
                            "{mode}  ·  sign={sign_mode}  ·  size={payload_size}B"
                        ),
                        throughput_bps: None,
                        bytes: None,
                        duration_secs: Some(*duration_secs as f64),
                        loss_pct: None,
                        rtt_avg_us: None,
                        summary_lines: vec![
                            format!("mode={mode}"),
                            format!("sign={sign_mode}"),
                            format!("size={payload_size}B"),
                        ],
                        intervals: vec![],
                        ping_rtts: vec![],
                    };
                    let max_results = DASH_SETTINGS.peek().results_max_entries;
                    let mut results = TOOL_RESULTS.write();
                    results.push_front(entry);
                    while results.len() > max_results {
                        results.pop_back();
                    }
                }
            } else if inst_id != srv_ping_id {
                let mut insts = TOOL_INSTANCES.write();
                if let Some(inst) = insts.get_mut(&inst_id) {
                    match &ev.structured {
                        Some(ToolData::IperfInterval { throughput_bps, .. }) => {
                            inst.tp_history.push(*throughput_bps);
                            inst.elapsed_secs = inst.start_time.elapsed().as_secs_f64();
                            if inst.tp_history.len() > 480 {
                                inst.tp_history.remove(0);
                            }
                        }
                        Some(ToolData::IperfSummary { .. }) => {
                            inst.iperf_summary = ev.structured.clone();
                        }
                        Some(ToolData::PingResult { rtt_us, .. }) => {
                            inst.current_rtt_us = Some(*rtt_us);
                            inst.ping_rtts.push(*rtt_us);
                            if inst.ping_rtts.len() > 500 {
                                inst.ping_rtts.remove(0);
                            }
                        }
                        Some(ToolData::PingSummary { .. }) => {
                            inst.ping_summary = ev.structured.clone();
                        }
                        _ => {}
                    }
                    inst.output.push_back(ev);
                    if inst.output.len() > 200 {
                        inst.output.pop_front();
                    }
                }
            }
        }
    }
}

#[component]
pub fn App() -> Element {
    use_hook(tray::setup);

    let mut conn_state: Signal<ConnState> = use_signal(|| ConnState::Disconnected);
    let mut socket_path: Signal<String> = use_signal(default_socket_path);
    let status: Signal<Option<ForwarderStatus>> = use_signal(|| None);
    let faces: Signal<Vec<FaceInfo>> = use_signal(Vec::new);
    let routes: Signal<Vec<FibEntry>> = use_signal(Vec::new);
    let rib_entries: Signal<Vec<RibEntryInfo>> = use_signal(Vec::new);
    let cs: Signal<Option<CsInfo>> = use_signal(|| None);
    let strategies: Signal<Vec<StrategyEntry>> = use_signal(Vec::new);
    let counters: Signal<Vec<FaceCounter>> = use_signal(Vec::new);
    let measurements: Signal<Vec<MeasurementEntry>> = use_signal(Vec::new);
    let config_toml: Signal<String> = use_signal(String::new);
    let throughput: Signal<VecDeque<ThroughputSample>> = use_signal(VecDeque::new);
    let prev_counters: Signal<ThroughputSample> = use_signal(ThroughputSample::default);
    let session_log: Signal<Vec<SessionEntry>> = use_signal(Vec::new);
    let recording: Signal<bool> = use_signal(|| false);
    let neighbors: Signal<Vec<NeighborInfo>> = use_signal(Vec::new);
    let security_keys: Signal<Vec<SecurityKeyInfo>> = use_signal(Vec::new);
    let security_anchors: Signal<Vec<AnchorInfo>> = use_signal(Vec::new);
    let ca_info: Signal<Option<CaInfo>> = use_signal(|| None);
    let schema_rules: Signal<Vec<SchemaRuleInfo>> = use_signal(Vec::new);
    let yubikey_status: Signal<Option<String>> = use_signal(|| None);
    let identity_name: Signal<String> = use_signal(String::new);
    let identity_is_ephemeral: Signal<bool> = use_signal(|| false);
    let identity_pib_path: Signal<Option<String>> = use_signal(|| None);
    let cert_valid_until_unix_s: Signal<Option<u64>> = use_signal(|| None);
    let mgmt_signed_commands_required: Signal<Option<bool>> = use_signal(|| None);
    let mgmt_access_policy: Signal<Option<MgmtAccessPolicySnapshot>> = use_signal(|| None);
    let security_surface_supported: Signal<Option<bool>> = use_signal(|| None);
    let validation_stats: Signal<Option<ValidationStats>> = use_signal(|| None);
    let validation_history: Signal<VecDeque<(u64, u64)>> = use_signal(VecDeque::new);
    let trust_validation: Signal<Option<(String, TrustValidationResult)>> = use_signal(|| None);
    let trust_inspector_open: Signal<bool> = use_signal(|| false);

    use_hook(|| {
        let key_locator = ndn_packet::Name::root()
            .append(b"local")
            .append(b"ndn-dashboard")
            .append(b"KEY")
            .append(b"ephemeral");
        crate::security_chains::init_audit_chain(audit_chain_dir(), key_locator.clone());
        crate::security_chains::init_schema_journal(schema_journal_dir(), key_locator);
    });
    let cs_hit_history: Signal<VecDeque<f64>> = use_signal(VecDeque::new);
    let face_throughput: Signal<HashMap<u64, VecDeque<ThroughputSample>>> =
        use_signal(HashMap::new);
    let face_prev_ctr: Signal<HashMap<u64, ThroughputSample>> = use_signal(HashMap::new);
    let discovery_status: Signal<Option<DiscoveryStatus>> = use_signal(|| None);
    let dvr_status: Signal<Option<DvrStatus>> = use_signal(|| None);
    let mut error_msg: Signal<Option<String>> = use_signal(|| None);
    let mut show_onboarding: Signal<bool> = use_signal(|| !is_onboarded());
    let mut show_start_modal: Signal<bool> = use_signal(|| false);
    let mut show_gear_menu: Signal<bool> = use_signal(|| false);
    // Buckets the user has collapsed in the sidebar; all expanded by default.
    let collapsed_buckets: Signal<HashSet<crate::views::Bucket>> = use_signal(HashSet::new);

    let (srv_cmd_tx, srv_cmd_rx) = tokio::sync::mpsc::unbounded_channel::<ToolCmd>();
    let srv_cmd_tx_arc = std::sync::Arc::new(srv_cmd_tx);
    let srv_cmd_rx_cell = std::sync::Arc::new(std::sync::Mutex::new(Some(srv_cmd_rx)));

    let srv_cmd_tx_arc_r = srv_cmd_tx_arc.clone();
    let router_cmd = use_coroutine(move |mut rx: UnboundedReceiver<RouterCmd>| {
        let srv_cmd_tx = srv_cmd_tx_arc_r.clone();
        async move {
            let mut proc: Option<forwarder_proc::RouterProc> = None;
            let mut check = tokio::time::interval(Duration::from_millis(500));

            loop {
                tokio::select! {
                    _ = check.tick() => {
                        if let Some(ref mut p) = proc {
                            if !p.is_running() {
                                proc = None;
                                *ROUTER_RUNNING.write() = false;
                                let _ = srv_cmd_tx.send(ToolCmd::StopPingServer);
                                let _ = srv_cmd_tx.send(ToolCmd::StopIperfServer);
                            } else {
                                let lines = p.drain_logs();
                                if !lines.is_empty() {
                                    let mut log = ROUTER_LOG.write();
                                    for entry in lines {
                                        log.push_back(entry);
                                        if log.len() > 2000 { log.pop_front(); }
                                    }
                                }
                            }
                        }
                    }
                    Some(cmd) = rx.next() => {
                        match cmd {
                            RouterCmd::Start(config_path) => {
                                if proc.is_none() {
                                    let prof = crate::forwarder_profile::selected_profile();
                                    match forwarder_proc::find_binary_for(prof) {
                                        Some(bin) => {
                                            match forwarder_proc::RouterProc::start(&bin, config_path.as_deref()).await {
                                                Ok(p) => {
                                                    *ROUTER_RUNNING.write() = true;
                                                    proc = Some(p);

                                                    tokio::time::sleep(Duration::from_millis(800)).await;

                                                    let s = DASH_SETTINGS.peek().clone();
                                                    if s.ping_server_auto  { let _ = srv_cmd_tx.send(ToolCmd::StartPingServer);  }
                                                    if s.iperf_server_auto { let _ = srv_cmd_tx.send(ToolCmd::StartIperfServer); }
                                                }
                                                Err(e) => tracing::error!("start router: {e}"),
                                            }
                                        }
                                        None => tracing::warn!(
                                            forwarder = %prof.human_label(),
                                            binary = prof.binary_name(),
                                            "forwarder binary not found in PATH",
                                        ),
                                    }
                                }
                            }
                            RouterCmd::Stop => {
                                let _ = srv_cmd_tx.send(ToolCmd::StopPingServer);
                                let _ = srv_cmd_tx.send(ToolCmd::StopIperfServer);
                                if let Some(ref mut p) = proc {
                                    p.kill().await;
                                }
                                proc = None;
                                *ROUTER_RUNNING.write() = false;
                            }
                        }
                    }
                }
            }
        }
    });

    use_coroutine(move |_: UnboundedReceiver<()>| async move {
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        loop {
            interval.tick().await;

            {
                let now = std::time::Instant::now();
                if TOASTS
                    .read()
                    .iter()
                    .any(|t| now.duration_since(t.created).as_secs() >= 5)
                {
                    TOASTS
                        .write()
                        .retain(|t| now.duration_since(t.created).as_secs() < 5);
                }
            }

            let connected = matches!(*conn_state.read(), ConnState::Connected);
            let running = *ROUTER_RUNNING.read();
            tray::update_state(connected, running);

            while let Some(tc) = tray::poll_menu_event() {
                match tc {
                    tray::TrayCmd::StartRouter => router_cmd.send(RouterCmd::Start(None)),
                    tray::TrayCmd::StopRouter => router_cmd.send(RouterCmd::Stop),
                    tray::TrayCmd::OpenDashboard => { /* window is always open */ }
                    tray::TrayCmd::OpenTools => {
                        *ACTIVE_VIEW.write() = View::Tools;
                    }
                    tray::TrayCmd::SendFile => {
                        *ACTIVE_VIEW.write() = View::Tools;
                    }
                    tray::TrayCmd::Quit => {
                        router_cmd.send(RouterCmd::Stop);
                        std::process::exit(0);
                    }
                }
            }
        }
    });

    let cmd = use_coroutine(move |mut rx: UnboundedReceiver<DashCmd>| async move {
        loop {
            conn_state.set(ConnState::Connecting);
            let path = socket_path.peek().clone();

            let client = match MgmtClient::connect(&path).await {
                // Gate: when the operator has provisioned a signing key into the
                // dashboard, sign mgmt commands through its custodian; otherwise
                // keep the DigestSha256 default. Datasets stay unsigned either way.
                Ok(c) => match crate::operator_keyring::command_signer() {
                    Some(signer) => c.with_signer(signer),
                    None => c,
                },
                Err(e) => {
                    conn_state.set(ConnState::Error(e.to_string()));
                    let sleep = tokio::time::sleep(Duration::from_secs(3));
                    tokio::pin!(sleep);
                    loop {
                        tokio::select! {
                            _ = &mut sleep => break,
                            Some(cmd) = rx.next() => {
                                if matches!(cmd, DashCmd::Reconnect) { break }
                            }
                        }
                    }
                    continue;
                }
            };

            conn_state.set(ConnState::Connected);
            error_msg.set(None);
            // A *successful* new connection (or an explicit Reconnect that
            // reaches this point) re-fires the security gate. Resetting
            // acceptance here — rather than at the top of the loop — means a
            // forwarder we can't reach no longer wipes the operator's
            // acknowledgement on every 3s retry tick, which previously made
            // the gate impossible to dismiss while disconnected.
            crate::security_state::reset_acceptance();
            *LAST_LOG_SEQ.write() = 0;

            // The engine owns the connected client: the poll loop drives it
            // (forwarding plane via `poll_forwarding`) while commands and the
            // not-yet-modeled datasets borrow it back via `client`/`client_mut`.
            let mut engine = ndn_dashboard_core::DashboardEngine::new(
                crate::native_mgmt::NativeMgmtClient(client),
            );

            if let Err(e) = poll_all(
                &mut engine,
                status,
                faces,
                routes,
                rib_entries,
                cs,
                strategies,
                counters,
                measurements,
                config_toml,
                throughput,
                prev_counters,
                neighbors,
                security_keys,
                security_anchors,
                ca_info,
                schema_rules,
                cs_hit_history,
                face_throughput,
                face_prev_ctr,
                discovery_status,
                dvr_status,
                identity_name,
                identity_is_ephemeral,
                identity_pib_path,
                cert_valid_until_unix_s,
                mgmt_signed_commands_required,
                mgmt_access_policy,
                security_surface_supported,
                validation_stats,
                validation_history,
            )
            .await
            {
                conn_state.set(ConnState::Disconnected);
                error_msg.set(Some(e));
                // Back off before retrying. The socket accepted us but the
                // forwarder's management responses don't decode (e.g. a
                // non-ndn-rs forwarder listening on this socket, or a
                // half-open socket). Without a delay this spins
                // connect-succeeds / poll-fails in a tight loop, flooding the
                // UI with reconnect churn. Interruptible by an explicit
                // Reconnect, matching the connect-failure path above.
                let sleep = tokio::time::sleep(Duration::from_secs(3));
                tokio::pin!(sleep);
                loop {
                    tokio::select! {
                        _ = &mut sleep => break,
                        Some(cmd) = rx.next() => {
                            if matches!(cmd, DashCmd::Reconnect) { break }
                        }
                    }
                }
                continue;
            }

            let mut interval = tokio::time::interval(Duration::from_secs(3));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await;

            'session: loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = poll_all(&mut engine, status, faces, routes, rib_entries, cs, strategies, counters, measurements, config_toml, throughput, prev_counters, neighbors, security_keys, security_anchors, ca_info, schema_rules, cs_hit_history, face_throughput, face_prev_ctr, discovery_status, dvr_status, identity_name, identity_is_ephemeral, identity_pib_path, cert_valid_until_unix_s, mgmt_signed_commands_required, mgmt_access_policy, security_surface_supported, validation_stats, validation_history).await {
                            conn_state.set(ConnState::Disconnected);
                            error_msg.set(Some(e));
                            break 'session;
                        }
                    }
                    Some(cmd_msg) = rx.next() => {
                        match cmd_msg {
                            DashCmd::Reconnect => break 'session,
                            // Event-driven immediate poll (notify_sub) — same
                            // refresh as an interval tick, off-cadence.
                            DashCmd::RefreshNow => {
                                if let Err(e) = poll_all(&mut engine, status, faces, routes, rib_entries, cs, strategies, counters, measurements, config_toml, throughput, prev_counters, neighbors, security_keys, security_anchors, ca_info, schema_rules, cs_hit_history, face_throughput, face_prev_ctr, discovery_status, dvr_status, identity_name, identity_is_ephemeral, identity_pib_path, cert_valid_until_unix_s, mgmt_signed_commands_required, mgmt_access_policy, security_surface_supported, validation_stats, validation_history).await {
                                    conn_state.set(ConnState::Disconnected);
                                    error_msg.set(Some(e));
                                    break 'session;
                                }
                            }
                            _ => {
                                run_cmd(cmd_msg, &engine, status, faces, routes, rib_entries, cs, strategies, counters, measurements, error_msg, config_toml, throughput, prev_counters, session_log, recording, neighbors, security_keys, security_anchors, ca_info, schema_rules, yubikey_status, cs_hit_history, face_throughput, face_prev_ctr, discovery_status, dvr_status, identity_name, identity_is_ephemeral, identity_pib_path, cert_valid_until_unix_s, mgmt_signed_commands_required, mgmt_access_policy, security_surface_supported, validation_stats, validation_history, trust_validation).await;
                                // Immediate post-command refresh — moved out of run_cmd (which now
                                // takes a shared &engine) into the loop, which owns the &mut engine.
                                // Best-effort: a failure surfaces on the next interval tick.
                                let _ = poll_all(&mut engine, status, faces, routes, rib_entries, cs, strategies, counters, measurements, config_toml, throughput, prev_counters, neighbors, security_keys, security_anchors, ca_info, schema_rules, cs_hit_history, face_throughput, face_prev_ctr, discovery_status, dvr_status, identity_name, identity_is_ephemeral, identity_pib_path, cert_valid_until_unix_s, mgmt_signed_commands_required, mgmt_access_policy, security_surface_supported, validation_stats, validation_history).await;
                            }
                        }
                    }
                }
            }
        }
    });

    // Live event subscriber: long-polls the forwarder's faces/rib/strategy
    // notification streams (one connection each) and sends `RefreshNow` so
    // external changes appear without waiting for the 3s poll.
    use_coroutine(move |_rx: UnboundedReceiver<()>| async move {
        let subs = crate::notify_sub::MODULES
            .map(|m| crate::notify_sub::run_subscriber(m, socket_path, cmd));
        futures::future::join_all(subs).await;
    });

    /// Reserved instance IDs for in-process servers.
    const SRV_PING_ID: u32 = u32::MAX - 1;
    const SRV_IPERF_ID: u32 = u32::MAX;

    let srv_cmd_rx_cell2 = srv_cmd_rx_cell.clone();
    let tool_cmd = use_coroutine(move |mut rx: UnboundedReceiver<ToolCmd>| {
        let srv_cmd_rx_cell = srv_cmd_rx_cell2.clone();
        async move {
            use ndn_tools_core::common::ConnectConfig;

            let mut srv_rx = srv_cmd_rx_cell
                .lock()
                .unwrap()
                .take()
                .expect("srv_cmd_rx already taken");

            let (ev_tx, mut ev_rx) = tokio::sync::mpsc::unbounded_channel::<(
                u32,
                Option<ndn_tools_core::common::ToolEvent>,
            )>();

            let mut handles: std::collections::HashMap<u32, tokio::task::AbortHandle> =
                std::collections::HashMap::new();

            loop {
                let maybe_cmd: Option<ToolCmd> = tokio::select! {
                    Some(cmd) = rx.next() => Some(cmd),
                    Some(cmd) = srv_rx.recv() => Some(cmd),
                    Some((inst_id, ev_opt)) = ev_rx.recv() => {
                        process_tool_event(inst_id, ev_opt, &mut handles, SRV_PING_ID, SRV_IPERF_ID);
                        while let Ok((id, ev)) = ev_rx.try_recv() {
                            process_tool_event(id, ev, &mut handles, SRV_PING_ID, SRV_IPERF_ID);
                        }
                        None
                    }
                };

                let Some(cmd) = maybe_cmd else { continue };

                match cmd {
                    ToolCmd::Stop { id } => {
                        if let Some(inst) = TOOL_INSTANCES.write().get_mut(&id) {
                            inst.running = false;
                        }
                        if let Some(h) = handles.remove(&id) {
                            h.abort();
                        }
                    }

                    ToolCmd::Run { id, params } => {
                        if let Some(h) = handles.remove(&id) {
                            h.abort();
                        }

                        let settings = DASH_SETTINGS.peek().clone();
                        let node_pfx = if settings.node_prefix.is_empty() {
                            None
                        } else {
                            Some(settings.node_prefix.clone())
                        };

                        match &params {
                            ToolParams::PingClient {
                                prefix,
                                count,
                                interval_ms,
                                lifetime_ms,
                            } => {
                                TOOL_INSTANCES.write().insert(
                                    id,
                                    ToolInstanceState {
                                        id,
                                        kind: "ping",
                                        running: true,
                                        tp_history: Vec::new(),
                                        current_rtt_us: None,
                                        output: VecDeque::new(),
                                        iperf_summary: None,
                                        ping_summary: None,
                                        ping_rtts: Vec::new(),
                                        label: prefix.clone(),
                                        elapsed_secs: 0.0,
                                        start_time: std::time::Instant::now(),
                                        run_params: vec![
                                            format!("count={count}"),
                                            format!("interval={interval_ms}ms"),
                                            format!("lifetime={lifetime_ms}ms"),
                                        ],
                                    },
                                );
                            }
                            ToolParams::IperfClient {
                                prefix,
                                duration_secs,
                                window,
                                cc,
                                reverse,
                                sign_mode,
                                face_type,
                            } => {
                                let mut rp = vec![
                                    format!("duration={duration_secs}s"),
                                    format!("window={window}"),
                                    format!("cc={cc}"),
                                    format!("sign={sign_mode}"),
                                    format!("face={face_type}"),
                                ];
                                if *reverse {
                                    rp.push("reverse".to_string());
                                }
                                TOOL_INSTANCES.write().insert(
                                    id,
                                    ToolInstanceState {
                                        id,
                                        kind: "iperf",
                                        running: true,
                                        tp_history: Vec::new(),
                                        current_rtt_us: None,
                                        output: VecDeque::new(),
                                        iperf_summary: None,
                                        ping_summary: None,
                                        ping_rtts: Vec::new(),
                                        label: prefix.clone(),
                                        elapsed_secs: 0.0,
                                        start_time: std::time::Instant::now(),
                                        run_params: rp,
                                    },
                                );
                            }
                            ToolParams::PeekClient { name, pipeline, .. } => {
                                TOOL_INSTANCES.write().insert(
                                    id,
                                    ToolInstanceState {
                                        id,
                                        kind: "peek",
                                        running: true,
                                        tp_history: Vec::new(),
                                        current_rtt_us: None,
                                        output: VecDeque::new(),
                                        iperf_summary: None,
                                        ping_summary: None,
                                        ping_rtts: Vec::new(),
                                        label: name.clone(),
                                        elapsed_secs: 0.0,
                                        start_time: std::time::Instant::now(),
                                        run_params: match pipeline {
                                            Some(p) => vec![format!("pipeline={p}")],
                                            None => vec![],
                                        },
                                    },
                                );
                            }
                            ToolParams::PutClient {
                                name,
                                sign,
                                freshness_ms,
                                data,
                            } => {
                                TOOL_INSTANCES.write().insert(
                                    id,
                                    ToolInstanceState {
                                        id,
                                        kind: "put",
                                        running: true,
                                        tp_history: Vec::new(),
                                        current_rtt_us: None,
                                        output: VecDeque::new(),
                                        iperf_summary: None,
                                        ping_summary: None,
                                        ping_rtts: Vec::new(),
                                        label: name.clone(),
                                        elapsed_secs: 0.0,
                                        start_time: std::time::Instant::now(),
                                        run_params: {
                                            let mut rp = vec![format!("{}B", data.len())];
                                            if *sign {
                                                rp.push("signed".to_string());
                                            }
                                            if *freshness_ms > 0 {
                                                rp.push(format!("freshness={freshness_ms}ms"));
                                            }
                                            rp
                                        },
                                    },
                                );
                            }
                        }

                        let done_tx = ev_tx.clone();
                        let fwd_tx = ev_tx.clone();
                        let face_socket = socket_path.peek().clone();

                        let h = match params {
                            ToolParams::PingClient {
                                prefix,
                                count,
                                interval_ms,
                                lifetime_ms,
                            } => tokio::spawn(async move {
                                let (ttx, mut trx) = tokio::sync::mpsc::channel(256);
                                let run_fut = ndn_tools_core::ping::run_client(
                                    ndn_tools_core::ping::PingClientParams {
                                        conn: ConnectConfig {
                                            face_socket,
                                            use_shm: true,
                                            mtu: None,
                                        },
                                        prefix,
                                        count,
                                        interval_ms,
                                        lifetime_ms,
                                    },
                                    ttx,
                                );
                                let bridge_fut = async {
                                    while let Some(ev) = trx.recv().await {
                                        let _ = fwd_tx.send((id, Some(ev)));
                                    }
                                };
                                let (res, _) = tokio::join!(run_fut, bridge_fut);
                                if let Err(e) = res {
                                    let _ = fwd_tx.send((
                                        id,
                                        Some(ndn_tools_core::common::ToolEvent::error(format!(
                                            "Error: {e}"
                                        ))),
                                    ));
                                }
                                let _ = done_tx.send((id, None));
                            }),
                            ToolParams::IperfClient {
                                prefix,
                                duration_secs,
                                window,
                                cc,
                                reverse,
                                sign_mode,
                                face_type,
                            } => tokio::spawn(async move {
                                let (ttx, mut trx) = tokio::sync::mpsc::channel(256);
                                let conn = ConnectConfig {
                                    face_socket,
                                    use_shm: face_type == "shm",
                                    mtu: None,
                                };
                                let run_fut = ndn_tools_core::iperf::run_client(
                                    ndn_tools_core::iperf::IperfClientParams {
                                        conn,
                                        prefix,
                                        duration_secs,
                                        initial_window: window,
                                        cc,
                                        min_window: None,
                                        max_window: None,
                                        ai: None,
                                        md: None,
                                        cubic_c: None,
                                        lifetime_ms: 4000,
                                        quiet: false,
                                        interval_ms: 250,
                                        reverse,
                                        node_prefix: node_pfx,
                                        sign_mode,
                                    },
                                    ttx,
                                );
                                let bridge_fut = async {
                                    while let Some(ev) = trx.recv().await {
                                        let _ = fwd_tx.send((id, Some(ev)));
                                    }
                                };
                                let (res, _) = tokio::join!(run_fut, bridge_fut);
                                if let Err(e) = res {
                                    let _ = fwd_tx.send((
                                        id,
                                        Some(ndn_tools_core::common::ToolEvent::error(format!(
                                            "Error: {e}"
                                        ))),
                                    ));
                                }
                                let _ = done_tx.send((id, None));
                            }),
                            ToolParams::PeekClient {
                                name,
                                output_file,
                                pipeline,
                            } => tokio::spawn(async move {
                                let (ttx, mut trx) = tokio::sync::mpsc::channel(256);
                                let run_fut = ndn_tools_core::peek::run_peek(
                                    ndn_tools_core::peek::PeekParams {
                                        conn: ConnectConfig {
                                            face_socket,
                                            use_shm: true,
                                            mtu: None,
                                        },
                                        name,
                                        lifetime_ms: 4000,
                                        output: output_file,
                                        pipeline,
                                        hex: false,
                                        meta_only: false,
                                        verbose: false,
                                        can_be_prefix: false,
                                    },
                                    ttx,
                                );
                                let bridge_fut = async {
                                    while let Some(ev) = trx.recv().await {
                                        let _ = fwd_tx.send((id, Some(ev)));
                                    }
                                };
                                let (res, _) = tokio::join!(run_fut, bridge_fut);
                                if let Err(e) = res {
                                    let _ = fwd_tx.send((
                                        id,
                                        Some(ndn_tools_core::common::ToolEvent::error(format!(
                                            "Error: {e}"
                                        ))),
                                    ));
                                }
                                let _ = done_tx.send((id, None));
                            }),
                            ToolParams::PutClient {
                                name,
                                data,
                                sign,
                                freshness_ms,
                            } => {
                                let data_bytes = bytes::Bytes::from(data);
                                tokio::spawn(async move {
                                    let (ttx, mut trx) = tokio::sync::mpsc::channel(256);
                                    let run_fut = ndn_tools_core::put::run_producer(
                                        ndn_tools_core::put::PutParams {
                                            conn: ConnectConfig {
                                                face_socket,
                                                use_shm: true,
                                                mtu: None,
                                            },
                                            name,
                                            data: data_bytes,
                                            chunk_size: 0,
                                            sign,
                                            hmac: false,
                                            freshness_ms,
                                            timeout_secs: 0,
                                            quiet: false,
                                        },
                                        ttx,
                                    );
                                    let bridge_fut = async {
                                        while let Some(ev) = trx.recv().await {
                                            let _ = fwd_tx.send((id, Some(ev)));
                                        }
                                    };
                                    let (res, _) = tokio::join!(run_fut, bridge_fut);
                                    if let Err(e) = res {
                                        let _ = fwd_tx.send((
                                            id,
                                            Some(ndn_tools_core::common::ToolEvent::error(
                                                format!("Error: {e}"),
                                            )),
                                        ));
                                    }
                                    let _ = done_tx.send((id, None));
                                })
                            }
                        };
                        handles.insert(id, h.abort_handle());
                    }

                    ToolCmd::StartIperfServer => {
                        if handles.contains_key(&SRV_IPERF_ID) {
                            continue;
                        }
                        let settings = DASH_SETTINGS.peek().clone();
                        let iperf_prefix = if settings.iperf_use_custom_name
                            && !settings.iperf_custom_name.is_empty()
                        {
                            settings.iperf_custom_name.clone()
                        } else if !settings.node_prefix.is_empty() {
                            format!(
                                "{}{}",
                                settings.node_prefix.trim_end_matches('/'),
                                settings.iperf_prefix
                            )
                        } else {
                            settings.iperf_prefix.clone()
                        };
                        let payload_size = settings.iperf_size as usize;
                        let face_socket = socket_path.peek().clone();
                        let fwd_tx = ev_tx.clone();
                        let done_tx = ev_tx.clone();
                        let h = tokio::spawn(async move {
                            let (ttx, mut trx) = tokio::sync::mpsc::channel(256);
                            let run_fut = ndn_tools_core::iperf::run_server(
                                ndn_tools_core::iperf::IperfServerParams {
                                    conn: ConnectConfig {
                                        face_socket,
                                        use_shm: settings.iperf_face_type != "unix",
                                        mtu: None,
                                    },
                                    prefix: iperf_prefix,
                                    payload_size,
                                    freshness_ms: 0,
                                    quiet: true,
                                    interval_ms: 1000,
                                },
                                ttx,
                            );
                            let bridge_fut = async {
                                while let Some(ev) = trx.recv().await {
                                    let _ = fwd_tx.send((SRV_IPERF_ID, Some(ev)));
                                }
                            };
                            let _ = tokio::join!(run_fut, bridge_fut);
                            let _ = done_tx.send((SRV_IPERF_ID, None));
                        });
                        handles.insert(SRV_IPERF_ID, h.abort_handle());
                    }

                    ToolCmd::StopIperfServer => {
                        if let Some(h) = handles.remove(&SRV_IPERF_ID) {
                            h.abort();
                        }
                    }

                    ToolCmd::StartPingServer => {
                        if handles.contains_key(&SRV_PING_ID) {
                            continue;
                        }
                        let settings = DASH_SETTINGS.peek().clone();
                        let ping_prefix = if !settings.node_prefix.is_empty() {
                            format!(
                                "{}{}",
                                settings.node_prefix.trim_end_matches('/'),
                                settings.ping_prefix
                            )
                        } else {
                            settings.ping_prefix.clone()
                        };
                        let face_socket = socket_path.peek().clone();
                        let fwd_tx = ev_tx.clone();
                        let done_tx = ev_tx.clone();
                        let h = tokio::spawn(async move {
                            let (ttx, mut trx) = tokio::sync::mpsc::channel(256);
                            let run_fut = ndn_tools_core::ping::run_server(
                                ndn_tools_core::ping::PingServerParams {
                                    conn: ConnectConfig {
                                        face_socket,
                                        use_shm: true,
                                        mtu: None,
                                    },
                                    prefix: ping_prefix,
                                    freshness_ms: 0,
                                    sign: false,
                                },
                                ttx,
                            );
                            let bridge_fut = async {
                                while let Some(ev) = trx.recv().await {
                                    let _ = fwd_tx.send((SRV_PING_ID, Some(ev)));
                                }
                            };
                            let _ = tokio::join!(run_fut, bridge_fut);
                            let _ = done_tx.send((SRV_PING_ID, None));
                        });
                        handles.insert(SRV_PING_ID, h.abort_handle());
                    }

                    ToolCmd::StopPingServer => {
                        if let Some(h) = handles.remove(&SRV_PING_ID) {
                            h.abort();
                        }
                    }
                }
            }
        }
    });

    let ctx = AppCtx {
        conn: conn_state,
        status,
        faces,
        routes,
        rib_entries,
        cs,
        strategies,
        counters,
        measurements,
        config_toml,
        throughput,
        prev_counters,
        session_log,
        recording,
        neighbors,
        security_keys,
        security_anchors,
        ca_info,
        schema_rules,
        yubikey_status,
        identity_name,
        identity_is_ephemeral,
        identity_pib_path,
        cert_valid_until_unix_s,
        mgmt_signed_commands_required,
        mgmt_access_policy,
        security_surface_supported,
        validation_stats,
        validation_history,
        trust_validation,
        trust_inspector_open,
        cs_hit_history,
        face_throughput,
        discovery_status,
        dvr_status,
        router_cmd,
        cmd,
        tool_cmd,
    };
    use_context_provider(move || ctx);

    // Light-mode lives on the outermost `.app-root` (not `.layout`) so the
    // whole subtree — including `body`'s show-through behind transparent
    // panes and the position:fixed modals/toasts/gate — inherits the theme
    // variables. Mirrors the web build's wrapper.
    let app_root_class = if *DARK_MODE.read() {
        "app-root"
    } else {
        "app-root light-mode"
    };

    rsx! {
        div { class: "{app_root_class}",
        AppStyles {}

        crate::security_gate::SecurityGate {}

        if *show_onboarding.read() {
            Onboarding {
                on_complete: move |_| show_onboarding.set(false),
            }
        }

        if *show_start_modal.read() {
            StartRouterModal {
                on_close: move |_| show_start_modal.set(false),
                config_toml,
            }
        }

        ToastOverlay {}

        crate::views::safebag_import::SafeBagImportModal {
            state: crate::app_shared::SAFEBAG_IMPORT_STATE.signal(),
        }

        crate::views::enrollment_wizard::EnrollmentWizardModal {
            state: crate::app_shared::ENROLLMENT_WIZARD_STATE.signal(),
        }

        crate::views::key_rotation::KeyRotationModal {
            state: crate::app_shared::KEY_ROTATION_STATE.signal(),
        }

        div {
            class: "layout",
            ondragover: move |evt| { evt.prevent_default(); },
            ondrop: move |evt| {
                evt.prevent_default();
                let files = evt.files();
                if let Some(file) = files.first().cloned() {
                    let filename = file.name();
                    spawn(async move {
                        if let Ok(bytes) = file.read_bytes().await {
                            let wire = bytes.to_vec();
                            crate::views::safebag_import::open_with_wire(filename, wire);
                        }
                    });
                }
            },
            nav { class: "sidebar",
                div { class: "sidebar-logo",
                    style: "display:flex;align-items:center;justify-content:space-between;",
                    span { "NDN Dashboard" }
                    crate::security_surfaces::SecDot {}
                }
                for bucket in crate::views::Bucket::ALL {
                    {
                        let bucket = *bucket;
                        let mut collapsed_buckets = collapsed_buckets;
                        let is_collapsed = collapsed_buckets.read().contains(&bucket);
                        rsx! {
                            div { class: "nav-section",
                                div {
                                    class: "nav-section-header",
                                    onclick: move |_| {
                                        let mut set = collapsed_buckets.write();
                                        if !set.remove(&bucket) {
                                            set.insert(bucket);
                                        }
                                    },
                                    span { class: "nav-section-caret",
                                        if is_collapsed { "▸" } else { "▾" }
                                    }
                                    span { style: "flex:1;", "{bucket.label()}" }
                                    {
                                        let count = crate::views::bucket_count(
                                            bucket,
                                            &faces.read(),
                                            &security_keys.read(),
                                            &rib_entries.read(),
                                        );
                                        rsx! { span { class: "nav-count", "{count}" } }
                                    }
                                }
                                if !is_collapsed {
                                    for view in bucket.views() {
                                        {
                                            let view = *view;
                                            let is_active = *ACTIVE_VIEW.read() == view;
                                            rsx! {
                                                div {
                                                    class: if is_active { "nav-item active" } else { "nav-item" },
                                                    onclick: move |_| { *ACTIVE_VIEW.write() = view; },
                                                    "{view.label()}"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                div { class: "sidebar-spacer" }

                div { class: "sidebar-bottom",
                    if *show_gear_menu.read() {
                        div { class: "gear-menu",
                            div {
                                class: "gear-menu-item",
                                onclick: move |_| {
                                    *ACTIVE_VIEW.write() = View::DashboardConfig;
                                    show_gear_menu.set(false);
                                },
                                "Dashboard Config"
                            }
                            div {
                                class: "gear-menu-item",
                                onclick: move |_| {
                                    *ACTIVE_VIEW.write() = View::RouterConfig;
                                    show_gear_menu.set(false);
                                },
                                "Router Config"
                            }
                        }
                    }
                    button {
                        class: "icon-btn",
                        style: "width:100%;text-align:left;",
                        onclick: move |_| { let v = *show_gear_menu.read(); show_gear_menu.set(!v); },
                        "⚙ Settings"
                    }
                }
            }

            div { class: "main",
                // Attach bar — two independent axes (note §8): the Engine you
                // operate and the identity you're Acting as.
                div { class: "conn-bar",
                    span {
                        class: "{conn_state.read().badge_class()}",
                        "{conn_state.read().label()}"
                    }
                    span { class: "axis-label", "Engine" }
                    crate::views::engine_pill::EnginePill {}
                    input {
                        r#type: "text",
                        placeholder: "Socket path",
                        value: "{socket_path}",
                        oninput: move |e| socket_path.set(e.value()),
                    }
                    button {
                        class: "btn btn-secondary",
                        onclick: move |_| cmd.send(DashCmd::Reconnect),
                        "Connect"
                    }
                    span { class: "axis-divider" }
                    crate::security_surfaces::IdentityAxisControl {}
                    crate::security_surfaces::CapabilityBadge {}
                    button {
                        class: "icon-btn",
                        title: "Refresh",
                        onclick: move |_| cmd.send(DashCmd::Reconnect),
                        "⟳"
                    }
                    div { style: "flex:1;" }
                    button {
                        class: "theme-toggle",
                        title: if *DARK_MODE.read() { "Switch to Light Mode" } else { "Switch to Dark Mode" },
                        onclick: move |_| {
                            let next = !*DARK_MODE.read();
                            *DARK_MODE.write() = next;
                        },
                        if *DARK_MODE.read() { "☀" } else { "🌙" }
                    }
                    div { style: "width:1px;height:20px;background:var(--border);flex-shrink:0;" }
                    {
                        let running = *ROUTER_RUNNING.read();
                        rsx! {
                            span {
                                class: if running { "badge badge-green" } else { "badge badge-gray" },
                                style: "flex-shrink:0;",
                                if running { "Router Running" } else { "Router Stopped" }
                            }
                            if !running {
                                {
                                    let external = matches!(*conn_state.read(), ConnState::Connected);
                                    rsx! {
                                        button {
                                            class: "btn btn-primary btn-sm",
                                            disabled: external,
                                            title: if external {
                                                "Connected to an external forwarder — disconnect or shut it down first"
                                            } else {
                                                "Start a local ndn-fwd process"
                                            },
                                            onclick: move |_| { if !external { show_start_modal.set(true); } },
                                            "▶ Start"
                                        }
                                    }
                                }
                                if *conn_state.read() == ConnState::Connected {
                                    button {
                                        class: "btn btn-danger btn-sm",
                                        onclick: move |_| cmd.send(DashCmd::Shutdown),
                                        "■ Shutdown"
                                    }
                                }
                            } else {
                                button {
                                    class: "btn btn-danger btn-sm",
                                    onclick: move |_| router_cmd.send(RouterCmd::Stop),
                                    "■ Stop"
                                }
                            }
                        }
                    }
                }

                if *ACTIVE_VIEW.read() == View::Logs {
                    div { style: "flex:1;min-height:0;overflow:hidden;display:flex;flex-direction:column;",
                        if let Some(ref err) = *error_msg.read() {
                            div { class: "error-banner", style: "margin:8px 12px 0;",
                                span { "{err}" }
                                button {
                                    class: "btn btn-secondary btn-sm",
                                    onclick: move |_| error_msg.set(None),
                                    "✕"
                                }
                            }
                        }
                        Logs {}
                    }
                } else {
                    // Center content + right-hand inspector (design note §3).
                    div { class: if crate::views::inspector::inspector_visible() { "content-host inspector-open" } else { "content-host" },
                        div { class: "content",
                            if let Some(ref err) = *error_msg.read() {
                                div { class: "error-banner",
                                    span { "{err}" }
                                    button {
                                        class: "btn btn-secondary btn-sm",
                                        onclick: move |_| error_msg.set(None),
                                        "✕"
                                    }
                                }
                            }
                            crate::security_surfaces::TrustStatusPanel {}
                            {render_view(*ACTIVE_VIEW.read())}
                        }
                        crate::views::inspector::Inspector {}
                    }
                }
            }
        }
        }
    }
}

/// Installs the global stylesheet exactly once.
///
/// Inlining `document::Style { "{CSS}" }` directly in `App` re-emitted it on
/// every poll-driven re-render, which Dioxus rejects with "Changing the props
/// of `Style {}` is not supported" (and which left the webview with a
/// half-applied stylesheet during reconnect churn). A propless child component
/// is memoized — it renders a single time — so the stylesheet is installed
/// once and never diffed again.
#[component]
fn AppStyles() -> Element {
    rsx! {
        document::Style { "{crate::fonts::FONT_FACES}" }
        document::Style { "{CSS}" }
    }
}

#[component]
fn ToastOverlay() -> Element {
    let toasts = TOASTS.read();
    if toasts.is_empty() {
        return rsx! {};
    }
    rsx! {
        div { class: "toast-container",
            for toast in toasts.iter() {
                {
                    let id = toast.id;
                    let icon = toast.level.icon();
                    let msg = toast.message.clone();
                    let cls = toast.level.css_class();
                    rsx! {
                        div { class: "toast {cls}",
                            div { class: "toast-body",
                                span { class: "toast-icon", "{icon}" }
                                span { class: "toast-msg", "{msg}" }
                            }
                            button {
                                class: "toast-close",
                                onclick: move |_| { TOASTS.write().retain(|t| t.id != id); },
                                "✕"
                            }
                        }
                    }
                }
            }
        }
    }
}

fn render_view(view: View) -> Element {
    match view {
        View::Overview => rsx! { Overview {} },
        View::Strategy => rsx! { Strategy {} },
        View::Coding => rsx! { crate::views::coding::Coding {} },
        View::RateLimit => rsx! { crate::views::rate_limit::RateLimit {} },
        View::Logs => rsx! {},
        View::Session => rsx! { Session {} },
        View::Security => rsx! { Security {} },
        View::Fleet => rsx! { Fleet {} },
        View::Routing => rsx! { Routing {} },
        View::Radio => rsx! { Radio {} },
        View::Tools => rsx! { Tools {} },
        View::Compose => rsx! { crate::views::compose::Compose {} },
        View::TrustContext => rsx! { crate::views::trust_context::TrustContext {} },
        View::Pairing => rsx! { crate::views::pairing::Pairing {} },
        View::DashboardConfig => rsx! { DashboardConfig {} },
        View::RouterConfig => rsx! { Config {} },
    }
}

/// Per-forwarder audit chain dir. Keyed by the selected forwarder profile so
/// toggling `--forwarder=` doesn't replay another impl's history.
fn audit_chain_dir() -> std::path::PathBuf {
    dashboard_chain_dir_root().join("audit")
}

fn schema_journal_dir() -> std::path::PathBuf {
    dashboard_chain_dir_root().join("schema")
}

fn dashboard_chain_dir_root() -> std::path::PathBuf {
    let profile = crate::forwarder_profile::selected_profile();
    let base = dirs_next::config_dir().unwrap_or_else(std::env::temp_dir);
    base.join("ndn-dashboard").join(profile.machine_name())
}

fn default_socket_path() -> String {
    #[cfg(windows)]
    return r"\\.\pipe\ndn".to_string();
    #[cfg(not(windows))]
    {
        crate::forwarder_profile::selected().1.display().to_string()
    }
}

#[allow(clippy::too_many_arguments)]
async fn poll_all(
    engine: &mut ndn_dashboard_core::DashboardEngine<crate::native_mgmt::NativeMgmtClient>,
    mut status: Signal<Option<ForwarderStatus>>,
    mut faces: Signal<Vec<FaceInfo>>,
    mut routes: Signal<Vec<FibEntry>>,
    mut rib_entries: Signal<Vec<RibEntryInfo>>,
    mut cs: Signal<Option<CsInfo>>,
    mut strategies: Signal<Vec<StrategyEntry>>,
    mut counters: Signal<Vec<FaceCounter>>,
    mut measurements: Signal<Vec<MeasurementEntry>>,
    mut config_toml: Signal<String>,
    mut throughput: Signal<VecDeque<ThroughputSample>>,
    mut prev_counters: Signal<ThroughputSample>,
    mut neighbors: Signal<Vec<NeighborInfo>>,
    mut security_keys: Signal<Vec<SecurityKeyInfo>>,
    mut security_anchors: Signal<Vec<AnchorInfo>>,
    mut ca_info: Signal<Option<CaInfo>>,
    mut schema_rules: Signal<Vec<SchemaRuleInfo>>,
    mut cs_hit_history: Signal<VecDeque<f64>>,
    mut face_throughput: Signal<HashMap<u64, VecDeque<ThroughputSample>>>,
    mut face_prev_ctr: Signal<HashMap<u64, ThroughputSample>>,
    mut discovery_status: Signal<Option<DiscoveryStatus>>,
    mut dvr_status: Signal<Option<DvrStatus>>,
    mut identity_name: Signal<String>,
    mut identity_is_ephemeral: Signal<bool>,
    mut identity_pib_path: Signal<Option<String>>,
    mut cert_valid_until_unix_s: Signal<Option<u64>>,
    mut mgmt_signed_commands_required: Signal<Option<bool>>,
    mut mgmt_access_policy: Signal<Option<MgmtAccessPolicySnapshot>>,
    mut security_surface_supported: Signal<Option<bool>>,
    mut validation_stats: Signal<Option<ValidationStats>>,
    mut validation_history: Signal<VecDeque<(u64, u64)>>,
) -> Result<(), String> {
    use ndn_dashboard_core::StateUpdate;

    // Forwarding plane via the engine (status/faces/fib/cs/strategy), with the
    // engine owning the wire→view-model mapping. The desktop treats these as
    // fatal — a missing one means the forwarder or socket is unhealthy, so we
    // reconnect (unlike the web's best-effort poll). The throughput/per-face
    // history derivation below is unchanged; it reads the `counters` signal.
    let updates = engine.poll_forwarding().await;
    for essential in [
        StateUpdate::Status,
        StateUpdate::Faces,
        StateUpdate::Routes,
        StateUpdate::Cs,
        StateUpdate::Strategies,
    ] {
        if !updates.contains(&essential) {
            return Err(format!("forwarding poll incomplete ({essential:?} missing)"));
        }
    }
    {
        let st = engine.state();
        status.set(st.status.clone());
        let face_infos = st.faces.clone();
        let derived_counters: Vec<FaceCounter> = face_infos
            .iter()
            .map(|f| FaceCounter {
                face_id: f.face_id,
                in_interests: f.n_in_interests,
                in_data: f.n_in_data,
                out_interests: f.n_out_interests,
                out_data: f.n_out_data,
                in_bytes: f.n_in_bytes,
                out_bytes: f.n_out_bytes,
            })
            .collect();
        faces.set(face_infos);
        counters.set(derived_counters);
        routes.set(st.routes.clone());
        cs.set(st.cs.clone());
        strategies.set(st.strategies.clone());
    }

    // Datasets the engine doesn't model yet — drive the engine's client
    // directly. These stay best-effort, as before.
    let client = &engine.client().0;
    if let Ok(rib_data) = client.rib_list().await {
        rib_entries.set(rib_data.into_iter().map(RibEntryInfo::from).collect());
    }
    if let Ok(r) = client.measurements_list().await {
        measurements.set(MeasurementEntry::parse_list(&r.status_text));
    }
    if config_toml.read().is_empty()
        && let Ok(r) = client.config_get().await
    {
        config_toml.set(r.status_text);
    }
    {
        let curr_counters = counters.read();
        let active: HashSet<u64> = curr_counters.iter().map(|c| c.face_id).collect();
        let mut fp = face_prev_ctr.write();
        let mut fh = face_throughput.write();
        for c in curr_counters.iter() {
            let fid = c.face_id;
            let curr_snap = ThroughputSample::from_face_counter(c);
            let prev_snap = fp.get(&fid).cloned().unwrap_or_default();
            let rate = ThroughputSample::rate_from_delta(&prev_snap, &curr_snap, 3.0);
            fp.insert(fid, curr_snap);
            let hist = fh.entry(fid).or_default();
            hist.push_back(rate);
            if hist.len() > 60 {
                hist.pop_front();
            }
        }
        fh.retain(|k, _| active.contains(k));
        fp.retain(|k, _| active.contains(k));
    }
    {
        let curr = ThroughputSample::from_counters(&counters.read());
        let rate = ThroughputSample::rate_from_delta(&prev_counters.read(), &curr, 3.0);
        prev_counters.set(curr);
        let mut hist = throughput.write();
        hist.push_back(rate);
        if hist.len() > 60 {
            hist.pop_front();
        }
    }
    if let Ok(r) = client.neighbors_list().await {
        neighbors.set(NeighborInfo::parse_list(&r.status_text));
    }
    if let Ok(r) = client.security_identity_list().await {
        let keys = SecurityKeyInfo::parse_list(&r.status_text);
        let expiry = keys.iter().find_map(SecurityKeyInfo::valid_until_unix_s);
        cert_valid_until_unix_s.set(expiry);
        security_keys.set(keys);
    }
    if let Ok(r) = client.security_policy_get().await
        && let Ok(parsed) = MgmtAccessPolicySnapshot::from_json(&r.status_text)
    {
        mgmt_signed_commands_required.set(Some(parsed.require_signed_commands));
        mgmt_access_policy.set(Some(parsed));
    }
    if let Ok(r) = client.security_validation_stats().await {
        let parsed = ValidationStats::parse(&r.status_text);
        let rate = validation_stats
            .peek()
            .and_then(|prev| parsed.rate_against(&prev))
            .unwrap_or((parsed.verified_per_sec, parsed.rejected_per_sec));
        validation_stats.set(Some(parsed));
        let mut hist = validation_history.write();
        hist.push_back(rate);
        if hist.len() > 60 {
            hist.pop_front();
        }
    }
    if let Ok(r) = client.security_anchor_list().await {
        security_anchors.set(AnchorInfo::parse_list(&r.status_text));
    }
    if let Ok(r) = client.security_ca_info().await {
        ca_info.set(CaInfo::parse(&r.status_text));
    }
    if let Ok(r) = client.security_schema_list().await {
        schema_rules.set(SchemaRuleInfo::parse_list(&r.status_text));
    }
    // Also probes ndn-rs's security/* mgmt extensions: 2xx ⇒ supported,
    // 404 ⇒ cross-impl forwarder (NFD / YaNFD).
    if let Ok(r) = client.security_identity_status().await {
        if r.is_ok() {
            let (name, ephemeral, pib) = parse_identity_status(&r.status_text);
            identity_name.set(name);
            identity_is_ephemeral.set(ephemeral);
            identity_pib_path.set(pib);
            security_surface_supported.set(Some(true));
        } else if r.status_code == ndn_config::control_response::status::NOT_FOUND {
            security_surface_supported.set(Some(false));
        }
    }
    if let Ok(r) = client.discovery_status().await {
        discovery_status.set(DiscoveryStatus::parse(&r.status_text));
    }
    if let Ok(r) = client.routing_dvr_status().await {
        dvr_status.set(DvrStatus::parse(&r.status_text));
    }
    // Guards must not be held across await — extract signal values first.
    let is_running = *ROUTER_RUNNING.read();
    let last_seq = *LAST_LOG_SEQ.read();
    if !is_running && let Ok(r) = client.log_get_recent(last_seq).await {
        let text = r.status_text.trim().to_string();
        let mut lines = text.lines();
        if let Some(seq_str) = lines.next()
            && let Ok(max_seq) = seq_str.parse::<u64>()
            && max_seq > last_seq
        {
            *LAST_LOG_SEQ.write() = max_seq;
            {
                let mut log = ROUTER_LOG.write();
                for line in lines {
                    if !line.is_empty() {
                        let entry = crate::types::LogEntry::parse_line(line);
                        log.push_back(entry);
                        if log.len() > 2000 {
                            log.pop_front();
                        }
                    }
                }
            }
        }
    }
    // Write guard must drop before the await — collapsing into `if let ... && .await`
    // would hold it across the await.
    let pending_filter = PENDING_LOG_FILTER.write().take();
    if let Some(filter) = pending_filter {
        #[allow(clippy::collapsible_if)]
        if client.log_set_filter(&filter).await.is_ok() {
            *LOG_FILTER.write() = filter;
        }
    }
    if let Ok(r) = client.log_get_filter().await {
        let fetched = r.status_text.trim().to_string();
        let current = LOG_FILTER.read().clone();
        if current != fetched {
            *LOG_FILTER.write() = fetched;
        }
    }
    if let Some(ref info) = *cs.read() {
        let rate = info.hit_rate_pct();
        let mut h = cs_hit_history.write();
        h.push_back(rate);
        if h.len() > 60 {
            h.pop_front();
        }
    }
    Ok(())
}

/// Reconstruct a [`DashCmd`] from a recorded [`SessionEntry`] for replay.
fn session_entry_to_cmd(entry: &SessionEntry) -> Option<DashCmd> {
    match entry.kind.as_str() {
        "FaceCreate" => Some(DashCmd::FaceCreate(entry.params.clone())),
        "FaceDestroy" => entry.params.parse::<u64>().ok().map(DashCmd::FaceDestroy),
        "RouteAdd" => {
            let mut prefix = String::new();
            let mut face_id = 0u64;
            let mut cost = 10u64;
            for token in entry.params.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    match k {
                        "prefix" => prefix = v.to_string(),
                        "face" => face_id = v.parse().unwrap_or(0),
                        "cost" => cost = v.parse().unwrap_or(10),
                        _ => {}
                    }
                }
            }
            (!prefix.is_empty()).then_some(DashCmd::RouteAdd {
                prefix,
                face_id,
                cost,
            })
        }
        "RouteRemove" => {
            let mut prefix = String::new();
            let mut face_id = 0u64;
            for token in entry.params.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    match k {
                        "prefix" => prefix = v.to_string(),
                        "face" => face_id = v.parse().unwrap_or(0),
                        _ => {}
                    }
                }
            }
            (!prefix.is_empty()).then_some(DashCmd::RouteRemove { prefix, face_id })
        }
        "StrategySet" => {
            let mut prefix = String::new();
            let mut strategy = String::new();
            for token in entry.params.split_whitespace() {
                if let Some((k, v)) = token.split_once('=') {
                    match k {
                        "prefix" => prefix = v.to_string(),
                        "strategy" => strategy = v.to_string(),
                        _ => {}
                    }
                }
            }
            (!prefix.is_empty() && !strategy.is_empty())
                .then_some(DashCmd::StrategySet { prefix, strategy })
        }
        "StrategyUnset" => Some(DashCmd::StrategyUnset(entry.params.clone())),
        "CsCapacity" => entry.params.parse::<u64>().ok().map(DashCmd::CsCapacity),
        "CsErase" => Some(DashCmd::CsErase(entry.params.clone())),
        _ => None,
    }
}

fn cmd_to_session_entry(cmd: &DashCmd) -> Option<SessionEntry> {
    match cmd {
        DashCmd::FaceCreate(uri) => Some(SessionEntry {
            kind: "FaceCreate".into(),
            params: uri.clone(),
        }),
        DashCmd::FaceDestroy(id) => Some(SessionEntry {
            kind: "FaceDestroy".into(),
            params: id.to_string(),
        }),
        DashCmd::RouteAdd {
            prefix,
            face_id,
            cost,
        } => Some(SessionEntry {
            kind: "RouteAdd".into(),
            params: format!("prefix={prefix} face={face_id} cost={cost}"),
        }),
        DashCmd::RouteRemove { prefix, face_id } => Some(SessionEntry {
            kind: "RouteRemove".into(),
            params: format!("prefix={prefix} face={face_id}"),
        }),
        DashCmd::StrategySet { prefix, strategy } => Some(SessionEntry {
            kind: "StrategySet".into(),
            params: format!("prefix={prefix} strategy={strategy}"),
        }),
        DashCmd::StrategyUnset(prefix) => Some(SessionEntry {
            kind: "StrategyUnset".into(),
            params: prefix.clone(),
        }),
        DashCmd::CsCapacity(bytes) => Some(SessionEntry {
            kind: "CsCapacity".into(),
            params: bytes.to_string(),
        }),
        DashCmd::CsErase(prefix) => Some(SessionEntry {
            kind: "CsErase".into(),
            params: prefix.clone(),
        }),
        DashCmd::Shutdown => Some(SessionEntry {
            kind: "Shutdown".into(),
            params: String::new(),
        }),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_cmd(
    cmd: DashCmd,
    engine: &ndn_dashboard_core::DashboardEngine<crate::native_mgmt::NativeMgmtClient>,
    status: Signal<Option<ForwarderStatus>>,
    faces: Signal<Vec<FaceInfo>>,
    routes: Signal<Vec<FibEntry>>,
    rib_entries: Signal<Vec<RibEntryInfo>>,
    cs: Signal<Option<CsInfo>>,
    strategies: Signal<Vec<StrategyEntry>>,
    counters: Signal<Vec<FaceCounter>>,
    measurements: Signal<Vec<MeasurementEntry>>,
    mut error_msg: Signal<Option<String>>,
    mut config_toml: Signal<String>,
    throughput: Signal<VecDeque<ThroughputSample>>,
    prev_counters: Signal<ThroughputSample>,
    mut session_log: Signal<Vec<SessionEntry>>,
    mut recording: Signal<bool>,
    neighbors: Signal<Vec<NeighborInfo>>,
    security_keys: Signal<Vec<SecurityKeyInfo>>,
    security_anchors: Signal<Vec<AnchorInfo>>,
    ca_info: Signal<Option<CaInfo>>,
    schema_rules: Signal<Vec<SchemaRuleInfo>>,
    mut yubikey_status: Signal<Option<String>>,
    cs_hit_history: Signal<VecDeque<f64>>,
    face_throughput: Signal<HashMap<u64, VecDeque<ThroughputSample>>>,
    face_prev_ctr: Signal<HashMap<u64, ThroughputSample>>,
    discovery_status: Signal<Option<DiscoveryStatus>>,
    dvr_status: Signal<Option<DvrStatus>>,
    identity_name: Signal<String>,
    identity_is_ephemeral: Signal<bool>,
    identity_pib_path: Signal<Option<String>>,
    cert_valid_until_unix_s: Signal<Option<u64>>,
    mgmt_signed_commands_required: Signal<Option<bool>>,
    mgmt_access_policy: Signal<Option<MgmtAccessPolicySnapshot>>,
    security_surface_supported: Signal<Option<bool>>,
    validation_stats: Signal<Option<ValidationStats>>,
    validation_history: Signal<VecDeque<(u64, u64)>>,
    mut trust_validation: Signal<Option<(String, TrustValidationResult)>>,
) {
    // The engine owns the client; command dispatch reads it through a shared
    // borrow (ndn-ipc's methods are `&self`). The typed `client.*` calls below
    // are unchanged. The native UI calls the engine's command builders instead.
    let client = &engine.client().0;

    if *recording.read()
        && let Some(entry) = cmd_to_session_entry(&cmd)
    {
        session_log.write().push(entry);
    }

    let op_label: Option<&'static str> = match &cmd {
        DashCmd::FaceCreate(_) => Some("Face created"),
        DashCmd::FaceDestroy(_) => Some("Face destroyed"),
        DashCmd::RouteAdd { .. } => Some("Route added"),
        DashCmd::RouteRemove { .. } => Some("Route removed"),
        DashCmd::CsCapacity(_) => Some("CS capacity updated"),
        DashCmd::CsErase(_) => Some("CS entries erased"),
        DashCmd::Shutdown => Some("Router shutdown initiated"),
        DashCmd::StrategySet { .. } => Some("Strategy updated"),
        DashCmd::StrategyUnset(_) => Some("Strategy cleared"),
        DashCmd::DiscoveryConfigSet(_) => Some("Discovery config applied"),
        DashCmd::DvrConfigSet(_) => Some("DVR config applied"),
        DashCmd::SchemaRuleAdd(_) => Some("Trust schema rule added"),
        DashCmd::SchemaRuleRemove(_) => Some("Trust schema rule removed"),
        DashCmd::SchemaSet(_) => Some("Trust schema updated"),
        DashCmd::SecurityPolicySet(_) => Some("Mgmt access policy updated"),
        DashCmd::SecurityValidateTrace(_) => None, // surfaces via the sidesheet, not a toast
        DashCmd::SecurityAnchorAdd { .. } => Some("Anchor promoted (TOFU)"),
        DashCmd::SecurityAnchorRemove { .. } => Some("Anchor removed"),
        DashCmd::SecuritySafebagImport { .. } => Some("SafeBag imported"),
        DashCmd::CaListApprovals => None, // refresh is silent; state-signal drives UI
        DashCmd::CaApprove { .. } => Some("Approval published"),
        DashCmd::CaDeny { .. } => Some("Denial published"),
        _ => None,
    };

    let result: Result<(), String> = match cmd {
        DashCmd::FaceCreate(uri) => client
            .face_create(&uri)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string()),
        DashCmd::FaceDestroy(id) => client
            .face_destroy(id)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string()),
        DashCmd::RouteAdd {
            prefix,
            face_id,
            cost,
        } => match prefix.parse::<ndn_packet::Name>() {
            Ok(n) => client
                .route_add(&n, Some(face_id), cost)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        },
        DashCmd::RouteRemove { prefix, face_id } => match prefix.parse::<ndn_packet::Name>() {
            Ok(n) => client
                .route_remove(&n, Some(face_id))
                .await
                .map(|_| ())
                .map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        },
        DashCmd::StrategySet { prefix, strategy } => {
            match (
                prefix.parse::<ndn_packet::Name>(),
                strategy.parse::<ndn_packet::Name>(),
            ) {
                (Ok(p), Ok(s)) => client
                    .strategy_set(&p, &s)
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
                _ => Err("Invalid NDN name".into()),
            }
        }
        DashCmd::StrategyUnset(prefix) => match prefix.parse::<ndn_packet::Name>() {
            Ok(n) => client
                .strategy_unset(&n)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        },
        DashCmd::CsCapacity(bytes) => client
            .cs_config(Some(bytes))
            .await
            .map(|_| ())
            .map_err(|e| e.to_string()),
        DashCmd::CsErase(prefix) => match prefix.parse::<ndn_packet::Name>() {
            Ok(n) => client
                .cs_erase(&n, None)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        },
        DashCmd::Shutdown => client
            .shutdown()
            .await
            .map(|_| ())
            .map_err(|e| e.to_string()),
        DashCmd::Reconnect => return,
        // Handled in the session loop (immediate poll); never a real command.
        DashCmd::RefreshNow => return,
        DashCmd::RefreshConfig => {
            config_toml.set(String::new()); // clear so poll_all re-fetches
            return;
        }
        DashCmd::RecordStart => {
            recording.set(true);
            return;
        }
        DashCmd::RecordStop => {
            recording.set(false);
            return;
        }
        DashCmd::RecordClear => {
            session_log.set(Vec::new());
            return;
        }
        DashCmd::ReplaySession => {
            let entries = session_log.read().clone();
            tracing::info!("ReplaySession: replaying {} commands", entries.len());
            for entry in &entries {
                if let Some(replay_cmd) = session_entry_to_cmd(entry) {
                    // Skip recording replayed commands to avoid infinite loops.
                    let was_recording = *recording.read();
                    recording.set(false);
                    Box::pin(run_cmd(
                        replay_cmd,
                        engine,
                        status,
                        faces,
                        routes,
                        rib_entries,
                        cs,
                        strategies,
                        counters,
                        measurements,
                        error_msg,
                        config_toml,
                        throughput,
                        prev_counters,
                        session_log,
                        recording,
                        neighbors,
                        security_keys,
                        security_anchors,
                        ca_info,
                        schema_rules,
                        yubikey_status,
                        cs_hit_history,
                        face_throughput,
                        face_prev_ctr,
                        discovery_status,
                        dvr_status,
                        identity_name,
                        identity_is_ephemeral,
                        identity_pib_path,
                        cert_valid_until_unix_s,
                        mgmt_signed_commands_required,
                        mgmt_access_policy,
                        security_surface_supported,
                        validation_stats,
                        validation_history,
                        trust_validation,
                    ))
                    .await;
                    recording.set(was_recording);
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
            }
            return;
        }
        DashCmd::SecurityGenerate(name) => match name.parse::<ndn_packet::Name>() {
            Ok(n) => client
                .security_identity_generate(&n)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        },
        DashCmd::SecurityKeyDelete(name) => match name.parse::<ndn_packet::Name>() {
            Ok(n) => client
                .security_key_delete(&n)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        },
        DashCmd::SecurityEnroll {
            ca_prefix,
            challenge_type,
            challenge_param,
        } => {
            use crate::views::enrollment_wizard::EnrollmentResult;
            match ca_prefix.parse::<ndn_packet::Name>() {
                Ok(n) => match client
                    .security_ca_enroll(&n, &challenge_type, &challenge_param)
                    .await
                {
                    Ok(echo) => {
                        // ca-enroll echoes ControlResponse "started" with the
                        // identity name as `name` and (optionally) a status
                        // hint as `uri`. Surface whichever is present.
                        let text = match (echo.name.as_ref(), echo.uri.as_deref()) {
                            (Some(n), Some(u)) if !u.is_empty() => format!("started · {n} · {u}"),
                            (Some(n), _) => format!("started · {n}"),
                            (None, Some(u)) if !u.is_empty() => format!("started · {u}"),
                            _ => "started".to_owned(),
                        };
                        *crate::app_shared::ENROLLMENT_RESULT.write() =
                            Some(EnrollmentResult::Submitted { text });
                        Ok(())
                    }
                    Err(e) => {
                        *crate::app_shared::ENROLLMENT_RESULT.write() =
                            Some(EnrollmentResult::Failed {
                                reason: e.to_string(),
                            });
                        Err(e.to_string())
                    }
                },
                Err(e) => {
                    *crate::app_shared::ENROLLMENT_RESULT.write() =
                        Some(EnrollmentResult::Failed {
                            reason: format!("invalid CA prefix: {e}"),
                        });
                    Err(e.to_string())
                }
            }
        }
        DashCmd::SecurityTokenAdd(description) => client
            .security_ca_token_add(&description)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string()),
        DashCmd::YubikeyDetect => {
            match client.security_yubikey_detect().await {
                Ok(r) => {
                    yubikey_status.set(Some(format!("YubiKey: {}", r.status_text)));
                    Ok(())
                }
                Err(e) => {
                    yubikey_status.set(Some(format!("Not found: {e}")));
                    Ok(()) // Don't propagate as error — just update status
                }
            }
        }
        DashCmd::YubikeyGeneratePiv(name) => match name.parse::<ndn_packet::Name>() {
            Ok(n) => match client.security_yubikey_generate(&n).await {
                Ok(p) => {
                    let pubkey = p.uri.unwrap_or_else(|| "(no key returned)".to_string());
                    yubikey_status.set(Some(format!("Generated. Public key: {pubkey}")));
                    Ok(())
                }
                Err(e) => {
                    yubikey_status.set(Some(format!("Generate failed: {e}")));
                    Ok(())
                }
            },
            Err(_) => {
                yubikey_status.set(Some("Invalid NDN name".to_string()));
                Ok(())
            }
        },
        DashCmd::DiscoveryConfigSet(params) => client
            .discovery_config_set(&params)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string()),
        DashCmd::DvrConfigSet(params) => client
            .routing_dvr_config_set(&params)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string()),
        DashCmd::SchemaRuleAdd(rule) => match client.security_schema_rule_add(&rule).await {
            Ok(_) => {
                append_schema_journal(
                    SchemaJournalKind::SchemaRuleAdd,
                    rule,
                    &identity_name,
                    &identity_is_ephemeral,
                );
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        },
        DashCmd::SchemaRuleRemove(index) => {
            // Capture the rule text before the remove so the journal entry has a
            // meaningful subject; out-of-range indices journal with "<unknown>".
            let subject = schema_rules
                .peek()
                .iter()
                .find(|r| r.index as u64 == index)
                .map(|r| format!("{} => {}", r.data_pattern, r.key_pattern))
                .unwrap_or_else(|| format!("<index={index}>"));
            match client.security_schema_rule_remove(index).await {
                Ok(_) => {
                    append_schema_journal(
                        SchemaJournalKind::SchemaRuleRemove,
                        subject,
                        &identity_name,
                        &identity_is_ephemeral,
                    );
                    Ok(())
                }
                Err(e) => Err(e.to_string()),
            }
        }
        DashCmd::SchemaSet(rules) => match client.security_schema_set(&rules).await {
            Ok(_) => {
                let line_count = rules.lines().filter(|l| !l.trim().is_empty()).count();
                let subject = format!("<bulk replace · {line_count} rule(s)>");
                append_schema_journal(
                    SchemaJournalKind::SchemaRuleAdd,
                    subject,
                    &identity_name,
                    &identity_is_ephemeral,
                );
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        },
        DashCmd::SecurityValidateTrace(target) => {
            // Result lands in the sidesheet; no toast (the sidesheet IS the UX).
            match target.parse::<ndn_packet::Name>() {
                Ok(n) => match client.security_validate(&n).await {
                    Ok(resp) if resp.is_ok() => {
                        match TrustValidationResult::from_json(&resp.status_text) {
                            Ok(parsed) => {
                                trust_validation.set(Some((target, parsed)));
                                Ok(())
                            }
                            Err(e) => Err(format!("validate response parse: {e}")),
                        }
                    }
                    Ok(resp) => Err(format!(
                        "validate rejected: {} {}",
                        resp.status_code, resp.status_text
                    )),
                    Err(e) => Err(e.to_string()),
                },
                Err(e) => Err(format!("invalid target name: {e}")),
            }
        }
        DashCmd::SecurityAnchorAdd {
            name,
            fingerprint_hex,
            cert_wire_hex,
        } => {
            // Empty cert_wire_hex journals intent only; otherwise fires anchor-add
            // and journals on 2xx only (the anchor must actually be installed).
            let parsed_name = match name.parse::<ndn_packet::Name>() {
                Ok(n) => n,
                Err(e) => {
                    return push_toast(format!("invalid anchor name: {e}"), ToastLevel::Error);
                }
            };
            let wire_subject = format!("anchor={name} fingerprint={fingerprint_hex}");
            if cert_wire_hex.trim().is_empty() {
                append_schema_journal(
                    SchemaJournalKind::AnchorAdd,
                    format!("{wire_subject} mode=intent-only"),
                    &identity_name,
                    &identity_is_ephemeral,
                );
                Ok(())
            } else {
                match client
                    .security_anchor_add(&parsed_name, &cert_wire_hex)
                    .await
                {
                    Ok(_) => {
                        append_schema_journal(
                            SchemaJournalKind::AnchorAdd,
                            format!("{wire_subject} mode=installed"),
                            &identity_name,
                            &identity_is_ephemeral,
                        );
                        Ok(())
                    }
                    Err(e) => Err(e.to_string()),
                }
            }
        }
        DashCmd::SecurityAnchorRemove { name } => {
            let parsed_name = match name.parse::<ndn_packet::Name>() {
                Ok(n) => n,
                Err(e) => {
                    return push_toast(format!("invalid anchor name: {e}"), ToastLevel::Error);
                }
            };
            match client.security_anchor_remove(&parsed_name).await {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
        DashCmd::SecuritySafebagImport {
            name,
            safebag_wire,
            passphrase,
        } => {
            let parsed_name = match name.parse::<ndn_packet::Name>() {
                Ok(n) => n,
                Err(e) => {
                    return push_toast(format!("invalid SafeBag key name: {e}"), ToastLevel::Error);
                }
            };
            match client
                .security_safebag_import(&parsed_name, &safebag_wire, passphrase.as_bytes())
                .await
            {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
        DashCmd::CaListApprovals => refresh_ca_approvals(client).await,
        DashCmd::CaApprove { request_id } => {
            let result = client
                .ca_approve(&request_id)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string());
            // Refresh the pending list so the just-approved row
            // disappears from the operator's view. Refresh failures
            // are non-fatal — surface only the original verb's error.
            let _ = refresh_ca_approvals(client).await;
            result
        }
        DashCmd::CaDeny { request_id, reason } => {
            let result = client
                .ca_deny(&request_id, &reason)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string());
            let _ = refresh_ca_approvals(client).await;
            result
        }
        DashCmd::SecurityPolicySet(policy) => {
            let body = policy.to_json();
            match client.security_policy_set(&body).await {
                Ok(resp) if resp.is_ok() => {
                    // Audit bridge: hash the submitted JSON body and append a
                    // policy-set event to the local AuditLogChain.
                    let initiator =
                        active_identity_name_for_audit(&identity_name, &identity_is_ephemeral);
                    let ts_ns = unix_ns_now();
                    use sha2::{Digest as _, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(body.as_bytes());
                    let digest: [u8; 32] = hasher.finalize().into();
                    let entry =
                        crate::security_chains::policy_set_audit_entry(ts_ns, &initiator, &digest);
                    crate::security_chains::append_audit_entry(entry);
                    let _ = mgmt_access_policy;
                    Ok(())
                }
                Ok(resp) => Err(format!(
                    "policy-set rejected: {} {}",
                    resp.status_code, resp.status_text
                )),
                Err(e) => Err(e.to_string()),
            }
        }
    };

    match result {
        Ok(()) => {
            error_msg.set(None);
            if let Some(label) = op_label {
                push_toast(label, ToastLevel::Success);
            }
            // The immediate post-command refresh now runs in the coroutine loop
            // (which owns `&mut engine`) right after run_cmd returns.
        }
        Err(e) => {
            push_toast(humanize_cmd_error(&e), ToastLevel::Error);
        }
    }
}

/// Turn a raw mgmt error into operator-actionable guidance. Privileged
/// commands (add anchor, import key, route/schema edits) are always
/// signed-and-validated by the forwarder; a fresh forwarder with no
/// configured trust anchor refuses them by design — trust is bootstrapped
/// out-of-band, not over the unauthenticated management channel.
fn humanize_cmd_error(e: &str) -> String {
    let lower = e.to_lowercase();
    if lower.contains("no validator is configured") || lower.contains("authentication required") {
        return format!(
            "Forwarder refused a privileged command: it requires signed management commands but \
             has no trust anchor configured, so it can't validate anyone. Bootstrap trust out-of-band: \
             (1) `ndn-sec keygen --anchor /op/<you>`, (2) point [security.mgmt] trust_anchor_pib at that \
             PIB and restart the forwarder, (3) `ndn-sec export /op/<you>` and import that SafeBag here \
             so the dashboard signs as a trusted operator. ({e})"
        );
    }
    if lower.contains("invalid command signature")
        || lower.contains("signature required")
        || lower.contains("unauthorized")
    {
        return format!(
            "Forwarder rejected the command's signature: the dashboard's active signing identity isn't \
             trusted for this operation. Import a SafeBag whose identity the forwarder's trust anchor \
             covers, then retry. ({e})"
        );
    }
    format!("Command failed: {e}")
}

/// Initiator name attached to audit entries. Returns the live identity name
/// when persistent, or `/local/ndn-dashboard/ephemeral-<name>` when ephemeral
/// (so the audit log records who clicked without conflating with a real
/// persistent identity).
fn active_identity_name_for_audit(
    identity_name: &Signal<String>,
    identity_is_ephemeral: &Signal<bool>,
) -> String {
    let n = identity_name.peek().clone();
    if n.is_empty() {
        return "/local/ndn-dashboard/anonymous".into();
    }
    if *identity_is_ephemeral.peek() {
        format!("/local/ndn-dashboard/ephemeral{n}")
    } else {
        n
    }
}

/// Unix-epoch nanoseconds; falls back to zero on clock-before-epoch.
fn unix_ns_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Fetch the latest `ca/list-approvals` and update CA_APPROVALS_STATE.
/// Shared by the explicit refresh command (operator tap) and the
/// post-approve/post-deny refresh path so the operator's view stays
/// in sync. Returns `Err(...)` on transport failure (status row
/// renders the error).
async fn refresh_ca_approvals(client: &MgmtClient) -> Result<(), String> {
    use crate::views::ca_approvals::{CaApprovalsState, PendingApprovalRow};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .ok();
    match client.ca_list_approvals().await {
        Ok(rows) => {
            let mapped: Vec<PendingApprovalRow> = rows
                .into_iter()
                .map(|(id, cert_name, description)| PendingApprovalRow {
                    id,
                    cert_name,
                    description,
                })
                .collect();
            *crate::app_shared::CA_APPROVALS_STATE.write() = CaApprovalsState {
                rows: mapped,
                last_refresh_unix_s: now,
                last_error: None,
            };
            Ok(())
        }
        Err(e) => {
            *crate::app_shared::CA_APPROVALS_STATE.write() = CaApprovalsState {
                rows: Vec::new(),
                last_refresh_unix_s: now,
                last_error: Some(e.to_string()),
            };
            Err(e.to_string())
        }
    }
}

/// Pulls the initiator name from the same helper the audit bridge uses so the
/// two chains agree on "who did this".
fn append_schema_journal(
    kind: crate::security_chains::SchemaJournalKind,
    subject_name: String,
    identity_name: &Signal<String>,
    identity_is_ephemeral: &Signal<bool>,
) {
    let initiator = active_identity_name_for_audit(identity_name, identity_is_ephemeral);
    let entry = crate::security_chains::SchemaJournalEntry {
        ts_unix_ns: unix_ns_now(),
        kind,
        subject_name,
        initiator_name: initiator,
    };
    crate::security_chains::append_schema_entry(entry);
}

/// Parse the `identity-status` dataset response.
///
/// Expected format: `identity=<name> is_ephemeral=<bool> pib_path=<path>`
fn parse_identity_status(text: &str) -> (String, bool, Option<String>) {
    let mut name = String::new();
    let mut ephemeral = false;
    let mut pib_path = None::<String>;

    for token in text.split_whitespace() {
        if let Some(v) = token.strip_prefix("identity=") {
            name = v.to_string();
        }
        if let Some(v) = token.strip_prefix("is_ephemeral=") {
            ephemeral = v == "true";
        }
        if let Some(v) = token.strip_prefix("pib_path=") {
            pib_path = Some(v.to_string());
        }
    }
    (name, ephemeral, if ephemeral { None } else { pib_path })
}
