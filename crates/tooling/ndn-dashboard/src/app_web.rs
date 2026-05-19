//! Web variant of the dashboard App component.
//!
//! Uses [`WsMgmtClient`] over WebSocket instead of `ndn_ipc::MgmtClient`
//! over Unix sockets.  Omits desktop-only features: system tray, subprocess
//! management, and embedded tool servers.

#![cfg(feature = "web")]

use std::collections::{HashMap, VecDeque};

use dioxus::prelude::*;
use futures::StreamExt as _;

pub use crate::app_shared::*;

use crate::{
    settings::DASH_SETTINGS,
    styles::CSS,
    types::*,
    views::{
        View,
        fleet::Fleet,
        logs::Logs,
        onboarding::{Onboarding, is_onboarded},
        overview::Overview,
        radio::Radio,
        routing::Routing,
        security::Security,
        strategy::Strategy,
    },
    ws_mgmt::WsMgmtClient,
};

fn default_ws_url() -> String {
    let query = web_sys::window()
        .and_then(|w| w.location().search().ok())
        .unwrap_or_default();
    match crate::forwarder_profile::resolve_web(&query) {
        crate::forwarder_profile::ConnectionMode::WebSocket { url, profile } => {
            tracing::info!(
                forwarder = %profile.human_label(),
                url,
                "selected forwarder profile (web)",
            );
            url
        }
        crate::forwarder_profile::ConnectionMode::BrowserEngine => {
            // Fall through to ws default; the in-page engine path is
            // wired separately via `?engine=local` in the
            // `app_web_engine` module (stub today). Keeping a usable
            // ws URL avoids a hard error if the engine path isn't
            // built in.
            tracing::info!("?engine=local requested — browser-engine path is stubbed");
            "ws://localhost:9696".to_string()
        }
        // Spawn / Attach are desktop-only; not reachable on wasm32.
        _ => "ws://localhost:9696".to_string(),
    }
}

/// Web-specific App component.
///
/// Identical sidebar + view layout to the desktop app, but:
/// - Connects via WebSocket instead of Unix socket
/// - No "Start/Stop Router" controls
/// - No embedded tool servers
/// - No system tray
/// - Settings persisted to localStorage
#[component]
pub fn AppWeb() -> Element {
    let mut conn_state: Signal<ConnState> = use_signal(|| ConnState::Disconnected);
    let mut ws_url: Signal<String> = use_signal(default_ws_url);
    let status: Signal<Option<ForwarderStatus>> = use_signal(|| None);
    let mut faces: Signal<Vec<FaceInfo>> = use_signal(Vec::new);
    let mut routes: Signal<Vec<FibEntry>> = use_signal(Vec::new);
    let rib_entries: Signal<Vec<RibEntryInfo>> = use_signal(Vec::new);
    let mut cs: Signal<Option<CsInfo>> = use_signal(|| None);
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
    let cs_hit_history: Signal<VecDeque<f64>> = use_signal(VecDeque::new);
    let face_throughput: Signal<HashMap<u64, VecDeque<ThroughputSample>>> =
        use_signal(HashMap::new);
    let discovery_status: Signal<Option<DiscoveryStatus>> = use_signal(|| None);
    let dvr_status: Signal<Option<DvrStatus>> = use_signal(|| None);
    let mut error_msg: Signal<Option<String>> = use_signal(|| None);
    let mut show_onboarding: Signal<bool> = use_signal(|| !is_onboarded());
    let mut show_gear_menu: Signal<bool> = use_signal(|| false);

    // Theme class is bound reactively on the layout root below — no JS.

    // ── Engine / WebSocket management coroutine ─────────────────────────────
    // Two paths gated on connection mode:
    //   - `?engine=local` (browser-engine feature): start the in-page
    //     `ForwarderEngine`, set Connected, poll via direct introspection.
    //   - else: speak NFD-mgmt over WebSocket (the original WS path).
    let cmd = use_coroutine(move |mut rx: UnboundedReceiver<DashCmd>| async move {
        // Decide the mode once per coroutine spawn. Reconnect spins this loop.
        let query = web_sys::window()
            .and_then(|w| w.location().search().ok())
            .unwrap_or_default();
        let mode = crate::forwarder_profile::resolve_web(&query);

        // Build a client appropriate for the resolved connection mode.
        // BrowserEngine takes the local-transport branch (in-page
        // engine + `mount_management`); everything else falls through
        // to the WebSocket transport.  The poll/cmd loop below is
        // identical for both — the dashboard speaks NFD mgmt over a
        // single client type.
        #[cfg(feature = "browser-engine")]
        let local_engine_mode = matches!(
            mode,
            crate::forwarder_profile::ConnectionMode::BrowserEngine
        );
        #[cfg(not(feature = "browser-engine"))]
        let local_engine_mode = false;
        let _ = mode;

        loop {
            conn_state.set(ConnState::Connecting);
            // §6: new connection = new session; reset gate
            // acceptance (mirrors the desktop coroutine).
            crate::security_state::reset_acceptance();

            let mut client = {
                #[cfg(feature = "browser-engine")]
                if local_engine_mode {
                    let handle = crate::browser_engine::init();
                    match handle.take_mgmt_channels().await {
                        Some(channels) => WsMgmtClient::new_local(channels),
                        None => {
                            // The in-page engine's mgmt channels can only
                            // be taken once; on reconnect we already
                            // own them, so signal Connected and idle.
                            conn_state.set(ConnState::Connected);
                            error_msg.set(None);
                            futures::future::pending::<()>().await;
                            unreachable!();
                        }
                    }
                } else {
                    WsMgmtClient::new(&ws_url.peek().clone())
                }
                #[cfg(not(feature = "browser-engine"))]
                WsMgmtClient::new(&ws_url.peek().clone())
            };

            match client.connect().await {
                Ok(()) => {}
                Err(e) => {
                    conn_state.set(ConnState::Error(e.to_string()));
                    // Wait before retry
                    gloo_timers::future::TimeoutFuture::new(3_000).await;
                    continue;
                }
            };

            conn_state.set(ConnState::Connected);
            error_msg.set(None);
            *LAST_LOG_SEQ.write() = 0;

            // Initial poll
            if let Err(e) =
                poll_all_web(&mut client, &status, &faces, &routes, &cs, &strategies).await
            {
                conn_state.set(ConnState::Disconnected);
                error_msg.set(Some(e));
                continue;
            }

            // Poll loop
            let mut tick = 0u32;
            'session: loop {
                // Use gloo timer for web-compatible sleep
                gloo_timers::future::TimeoutFuture::new(3_000).await;
                tick += 1;

                // Check for commands (non-blocking drain)
                while let Ok(Some(cmd_msg)) = rx.try_next() {
                    if matches!(cmd_msg, DashCmd::Reconnect) {
                        break 'session;
                    }
                    run_cmd_web(cmd_msg, &mut client, &error_msg).await;
                }

                // Poll
                if let Err(e) =
                    poll_all_web(&mut client, &status, &faces, &routes, &cs, &strategies).await
                {
                    conn_state.set(ConnState::Disconnected);
                    error_msg.set(Some(e));
                    break 'session;
                }
            }
        }
    });

    // router_cmd / tool_cmd are desktop-only fields on AppCtx — no
    // subprocess substrate on web means no stub coroutines either.

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
        cs_hit_history,
        face_throughput,
        discovery_status,
        dvr_status,
        cmd,
    };
    use_context_provider(move || ctx);

    // §3.2 sec_dot + §3.1 IdentityChip derive from AppCtx via the
    // shared components; the prior keys-presence heuristic is gone.

    // Views that are NOT available on web. Coding/RateLimit are
    // desktop-only until the WsMgmtClient-backed variants land
    // (docs/notes/dashboard-correctness-floor-2026-05-13.md §1d).
    let web_hidden_views = [View::Tools, View::Session, View::Coding, View::RateLimit];

    rsx! {
        document::Style { "{CSS}" }

        // §2 security gate — modal first-run gate (same component on
        // desktop and web; reads AppCtx).
        crate::security_gate::SecurityGate {}

        if *show_onboarding.read() {
            Onboarding {
                on_complete: move |_| show_onboarding.set(false),
            }
        }

        div {
            class: if *DARK_MODE.read() { "layout" } else { "layout light-mode" },
            // ── Sidebar ───────────────────────────────────────────────────
            nav { class: "sidebar",
                div { class: "sidebar-logo",
                    style: "display:flex;align-items:center;justify-content:space-between;",
                    span { "NDN Dashboard" }
                    span { class: "badge badge-sm", style: "font-size:0.6rem;", "WEB" }
                    crate::security_surfaces::SecDot {}
                }
                for view in View::NAV {
                    {
                        let view = *view;
                        // Skip desktop-only views
                        if web_hidden_views.contains(&view) {
                            return rsx! {};
                        }
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

            // ── Main area ─────────────────────────────────────────────────
            div { class: "main",
                // Connection bar — WebSocket URL instead of socket path
                div { class: "conn-bar",
                    span {
                        class: "{conn_state.read().badge_class()}",
                        "{conn_state.read().label()}"
                    }
                    crate::security_surfaces::IdentityChip {}
                    input {
                        r#type: "text",
                        placeholder: "WebSocket URL (ws://host:port)",
                        value: "{ws_url}",
                        oninput: move |e| ws_url.set(e.value()),
                        style: "min-width:200px;",
                    }
                    button {
                        class: "btn btn-secondary",
                        onclick: move |_| cmd.send(DashCmd::Reconnect),
                        "Connect"
                    }
                    button {
                        class: "icon-btn",
                        title: "Refresh",
                        onclick: move |_| cmd.send(DashCmd::Reconnect),
                        "⟳"
                    }
                    div { style: "flex:1;" }
                    // Theme toggle
                    button {
                        class: "theme-toggle",
                        title: if *DARK_MODE.read() { "Switch to Light Mode" } else { "Switch to Dark Mode" },
                        onclick: move |_| {
                            let next = !*DARK_MODE.read();
                            *DARK_MODE.write() = next;
                        },
                        if *DARK_MODE.read() { "☀" } else { "🌙" }
                    }
                    // No router start/stop on web — just connection status
                }

                // View content
                div { class: "content-area",
                    if let Some(err) = error_msg.read().as_ref() {
                        div { class: "alert alert-error",
                            strong { "Connection error: " }
                            "{err}"
                        }
                    }
                    { render_view_web(*ACTIVE_VIEW.read()) }
                }
            }
        }
    }
}

/// Render a view component (web variant — omits Tools and Session).
fn render_view_web(view: View) -> Element {
    match view {
        View::Overview => rsx! { Overview {} },
        // Routes and Faces are rendered under their parent views
        View::Strategy => rsx! { Strategy {} },
        View::Fleet => rsx! { Fleet {} },
        View::Routing => rsx! { Routing {} },
        View::Security => rsx! { Security {} },
        View::Logs => rsx! { Logs {} },
        View::RouterConfig | View::DashboardConfig => rsx! {
            div { class: "placeholder", style: "padding:2rem;color:var(--text2);",
                "Configuration editing requires the desktop version."
            }
        },
        View::Radio => rsx! { Radio {} },
        // Desktop-only views render a placeholder on web.
        // Coding/RateLimit will move to web once their fetch path is
        // ported off `ndn-ipc::MgmtClient` (§1d).
        View::Tools | View::Session | View::Coding | View::RateLimit => rsx! {
            div { class: "placeholder",
                style: "padding:2rem;color:var(--text2);",
                "This feature requires the desktop version of the dashboard."
            }
        },
    }
}

// ── Simplified polling for web ──────────────────────────────────────────────

async fn poll_all_web(
    client: &mut WsMgmtClient,
    status: &Signal<Option<ForwarderStatus>>,
    faces: &Signal<Vec<FaceInfo>>,
    routes: &Signal<Vec<FibEntry>>,
    cs: &Signal<Option<CsInfo>>,
    strategies: &Signal<Vec<StrategyEntry>>,
) -> Result<(), String> {
    use ndn_config::nfd_dataset;

    // ── status/general — ControlResponse text encodes `faces=N fib=N pit=N cs=N`.
    if let Ok(resp) = client.status_general().await
        && resp.is_ok()
    {
        let mut status_sig = *status;
        status_sig.set(Some(ForwarderStatus::parse(&resp.status_text)));
    }

    // ── faces/list — dataset of FaceStatus TLVs.
    if let Ok(resp) = client.list_faces().await
        && resp.is_ok()
    {
        let entries = nfd_dataset::FaceStatus::decode_all(&resp.body);
        let mapped: Vec<FaceInfo> = entries
            .into_iter()
            .map(|fs| FaceInfo {
                face_id: fs.face_id,
                remote_uri: Some(fs.uri.clone()),
                local_uri: if fs.local_uri.is_empty() {
                    None
                } else {
                    Some(fs.local_uri.clone())
                },
                persistency: fs.persistency_str().to_string(),
                kind: None,
                face_scope: fs.face_scope,
                link_type: fs.link_type,
                mtu: fs.mtu,
                n_in_interests: fs.n_in_interests,
                n_out_interests: fs.n_out_interests,
                n_in_data: fs.n_in_data,
                n_out_data: fs.n_out_data,
                n_in_bytes: fs.n_in_bytes,
                n_out_bytes: fs.n_out_bytes,
                n_in_nacks: fs.n_in_nacks,
                n_out_nacks: fs.n_out_nacks,
            })
            .collect();
        let mut faces_sig = *faces;
        faces_sig.set(mapped);
    }

    // ── fib/list — dataset of FibEntry TLVs.
    if let Ok(resp) = client.list_fib().await
        && resp.is_ok()
    {
        let entries = nfd_dataset::FibEntry::decode_all(&resp.body);
        let mapped: Vec<FibEntry> = entries
            .into_iter()
            .map(|fe| FibEntry {
                prefix: fe.name.to_string(),
                nexthops: fe
                    .nexthops
                    .iter()
                    .map(|nh| NextHop {
                        face_id: nh.face_id,
                        cost: nh.cost as u32,
                    })
                    .collect(),
            })
            .collect();
        let mut routes_sig = *routes;
        routes_sig.set(mapped);
    }

    // ── cs/info — ControlResponse text encodes counters.
    if let Ok(resp) = client.cs_info().await
        && resp.is_ok()
    {
        let mut cs_sig = *cs;
        cs_sig.set(CsInfo::parse(&resp.status_text));
    }

    // ── strategy-choice/list — dataset of StrategyChoice TLVs.
    if let Ok(resp) = client.list_strategy().await
        && resp.is_ok()
    {
        let entries = nfd_dataset::StrategyChoice::decode_all(&resp.body);
        let mapped: Vec<StrategyEntry> = entries
            .into_iter()
            .map(|sc| StrategyEntry {
                prefix: sc.name.to_string(),
                strategy: sc.strategy.to_string(),
            })
            .collect();
        let mut strategies_sig = *strategies;
        strategies_sig.set(mapped);
    }

    Ok(())
}

async fn run_cmd_web(cmd: DashCmd, client: &mut WsMgmtClient, error_msg: &Signal<Option<String>>) {
    use ndn_config::ControlParameters;
    use ndn_packet::Name;

    let result = match cmd {
        DashCmd::FaceCreate(uri) => {
            let params = ControlParameters {
                uri: Some(uri),
                ..Default::default()
            };
            client.send_cmd("faces", "create", Some(&params)).await
        }
        DashCmd::FaceDestroy(id) => {
            let params = ControlParameters {
                face_id: Some(id),
                ..Default::default()
            };
            client.send_cmd("faces", "destroy", Some(&params)).await
        }
        DashCmd::RouteAdd {
            prefix,
            face_id,
            cost,
        } => {
            let name: Name = match prefix.parse() {
                Ok(n) => n,
                Err(e) => {
                    error_msg
                        .to_owned()
                        .set(Some(format!("invalid prefix '{prefix}': {e:?}")));
                    return;
                }
            };
            let params = ControlParameters {
                name: Some(name),
                // face_id == 0 means "use the requesting face" — leave
                // it unset so the forwarder resolves it from the PIT.
                face_id: (face_id != 0).then_some(face_id),
                cost: Some(cost),
                ..Default::default()
            };
            client.send_cmd("rib", "register", Some(&params)).await
        }
        DashCmd::RouteRemove { prefix, face_id } => {
            let name: Name = match prefix.parse() {
                Ok(n) => n,
                Err(e) => {
                    error_msg
                        .to_owned()
                        .set(Some(format!("invalid prefix '{prefix}': {e:?}")));
                    return;
                }
            };
            let params = ControlParameters {
                name: Some(name),
                face_id: (face_id != 0).then_some(face_id),
                ..Default::default()
            };
            client.send_cmd("rib", "unregister", Some(&params)).await
        }
        DashCmd::StrategySet { prefix, strategy } => {
            let name: Name = match prefix.parse() {
                Ok(n) => n,
                Err(e) => {
                    error_msg
                        .to_owned()
                        .set(Some(format!("invalid prefix '{prefix}': {e:?}")));
                    return;
                }
            };
            let strategy_name: Name = match strategy.parse() {
                Ok(n) => n,
                Err(e) => {
                    error_msg
                        .to_owned()
                        .set(Some(format!("invalid strategy '{strategy}': {e:?}")));
                    return;
                }
            };
            let params = ControlParameters {
                name: Some(name),
                strategy: Some(strategy_name),
                ..Default::default()
            };
            client
                .send_cmd("strategy-choice", "set", Some(&params))
                .await
        }
        DashCmd::StrategyUnset(prefix) => {
            let name: Name = match prefix.parse() {
                Ok(n) => n,
                Err(e) => {
                    error_msg
                        .to_owned()
                        .set(Some(format!("invalid prefix '{prefix}': {e:?}")));
                    return;
                }
            };
            let params = ControlParameters {
                name: Some(name),
                ..Default::default()
            };
            client
                .send_cmd("strategy-choice", "unset", Some(&params))
                .await
        }
        DashCmd::CsCapacity(capacity) => {
            let params = ControlParameters {
                capacity: Some(capacity),
                ..Default::default()
            };
            client.send_cmd("cs", "config", Some(&params)).await
        }
        DashCmd::CsErase(prefix) => {
            let name: Name = match prefix.parse() {
                Ok(n) => n,
                Err(e) => {
                    error_msg
                        .to_owned()
                        .set(Some(format!("invalid prefix '{prefix}': {e:?}")));
                    return;
                }
            };
            let params = ControlParameters {
                name: Some(name),
                ..Default::default()
            };
            client.send_cmd("cs", "erase", Some(&params)).await
        }
        DashCmd::Shutdown => client.send_cmd("status", "shutdown", None).await,
        DashCmd::Reconnect => return,
        DashCmd::RefreshConfig => client.send_cmd("config", "get", None).await,
        // The remaining DashCmd variants (recording, security, yubikey,
        // discovery/dvr config, schema) are desktop-only flows that
        // don't have a web equivalent yet. Surface the gap as an error
        // instead of a silent warn so the user sees why nothing happened.
        other => {
            error_msg
                .to_owned()
                .set(Some(format!("Command not supported on web: {other:?}")));
            return;
        }
    };

    match result {
        Ok(resp) if resp.is_ok() => {
            // Clear any prior error on success.
            error_msg.to_owned().set(None);
        }
        Ok(resp) => {
            error_msg.to_owned().set(Some(format!(
                "mgmt {}: {}",
                resp.status_code, resp.status_text
            )));
        }
        Err(e) => {
            error_msg.to_owned().set(Some(e.to_string()));
        }
    }
}
