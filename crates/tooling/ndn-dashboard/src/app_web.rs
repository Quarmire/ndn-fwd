//! Web variant of the dashboard App component.
//!
//! Uses [`WsMgmtClient`] over WebSocket instead of `ndn_ipc::MgmtClient`
//! over Unix sockets.  Omits desktop-only features: system tray, subprocess
//! management, and embedded tool servers.

#![cfg(feature = "web")]

use std::collections::{HashMap, VecDeque};

use dioxus::prelude::*;
use futures::{FutureExt as _, StreamExt as _};

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

    // §4.6 / §2.4 — initialise the IndexedDB-backed audit log + schema
    // journal once per page load. `init_*` is fire-and-forget: the
    // async IDB open runs via `wasm_bindgen_futures::spawn_local` and
    // the chains become writable once the open resolves. Entries
    // submitted before then log a WARN and drop.
    use_hook(|| {
        let key_locator = ndn_packet::Name::root()
            .append(b"local")
            .append(b"ndn-dashboard")
            .append(b"KEY")
            .append(b"ephemeral");
        // Dir argument is ignored on wasm32 — kept for signature
        // parity with the desktop FileStore-based init.
        let dir = std::path::PathBuf::new();
        crate::security_chains::init_audit_chain(dir.clone(), key_locator.clone());
        crate::security_chains::init_schema_journal(dir, key_locator);
    });
    let cs_hit_history: Signal<VecDeque<f64>> = use_signal(VecDeque::new);
    let face_throughput: Signal<HashMap<u64, VecDeque<ThroughputSample>>> =
        use_signal(HashMap::new);
    let discovery_status: Signal<Option<DiscoveryStatus>> = use_signal(|| None);
    let dvr_status: Signal<Option<DvrStatus>> = use_signal(|| None);
    let mut error_msg: Signal<Option<String>> = use_signal(|| None);
    let mut show_onboarding: Signal<bool> = use_signal(|| !is_onboarded());
    let mut show_gear_menu: Signal<bool> = use_signal(|| false);
    let collapsed_buckets: Signal<std::collections::HashSet<crate::views::Bucket>> =
        use_signal(std::collections::HashSet::new);

    // Theme class is bound reactively on the layout root below — no JS.

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
            // §6: a *successful* new connection re-fires the security gate.
            // Resetting here (not at the top of the loop) mirrors the
            // desktop coroutine and stops a failed reconnect from wiping
            // the operator's acknowledgement on every retry.
            crate::security_state::reset_acceptance();
            *LAST_LOG_SEQ.write() = 0;

            // The engine now owns the connected client: the poll loop drives it
            // (forwarding plane via `poll_forwarding`) and commands borrow it
            // back via `client_mut`.
            let mut engine = ndn_dashboard_core::DashboardEngine::new(client);

            // Initial poll
            if let Err(e) = poll_all_web(
                &mut engine,
                &status,
                &faces,
                &routes,
                &cs,
                &strategies,
                &security_keys,
                &security_anchors,
                &schema_rules,
                &ca_info,
                &identity_name,
                &identity_is_ephemeral,
                &identity_pib_path,
                &cert_valid_until_unix_s,
                &mgmt_signed_commands_required,
                &mgmt_access_policy,
                &security_surface_supported,
                &validation_stats,
                &validation_history,
            )
            .await
            {
                conn_state.set(ConnState::Disconnected);
                error_msg.set(Some(e));
                // Back off before retrying: the connection opened but the
                // forwarder's mgmt responses don't decode. Without this,
                // connect-succeeds / poll-fails spins in a tight loop and
                // floods the UI with reconnect churn (mirrors the desktop
                // coroutine and the session poll loop below).
                gloo_timers::future::TimeoutFuture::new(3_000).await;
                continue;
            }

            // Poll loop
            let mut tick = 0u32;
            'session: loop {
                // Wake on the 3s tick OR as soon as a command arrives, so
                // RefreshNow (live events) and user commands act promptly
                // instead of waiting up to a full poll interval.
                let woke_on: Option<DashCmd> = {
                    let timer = gloo_timers::future::TimeoutFuture::new(3_000).fuse();
                    let next = rx.next().fuse();
                    futures::pin_mut!(timer, next);
                    futures::select! {
                        _ = timer => None,
                        c = next => c,
                    }
                };
                tick += 1;

                // Handle the waking command (if any) plus any others queued.
                // RefreshNow just falls through to an immediate poll.
                let mut pending = woke_on;
                let mut do_reconnect = false;
                while let Some(cmd_msg) = pending.take() {
                    match cmd_msg {
                        DashCmd::Reconnect => {
                            do_reconnect = true;
                            break;
                        }
                        DashCmd::RefreshNow => {}
                        other => {
                            run_cmd_web(
                                other,
                                engine.client_mut(),
                                &error_msg,
                                &trust_validation,
                                &identity_name,
                                &identity_is_ephemeral,
                            )
                            .await;
                        }
                    }
                    pending = rx.try_next().ok().flatten();
                }
                if do_reconnect {
                    break 'session;
                }

                // Poll
                if let Err(e) = poll_all_web(
                    &mut engine,
                    &status,
                    &faces,
                    &routes,
                    &cs,
                    &strategies,
                    &security_keys,
                    &security_anchors,
                    &schema_rules,
                    &ca_info,
                    &identity_name,
                    &identity_is_ephemeral,
                    &identity_pib_path,
                    &cert_valid_until_unix_s,
                    &mgmt_signed_commands_required,
                    &mgmt_access_policy,
                    &security_surface_supported,
                    &validation_stats,
                    &validation_history,
                )
                .await
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

    // Live event subscriber: short-polls the faces/rib/strategy notification
    // streams (one WS connection each) and sends RefreshNow so external
    // changes refresh promptly. Fail-safe — if a stream/relay doesn't serve
    // notifications it just reconnects and the 3s poll loop carries on.
    use_coroutine(move |_rx: UnboundedReceiver<()>| async move {
        let subs = ["faces", "rib", "strategy-choice"].map(|m| run_ws_subscriber(m, ws_url, cmd));
        futures::future::join_all(subs).await;
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
        cmd,
    };
    use_context_provider(move || ctx);

    // §3.2 sec_dot + §3.1 IdentityChip derive from AppCtx via the
    // shared components; the prior keys-presence heuristic is gone.

    // Views that are NOT available on web. Coding/RateLimit are
    // desktop-only until the WsMgmtClient-backed variants land
    // ((internal) §1d).
    let web_hidden_views = [View::Tools, View::Session, View::Coding, View::RateLimit];
    let app_root_class = if *DARK_MODE.read() {
        "app-root"
    } else {
        "app-root light-mode"
    };

    rsx! {
        AppStyles {}

        // Single ancestor for every overlay — gate, modals, toast,
        // drawer backdrop — so they all inherit light-mode CSS
        // variables from the `light-mode` class. Previously only
        // `.layout` carried the class, leaving every position:fixed
        // sibling stuck on dark-mode colors. The `.app-root` rule
        // also sets background:var(--bg) so body's `:root` dark bg
        // doesn't peek through.
        div {
            class: "{app_root_class}",
            WebToastOverlay {}

        // §2 security gate — modal first-run gate (same component on
        // desktop and web; reads AppCtx).
        crate::security_gate::SecurityGate {}

        // Phase C modal mounts — every button that flips one of these
        // signals depends on the corresponding modal being in the
        // component tree. Desktop mounts these in app.rs; the web
        // build was missing them, so every "+ Import SafeBag",
        // "+ Join via NDNCERT", and "Renew" action was a no-op on
        // mobile. Mounting them here gives the web build the same
        // surface as desktop.
        crate::views::safebag_import::SafeBagImportModal {
            state: crate::app_shared::SAFEBAG_IMPORT_STATE.signal(),
        }
        crate::views::enrollment_wizard::EnrollmentWizardModal {
            state: crate::app_shared::ENROLLMENT_WIZARD_STATE.signal(),
        }
        crate::views::key_rotation::KeyRotationModal {
            state: crate::app_shared::KEY_ROTATION_STATE.signal(),
        }

        if *show_onboarding.read() {
            Onboarding {
                on_complete: move |_| show_onboarding.set(false),
            }
        }

        // Mobile sidebar drawer — backdrop closes the drawer on tap.
        // Only meaningful at viewport <= 768px (handled by CSS); on
        // desktop the .sidebar-backdrop is `display:none`.
        if *SIDEBAR_OPEN.read() {
            div {
                class: "sidebar-backdrop",
                onclick: move |_| { *SIDEBAR_OPEN.write() = false; },
            }
        }

        div {
            class: {
                // light-mode lives on the `.app-root` ancestor now;
                // this layout div just tracks the drawer state.
                let mut c = String::from("layout");
                if *SIDEBAR_OPEN.read() { c.push_str(" sidebar-open"); }
                c
            },
            nav { class: "sidebar",
                div { class: "sidebar-logo",
                    style: "display:flex;align-items:center;justify-content:space-between;",
                    span { "NDN Dashboard" }
                    span { class: "badge badge-sm", style: "font-size:0.6rem;", "WEB" }
                    crate::security_surfaces::SecDot {}
                }
                for bucket in crate::views::Bucket::ALL {
                    {
                        let bucket = *bucket;
                        // Views in this bucket that the web build actually shows.
                        let visible: Vec<View> = bucket
                            .views()
                            .iter()
                            .copied()
                            .filter(|v| !web_hidden_views.contains(v))
                            .collect();
                        if visible.is_empty() {
                            return rsx! {};
                        }
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
                                    for view in visible {
                                        {
                                            let is_active = *ACTIVE_VIEW.read() == view;
                                            rsx! {
                                                div {
                                                    class: if is_active { "nav-item active" } else { "nav-item" },
                                                    onclick: move |_| {
                                                        *ACTIVE_VIEW.write() = view;
                                                        // Auto-close drawer on mobile after pick.
                                                        *SIDEBAR_OPEN.write() = false;
                                                    },
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
                // Connection bar — two-row on mobile. Status row
                // (always visible) carries hamburger, conn state,
                // identity chip, engine pill, refresh, theme toggle.
                // Config row (URL + Connect) is hidden by default on
                // mobile; tap the conn-state badge to expand. Desktop
                // shows everything on one row.
                div { class: "conn-bar",
                    // Status row.
                    div { class: "conn-bar-status",
                        button {
                            class: "hamburger",
                            aria_label: "Open menu",
                            onclick: move |_| {
                                let cur = *SIDEBAR_OPEN.read();
                                *SIDEBAR_OPEN.write() = !cur;
                            },
                            "☰"
                        }
                        button {
                            class: "conn-state-toggle {conn_state.read().badge_class()}",
                            title: "Tap to show / hide the WebSocket URL field",
                            aria_expanded: if *CONN_FIELD_OPEN.read() { "true" } else { "false" },
                            onclick: move |_| {
                                let cur = *CONN_FIELD_OPEN.read();
                                *CONN_FIELD_OPEN.write() = !cur;
                            },
                            "{conn_state.read().label()}"
                            // Rotating chevron — points down when collapsed
                            // (room to expand), up when expanded (room to
                            // collapse). Inline SVG-free via Unicode glyph.
                            span {
                                class: "conn-state-caret",
                                style: if *CONN_FIELD_OPEN.read() {
                                    "transform:rotate(180deg);"
                                } else {
                                    ""
                                },
                                " ▾"
                            }
                        }
                        span { class: "axis-label", "Engine" }
                        crate::views::engine_pill::EnginePill {}
                        span { class: "axis-divider" }
                        crate::security_surfaces::IdentityAxisControl {}
                        crate::security_surfaces::CapabilityBadge {}
                        div { class: "conn-bar-spacer" }
                        button {
                            class: "icon-btn",
                            title: "Refresh",
                            onclick: move |_| cmd.send(DashCmd::Reconnect),
                            "⟳"
                        }
                        button {
                            class: "theme-toggle",
                            title: if *DARK_MODE.read() { "Switch to Light Mode" } else { "Switch to Dark Mode" },
                            onclick: move |_| {
                                let next = !*DARK_MODE.read();
                                *DARK_MODE.write() = next;
                            },
                            if *DARK_MODE.read() { "☀" } else { "🌙" }
                        }
                    }

                    // Config row — URL + Connect inline. Hidden on
                    // mobile unless CONN_FIELD_OPEN is true; always
                    // shown on desktop via the `.conn-bar-config` CSS.
                    div { class: if *CONN_FIELD_OPEN.read() { "conn-bar-config open" } else { "conn-bar-config" },
                        input {
                            r#type: "text",
                            placeholder: "WebSocket URL (ws://host:port)",
                            value: "{ws_url}",
                            oninput: move |e| ws_url.set(e.value()),
                        }
                        button {
                            class: "btn btn-secondary",
                            onclick: move |_| {
                                cmd.send(DashCmd::Reconnect);
                                *CONN_FIELD_OPEN.write() = false;
                            },
                            "Connect"
                        }
                    }
                }

                // View content + right-hand inspector (design note §3).
                div { class: if crate::views::inspector::inspector_visible() { "content-host inspector-open" } else { "content-host" },
                    div { class: "content-area",
                        if let Some(err) = error_msg.read().as_ref() {
                            div { class: "alert alert-error",
                                strong { "Connection error: " }
                                "{err}"
                            }
                        }
                        crate::security_surfaces::TrustStatusPanel {}
                        { render_view_web(*ACTIVE_VIEW.read()) }
                    }
                    crate::views::inspector::Inspector {}
                }
            } // close .main
        } // close .layout
        } // close .app-root wrapper
    }
}

/// Live-event subscriber for the web build: short-polls one module's
/// `/localhost/nfd/<module>/notifications` stream on a dedicated WebSocket and
/// sends [`DashCmd::RefreshNow`] when the event sequence advances. Reconnects
/// on error/timeout; the base poll loop runs regardless, so a relay that
/// doesn't serve notifications is a harmless no-op. Mirrors the desktop
/// `notify_sub::run_subscriber`, but short-polls "latest" rather than holding
/// a long-poll (a WS relay may not keep an Interest open — see
/// `WsMgmtClient::latest_notification`).
async fn run_ws_subscriber(module: &str, ws_url: Signal<String>, cmd: Coroutine<DashCmd>) {
    loop {
        let mut client = WsMgmtClient::new(&ws_url.peek().clone());
        if client.connect().await.is_err() {
            gloo_timers::future::TimeoutFuture::new(3_000).await;
            continue;
        }
        let mut last: u64 = 0;
        loop {
            gloo_timers::future::TimeoutFuture::new(2_000).await;
            match client.latest_notification(module, 5_000).await {
                Ok(Some(seq)) => {
                    if last != 0 && seq > last {
                        cmd.send(DashCmd::RefreshNow);
                    }
                    last = seq;
                }
                // Timed out (no events yet) — reconnect to avoid a stale
                // pending recv on the cancelled long-poll.
                Ok(None) => break,
                Err(_) => break,
            }
        }
        gloo_timers::future::TimeoutFuture::new(2_000).await;
    }
}

/// Installs the global stylesheet exactly once. A propless child component is
/// memoized, so the stylesheet is rendered a single time rather than re-emitted
/// on every poll-driven re-render (which Dioxus rejects with "Changing the
/// props of `Style {}` is not supported"). Mirrors `app::AppStyles`.
#[component]
fn AppStyles() -> Element {
    rsx! {
        document::Style { "{crate::fonts::FONT_FACES}" }
        document::Style { "{CSS}" }
    }
}

/// Toast overlay for the web build. Reads `app_shared::TOASTS` (the
/// shared queue that `app_shared::push_toast` writes to). Mirrors the
/// desktop `ToastOverlay` in `app.rs` but separated so the desktop
/// path stays untouched.

#[component]
fn WebToastOverlay() -> Element {
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
        View::Compose => rsx! { crate::views::compose::Compose {} },
        View::TrustContext => rsx! { crate::views::trust_context::TrustContext {} },
        // Desktop-only views render a placeholder on web.
        // Coding/RateLimit will move to web once their fetch path is
        // ported off `ndn-ipc::MgmtClient` (§1d).
        View::Tools | View::Session | View::Coding | View::RateLimit | View::Pairing => rsx! {
            div { class: "placeholder",
                style: "padding:2rem;color:var(--text2);",
                "This feature requires the desktop version of the dashboard."
            }
        },
    }
}

#[allow(clippy::too_many_arguments)]
async fn poll_all_web(
    engine: &mut ndn_dashboard_core::DashboardEngine<WsMgmtClient>,
    status: &Signal<Option<ForwarderStatus>>,
    faces: &Signal<Vec<FaceInfo>>,
    routes: &Signal<Vec<FibEntry>>,
    cs: &Signal<Option<CsInfo>>,
    strategies: &Signal<Vec<StrategyEntry>>,
    security_keys: &Signal<Vec<SecurityKeyInfo>>,
    security_anchors: &Signal<Vec<AnchorInfo>>,
    schema_rules: &Signal<Vec<SchemaRuleInfo>>,
    ca_info: &Signal<Option<CaInfo>>,
    identity_name: &Signal<String>,
    identity_is_ephemeral: &Signal<bool>,
    identity_pib_path: &Signal<Option<String>>,
    cert_valid_until_unix_s: &Signal<Option<u64>>,
    mgmt_signed_commands_required: &Signal<Option<bool>>,
    mgmt_access_policy: &Signal<Option<MgmtAccessPolicySnapshot>>,
    security_surface_supported: &Signal<Option<bool>>,
    validation_stats: &Signal<Option<ValidationStats>>,
    validation_history: &Signal<VecDeque<(u64, u64)>>,
) -> Result<(), String> {
    use ndn_dashboard_core::StateUpdate;

    // Forwarding plane: one engine poll replaces the per-dataset fetch+parse
    // that used to live here and (duplicated) in app.rs — the engine owns the
    // wire→view-model mapping now. Each StateUpdate copies the engine's state
    // into the matching Signal; a block that didn't refresh leaves its Signal
    // (and the engine's retained value) untouched, the same best-effort
    // semantics as before.
    for upd in engine.poll_forwarding().await {
        let st = engine.state();
        match upd {
            StateUpdate::Status => {
                let mut s = *status;
                s.set(st.status.clone());
            }
            StateUpdate::Faces => {
                let mut s = *faces;
                s.set(st.faces.clone());
            }
            StateUpdate::Routes => {
                let mut s = *routes;
                s.set(st.routes.clone());
            }
            StateUpdate::Cs => {
                let mut s = *cs;
                s.set(st.cs.clone());
            }
            StateUpdate::Strategies => {
                let mut s = *strategies;
                s.set(st.strategies.clone());
            }
        }
    }

    // The security/identity datasets aren't in the engine yet; reborrow the
    // engine's client and poll them as before.
    let client = engine.client_mut();

    // Auth-exempt verbs per `is_public_dataset_verb`; the web build
    // now polls them so chip + gate + tabs hit feature parity with
    // desktop. Each block is best-effort — older forwarders without
    // these verbs degrade to "no data" cleanly.
    if let Ok(resp) = client.security_identity_list().await
        && resp.is_ok()
    {
        let keys = SecurityKeyInfo::parse_list(&resp.status_text);
        let expiry = keys.iter().find_map(SecurityKeyInfo::valid_until_unix_s);
        let mut cv = *cert_valid_until_unix_s;
        cv.set(expiry);
        let mut sk = *security_keys;
        sk.set(keys);
    }
    // Identity status doubles as the security-extension probe — see
    // `app.rs`'s desktop counterpart for the rationale. The web path
    // mirrors it bit-for-bit: 2xx ⇒ supported, 404 ⇒ NFD-style
    // cross-impl forwarder, other ⇒ leave the signal at its prior
    // value.
    if let Ok(resp) = client.security_identity_status().await {
        if resp.is_ok() {
            let (name, ephemeral, pib) = parse_identity_status_web(&resp.status_text);
            let mut n = *identity_name;
            n.set(name);
            let mut e = *identity_is_ephemeral;
            e.set(ephemeral);
            let mut p = *identity_pib_path;
            p.set(pib);
            let mut s = *security_surface_supported;
            s.set(Some(true));
        } else if resp.status_code == ndn_config::control_response::status::NOT_FOUND {
            let mut s = *security_surface_supported;
            s.set(Some(false));
        }
    }
    if let Ok(resp) = client.security_policy_get().await
        && resp.is_ok()
        && let Ok(parsed) = MgmtAccessPolicySnapshot::from_json(&resp.status_text)
    {
        let mut req = *mgmt_signed_commands_required;
        req.set(Some(parsed.require_signed_commands));
        let mut pol = *mgmt_access_policy;
        pol.set(Some(parsed));
    }
    if let Ok(resp) = client.security_validation_stats().await
        && resp.is_ok()
    {
        let parsed = ValidationStats::parse(&resp.status_text);
        // Same shape as the desktop poll — derive per-sec from the
        // delta against the previous sample when totals are present;
        // fall back to legacy `*_per_sec` fields otherwise.
        let rate = validation_stats
            .peek()
            .and_then(|prev| parsed.rate_against(&prev))
            .unwrap_or((parsed.verified_per_sec, parsed.rejected_per_sec));
        let mut vs = *validation_stats;
        vs.set(Some(parsed));
        let mut hist = *validation_history;
        let mut h = hist.write();
        h.push_back(rate);
        if h.len() > 60 {
            h.pop_front();
        }
    }
    if let Ok(resp) = client.security_anchor_list().await
        && resp.is_ok()
    {
        let mut a = *security_anchors;
        a.set(AnchorInfo::parse_list(&resp.status_text));
    }
    if let Ok(resp) = client.security_schema_list().await
        && resp.is_ok()
    {
        let mut s = *schema_rules;
        s.set(SchemaRuleInfo::parse_list(&resp.status_text));
    }
    if let Ok(resp) = client.security_ca_info().await {
        // ca-info returns NOT_FOUND when the forwarder isn't acting
        // as a CA — that's a normal state for the dashboard, not an
        // error.
        if resp.is_ok() {
            let mut c = *ca_info;
            c.set(CaInfo::parse(&resp.status_text));
        }
    }

    Ok(())
}

/// Pull `ca/list-approvals` and reconcile `CA_APPROVALS_STATE`. Decodes the
/// dataset through the shared `ndn_mgmt_wire::PendingApproval` codec. Used
/// both by the operator-driven refresh button and by the
/// post-approve/post-deny refresh paths so the operator's view stays
/// in sync after each mutation. Always returns the underlying
/// `MgmtResponse` so the caller's standard error-surfacing path runs.
async fn refresh_ca_approvals_web(
    client: &mut WsMgmtClient,
) -> anyhow::Result<crate::ws_mgmt::MgmtResponse> {
    use crate::views::ca_approvals::{CaApprovalsState, PendingApprovalRow};
    let resp = client.ca_list_approvals().await;
    let now = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .ok();
    match &resp {
        Ok(r) if r.is_ok() => {
            let mapped: Vec<PendingApprovalRow> =
                ndn_mgmt_wire::PendingApproval::decode_all(&r.body)
                    .into_iter()
                    .map(|a| PendingApprovalRow {
                        id: a.request_id,
                        cert_name: a.cert_name,
                        description: a.description,
                    })
                    .collect();
            *crate::app_shared::CA_APPROVALS_STATE.write() = CaApprovalsState {
                rows: mapped,
                last_refresh_unix_s: now,
                last_error: None,
            };
        }
        Ok(r) => {
            *crate::app_shared::CA_APPROVALS_STATE.write() = CaApprovalsState {
                rows: Vec::new(),
                last_refresh_unix_s: now,
                last_error: Some(format!("{} {}", r.status_code, r.status_text)),
            };
        }
        Err(e) => {
            *crate::app_shared::CA_APPROVALS_STATE.write() = CaApprovalsState {
                rows: Vec::new(),
                last_refresh_unix_s: now,
                last_error: Some(e.to_string()),
            };
        }
    }
    resp
}

fn parse_identity_status_web(text: &str) -> (String, bool, Option<String>) {
    let mut name = String::new();
    let mut ephemeral = false;
    let mut pib = None::<String>;
    for token in text.split_whitespace() {
        if let Some((k, v)) = token.split_once('=') {
            match k {
                "identity" => name = v.to_string(),
                "is_ephemeral" => ephemeral = v == "true",
                "pib_path" => {
                    pib = if v.is_empty() || v == "-" {
                        None
                    } else {
                        Some(v.to_string())
                    }
                }
                _ => {}
            }
        }
    }
    (name, ephemeral, pib)
}

#[allow(clippy::too_many_arguments)]
async fn run_cmd_web(
    cmd: DashCmd,
    client: &mut WsMgmtClient,
    error_msg: &Signal<Option<String>>,
    trust_validation: &Signal<Option<(String, TrustValidationResult)>>,
    identity_name: &Signal<String>,
    identity_is_ephemeral: &Signal<bool>,
) {
    use ndn_config::ControlParameters;
    use ndn_packet::Name;

    // Inline copies of the desktop run_cmd's helpers so the web
    // build doesn't have to depend on `app.rs`. These mirror the
    // §11.10 audit-bridge + §2.4 schema-journal initiator-name
    // discipline exactly.
    fn web_unix_ns_now() -> u64 {
        web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
    fn web_initiator_name(
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

        DashCmd::SecurityGenerate(name) => match name.parse::<Name>() {
            Ok(n) => {
                let params = ControlParameters {
                    name: Some(n),
                    ..Default::default()
                };
                client
                    .send_cmd("security", "identity-generate", Some(&params))
                    .await
            }
            Err(e) => {
                error_msg
                    .to_owned()
                    .set(Some(format!("invalid name '{name}': {e:?}")));
                return;
            }
        },
        DashCmd::SecurityKeyDelete(name) => match name.parse::<Name>() {
            Ok(n) => {
                let params = ControlParameters {
                    name: Some(n),
                    ..Default::default()
                };
                client
                    .send_cmd("security", "key-delete", Some(&params))
                    .await
            }
            Err(e) => {
                error_msg
                    .to_owned()
                    .set(Some(format!("invalid name '{name}': {e:?}")));
                return;
            }
        },
        DashCmd::SchemaRuleAdd(rule) => {
            let params = ControlParameters {
                uri: Some(rule.clone()),
                ..Default::default()
            };
            let resp = client
                .send_cmd("security", "schema-rule-add", Some(&params))
                .await;
            if let Ok(r) = &resp
                && r.is_ok()
            {
                let entry = crate::security_chains::SchemaJournalEntry {
                    ts_unix_ns: web_unix_ns_now(),
                    kind: crate::security_chains::SchemaJournalKind::SchemaRuleAdd,
                    subject_name: rule,
                    initiator_name: web_initiator_name(identity_name, identity_is_ephemeral),
                };
                crate::security_chains::append_schema_entry(entry);
            }
            resp
        }
        DashCmd::SchemaRuleRemove(index) => {
            let params = ControlParameters {
                count: Some(index),
                ..Default::default()
            };
            let resp = client
                .send_cmd("security", "schema-rule-remove", Some(&params))
                .await;
            if let Ok(r) = &resp
                && r.is_ok()
            {
                let entry = crate::security_chains::SchemaJournalEntry {
                    ts_unix_ns: web_unix_ns_now(),
                    kind: crate::security_chains::SchemaJournalKind::SchemaRuleRemove,
                    subject_name: format!("<index={index}>"),
                    initiator_name: web_initiator_name(identity_name, identity_is_ephemeral),
                };
                crate::security_chains::append_schema_entry(entry);
            }
            resp
        }
        DashCmd::SchemaSet(rules) => {
            let params = ControlParameters {
                uri: Some(rules.clone()),
                ..Default::default()
            };
            let resp = client
                .send_cmd("security", "schema-set", Some(&params))
                .await;
            if let Ok(r) = &resp
                && r.is_ok()
            {
                let line_count = rules.lines().filter(|l| !l.trim().is_empty()).count();
                let entry = crate::security_chains::SchemaJournalEntry {
                    ts_unix_ns: web_unix_ns_now(),
                    kind: crate::security_chains::SchemaJournalKind::SchemaRuleAdd,
                    subject_name: format!("<bulk replace · {line_count} rule(s)>"),
                    initiator_name: web_initiator_name(identity_name, identity_is_ephemeral),
                };
                crate::security_chains::append_schema_entry(entry);
            }
            resp
        }
        DashCmd::SecurityPolicySet(policy) => {
            let body = policy.to_json();
            let params = ControlParameters {
                uri: Some(body.clone()),
                ..Default::default()
            };
            let resp = client
                .send_cmd("security", "policy-set", Some(&params))
                .await;
            if let Ok(r) = &resp
                && r.is_ok()
            {
                use sha2::{Digest as _, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(body.as_bytes());
                let digest: [u8; 32] = hasher.finalize().into();
                let initiator = web_initiator_name(identity_name, identity_is_ephemeral);
                let entry = crate::security_chains::policy_set_audit_entry(
                    web_unix_ns_now(),
                    &initiator,
                    &digest,
                );
                crate::security_chains::append_audit_entry(entry);
            }
            resp
        }
        DashCmd::SecurityValidateTrace(target) => {
            let resp = client.security_validate(&target).await;
            if let Ok(r) = &resp
                && r.is_ok()
            {
                match TrustValidationResult::from_json(&r.status_text) {
                    Ok(parsed) => {
                        let mut tv = *trust_validation;
                        tv.set(Some((target, parsed)));
                    }
                    Err(e) => {
                        error_msg
                            .to_owned()
                            .set(Some(format!("validate response parse: {e}")));
                    }
                }
            }
            resp
        }
        DashCmd::SecurityAnchorAdd {
            name,
            fingerprint_hex,
            cert_wire_hex,
        } => {
            let subject = format!("anchor={name} fingerprint={fingerprint_hex}");
            if cert_wire_hex.trim().is_empty() {
                // Intent-only path — journal without firing the verb.
                let entry = crate::security_chains::SchemaJournalEntry {
                    ts_unix_ns: web_unix_ns_now(),
                    kind: crate::security_chains::SchemaJournalKind::AnchorAdd,
                    subject_name: format!("{subject} mode=intent-only"),
                    initiator_name: web_initiator_name(identity_name, identity_is_ephemeral),
                };
                crate::security_chains::append_schema_entry(entry);
                return; // success — no client call to dispatch
            }
            let parsed = match name.parse::<Name>() {
                Ok(n) => n,
                Err(e) => {
                    error_msg
                        .to_owned()
                        .set(Some(format!("invalid anchor name '{name}': {e:?}")));
                    return;
                }
            };
            let cp = ControlParameters {
                name: Some(parsed),
                uri: Some(cert_wire_hex),
                ..Default::default()
            };
            let resp = client.send_cmd("security", "anchor-add", Some(&cp)).await;
            if let Ok(r) = &resp
                && r.is_ok()
            {
                let entry = crate::security_chains::SchemaJournalEntry {
                    ts_unix_ns: web_unix_ns_now(),
                    kind: crate::security_chains::SchemaJournalKind::AnchorAdd,
                    subject_name: format!("{subject} mode=installed"),
                    initiator_name: web_initiator_name(identity_name, identity_is_ephemeral),
                };
                crate::security_chains::append_schema_entry(entry);
            }
            resp
        }
        DashCmd::SecurityAnchorRemove { name } => {
            let parsed = match name.parse::<Name>() {
                Ok(n) => n,
                Err(e) => {
                    error_msg
                        .to_owned()
                        .set(Some(format!("invalid anchor name '{name}': {e:?}")));
                    return;
                }
            };
            let cp = ControlParameters {
                name: Some(parsed),
                ..Default::default()
            };
            client.send_cmd("security", "anchor-remove", Some(&cp)).await
        }
        DashCmd::SecurityTokenAdd(description) => {
            let params = ControlParameters {
                uri: Some(description),
                ..Default::default()
            };
            client
                .send_cmd("security", "ca-token-add", Some(&params))
                .await
        }
        DashCmd::SecurityEnroll {
            ca_prefix,
            challenge_type,
            challenge_param,
        } => {
            use crate::views::enrollment_wizard::EnrollmentResult;
            match ca_prefix.parse::<Name>() {
                Ok(n) => {
                    let params = ControlParameters {
                        name: Some(n),
                        uri: Some(format!("{challenge_type}:{challenge_param}")),
                        ..Default::default()
                    };
                    let resp = client
                        .send_cmd("security", "ca-enroll", Some(&params))
                        .await;
                    match &resp {
                        Ok(r) if r.is_ok() => {
                            *crate::app_shared::ENROLLMENT_RESULT.write() =
                                Some(EnrollmentResult::Submitted {
                                    text: format!("{} {}", r.status_code, r.status_text),
                                });
                        }
                        Ok(r) => {
                            *crate::app_shared::ENROLLMENT_RESULT.write() =
                                Some(EnrollmentResult::Failed {
                                    reason: format!("{} {}", r.status_code, r.status_text),
                                });
                        }
                        Err(e) => {
                            *crate::app_shared::ENROLLMENT_RESULT.write() =
                                Some(EnrollmentResult::Failed {
                                    reason: e.to_string(),
                                });
                        }
                    }
                    resp
                }
                Err(e) => {
                    *crate::app_shared::ENROLLMENT_RESULT.write() =
                        Some(EnrollmentResult::Failed {
                            reason: format!("invalid ca_prefix '{ca_prefix}': {e:?}"),
                        });
                    error_msg
                        .to_owned()
                        .set(Some(format!("invalid ca_prefix '{ca_prefix}': {e:?}")));
                    return;
                }
            }
        }
        DashCmd::DiscoveryConfigSet(params_str) => {
            let cp = ControlParameters {
                uri: Some(params_str),
                ..Default::default()
            };
            client.send_cmd("discovery", "config", Some(&cp)).await
        }
        DashCmd::DvrConfigSet(params_str) => {
            let cp = ControlParameters {
                uri: Some(params_str),
                ..Default::default()
            };
            client.send_cmd("routing", "dvr-config", Some(&cp)).await
        }
        DashCmd::SecuritySafebagImport {
            name,
            safebag_wire,
            passphrase,
        } => {
            client
                .security_safebag_import(&name, &safebag_wire, passphrase.as_bytes())
                .await
        }
        DashCmd::CaListApprovals => refresh_ca_approvals_web(client).await,
        DashCmd::CaApprove { request_id } => {
            let resp = client.ca_approve(&request_id).await;
            let _ = refresh_ca_approvals_web(client).await;
            resp
        }
        DashCmd::CaDeny { request_id, reason } => {
            let resp = client.ca_deny(&request_id, &reason).await;
            let _ = refresh_ca_approvals_web(client).await;
            resp
        }

        // Recording flows + YubiKey detection are local-only on web
        // today. RecordStart/Stop/Clear/ReplaySession touch the
        // session log signal which web doesn't expose; YubiKey USB
        // probes aren't available from inside a browser tab.
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
