//! Dioxus application shell for dashboard-next.

use dioxus::prelude::*;

use crate::audit::{AuditViewModel, LogLevel};
use crate::client::{
    DashboardClient, DesktopLocalClient, MockDashboardClient, ProbeOutcome, ProbeResult,
    ProbeTranscript, state_from_probe,
};
use crate::config::{
    ConfigPreset, DashboardSettingsDraft, RouterConfigDraft, StartupFaceDraft, StartupRouteDraft,
};
use crate::core::{
    AttachMode, AttachTarget, DashboardPreferences, DashboardState, Density, FeatureState,
    ForwarderKind, ObservePosture, PlatformKind, SavedAttachTarget, TrustPosture,
    capability_matrix,
};
use crate::engine::{EngineDetail, EngineSummary, compact_count, poll_engine_summary};
use crate::extensions::ExtensionRegistry;
use crate::identity::TrustContextSummary;
use crate::mutation::{
    CsCapacityCommand, CsEraseCommand, FaceCreateCommand, FaceDestroyCommand, MutationOperation,
    MutationPreflight, MutationRecord, MutationSession, MutationStatus, PreflightStatus,
    ReconnectForwarderCommand, RouteAddCommand, RouteRemoveCommand, ShutdownForwarderCommand,
    StrategySetCommand, StrategyUnsetCommand, TypedMutationCommand, execute_cs_erase,
    execute_cs_set_capacity, execute_face_create, execute_face_destroy,
    execute_reconnect_forwarder, execute_route_add, execute_route_remove,
    execute_shutdown_forwarder, execute_strategy_set, execute_strategy_unset,
    execute_typed_mutation, preflight_mutation,
};
use crate::network::NetworkViewModel;
use crate::observe::{
    BridgeExportStatus, LogEvidenceRow, ObserveSummary, PitFanOutRow, SpanTreeRow, TraceView,
    correlated_logs_for_trace, filter_traces, pit_fanout_rows, poll_observe_summary,
    span_tree_rows,
};
use crate::operations::{
    EngineOwnership, OperationsHomeModel, RouterLifecycleAction, StartRouterModalModel,
    StartRouterTab,
};
use crate::platform::{self, PlatformServices, density_storage_label, preference_key};
use crate::tools::{
    IperfWorkflowConfig, PeekWorkflowConfig, PingWorkflowConfig, PutWorkflowConfig, ToolKind,
    ToolRun, ToolStatus, mock_runs, run_face_diagnostic, run_iperf_workflow, run_peek_workflow,
    run_ping_workflow, run_put_workflow, run_route_diagnostic, run_trace_lookup,
    tool_server_controls,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Workspace {
    Operations,
    Observe,
    Trust,
    Engine,
    Tools,
    Settings,
}

impl Workspace {
    const ALL: [Workspace; 6] = [
        Workspace::Operations,
        Workspace::Observe,
        Workspace::Trust,
        Workspace::Engine,
        Workspace::Tools,
        Workspace::Settings,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Operations => "Operations",
            Self::Observe => "Observe",
            Self::Trust => "Trust",
            Self::Engine => "Engine",
            Self::Tools => "Tools",
            Self::Settings => "Settings",
        }
    }

    fn icon(self) -> &'static str {
        match self {
            Self::Operations => "OP",
            Self::Observe => "OB",
            Self::Trust => "TR",
            Self::Engine => "EN",
            Self::Tools => "TO",
            Self::Settings => "SE",
        }
    }

    fn test_id(self) -> &'static str {
        match self {
            Self::Operations => "operations",
            Self::Observe => "observe",
            Self::Trust => "trust",
            Self::Engine => "engine",
            Self::Tools => "tools",
            Self::Settings => "settings",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ToolPanelKind {
    Ping,
    Iperf,
    Peek,
    Put,
    Diagnostics,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TrustModal {
    Verify,
    Adopt,
    Sign,
    Enroll,
    Approvals,
    Trace,
    Maintenance,
    SafeBag,
}

impl TrustModal {
    fn title(self) -> &'static str {
        match self {
            Self::Verify => "Verify Data",
            Self::Adopt => "Adopt Context",
            Self::Sign => "Signing Identity",
            Self::Enroll => "Enroll Certificate",
            Self::Approvals => "Approvals",
            Self::Trace => "Validation Trace",
            Self::Maintenance => "Trust Maintenance",
            Self::SafeBag => "SafeBag Preview",
        }
    }
}

const KNOWN_STRATEGIES: [(&str, &str); 5] = [
    ("/ndn/strategy/best-route/v5", "Best Route"),
    ("/ndn/strategy/multicast/v5", "Multicast"),
    ("/ndn/strategy/ncc/v1", "NCC"),
    ("/ndn/strategy/access/v1", "Access"),
    ("/ndn/strategy/self-learning", "Self-Learning"),
];

impl ToolPanelKind {
    const ALL: [Self; 5] = [
        Self::Ping,
        Self::Iperf,
        Self::Peek,
        Self::Put,
        Self::Diagnostics,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Ping => "Ping",
            Self::Iperf => "Iperf",
            Self::Peek => "Peek",
            Self::Put => "Put",
            Self::Diagnostics => "Diagnostics",
        }
    }
}

#[component]
pub fn App() -> Element {
    let platform = platform::current_platform();
    let initial_preferences = {
        let client = MockDashboardClient::new(platform);
        platform::load_or_default_preferences(platform, client.attach_targets())
    };
    let initial_density = initial_preferences.density;
    let mut active = use_signal(|| Workspace::Operations);
    let mut nav_collapsed = use_signal(|| false);
    let mut state = use_signal(move || {
        let mut state = DashboardState::detached(platform);
        state.density = initial_density;
        state
    });
    let mut preferences = use_signal(move || initial_preferences.clone());
    let mut last_probe = use_signal(|| None::<ProbeTranscript>);
    let mut last_probe_at = use_signal(|| None::<u64>);
    let mut last_attach_error = use_signal(|| None::<String>);
    let mut forwarder_notice = use_signal(|| None::<ForwarderActionNotice>);
    let mut start_router_open = use_signal(|| false);
    let mut start_router_tab = use_signal(|| StartRouterTab::QuickStart);
    let mut start_router_draft = use_signal(move || {
        RouterConfigDraft::preset(match platform {
            PlatformKind::Browser => ConfigPreset::BrowserSandbox,
            PlatformKind::Desktop => ConfigPreset::LocalLab,
        })
    });
    let mut start_router_raw_toml = use_signal(String::new);
    let mut start_router_parse_error = use_signal(|| None::<String>);

    let density = state.read().density;
    let density_class = match density {
        Density::Compact => "density-compact",
        Density::Comfortable => "density-comfortable",
    };
    let nav_class = if *nav_collapsed.read() {
        "nav-collapsed"
    } else {
        "nav-expanded"
    };
    let current = state.read().clone();
    let workspace = *active.read();
    let engine_resource = use_resource(move || {
        let profile = state.read().profile.clone();
        async move {
            poll_engine_summary(profile.clone())
                .await
                .unwrap_or_else(|_| EngineSummary::disconnected(&profile))
        }
    });
    let observe_resource = use_resource(move || {
        let current = state.read().clone();
        async move { poll_observe_summary(current.profile, current.observe).await }
    });
    let trust = TrustContextSummary::from_profile(&current.profile, current.trust);
    let observe = observe_resource
        .read()
        .as_ref()
        .cloned()
        .unwrap_or_else(|| ObserveSummary::mock(&current.profile, current.observe));
    let engine = engine_resource
        .read()
        .as_ref()
        .cloned()
        .unwrap_or_else(|| EngineSummary::mock(&current.profile));
    let services = platform::services(current.platform);
    let tools = mock_runs();
    let prefs = preferences.read().clone();
    let probe = last_probe.read().clone();
    let probe_at = *last_probe_at.read();
    let attach_error = last_attach_error.read().clone();
    let selected_target = prefs.selected_target().cloned();
    let start_notice = forwarder_notice.read().clone();
    let operations = OperationsHomeModel::new(
        current.platform,
        current.attach_state.clone(),
        current.profile.capabilities.clone(),
        selected_target.as_ref(),
    );

    rsx! {
        document::Link { rel: "manifest", href: "manifest.webmanifest" }
        style { "{STYLE}" }
        div { class: "app-shell {density_class} {nav_class}", "data-testid": "dashboard-next-root",
            a { class: "skip-link", href: "#dashboard-next-main", "Skip to workspace" }
            aside { class: "sidebar",
                div { class: "brand",
                    div { class: "brand-mark", "ND" }
                    div { class: "brand-copy",
                        div { class: "brand-title", "ndn-dashboard-next" }
                        div { class: "brand-sub", "browser-first operator console" }
                    }
                }
                button {
                    class: "nav-collapse-button",
                    "aria-label": if *nav_collapsed.read() { "Expand workspace navigation" } else { "Collapse workspace navigation" },
                    "aria-expanded": "{!*nav_collapsed.read()}",
                    title: if *nav_collapsed.read() { "Expand navigation" } else { "Collapse navigation" },
                    onclick: move |_| {
                        let collapsed = *nav_collapsed.read();
                        nav_collapsed.set(!collapsed);
                    },
                    span { class: "hamburger-icon", "aria-hidden": "true",
                        span {}
                        span {}
                        span {}
                    }
                }
                nav { class: "nav-list", "aria-label": "Primary workspace navigation",
                    for item in Workspace::ALL {
                        button {
                            class: if workspace == item { "nav-item active" } else { "nav-item" },
                            "data-testid": "nav-{item.test_id()}",
                            "aria-current": if workspace == item { "page" } else { "false" },
                            "aria-label": "Open {item.label()} workspace",
                            title: "{item.label()}",
                            onclick: move |_| active.set(item),
                            span { class: "nav-icon", "aria-hidden": "true", "{item.icon()}" }
                            span { class: "nav-label", "{item.label()}" }
                        }
                    }
                }
            }

            main { id: "dashboard-next-main", class: "main", tabindex: "-1",
                AttachBar {
                    state: current.clone(),
                    on_density: move |_| {
                        let mut next = state.read().clone();
                        next.density = match next.density {
                            Density::Compact => Density::Comfortable,
                            Density::Comfortable => Density::Compact,
                        };
                        let mut next_prefs = preferences.read().clone();
                        next_prefs.density = next.density;
                        platform::save_preferences(next_prefs.clone());
                        preferences.set(next_prefs);
                        state.set(next);
                    }
                }
                OperatorConnectBand {
                    state: current.clone(),
                    selected: selected_target.clone(),
                    last_probe_at_unix_s: probe_at,
                    last_attach_error: attach_error.clone(),
                    start_notice: start_notice.clone(),
                    on_probe_selected: move |_| {
                        let selected = preferences.read().selected_target().cloned();
                        if let Some(target) = selected {
                            let client = MockDashboardClient::new(platform);
                            match client.probe(&target.attach_target()) {
                                Ok(probe) => {
                                    apply_probe_result(
                                        platform,
                                        probe,
                                        Some(target),
                                                None,
                                        state,
                                        preferences,
                                        last_probe,
                                        last_probe_at,
                                        last_attach_error,
                                    );
                                    forwarder_notice.set(None);
                                }
                                Err(err) => {
                                    last_attach_error.set(Some(err.message().to_string()));
                                }
                            }
                        } else {
                            last_attach_error.set(Some("Select an attach target first.".into()));
                        }
                    },
                    on_probe_default: move |_| {
                        let client = MockDashboardClient::new(platform);
                        if let Some(target) = client.attach_targets().first().cloned() {
                            match client.probe(&target) {
                                Ok(probe) => {
                                    apply_probe_result(
                                        platform,
                                        probe,
                                        None,
                                                None,
                                        state,
                                        preferences,
                                        last_probe,
                                        last_probe_at,
                                        last_attach_error,
                                    );
                                    forwarder_notice.set(None);
                                }
                                Err(err) => {
                                    last_attach_error.set(Some(err.message().to_string()));
                                }
                            }
                        }
                    },
                    on_open_start_router: move |_| {
                        start_router_tab.set(StartRouterTab::QuickStart);
                        if start_router_raw_toml.read().is_empty() {
                            let toml = start_router_draft
                                .read()
                                .render_toml()
                                .unwrap_or_default();
                            start_router_raw_toml.set(toml);
                        }
                        start_router_open.set(true);
                    },
                    on_stop_forwarder: move |_| {
                        match platform::stop_local_forwarder() {
                            Ok(message) => {
                                forwarder_notice.set(Some(ForwarderActionNotice::neutral(
                                    "Local ndn-fwd stopped",
                                    message,
                                )));
                            }
                            Err(err) => {
                                forwarder_notice.set(Some(ForwarderActionNotice::bad(
                                    "Could not stop ndn-fwd",
                                    err,
                                )));
                            }
                        }
                    },
                    on_open_settings: move |_| active.set(Workspace::Settings)
                }

                section { class: "workspace",
                    match workspace {
                        Workspace::Operations => rsx! {
                            OperationsView {
                                model: operations.clone(),
                                state: current.clone(),
                                engine: engine.clone(),
                                observe: observe.clone(),
                                active_tools: tools.clone(),
                                last_attach_error: attach_error.clone(),
                                start_notice: start_notice.clone(),
                                on_probe_selected: move |_| {
                                    let selected = preferences.read().selected_target().cloned();
                                    if let Some(target) = selected {
                                        let client = MockDashboardClient::new(platform);
                                        match client.probe(&target.attach_target()) {
                                            Ok(probe) => {
                                                apply_probe_result(
                                                    platform,
                                                    probe,
                                                    Some(target),
                                                    None,
                                                    state,
                                                    preferences,
                                                    last_probe,
                                                    last_probe_at,
                                                    last_attach_error,
                                                );
                                                forwarder_notice.set(None);
                                            }
                                            Err(err) => {
                                                last_attach_error
                                                    .set(Some(err.message().to_string()));
                                            }
                                        }
                                    } else {
                                        last_attach_error
                                            .set(Some("Select an attach target first.".into()));
                                    }
                                },
                                on_probe_default: move |_| {
                                    let client = MockDashboardClient::new(platform);
                                    if let Some(target) = client.attach_targets().first().cloned() {
                                        match client.probe(&target) {
                                            Ok(probe) => {
                                                apply_probe_result(
                                                    platform,
                                                    probe,
                                                    None,
                                                    None,
                                                    state,
                                                    preferences,
                                                    last_probe,
                                                    last_probe_at,
                                                    last_attach_error,
                                                );
                                                forwarder_notice.set(None);
                                            }
                                            Err(err) => {
                                                last_attach_error
                                                    .set(Some(err.message().to_string()));
                                            }
                                        }
                                    }
                                },
                                on_open_start_router: move |_| {
                                    start_router_tab.set(StartRouterTab::QuickStart);
                                    start_router_open.set(true);
                                },
                            }
                        },
                        Workspace::Observe => rsx! { ObserveView { summary: observe } },
                        Workspace::Trust => rsx! { TrustView { profile: current.profile.clone(), summary: trust } },
                        Workspace::Engine => rsx! {
                            EngineView {
                                profile: current.profile.clone(),
                                trust: current.trust,
                                summary: engine,
                            }
                        },
                        Workspace::Tools => rsx! {
                            ToolsView {
                                profile: current.profile.clone(),
                                engine: engine.clone(),
                                observe: observe.clone(),
                                initial_runs: tools
                            }
                        },
                        Workspace::Settings => rsx! {
                            SettingsView {
                                state: current.clone(),
                                services,
                                preferences: prefs.clone(),
                                last_probe: probe.clone(),
                                last_probe_at_unix_s: probe_at,
                                last_attach_error: attach_error.clone(),
                                start_notice: start_notice.clone(),
                                on_select_target: move |id: String| {
                                    let mut next = preferences.read().clone();
                                    next.select(&id);
                                    platform::save_preferences(next.clone());
                                    preferences.set(next);
                                },
                                on_probe_selected: move |_| {
                                    let selected = preferences.read().selected_target().cloned();
                                    if let Some(target) = selected {
                                        let client = MockDashboardClient::new(platform);
                                        match client.probe(&target.attach_target()) {
                                            Ok(probe) => {
                                                apply_probe_result(
                                                    platform,
                                                    probe,
                                                    Some(target),
                                                None,
                                                    state,
                                                    preferences,
                                                    last_probe,
                                                    last_probe_at,
                                                    last_attach_error,
                                                );
                                                forwarder_notice.set(None);
                                            }
                                            Err(err) => {
                                                last_attach_error.set(Some(err.message().to_string()));
                                            }
                                        }
                                    }
                                },
                                on_mock_ndnrs: move |_| {
                                    let density = state.read().density;
                                    let mut next = DashboardState::mock_ndnrs(platform);
                                    next.density = density;
                                    last_probe.set(None);
                                    last_probe_at.set(None);
                                    last_attach_error.set(None);
                                    state.set(next);
                                },
                                on_mock_browser: move |_| {
                                    if let Some(target) = preferences
                                        .read()
                                        .saved_targets
                                        .iter()
                                        .find(|target| target.label == "browser in-page engine")
                                        .cloned()
                                    {
                                        let client = MockDashboardClient::new(platform);
                                        if let Ok(probe) = client.probe(&target.attach_target()) {
                                            apply_probe_result(
                                                platform,
                                                probe,
                                                Some(target),
                                                None,
                                                state,
                                                preferences,
                                                last_probe,
                                                last_probe_at,
                                                last_attach_error,
                                            );
                                        }
                                    }
                                },
                                on_mock_nfd: move |_| {
                                    if let Some(target) = preferences
                                        .read()
                                        .saved_targets
                                        .iter()
                                        .find(|target| target.label == "NFD compatibility")
                                        .cloned()
                                    {
                                        let client = MockDashboardClient::new(platform);
                                        if let Ok(probe) = client.probe(&target.attach_target()) {
                                            apply_probe_result(
                                                platform,
                                                probe,
                                                Some(target),
                                                None,
                                                state,
                                                preferences,
                                                last_probe,
                                                last_probe_at,
                                                last_attach_error,
                                            );
                                        }
                                    }
                                },
                                on_mock_yanfd: move |_| {
                                    if let Some(target) = preferences
                                        .read()
                                        .saved_targets
                                        .iter()
                                        .find(|target| target.label == "YaNFD compatibility")
                                        .cloned()
                                    {
                                        let client = MockDashboardClient::new(platform);
                                        if let Ok(probe) = client.probe(&target.attach_target()) {
                                            apply_probe_result(
                                                platform,
                                                probe,
                                                Some(target),
                                                None,
                                                state,
                                                preferences,
                                                last_probe,
                                                last_probe_at,
                                                last_attach_error,
                                            );
                                        }
                                    }
                                },
                                on_probe_default: move |_| {
                                    let client = MockDashboardClient::new(platform);
                                    if let Some(target) = client.attach_targets().first().cloned()
                                        && let Ok(probe) = client.probe(&target)
                                    {
                                        apply_probe_result(
                                            platform,
                                            probe,
                                            None,
                                                None,
                                            state,
                                            preferences,
                                            last_probe,
                                            last_probe_at,
                                            last_attach_error,
                                        );
                                        forwarder_notice.set(None);
                                    }
                                },
                                on_start_forwarder: move |toml: String| {
                                    let notice = start_and_attach_local_forwarder(
                                        platform,
                                        &toml,
                                        state,
                                        preferences,
                                        last_probe,
                                        last_probe_at,
                                        last_attach_error,
                                    );
                                    forwarder_notice.set(Some(notice));
                                },
                                on_stop_forwarder: move |_| {
                                    match platform::stop_local_forwarder() {
                                        Ok(message) => {
                                            forwarder_notice.set(Some(ForwarderActionNotice::neutral(
                                                "Local ndn-fwd stopped",
                                                message,
                                            )));
                                        }
                                        Err(err) => {
                                            forwarder_notice.set(Some(ForwarderActionNotice::bad(
                                                "Could not stop ndn-fwd",
                                                err,
                                            )));
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }

            nav { class: "bottom-nav", "aria-label": "Mobile workspace navigation",
                for item in Workspace::ALL {
                    button {
                        class: if workspace == item { "bottom-item active" } else { "bottom-item" },
                        "data-testid": "bottom-nav-{item.test_id()}",
                        "aria-current": if workspace == item { "page" } else { "false" },
                        "aria-label": "Open {item.label()} workspace",
                        onclick: move |_| active.set(item),
                        "{item.label()}"
                    }
                }
            }
            if *start_router_open.read() {
                StartRouterModal {
                    platform: current.platform,
                    active_tab: *start_router_tab.read(),
                    draft: start_router_draft.read().clone(),
                    current_config: RouterConfigDraft::preset(match current.platform {
                        PlatformKind::Browser => ConfigPreset::BrowserSandbox,
                        PlatformKind::Desktop => ConfigPreset::LocalLab,
                    }),
                    raw_toml: start_router_raw_toml.read().clone(),
                    parse_error: start_router_parse_error.read().clone(),
                    start_notice: start_notice.clone(),
                    on_close: move |_| start_router_open.set(false),
                    on_tab: move |tab| start_router_tab.set(tab),
                    on_update: move |draft: RouterConfigDraft| {
                        let toml = draft.render_toml().unwrap_or_default();
                        start_router_raw_toml.set(toml);
                        start_router_parse_error.set(None);
                        start_router_draft.set(draft);
                    },
                    on_raw_toml: move |raw: String| {
                        start_router_raw_toml.set(raw);
                        start_router_parse_error.set(None);
                    },
                    on_apply_raw: move |raw: String| {
                        match RouterConfigDraft::parse_toml(&raw) {
                            Ok(draft) => {
                                start_router_draft.set(draft);
                                start_router_parse_error.set(None);
                            }
                            Err(err) => start_router_parse_error.set(Some(err)),
                        }
                    },
                    on_start: move |toml: String| {
                        let notice = start_and_attach_local_forwarder(
                            platform,
                            &toml,
                            state,
                            preferences,
                            last_probe,
                            last_probe_at,
                            last_attach_error,
                        );
                        let should_close = notice.tone == "good";
                        forwarder_notice.set(Some(notice));
                        if should_close {
                            start_router_open.set(false);
                        }
                    },
                    on_export: move |toml: String| {
                        let _ = platform::download_text("ndn-dashboard-next-router.toml", &toml);
                    }
                }
            }
        }
    }
}

#[component]
fn AttachBar(state: DashboardState, on_density: EventHandler<()>) -> Element {
    rsx! {
        header { class: "attach-bar",
            div { class: "attach-primary",
                div { class: "attach-label", "Engine" }
                div { class: "attach-value", "{state.profile.display_name()}" }
                div { class: "attach-meta", "{state.profile.endpoint} via {state.profile.attach_mode.label()}" }
            }
            div { class: "chip-row",
                StatusChip { label: state.trust.label().to_string(), tone: tone_for_trust(state.trust).to_string() }
                StatusChip { label: state.observe.label().to_string(), tone: tone_for_observe(state.observe).to_string() }
                StatusChip { label: state.platform_label(), tone: "neutral".to_string() }
                button {
                    class: "density-toggle",
                    "aria-label": "Toggle density. Current density is {state.density.label()}",
                    onclick: move |_| on_density.call(()),
                    "density: {state.density.label()}"
                }
            }
        }
    }
}

trait PlatformLabel {
    fn platform_label(&self) -> String;
}

impl PlatformLabel for DashboardState {
    fn platform_label(&self) -> String {
        match self.platform {
            PlatformKind::Browser => "browser target".into(),
            PlatformKind::Desktop => "desktop target".into(),
        }
    }
}

#[component]
fn StatusChip(label: String, tone: String) -> Element {
    rsx! {
        span { class: "chip {tone}", role: "status", "aria-label": "{label}", "{label}" }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ForwarderActionNotice {
    tone: &'static str,
    title: String,
    detail: String,
}

impl ForwarderActionNotice {
    fn good(title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            tone: "good",
            title: title.into(),
            detail: detail.into(),
        }
    }

    fn bad(title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            tone: "bad",
            title: title.into(),
            detail: detail.into(),
        }
    }

    fn neutral(title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            tone: "neutral",
            title: title.into(),
            detail: detail.into(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_probe_result(
    platform: PlatformKind,
    probe: ProbeResult,
    connected_target: Option<SavedAttachTarget>,
    ownership: Option<EngineOwnership>,
    mut state: Signal<DashboardState>,
    mut preferences: Signal<DashboardPreferences>,
    mut last_probe: Signal<Option<ProbeTranscript>>,
    mut last_probe_at: Signal<Option<u64>>,
    mut last_attach_error: Signal<Option<String>>,
) {
    let density = state.read().density;
    let mut next = state_from_probe(platform, probe.clone());
    next.density = density;
    if let Some(ownership) = ownership
        && let crate::operations::AttachState::Attached { binding } = &mut next.attach_state
    {
        binding.ownership = ownership;
        if let Some(target) = connected_target.as_ref() {
            binding.target_label = Some(target.label.clone());
        }
    }
    let mut next_prefs = preferences.read().clone();
    next_prefs.density = density;
    if let Some(target) = connected_target {
        next_prefs.remember_connected(target, 1_717_300_000);
    }
    platform::save_preferences(next_prefs.clone());
    preferences.set(next_prefs);
    last_probe.set(Some(probe.transcript));
    last_probe_at.set(Some(1_717_300_000));
    last_attach_error.set(None);
    state.set(next);
}

fn dashboard_started_target(draft: &RouterConfigDraft) -> SavedAttachTarget {
    SavedAttachTarget::from_target(
        AttachTarget {
            label: "dashboard-started ndn-fwd".into(),
            endpoint: draft.management_socket.clone(),
            mode: AttachMode::LocalDesktop,
            profile_hint: Some(ForwarderKind::NdnRs),
        },
        false,
        None,
    )
}

fn probe_dashboard_started_forwarder(
    platform: PlatformKind,
    draft: &RouterConfigDraft,
    state: Signal<DashboardState>,
    preferences: Signal<DashboardPreferences>,
    last_probe: Signal<Option<ProbeTranscript>>,
    last_probe_at: Signal<Option<u64>>,
    last_attach_error: Signal<Option<String>>,
) -> Result<SavedAttachTarget, String> {
    let target = dashboard_started_target(draft);
    let client = DesktopLocalClient {
        socket: draft.management_socket.clone(),
    };
    let probe = client
        .probe(&target.attach_target())
        .map_err(|err| err.message().to_string())?;
    apply_probe_result(
        platform,
        probe,
        Some(target.clone()),
        Some(EngineOwnership::DashboardStarted),
        state,
        preferences,
        last_probe,
        last_probe_at,
        last_attach_error,
    );
    Ok(target)
}

fn start_and_attach_local_forwarder(
    platform: PlatformKind,
    toml: &str,
    state: Signal<DashboardState>,
    preferences: Signal<DashboardPreferences>,
    last_probe: Signal<Option<ProbeTranscript>>,
    last_probe_at: Signal<Option<u64>>,
    last_attach_error: Signal<Option<String>>,
) -> ForwarderActionNotice {
    let draft = match RouterConfigDraft::parse_toml(toml) {
        Ok(draft) => draft,
        Err(err) => {
            return ForwarderActionNotice::bad(
                "Could not start ndn-fwd",
                format!("Router TOML is invalid: {err}"),
            );
        }
    };

    match platform::start_local_forwarder_with_config(toml) {
        Ok(launch) => match probe_dashboard_started_forwarder(
            platform,
            &draft,
            state,
            preferences,
            last_probe,
            last_probe_at,
            last_attach_error,
        ) {
            Ok(target) => ForwarderActionNotice::good(
                "Local ndn-fwd started and attached",
                format!(
                    "pid {} using {}; attached through {}.",
                    launch.pid, launch.config_path, target.endpoint
                ),
            ),
            Err(err) => ForwarderActionNotice::bad(
                "Local ndn-fwd started; attach failed",
                format!(
                    "pid {} using {}; probe {} failed: {err}. Check the management socket and attach the target from Operations or Settings.",
                    launch.pid, launch.config_path, draft.management_socket
                ),
            ),
        },
        Err(err) if err.contains("already running from this dashboard") => {
            match probe_dashboard_started_forwarder(
                platform,
                &draft,
                state,
                preferences,
                last_probe,
                last_probe_at,
                last_attach_error,
            ) {
                Ok(target) => ForwarderActionNotice::good(
                    "Attached to dashboard-started ndn-fwd",
                    format!("{err}; attached through {}.", target.endpoint),
                ),
                Err(probe_err) => ForwarderActionNotice::bad(
                    "Dashboard-started ndn-fwd is running; attach failed",
                    format!(
                        "{err}; probe {} failed: {probe_err}. Stop it or repair the selected management socket.",
                        draft.management_socket
                    ),
                ),
            }
        }
        Err(err) => ForwarderActionNotice::bad("Could not start ndn-fwd", err),
    }
}

#[component]
fn OperatorConnectBand(
    state: DashboardState,
    selected: Option<SavedAttachTarget>,
    last_probe_at_unix_s: Option<u64>,
    last_attach_error: Option<String>,
    start_notice: Option<ForwarderActionNotice>,
    on_probe_selected: EventHandler<()>,
    on_probe_default: EventHandler<()>,
    on_open_start_router: EventHandler<()>,
    on_stop_forwarder: EventHandler<()>,
    on_open_settings: EventHandler<()>,
) -> Element {
    let selected_available = selected
        .as_ref()
        .map(|target| target.platform_status(state.platform).is_available())
        .unwrap_or(false);
    let selected_label = selected
        .as_ref()
        .map(|target| target.label.clone())
        .unwrap_or_else(|| "no target selected".into());
    let selected_endpoint = selected
        .as_ref()
        .map(|target| target.endpoint.clone())
        .unwrap_or_else(|| "open Settings to add or choose a target".into());
    let attached = last_probe_at_unix_s.is_some();
    let attach_dot_class = if attached {
        "status-dot good"
    } else {
        "status-dot amber"
    };
    let target_dot_class = if selected_available {
        "status-dot good"
    } else {
        "status-dot muted"
    };
    let launch_enabled = state.platform == PlatformKind::Desktop;
    rsx! {
        section { class: "operator-band", "aria-label": "Engine attach controls",
            div { class: "operator-compact",
                div { class: "operator-line", title: "{state.profile.endpoint}",
                    span { class: "{attach_dot_class}", "aria-label": if attached { "attached" } else { "detached" } }
                    span { class: "operator-kicker", "Forwarder" }
                    strong { "{state.profile.display_name()}" }
                }
                div { class: "operator-line", title: "{selected_endpoint}",
                    span { class: "{target_dot_class}", "aria-label": if selected_available { "target ready" } else { "target unavailable" } }
                    span { class: "operator-kicker", "Target" }
                    strong { "{selected_label}" }
                }
                details { class: "operator-popover",
                    summary { "details" }
                    div { class: "operator-popover-body",
                        div { class: "kv", span { "Platform" } strong { "{state.platform_label()}" } }
                        div { class: "kv", span { "Forwarder" } strong { "{state.profile.display_name()}" } }
                        div { class: "kv", span { "Endpoint" } strong { class: "mono", "{state.profile.endpoint}" } }
                        div { class: "kv", span { "Selected target" } strong { "{selected_label}" } }
                        div { class: "kv", span { "Target endpoint" } strong { class: "mono", "{selected_endpoint}" } }
                    }
                }
            }
            div { class: "operator-actions",
                button {
                    class: "tool-button primary",
                    disabled: !selected_available,
                    "aria-label": "Attach to selected engine target",
                    onclick: move |_| on_probe_selected.call(()),
                    "attach"
                }
                button {
                    class: "tool-button",
                    "aria-label": "Attach to default engine target",
                    onclick: move |_| on_probe_default.call(()),
                    "default"
                }
                button {
                    class: "tool-button primary",
                    disabled: !launch_enabled,
                    title: if launch_enabled { "Open router startup workflow" } else { "Browsers cannot start local processes" },
                    "aria-label": "Open Start Router workflow",
                    onclick: move |_| on_open_start_router.call(()),
                    "start"
                }
                button {
                    class: "tool-button",
                    disabled: !launch_enabled,
                    "aria-label": "Stop dashboard-started local ndn-fwd",
                    onclick: move |_| on_stop_forwarder.call(()),
                    "stop"
                }
                button {
                    class: "tool-button",
                    "aria-label": "Open attach and deployment settings",
                    onclick: move |_| on_open_settings.call(()),
                    "settings"
                }
            }
            if let Some(message) = last_attach_error {
                div { class: "operator-message bad", role: "alert",
                    strong { "Attach failed" }
                    span { "{message}" }
                }
            } else if state.platform == PlatformKind::Browser && start_notice.is_none() {
                div { class: "operator-message neutral", role: "status",
                    strong { "Browser target" }
                    span { "Local process start is desktop-only; attach to an in-page engine, remote web target, or relay." }
                }
            }
            if let Some(notice) = start_notice {
                div { class: "operator-message {notice.tone}", role: "status",
                    strong { "{notice.title}" }
                    span { "{notice.detail}" }
                }
            }
        }
    }
}

#[component]
fn StartRouterModal(
    platform: PlatformKind,
    active_tab: StartRouterTab,
    draft: RouterConfigDraft,
    current_config: RouterConfigDraft,
    raw_toml: String,
    parse_error: Option<String>,
    start_notice: Option<ForwarderActionNotice>,
    on_close: EventHandler<()>,
    on_tab: EventHandler<StartRouterTab>,
    on_update: EventHandler<RouterConfigDraft>,
    on_raw_toml: EventHandler<String>,
    on_apply_raw: EventHandler<String>,
    on_start: EventHandler<String>,
    on_export: EventHandler<String>,
) -> Element {
    let model = StartRouterModalModel::new(platform, active_tab, draft.clone(), current_config);
    let name_value = draft.router_name.clone();
    let socket_value = draft.management_socket.clone();
    let cs_value = draft.cs_capacity_bytes.to_string();
    let discovery_value = draft.discovery.service_prefix.clone();
    let trust_context_value = draft.security.trust_context.clone();
    let face_value = draft
        .faces
        .first()
        .map(|face| face.uri.clone())
        .unwrap_or_default();
    let route_prefix_value = draft
        .routes
        .first()
        .map(|route| route.prefix.clone())
        .unwrap_or_default();
    let route_cost_value = draft
        .routes
        .first()
        .map(|route| route.cost.to_string())
        .unwrap_or_else(|| "10".into());
    let draft_for_name = draft.clone();
    let draft_for_socket = draft.clone();
    let draft_for_cs = draft.clone();
    let draft_for_face = draft.clone();
    let draft_for_route_prefix = draft.clone();
    let draft_for_route_cost = draft.clone();
    let draft_for_discovery = draft.clone();
    let draft_for_trust = draft.clone();
    let draft_for_discovery_toggle = draft.clone();
    let draft_for_signed_toggle = draft.clone();
    let quick_preview = model.preview_toml.clone();
    let export_preview = model.preview_toml.clone();
    let start_preview = model.preview_toml.clone();
    let apply_raw = raw_toml.clone();

    rsx! {
        div { class: "modal-backdrop", role: "presentation",
            div {
                class: "trust-modal router-modal",
                role: "dialog",
                "aria-modal": "true",
                "aria-label": "Start Router",
                div { class: "modal-head",
                    div {
                        span { "Operations" }
                        strong { "Start Router" }
                    }
                    button {
                        class: "modal-close",
                        "aria-label": "Close Start Router",
                        onclick: move |_| on_close.call(()),
                        "close"
                    }
                }
                div { class: "router-tab-row", role: "tablist", "aria-label": "Start Router sections",
                    for tab in StartRouterTab::ALL {
                        button {
                            class: if model.active_tab == tab { "tool-button primary" } else { "tool-button" },
                            role: "tab",
                            "aria-selected": if model.active_tab == tab { "true" } else { "false" },
                            onclick: move |_| on_tab.call(tab),
                            "{tab.label()}"
                        }
                    }
                }
                if let Some(blocker) = model.blocker.clone() {
                    div { class: "operator-message amber", role: "status",
                        strong { "Startup unavailable" }
                        span { "{blocker}" }
                    }
                }
                if let Some(notice) = start_notice {
                    div { class: "operator-message {notice.tone}", role: "status",
                        strong { "{notice.title}" }
                        span { "{notice.detail}" }
                    }
                }
                div { class: "modal-body router-modal-body",
                    match model.active_tab {
                        StartRouterTab::QuickStart => rsx! {
                            div { class: "modal-section-grid",
                                div { class: "modal-section",
                                    div { class: "mini-section-title", "Startup target" }
                                    div { class: "modal-kv-grid",
                                        div { class: "kv", span { "Router" } strong { "{model.draft.router_name}" } }
                                        div { class: "kv", span { "Management" } strong { class: "mono", "{model.draft.management_socket}" } }
                                        div { class: "kv", span { "Content store" } strong { "{model.draft.cs_capacity_bytes} bytes" } }
                                        div { class: "kv", span { "Signed mgmt" } strong { if model.draft.security.require_signed_commands { "required" } else { "not required" } } }
                                    }
                                }
                                div { class: "modal-section",
                                    div { class: "mini-section-title", "Startup forwarding" }
                                    div { class: "trust-modal-table cols-3",
                                        for face in model.draft.faces.iter().cloned() {
                                            div { class: "trust-modal-row",
                                                strong { "face" }
                                                span { class: "mono", "{face.uri}" }
                                                StatusChip { label: if face.persist { "persist".to_string() } else { "temporary".to_string() }, tone: "neutral".to_string() }
                                            }
                                        }
                                        for route in model.draft.routes.iter().cloned() {
                                            div { class: "trust-modal-row",
                                                strong { "{route.prefix}" }
                                                span { class: "mono", "{route.face_uri}" }
                                                StatusChip { label: format!("cost {}", route.cost), tone: "info".to_string() }
                                            }
                                        }
                                    }
                                }
                                div { class: "modal-section wide",
                                    div { class: "mini-section-title", "Generated TOML" }
                                    textarea {
                                        class: "code-preview tall router-preview",
                                        readonly: true,
                                        "aria-label": "Generated router TOML",
                                        value: "{quick_preview}"
                                    }
                                }
                            }
                        },
                        StartRouterTab::BuildConfig => rsx! {
                            div { class: "trust-modal-stack",
                                div { class: "mutation-grid",
                                    label { class: "tool-field",
                                        span { "Router name" }
                                        input {
                                            r#type: "text",
                                            value: "{name_value}",
                                            "aria-label": "Router name",
                                            oninput: move |event| {
                                                let mut next = draft_for_name.clone();
                                                next.router_name = event.value();
                                                on_update.call(next);
                                            }
                                        }
                                    }
                                    label { class: "tool-field",
                                        span { "Mgmt socket" }
                                        input {
                                            r#type: "text",
                                            value: "{socket_value}",
                                            "aria-label": "Management socket",
                                            oninput: move |event| {
                                                let mut next = draft_for_socket.clone();
                                                next.management_socket = event.value();
                                                on_update.call(next);
                                            }
                                        }
                                    }
                                    label { class: "tool-field",
                                        span { "CS bytes" }
                                        input {
                                            r#type: "number",
                                            min: "0",
                                            value: "{cs_value}",
                                            "aria-label": "Content store capacity",
                                            oninput: move |event| {
                                                if let Ok(value) = event.value().parse::<u64>() {
                                                    let mut next = draft_for_cs.clone();
                                                    next.cs_capacity_bytes = value;
                                                    on_update.call(next);
                                                }
                                            }
                                        }
                                    }
                                    label { class: "tool-field",
                                        span { "Face URI" }
                                        input {
                                            r#type: "text",
                                            value: "{face_value}",
                                            "aria-label": "Startup face URI",
                                            oninput: move |event| {
                                                let mut next = draft_for_face.clone();
                                                let uri = event.value();
                                                if let Some(face) = next.faces.first_mut() {
                                                    face.uri = uri.clone();
                                                } else if !uri.is_empty() {
                                                    next.faces.push(StartupFaceDraft { uri: uri.clone(), persist: true });
                                                }
                                                if let Some(route) = next.routes.first_mut() {
                                                    route.face_uri = uri;
                                                }
                                                on_update.call(next);
                                            }
                                        }
                                    }
                                    label { class: "tool-field",
                                        span { "Route prefix" }
                                        input {
                                            r#type: "text",
                                            value: "{route_prefix_value}",
                                            "aria-label": "Startup route prefix",
                                            oninput: move |event| {
                                                let mut next = draft_for_route_prefix.clone();
                                                let prefix = event.value();
                                                if let Some(route) = next.routes.first_mut() {
                                                    route.prefix = prefix;
                                                } else if !prefix.is_empty() {
                                                    let face_uri = next.faces.first().map(|face| face.uri.clone()).unwrap_or_default();
                                                    next.routes.push(StartupRouteDraft { prefix, face_uri, cost: 10 });
                                                }
                                                on_update.call(next);
                                            }
                                        }
                                    }
                                    label { class: "tool-field",
                                        span { "Route cost" }
                                        input {
                                            r#type: "number",
                                            min: "0",
                                            value: "{route_cost_value}",
                                            "aria-label": "Startup route cost",
                                            oninput: move |event| {
                                                if let Ok(cost) = event.value().parse::<u64>() {
                                                    let mut next = draft_for_route_cost.clone();
                                                    if let Some(route) = next.routes.first_mut() {
                                                        route.cost = cost;
                                                    }
                                                    on_update.call(next);
                                                }
                                            }
                                        }
                                    }
                                    label { class: "tool-field",
                                        span { "Discovery prefix" }
                                        input {
                                            r#type: "text",
                                            value: "{discovery_value}",
                                            "aria-label": "Discovery service prefix",
                                            oninput: move |event| {
                                                let mut next = draft_for_discovery.clone();
                                                next.discovery.service_prefix = event.value();
                                                on_update.call(next);
                                            }
                                        }
                                    }
                                    label { class: "tool-field",
                                        span { "Trust context" }
                                        input {
                                            r#type: "text",
                                            value: "{trust_context_value}",
                                            "aria-label": "Trust context",
                                            oninput: move |event| {
                                                let mut next = draft_for_trust.clone();
                                                next.security.trust_context = event.value();
                                                on_update.call(next);
                                            }
                                        }
                                    }
                                    label { class: "tool-check",
                                        input {
                                            r#type: "checkbox",
                                            checked: draft.discovery.enabled,
                                            onchange: move |event| {
                                                let mut next = draft_for_discovery_toggle.clone();
                                                next.discovery.enabled = event.checked();
                                                on_update.call(next);
                                            }
                                        }
                                        span { "discovery" }
                                    }
                                    label { class: "tool-check",
                                        input {
                                            r#type: "checkbox",
                                            checked: draft.security.require_signed_commands,
                                            onchange: move |event| {
                                                let mut next = draft_for_signed_toggle.clone();
                                                next.security.require_signed_commands = event.checked();
                                                on_update.call(next);
                                            }
                                        }
                                        span { "signed management" }
                                    }
                                }
                            }
                        },
                        StartRouterTab::LoadToml => rsx! {
                            div { class: "trust-modal-stack",
                                textarea {
                                    class: "code-preview tall router-preview",
                                    "aria-label": "Router TOML input",
                                    value: "{raw_toml}",
                                    oninput: move |event| on_raw_toml.call(event.value())
                                }
                                if let Some(error) = parse_error {
                                    div { class: "operator-message bad", role: "alert",
                                        strong { "TOML parse failed" }
                                        span { "{error}" }
                                    }
                                }
                                div { class: "modal-action-row",
                                    button {
                                        class: "tool-button primary",
                                        "aria-label": "Apply router TOML",
                                        onclick: move |_| on_apply_raw.call(apply_raw.clone()),
                                        "apply TOML"
                                    }
                                }
                            }
                        },
                        StartRouterTab::Presets => rsx! {
                            div { class: "preset-grid",
                                for preset in ConfigPreset::ALL {
                                    button {
                                        class: "target-row preset-card",
                                        "aria-label": "Apply {preset.label()} router preset",
                                        onclick: move |_| on_update.call(RouterConfigDraft::preset(preset)),
                                        div {
                                            div { class: "target-name", "{preset.label()}" }
                                            div { class: "target-meta", "{RouterConfigDraft::preset(preset).management_socket}" }
                                        }
                                        StatusChip {
                                            label: if RouterConfigDraft::preset(preset).security.require_signed_commands { "signed".to_string() } else { "unsigned".to_string() },
                                            tone: "neutral".to_string()
                                        }
                                    }
                                }
                            }
                        },
                        StartRouterTab::CurrentConfig => rsx! {
                            div { class: "trust-modal-stack",
                                div { class: "dense-table config-diff-table",
                                    div { class: "table-head", span { "Field" } span { "Current" } span { "Draft" } span { "Apply" } }
                                    if model.diff.is_empty() {
                                        div { class: "table-row", span { "clean" } span { "-" } span { "-" } span { "live" } }
                                    }
                                    for diff in model.diff.clone() {
                                        div { class: "table-row",
                                            span { "{diff.field}" }
                                            span { "{diff.current}" }
                                            span { "{diff.draft}" }
                                            span { if diff.restart_required { "restart" } else { "runtime" } }
                                        }
                                    }
                                }
                                textarea {
                                    class: "code-preview tall router-preview",
                                    readonly: true,
                                    "aria-label": "Current draft router TOML",
                                    value: "{model.preview_toml}"
                                }
                            }
                        },
                    }
                }
                div { class: "modal-action-row router-modal-actions",
                    button {
                        class: "tool-button",
                        "aria-label": "Export router TOML",
                        onclick: move |_| on_export.call(export_preview.clone()),
                        "export TOML"
                    }
                    button {
                        class: "tool-button primary",
                        disabled: !model.can_start,
                        "aria-label": "Start local ndn-fwd with router config",
                        onclick: move |_| on_start.call(start_preview.clone()),
                        "start ndn-fwd"
                    }
                }
            }
        }
    }
}

#[component]
fn OperationsView(
    model: OperationsHomeModel,
    state: DashboardState,
    engine: EngineSummary,
    observe: ObserveSummary,
    active_tools: Vec<ToolRun>,
    last_attach_error: Option<String>,
    start_notice: Option<ForwarderActionNotice>,
    on_probe_selected: EventHandler<()>,
    on_probe_default: EventHandler<()>,
    on_open_start_router: EventHandler<()>,
) -> Element {
    let attached = model.attach_state.is_attached();
    let selected_available = model
        .selected_target_status
        .is_some_and(|status| status.is_available());
    let start_available = model
        .action(RouterLifecycleAction::StartRouter)
        .is_some_and(|action| action.enabled);
    let lifecycle_available_count = model
        .lifecycle_actions
        .iter()
        .filter(|action| action.enabled)
        .count();
    let target_label = model
        .selected_target
        .as_ref()
        .map(|target| target.label.clone())
        .unwrap_or_else(|| "no attach target selected".into());
    let target_endpoint = model
        .selected_target
        .as_ref()
        .map(|target| target.endpoint.clone())
        .unwrap_or_else(|| "choose an attach target in Settings".into());
    let target_status = model
        .selected_target_status
        .map(|status| status.label().to_string())
        .unwrap_or_else(|| "not selected".into());
    let active_tool_count = if attached {
        active_tools
            .iter()
            .filter(|run| matches!(run.status, ToolStatus::Running | ToolStatus::Streaming))
            .count()
    } else {
        0
    };
    let face_count = if attached { engine.faces.len() } else { 0 };
    let route_count = if attached { engine.routes.len() } else { 0 };
    let trace_count = if attached && model.capability_summary.observe_available {
        observe.recent.len()
    } else {
        0
    };
    let attach_dot_class = if attached {
        "status-dot good"
    } else {
        "status-dot amber"
    };
    let target_dot_class = if selected_available {
        "status-dot good"
    } else {
        "status-dot muted"
    };
    let trust_dot_class = if matches!(state.trust, TrustPosture::Valid) {
        "status-dot good"
    } else {
        "status-dot amber"
    };
    let observe_dot_class = if matches!(state.observe, ObservePosture::Enabled) {
        "status-dot good"
    } else {
        "status-dot amber"
    };
    rsx! {
        div { class: "view-grid operations-grid", "data-testid": "workspace-operations",
            Panel { title: "Operations".to_string(),
                div { class: "operations-board",
                    div { class: "ops-command-surface",
                        div { class: "ops-current", title: "{target_endpoint}",
                            div { class: "ops-current-title",
                                span { class: "{attach_dot_class}", "aria-label": model.run_state.label() }
                                strong { "{state.profile.display_name()}" }
                            }
                            div { class: "row-sub mono", "{state.profile.endpoint}" }
                            div { class: "ops-current-title target",
                                span { class: "{target_dot_class}", "aria-label": "{target_status}" }
                                strong { "{target_label}" }
                            }
                        }
                        div { class: "ops-status-strip", "aria-label": "Operator posture",
                            div { class: "ops-status-item", title: "{state.trust.label()}",
                                span { class: "{trust_dot_class}" }
                                strong { "Trust" }
                            }
                            div { class: "ops-status-item", title: "{state.observe.label()}",
                                span { class: "{observe_dot_class}" }
                                strong { "Observe" }
                            }
                            div { class: "ops-status-item", title: "{state.platform_label()}",
                                span { class: "status-dot info" }
                                strong { "Shell" }
                            }
                        }
                        div { class: "operator-actions inline-actions",
                            button {
                                class: "tool-button primary",
                                disabled: !selected_available,
                                "aria-label": "Attach selected target from Operations",
                                onclick: move |_| on_probe_selected.call(()),
                                "attach"
                            }
                            button {
                                class: "tool-button",
                                "aria-label": "Attach default target from Operations",
                                onclick: move |_| on_probe_default.call(()),
                                "default"
                            }
                            button {
                                class: "tool-button primary",
                                disabled: !start_available,
                                "aria-label": "Open Start Router from Operations",
                                onclick: move |_| on_open_start_router.call(()),
                                "start"
                            }
                        }
                    }
                    div { class: "summary-grid",
                        Metric { label: "Faces".to_string(), value: face_count.to_string() }
                        Metric { label: "Routes".to_string(), value: route_count.to_string() }
                        Metric { label: "Recent traces".to_string(), value: trace_count.to_string() }
                        Metric { label: "Tool runs".to_string(), value: active_tool_count.to_string() }
                    }
                    div { class: "ops-capability-meter", "aria-label": "Capability availability",
                        div { class: if model.capability_summary.live_engine { "meter-segment enabled" } else { "meter-segment disabled" }, title: "NFD baseline",
                            span { "NFD" }
                        }
                        div { class: if model.capability_summary.trust_available { "meter-segment enabled" } else { "meter-segment disabled" }, title: "TrustContext",
                            span { "Trust" }
                        }
                        div { class: if model.capability_summary.observe_available { "meter-segment enabled" } else { "meter-segment disabled" }, title: "Observability",
                            span { "Observe" }
                        }
                        div { class: if model.capability_summary.tools_available { "meter-segment enabled" } else { "meter-segment disabled" }, title: "Tools",
                            span { "Tools" }
                        }
                    }
                    if let Some(error) = last_attach_error {
                        div { class: "operator-message bad", role: "alert",
                            strong { "Attach failed" }
                            span { "{error}" }
                        }
                    } else if let Some(notice) = start_notice {
                        div { class: "operator-message {notice.tone}", role: "status",
                            strong { "{notice.title}" }
                            span { "{notice.detail}" }
                        }
                    } else if !attached {
                        EmptyState {
                            title: "Detached".to_string(),
                            detail: "Attach a target or start a local router; details stay folded until needed.".to_string()
                        }
                    }
                }
            }
            div { class: "ops-disclosure-grid",
                details { class: "ops-disclosure",
                    summary {
                        span { "Target" }
                        span { class: "{target_dot_class}", title: "{target_status}" }
                    }
                    div { class: "target-row selected",
                        div {
                            div { class: "target-name", "{target_label}" }
                            div { class: "target-meta",
                                span { class: "mono", "{target_endpoint}" }
                            }
                        }
                    }
                }
                details { class: "ops-disclosure",
                    summary {
                        span { "Lifecycle" }
                        span { class: "metric", "{lifecycle_available_count}/{model.lifecycle_actions.len()}" }
                    }
                    div { class: "lifecycle-list compact-lifecycle",
                        for action in model.lifecycle_actions.clone() {
                            {
                                let action_dot_class = if action.enabled { "status-dot good" } else { "status-dot muted" };
                                let action_title = action.reason.clone().unwrap_or_else(|| action.action.label().to_string());
                                rsx! {
                            div { class: if action.enabled { "lifecycle-row enabled" } else { "lifecycle-row disabled" },
                                span { class: "{action_dot_class}", title: "{action_title}" }
                                div {
                                    div { class: "row-title", "{action.action.label()}" }
                                }
                                if action.action == RouterLifecycleAction::StartRouter {
                                    button {
                                        class: "icon-button",
                                        disabled: !action.enabled,
                                        title: "Open Start Router",
                                        "aria-label": "Open Start Router workflow",
                                        onclick: move |_| on_open_start_router.call(()),
                                        "+"
                                    }
                                }
                            }
                                }
                            }
                        }
                    }
                }
                details { class: "ops-disclosure",
                    summary {
                        span { "Evidence" }
                        span { class: "metric", "4 rows" }
                    }
                    div { class: "dense-table evidence-table resizable-table",
                        div { class: "table-head", span { "Area" } span { "Evidence" } span { "State" } }
                        div { class: "table-row", span { "Engine" } span { "{state.profile.endpoint}" } span { "{state.profile.capabilities.nfd_basic.label()}" } }
                        div { class: "table-row", span { "Trust" } span { "TrustContext and custodian posture" } span { "{state.trust.label()}" } }
                        div { class: "table-row", span { "Observe" } span { "{observe.prefix}" } span { "{observe.source.label()}" } }
                        div { class: "table-row", span { "Tools" } span { "current dashboard run" } span { "{active_tool_count} active" } }
                    }
                }
            }
        }
    }
}

#[component]
fn CapabilityLine(label: String, enabled: bool) -> Element {
    rsx! {
        div { class: "capability-line",
            span { "{label}" }
            StatusChip {
                label: if enabled { "available".to_string() } else { "unavailable".to_string() },
                tone: if enabled { "good".to_string() } else { "muted".to_string() }
            }
        }
    }
}

#[component]
fn ObserveView(summary: ObserveSummary) -> Element {
    let mut search = use_signal(String::new);
    let query = search.read().clone();
    let filtered = filter_traces(&summary.recent, &query);
    let selected = filtered.first().cloned();
    let audit = AuditViewModel::demo();
    let warn_logs = audit.filter_logs(LogLevel::Info, "");
    let trace_count = filtered.len();
    let total_trace_count = summary.recent.len();
    let trace_count_label = if query.trim().is_empty() {
        format!("{trace_count} traces")
    } else {
        format!("{trace_count}/{total_trace_count} traces")
    };
    rsx! {
        div { class: "view-grid observe-grid", "data-testid": "workspace-observe",
            Panel { title: "Trace feed".to_string(),
                div { class: "panel-toolbar",
                    span { class: "mono", "{summary.prefix}" }
                    StatusChip { label: summary.posture.label().to_string(), tone: tone_for_observe(summary.posture).to_string() }
                    StatusChip { label: summary.source.label().to_string(), tone: summary.source.tone().to_string() }
                    span { class: "metric", "{trace_count_label}" }
                }
                div { class: "trace-search",
                    input {
                        r#type: "search",
                        value: "{query}",
                        placeholder: "Search trace ID, name, face, target, strategy, status",
                        "aria-label": "Search traces by trace ID, name prefix, face, target, strategy, or status",
                        oninput: move |event| search.set(event.value())
                    }
                }
                if let Some(guidance) = summary.guidance.clone() {
                    div { class: "observe-guidance",
                        strong { "Operator note" }
                        span { "{guidance}" }
                    }
                }
                if summary.recent.is_empty() {
                    EmptyState {
                        title: summary.source.label().to_string(),
                        detail: "Observe will populate when the selected attach target exposes recent OTLP span Data.".to_string()
                    }
                } else if filtered.is_empty() {
                    EmptyState {
                        title: "No matching traces".to_string(),
                        detail: "Try a trace ID, span name, target, face ID, strategy, Interest name, or status value from the current trace set.".to_string()
                    }
                } else {
                    div { class: "trace-list",
                        for trace in filtered.clone() {
                            div { class: "trace-row",
                                div {
                                    div { class: "row-title", "{trace.root_name}" }
                                    div { class: "row-sub mono", "{trace.trace_id}" }
                                }
                                div { class: "metric", "{trace.span_count} spans" }
                                div { class: "metric", "{trace.duration_us} us" }
                                if trace.has_pit_fanout {
                                    span { class: "chip amber", "PIT fan-out" }
                                }
                            }
                        }
                    }
                }
            }
            Panel { title: "Trace detail".to_string(),
                if let Some(trace) = selected {
                    TraceDetail {
                        trace,
                        bridge_status: summary.bridge_status.clone(),
                        recent_logs: summary.recent_logs.clone()
                    }
                } else {
                    EmptyState {
                        title: "No trace selected".to_string(),
                        detail: "Recent spans, PIT fan-out, CS attribution, strategy rationale, and correlated logs will appear here once live span Data is available.".to_string()
                    }
                }
            }
            Panel { title: "Logs And Events".to_string(),
                div { class: "panel-toolbar",
                    StatusChip {
                        label: if audit.events.enabled { "event stream".to_string() } else { "polling".to_string() },
                        tone: if audit.events.enabled { "good".to_string() } else { "amber".to_string() },
                    }
                    span { class: "mono", "{audit.events.source}" }
                }
                div { class: "dense-table log-table",
                    div { class: "table-head", span { "Level" } span { "Target" } span { "Trace" } span { "Message" } }
                    for row in warn_logs {
                        div { class: "table-row",
                            span { "{row.level.label()}" }
                            span { "{row.target}" }
                            span { "{row.trace_id.clone().unwrap_or_else(|| \"-\".into())}" }
                            span { "{row.message}" }
                        }
                    }
                }
                div { class: "modal-action-row",
                    button {
                        class: "tool-button",
                        "aria-label": "Export filtered logs",
                        onclick: move |_| {
                            let rows = AuditViewModel::demo().filter_logs(LogLevel::Info, "");
                            if let Ok(body) = AuditViewModel::export_logs_json(&rows) {
                                let _ = platform::download_text("ndn-dashboard-next-logs.json", &body);
                            }
                        },
                        "export logs"
                    }
                }
            }
        }
    }
}

#[component]
fn TraceDetail(
    trace: TraceView,
    bridge_status: BridgeExportStatus,
    recent_logs: Vec<LogEvidenceRow>,
) -> Element {
    let root = trace.spans.first().cloned();
    let tree_rows = span_tree_rows(&trace);
    let pit_rows = pit_fanout_rows(&trace);
    let log_rows = correlated_logs_for_trace(&trace, &recent_logs);
    let pit_count = pit_rows.len();
    let log_count = log_rows.len();
    let cs_label = trace
        .spans
        .iter()
        .find(|span| span.name.contains("cs"))
        .map(|span| span.name.clone())
        .unwrap_or_else(|| "not attributed".into());
    let strategy_label = trace
        .spans
        .iter()
        .find_map(|span| span.strategy.clone())
        .unwrap_or_else(|| "not exported".into());
    let target_label = root
        .as_ref()
        .map(|span| span.target.clone())
        .unwrap_or_else(|| "unknown".into());
    let face_label = root
        .as_ref()
        .and_then(|span| span.face_id)
        .map(|face| face.to_string())
        .unwrap_or_else(|| "n/a".into());
    let status_label = root
        .as_ref()
        .map(|span| span.status.label().to_string())
        .unwrap_or_else(|| "unknown".into());

    rsx! {
        div { class: "detail-table observe-detail",
            div { class: "kv", span { "Root span" } strong { "{trace.root_name}" } }
            div { class: "kv", span { "Trace ID" } strong { class: "mono", "{trace.trace_id}" } }
            div { class: "kv", span { "Target" } strong { "{target_label}" } }
            div { class: "kv", span { "Incoming face" } strong { "{face_label}" } }
            div { class: "kv", span { "Status" } strong { "{status_label}" } }
            div { class: "kv", span { "CS attribution" } strong { "{cs_label}" } }
            div { class: "kv", span { "Strategy rationale" } strong { "{strategy_label}" } }
            div { class: "kv", span { "PIT fan-out spans" } strong { "{pit_count}" } }
            div { class: "kv", span { "Correlated logs" } strong { "{log_count} rows" } }
            div { class: "kv", span { "Export path" } strong { "{bridge_status.state.label()}" } }
        }
        div { class: "bridge-status",
            StatusChip { label: bridge_status.state.label().to_string(), tone: bridge_status.state.tone().to_string() }
            span { "{bridge_status.detail}" }
        }
        div { class: "stage-strip live-stage-strip",
            for span in trace.spans.iter().take(6) {
                div { class: "stage ok",
                    strong { "{span.name}" }
                    span { "{span.duration_us} us" }
                }
            }
        }
        div { class: "pit-fanout", "aria-label": "PIT fan-out detail",
            div { class: "mini-section-title", "PIT fan-out" }
            if pit_rows.is_empty() {
                div { class: "mini-empty", "No PIT fan-out spans in this trace" }
            } else {
                for row in pit_rows {
                    PitFanOutRowView { row }
                }
            }
        }
        div { class: "span-tree", role: "tree", "aria-label": "Trace span tree",
            for row in tree_rows {
                SpanTreeRowView { row }
            }
        }
        div { class: "trace-logs", "aria-label": "Trace-correlated log evidence",
            div { class: "mini-section-title", "Correlated logs" }
            if log_rows.is_empty() {
                div { class: "mini-empty", "No recent log lines matched this trace's IDs, names, targets, faces, or strategy" }
            } else {
                for row in log_rows {
                    LogEvidenceRowView { row }
                }
            }
        }
    }
}

#[component]
fn LogEvidenceRowView(row: LogEvidenceRow) -> Element {
    let seq_label = format!("#{}", row.seq);
    let match_label = if row.matched_by.is_empty() {
        "matched".to_string()
    } else {
        format!("by {}", row.matched_by)
    };

    rsx! {
        div { class: "log-row",
            span { class: "mono", "{seq_label}" }
            span { "{row.level}" }
            span { "{row.target}" }
            span { "{match_label}" }
            strong { "{row.message}" }
        }
    }
}

#[component]
fn PitFanOutRowView(row: PitFanOutRow) -> Element {
    let face_label = row
        .face_id
        .map(|face| format!("face {face}"))
        .unwrap_or_else(|| "face n/a".into());
    let interest_label = row
        .interest_name
        .clone()
        .unwrap_or_else(|| "interest n/a".into());
    let result_label = format!("{} / {} us", row.status.label(), row.duration_us);

    rsx! {
        div { class: "pit-row",
            strong { "{row.span_name}" }
            span { "{face_label}" }
            span { "{interest_label}" }
            span { "{result_label}" }
        }
    }
}

#[component]
fn SpanTreeRowView(row: SpanTreeRow) -> Element {
    let indent = format!("padding-left: {}px", 8 + row.depth * 14);
    let child_label = if row.child_count == 1 {
        "1 child".to_string()
    } else {
        format!("{} children", row.child_count)
    };
    let status_label = row.span.status.label().to_string();

    rsx! {
        div { class: "span-node", role: "treeitem", style: "{indent}",
            div {
                strong { "{row.span.name}" }
                span { class: "mono", "{row.span.span_id}" }
            }
            span { "{row.span.target}" }
            span { "{child_label}" }
            span { "{status_label}" }
            if row.orphaned_parent {
                span { class: "chip amber", "missing parent" }
            }
        }
    }
}

#[component]
fn TrustView(profile: crate::core::ForwarderProfile, summary: TrustContextSummary) -> Element {
    let mut active_modal = use_signal(|| None::<TrustModal>);
    let modal = *active_modal.read();

    rsx! {
        div { class: "trust-workspace", "data-testid": "workspace-trust",
            TrustOverview { summary: summary.clone(), on_open: move |modal| active_modal.set(Some(modal)) }
            div { class: "trust-main-grid",
                TrustVerifyPanel { summary: summary.clone(), on_open: move |modal| active_modal.set(Some(modal)) }
                TrustSignPanel { summary: summary.clone(), on_open: move |modal| active_modal.set(Some(modal)) }
            }
            div { class: "trust-main-grid secondary",
                TrustTracePanel { summary: summary.clone(), on_open: move |modal| active_modal.set(Some(modal)) }
                TrustMaintenancePanel { summary: summary.clone(), on_open: move |modal| active_modal.set(Some(modal)) }
            }
            TrustAuditPanel {}
            if let Some(modal) = modal {
                TrustModalView {
                    profile,
                    summary,
                    modal,
                    on_close: move |_| active_modal.set(None),
                }
            }
        }
    }
}

#[component]
fn TrustOverview(summary: TrustContextSummary, on_open: EventHandler<TrustModal>) -> Element {
    let active_identity = summary
        .identities
        .iter()
        .find(|identity| identity.active)
        .or_else(|| summary.identities.first())
        .cloned();
    let sign_value = active_identity
        .as_ref()
        .map(|identity| identity.certificate.to_string())
        .unwrap_or_else(|| "none".to_string());
    let sign_detail = active_identity
        .as_ref()
        .map(|identity| identity.name.clone())
        .unwrap_or_else(|| "verification only".to_string());
    let action_value = if summary.pending_approvals > 0 {
        format!("{} approval", summary.pending_approvals)
    } else {
        summary.action_label().to_string()
    };
    rsx! {
        Panel { title: "Security".to_string(),
            div { class: "trust-status-grid",
                TrustStatusCard {
                    label: "Verify".to_string(),
                    value: summary.posture.label().to_string(),
                    detail: format!("{} contexts / {} anchors", summary.contexts.len(), summary.anchors),
                    tone: tone_for_trust(summary.posture).to_string(),
                    modal: TrustModal::Verify,
                    on_open
                }
                TrustStatusCard {
                    label: "Sign".to_string(),
                    value: sign_value,
                    detail: sign_detail,
                    tone: if summary.identities.is_empty() { "neutral".to_string() } else { "good".to_string() },
                    modal: TrustModal::Sign,
                    on_open
                }
                TrustStatusCard {
                    label: "Mgmt".to_string(),
                    value: if summary.posture == crate::core::TrustPosture::Unsupported { "compat".to_string() } else { "signed".to_string() },
                    detail: summary.custody.title.to_string(),
                    tone: if summary.posture == crate::core::TrustPosture::Unsupported { "neutral".to_string() } else { "good".to_string() },
                    modal: TrustModal::Trace,
                    on_open
                }
                TrustStatusCard {
                    label: "Action".to_string(),
                    value: action_value,
                    detail: summary.namespace.clone(),
                    tone: if summary.pending_approvals > 0 { "amber".to_string() } else { "info".to_string() },
                    modal: if summary.pending_approvals > 0 { TrustModal::Approvals } else { TrustModal::Adopt },
                    on_open
                }
            }
        }
    }
}

#[component]
fn TrustAuditPanel() -> Element {
    let audit = AuditViewModel::demo();
    rsx! {
        Panel { title: "Security Audit".to_string(),
            div { class: "dense-table audit-table",
                div { class: "table-head", span { "Action" } span { "Actor" } span { "Outcome" } span { "Trace" } }
                for row in audit.security {
                    div { class: "table-row",
                        span { "{row.action}" }
                        span { "{row.actor}" }
                        span { "{row.outcome}" }
                        span { "{row.trace_id.clone().unwrap_or_else(|| \"-\".into())}" }
                    }
                }
            }
        }
    }
}

#[component]
fn TrustStatusCard(
    label: String,
    value: String,
    detail: String,
    tone: String,
    modal: TrustModal,
    on_open: EventHandler<TrustModal>,
) -> Element {
    rsx! {
        button {
            class: "trust-status-card {tone}",
            "aria-label": "Open {label} trust details",
            onclick: move |_| on_open.call(modal),
            span { "{label}" }
            strong { "{value}" }
            small { "{detail}" }
        }
    }
}

#[component]
fn TrustVerifyPanel(summary: TrustContextSummary, on_open: EventHandler<TrustModal>) -> Element {
    rsx! {
        Panel { title: "Verify".to_string(),
            div { class: "trust-chain-strip",
                div { class: "chain-pill good", span { "Context" } strong { "{summary.contexts.len()}" } }
                div { class: "chain-pill good", span { "Anchor" } strong { "{summary.anchors}" } }
                div { class: "chain-pill info", span { "Schema" } strong { "{summary.schema_rules}" } }
                div { class: "chain-pill {tone_for_trust(summary.posture)}", span { "Verdict" } strong { "{summary.posture.label()}" } }
            }
            div { class: "trust-command-row",
                button {
                    class: "tool-button primary",
                    "aria-label": "Inspect verification contexts anchors and schemas",
                    onclick: move |_| on_open.call(TrustModal::Verify),
                    "inspect"
                }
                button {
                    class: "tool-button",
                    "aria-label": "Adopt or update trust context",
                    onclick: move |_| on_open.call(TrustModal::Adopt),
                    "adopt"
                }
            }
        }
    }
}

#[component]
fn TrustSignPanel(summary: TrustContextSummary, on_open: EventHandler<TrustModal>) -> Element {
    let active_identity = summary
        .identities
        .iter()
        .find(|identity| identity.active)
        .or_else(|| summary.identities.first())
        .cloned();
    rsx! {
        Panel { title: "Sign".to_string(),
            if let Some(identity) = active_identity {
                div { class: "active-identity-card",
                    div {
                        span { "Active identity" }
                        strong { "{identity.name}" }
                    }
                    StatusChip { label: identity.certificate.to_string(), tone: if identity.certificate == "valid" { "good".to_string() } else { "amber".to_string() } }
                }
            } else {
                div { class: "mini-empty", "No signing identity" }
            }
            div { class: "trust-action-row",
                strong { "Enroll" }
                span { "{summary.enrollment.subject_hint}" }
                StatusChip { label: summary.enrollment.state.to_string(), tone: if summary.enrollment.available { "info".to_string() } else { "neutral".to_string() } }
            }
            div { class: "trust-command-row",
                button {
                    class: "tool-button primary",
                    "aria-label": "Inspect signing identities and keys",
                    onclick: move |_| on_open.call(TrustModal::Sign),
                    "keys"
                }
                button {
                    class: "tool-button",
                    "aria-label": "Open certificate enrollment",
                    onclick: move |_| on_open.call(TrustModal::Enroll),
                    "enroll"
                }
                button {
                    class: "tool-button",
                    "aria-label": "Review pending trust approvals",
                    onclick: move |_| on_open.call(TrustModal::Approvals),
                    "approvals"
                }
            }
        }
    }
}

#[component]
fn TrustTracePanel(summary: TrustContextSummary, on_open: EventHandler<TrustModal>) -> Element {
    rsx! {
        Panel { title: "Trace".to_string(),
            if let Some(frame) = summary.validation_frame.clone() {
                div { class: "trace-summary",
                    strong { "{frame.target}" }
                    StatusChip { label: frame.verdict.to_string(), tone: if frame.verdict == "valid" { "good".to_string() } else { "bad".to_string() } }
                }
                if let Some(failure) = frame.failure.clone() {
                    div { class: "inline-alert", "{failure}" }
                }
                div { class: "trust-command-row",
                    button {
                        class: "tool-button primary",
                        "aria-label": "Open validation path",
                        onclick: move |_| on_open.call(TrustModal::Trace),
                        "path"
                    }
                    button {
                        class: "tool-button",
                        "aria-label": "Open DID framing details",
                        onclick: move |_| on_open.call(TrustModal::Trace),
                        "DID"
                    }
                }
            } else {
                div { class: "mini-empty", "No validation trace" }
            }
        }
    }
}

#[component]
fn TrustMaintenancePanel(
    summary: TrustContextSummary,
    on_open: EventHandler<TrustModal>,
) -> Element {
    rsx! {
        Panel { title: "Maintenance".to_string(),
            div { class: "compact-stack",
                div { class: "trust-compact-row with-sub",
                    strong { "Schema" }
                    span { class: "row-sub", "{summary.schema_summaries.len()} sets" }
                    StatusChip { label: if summary.schema_reviews.is_empty() { "stable".to_string() } else { "review".to_string() }, tone: if summary.schema_reviews.is_empty() { "good".to_string() } else { "amber".to_string() } }
                }
                div { class: "trust-compact-row",
                    strong { "SafeBag" }
                    StatusChip { label: if summary.safebag_import.available { "ready".to_string() } else { "unavailable".to_string() }, tone: if summary.safebag_import.available { "info".to_string() } else { "neutral".to_string() } }
                }
                div { class: "trust-compact-row with-sub",
                    strong { "Recent validations" }
                    span { class: "row-sub", "{summary.validation_traces.len()} rows" }
                    StatusChip { label: summary.posture.label().to_string(), tone: tone_for_trust(summary.posture).to_string() }
                }
            }
            div { class: "trust-command-row",
                button {
                    class: "tool-button primary",
                    "aria-label": "Open trust maintenance details",
                    onclick: move |_| on_open.call(TrustModal::Maintenance),
                    "review"
                }
                button {
                    class: "tool-button",
                    "aria-label": "Open SafeBag preview",
                    onclick: move |_| on_open.call(TrustModal::SafeBag),
                    "SafeBag"
                }
            }
        }
    }
}

#[component]
fn TrustModalView(
    profile: crate::core::ForwarderProfile,
    summary: TrustContextSummary,
    modal: TrustModal,
    on_close: EventHandler<()>,
) -> Element {
    let adopt_preflight = preflight_mutation(
        &profile,
        summary.posture,
        MutationOperation::AdoptTrustContext,
    );
    let enroll_preflight = preflight_mutation(
        &profile,
        summary.posture,
        MutationOperation::EnrollCertificate,
    );
    let approve_preflight = preflight_mutation(
        &profile,
        summary.posture,
        MutationOperation::ApproveTrustRequest,
    );
    let reject_preflight = preflight_mutation(
        &profile,
        summary.posture,
        MutationOperation::RejectTrustRequest,
    );
    let schema_preflight = preflight_mutation(
        &profile,
        summary.posture,
        MutationOperation::ReviewSchemaChange,
    );
    let safebag_preflight =
        preflight_mutation(&profile, summary.posture, MutationOperation::ImportSafeBag);

    rsx! {
        div { class: "modal-backdrop", role: "presentation",
            div {
                class: "trust-modal",
                role: "dialog",
                "aria-modal": "true",
                "aria-label": "{modal.title()}",
                div { class: "modal-head",
                    div {
                        span { "Trust" }
                        strong { "{modal.title()}" }
                    }
                    button {
                        class: "modal-close",
                        "aria-label": "Close trust dialog",
                        onclick: move |_| on_close.call(()),
                        "close"
                    }
                }
                div { class: "modal-body",
                    match modal {
                        TrustModal::Verify => rsx! {
                            div { class: "modal-section-grid",
                                div { class: "modal-section",
                                    div { class: "mini-section-title", "Contexts" }
                                    div { class: "trust-modal-table cols-3",
                                        for context in summary.contexts.iter().cloned() {
                                            div { class: "trust-modal-row",
                                                strong { "{context.namespace}" }
                                                span { "{context.source}" }
                                                StatusChip { label: context.state.to_string(), tone: tone_for_trust(context.posture).to_string() }
                                            }
                                        }
                                    }
                                }
                                div { class: "modal-section",
                                    div { class: "mini-section-title", "Anchors" }
                                    div { class: "trust-modal-table cols-3",
                                        for anchor in summary.anchors_detail.iter().cloned() {
                                            div { class: "trust-modal-row",
                                                strong { "{anchor.name}" }
                                                span { class: "mono", "{anchor.fingerprint}" }
                                                StatusChip { label: anchor.state.to_string(), tone: if anchor.state == "trusted" { "good".to_string() } else { "amber".to_string() } }
                                            }
                                        }
                                    }
                                }
                                div { class: "modal-section wide",
                                    div { class: "mini-section-title", "Schemas" }
                                    div { class: "trust-modal-table cols-4",
                                        for schema in summary.schema_summaries.iter().cloned() {
                                            div { class: "trust-modal-row",
                                                strong { "{schema.namespace}" }
                                                span { "{schema.version}" }
                                                span { "{schema.rules} rules" }
                                                StatusChip { label: schema.strictness.to_string(), tone: if schema.strictness == "weakened" { "amber".to_string() } else { "info".to_string() } }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        TrustModal::Adopt => rsx! {
                            div { class: "trust-modal-stack",
                                PreflightPanel { preflight: adopt_preflight.clone() }
                                div { class: "modal-kv-grid",
                                    div { class: "kv", span { "Namespace" } strong { "{summary.adoption.namespace_hint}" } }
                                    div { class: "kv", span { "Fingerprint" } strong { class: "mono", "{summary.adoption.fingerprint_hint}" } }
                                    div { class: "kv", span { "State" } strong { "{summary.adoption.state}" } }
                                    div { class: "kv", span { "Confirmation" } strong { if summary.adoption.requires_oob_confirmation { "out-of-band" } else { "not required" } } }
                                }
                                div { class: "preflight-note", "{summary.adoption.next_action}" }
                                div { class: "modal-action-row",
                                    button { class: "tool-button primary", disabled: true, "compare fingerprint" }
                                    button { class: "tool-button", disabled: true, "{pending_action_label(&adopt_preflight)}" }
                                }
                            }
                        },
                        TrustModal::Sign => rsx! {
                            div { class: "trust-modal-stack",
                                div { class: "custody-alert",
                                    strong { "{summary.custody.title}" }
                                    span { "{summary.custody.detail}" }
                                }
                                div { class: "modal-section",
                                    div { class: "mini-section-title", "Identities" }
                                    div { class: "trust-modal-table cols-4",
                                        for identity in summary.identities.iter().cloned() {
                                            div { class: "trust-modal-row",
                                                strong { "{identity.name}" }
                                                span { "{identity.custodian}" }
                                                span { "{identity.certificate}" }
                                                StatusChip { label: if identity.active { "active".to_string() } else { "standby".to_string() }, tone: if identity.active { "good".to_string() } else { "neutral".to_string() } }
                                            }
                                        }
                                    }
                                }
                                div { class: "modal-section",
                                    div { class: "mini-section-title", "Keys" }
                                    div { class: "trust-modal-table cols-4",
                                        for key in summary.key_inventory.iter().cloned() {
                                            div { class: "trust-modal-row",
                                                strong { "{key.key_name}" }
                                                span { "{key.algorithm}" }
                                                span { "{key.storage}" }
                                                StatusChip { label: key.certificate_state.to_string(), tone: if key.certificate_state == "valid" { "good".to_string() } else { "amber".to_string() } }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        TrustModal::Enroll => rsx! {
                            div { class: "trust-modal-stack",
                                PreflightPanel { preflight: enroll_preflight.clone() }
                                div { class: "modal-kv-grid",
                                    div { class: "kv", span { "Subject" } strong { "{summary.enrollment.subject_hint}" } }
                                    div { class: "kv", span { "Challenge" } strong { "{summary.enrollment.challenge_summary}" } }
                                    div { class: "kv", span { "State" } strong { "{summary.enrollment.state}" } }
                                    div { class: "kv", span { "CA" } strong { "{summary.enrollment.ca_endpoints.join(\", \")}" } }
                                }
                                div { class: "preflight-note", "{summary.enrollment.next_action}" }
                                div { class: "modal-action-row",
                                    button { class: "tool-button primary", disabled: true, "run NEW" }
                                    button { class: "tool-button", disabled: true, "{pending_action_label(&enroll_preflight)}" }
                                }
                            }
                        },
                        TrustModal::Approvals => rsx! {
                            div { class: "trust-modal-stack",
                                PreflightPanel { preflight: approve_preflight.clone() }
                                if summary.approvals.is_empty() {
                                    div { class: "mini-empty", "No pending approvals" }
                                }
                                div { class: "trust-modal-table cols-4",
                                    for approval in summary.approvals.iter().cloned() {
                                        div { class: "trust-modal-row",
                                            strong { "{approval.subject}" }
                                            span { "{approval.requester}" }
                                            span { "{approval.challenge}" }
                                            StatusChip { label: approval.state.to_string(), tone: "amber".to_string() }
                                        }
                                    }
                                }
                                div { class: "modal-action-row",
                                    button { class: "tool-button primary", disabled: true, "{pending_action_label(&approve_preflight)}" }
                                    button { class: "tool-button", disabled: true, "{pending_action_label(&reject_preflight)}" }
                                }
                            }
                        },
                        TrustModal::Trace => rsx! {
                            div { class: "trust-modal-stack",
                                if let Some(frame) = summary.validation_frame.clone() {
                                    div { class: "trace-summary",
                                        strong { "{frame.target}" }
                                        StatusChip { label: frame.verdict.to_string(), tone: if frame.verdict == "valid" { "good".to_string() } else { "bad".to_string() } }
                                    }
                                    if let Some(failure) = frame.failure.clone() {
                                        div { class: "inline-alert", "{failure}" }
                                    }
                                    div { class: "modal-section-grid",
                                        div { class: "modal-section",
                                            div { class: "mini-section-title", "Chain" }
                                            div { class: "trust-modal-table cols-3",
                                                for step in frame.chain.iter().cloned() {
                                                    div { class: "trust-modal-row",
                                                        strong { "{step.name}" }
                                                        span { "{step.signed_by}" }
                                                        StatusChip { label: if step.anchor { "anchor".to_string() } else { "chain".to_string() }, tone: if step.anchor { "good".to_string() } else { "info".to_string() } }
                                                    }
                                                }
                                            }
                                        }
                                        div { class: "modal-section",
                                            div { class: "mini-section-title", "Schema Rules" }
                                            div { class: "trust-modal-table cols-3",
                                                for rule in frame.rules.iter().cloned() {
                                                    div { class: "trust-modal-row",
                                                        strong { "{rule.data_pattern}" }
                                                        span { "{rule.key_pattern}" }
                                                        StatusChip { label: if rule.matches { "matched".to_string() } else { "missed".to_string() }, tone: if rule.matches { "good".to_string() } else { "bad".to_string() } }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    div { class: "mini-empty", "No validation trace" }
                                }
                                div { class: "modal-section",
                                    div { class: "mini-section-title", "DID" }
                                    if summary.did_frames.is_empty() {
                                        div { class: "mini-empty", "No DID framing" }
                                    }
                                    div { class: "trust-modal-table cols-4",
                                        for did in summary.did_frames.iter().cloned() {
                                            div { class: "trust-modal-row",
                                                strong { "{did.did}" }
                                                span { "{did.source_name}" }
                                                span { "{did.verification_methods} methods" }
                                                span { "{did.services} services" }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        TrustModal::Maintenance => rsx! {
                            div { class: "modal-section-grid",
                                div { class: "modal-section wide",
                                    PreflightPanel { preflight: schema_preflight.clone() }
                                }
                                div { class: "modal-section",
                                    div { class: "mini-section-title", "Schema Review" }
                                    div { class: "trust-modal-table cols-3",
                                        for review in summary.schema_reviews.iter().cloned() {
                                            div { class: "trust-modal-row",
                                                strong { "{review.namespace}" }
                                                span { "{review.change}" }
                                                StatusChip { label: review.operator_action.to_string(), tone: tone_for_trust(review.posture).to_string() }
                                            }
                                        }
                                    }
                                }
                                div { class: "modal-section",
                                    div { class: "mini-section-title", "Recent Validations" }
                                    div { class: "trust-modal-table cols-4",
                                        for trace in summary.validation_traces.iter().cloned() {
                                            div { class: "trust-modal-row",
                                                strong { "{trace.packet_name}" }
                                                span { "{trace.signer}" }
                                                span { "{trace.rule}" }
                                                StatusChip { label: trace.outcome.to_string(), tone: if trace.outcome.contains("valid") { "good".to_string() } else { "bad".to_string() } }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        TrustModal::SafeBag => rsx! {
                            div { class: "trust-modal-stack",
                                PreflightPanel { preflight: safebag_preflight.clone() }
                                div { class: "safebag-preview",
                                    strong { if summary.safebag_import.available { "Ready" } else { "Unavailable" } }
                                    span { "{summary.safebag_import.summary}" }
                                }
                                div { class: "compact-stack",
                                    for warning in summary.safebag_import.warnings.iter().cloned() {
                                        div { class: "trust-compact-row",
                                            strong { "{warning}" }
                                            StatusChip { label: "boundary".to_string(), tone: "info".to_string() }
                                        }
                                    }
                                }
                                div { class: "modal-action-row",
                                    button { class: "tool-button primary", disabled: true, "preview import" }
                                    button { class: "tool-button", disabled: true, "{pending_action_label(&safebag_preflight)}" }
                                }
                            }
                        },
                    }
                }
            }
        }
    }
}

#[component]
fn PreflightPanel(preflight: MutationPreflight) -> Element {
    rsx! {
        div { class: "preflight-panel",
            div { class: "preflight-head",
                strong { "{preflight.operation.label()}" }
                StatusChip {
                    label: preflight.status.label().to_string(),
                    tone: tone_for_preflight(preflight.status).to_string(),
                }
            }
            div { class: "preflight-summary", "{preflight.summary()}" }
            div { class: "preflight-checks",
                for check in preflight.checks.iter().cloned() {
                    div { class: if check.passed { "preflight-check passed" } else { "preflight-check failed" },
                        span { "{check.label}" }
                        strong { "{check.detail}" }
                    }
                }
            }
        }
    }
}

fn pending_action_label(preflight: &MutationPreflight) -> &'static str {
    if preflight.can_execute() {
        "execution adapter pending"
    } else {
        "blocked by preflight"
    }
}

#[component]
fn MutationHistory(records: Vec<MutationRecord>) -> Element {
    rsx! {
        div { class: "mutation-history",
            div { class: "mini-section-title", "Mutation history" }
            if records.is_empty() {
                div { class: "mini-empty", "No mutations in this session" }
            }
            for record in records {
                div { class: "mutation-row",
                    strong { "{record.operation.label()}" }
                    span { class: "mono", "{record.target}" }
                    StatusChip {
                        label: record.status.label().to_string(),
                        tone: tone_for_mutation_status(record.status).to_string(),
                    }
                    span { class: "result-cell", "{record.result}" }
                }
            }
        }
    }
}

fn replace_running_mutation(records: &mut Signal<Vec<MutationRecord>>, record: MutationRecord) {
    let mut rows = records.write();
    if let Some(slot) = rows.iter_mut().find(|row| {
        row.operation == record.operation
            && row.target == record.target
            && row.status == MutationStatus::Running
    }) {
        *slot = record;
    } else {
        rows.insert(0, record);
    }
}

#[component]
fn EngineView(
    profile: crate::core::ForwarderProfile,
    trust: crate::core::TrustPosture,
    summary: EngineSummary,
) -> Element {
    let mut mutation_records = use_signal(Vec::<MutationRecord>::new);
    let mut mutation_session = use_signal(MutationSession::default);
    let mut face_uri = use_signal(|| "udp4://127.0.0.1:6363".to_string());
    let mut face_mtu = use_signal(String::new);
    let mut destroy_face_id = use_signal(|| match summary.detail.clone() {
        EngineDetail::Face(face) => face.id.to_string(),
        _ => summary
            .faces
            .first()
            .map(|face| face.id.to_string())
            .unwrap_or_default(),
    });
    let mut confirm_destroy = use_signal(|| false);
    let mut route_prefix = use_signal(|| "/ndn/site/video".to_string());
    let mut route_face_id = use_signal(|| {
        summary
            .faces
            .first()
            .map(|face| face.id.to_string())
            .unwrap_or_default()
    });
    let mut route_cost = use_signal(|| "10".to_string());
    let mut remove_route_prefix = use_signal(|| {
        summary
            .routes
            .first()
            .map(|route| route.prefix.clone())
            .unwrap_or_else(|| "/ndn/site/video".to_string())
    });
    let mut remove_route_face_id = use_signal(|| {
        summary
            .routes
            .first()
            .map(|route| route.face_id.to_string())
            .unwrap_or_default()
    });
    let mut confirm_route_remove = use_signal(|| false);
    let mut strategy_prefix = use_signal(|| {
        summary
            .strategies
            .first()
            .map(|strategy| strategy.prefix.clone())
            .unwrap_or_else(|| "/".to_string())
    });
    let mut strategy_name = use_signal(|| KNOWN_STRATEGIES[0].0.to_string());
    let mut custom_strategy_name = use_signal(String::new);
    let mut unset_strategy_prefix = use_signal(|| {
        summary
            .strategies
            .first()
            .map(|strategy| strategy.prefix.clone())
            .unwrap_or_else(|| "/".to_string())
    });
    let mut confirm_strategy_unset = use_signal(|| false);
    let mut cs_capacity = use_signal(|| {
        summary
            .store_pit
            .as_ref()
            .map(|store| store.cs_capacity.to_string())
            .unwrap_or_else(|| "65536".to_string())
    });
    let mut cs_erase_prefix = use_signal(|| "/".to_string());
    let mut cs_erase_count = use_signal(String::new);
    let mut confirm_cs_erase = use_signal(|| false);
    let mut shutdown_reason = use_signal(|| "operator requested shutdown".to_string());
    let mut confirm_shutdown = use_signal(|| false);
    let status = summary.status.clone();
    let store_pit = summary.store_pit.clone();
    let traffic = summary.traffic.clone();
    let face_rows = summary.filter_faces("");
    let face_options = face_rows.clone();
    let route_rows = summary.search_routes("");
    let create_preflight = preflight_mutation(&profile, trust, MutationOperation::CreateFace);
    let destroy_preflight = preflight_mutation(&profile, trust, MutationOperation::DestroyFace);
    let route_add_preflight = preflight_mutation(&profile, trust, MutationOperation::AddRoute);
    let route_remove_preflight =
        preflight_mutation(&profile, trust, MutationOperation::RemoveRoute);
    let strategy_set_preflight =
        preflight_mutation(&profile, trust, MutationOperation::SetStrategy);
    let strategy_unset_preflight =
        preflight_mutation(&profile, trust, MutationOperation::UnsetStrategy);
    let cs_capacity_preflight =
        preflight_mutation(&profile, trust, MutationOperation::SetCsCapacity);
    let cs_erase_preflight = preflight_mutation(&profile, trust, MutationOperation::EraseCs);
    let shutdown_preflight =
        preflight_mutation(&profile, trust, MutationOperation::ShutdownForwarder);
    let reconnect_preflight =
        preflight_mutation(&profile, trust, MutationOperation::ReconnectForwarder);
    let destroy_face_id_value = parse_opt_u64(&destroy_face_id.read());
    let route_face_id_value = parse_opt_u64(&route_face_id.read());
    let remove_route_face_id_value = parse_opt_u64(&remove_route_face_id.read());
    let cs_capacity_value = parse_opt_u64(&cs_capacity.read());
    let can_create = create_preflight.can_execute() && !face_uri.read().trim().is_empty();
    let can_destroy = destroy_preflight.can_execute()
        && destroy_face_id_value.is_some()
        && *confirm_destroy.read();
    let can_add_route = route_add_preflight.can_execute()
        && !route_prefix.read().trim().is_empty()
        && route_face_id_value.is_some();
    let can_remove_route = route_remove_preflight.can_execute()
        && !remove_route_prefix.read().trim().is_empty()
        && remove_route_face_id_value.is_some()
        && *confirm_route_remove.read();
    let selected_strategy_name = if strategy_name.read().as_str() == "__custom__" {
        custom_strategy_name.read().trim().to_string()
    } else {
        strategy_name.read().clone()
    };
    let can_set_strategy = strategy_set_preflight.can_execute()
        && !strategy_prefix.read().trim().is_empty()
        && !selected_strategy_name.is_empty();
    let can_unset_strategy = strategy_unset_preflight.can_execute()
        && !unset_strategy_prefix.read().trim().is_empty()
        && *confirm_strategy_unset.read();
    let can_set_cs_capacity = cs_capacity_preflight.can_execute() && cs_capacity_value.is_some();
    let can_erase_cs = cs_erase_preflight.can_execute()
        && !cs_erase_prefix.read().trim().is_empty()
        && *confirm_cs_erase.read();
    let can_shutdown = shutdown_preflight.can_execute() && *confirm_shutdown.read();
    let can_reconnect = reconnect_preflight.can_execute();
    let mutation_rows = mutation_records.read().clone();
    let session_lines = mutation_session.read().export_lines();
    let profile_for_create = profile.clone();
    let profile_for_destroy = profile.clone();
    let profile_for_route_add = profile.clone();
    let profile_for_route_remove = profile.clone();
    let profile_for_strategy_set = profile.clone();
    let profile_for_strategy_unset = profile.clone();
    let profile_for_cs_capacity = profile.clone();
    let profile_for_cs_erase = profile.clone();
    let profile_for_shutdown = profile.clone();
    let profile_for_reconnect = profile.clone();
    let profile_for_replay = profile.clone();
    let network_model = NetworkViewModel::from_engine(&profile, &summary);
    let extension_registry = ExtensionRegistry::for_profile(&profile);
    let read_only_label = if summary.read_only {
        "read-only"
    } else {
        "native"
    };

    rsx! {
        div { class: "view-grid engine-grid", "data-testid": "workspace-engine",
            Panel { title: "Overview".to_string(),
                div { class: "panel-toolbar",
                    StatusChip { label: read_only_label.to_string(), tone: if summary.read_only { "amber".to_string() } else { "good".to_string() } }
                    StatusChip { label: summary.profile_kind.label().to_string(), tone: "neutral".to_string() }
                }
                if let Some(status) = status {
                    div { class: "metrics-grid",
                        Metric { label: "Uptime".to_string(), value: format!("{}s", status.uptime_s) }
                        Metric { label: "In Interests".to_string(), value: compact_count(status.n_in_interests) }
                        Metric { label: "Out Data".to_string(), value: compact_count(status.n_out_data) }
                        Metric { label: "Version".to_string(), value: status.version }
                    }
                } else {
                    EmptyState {
                        title: "Engine status unavailable".to_string(),
                        detail: "Attach is disconnected or this target does not expose NFD-compatible status datasets.".to_string()
                    }
                }
                EngineSources { sources: summary.sources.clone() }
            }
            Panel { title: "Faces".to_string(),
                div { class: "panel-toolbar",
                    span { class: "mono", "filter: all" }
                    StatusChip { label: format!("{} rows", face_rows.len()), tone: "neutral".to_string() }
                }
                div { class: "dense-table engine-table faces-table",
                    div { class: "table-head", span { "Face" } span { "URI" } span { "State" } span { "Rx/Tx" } }
                    for face in face_rows.clone() {
                        div { class: "table-row",
                            span { "{face.id}" }
                            span { "{face.uri}" }
                            span { "{face.state} / {face.scope}" }
                            span { "{face.traffic_label()}" }
                        }
                    }
                }
            }
            Panel { title: "Face Mutations".to_string(),
                div { class: "mutation-grid",
                    div { class: "mutation-card",
                        div { class: "tool-card-title", "Create face" }
                        PreflightPanel { preflight: create_preflight.clone() }
                        label { class: "tool-field span-2",
                            span { "URI" }
                            input {
                                r#type: "text",
                                value: "{face_uri.read()}",
                                "aria-label": "Face URI",
                                oninput: move |event| face_uri.set(event.value())
                            }
                        }
                        label { class: "tool-field",
                            span { "MTU" }
                            input {
                                r#type: "number",
                                min: "0",
                                placeholder: "auto",
                                value: "{face_mtu.read()}",
                                "aria-label": "Face MTU",
                                oninput: move |event| face_mtu.set(event.value())
                            }
                        }
                        button {
                            class: "tool-button primary",
                            disabled: !can_create,
                            "aria-label": "Create face",
                            onclick: move |_| {
                                let uri = face_uri.read().trim().to_string();
                                let command = FaceCreateCommand {
                                    uri: uri.clone(),
                                    mtu: parse_opt_u64(&face_mtu.read()),
                                };
                                let typed = TypedMutationCommand::FaceCreate(command.clone());
                                let pending = MutationRecord::for_command(
                                    typed.clone(),
                                    create_preflight.clone(),
                                ).running();
                                mutation_records.write().insert(0, pending);
                                mutation_session.write().record(typed);
                                let profile = profile_for_create.clone();
                                let mut records = mutation_records;
                                spawn(async move {
                                    let record = execute_face_create(profile, trust, command).await;
                                    replace_running_mutation(&mut records, record);
                                });
                            },
                            "create"
                        }
                    }
                    div { class: "mutation-card",
                        div { class: "tool-card-title", "Destroy face" }
                        PreflightPanel { preflight: destroy_preflight.clone() }
                        label { class: "tool-field span-2",
                            span { "Face ID" }
                            input {
                                r#type: "number",
                                min: "0",
                                value: "{destroy_face_id.read()}",
                                "aria-label": "Destroy face ID",
                                oninput: move |event| destroy_face_id.set(event.value())
                            }
                        }
                        label { class: "tool-check span-2",
                            input {
                                r#type: "checkbox",
                                checked: *confirm_destroy.read(),
                                onchange: move |event| confirm_destroy.set(event.checked())
                            }
                            span { "confirm destroy" }
                        }
                        button {
                            class: "tool-button primary",
                            disabled: !can_destroy,
                            "aria-label": "Destroy face",
                            onclick: move |_| {
                                let Some(face_id) = parse_opt_u64(&destroy_face_id.read()) else {
                                    return;
                                };
                                let command = FaceDestroyCommand { face_id };
                                let typed = TypedMutationCommand::FaceDestroy(command.clone());
                                let pending = MutationRecord::for_command(
                                    typed.clone(),
                                    destroy_preflight.clone(),
                                ).running();
                                mutation_records.write().insert(0, pending);
                                mutation_session.write().record(typed);
                                confirm_destroy.set(false);
                                let profile = profile_for_destroy.clone();
                                let mut records = mutation_records;
                                spawn(async move {
                                    let record = execute_face_destroy(profile, trust, command).await;
                                    replace_running_mutation(&mut records, record);
                                });
                            },
                            "destroy"
                        }
                    }
                }
            }
            Panel { title: "Routes".to_string(),
                div { class: "panel-toolbar",
                    span { class: "mono", "prefix search: /" }
                    StatusChip { label: format!("{} rows", route_rows.len()), tone: "neutral".to_string() }
                }
                div { class: "dense-table engine-table route-table",
                    div { class: "table-head", span { "Prefix" } span { "Source" } span { "Face" } span { "Cost" } span { "Flags" } }
                    for route in route_rows.clone() {
                        div { class: "table-row",
                            span { "{route.prefix}" }
                            span { "{route.source}" }
                            span { "{route.face_id}" }
                            span { "{route.cost}" }
                            span { "{route.flags}" }
                        }
                    }
                }
            }
            Panel { title: "Route Mutations".to_string(),
                div { class: "mutation-grid",
                    div { class: "mutation-card",
                        div { class: "tool-card-title", "Add route" }
                        PreflightPanel { preflight: route_add_preflight.clone() }
                        label { class: "tool-field span-2",
                            span { "Prefix" }
                            input {
                                r#type: "text",
                                value: "{route_prefix.read()}",
                                "aria-label": "Route prefix",
                                oninput: move |event| route_prefix.set(event.value())
                            }
                        }
                        label { class: "tool-field",
                            span { "Face" }
                            select {
                                "aria-label": "Route face ID",
                                onchange: move |event| route_face_id.set(event.value()),
                                for face in face_options.clone() {
                                    option {
                                        value: "{face.id}",
                                        selected: *route_face_id.read() == face.id.to_string(),
                                        "{face.id} · {face.uri}"
                                    }
                                }
                            }
                        }
                        label { class: "tool-field",
                            span { "Cost" }
                            input {
                                r#type: "number",
                                min: "0",
                                value: "{route_cost.read()}",
                                "aria-label": "Route cost",
                                oninput: move |event| route_cost.set(event.value())
                            }
                        }
                        button {
                            class: "tool-button primary",
                            disabled: !can_add_route,
                            "aria-label": "Add route",
                            onclick: move |_| {
                                let Some(face_id) = parse_opt_u64(&route_face_id.read()) else {
                                    return;
                                };
                                let prefix = route_prefix.read().trim().to_string();
                                let command = RouteAddCommand {
                                    prefix: prefix.clone(),
                                    face_id: Some(face_id),
                                    cost: parse_u64_or(&route_cost.read(), 10),
                                };
                                let typed = TypedMutationCommand::RouteAdd(command.clone());
                                let pending = MutationRecord::for_command(
                                    typed.clone(),
                                    route_add_preflight.clone(),
                                ).running();
                                mutation_records.write().insert(0, pending);
                                mutation_session.write().record(typed);
                                let profile = profile_for_route_add.clone();
                                let mut records = mutation_records;
                                spawn(async move {
                                    let record = execute_route_add(profile, trust, command).await;
                                    replace_running_mutation(&mut records, record);
                                });
                            },
                            "add route"
                        }
                    }
                    div { class: "mutation-card",
                        div { class: "tool-card-title", "Remove route" }
                        PreflightPanel { preflight: route_remove_preflight.clone() }
                        label { class: "tool-field span-2",
                            span { "Prefix" }
                            input {
                                r#type: "text",
                                value: "{remove_route_prefix.read()}",
                                "aria-label": "Remove route prefix",
                                oninput: move |event| remove_route_prefix.set(event.value())
                            }
                        }
                        label { class: "tool-field",
                            span { "Face" }
                            input {
                                r#type: "number",
                                min: "0",
                                value: "{remove_route_face_id.read()}",
                                "aria-label": "Remove route face ID",
                                oninput: move |event| remove_route_face_id.set(event.value())
                            }
                        }
                        label { class: "tool-check",
                            input {
                                r#type: "checkbox",
                                checked: *confirm_route_remove.read(),
                                onchange: move |event| confirm_route_remove.set(event.checked())
                            }
                            span { "confirm remove" }
                        }
                        button {
                            class: "tool-button primary",
                            disabled: !can_remove_route,
                            "aria-label": "Remove route",
                            onclick: move |_| {
                                let Some(face_id) = parse_opt_u64(&remove_route_face_id.read()) else {
                                    return;
                                };
                                let prefix = remove_route_prefix.read().trim().to_string();
                                let command = RouteRemoveCommand {
                                    prefix: prefix.clone(),
                                    face_id: Some(face_id),
                                };
                                let typed = TypedMutationCommand::RouteRemove(command.clone());
                                let pending = MutationRecord::for_command(
                                    typed.clone(),
                                    route_remove_preflight.clone(),
                                ).running();
                                mutation_records.write().insert(0, pending);
                                mutation_session.write().record(typed);
                                confirm_route_remove.set(false);
                                let profile = profile_for_route_remove.clone();
                                let mut records = mutation_records;
                                spawn(async move {
                                    let record = execute_route_remove(profile, trust, command).await;
                                    replace_running_mutation(&mut records, record);
                                });
                            },
                            "remove"
                        }
                    }
                }
            }
            Panel { title: "Strategy Mutations".to_string(),
                div { class: "mutation-grid",
                    div { class: "mutation-card",
                        div { class: "tool-card-title", "Set strategy" }
                        PreflightPanel { preflight: strategy_set_preflight.clone() }
                        label { class: "tool-field span-2",
                            span { "Prefix" }
                            input {
                                r#type: "text",
                                value: "{strategy_prefix.read()}",
                                "aria-label": "Strategy prefix",
                                oninput: move |event| strategy_prefix.set(event.value())
                            }
                        }
                        label { class: "tool-field span-2",
                            span { "Strategy" }
                            select {
                                "aria-label": "Strategy name",
                                onchange: move |event| strategy_name.set(event.value()),
                                for (name, label) in KNOWN_STRATEGIES {
                                    option {
                                        value: "{name}",
                                        selected: *strategy_name.read() == name,
                                        "{label}"
                                    }
                                }
                                option {
                                    value: "__custom__",
                                    selected: *strategy_name.read() == "__custom__",
                                    "Custom"
                                }
                            }
                        }
                        if *strategy_name.read() == "__custom__" {
                            label { class: "tool-field span-2",
                                span { "Custom strategy" }
                                input {
                                    r#type: "text",
                                    placeholder: "/ndn/strategy/name/v1",
                                    value: "{custom_strategy_name.read()}",
                                    "aria-label": "Custom strategy name",
                                    oninput: move |event| custom_strategy_name.set(event.value())
                                }
                            }
                        }
                        button {
                            class: "tool-button primary",
                            disabled: !can_set_strategy,
                            "aria-label": "Set strategy",
                            onclick: move |_| {
                                let prefix = strategy_prefix.read().trim().to_string();
                                let strategy = if strategy_name.read().as_str() == "__custom__" {
                                    custom_strategy_name.read().trim().to_string()
                                } else {
                                    strategy_name.read().clone()
                                };
                                if prefix.is_empty() || strategy.is_empty() {
                                    return;
                                }
                                let command = StrategySetCommand {
                                    prefix: prefix.clone(),
                                    strategy: strategy.clone(),
                                };
                                let typed = TypedMutationCommand::StrategySet(command.clone());
                                let pending = MutationRecord::for_command(
                                    typed.clone(),
                                    strategy_set_preflight.clone(),
                                ).running();
                                mutation_records.write().insert(0, pending);
                                mutation_session.write().record(typed);
                                let profile = profile_for_strategy_set.clone();
                                let mut records = mutation_records;
                                spawn(async move {
                                    let record = execute_strategy_set(profile, trust, command).await;
                                    replace_running_mutation(&mut records, record);
                                });
                            },
                            "set strategy"
                        }
                    }
                    div { class: "mutation-card",
                        div { class: "tool-card-title", "Unset strategy" }
                        PreflightPanel { preflight: strategy_unset_preflight.clone() }
                        label { class: "tool-field span-2",
                            span { "Prefix" }
                            input {
                                r#type: "text",
                                value: "{unset_strategy_prefix.read()}",
                                "aria-label": "Unset strategy prefix",
                                oninput: move |event| unset_strategy_prefix.set(event.value())
                            }
                        }
                        label { class: "tool-check span-2",
                            input {
                                r#type: "checkbox",
                                checked: *confirm_strategy_unset.read(),
                                onchange: move |event| confirm_strategy_unset.set(event.checked())
                            }
                            span { "confirm unset" }
                        }
                        button {
                            class: "tool-button primary",
                            disabled: !can_unset_strategy,
                            "aria-label": "Unset strategy",
                            onclick: move |_| {
                                let prefix = unset_strategy_prefix.read().trim().to_string();
                                if prefix.is_empty() {
                                    return;
                                }
                                let command = StrategyUnsetCommand { prefix: prefix.clone() };
                                let typed = TypedMutationCommand::StrategyUnset(command.clone());
                                let pending = MutationRecord::for_command(
                                    typed.clone(),
                                    strategy_unset_preflight.clone(),
                                ).running();
                                mutation_records.write().insert(0, pending);
                                mutation_session.write().record(typed);
                                confirm_strategy_unset.set(false);
                                let profile = profile_for_strategy_unset.clone();
                                let mut records = mutation_records;
                                spawn(async move {
                                    let record = execute_strategy_unset(profile, trust, command).await;
                                    replace_running_mutation(&mut records, record);
                                });
                            },
                            "unset"
                        }
                    }
                }
            }
            Panel { title: "Mutation History".to_string(),
                MutationHistory { records: mutation_rows }
            }
            Panel { title: "Router Lifecycle".to_string(),
                div { class: "mutation-grid",
                    div { class: "mutation-card",
                        div { class: "tool-card-title", "Reconnect" }
                        PreflightPanel { preflight: reconnect_preflight.clone() }
                        button {
                            class: "tool-button primary",
                            disabled: !can_reconnect,
                            "aria-label": "Reconnect forwarder",
                            onclick: move |_| {
                                let command = ReconnectForwarderCommand {
                                    endpoint: profile_for_reconnect.endpoint.clone(),
                                };
                                let typed = TypedMutationCommand::ReconnectForwarder(command.clone());
                                let pending = MutationRecord::for_command(
                                    typed,
                                    reconnect_preflight.clone(),
                                ).running();
                                mutation_records.write().insert(0, pending);
                                let profile = profile_for_reconnect.clone();
                                let mut records = mutation_records;
                                spawn(async move {
                                    let record = execute_reconnect_forwarder(profile, trust, command).await;
                                    replace_running_mutation(&mut records, record);
                                });
                            },
                            "reconnect"
                        }
                    }
                    div { class: "mutation-card",
                        div { class: "tool-card-title", "Shutdown" }
                        PreflightPanel { preflight: shutdown_preflight.clone() }
                        label { class: "tool-field span-2",
                            span { "Reason" }
                            input {
                                r#type: "text",
                                value: "{shutdown_reason.read()}",
                                "aria-label": "Forwarder shutdown reason",
                                oninput: move |event| shutdown_reason.set(event.value())
                            }
                        }
                        label { class: "tool-check span-2",
                            input {
                                r#type: "checkbox",
                                checked: *confirm_shutdown.read(),
                                onchange: move |event| confirm_shutdown.set(event.checked())
                            }
                            span { "confirm shutdown" }
                        }
                        button {
                            class: "tool-button primary",
                            disabled: !can_shutdown,
                            "aria-label": "Shutdown forwarder",
                            onclick: move |_| {
                                let command = ShutdownForwarderCommand {
                                    reason: shutdown_reason.read().trim().to_string(),
                                };
                                let typed = TypedMutationCommand::ShutdownForwarder(command.clone());
                                let pending = MutationRecord::for_command(
                                    typed,
                                    shutdown_preflight.clone(),
                                ).running();
                                mutation_records.write().insert(0, pending);
                                confirm_shutdown.set(false);
                                let profile = profile_for_shutdown.clone();
                                let mut records = mutation_records;
                                spawn(async move {
                                    let record = execute_shutdown_forwarder(profile, trust, command).await;
                                    replace_running_mutation(&mut records, record);
                                });
                            },
                            "shutdown"
                        }
                    }
                }
            }
            Panel { title: "Typed Session".to_string(),
                div { class: "mutation-history",
                    div { class: "mini-section-title", "Replayable operations" }
                    if session_lines.is_empty() {
                        div { class: "mini-empty", "No replayable mutations" }
                    }
                    for (index, line) in session_lines.iter().enumerate() {
                        div { class: "mutation-row",
                            strong { "{index + 1}" }
                            span { class: "mono", "{line}" }
                            StatusChip { label: "typed".to_string(), tone: "info".to_string() }
                            span { class: "result-cell", "replayable" }
                        }
                    }
                    div { class: "modal-action-row",
                        button {
                            class: "tool-button",
                            disabled: session_lines.is_empty(),
                            "aria-label": "Replay typed mutation session",
                            onclick: move |_| {
                                let commands = mutation_session.read().commands.clone();
                                if commands.is_empty() {
                                    return;
                                }
                                let profile = profile_for_replay.clone();
                                let mut records = mutation_records;
                                spawn(async move {
                                    for command in commands {
                                        let preflight = preflight_mutation(&profile, trust, command.operation());
                                        let pending = MutationRecord::for_command(command.clone(), preflight).running();
                                        records.write().insert(0, pending);
                                        let record = execute_typed_mutation(profile.clone(), trust, command).await;
                                        replace_running_mutation(&mut records, record);
                                    }
                                });
                            },
                            "replay typed session"
                        }
                    }
                }
            }
            Panel { title: "CS, PIT, Traffic".to_string(),
                if let Some(store_pit) = store_pit {
                    div { class: "metrics-grid",
                        Metric { label: "CS Capacity".to_string(), value: compact_count(store_pit.cs_capacity) }
                        Metric { label: "CS Entries".to_string(), value: compact_count(store_pit.cs_entries) }
                        Metric { label: "CS Hit".to_string(), value: format!("{}%", store_pit.cs_hit_rate_pct) }
                        Metric { label: "PIT".to_string(), value: compact_count(store_pit.pit_entries) }
                        Metric { label: "PIT Sat".to_string(), value: format!("{}%", store_pit.pit_satisfied_rate_pct) }
                    }
                } else {
                    EmptyState {
                        title: "CS/PIT summary unavailable".to_string(),
                        detail: "This target did not provide a compatible content-store or PIT summary dataset.".to_string()
                    }
                }
                if let Some(traffic) = traffic {
                    div { class: "detail-table",
                        div { class: "kv", span { "Interests in/out" } strong { "{traffic.interest_in_rate}/s / {traffic.interest_out_rate}/s" } }
                        div { class: "kv", span { "Data in/out" } strong { "{traffic.data_in_rate}/s / {traffic.data_out_rate}/s" } }
                        div { class: "kv", span { "Satisfaction" } strong { "{traffic.satisfaction_rate_pct}%" } }
                    }
                }
            }
            Panel { title: "CS Mutations".to_string(),
                div { class: "mutation-grid",
                    div { class: "mutation-card",
                        div { class: "tool-card-title", "Set capacity" }
                        PreflightPanel { preflight: cs_capacity_preflight.clone() }
                        label { class: "tool-field span-2",
                            span { "Capacity bytes" }
                            input {
                                r#type: "number",
                                min: "0",
                                value: "{cs_capacity.read()}",
                                "aria-label": "Content store capacity bytes",
                                oninput: move |event| cs_capacity.set(event.value())
                            }
                        }
                        button {
                            class: "tool-button primary",
                            disabled: !can_set_cs_capacity,
                            "aria-label": "Set content store capacity",
                            onclick: move |_| {
                                let Some(capacity_bytes) = parse_opt_u64(&cs_capacity.read()) else {
                                    return;
                                };
                                let command = CsCapacityCommand { capacity_bytes };
                                let typed = TypedMutationCommand::CsCapacity(command.clone());
                                let pending = MutationRecord::for_command(
                                    typed.clone(),
                                    cs_capacity_preflight.clone(),
                                ).running();
                                mutation_records.write().insert(0, pending);
                                mutation_session.write().record(typed);
                                let profile = profile_for_cs_capacity.clone();
                                let mut records = mutation_records;
                                spawn(async move {
                                    let record = execute_cs_set_capacity(profile, trust, command).await;
                                    replace_running_mutation(&mut records, record);
                                });
                            },
                            "set capacity"
                        }
                    }
                    div { class: "mutation-card",
                        div { class: "tool-card-title", "Erase entries" }
                        PreflightPanel { preflight: cs_erase_preflight.clone() }
                        label { class: "tool-field span-2",
                            span { "Prefix" }
                            input {
                                r#type: "text",
                                value: "{cs_erase_prefix.read()}",
                                "aria-label": "Content store erase prefix",
                                oninput: move |event| cs_erase_prefix.set(event.value())
                            }
                        }
                        label { class: "tool-field",
                            span { "Limit" }
                            input {
                                r#type: "number",
                                min: "0",
                                placeholder: "all",
                                value: "{cs_erase_count.read()}",
                                "aria-label": "Content store erase limit",
                                oninput: move |event| cs_erase_count.set(event.value())
                            }
                        }
                        label { class: "tool-check",
                            input {
                                r#type: "checkbox",
                                checked: *confirm_cs_erase.read(),
                                onchange: move |event| confirm_cs_erase.set(event.checked())
                            }
                            span { "confirm erase" }
                        }
                        button {
                            class: "tool-button primary",
                            disabled: !can_erase_cs,
                            "aria-label": "Erase content store entries",
                            onclick: move |_| {
                                let prefix = cs_erase_prefix.read().trim().to_string();
                                if prefix.is_empty() {
                                    return;
                                }
                                let count = parse_opt_u64(&cs_erase_count.read());
                                let command = CsEraseCommand {
                                    prefix: prefix.clone(),
                                    count,
                                };
                                let typed = TypedMutationCommand::CsErase(command.clone());
                                let pending = MutationRecord::for_command(
                                    typed.clone(),
                                    cs_erase_preflight.clone(),
                                ).running();
                                mutation_records.write().insert(0, pending);
                                mutation_session.write().record(typed);
                                confirm_cs_erase.set(false);
                                let profile = profile_for_cs_erase.clone();
                                let mut records = mutation_records;
                                spawn(async move {
                                    let record = execute_cs_erase(profile, trust, command).await;
                                    replace_running_mutation(&mut records, record);
                                });
                            },
                            "erase"
                        }
                    }
                }
            }
            Panel { title: "Fleet And Discovery".to_string(),
                div { class: "panel-toolbar",
                    StatusChip {
                        label: network_model.discovery.status.label().to_string(),
                        tone: tone_for_feature(network_model.discovery.status).to_string(),
                    }
                    StatusChip {
                        label: if network_model.discovery.writable { "mutable".to_string() } else { "read-only".to_string() },
                        tone: if network_model.discovery.writable { "good".to_string() } else { "amber".to_string() },
                    }
                }
                div { class: "detail-table",
                    div { class: "kv", span { "Protocol" } strong { "{network_model.discovery.protocol}" } }
                    div { class: "kv", span { "Prefix" } strong { "{network_model.discovery.service_prefix}" } }
                }
                div { class: "dense-table fleet-table",
                    div { class: "table-head", span { "Peer" } span { "Face" } span { "Reach" } span { "Trust" } span { "Action" } }
                    for neighbor in network_model.neighbors.clone() {
                        div { class: "table-row",
                            span { "{neighbor.peer}" }
                            span { "{neighbor.face_uri}" }
                            span { "{neighbor.reachability}" }
                            span { "{neighbor.trust.label()}" }
                            span { "{neighbor.enrollment_action}" }
                        }
                    }
                }
            }
            Panel { title: "Routing And Radio".to_string(),
                div { class: "dense-table routing-table",
                    div { class: "table-head", span { "Protocol" } span { "State" } span { "Routes" } span { "Mode" } }
                    for row in network_model.routing.clone() {
                        div { class: "table-row",
                            span { "{row.protocol}" }
                            span {
                                StatusChip { label: row.status.label().to_string(), tone: tone_for_feature(row.status).to_string() }
                            }
                            span { "{row.routes}" }
                            span { if row.writable { "mutable" } else { "read-only" } }
                        }
                    }
                }
                div { class: "dense-table radio-table",
                    div { class: "table-head", span { "Transport" } span { "Face" } span { "State" } span { "Support" } }
                    for radio in network_model.radios.clone() {
                        div { class: "table-row",
                            span { "{radio.transport}" }
                            span { "{radio.face}" }
                            span { "{radio.state}" }
                            span {
                                StatusChip { label: radio.support.label().to_string(), tone: tone_for_feature(radio.support).to_string() }
                            }
                        }
                    }
                }
            }
            Panel { title: "Topology".to_string(),
                div { class: "dense-table topology-table",
                    div { class: "table-head", span { "Source" } span { "Target" } span { "Via" } span { "Evidence" } }
                    for edge in network_model.topology.clone() {
                        div { class: "table-row",
                            span { "{edge.source}" }
                            span { "{edge.target}" }
                            span { "{edge.via}" }
                            span { "{edge.evidence}" }
                        }
                    }
                }
            }
            Panel { title: "Advanced Extensions".to_string(),
                div { class: "dense-table extension-table",
                    div { class: "table-head", span { "Surface" } span { "Capability" } span { "Docs" } }
                    for surface in extension_registry.surfaces.clone() {
                        div { class: "table-row",
                            span { "{surface.title}" }
                            span {
                                StatusChip { label: surface.capability.label().to_string(), tone: tone_for_feature(surface.capability).to_string() }
                            }
                            span { "{surface.docs}" }
                        }
                    }
                }
                div { class: "metrics-grid",
                    for coding in extension_registry.coding.clone() {
                        div { class: "metric-card",
                            span { "Coding {coding.role}" }
                            strong { "{coding.prefix}" }
                            span { "{coding.generation}" }
                        }
                    }
                    for limit in extension_registry.rate_limits.clone() {
                        div { class: "metric-card",
                            span { "Rate {limit.scope}" }
                            strong { "{limit.limit}" }
                            span { "{limit.state.label()}" }
                        }
                    }
                    for compute in extension_registry.compute.clone() {
                        div { class: "metric-card",
                            span { "Compute" }
                            strong { "{compute.service}" }
                            span { "{compute.diagnostics}" }
                        }
                    }
                }
            }
            Panel { title: "Strategy And Detail".to_string(),
                div { class: "dense-table strategy-table",
                    div { class: "table-head", span { "Prefix" } span { "Strategy" } span { "Mode" } }
                    for strategy in summary.strategies.clone() {
                        div { class: "table-row",
                            span { "{strategy.prefix}" }
                            span { "{strategy.strategy}" }
                            span { if strategy.inherited { "inherited" } else { "explicit" } }
                        }
                    }
                }
                EngineDetailPanel { detail: summary.detail.clone() }
            }
        }
    }
}

#[component]
fn EngineSources(sources: Vec<crate::engine::DatasetSource>) -> Element {
    rsx! {
        div { class: "source-grid", "aria-label": "Engine dataset source states",
            for source in sources {
                div { class: "source-row",
                    span { class: "mono", "{source.name}" }
                    StatusChip { label: source.state.label(), tone: source.state.tone().to_string() }
                }
            }
        }
    }
}

#[component]
fn EngineDetailPanel(detail: EngineDetail) -> Element {
    rsx! {
        div { class: "engine-detail", role: "region", "aria-label": "Engine selected detail",
            match detail {
                EngineDetail::Face(face) => rsx! {
                    div { class: "detail-table",
                        div { class: "kv", span { "Selected face" } strong { "{face.id}" } }
                        div { class: "kv", span { "URI" } strong { "{face.uri}" } }
                        div { class: "kv", span { "Persistency" } strong { "{face.persistency}" } }
                        div { class: "kv", span { "Bytes Rx/Tx" } strong { "{compact_count(face.rx_bytes)} / {compact_count(face.tx_bytes)}" } }
                    }
                },
                EngineDetail::Route(route) => rsx! {
                    div { class: "detail-table",
                        div { class: "kv", span { "Selected route" } strong { "{route.prefix}" } }
                        div { class: "kv", span { "Face" } strong { "{route.face_id}" } }
                        div { class: "kv", span { "Cost" } strong { "{route.cost}" } }
                        div { class: "kv", span { "Flags" } strong { "{route.flags}" } }
                    }
                },
                EngineDetail::Strategy(strategy) => rsx! {
                    div { class: "detail-table",
                        div { class: "kv", span { "Selected prefix" } strong { "{strategy.prefix}" } }
                        div { class: "kv", span { "Strategy" } strong { "{strategy.strategy}" } }
                    }
                },
                EngineDetail::Empty => rsx! {
                    EmptyState {
                        title: "No detail selected".to_string(),
                        detail: "Attach to a compatible forwarder to inspect face, route, and strategy detail.".to_string()
                    }
                },
            }
        }
    }
}

#[component]
fn CapabilityRows(caps: crate::core::CapabilitySet) -> Element {
    rsx! {
        div { class: "detail-table",
            CapabilityRow { label: "NFD-compatible mgmt".to_string(), state: caps.nfd_basic }
            CapabilityRow { label: "ndn-rs native extensions".to_string(), state: caps.ndnrs_native }
            CapabilityRow { label: "Observability spans".to_string(), state: caps.observability }
            CapabilityRow { label: "TrustContext".to_string(), state: caps.trust_context }
            CapabilityRow { label: "Tools".to_string(), state: caps.tools }
        }
    }
}

#[component]
fn CapabilityRow(label: String, state: FeatureState) -> Element {
    rsx! {
        div { class: "kv",
            span { "{label}" }
            StatusChip { label: state.label().to_string(), tone: tone_for_feature(state).to_string() }
        }
    }
}

fn parse_u64_or(value: &str, fallback: u64) -> u64 {
    value.trim().parse().unwrap_or(fallback)
}

fn parse_opt_u64(value: &str) -> Option<u64> {
    value.trim().parse().ok()
}

fn parse_usize_or(value: &str, fallback: usize) -> usize {
    value.trim().parse().unwrap_or(fallback)
}

fn parse_opt_usize(value: &str) -> Option<usize> {
    value.trim().parse().ok()
}

fn parse_opt_f64(value: &str) -> Option<f64> {
    value.trim().parse().ok()
}

fn optional_text(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn tool_run_key(index: usize, run: &ToolRun) -> String {
    format!(
        "{index}:{}:{}:{}",
        run.kind.label(),
        run.target_name,
        run.result.as_deref().unwrap_or(run.status.label())
    )
}

fn tool_run_matches_filter(run: &ToolRun, filter: &str) -> bool {
    let needle = filter.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return true;
    }
    let result = run.result.as_deref().unwrap_or_default();
    run.kind.label().contains(&needle)
        || run.target_name.to_ascii_lowercase().contains(&needle)
        || run.status.label().contains(&needle)
        || result.to_ascii_lowercase().contains(&needle)
        || run.samples.iter().any(|sample| {
            sample.label.to_ascii_lowercase().contains(&needle)
                || sample.value.to_ascii_lowercase().contains(&needle)
        })
}

fn selected_tool_export(records: &[(usize, ToolRun)], selected_keys: &[String]) -> String {
    records
        .iter()
        .filter(|(index, run)| {
            let key = tool_run_key(*index, run);
            selected_keys.iter().any(|selected| selected == &key)
        })
        .map(|(index, run)| format!("run: {}\n{}", tool_run_key(*index, run), run.export_text()))
        .collect::<Vec<_>>()
        .join("\n---\n")
}

fn iperf_spark_points(run: &ToolRun) -> Vec<u8> {
    let raw: Vec<f64> = run
        .samples
        .iter()
        .filter(|sample| sample.label == "goodput")
        .filter_map(|sample| parse_bps_label(&sample.value))
        .collect();
    let Some(max) = raw.iter().copied().reduce(f64::max) else {
        return Vec::new();
    };
    if max <= 0.0 {
        return vec![1; raw.len()];
    }
    raw.iter()
        .map(|value| ((*value / max) * 24.0).round().clamp(2.0, 24.0) as u8)
        .collect()
}

fn parse_bps_label(value: &str) -> Option<f64> {
    let mut parts = value.split_whitespace();
    let amount: f64 = parts.next()?.parse().ok()?;
    let unit = parts.next().unwrap_or("bps").to_ascii_lowercase();
    let factor = if unit.starts_with("gbps") {
        1_000_000_000.0
    } else if unit.starts_with("mbps") {
        1_000_000.0
    } else if unit.starts_with("kbps") {
        1_000.0
    } else {
        1.0
    };
    Some(amount * factor)
}

fn tool_kind_icon(kind: ToolKind) -> &'static str {
    match kind {
        ToolKind::Ping => "PG",
        ToolKind::Iperf => "IP",
        ToolKind::Peek => "PK",
        ToolKind::Put => "PT",
        ToolKind::TraceLookup => "TR",
        ToolKind::RouteDiagnostic => "RT",
        ToolKind::FaceDiagnostic => "FC",
        ToolKind::Export => "EX",
    }
}

fn tool_status_tone(status: ToolStatus) -> &'static str {
    match status {
        ToolStatus::Complete => "good",
        ToolStatus::Failed => "bad",
        ToolStatus::Cancelled => "amber",
        ToolStatus::Pending | ToolStatus::Running | ToolStatus::Streaming => "neutral",
    }
}

#[component]
fn ToolsView(
    profile: crate::core::ForwarderProfile,
    engine: EngineSummary,
    observe: ObserveSummary,
    initial_runs: Vec<ToolRun>,
) -> Element {
    let mut runs = use_signal(move || initial_runs.clone());
    let mut active_tool = use_signal(|| ToolPanelKind::Ping);
    let mut tool_filter = use_signal(String::new);
    let mut selected_run_keys = use_signal(Vec::<String>::new);
    let mut expanded_run_keys = use_signal(Vec::<String>::new);
    let mut details_collapsed = use_signal(|| false);
    let mut ping_target = use_signal(|| "/demo/router".to_string());
    let mut ping_count = use_signal(|| "4".to_string());
    let mut ping_interval_ms = use_signal(|| "200".to_string());
    let mut ping_lifetime_ms = use_signal(|| "1000".to_string());
    let mut peek_target = use_signal(|| "/demo/data".to_string());
    let mut peek_lifetime_ms = use_signal(|| "800".to_string());
    let mut peek_pipeline = use_signal(String::new);
    let mut peek_save_to = use_signal(String::new);
    let mut peek_can_be_prefix = use_signal(|| false);
    let mut peek_hex = use_signal(|| false);
    let mut peek_meta_only = use_signal(|| false);
    let mut put_target = use_signal(|| "/demo/object".to_string());
    let mut put_payload = use_signal(|| "dashboard-next put payload\n".to_string());
    let mut put_chunk_size = use_signal(|| "0".to_string());
    let mut put_freshness_ms = use_signal(|| "1000".to_string());
    let mut put_timeout_secs = use_signal(|| "1".to_string());
    let mut put_sign = use_signal(|| false);
    let mut put_hmac = use_signal(|| false);
    let mut iperf_target = use_signal(|| "/demo/iperf".to_string());
    let mut iperf_duration_secs = use_signal(|| "1".to_string());
    let mut iperf_initial_window = use_signal(|| "4".to_string());
    let mut iperf_lifetime_ms = use_signal(|| "800".to_string());
    let mut iperf_interval_ms = use_signal(|| "500".to_string());
    let mut iperf_cc = use_signal(|| "aimd".to_string());
    let mut iperf_min_window = use_signal(|| "1".to_string());
    let mut iperf_max_window = use_signal(|| "128".to_string());
    let mut iperf_ai = use_signal(|| "1.0".to_string());
    let mut iperf_md = use_signal(|| "0.5".to_string());
    let mut iperf_cubic_c = use_signal(|| "0.4".to_string());
    let mut iperf_reverse = use_signal(|| false);
    let mut iperf_node_prefix = use_signal(String::new);
    let mut iperf_sign_mode = use_signal(|| "digest_sha256".to_string());
    let mut diagnostic_query = use_signal(|| "/demo/router".to_string());
    let run_rows = runs.read().clone();
    let indexed_runs = run_rows
        .iter()
        .cloned()
        .enumerate()
        .collect::<Vec<(usize, ToolRun)>>();
    let filter_text = tool_filter.read().clone();
    let visible_runs = indexed_runs
        .iter()
        .filter(|(_, run)| tool_run_matches_filter(run, &filter_text))
        .cloned()
        .collect::<Vec<_>>();
    let expanded_keys = expanded_run_keys.read().clone();
    let detail_runs = indexed_runs
        .iter()
        .filter(|(index, run)| {
            let key = tool_run_key(*index, run);
            expanded_keys.iter().any(|expanded| expanded == &key)
        })
        .cloned()
        .collect::<Vec<_>>();
    let failed_runs = indexed_runs
        .iter()
        .filter(|(_, run)| run.status == ToolStatus::Failed)
        .cloned()
        .collect::<Vec<_>>();
    let selected_keys = selected_run_keys.read().clone();
    let selected_count = selected_keys.len();
    let server_controls = tool_server_controls(&profile);
    let profile_for_ping = profile.clone();
    let profile_for_peek = profile.clone();
    let profile_for_put = profile.clone();
    let profile_for_iperf = profile.clone();
    let observe_for_trace = observe.clone();
    let engine_for_route = engine.clone();
    let engine_for_face = engine.clone();

    rsx! {
        div {
            class: if *details_collapsed.read() { "view-grid tools-grid tools-grid-collapsed" } else { "view-grid tools-grid" },
            "data-testid": "workspace-tools",
            Panel { title: "Network test workbench".to_string(),
                div { class: "tool-tabbar", role: "tablist", "aria-label": "Tool workflows",
                    for tool in ToolPanelKind::ALL {
                        button {
                            class: if *active_tool.read() == tool { "tool-tab active" } else { "tool-tab" },
                            role: "tab",
                            "aria-selected": "{*active_tool.read() == tool}",
                            onclick: move |_| active_tool.set(tool),
                            "{tool.label()}"
                        }
                    }
                }
                div { class: "tool-form-grid",
                    div { class: if *active_tool.read() == ToolPanelKind::Ping { "tool-card active-tool-card" } else { "tool-card tool-card-hidden" },
                        div { class: "tool-card-title", "Ping" }
                        label { class: "tool-field span-2",
                            span { "Prefix" }
                            input { r#type: "text", value: "{ping_target.read()}", oninput: move |event| ping_target.set(event.value()) }
                        }
                        label { class: "tool-field",
                            span { "Count" }
                            input { r#type: "number", min: "0", value: "{ping_count.read()}", oninput: move |event| ping_count.set(event.value()) }
                        }
                        label { class: "tool-field",
                            span { "Interval ms" }
                            input { r#type: "number", min: "1", value: "{ping_interval_ms.read()}", oninput: move |event| ping_interval_ms.set(event.value()) }
                        }
                        label { class: "tool-field",
                            span { "Lifetime ms" }
                            input { r#type: "number", min: "1", value: "{ping_lifetime_ms.read()}", oninput: move |event| ping_lifetime_ms.set(event.value()) }
                        }
                        button {
                            class: "tool-button primary span-2",
                            "aria-label": "Run ping workflow",
                            onclick: move |_| {
                                let profile = profile_for_ping.clone();
                                let target_name = ping_target.read().clone();
                                let config = PingWorkflowConfig {
                                    target_name: target_name.clone(),
                                    count: parse_u64_or(&ping_count.read(), 4),
                                    interval_ms: parse_u64_or(&ping_interval_ms.read(), 200),
                                    lifetime_ms: parse_u64_or(&ping_lifetime_ms.read(), 1000),
                                };
                                runs.write().insert(0, ToolRun::new(ToolKind::Ping, target_name.clone()).start());
                                let mut runs = runs;
                                spawn(async move {
                                    let run = run_ping_workflow(profile, config).await;
                                    let mut rows = runs.write();
                                    if let Some(slot) = rows.iter_mut().find(|row| {
                                        row.kind == ToolKind::Ping
                                            && row.target_name == target_name
                                            && row.status == ToolStatus::Running
                                    }) {
                                        *slot = run;
                                    } else {
                                        rows.insert(0, run);
                                    }
                                });
                            },
                            "run ping"
                        }
                    }
                    div { class: if *active_tool.read() == ToolPanelKind::Peek { "tool-card active-tool-card" } else { "tool-card tool-card-hidden" },
                        div { class: "tool-card-title", "Peek" }
                        label { class: "tool-field span-2",
                            span { "Name" }
                            input { r#type: "text", value: "{peek_target.read()}", oninput: move |event| peek_target.set(event.value()) }
                        }
                        label { class: "tool-field",
                            span { "Lifetime ms" }
                            input { r#type: "number", min: "1", value: "{peek_lifetime_ms.read()}", oninput: move |event| peek_lifetime_ms.set(event.value()) }
                        }
                        label { class: "tool-field",
                            span { "Pipeline" }
                            input { r#type: "number", min: "1", placeholder: "single", value: "{peek_pipeline.read()}", oninput: move |event| peek_pipeline.set(event.value()) }
                        }
                        label { class: "tool-field span-2",
                            span { "Save to" }
                            input { r#type: "text", placeholder: "optional local path", value: "{peek_save_to.read()}", oninput: move |event| peek_save_to.set(event.value()) }
                        }
                        label { class: "tool-check",
                            input { r#type: "checkbox", checked: *peek_can_be_prefix.read(), onchange: move |event| peek_can_be_prefix.set(event.checked()) }
                            span { "can be prefix" }
                        }
                        label { class: "tool-check",
                            input { r#type: "checkbox", checked: *peek_hex.read(), onchange: move |event| peek_hex.set(event.checked()) }
                            span { "hex" }
                        }
                        label { class: "tool-check",
                            input { r#type: "checkbox", checked: *peek_meta_only.read(), onchange: move |event| peek_meta_only.set(event.checked()) }
                            span { "metadata only" }
                        }
                        button {
                            class: "tool-button primary span-2",
                            "aria-label": "Run peek workflow",
                            onclick: move |_| {
                                let profile = profile_for_peek.clone();
                                let target_name = peek_target.read().clone();
                                let config = PeekWorkflowConfig {
                                    target_name: target_name.clone(),
                                    lifetime_ms: parse_u64_or(&peek_lifetime_ms.read(), 800),
                                    pipeline: parse_opt_usize(&peek_pipeline.read()),
                                    save_to: optional_text(&peek_save_to.read()),
                                    hex: *peek_hex.read(),
                                    meta_only: *peek_meta_only.read(),
                                    can_be_prefix: *peek_can_be_prefix.read(),
                                };
                                runs.write().insert(0, ToolRun::new(ToolKind::Peek, target_name.clone()).start());
                                let mut runs = runs;
                                spawn(async move {
                                    let run = run_peek_workflow(profile, config).await;
                                    let mut rows = runs.write();
                                    if let Some(slot) = rows.iter_mut().find(|row| {
                                        row.kind == ToolKind::Peek
                                            && row.target_name == target_name
                                            && row.status == ToolStatus::Running
                                    }) {
                                        *slot = run;
                                    } else {
                                        rows.insert(0, run);
                                    }
                                });
                            },
                            "peek"
                        }
                    }
                    div { class: if *active_tool.read() == ToolPanelKind::Put { "tool-card active-tool-card" } else { "tool-card tool-card-hidden" },
                        div { class: "tool-card-title", "Put" }
                        label { class: "tool-field span-2",
                            span { "Name" }
                            input { r#type: "text", value: "{put_target.read()}", oninput: move |event| put_target.set(event.value()) }
                        }
                        label { class: "tool-field span-2",
                            span { "Payload" }
                            textarea { value: "{put_payload.read()}", oninput: move |event| put_payload.set(event.value()) }
                        }
                        label { class: "tool-field",
                            span { "Chunk bytes" }
                            input { r#type: "number", min: "0", value: "{put_chunk_size.read()}", oninput: move |event| put_chunk_size.set(event.value()) }
                        }
                        label { class: "tool-field",
                            span { "Freshness ms" }
                            input { r#type: "number", min: "0", value: "{put_freshness_ms.read()}", oninput: move |event| put_freshness_ms.set(event.value()) }
                        }
                        label { class: "tool-field",
                            span { "Serve seconds" }
                            input { r#type: "number", min: "0", value: "{put_timeout_secs.read()}", oninput: move |event| put_timeout_secs.set(event.value()) }
                        }
                        label { class: "tool-check",
                            input { r#type: "checkbox", checked: *put_sign.read(), onchange: move |event| put_sign.set(event.checked()) }
                            span { "sign" }
                        }
                        label { class: "tool-check",
                            input { r#type: "checkbox", checked: *put_hmac.read(), onchange: move |event| put_hmac.set(event.checked()) }
                            span { "HMAC" }
                        }
                        button {
                            class: "tool-button primary span-2",
                            "aria-label": "Run put workflow",
                            onclick: move |_| {
                                let profile = profile_for_put.clone();
                                let target_name = put_target.read().clone();
                                let config = PutWorkflowConfig {
                                    target_name: target_name.clone(),
                                    payload: put_payload.read().as_bytes().to_vec(),
                                    chunk_size: parse_usize_or(&put_chunk_size.read(), 0),
                                    freshness_ms: parse_u64_or(&put_freshness_ms.read(), 1000),
                                    timeout_secs: parse_u64_or(&put_timeout_secs.read(), 1),
                                    sign: *put_sign.read(),
                                    hmac: *put_hmac.read(),
                                };
                                runs.write().insert(0, ToolRun::new(ToolKind::Put, target_name.clone()).start());
                                let mut runs = runs;
                                spawn(async move {
                                    let run = run_put_workflow(profile, config).await;
                                    let mut rows = runs.write();
                                    if let Some(slot) = rows.iter_mut().find(|row| {
                                        row.kind == ToolKind::Put
                                            && row.target_name == target_name
                                            && row.status == ToolStatus::Running
                                    }) {
                                        *slot = run;
                                    } else {
                                        rows.insert(0, run);
                                    }
                                });
                            },
                            "put"
                        }
                    }
                    div { class: if *active_tool.read() == ToolPanelKind::Iperf { "tool-card active-tool-card iperf-card" } else { "tool-card tool-card-hidden iperf-card" },
                        div { class: "tool-card-title", "Iperf" }
                        label { class: "tool-field span-2",
                            span { "Prefix" }
                            input { r#type: "text", value: "{iperf_target.read()}", oninput: move |event| iperf_target.set(event.value()) }
                        }
                        label { class: "tool-field",
                            span { "Duration s" }
                            input { r#type: "number", min: "1", value: "{iperf_duration_secs.read()}", oninput: move |event| iperf_duration_secs.set(event.value()) }
                        }
                        label { class: "tool-field",
                            span { "Window" }
                            input { r#type: "number", min: "1", value: "{iperf_initial_window.read()}", oninput: move |event| iperf_initial_window.set(event.value()) }
                        }
                        label { class: "tool-field",
                            span { "Lifetime ms" }
                            input { r#type: "number", min: "1", value: "{iperf_lifetime_ms.read()}", oninput: move |event| iperf_lifetime_ms.set(event.value()) }
                        }
                        label { class: "tool-field",
                            span { "Report ms" }
                            input { r#type: "number", min: "1", value: "{iperf_interval_ms.read()}", oninput: move |event| iperf_interval_ms.set(event.value()) }
                        }
                        label { class: "tool-field",
                            span { "CC" }
                            select { onchange: move |event| iperf_cc.set(event.value()),
                                option { value: "aimd", selected: *iperf_cc.read() == "aimd", "AIMD" }
                                option { value: "cubic", selected: *iperf_cc.read() == "cubic", "CUBIC" }
                                option { value: "fixed", selected: *iperf_cc.read() == "fixed", "Fixed" }
                            }
                        }
                        label { class: "tool-field",
                            span { "Auth" }
                            select { onchange: move |event| iperf_sign_mode.set(event.value()),
                                option { value: "none", selected: *iperf_sign_mode.read() == "none", "None" }
                                option { value: "digest_sha256", selected: *iperf_sign_mode.read() == "digest_sha256", "Digest SHA-256" }
                                option { value: "blake3", selected: *iperf_sign_mode.read() == "blake3", "BLAKE3" }
                                option { value: "hmac", selected: *iperf_sign_mode.read() == "hmac", "HMAC" }
                                option { value: "ed25519", selected: *iperf_sign_mode.read() == "ed25519", "Ed25519" }
                            }
                        }
                        if *iperf_cc.read() != "fixed" {
                            label { class: "tool-field",
                                span { "Min window" }
                                input { r#type: "number", step: "0.1", value: "{iperf_min_window.read()}", oninput: move |event| iperf_min_window.set(event.value()) }
                            }
                            label { class: "tool-field",
                                span { "Max window" }
                                input { r#type: "number", step: "0.1", value: "{iperf_max_window.read()}", oninput: move |event| iperf_max_window.set(event.value()) }
                            }
                        }
                        if *iperf_cc.read() == "aimd" {
                            label { class: "tool-field",
                                span { "AI" }
                                input { r#type: "number", step: "0.1", value: "{iperf_ai.read()}", oninput: move |event| iperf_ai.set(event.value()) }
                            }
                            label { class: "tool-field",
                                span { "MD" }
                                input { r#type: "number", step: "0.1", value: "{iperf_md.read()}", oninput: move |event| iperf_md.set(event.value()) }
                            }
                        }
                        if *iperf_cc.read() == "cubic" {
                            label { class: "tool-field",
                                span { "CUBIC C" }
                                input { r#type: "number", step: "0.01", value: "{iperf_cubic_c.read()}", oninput: move |event| iperf_cubic_c.set(event.value()) }
                            }
                        }
                        label { class: "tool-check",
                            input { r#type: "checkbox", checked: *iperf_reverse.read(), onchange: move |event| iperf_reverse.set(event.checked()) }
                            span { "reverse" }
                        }
                        if *iperf_reverse.read() {
                            label { class: "tool-field span-2",
                                span { "Node prefix" }
                                input { r#type: "text", placeholder: "required for reverse mode", value: "{iperf_node_prefix.read()}", oninput: move |event| iperf_node_prefix.set(event.value()) }
                            }
                        }
                        button {
                            class: "tool-button primary span-2",
                            "aria-label": "Run iperf workflow",
                            onclick: move |_| {
                                let profile = profile_for_iperf.clone();
                                let cc = iperf_cc.read().clone();
                                let target_name = iperf_target.read().clone();
                                let reverse = *iperf_reverse.read();
                                let config = IperfWorkflowConfig {
                                    target_name: target_name.clone(),
                                    duration_secs: parse_u64_or(&iperf_duration_secs.read(), 1),
                                    initial_window: parse_usize_or(&iperf_initial_window.read(), 4),
                                    cc: cc.clone(),
                                    min_window: (cc != "fixed")
                                        .then(|| parse_opt_f64(&iperf_min_window.read()))
                                        .flatten(),
                                    max_window: (cc != "fixed")
                                        .then(|| parse_opt_f64(&iperf_max_window.read()))
                                        .flatten(),
                                    ai: (cc == "aimd")
                                        .then(|| parse_opt_f64(&iperf_ai.read()))
                                        .flatten(),
                                    md: (cc == "aimd")
                                        .then(|| parse_opt_f64(&iperf_md.read()))
                                        .flatten(),
                                    cubic_c: (cc == "cubic")
                                        .then(|| parse_opt_f64(&iperf_cubic_c.read()))
                                        .flatten(),
                                    lifetime_ms: parse_u64_or(&iperf_lifetime_ms.read(), 800),
                                    interval_ms: parse_u64_or(&iperf_interval_ms.read(), 500),
                                    reverse,
                                    node_prefix: reverse
                                        .then(|| optional_text(&iperf_node_prefix.read()))
                                        .flatten(),
                                    sign_mode: iperf_sign_mode.read().clone(),
                                };
                                runs.write().insert(0, ToolRun::new(ToolKind::Iperf, target_name.clone()).start());
                                let mut runs = runs;
                                spawn(async move {
                                    let run = run_iperf_workflow(profile, config).await;
                                    let mut rows = runs.write();
                                    if let Some(slot) = rows.iter_mut().find(|row| {
                                        row.kind == ToolKind::Iperf
                                            && row.target_name == target_name
                                            && row.status == ToolStatus::Running
                                    }) {
                                        *slot = run;
                                    } else {
                                        rows.insert(0, run);
                                    }
                                });
                            },
                            "iperf"
                        }
                    }
                    div { class: if *active_tool.read() == ToolPanelKind::Diagnostics { "tool-card active-tool-card diagnostics-card" } else { "tool-card tool-card-hidden diagnostics-card" },
                        div { class: "tool-card-title", "Diagnostics" }
                        label { class: "tool-field span-2",
                            span { "Trace, route, or face query" }
                            input {
                                r#type: "text",
                                value: "{diagnostic_query.read()}",
                                "aria-label": "Diagnostic query",
                                oninput: move |event| diagnostic_query.set(event.value())
                            }
                        }
                        button {
                            class: "tool-button",
                            "aria-label": "Lookup trace",
                            onclick: move |_| {
                                let run = run_trace_lookup(&observe_for_trace, &diagnostic_query.read());
                                runs.write().insert(0, run);
                            },
                            "trace"
                        }
                        button {
                            class: "tool-button",
                            "aria-label": "Run route diagnostic",
                            onclick: move |_| {
                                let run = run_route_diagnostic(&engine_for_route, &diagnostic_query.read());
                                runs.write().insert(0, run);
                            },
                            "route"
                        }
                        button {
                            class: "tool-button",
                            "aria-label": "Run face diagnostic",
                            onclick: move |_| {
                                let run = run_face_diagnostic(&engine_for_face, &diagnostic_query.read());
                                runs.write().insert(0, run);
                            },
                            "face"
                        }
                    }
                }
                div { class: "server-controls", "aria-label": "Tool server controls",
                    for control in server_controls {
                        div { class: "server-control",
                            strong { "{control.target_name}" }
                            span { "{control.result.clone().unwrap_or_else(|| \"pending\".into())}" }
                        }
                    }
                }
                if !failed_runs.is_empty() {
                    div { class: "tool-error-banner", role: "alert",
                        strong { "{failed_runs.len()} tool error(s)" }
                        for (_, failed) in failed_runs.iter().take(3) {
                            span { "{failed.kind.label()} {failed.target_name}: {failed.result.clone().unwrap_or_else(|| \"failed\".into())}" }
                        }
                    }
                }
                div { class: "results-toolbar",
                    input {
                        r#type: "search",
                        value: "{tool_filter.read()}",
                        placeholder: "filter runs, targets, status, result",
                        "aria-label": "Filter tool results",
                        oninput: move |event| tool_filter.set(event.value())
                    }
                    button {
                        class: "tool-button",
                        disabled: selected_count == 0,
                        "aria-label": "Download selected tool results",
                        onclick: move |_| {
                            let body = selected_tool_export(&indexed_runs, &selected_run_keys.read());
                            let download_result =
                                platform::download_text("ndn-dashboard-tool-results.txt", &body);
                            let download_message = download_result.unwrap_or_else(|err| {
                                format!("download failed: {err}")
                            });
                            let run = ToolRun::new(ToolKind::Export, "selected tool results")
                                .start()
                                .push_sample("selected", selected_run_keys.read().len().to_string())
                                .push_sample("download", download_message)
                                .push_sample("download text", body)
                                .complete("selected result export prepared");
                            runs.write().insert(0, run);
                        },
                        "download selected ({selected_count})"
                    }
                    button {
                        class: "tool-button",
                        disabled: selected_count == 0,
                        "aria-label": "Clear selected tool results",
                        onclick: move |_| selected_run_keys.write().clear(),
                        "clear"
                    }
                }
                div { class: "dense-table tools-table",
                    div { class: "table-head", span { "Sel" } span { "Tool" } span { "Target" } span { "Status" } span { "Result" } span { "Open" } }
                    for (index, run) in visible_runs.clone() {
                        {
                            let row_key = tool_run_key(index, &run);
                            let row_key_for_select = row_key.clone();
                            let row_key_for_open = row_key.clone();
                            let selected = selected_keys.iter().any(|key| key == &row_key);
                            let expanded = expanded_keys.iter().any(|key| key == &row_key);
                            rsx! {
                        div { class: if run.status == ToolStatus::Failed { "table-row error-row" } else { "table-row" },
                            span {
                                input {
                                    r#type: "checkbox",
                                    checked: selected,
                                    "aria-label": "Select {run.kind.label()} result",
                                    onchange: move |event| {
                                        let mut keys = selected_run_keys.write();
                                        if event.checked() {
                                            if !keys.iter().any(|key| key == &row_key_for_select) {
                                                keys.push(row_key_for_select.clone());
                                            }
                                        } else {
                                            keys.retain(|key| key != &row_key_for_select);
                                        }
                                    }
                                }
                            }
                            span { "{run.kind.label()}" }
                            span { "{run.target_name}" }
                            span { class: "status-cell",
                                StatusChip {
                                    label: run.status.label().to_string(),
                                    tone: tool_status_tone(run.status).to_string()
                                }
                            }
                            span { class: "result-cell", "{run.result.clone().unwrap_or_else(|| \"streaming\".into())}" }
                            span {
                                button {
                                    class: "tool-button inline-button action-button",
                                    "aria-expanded": "{expanded}",
                                    onclick: move |_| {
                                        let mut keys = expanded_run_keys.write();
                                        if keys.iter().any(|key| key == &row_key_for_open) {
                                            keys.retain(|key| key != &row_key_for_open);
                                        } else {
                                            keys.push(row_key_for_open.clone());
                                        }
                                    },
                                    if expanded { "hide" } else { "open" }
                                }
                            }
                        }
                    }
                        }
                    }
                }
            }
            if *details_collapsed.read() {
                section { class: "panel tool-detail-rail", "aria-label": "Collapsed tool details",
                    button {
                        class: "rail-toggle",
                        "aria-label": "Expand tool detail panel",
                        onclick: move |_| details_collapsed.set(false),
                        span { class: "hamburger-icon", "aria-hidden": "true",
                            span {}
                            span {}
                            span {}
                        }
                    }
                    for (index, run) in detail_runs.clone() {
                        {
                            let key = tool_run_key(index, &run);
                            let icon = tool_kind_icon(run.kind);
                            rsx! {
                                button {
                                    class: if run.status == ToolStatus::Failed { "rail-icon error" } else { "rail-icon" },
                                    title: "{run.kind.label()} {run.target_name}",
                                    "aria-label": "Expand {run.kind.label()} details for {run.target_name}",
                                    onclick: move |_| {
                                        expanded_run_keys.write().retain(|expanded| expanded == &key);
                                        details_collapsed.set(false);
                                    },
                                    "{icon}"
                                }
                            }
                        }
                    }
                }
            } else {
            section { class: "panel tool-detail-panel",
                div { class: "panel-title-row",
                    h2 { class: "panel-title", "Latest samples" }
                    button {
                        class: "tool-button inline-button action-button",
                        "aria-label": "Collapse tool detail panel",
                        onclick: move |_| details_collapsed.set(true),
                        span { class: "panel-toggle-icon", "aria-hidden": "true",
                            span {}
                            span {}
                        }
                    }
                }
                div { class: "sample-list",
                    if detail_runs.is_empty() {
                        EmptyState {
                            title: "No run opened".to_string(),
                            detail: "Open a result row to inspect samples, trace pivots, exports, and iperf sparklines.".to_string()
                        }
                    }
                    for (index, run) in detail_runs {
                        ToolSampleCard {
                            run_key: tool_run_key(index, &run),
                            run,
                            runs,
                            expanded_run_keys,
                            diagnostic_query
                        }
                    }
                }
            }
            }
        }
    }
}

#[component]
fn ToolSampleCard(
    run_key: String,
    run: ToolRun,
    mut runs: Signal<Vec<ToolRun>>,
    mut expanded_run_keys: Signal<Vec<String>>,
    mut diagnostic_query: Signal<String>,
) -> Element {
    let trace_refs = run.trace_refs.clone();
    let export_run = run.clone();
    let cancel_run = run.clone();
    let retry_target = run.target_name.clone();
    let spark_points = iperf_spark_points(&run);

    rsx! {
        div { class: "sample-card",
            div { class: "sample-card-head",
                div { class: "row-title", "{run.kind.label()} -> {run.target_name}" }
                button {
                    class: "tool-button inline-button action-button",
                    "aria-label": "Collapse tool run details",
                    onclick: move |_| expanded_run_keys.write().retain(|key| key != &run_key),
                    span { class: "panel-toggle-icon", "aria-hidden": "true",
                        span {}
                        span {}
                    }
                }
            }
            if run.status == ToolStatus::Failed {
                div { class: "tool-error-detail", role: "alert",
                    strong { "Error" }
                    span { "{run.result.clone().unwrap_or_else(|| \"tool failed\".into())}" }
                }
            }
            if run.kind == ToolKind::Iperf && !spark_points.is_empty() {
                div { class: "sparkline", "aria-label": "Iperf throughput sparkline",
                    for point in spark_points {
                        span { style: "height: {point}px;" }
                    }
                }
            }
            for sample in run.samples.clone() {
                div { class: "kv", span { "{sample.label}" } strong { "{sample.value}" } }
            }
            if !trace_refs.is_empty() {
                div { class: "trace-ref-row",
                    for trace_ref in trace_refs {
                        span { class: "chip neutral", "Observe: {trace_ref}" }
                    }
                }
            }
            div { class: "tool-actions compact-actions",
                button {
                    class: "tool-button",
                    "aria-label": "Export tool run summary",
                    onclick: move |_| {
                        let mut next = export_run.clone();
                        next.add_sample("export", next.export_text());
                        runs.write().insert(0, next);
                    },
                    "export"
                }
                button {
                    class: "tool-button",
                    "aria-label": "Cancel tool run",
                    onclick: move |_| {
                        if let Some(row) = runs.write().iter_mut().find(|row| {
                            row.kind == cancel_run.kind
                                && row.target_name == cancel_run.target_name
                                && row.status == cancel_run.status
                        }) {
                            *row = cancel_run.clone().cancel();
                        } else {
                            runs.write().insert(0, cancel_run.clone().cancel());
                        }
                    },
                    "cancel"
                }
                button {
                    class: "tool-button",
                    "aria-label": "Retry tool run target",
                    onclick: move |_| {
                        diagnostic_query.set(retry_target.clone());
                    },
                    "retry"
                }
            }
        }
    }
}

#[component]
fn SettingsView(
    state: DashboardState,
    services: PlatformServices,
    preferences: DashboardPreferences,
    last_probe: Option<ProbeTranscript>,
    last_probe_at_unix_s: Option<u64>,
    last_attach_error: Option<String>,
    start_notice: Option<ForwarderActionNotice>,
    on_select_target: EventHandler<String>,
    on_probe_selected: EventHandler<()>,
    on_mock_ndnrs: EventHandler<()>,
    on_mock_browser: EventHandler<()>,
    on_mock_nfd: EventHandler<()>,
    on_mock_yanfd: EventHandler<()>,
    on_probe_default: EventHandler<()>,
    on_start_forwarder: EventHandler<String>,
    on_stop_forwarder: EventHandler<()>,
) -> Element {
    let selected_id = preferences.selected_target_id.clone();
    let selected_available = preferences
        .selected_target()
        .map(|target| target.platform_status(state.platform).is_available())
        .unwrap_or(false);
    let rows = capability_matrix(&state.profile);
    let mut selected_preset = use_signal(|| ConfigPreset::LocalLab);
    let mut router_draft = use_signal(|| RouterConfigDraft::preset(ConfigPreset::LocalLab));
    let mut dashboard_draft =
        use_signal(|| DashboardSettingsDraft::for_platform(services.kind, preferences.density));
    let current_router = RouterConfigDraft::preset(match state.platform {
        PlatformKind::Browser => ConfigPreset::BrowserSandbox,
        PlatformKind::Desktop => ConfigPreset::LocalLab,
    });
    let router_diff = router_draft.read().diff_from(&current_router);
    let router_toml = router_draft
        .read()
        .render_toml()
        .unwrap_or_else(|error| format!("# render error: {error}"));
    let dashboard_json = dashboard_draft
        .read()
        .export_json()
        .unwrap_or_else(|error| format!("{{\"error\":\"{error}\"}}"));
    let router_toml_for_export = router_toml.clone();
    let router_toml_for_start = router_toml.clone();
    let config_write_tone = if RouterConfigDraft::can_write(state.platform) {
        "good"
    } else {
        "amber"
    };
    let config_write_label = if RouterConfigDraft::can_write(state.platform) {
        "write path"
    } else {
        "read-only"
    };

    rsx! {
        div { class: "view-grid settings-grid", "data-testid": "workspace-settings",
            Panel { title: "Attach targets".to_string(),
                div { class: "tool-actions",
                    button {
                        class: "tool-button primary",
                        disabled: !selected_available,
                        "aria-label": "Probe selected attach target",
                        onclick: move |_| on_probe_selected.call(()),
                        "probe selected"
                    }
                    button { class: "tool-button", "aria-label": "Probe default attach target", onclick: move |_| on_probe_default.call(()), "probe default" }
                    button { class: "tool-button", "aria-label": "Switch to ndn-rs fixture profile", onclick: move |_| on_mock_ndnrs.call(()), "fixture ndn-rs" }
                    button { class: "tool-button", "aria-label": "Switch to browser engine fixture profile", onclick: move |_| on_mock_browser.call(()), "fixture browser" }
                    button { class: "tool-button", "aria-label": "Switch to NFD fixture profile", onclick: move |_| on_mock_nfd.call(()), "fixture NFD" }
                    button { class: "tool-button", "aria-label": "Switch to YaNFD fixture profile", onclick: move |_| on_mock_yanfd.call(()), "fixture YaNFD" }
                }
                if let Some(message) = last_attach_error {
                    div { class: "inline-alert", role: "alert", "{message}" }
                }
                div { class: "target-list", role: "list", "aria-label": "Saved attach targets",
                    for target in preferences.saved_targets.clone() {
                        AttachTargetRow {
                            target: target.clone(),
                            platform: state.platform,
                            selected: selected_id.as_ref() == Some(&target.id),
                            on_select: move |id| on_select_target.call(id),
                        }
                    }
                }
            }
            Panel { title: "Capability matrix".to_string(),
                div { class: "capability-matrix", role: "table", "aria-label": "Forwarder capability matrix",
                    div { class: "matrix-head", role: "row",
                        span { role: "columnheader", "Feature" }
                        span { role: "columnheader", "State" }
                        span { role: "columnheader", "Probe" }
                        span { role: "columnheader", "Meaning" }
                    }
                    for row in rows {
                        div { class: "matrix-row", role: "row",
                            span { role: "cell", "{row.feature}" }
                            span { role: "cell",
                                StatusChip { label: row.state.label().to_string(), tone: tone_for_feature(row.state).to_string() }
                            }
                            span { role: "cell", class: "mono",
                                "{row.source_probe}"
                                span { class: "probe-outcome", " {probe_outcome_label(last_probe.as_ref(), row.source_probe)}" }
                                span { class: "probe-time", " {probe_time_label(last_probe_at_unix_s)}" }
                            }
                            span { role: "cell", "{row.explanation}" }
                        }
                    }
                }
                div { class: "detail-table",
                    div { class: "kv", span { "Current profile" } strong { "{state.profile.display_name()}" } }
                    div { class: "kv", span { "Attach mode" } strong { "{state.profile.attach_mode.label()}" } }
                    div { class: "kv", span { "Kind" } strong { "{state.profile.kind.label()}" } }
                }
            }
            Panel { title: "Deployment platform".to_string(),
                div { class: "detail-table",
                    div { class: "kv", span { "Runtime" } strong { "{platform_kind_label(services.kind)}" } }
                    div { class: "kv", span { "Persistence" } strong { "{services.persistence}" } }
                    div { class: "kv", span { "Preference key" } strong { "{preference_key(services.kind)}" } }
                    div { class: "kv", span { "Density preference" } strong { "{density_storage_label(preferences.density)}" } }
                    div { class: "kv", span { "Clipboard" } strong { "{services.clipboard}" } }
                    div { class: "kv", span { "Notifications" } strong { "{services.notifications}" } }
                }
            }
            Panel { title: "Dashboard settings".to_string(),
                div { class: "mutation-grid",
                    label { class: "tool-field",
                        span { "Node prefix" }
                        input {
                            r#type: "text",
                            value: "{dashboard_draft.read().node_prefix}",
                            "aria-label": "Dashboard node prefix",
                            oninput: move |event| dashboard_draft.write().node_prefix = event.value()
                        }
                    }
                    label { class: "tool-field",
                        span { "Result limit" }
                        input {
                            r#type: "number",
                            min: "10",
                            value: "{dashboard_draft.read().max_tool_results}",
                            "aria-label": "Maximum tool results",
                            oninput: move |event| {
                                if let Ok(value) = event.value().parse::<usize>() {
                                    dashboard_draft.write().max_tool_results = value;
                                }
                            }
                        }
                    }
                    label { class: "tool-check",
                        input {
                            r#type: "checkbox",
                            checked: dashboard_draft.read().auto_start_ping_server,
                            onchange: move |event| dashboard_draft.write().auto_start_ping_server = event.checked()
                        }
                        span { "ping server" }
                    }
                    label { class: "tool-check",
                        input {
                            r#type: "checkbox",
                            checked: dashboard_draft.read().auto_start_iperf_server,
                            onchange: move |event| dashboard_draft.write().auto_start_iperf_server = event.checked()
                        }
                        span { "iperf server" }
                    }
                }
                textarea {
                    class: "code-preview",
                    readonly: true,
                    "aria-label": "Dashboard settings export",
                    value: "{dashboard_json}"
                }
            }
            Panel { title: "Router config".to_string(),
                div { class: "panel-toolbar",
                    StatusChip { label: config_write_label.to_string(), tone: config_write_tone.to_string() }
                    for preset in ConfigPreset::ALL {
                        button {
                            class: if *selected_preset.read() == preset { "tool-button primary" } else { "tool-button" },
                            "aria-label": "Apply {preset.label()} config preset",
                            onclick: move |_| {
                                selected_preset.set(preset);
                                router_draft.set(RouterConfigDraft::preset(preset));
                            },
                            "{preset.label()}"
                        }
                    }
                }
                div { class: "mutation-grid",
                    label { class: "tool-field",
                        span { "Router name" }
                        input {
                            r#type: "text",
                            value: "{router_draft.read().router_name}",
                            "aria-label": "Router name",
                            oninput: move |event| router_draft.write().router_name = event.value()
                        }
                    }
                    label { class: "tool-field",
                        span { "Mgmt socket" }
                        input {
                            r#type: "text",
                            value: "{router_draft.read().management_socket}",
                            "aria-label": "Management socket",
                            oninput: move |event| router_draft.write().management_socket = event.value()
                        }
                    }
                    label { class: "tool-field",
                        span { "CS bytes" }
                        input {
                            r#type: "number",
                            min: "0",
                            value: "{router_draft.read().cs_capacity_bytes}",
                            "aria-label": "Content store capacity in bytes",
                            oninput: move |event| {
                                if let Ok(value) = event.value().parse::<u64>() {
                                    router_draft.write().cs_capacity_bytes = value;
                                }
                            }
                        }
                    }
                    label { class: "tool-field",
                        span { "Discovery prefix" }
                        input {
                            r#type: "text",
                            value: "{router_draft.read().discovery.service_prefix}",
                            "aria-label": "Discovery service prefix",
                            oninput: move |event| router_draft.write().discovery.service_prefix = event.value()
                        }
                    }
                    label { class: "tool-field",
                        span { "Face URI" }
                        input {
                            r#type: "text",
                            value: "{router_draft.read().faces.first().map(|face| face.uri.clone()).unwrap_or_default()}",
                            "aria-label": "Startup face URI",
                            oninput: move |event| {
                                let mut draft = router_draft.write();
                                if let Some(face) = draft.faces.first_mut() {
                                    face.uri = event.value();
                                }
                            }
                        }
                    }
                    label { class: "tool-field",
                        span { "Route prefix" }
                        input {
                            r#type: "text",
                            value: "{router_draft.read().routes.first().map(|route| route.prefix.clone()).unwrap_or_default()}",
                            "aria-label": "Startup route prefix",
                            oninput: move |event| {
                                let mut draft = router_draft.write();
                                if let Some(route) = draft.routes.first_mut() {
                                    route.prefix = event.value();
                                }
                            }
                        }
                    }
                    label { class: "tool-field",
                        span { "Trust context" }
                        input {
                            r#type: "text",
                            value: "{router_draft.read().security.trust_context}",
                            "aria-label": "Startup trust context",
                            oninput: move |event| router_draft.write().security.trust_context = event.value()
                        }
                    }
                    label { class: "tool-check",
                        input {
                            r#type: "checkbox",
                            checked: router_draft.read().discovery.enabled,
                            onchange: move |event| router_draft.write().discovery.enabled = event.checked()
                        }
                        span { "discovery" }
                    }
                    label { class: "tool-check",
                        input {
                            r#type: "checkbox",
                            checked: router_draft.read().security.require_signed_commands,
                            onchange: move |event| router_draft.write().security.require_signed_commands = event.checked()
                        }
                        span { "signed mgmt" }
                    }
                }
                div { class: "dense-table config-diff-table",
                    div { class: "table-head", span { "Field" } span { "Current" } span { "Draft" } span { "Apply" } }
                    if router_diff.is_empty() {
                        div { class: "table-row", span { "clean" } span { "-" } span { "-" } span { "live" } }
                    }
                    for diff in router_diff.clone() {
                        div { class: "table-row",
                            span { "{diff.field}" }
                            span { "{diff.current}" }
                            span { "{diff.draft}" }
                            span {
                                if diff.restart_required { "restart" } else { "runtime" }
                            }
                        }
                    }
                }
                textarea {
                    class: "code-preview tall",
                    readonly: true,
                    "aria-label": "Router TOML preview",
                    value: "{router_toml}"
                }
                div { class: "modal-action-row",
                    button {
                        class: "tool-button",
                        disabled: !RouterConfigDraft::can_write(state.platform),
                        "aria-label": "Export router config TOML",
                        onclick: move |_| {
                            let _ = platform::download_text("ndn-dashboard-next-router.toml", &router_toml_for_export);
                        },
                        "export TOML"
                    }
                    button {
                        class: "tool-button primary",
                        disabled: !RouterConfigDraft::can_write(state.platform),
                        "aria-label": "Start local ndn-fwd with this router config",
                        onclick: move |_| on_start_forwarder.call(router_toml_for_start.clone()),
                        "start local ndn-fwd"
                    }
                    button {
                        class: "tool-button",
                        disabled: !RouterConfigDraft::can_write(state.platform),
                        "aria-label": "Stop dashboard-started local ndn-fwd",
                        onclick: move |_| on_stop_forwarder.call(()),
                        "stop local"
                    }
                }
                if let Some(notice) = start_notice {
                    div { class: "operator-message {notice.tone}", role: "status",
                        strong { "{notice.title}" }
                        span { "{notice.detail}" }
                    }
                }
            }
            Panel { title: "Recent targets".to_string(),
                div { class: "target-list compact", role: "list", "aria-label": "Recent attach targets",
                    for target in preferences.recent_targets {
                        div { class: "recent-target", role: "listitem",
                            div {
                                div { class: "row-title", "{target.label}" }
                                div { class: "row-sub mono", "{target.endpoint}" }
                            }
                            StatusChip { label: target.mode.label().to_string(), tone: "neutral".to_string() }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn AttachTargetRow(
    target: SavedAttachTarget,
    platform: PlatformKind,
    selected: bool,
    on_select: EventHandler<String>,
) -> Element {
    let status = target.platform_status(platform);
    let active_class = if selected { " active" } else { "" };
    let availability_tone = if status.is_available() {
        "good"
    } else {
        "amber"
    };
    let target_id = target.id.clone();

    rsx! {
        div { class: "target-row{active_class}", role: "listitem",
            button {
                class: "target-main",
                "aria-label": "Select {target.label} attach target",
                "aria-pressed": "{selected}",
                onclick: move |_| on_select.call(target_id.clone()),
                div { class: "row-title", "{target.label}" }
                div { class: "target-meta",
                    span { class: "mono", "{target.endpoint}" }
                    span { "{target.mode.label()}" }
                }
            }
            div { class: "target-badges",
                if target.pinned {
                    StatusChip { label: "saved".to_string(), tone: "neutral".to_string() }
                }
                StatusChip { label: status.label().to_string(), tone: availability_tone.to_string() }
            }
        }
    }
}

#[component]
fn Panel(title: String, children: Element) -> Element {
    rsx! {
        section { class: "panel",
            h2 { class: "panel-title", "{title}" }
            {children}
        }
    }
}

#[component]
fn Metric(label: String, value: String) -> Element {
    rsx! {
        div { class: "metric-card",
            span { "{label}" }
            strong { "{value}" }
        }
    }
}

#[component]
fn EmptyState(title: String, detail: String) -> Element {
    rsx! {
        div { class: "empty-state",
            strong { "{title}" }
            span { "{detail}" }
        }
    }
}

fn tone_for_feature(state: FeatureState) -> &'static str {
    match state {
        FeatureState::Enabled => "good",
        FeatureState::ReadOnly | FeatureState::Degraded => "amber",
        FeatureState::Disabled => "neutral",
        FeatureState::Unsupported => "muted",
    }
}

fn tone_for_trust(posture: crate::core::TrustPosture) -> &'static str {
    match posture {
        crate::core::TrustPosture::Valid => "good",
        crate::core::TrustPosture::Unsupported => "muted",
        crate::core::TrustPosture::None
        | crate::core::TrustPosture::Ephemeral
        | crate::core::TrustPosture::Weakened => "amber",
        crate::core::TrustPosture::Expired | crate::core::TrustPosture::Error => "bad",
    }
}

fn tone_for_preflight(status: PreflightStatus) -> &'static str {
    match status {
        PreflightStatus::Ready => "good",
        PreflightStatus::NeedsConfirmation => "amber",
        PreflightStatus::Blocked => "bad",
    }
}

fn tone_for_mutation_status(status: MutationStatus) -> &'static str {
    match status {
        MutationStatus::Complete => "good",
        MutationStatus::Failed | MutationStatus::Blocked => "bad",
        MutationStatus::Retryable => "amber",
        MutationStatus::Pending | MutationStatus::Running => "neutral",
    }
}

fn tone_for_observe(posture: crate::core::ObservePosture) -> &'static str {
    match posture {
        crate::core::ObservePosture::Enabled => "good",
        crate::core::ObservePosture::Degraded | crate::core::ObservePosture::Disabled => "amber",
        crate::core::ObservePosture::Unsupported => "muted",
        crate::core::ObservePosture::Error => "bad",
    }
}

fn platform_kind_label(kind: PlatformKind) -> &'static str {
    match kind {
        PlatformKind::Browser => "browser/PWA",
        PlatformKind::Desktop => "desktop",
    }
}

fn probe_outcome_label(transcript: Option<&ProbeTranscript>, source: &str) -> &'static str {
    let Some(transcript) = transcript else {
        return "";
    };
    let Some(outcome) = transcript
        .steps
        .iter()
        .find(|step| step.endpoint.name() == source)
        .map(|step| step.outcome)
    else {
        return "not probed";
    };

    match outcome {
        ProbeOutcome::Ok => "ok",
        ProbeOutcome::NotFound => "404",
        ProbeOutcome::Unauthorized => "auth",
        ProbeOutcome::Timeout => "timeout",
        ProbeOutcome::InvalidResponse => "invalid",
        ProbeOutcome::TransportUnavailable => "offline",
    }
}

fn probe_time_label(probed_at_unix_s: Option<u64>) -> String {
    probed_at_unix_s
        .map(|ts| format!("at {ts}"))
        .unwrap_or_else(|| "not run".into())
}

const STYLE: &str = r#"
:root {
  color-scheme: dark;
  --bg: #161616;
  --bg-rail: #161616;
  --surface: #262626;
  --surface-2: #393939;
  --surface-3: #525252;
  --surface-raised: #303030;
  --field: #393939;
  --border: #393939;
  --border-strong: #6f6f6f;
  --text: #f4f4f4;
  --muted: #c6c6c6;
  --faint: #8d8d8d;
  --accent: #0f62fe;
  --accent-2: #33b1ff;
  --blue: #78a9ff;
  --green: #42be65;
  --amber: #f1c21b;
  --red: #fa4d56;
  --focus: #ffffff;
  --shadow: rgba(0, 0, 0, .38);
  --nav-w: 256px;
  --nav-collapsed-w: 64px;
}

* { box-sizing: border-box; }
html, body, #main { margin: 0; min-height: 100%; background: var(--bg); color: var(--text); }
body { font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
button, input, select, textarea { font: inherit; }
button { cursor: pointer; }
button:disabled { cursor: not-allowed; opacity: .62; }
button:focus-visible, a:focus-visible, [tabindex]:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: 2px;
  box-shadow: 0 0 0 4px rgba(15, 98, 254, .34);
}

.skip-link {
  position: fixed; left: 10px; top: 10px; z-index: 10; transform: translateY(-160%);
  background: var(--focus); color: #161616; border-radius: 0; padding: 7px 10px;
  font-size: 12px; font-weight: 800; text-decoration: none;
}
.skip-link:focus { transform: translateY(0); }

.app-shell {
  min-height: 100vh;
  display: grid;
  grid-template-columns: var(--nav-w) minmax(0, 1fr);
  background: var(--bg);
}
.app-shell.nav-collapsed { grid-template-columns: var(--nav-collapsed-w) minmax(0, 1fr); }

.density-compact { --gap: 8px; --pad: 16px; --row: 32px; --font-sm: 12px; --font-xs: 11px; }
.density-comfortable { --gap: 16px; --pad: 24px; --row: 40px; --font-sm: 13px; --font-xs: 12px; }

.sidebar {
  position: sticky;
  top: 0;
  isolation: isolate;
  height: 100vh;
  padding: 0;
  border-right: 1px solid var(--border);
  background: var(--bg-rail);
}

.brand {
  display: flex; gap: 10px; align-items: center; min-height: 48px;
  padding: 0 48px 0 16px; border-bottom: 1px solid var(--border);
}
.brand-mark {
  width: 32px; height: 32px; display: grid; place-items: center;
  background: var(--accent); color: #ffffff; font-weight: 800; border-radius: 0;
}
.brand-title { font-size: 13px; font-weight: 700; }
.brand-sub { color: var(--muted); font-size: var(--font-xs); margin-top: 2px; }
.nav-collapse-button {
  position: absolute; top: 8px; right: 8px; z-index: 1;
  width: 32px; height: 32px; display: grid; place-items: center; padding: 0;
  border: 1px solid transparent;
  border-radius: 0; background: transparent; color: var(--muted);
}
.nav-collapse-button:hover { color: var(--text); border-color: var(--border); background: var(--surface); }
.hamburger-icon, .panel-toggle-icon {
  width: 14px; display: grid; gap: 3px; align-content: center; justify-items: stretch;
}
.hamburger-icon span, .panel-toggle-icon span {
  display: block; height: 2px; border-radius: 999px; background: currentColor;
}
.panel-toggle-icon { width: 13px; transform: rotate(90deg); }
.nav-list { display: grid; gap: 0; padding: 8px 0; }
.nav-item, .bottom-item {
  border: 0; background: transparent; color: var(--muted); text-align: left; padding: 0 16px;
  border-radius: 0; font-size: var(--font-sm);
}
.nav-item { display: flex; align-items: center; gap: 12px; min-width: 0; min-height: 40px; border-left: 3px solid transparent; }
.nav-icon {
  flex: 0 0 28px; min-height: 28px; display: grid; place-items: center;
  color: var(--blue); font-size: 10px; font-weight: 850;
}
.nav-label { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.nav-item:hover, .bottom-item:hover { color: var(--text); background: var(--surface); }
.nav-item.active, .bottom-item.active {
  background: var(--surface); color: var(--text); border-left-color: var(--accent);
  box-shadow: none;
}
.nav-collapsed .sidebar { padding: 0; }
.nav-collapsed .brand { display: none; }
.nav-collapsed .brand-copy, .nav-collapsed .nav-label { display: none; }
.nav-collapsed .nav-collapse-button { position: static; width: 100%; height: 48px; margin-bottom: 8px; border-bottom: 1px solid var(--border); }
.nav-collapsed .nav-item {
  justify-content: center; padding: 0; min-height: 40px; border-left-width: 2px;
}
.nav-collapsed .nav-icon { flex-basis: 30px; min-height: 28px; }

.main { min-width: 0; display: flex; flex-direction: column; }
.main:focus { outline: none; }
.attach-bar {
  position: sticky; top: 0; z-index: 2; min-height: 48px; padding: 0 var(--pad);
  display: flex; align-items: center; gap: var(--gap); justify-content: space-between;
  border-bottom: 1px solid var(--border);
  background: rgba(22, 22, 22, 0.96);
  backdrop-filter: blur(8px);
}
.attach-primary { min-width: 0; }
.attach-label { color: var(--faint); font-size: 10px; text-transform: uppercase; letter-spacing: 0; }
.attach-value { font-weight: 750; font-size: 15px; }
.attach-meta { color: var(--muted); font-size: var(--font-xs); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.chip-row { display: flex; align-items: center; justify-content: flex-end; flex-wrap: wrap; gap: 6px; }
.chip {
  display: inline-flex; min-height: 22px; align-items: center; border-radius: 0; padding: 2px 8px;
  border: 1px solid var(--border); font-size: var(--font-xs); white-space: nowrap; color: var(--muted);
  background: transparent;
}
.chip.good { color: var(--green); border-color: rgba(66, 190, 101, .75); background: rgba(66, 190, 101, .08); }
.chip.amber { color: var(--amber); border-color: rgba(241, 194, 27, .75); background: rgba(241, 194, 27, .08); }
.chip.bad { color: var(--red); border-color: rgba(250, 77, 86, .75); background: rgba(250, 77, 86, .08); }
.chip.muted { color: var(--faint); }
.chip.neutral, .chip.info { color: var(--blue); border-color: rgba(120, 169, 255, .58); background: rgba(120, 169, 255, .08); }
.density-toggle, .primary-action, .tool-button {
  min-height: 32px; border-radius: 0; border: 1px solid var(--border); background: transparent;
  color: var(--text); padding: 0 12px; font-size: var(--font-xs);
}
.density-toggle:hover, .primary-action:hover, .tool-button:hover { border-color: var(--border-strong); background: var(--surface); }
.primary-action, .tool-button.primary {
  border-color: var(--accent); background: var(--accent); color: #ffffff;
}
.primary-action:hover, .tool-button.primary:hover {
  border-color: #4589ff; background: #4589ff; color: #ffffff;
}
.operator-band {
  min-width: 0; display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 1px;
  align-items: stretch; padding: 0 var(--pad); border-bottom: 1px solid var(--border);
  background: var(--border);
}
.operator-compact {
  min-width: 0; display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) auto;
  gap: 1px; align-items: stretch; background: var(--border);
}
.operator-line {
  min-width: 0; min-height: 44px; display: grid; grid-template-columns: auto 70px minmax(0, 1fr);
  gap: 8px; align-items: center; padding: 6px 10px; background: var(--surface);
}
.operator-kicker {
  color: var(--faint); font-size: 10px; line-height: 1; text-transform: uppercase;
}
.operator-line strong {
  min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  font-size: 13px; line-height: 1.2; font-weight: 700;
}
.status-dot {
  width: 9px; height: 9px; display: inline-block; border-radius: 50%;
  background: var(--border-strong); box-shadow: 0 0 0 1px rgba(255,255,255,.08);
}
.status-dot.good { background: var(--green); box-shadow: 0 0 0 2px rgba(66, 190, 101, .14); }
.status-dot.amber {
  background: var(--amber); box-shadow: 0 0 0 2px rgba(241, 194, 27, .14);
  animation: status-pulse 1.8s ease-in-out infinite;
}
.status-dot.bad { background: var(--red); box-shadow: 0 0 0 2px rgba(250, 77, 86, .14); }
.status-dot.info { background: var(--blue); box-shadow: 0 0 0 2px rgba(120, 169, 255, .14); }
.status-dot.muted { background: var(--border-strong); }
@keyframes status-pulse {
  0%, 100% { opacity: .55; }
  50% { opacity: 1; }
}
@media (prefers-reduced-motion: reduce) {
  .status-dot.amber { animation: none; }
}
.operator-status {
  min-width: 0; display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 8px; align-items: center;
  min-height: 56px; border: 0; border-radius: 0; padding: 8px 12px; background: var(--surface);
}
.operator-popover { position: relative; }
.operator-popover summary {
  min-height: 44px; display: inline-flex; align-items: center; cursor: pointer;
  color: var(--blue); font-size: var(--font-xs); list-style: none; padding: 0 10px;
  background: var(--surface);
}
.operator-popover summary::-webkit-details-marker { display: none; }
.operator-popover-body {
  position: absolute; right: 0; top: calc(100% + 8px); z-index: 5; width: min(520px, calc(100vw - 32px));
  padding: 10px 12px; border: 1px solid var(--border-strong); background: var(--surface); box-shadow: 0 18px 40px var(--shadow);
}
.operator-title { color: var(--faint); font-size: 10px; text-transform: uppercase; }
.operator-main { font-size: var(--font-sm); font-weight: 750; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.operator-meta { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.operator-actions { display: flex; gap: 1px; align-items: stretch; justify-content: flex-end; flex-wrap: wrap; background: var(--border); }
.operator-actions .tool-button { min-width: 72px; white-space: nowrap; }
.operator-message {
  grid-column: 1 / -1; display: flex; gap: 8px; align-items: center; min-height: 32px;
  border-radius: 0; border: 0; border-top: 1px solid var(--border); padding: 6px 12px; font-size: var(--font-xs);
  background: var(--surface);
}
.operator-message strong { white-space: nowrap; }
.operator-message span { color: var(--muted); overflow-wrap: anywhere; }
.operator-message.good { box-shadow: inset 3px 0 0 var(--green); background: var(--surface); }
.operator-message.good strong { color: var(--green); }
.operator-message.bad { box-shadow: inset 3px 0 0 var(--red); background: var(--surface); }
.operator-message.bad strong { color: var(--red); }
.operator-message.neutral { box-shadow: inset 3px 0 0 var(--blue); background: var(--surface); }
.operator-message.neutral strong { color: var(--blue); }

.workspace { padding: var(--pad); min-width: 0; }
.view-grid { display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(320px, .8fr); gap: var(--gap); align-items: start; }
.operations-grid { grid-template-columns: minmax(0, 1.15fr) minmax(340px, .85fr); }
.operations-grid > .panel:first-child { grid-column: 1 / -1; }
.operations-grid > .panel:nth-child(4) { grid-column: 1 / -1; }
.ops-disclosure-grid { display: grid; grid-template-columns: minmax(0, .9fr) minmax(0, 1fr) minmax(0, 1.1fr); gap: var(--gap); align-items: start; }
.observe-grid, .engine-grid, .tools-grid { grid-template-columns: minmax(0, 1fr) minmax(360px, .8fr); }
.tools-grid-collapsed { grid-template-columns: minmax(0, 1fr) 54px; }
.settings-grid { grid-template-columns: minmax(380px, 1fr) minmax(420px, 1.05fr); }
.panel {
  min-width: 0; border: 1px solid var(--border); background: var(--surface); border-radius: 0;
  padding: 0; box-shadow: none;
}
.panel > :not(.panel-title):not(.panel-title-row) { margin-left: var(--pad); margin-right: var(--pad); }
.panel > :last-child { margin-bottom: var(--pad); }
.panel-title {
  font-size: 12px; font-weight: 650; margin: 0 0 var(--pad); min-height: 40px;
  display: flex; align-items: center; padding: 0 var(--pad); border-bottom: 1px solid var(--border);
  background: #1f1f1f; color: var(--text);
}
.panel-title-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 10px; }
.panel-title-row .panel-title { margin: 0; }
.panel-toolbar, .hero-line, .tool-actions { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; }
.mono { font-family: "SF Mono", Consolas, ui-monospace, monospace; font-size: var(--font-xs); color: var(--muted); }
.compact-copy { color: var(--muted); font-size: var(--font-sm); line-height: 1.45; }

.operations-board {
  min-width: 0; display: grid; grid-template-columns: minmax(0, 1fr) minmax(220px, .34fr);
  gap: 10px; align-items: stretch;
}
.ops-command-surface {
  min-width: 0; display: grid; grid-template-columns: minmax(0, 1fr) auto auto;
  gap: 1px; align-items: stretch; background: var(--border);
}
.ops-current {
  min-width: 0; display: grid; align-content: center; gap: 3px; padding: 8px 10px;
  background: var(--surface-2);
}
.ops-current-title {
  min-width: 0; display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 7px; align-items: center;
}
.ops-current-title.target strong { color: var(--muted); font-size: var(--font-xs); }
.ops-current-title strong {
  min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  font-size: 14px; line-height: 1.2;
}
.ops-status-strip {
  min-width: 0; display: grid; grid-template-columns: repeat(3, minmax(70px, 1fr));
  gap: 1px; background: var(--border);
}
.ops-status-item {
  min-width: 0; display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 6px; align-items: center;
  padding: 0 10px; background: var(--surface); font-size: var(--font-xs);
}
.ops-status-item strong { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: 650; }
.inline-actions { flex-wrap: nowrap; }
.ops-capability-meter {
  min-width: 0; display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 1px;
  background: var(--border); min-height: 38px; align-self: stretch;
}
.meter-segment {
  min-width: 0; display: grid; place-items: center; background: #1f1f1f; color: var(--faint);
  border-top: 2px solid var(--border-strong); font-size: 10px; text-transform: uppercase;
}
.meter-segment.enabled { color: var(--text); border-top-color: var(--green); }
.meter-segment.disabled { color: var(--faint); border-top-color: var(--border-strong); }
.ops-disclosure {
  min-width: 0; border: 1px solid var(--border); background: var(--surface);
}
.ops-disclosure summary {
  min-height: 38px; display: flex; align-items: center; justify-content: space-between; gap: 10px;
  padding: 0 12px; border-bottom: 1px solid var(--border); cursor: pointer; color: var(--text);
  background: #1f1f1f; font-size: var(--font-sm); font-weight: 650;
}
.ops-disclosure summary::marker { color: var(--blue); }
.ops-disclosure > :not(summary) { margin: 10px 12px 12px; }

.trace-list { display: grid; gap: 6px; }
.trace-search { margin-bottom: 8px; }
.trace-search input {
  width: 100%; min-height: 30px; border-radius: 6px; border: 1px solid var(--border);
  background: var(--surface-2); color: var(--text); padding: 5px 8px; font-size: var(--font-sm);
}
.observe-guidance {
  display: grid; gap: 3px; margin-bottom: 8px; padding: 8px; border: 1px solid rgba(229, 184, 92, .34);
  border-radius: 6px; background: rgba(229, 184, 92, .08); color: var(--muted); font-size: var(--font-sm);
}
.observe-guidance strong { color: var(--amber); }
.trace-row, .sample-card {
  display: grid; gap: 8px; align-items: center; min-height: var(--row);
  grid-template-columns: minmax(0, 1fr) auto auto auto; padding: 8px 10px; border: 0;
  border-bottom: 1px solid var(--border); border-radius: 0; background: transparent;
}
.sample-card { grid-template-columns: 1fr; align-items: stretch; }
.sample-list { display: grid; gap: 8px; }
.sample-card-head { display: flex; gap: 8px; align-items: center; justify-content: space-between; }
.row-title { font-weight: 700; font-size: var(--font-sm); }
.row-sub { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.metric { color: var(--muted); font-size: var(--font-xs); white-space: nowrap; }
.summary-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 1px; margin-bottom: 10px; background: var(--border); }
.capability-list, .lifecycle-list { display: grid; gap: 6px; }
.capability-line, .lifecycle-row {
  min-width: 0; display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; align-items: center;
  min-height: var(--row); border: 0; border-bottom: 1px solid var(--border); border-radius: 0; background: transparent; padding: 7px 0;
}
.compact-lifecycle {
  gap: 1px; background: var(--border);
  grid-template-columns: repeat(auto-fit, minmax(min(170px, 100%), 1fr));
}
.lifecycle-row {
  grid-template-columns: auto minmax(0, 1fr) auto; gap: 7px; min-height: 38px;
  padding: 7px 8px; border-bottom: 0; background: var(--surface);
}
.lifecycle-row.disabled { opacity: .74; }
.icon-button {
  width: 32px; height: 32px; display: grid; place-items: center; border-radius: 0;
  border: 1px solid var(--border); background: transparent; color: var(--text);
  font-weight: 800; line-height: 1;
}
.icon-button:hover { border-color: var(--accent); color: var(--accent); background: rgba(24, 170, 255, .10); }
.evidence-table .table-head, .evidence-table .table-row {
  grid-template-columns: minmax(0, .65fr) minmax(0, 1.8fr) minmax(0, .8fr);
}
.stage-strip { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 5px; margin-bottom: 10px; }
.stage { min-height: 42px; display: grid; place-items: center; border-radius: 6px; border: 1px solid var(--border); font-size: var(--font-xs); }
.live-stage-strip { margin-top: 10px; }
.live-stage-strip .stage { place-items: start; align-content: center; padding: 7px; overflow: hidden; }
.stage strong, .stage span { max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.stage.ok { color: var(--green); border-color: rgba(103, 208, 141, .38); background: rgba(103, 208, 141, .09); }
.bridge-status {
  display: flex; align-items: center; gap: 8px; margin-top: 8px; padding: 7px 8px;
  border: 1px solid var(--border); border-radius: 6px; background: var(--surface-2);
  color: var(--muted); font-size: var(--font-xs);
}
.bridge-status span:last-child { overflow-wrap: anywhere; }
.span-tree { display: grid; gap: 5px; margin-top: 10px; }
.mini-section-title { color: var(--muted); font-size: 10px; text-transform: uppercase; margin-bottom: 5px; }
.mini-empty {
  min-height: 28px; display: grid; align-items: center; color: var(--faint); font-size: var(--font-xs);
  border: 1px dashed var(--border); border-radius: 6px; padding: 5px 8px;
}
.pit-fanout { margin-top: 10px; }
.pit-row {
  display: grid; grid-template-columns: minmax(0, 1fr) auto minmax(0, 1.2fr) auto; gap: 8px; align-items: center;
  min-height: 30px; padding: 5px 8px; border: 1px solid rgba(229, 184, 92, .32); border-radius: 6px;
  background: rgba(229, 184, 92, .07); font-size: var(--font-xs); margin-bottom: 5px;
}
.pit-row span, .pit-row strong { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pit-row span { color: var(--muted); }
.span-node {
  display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(0, .9fr) auto auto auto; gap: 8px; align-items: center;
  min-height: 32px; padding: 6px 8px; border: 1px solid var(--border); border-radius: 6px;
  background: var(--surface-2); font-size: var(--font-xs);
}
.span-node div { min-width: 0; display: grid; gap: 2px; }
.span-node span { color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.trace-logs { margin-top: 10px; }
.log-row {
  display: grid; grid-template-columns: auto auto minmax(0, .85fr) auto minmax(0, 1.5fr); gap: 8px; align-items: center;
  min-height: 30px; padding: 5px 8px; border: 1px solid var(--border); border-radius: 6px;
  background: var(--surface-2); font-size: var(--font-xs); margin-bottom: 5px;
}
.log-row span, .log-row strong { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.log-row span { color: var(--muted); }

.detail-table { display: grid; gap: 6px; }
.kv {
  min-height: var(--row); display: flex; align-items: center; justify-content: space-between; gap: 12px;
  border-bottom: 1px solid var(--border); padding: 4px 0; font-size: var(--font-sm);
}
.kv span { color: var(--muted); }
.kv strong { text-align: right; font-weight: 700; overflow-wrap: anywhere; }
.metrics-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 6px; margin-bottom: 10px; }
.metric-card { padding: 12px; border: 0; border-radius: 0; background: var(--surface-2); }
.metric-card span { display: block; color: var(--muted); font-size: var(--font-xs); }
.metric-card strong { display: block; margin-top: 5px; font-size: 20px; font-weight: 500; }
.dense-table { display: grid; border: 1px solid var(--border); border-radius: 0; overflow: hidden; }
.table-head, .table-row { display: grid; grid-template-columns: .6fr minmax(0, 2fr) 1fr 1fr; min-height: var(--row); align-items: center; }
.table-head { background: #1f1f1f; color: var(--muted); font-size: 10px; text-transform: uppercase; }
.table-row { background: var(--surface); font-size: var(--font-sm); border-top: 1px solid var(--border); }
.table-row:nth-child(even) { background: #2b2b2b; }
.table-row:hover { background: var(--surface-2); }
.table-head span, .table-row span { padding: 0 8px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.engine-table.route-table .table-head, .engine-table.route-table .table-row {
  grid-template-columns: minmax(0, 1.8fr) .8fr .5fr .5fr .9fr;
}
.strategy-table { margin-bottom: 10px; }
.strategy-table .table-head, .strategy-table .table-row {
  grid-template-columns: minmax(0, 1fr) minmax(0, 1.7fr) .7fr;
}
.config-diff-table { margin: 10px 0; }
.config-diff-table .table-head, .config-diff-table .table-row {
  grid-template-columns: minmax(0, .8fr) minmax(0, 1fr) minmax(0, 1fr) .55fr;
}
.fleet-table, .routing-table, .radio-table, .topology-table, .extension-table { margin-top: 10px; }
.fleet-table .table-head, .fleet-table .table-row {
  grid-template-columns: minmax(0, 1fr) minmax(0, 1.6fr) .7fr .9fr .8fr;
}
.routing-table .table-head, .routing-table .table-row,
.radio-table .table-head, .radio-table .table-row,
.topology-table .table-head, .topology-table .table-row {
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) .65fr minmax(0, 1fr);
}
.extension-table .table-head, .extension-table .table-row {
  grid-template-columns: minmax(0, .8fr) minmax(0, .8fr) minmax(0, 1.7fr);
}
.log-table .table-head, .log-table .table-row,
.audit-table .table-head, .audit-table .table-row {
  grid-template-columns: .55fr minmax(0, 1fr) minmax(0, .9fr) minmax(0, 1.6fr);
}
.code-preview {
  width: 100%; min-height: 132px; resize: vertical; margin-top: 8px; padding: 10px;
  border: 1px solid var(--border); border-radius: 0; background: #1f1f1f;
  color: var(--text); font: 11px/1.45 var(--mono); white-space: pre; overflow: auto;
}
.code-preview.tall { min-height: 240px; }
.source-grid { display: grid; gap: 5px; margin-top: 10px; }
.source-row {
  display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 8px;
  min-height: 28px; border-bottom: 1px solid rgba(48, 57, 70, .75);
}
.mutation-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(260px, 100%), 1fr)); gap: 8px; margin-bottom: 10px; }
.mutation-card {
  min-width: 0; display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px;
  align-content: start; padding: 8px; border: 1px solid var(--border); border-radius: 0; background: var(--surface-2);
}
.mutation-card .preflight-panel { grid-column: 1 / -1; }
.mutation-history { display: grid; gap: 6px; }
.mutation-row {
  min-width: 0; display: grid; grid-template-columns: minmax(96px, .7fr) minmax(0, 1fr) auto minmax(0, 1.4fr);
  gap: 8px; align-items: center; min-height: 34px; padding: 6px 8px; border-bottom: 1px solid var(--border);
  border-radius: 0; background: transparent; font-size: var(--font-sm);
}
.mutation-row strong, .mutation-row span { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.trust-workspace { display: grid; gap: var(--gap); align-items: start; }
.trust-main-grid {
  display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--gap); align-items: start;
}
.trust-main-grid.secondary { grid-template-columns: minmax(0, .9fr) minmax(320px, .65fr); }
.trust-status-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; }
.trust-status-card {
  min-width: 0; display: grid; gap: 4px; padding: 10px; border: 1px solid var(--border); border-radius: 0;
  color: var(--text); text-align: left; background: var(--surface-2); box-shadow: inset 3px 0 0 var(--border-strong);
}
.trust-status-card:hover { border-color: var(--border-strong); background: var(--surface-3); }
.trust-status-card span { color: var(--muted); font-size: 10px; text-transform: uppercase; }
.trust-status-card strong { min-width: 0; font-size: 18px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.trust-status-card small { min-width: 0; color: var(--faint); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.trust-status-card.good { box-shadow: inset 3px 0 0 var(--green); }
.trust-status-card.info { box-shadow: inset 3px 0 0 var(--accent); }
.trust-status-card.amber { box-shadow: inset 3px 0 0 var(--amber); }
.trust-status-card.bad { box-shadow: inset 3px 0 0 var(--red); }
.trust-chain-strip { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 6px; margin-bottom: 10px; }
.chain-pill {
  min-width: 0; min-height: 46px; display: grid; align-content: center; gap: 2px; padding: 7px 8px;
  border: 1px solid var(--border); border-radius: 0; background: var(--surface-2);
}
.chain-pill span { color: var(--muted); font-size: 10px; text-transform: uppercase; }
.chain-pill strong { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.chain-pill.good { border-color: rgba(103, 208, 141, .38); background: rgba(103, 208, 141, .08); }
.chain-pill.info { border-color: rgba(24, 170, 255, .38); background: rgba(24, 170, 255, .07); }
.chain-pill.amber { border-color: rgba(229, 184, 92, .38); background: rgba(229, 184, 92, .08); }
.chain-pill.bad { border-color: rgba(255, 127, 135, .45); background: rgba(255, 127, 135, .08); }
.split-list { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; margin-bottom: 10px; }
.compact-stack { display: grid; gap: 6px; }
.trust-compact-row {
  min-width: 0; display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; align-items: center;
  min-height: 34px; padding: 6px 8px; border-bottom: 1px solid var(--border); border-radius: 0;
  background: transparent; font-size: var(--font-sm);
}
.trust-compact-row.with-sub { grid-template-columns: minmax(0, 1fr) auto auto; }
.trust-compact-row strong, .trust-compact-row span { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.trust-action-row, .active-identity-card, .trace-summary {
  min-width: 0; display: grid; grid-template-columns: auto minmax(0, 1fr) auto; gap: 8px; align-items: center;
  min-height: 40px; padding: 8px; border: 1px solid rgba(15, 98, 254, .55); border-radius: 0;
  background: rgba(15, 98, 254, .08); margin-bottom: 10px;
}
.active-identity-card { grid-template-columns: minmax(0, 1fr) auto; }
.trace-summary { grid-template-columns: minmax(0, 1fr) auto; }
.active-identity-card div { min-width: 0; display: grid; gap: 2px; }
.active-identity-card span { color: var(--muted); font-size: 10px; text-transform: uppercase; }
.active-identity-card strong, .trust-action-row span, .trace-summary strong { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.trust-command-row {
  display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-top: 10px;
}
.modal-backdrop {
  position: fixed; inset: 0; z-index: 20; display: grid; place-items: center; padding: 22px;
  background: rgba(3, 6, 9, .72); backdrop-filter: blur(8px);
}
.trust-modal {
  width: min(1080px, 100%); max-height: min(760px, calc(100vh - 44px)); display: grid; grid-template-rows: auto minmax(0, 1fr);
  border: 1px solid var(--border-strong); border-radius: 0; background: var(--surface); box-shadow: 0 24px 70px rgba(0, 0, 0, .58);
}
.modal-head {
  display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 12px;
  min-height: 54px; padding: 10px 12px; border-bottom: 1px solid var(--border);
}
.modal-head div { min-width: 0; display: grid; gap: 2px; }
.modal-head span { color: var(--muted); font-size: 10px; text-transform: uppercase; }
.modal-head strong { min-width: 0; font-size: 18px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.modal-close {
  min-height: 30px; border-radius: 0; border: 1px solid var(--border); background: transparent;
  color: var(--muted); padding: 4px 10px; font-size: var(--font-xs);
}
.modal-close:hover { color: var(--text); border-color: var(--border-strong); background: var(--surface-3); }
.modal-body { min-height: 0; overflow: auto; padding: 12px; }
.trust-modal-stack, .modal-section { min-width: 0; display: grid; gap: 10px; align-content: start; }
.modal-section-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
.modal-section-grid .wide { grid-column: 1 / -1; }
.modal-kv-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
.modal-action-row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.router-modal { max-width: min(1120px, calc(100vw - 28px)); }
.router-tab-row {
  display: flex; gap: 6px; overflow-x: auto; padding: 10px 12px; border-bottom: 1px solid var(--border);
}
.router-modal-body { padding-bottom: 4px; }
.router-preview { min-height: 280px; }
.router-modal-actions {
  justify-content: flex-end; padding: 10px 12px 12px; border-top: 1px solid var(--border);
}
.preset-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(280px, 100%), 1fr)); gap: 8px; }
.preset-card {
  width: 100%; color: inherit; text-align: left; cursor: pointer;
}
.preset-card:hover { border-color: var(--accent); background: rgba(24, 170, 255, .08); }
.preflight-panel {
  display: grid; gap: 7px; padding: 9px; border: 1px solid rgba(15, 98, 254, .55);
  border-radius: 0; background: rgba(15, 98, 254, .08);
}
.preflight-head {
  display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; align-items: center;
}
.preflight-head strong { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.preflight-summary { color: var(--muted); font-size: var(--font-xs); }
.preflight-checks { display: grid; gap: 5px; }
.preflight-check {
  min-width: 0; display: grid; grid-template-columns: 90px minmax(0, 1fr); gap: 8px; align-items: center;
  min-height: 28px; padding: 5px 7px; border-bottom: 1px solid var(--border); border-radius: 0; background: transparent;
  font-size: var(--font-xs);
}
.preflight-check span { color: var(--muted); text-transform: uppercase; }
.preflight-check strong { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.preflight-check.passed { box-shadow: inset 3px 0 0 var(--green); }
.preflight-check.failed { box-shadow: inset 3px 0 0 var(--red); }
.preflight-note {
  min-height: 32px; display: grid; align-items: center; padding: 7px 8px;
  border: 1px solid rgba(241, 194, 27, .65); border-radius: 0;
  background: rgba(241, 194, 27, .08); color: var(--amber); font-size: var(--font-sm);
}
.trust-modal-table { display: grid; gap: 5px; }
.trust-modal-row {
  min-width: 0; display: grid; gap: 8px; align-items: center; min-height: 34px;
  padding: 6px 8px; border-bottom: 1px solid var(--border); border-radius: 0; background: transparent;
  font-size: var(--font-sm);
}
.trust-modal-table.cols-3 .trust-modal-row { grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr) auto; }
.trust-modal-table.cols-4 .trust-modal-row { grid-template-columns: minmax(0, 1.3fr) minmax(0, 1fr) minmax(0, .65fr) auto; }
.trust-modal-row strong, .trust-modal-row span { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.trust-list { display: grid; gap: 6px; margin-bottom: 10px; }
.trust-row, .approval-row, .schema-review-row {
  min-width: 0; display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; align-items: center;
  min-height: var(--row); padding: 7px 0; border-bottom: 1px solid var(--border); border-radius: 0;
  background: transparent; font-size: var(--font-sm);
}
.trust-row > div, .approval-row > div, .schema-review-row > div { min-width: 0; display: grid; gap: 2px; }
.trust-flow-card {
  display: grid; gap: 6px; align-content: start; min-width: 0; padding: 9px;
  border: 1px solid var(--border); border-radius: 0; background: var(--surface-2);
}
.primary-flow { border-color: rgba(15, 98, 254, .55); background: rgba(15, 98, 254, .08); margin-bottom: 10px; }
.lane-section, .evidence-block { min-width: 0; display: grid; gap: 6px; }
.evidence-subtitle { margin-top: 10px; }
.validation-frame, .did-frame-list { display: grid; gap: 8px; margin-bottom: 10px; }
.custody-alert, .safebag-preview {
  display: grid; gap: 4px; margin-bottom: 10px; padding: 8px; border: 1px solid rgba(15, 98, 254, .55);
  border-radius: 0; background: rgba(15, 98, 254, .08); font-size: var(--font-sm);
}
.custody-alert strong, .safebag-preview strong { color: var(--accent); }
.identity-table, .schema-table { margin-bottom: 10px; }
.identity-table .table-head, .identity-table .table-row,
.schema-table .table-head, .schema-table .table-row {
  grid-template-columns: minmax(0, 1.4fr) minmax(0, .9fr) minmax(0, .75fr) minmax(92px, .55fr);
}
.engine-detail { margin-top: 8px; border-top: 1px solid var(--border); padding-top: 8px; }
.tool-actions { align-items: stretch; }
.tool-button { text-transform: none; }
.inline-button { min-height: 24px; padding: 2px 7px; }
.action-button { white-space: nowrap; word-break: keep-all; min-width: max-content; }
.tool-tabbar { display: flex; gap: 5px; flex-wrap: wrap; margin-bottom: 8px; }
.tool-tab {
  min-height: 30px; border: 1px solid var(--border); border-radius: 0; background: transparent;
  color: var(--muted); padding: 4px 10px; font-size: var(--font-xs);
}
.tool-tab.active {
  color: #ffffff; border-color: var(--accent); background: var(--accent);
  box-shadow: inset 0 -2px 0 var(--accent);
}
.tool-form-grid { display: grid; grid-template-columns: minmax(0, 1fr); gap: 8px; margin-bottom: 10px; }
.tool-card {
  min-width: 0; display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 7px;
  align-content: start; border: 1px solid var(--border); border-radius: 0; background: var(--surface-2); padding: 8px;
}
.active-tool-card { max-width: 760px; }
.tool-card-hidden { display: none; }
.tool-card-title {
  grid-column: 1 / -1; color: var(--accent); font-size: 10px; font-weight: 800; text-transform: uppercase;
}
.tool-field { min-width: 0; display: grid; gap: 3px; color: var(--muted); font-size: 10px; text-transform: uppercase; }
.tool-field input, .tool-field select, .tool-field textarea {
  min-width: 0; width: 100%; border-radius: 0; border: 1px solid transparent; border-bottom-color: var(--border-strong);
  background: var(--field); color: var(--text); padding: 5px 7px; font-size: var(--font-sm); text-transform: none;
}
.tool-field input:focus, .tool-field select:focus, .tool-field textarea:focus { border-bottom-color: var(--accent-2); outline: 1px solid var(--accent-2); }
.tool-field textarea { min-height: 58px; resize: vertical; font-family: "SF Mono", Consolas, ui-monospace, monospace; }
.tool-check {
  min-width: 0; min-height: 30px; display: flex; align-items: center; gap: 6px; color: var(--muted);
  font-size: var(--font-xs); text-transform: none;
}
.tool-check input { margin: 0; }
.span-2 { grid-column: 1 / -1; }
.results-toolbar {
  display: grid; grid-template-columns: minmax(180px, 1fr) auto auto; gap: 6px; align-items: center; margin-bottom: 8px;
}
.results-toolbar input {
  min-width: 0; min-height: 30px; border-radius: 6px; border: 1px solid var(--border);
  background: var(--surface-2); color: var(--text); padding: 5px 8px; font-size: var(--font-sm);
}
.tools-table .table-head, .tools-table .table-row {
  grid-template-columns: 44px minmax(64px, .55fr) minmax(0, 1.25fr) minmax(98px, .7fr) minmax(0, 2.35fr) 72px;
}
.tools-table .table-row { align-items: start; min-height: auto; }
.tools-table .table-head > span, .tools-table .table-row > span {
  min-width: 0; padding: 7px 8px; white-space: normal; overflow: visible; text-overflow: clip; overflow-wrap: anywhere;
}
.tools-table .table-head > span { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.tools-table .table-row > span:last-child { white-space: nowrap; overflow: visible; }
.tools-table .status-cell { display: flex; align-items: center; gap: 6px; }
.tools-table .chip { padding: 2px 8px; overflow: visible; text-overflow: clip; }
.error-row { box-shadow: inset 3px 0 0 var(--red); background: rgba(255, 127, 135, .07); }
.result-cell { line-height: 1.35; color: var(--text); }
.tool-error-banner, .tool-error-detail {
  display: grid; gap: 3px; margin-bottom: 8px; border: 1px solid rgba(255, 127, 135, .44);
  border-radius: 6px; background: rgba(255, 127, 135, .09); color: var(--red); padding: 7px 8px;
  font-size: var(--font-xs);
}
.tool-error-banner span, .tool-error-detail span { color: var(--text); overflow-wrap: anywhere; }
.tool-detail-panel { min-width: 0; }
.tool-detail-rail {
  display: grid; justify-items: center; align-content: start; gap: 7px; padding: 8px 6px;
}
.rail-toggle, .rail-icon {
  width: 34px; min-height: 30px; border: 1px solid var(--border); border-radius: 6px;
  background: var(--surface-raised); color: var(--muted); font-size: 10px; font-weight: 800;
}
.panel-title-row .action-button, .sample-card-head .action-button {
  width: 28px; min-width: 28px; min-height: 26px; display: grid; place-items: center; padding: 0;
}
.rail-toggle:hover, .rail-icon:hover { border-color: var(--border-strong); color: var(--accent); background: var(--surface-3); }
.rail-icon.error { color: var(--red); border-color: rgba(255, 127, 135, .52); background: rgba(255, 127, 135, .08); }
.sparkline {
  min-height: 34px; display: flex; align-items: end; gap: 3px; padding: 6px 8px;
  border: 1px solid rgba(24, 170, 255, .28); border-radius: 6px; background: rgba(24, 170, 255, .06);
}
.sparkline span {
  width: 7px; min-height: 2px; border-radius: 2px 2px 0 0;
  background: linear-gradient(180deg, var(--accent-2), var(--accent));
  box-shadow: 0 0 8px rgba(24, 170, 255, .28);
}
.tool-input {
  min-height: 30px; min-width: 210px; border-radius: 6px; border: 1px solid var(--border);
  background: var(--surface-2); color: var(--text); padding: 5px 8px; font-size: var(--font-sm);
}
.server-controls { display: grid; gap: 5px; margin-bottom: 10px; }
.server-control {
  display: grid; grid-template-columns: minmax(0, .8fr) minmax(0, 1.6fr); gap: 8px; align-items: center;
  min-height: 30px; padding: 5px 8px; border: 1px solid var(--border); border-radius: 6px;
  background: var(--surface-2); font-size: var(--font-xs);
}
.server-control span, .server-control strong { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.server-control span { color: var(--muted); }
.compact-actions { margin: 6px 0 0; }
.trace-ref-row { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 6px; }
.inline-alert {
  margin-bottom: 10px; border: 1px solid rgba(250, 77, 86, .65); border-radius: 0;
  background: rgba(250, 77, 86, .08); color: var(--red); padding: 8px 10px; font-size: var(--font-sm);
}
.target-list { display: grid; gap: 0; border-top: 1px solid var(--border); }
.target-list.compact { gap: 0; }
.target-row {
  min-width: 0; display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; align-items: center;
  border: 0; border-bottom: 1px solid var(--border); border-radius: 0; background: transparent; padding: 8px 0;
}
.target-row.active { box-shadow: inset 3px 0 0 var(--accent); padding-left: 8px; }
.target-main {
  min-width: 0; display: grid; gap: 3px; border: 0; background: transparent; color: var(--text); text-align: left; padding: 2px;
}
.target-meta { display: flex; flex-wrap: wrap; gap: 8px; color: var(--muted); font-size: var(--font-xs); }
.target-badges { display: flex; gap: 5px; flex-wrap: wrap; justify-content: flex-end; }
.recent-target {
  display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; align-items: center;
  min-height: var(--row); border-bottom: 1px solid var(--border); padding: 3px 0;
}
.capability-matrix {
  display: grid; border: 1px solid var(--border); border-radius: 0; overflow: hidden; margin-bottom: 10px;
}
.matrix-head, .matrix-row {
  display: grid; grid-template-columns: minmax(120px, .85fr) minmax(90px, .55fr) minmax(180px, 1fr) minmax(180px, 1.25fr);
  align-items: center;
}
.matrix-head { min-height: 30px; background: #1f1f1f; color: var(--muted); font-size: 10px; text-transform: uppercase; }
.matrix-row { min-height: var(--row); background: var(--surface); border-top: 1px solid var(--border); font-size: var(--font-sm); }
.matrix-head span, .matrix-row span { min-width: 0; padding: 6px 8px; overflow-wrap: anywhere; }
.probe-outcome { color: var(--accent); font-family: inherit; font-size: var(--font-xs); }
.probe-time { color: var(--faint); font-family: inherit; font-size: var(--font-xs); }
.empty-state {
  min-height: 120px; display: grid; align-content: center; gap: 6px; color: var(--muted);
  border: 1px dashed var(--border-strong); border-radius: 0; padding: 14px; font-size: var(--font-sm);
}
.empty-state strong { color: var(--text); }
.bottom-nav { display: none; }

@media (max-width: 1240px) {
  .operator-band, .operations-board { grid-template-columns: 1fr; }
  .ops-command-surface { grid-template-columns: minmax(0, 1fr); }
  .operator-actions, .inline-actions { justify-content: flex-start; }
}

@media (max-width: 980px) {
  .app-shell, .app-shell.nav-collapsed { grid-template-columns: 1fr; padding-bottom: 56px; }
  .sidebar { display: none; }
  .operations-grid > .panel:first-child, .operations-grid > .panel:nth-child(4) { grid-column: auto; }
  .operator-compact, .ops-disclosure-grid, .operations-board { grid-template-columns: 1fr; }
  .view-grid, .operations-grid, .observe-grid, .engine-grid, .tools-grid, .tools-grid-collapsed { grid-template-columns: 1fr; }
  .trust-main-grid, .trust-main-grid.secondary { grid-template-columns: 1fr; }
  .trust-status-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .modal-section-grid, .modal-kv-grid { grid-template-columns: 1fr; }
  .settings-grid { grid-template-columns: 1fr; }
  .tool-detail-rail {
    position: fixed; right: 10px; bottom: 66px; z-index: 4; width: auto; min-width: 0;
    padding: 6px; border-radius: 10px; box-shadow: 0 10px 24px var(--shadow);
  }
  .tool-detail-rail .rail-toggle, .tool-detail-rail .rail-icon { width: 32px; min-height: 30px; }
  .bottom-nav {
    position: fixed; left: 0; right: 0; bottom: 0; z-index: 3; display: grid; grid-template-columns: repeat(6, 1fr);
    border-top: 1px solid var(--border); background: rgba(22, 22, 22, 0.98); padding: 0;
  }
  .bottom-item { text-align: center; padding: 8px 2px; font-size: 11px; min-height: 48px; }
  .bottom-item.active { border-left: 0; box-shadow: inset 0 3px 0 var(--accent); }
}

@media (max-width: 640px) {
  .attach-bar { align-items: stretch; flex-direction: column; gap: 7px; padding-top: 8px; padding-bottom: 8px; }
  .chip-row { justify-content: flex-start; }
  .operator-band { padding: 0; }
  .operator-line { grid-template-columns: auto 58px minmax(0, 1fr); }
  .operator-popover-body { left: 0; right: auto; }
  .operator-status { grid-template-columns: 1fr; gap: 5px; }
  .operator-actions { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .operator-actions .tool-button { min-width: 0; }
  .operator-message { align-items: flex-start; flex-direction: column; gap: 3px; }
  .workspace { padding: 8px; }
  .panel { border-radius: 0; }
  .panel > :not(.panel-title):not(.panel-title-row) { margin-left: 10px; margin-right: 10px; }
  .panel-title { padding: 0 10px; }
  .summary-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .ops-capability-meter { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .ops-status-strip { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .capability-line { grid-template-columns: 1fr; align-items: start; padding: 8px 0; }
  .lifecycle-row { grid-template-columns: auto minmax(0, 1fr) auto; }
  .trace-row { grid-template-columns: 1fr 1fr; }
  .bridge-status { align-items: flex-start; flex-direction: column; }
  .log-row { grid-template-columns: 1fr; }
  .server-control { grid-template-columns: 1fr; }
  .pit-row { grid-template-columns: 1fr; }
  .span-node { grid-template-columns: 1fr; }
  .stage-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .metrics-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .mutation-grid { grid-template-columns: 1fr; }
  .mutation-row { grid-template-columns: 1fr; align-items: start; }
  .trust-chain-strip, .split-list { grid-template-columns: 1fr; }
  .trust-action-row, .trace-summary { grid-template-columns: 1fr auto; }
  .trust-action-row span { grid-column: 1 / -1; }
  .modal-backdrop { align-items: stretch; padding: 8px; }
  .trust-modal { max-height: calc(100vh - 16px); }
  .preflight-check { grid-template-columns: 1fr; align-items: start; }
  .trust-modal-table.cols-3 .trust-modal-row,
  .trust-modal-table.cols-4 .trust-modal-row { grid-template-columns: 1fr; align-items: start; }
  .modal-action-row .tool-button { flex: 1 1 140px; }
  .tool-form-grid { grid-template-columns: 1fr; }
  .tool-card { grid-template-columns: 1fr 1fr; }
  .active-tool-card { max-width: none; }
  .results-toolbar { grid-template-columns: 1fr 1fr; }
  .results-toolbar input { grid-column: 1 / -1; }
  .table-head, .table-row { grid-template-columns: .7fr minmax(0, 1.6fr) .8fr .9fr; }
  .table-head span, .table-row span { padding: 0 5px; }
  .tools-table .table-head { display: none; }
  .tools-table .table-row { grid-template-columns: 1fr; padding: 6px; gap: 3px; }
  .tools-table .table-row > span { padding: 1px 0; }
  .tools-table .table-row > span::before {
    display: inline-block; min-width: 54px; margin-right: 6px; color: var(--faint); font-size: 10px; text-transform: uppercase;
  }
  .tools-table .status-cell { display: flex; align-items: center; gap: 6px; }
  .tools-table .status-cell::before { flex: 0 0 54px; margin-right: 0; }
  .tools-table .status-cell .chip { min-height: 22px; max-width: calc(100% - 60px); overflow: hidden; text-overflow: ellipsis; }
  .tools-table .table-row > span:nth-child(1)::before { content: "Sel"; }
  .tools-table .table-row > span:nth-child(2)::before { content: "Tool"; }
  .tools-table .table-row > span:nth-child(3)::before { content: "Target"; }
  .tools-table .table-row > span:nth-child(4)::before { content: "Status"; }
  .tools-table .table-row > span:nth-child(5)::before { content: "Result"; }
  .tools-table .table-row > span:nth-child(6)::before { content: "Open"; }
  .engine-table.route-table .table-head, .engine-table.route-table .table-row,
  .strategy-table .table-head, .strategy-table .table-row,
  .identity-table .table-head, .identity-table .table-row,
  .schema-table .table-head, .schema-table .table-row { grid-template-columns: 1fr; }
  .trust-row, .approval-row, .schema-review-row { grid-template-columns: 1fr; align-items: start; }
  .target-row { grid-template-columns: 1fr; }
  .target-badges { justify-content: flex-start; }
  .matrix-head { display: none; }
  .matrix-row { grid-template-columns: 1fr; gap: 2px; padding: 6px; }
  .matrix-row span { padding: 2px 0; }
  .evidence-table .table-head { display: none; }
  .evidence-table .table-row { grid-template-columns: 1fr; padding: 6px; gap: 2px; }
  .evidence-table .table-row span { padding: 2px 0; }
}

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    scroll-behavior: auto !important;
    transition-duration: .001ms !important;
    animation-duration: .001ms !important;
    animation-iteration-count: 1 !important;
  }
}
"#;
