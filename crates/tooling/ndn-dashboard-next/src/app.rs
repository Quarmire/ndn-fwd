//! Dioxus application shell for dashboard-next.

use dioxus::prelude::*;

use crate::client::{
    DashboardClient, MockDashboardClient, ProbeOutcome, ProbeTranscript, state_from_probe,
};
use crate::core::{
    DashboardPreferences, DashboardState, Density, FeatureState, PlatformKind, SavedAttachTarget,
    capability_matrix,
};
use crate::engine::{EngineDetail, EngineSummary, compact_count, poll_engine_summary};
use crate::identity::TrustContextSummary;
use crate::observe::{ObserveSummary, TraceView, filter_traces, poll_observe_summary};
use crate::platform::{self, PlatformServices, density_storage_label, preference_key};
use crate::tools::{ToolRun, mock_runs};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Workspace {
    Observe,
    Trust,
    Engine,
    Tools,
    Settings,
}

impl Workspace {
    const ALL: [Workspace; 5] = [
        Workspace::Observe,
        Workspace::Trust,
        Workspace::Engine,
        Workspace::Tools,
        Workspace::Settings,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Observe => "Observe",
            Self::Trust => "Trust",
            Self::Engine => "Engine",
            Self::Tools => "Tools",
            Self::Settings => "Settings",
        }
    }

    fn test_id(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Trust => "trust",
            Self::Engine => "engine",
            Self::Tools => "tools",
            Self::Settings => "settings",
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
    let mut active = use_signal(|| Workspace::Observe);
    let mut state = use_signal(move || {
        let mut state = DashboardState::mock_ndnrs(platform);
        state.density = initial_density;
        state
    });
    let mut preferences = use_signal(move || initial_preferences.clone());
    let mut last_probe = use_signal(|| None::<ProbeTranscript>);
    let mut last_probe_at = use_signal(|| None::<u64>);
    let mut last_attach_error = use_signal(|| None::<String>);

    let density = state.read().density;
    let density_class = match density {
        Density::Compact => "density-compact",
        Density::Comfortable => "density-comfortable",
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

    rsx! {
        style { "{STYLE}" }
        div { class: "app-shell {density_class}", "data-testid": "dashboard-next-root",
            a { class: "skip-link", href: "#dashboard-next-main", "Skip to workspace" }
            aside { class: "sidebar",
                div { class: "brand",
                    div { class: "brand-mark", "ND" }
                    div {
                        div { class: "brand-title", "ndn-dashboard-next" }
                        div { class: "brand-sub", "browser-first operator console" }
                    }
                }
                nav { class: "nav-list", "aria-label": "Primary workspace navigation",
                    for item in Workspace::ALL {
                        button {
                            class: if workspace == item { "nav-item active" } else { "nav-item" },
                            "data-testid": "nav-{item.test_id()}",
                            "aria-current": if workspace == item { "page" } else { "false" },
                            onclick: move |_| active.set(item),
                            "{item.label()}"
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

                section { class: "workspace",
                    match workspace {
                        Workspace::Observe => rsx! { ObserveView { summary: observe } },
                        Workspace::Trust => rsx! { TrustView { summary: trust } },
                        Workspace::Engine => rsx! { EngineView { summary: engine } },
                        Workspace::Tools => rsx! { ToolsView { runs: tools } },
                        Workspace::Settings => rsx! {
                            SettingsView {
                                state: current.clone(),
                                services,
                                preferences: prefs.clone(),
                                last_probe: probe.clone(),
                                last_probe_at_unix_s: probe_at,
                                last_attach_error: attach_error.clone(),
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
                                                let density = state.read().density;
                                                let mut next = state_from_probe(platform, probe.clone());
                                                next.density = density;
                                                let mut next_prefs = preferences.read().clone();
                                                next_prefs.density = density;
                                                next_prefs.remember_connected(target, 1_717_300_000);
                                                platform::save_preferences(next_prefs.clone());
                                                preferences.set(next_prefs);
                                                last_probe.set(Some(probe.transcript));
                                                last_probe_at.set(Some(1_717_300_000));
                                                last_attach_error.set(None);
                                                state.set(next);
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
                                    let density = state.read().density;
                                    if let Some(target) = preferences
                                        .read()
                                        .saved_targets
                                        .iter()
                                        .find(|target| target.label == "browser in-page engine")
                                        .cloned()
                                    {
                                        let client = MockDashboardClient::new(platform);
                                        if let Ok(probe) = client.probe(&target.attach_target()) {
                                            let mut next = state_from_probe(platform, probe.clone());
                                            next.density = density;
                                            last_probe.set(Some(probe.transcript));
                                            last_probe_at.set(Some(1_717_300_000));
                                            last_attach_error.set(None);
                                            state.set(next);
                                        }
                                    }
                                },
                                on_mock_nfd: move |_| {
                                    let density = state.read().density;
                                    if let Some(target) = preferences
                                        .read()
                                        .saved_targets
                                        .iter()
                                        .find(|target| target.label == "NFD compatibility")
                                        .cloned()
                                    {
                                        let client = MockDashboardClient::new(platform);
                                        if let Ok(probe) = client.probe(&target.attach_target()) {
                                            let mut next = state_from_probe(platform, probe.clone());
                                            next.density = density;
                                            last_probe.set(Some(probe.transcript));
                                            last_probe_at.set(Some(1_717_300_000));
                                            last_attach_error.set(None);
                                            state.set(next);
                                        }
                                    }
                                },
                                on_mock_yanfd: move |_| {
                                    let density = state.read().density;
                                    if let Some(target) = preferences
                                        .read()
                                        .saved_targets
                                        .iter()
                                        .find(|target| target.label == "YaNFD compatibility")
                                        .cloned()
                                    {
                                        let client = MockDashboardClient::new(platform);
                                        if let Ok(probe) = client.probe(&target.attach_target()) {
                                            let mut next = state_from_probe(platform, probe.clone());
                                            next.density = density;
                                            last_probe.set(Some(probe.transcript));
                                            last_probe_at.set(Some(1_717_300_000));
                                            last_attach_error.set(None);
                                            state.set(next);
                                        }
                                    }
                                },
                                on_probe_default: move |_| {
                                    let client = MockDashboardClient::new(platform);
                                    if let Some(target) = client.attach_targets().first().cloned()
                                        && let Ok(probe) = client.probe(&target)
                                    {
                                        let density = state.read().density;
                                        let mut next = state_from_probe(platform, probe.clone());
                                        next.density = density;
                                        last_probe.set(Some(probe.transcript));
                                        last_probe_at.set(Some(1_717_300_000));
                                        last_attach_error.set(None);
                                        state.set(next);
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

#[component]
fn ObserveView(summary: ObserveSummary) -> Element {
    let mut search = use_signal(String::new);
    let query = search.read().clone();
    let filtered = filter_traces(&summary.recent, &query);
    let selected = filtered.first().cloned();
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
                    TraceDetail { trace, bridge_status: summary.bridge_status.clone() }
                } else {
                    EmptyState {
                        title: "No trace selected".to_string(),
                        detail: "Recent spans, PIT fan-out, CS attribution, strategy rationale, and correlated logs will appear here once live span Data is available.".to_string()
                    }
                }
            }
        }
    }
}

#[component]
fn TraceDetail(trace: TraceView, bridge_status: String) -> Element {
    let root = trace.spans.first().cloned();
    let pit_count = trace
        .spans
        .iter()
        .filter(|span| span.name.starts_with("pit."))
        .count();
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
            div { class: "kv", span { "Correlated logs" } strong { "trace-scoped evidence" } }
            div { class: "kv", span { "Export path" } strong { "{bridge_status}" } }
        }
        div { class: "stage-strip live-stage-strip",
            for span in trace.spans.iter().take(6) {
                div { class: "stage ok",
                    strong { "{span.name}" }
                    span { "{span.duration_us} us" }
                }
            }
        }
        div { class: "span-tree", role: "tree", "aria-label": "Trace span tree",
            for span in trace.spans {
                div { class: "span-node", role: "treeitem",
                    div {
                        strong { "{span.name}" }
                        span { class: "mono", "{span.span_id}" }
                    }
                    span { "{span.target}" }
                    span { "{span.status.label()}" }
                }
            }
        }
    }
}

#[component]
fn TrustView(summary: TrustContextSummary) -> Element {
    rsx! {
        div { class: "view-grid", "data-testid": "workspace-trust",
            Panel { title: "Trust context".to_string(),
                div { class: "hero-line",
                    StatusChip { label: summary.posture.label().to_string(), tone: tone_for_trust(summary.posture).to_string() }
                    button { class: "primary-action", "aria-label": "{summary.action_label()}", "{summary.action_label()}" }
                }
                div { class: "detail-table",
                    div { class: "kv", span { "Namespace" } strong { "{summary.namespace}" } }
                    div { class: "kv", span { "Acting as" } strong { "{summary.identity}" } }
                    div { class: "kv", span { "Anchors" } strong { "{summary.anchors}" } }
                    div { class: "kv", span { "Schema rules" } strong { "{summary.schema_rules}" } }
                    div { class: "kv", span { "Pending approvals" } strong { "{summary.pending_approvals}" } }
                }
            }
            Panel { title: "Security model".to_string(),
                div { class: "compact-copy",
                    "Dashboard-next consumes TrustContext, Custodian, SafeBag, and NDNCERT APIs. It presents posture and workflows without owning private key storage or defining trust policy."
                }
            }
        }
    }
}

#[component]
fn EngineView(summary: EngineSummary) -> Element {
    let status = summary.status.clone();
    let store_pit = summary.store_pit.clone();
    let traffic = summary.traffic.clone();
    let face_rows = summary.filter_faces("");
    let route_rows = summary.search_routes("");
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
                    for face in face_rows {
                        div { class: "table-row",
                            span { "{face.id}" }
                            span { "{face.uri}" }
                            span { "{face.state} / {face.scope}" }
                            span { "{face.traffic_label()}" }
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
                    for route in route_rows {
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
            Panel { title: "CS, PIT, Traffic".to_string(),
                if let Some(store_pit) = store_pit {
                    div { class: "metrics-grid",
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

#[component]
fn ToolsView(runs: Vec<ToolRun>) -> Element {
    rsx! {
        div { class: "view-grid tools-grid", "data-testid": "workspace-tools",
            Panel { title: "Network test workbench".to_string(),
                div { class: "tool-actions",
                    for action in ["ping", "peek", "put", "iperf", "trace", "route", "face"] {
                        button { class: "tool-button", "aria-label": "Open {action} tool", "{action}" }
                    }
                }
                div { class: "dense-table",
                    div { class: "table-head", span { "Tool" } span { "Target" } span { "Status" } span { "Result" } }
                    for run in runs.clone() {
                        div { class: "table-row",
                            span { "{run.kind.label()}" }
                            span { "{run.target_name}" }
                            span { "{run.status.label()}" }
                            span { "{run.result.clone().unwrap_or_else(|| \"streaming\".into())}" }
                        }
                    }
                }
            }
            Panel { title: "Latest samples".to_string(),
                for run in runs {
                    div { class: "sample-card",
                        div { class: "row-title", "{run.kind.label()} -> {run.target_name}" }
                        for sample in run.samples {
                            div { class: "kv", span { "{sample.label}" } strong { "{sample.value}" } }
                        }
                    }
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
    on_select_target: EventHandler<String>,
    on_probe_selected: EventHandler<()>,
    on_mock_ndnrs: EventHandler<()>,
    on_mock_browser: EventHandler<()>,
    on_mock_nfd: EventHandler<()>,
    on_mock_yanfd: EventHandler<()>,
    on_probe_default: EventHandler<()>,
) -> Element {
    let selected_id = preferences.selected_target_id.clone();
    let selected_available = preferences
        .selected_target()
        .map(|target| target.platform_status(state.platform).is_available())
        .unwrap_or(false);
    let rows = capability_matrix(&state.profile);

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
                    button { class: "tool-button", "aria-label": "Switch to ndn-rs mock profile", onclick: move |_| on_mock_ndnrs.call(()), "ndn-rs" }
                    button { class: "tool-button", "aria-label": "Switch to browser engine mock profile", onclick: move |_| on_mock_browser.call(()), "browser engine" }
                    button { class: "tool-button", "aria-label": "Switch to NFD mock profile", onclick: move |_| on_mock_nfd.call(()), "NFD" }
                    button { class: "tool-button", "aria-label": "Switch to YaNFD mock profile", onclick: move |_| on_mock_yanfd.call(()), "YaNFD" }
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
                div { class: "compact-copy",
                    "Browser deployment is treated as a static app with browser-safe attach transports. Desktop adds local socket and process workflows while sharing the same core state."
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
  --bg: #0b0e11;
  --bg-rail: #10161a;
  --surface: #151b1e;
  --surface-2: #1b2427;
  --surface-3: #223034;
  --surface-raised: #20282b;
  --border: #334145;
  --border-strong: #4a5e63;
  --text: #edf2ef;
  --muted: #b1bdb8;
  --faint: #7d8b86;
  --accent: #77d7cf;
  --accent-2: #a69df5;
  --blue: #89b7ff;
  --green: #67d08d;
  --amber: #e5b85c;
  --red: #ff7f87;
  --focus: #f2d36b;
  --shadow: rgba(0, 0, 0, .32);
  --nav-w: 224px;
}

* { box-sizing: border-box; }
html, body, #main { margin: 0; min-height: 100%; background: var(--bg); color: var(--text); }
body { font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
button, input, select { font: inherit; }
button { cursor: pointer; }
button:disabled { cursor: not-allowed; opacity: .62; }
button:focus-visible, a:focus-visible, [tabindex]:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: 2px;
  box-shadow: 0 0 0 4px rgba(242, 211, 107, .14);
}

.skip-link {
  position: fixed; left: 10px; top: 10px; z-index: 10; transform: translateY(-160%);
  background: var(--focus); color: #18130a; border-radius: 6px; padding: 7px 10px;
  font-size: 12px; font-weight: 800; text-decoration: none;
}
.skip-link:focus { transform: translateY(0); }

.app-shell {
  min-height: 100vh;
  display: grid;
  grid-template-columns: var(--nav-w) minmax(0, 1fr);
  background:
    linear-gradient(180deg, rgba(119, 215, 207, .035), transparent 34vh),
    var(--bg);
}

.density-compact { --gap: 10px; --pad: 12px; --row: 34px; --font-sm: 12px; --font-xs: 11px; }
.density-comfortable { --gap: 14px; --pad: 16px; --row: 42px; --font-sm: 13px; --font-xs: 12px; }

.sidebar {
  position: sticky;
  top: 0;
  height: 100vh;
  padding: var(--pad);
  border-right: 1px solid var(--border);
  background: var(--bg-rail);
}

.brand { display: flex; gap: 10px; align-items: center; margin-bottom: 18px; }
.brand-mark {
  width: 34px; height: 34px; border: 1px solid var(--border); display: grid; place-items: center;
  background: linear-gradient(135deg, rgba(119, 215, 207, .16), rgba(166, 157, 245, .14));
  color: var(--accent); font-weight: 800; border-radius: 6px;
}
.brand-title { font-size: 13px; font-weight: 700; }
.brand-sub { color: var(--muted); font-size: var(--font-xs); margin-top: 2px; }
.nav-list { display: grid; gap: 4px; }
.nav-item, .bottom-item {
  border: 1px solid transparent; background: transparent; color: var(--muted); text-align: left; padding: 9px 10px;
  border-radius: 6px; font-size: var(--font-sm);
}
.nav-item:hover, .bottom-item:hover { color: var(--text); background: rgba(255, 255, 255, .035); }
.nav-item.active, .bottom-item.active {
  background: var(--surface-2); color: var(--text); border-color: rgba(119, 215, 207, .24);
  box-shadow: inset 3px 0 0 var(--accent);
}

.main { min-width: 0; display: flex; flex-direction: column; }
.main:focus { outline: none; }
.attach-bar {
  position: sticky; top: 0; z-index: 2; min-height: 58px; padding: 8px var(--pad);
  display: flex; align-items: center; gap: var(--gap); justify-content: space-between;
  border-bottom: 1px solid var(--border);
  background: rgba(11, 14, 17, 0.96);
  backdrop-filter: blur(8px);
}
.attach-primary { min-width: 0; }
.attach-label { color: var(--faint); font-size: 10px; text-transform: uppercase; letter-spacing: 0; }
.attach-value { font-weight: 750; font-size: 15px; }
.attach-meta { color: var(--muted); font-size: var(--font-xs); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.chip-row { display: flex; align-items: center; justify-content: flex-end; flex-wrap: wrap; gap: 6px; }
.chip {
  display: inline-flex; min-height: 24px; align-items: center; border-radius: 999px; padding: 2px 8px;
  border: 1px solid var(--border); font-size: var(--font-xs); white-space: nowrap; color: var(--muted);
}
.chip.good { color: var(--green); border-color: rgba(103, 208, 141, .52); background: rgba(103, 208, 141, .10); }
.chip.amber { color: var(--amber); border-color: rgba(229, 184, 92, .52); background: rgba(229, 184, 92, .11); }
.chip.bad { color: var(--red); border-color: rgba(255, 127, 135, .55); background: rgba(255, 127, 135, .10); }
.chip.muted { color: var(--faint); }
.chip.neutral { color: var(--blue); border-color: rgba(137, 183, 255, .42); background: rgba(137, 183, 255, .08); }
.density-toggle, .primary-action, .tool-button {
  min-height: 30px; border-radius: 6px; border: 1px solid var(--border); background: var(--surface-raised);
  color: var(--text); padding: 4px 9px; font-size: var(--font-xs);
}
.density-toggle:hover, .primary-action:hover, .tool-button:hover { border-color: var(--border-strong); background: var(--surface-3); }
.primary-action, .tool-button.primary { border-color: rgba(119, 215, 207, .55); color: var(--accent); }

.workspace { padding: var(--pad); min-width: 0; }
.view-grid { display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(320px, .8fr); gap: var(--gap); align-items: start; }
.observe-grid, .engine-grid, .tools-grid { grid-template-columns: minmax(0, 1fr) minmax(360px, .8fr); }
.settings-grid { grid-template-columns: minmax(380px, 1fr) minmax(420px, 1.05fr); }
.panel {
  min-width: 0; border: 1px solid var(--border); background: var(--surface); border-radius: 8px;
  padding: var(--pad); box-shadow: 0 1px 0 rgba(255,255,255,.03) inset, 0 10px 24px var(--shadow);
}
.panel-title { font-size: 13px; font-weight: 750; margin: 0 0 10px; }
.panel-toolbar, .hero-line, .tool-actions { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-bottom: 10px; }
.mono { font-family: "SF Mono", Consolas, ui-monospace, monospace; font-size: var(--font-xs); color: var(--muted); }
.compact-copy { color: var(--muted); font-size: var(--font-sm); line-height: 1.45; }

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
  grid-template-columns: minmax(0, 1fr) auto auto auto; padding: 8px; border: 1px solid var(--border);
  border-radius: 6px; background: var(--surface-2);
}
.row-title { font-weight: 700; font-size: var(--font-sm); }
.row-sub { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.metric { color: var(--muted); font-size: var(--font-xs); white-space: nowrap; }
.stage-strip { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 5px; margin-bottom: 10px; }
.stage { min-height: 42px; display: grid; place-items: center; border-radius: 6px; border: 1px solid var(--border); font-size: var(--font-xs); }
.live-stage-strip { margin-top: 10px; }
.live-stage-strip .stage { place-items: start; align-content: center; padding: 7px; overflow: hidden; }
.stage strong, .stage span { max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.stage.ok { color: var(--green); border-color: rgba(103, 208, 141, .38); background: rgba(103, 208, 141, .09); }
.span-tree { display: grid; gap: 5px; margin-top: 10px; }
.span-node {
  display: grid; grid-template-columns: minmax(0, 1.3fr) minmax(0, .9fr) auto; gap: 8px; align-items: center;
  min-height: 32px; padding: 6px 8px; border: 1px solid var(--border); border-radius: 6px;
  background: var(--surface-2); font-size: var(--font-xs);
}
.span-node div { min-width: 0; display: grid; gap: 2px; }
.span-node span { color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.detail-table { display: grid; gap: 6px; }
.kv {
  min-height: var(--row); display: flex; align-items: center; justify-content: space-between; gap: 12px;
  border-bottom: 1px solid rgba(48, 57, 70, .75); padding: 4px 0; font-size: var(--font-sm);
}
.kv span { color: var(--muted); }
.kv strong { text-align: right; font-weight: 700; overflow-wrap: anywhere; }
.metrics-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 6px; margin-bottom: 10px; }
.metric-card { padding: 9px; border: 1px solid var(--border); border-radius: 6px; background: var(--surface-2); }
.metric-card span { display: block; color: var(--muted); font-size: var(--font-xs); }
.metric-card strong { display: block; margin-top: 4px; font-size: 18px; }
.dense-table { display: grid; border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
.table-head, .table-row { display: grid; grid-template-columns: .6fr minmax(0, 2fr) 1fr 1fr; min-height: var(--row); align-items: center; }
.table-head { background: var(--surface-3); color: var(--muted); font-size: 10px; text-transform: uppercase; }
.table-row { background: var(--surface-2); font-size: var(--font-sm); border-top: 1px solid var(--border); }
.table-row:hover { background: #223035; }
.table-head span, .table-row span { padding: 0 8px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.engine-table.route-table .table-head, .engine-table.route-table .table-row {
  grid-template-columns: minmax(0, 1.8fr) .8fr .5fr .5fr .9fr;
}
.strategy-table { margin-bottom: 10px; }
.strategy-table .table-head, .strategy-table .table-row {
  grid-template-columns: minmax(0, 1fr) minmax(0, 1.7fr) .7fr;
}
.source-grid { display: grid; gap: 5px; margin-top: 10px; }
.source-row {
  display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 8px;
  min-height: 28px; border-bottom: 1px solid rgba(48, 57, 70, .75);
}
.engine-detail { margin-top: 8px; border-top: 1px solid var(--border); padding-top: 8px; }
.tool-actions { align-items: stretch; }
.tool-button { text-transform: none; }
.inline-alert {
  margin-bottom: 10px; border: 1px solid rgba(255, 127, 135, .45); border-radius: 6px;
  background: rgba(255, 127, 135, .09); color: var(--red); padding: 8px 10px; font-size: var(--font-sm);
}
.target-list { display: grid; gap: 6px; }
.target-list.compact { gap: 5px; }
.target-row {
  min-width: 0; display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; align-items: center;
  border: 1px solid var(--border); border-radius: 6px; background: var(--surface-2); padding: 6px;
}
.target-row.active { border-color: rgba(119, 215, 207, .58); box-shadow: inset 3px 0 0 var(--accent); }
.target-main {
  min-width: 0; display: grid; gap: 3px; border: 0; background: transparent; color: var(--text); text-align: left; padding: 2px;
}
.target-meta { display: flex; flex-wrap: wrap; gap: 8px; color: var(--muted); font-size: var(--font-xs); }
.target-badges { display: flex; gap: 5px; flex-wrap: wrap; justify-content: flex-end; }
.recent-target {
  display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; align-items: center;
  min-height: var(--row); border-bottom: 1px solid rgba(48, 57, 70, .75); padding: 3px 0;
}
.capability-matrix {
  display: grid; border: 1px solid var(--border); border-radius: 6px; overflow: hidden; margin-bottom: 10px;
}
.matrix-head, .matrix-row {
  display: grid; grid-template-columns: minmax(120px, .85fr) minmax(90px, .55fr) minmax(180px, 1fr) minmax(180px, 1.25fr);
  align-items: center;
}
.matrix-head { min-height: 30px; background: var(--surface-3); color: var(--muted); font-size: 10px; text-transform: uppercase; }
.matrix-row { min-height: var(--row); background: var(--surface-2); border-top: 1px solid var(--border); font-size: var(--font-sm); }
.matrix-head span, .matrix-row span { min-width: 0; padding: 6px 8px; overflow-wrap: anywhere; }
.probe-outcome { color: var(--accent); font-family: inherit; font-size: var(--font-xs); }
.probe-time { color: var(--faint); font-family: inherit; font-size: var(--font-xs); }
.empty-state {
  min-height: 120px; display: grid; align-content: center; gap: 6px; color: var(--muted);
  border: 1px dashed var(--border); border-radius: 6px; padding: 14px; font-size: var(--font-sm);
}
.empty-state strong { color: var(--text); }
.bottom-nav { display: none; }

@media (max-width: 980px) {
  .app-shell { grid-template-columns: 1fr; padding-bottom: 56px; }
  .sidebar { display: none; }
  .view-grid, .observe-grid, .engine-grid, .tools-grid { grid-template-columns: 1fr; }
  .settings-grid { grid-template-columns: 1fr; }
  .bottom-nav {
    position: fixed; left: 0; right: 0; bottom: 0; z-index: 3; display: grid; grid-template-columns: repeat(5, 1fr);
    border-top: 1px solid var(--border); background: rgba(11, 14, 17, 0.97); padding: 5px;
  }
  .bottom-item { text-align: center; padding: 8px 2px; font-size: 11px; }
  .bottom-item.active { box-shadow: inset 0 3px 0 var(--accent); }
}

@media (max-width: 640px) {
  .attach-bar { align-items: stretch; flex-direction: column; gap: 7px; }
  .chip-row { justify-content: flex-start; }
  .workspace { padding: 8px; }
  .panel { border-radius: 6px; }
  .trace-row { grid-template-columns: 1fr 1fr; }
  .span-node { grid-template-columns: 1fr; }
  .stage-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .metrics-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .table-head, .table-row { grid-template-columns: .7fr minmax(0, 1.6fr) .8fr .9fr; }
  .table-head span, .table-row span { padding: 0 5px; }
  .engine-table.route-table .table-head, .engine-table.route-table .table-row,
  .strategy-table .table-head, .strategy-table .table-row { grid-template-columns: 1fr; }
  .target-row { grid-template-columns: 1fr; }
  .target-badges { justify-content: flex-start; }
  .matrix-head { display: none; }
  .matrix-row { grid-template-columns: 1fr; gap: 2px; padding: 6px; }
  .matrix-row span { padding: 2px 0; }
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
