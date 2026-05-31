//! Right-hand inspector pane — the third pane of the master–detail shell
//! (design note §3, Eagle spine). The center pane lists entities; clicking one
//! selects it here and the inspector shows its full detail, replacing
//! per-entity modals / inline expand rows.
//!
//! Slice 3 pilots this with Faces: the Overview "Active Faces" table shows five
//! columns, but a face carries far more (scope, link type, MTU, per-direction
//! interest/data/nack/byte counters). The inspector surfaces all of it without
//! widening the table. Selection is one global signal so any future producer
//! (routes, identities, CS entries) feeds the same pane.

use dioxus::prelude::*;

use crate::app::{AppCtx, DashCmd};
use crate::views::KNOWN_STRATEGIES;
use crate::views::View;
use crate::views::traffic::render_throughput_bars;

/// The entity currently shown in the inspector. Extends to `Identity`,
/// `CsEntry`, … as each surface is migrated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectedEntity {
    Face(u64),
    /// A FIB/RIB route, keyed by its name prefix.
    Route(String),
}

impl SelectedEntity {
    /// The face id, when a face is selected.
    pub fn face_id(&self) -> Option<u64> {
        match self {
            SelectedEntity::Face(id) => Some(*id),
            _ => None,
        }
    }

    /// The route prefix, when a route is selected.
    pub fn route_prefix(&self) -> Option<&str> {
        match self {
            SelectedEntity::Route(p) => Some(p.as_str()),
            _ => None,
        }
    }

    /// The nav view this selection is relevant to. The inspector only renders
    /// when the active view matches, so navigating away hides stale detail
    /// without having to clear the selection from every nav handler.
    pub fn relevant_view(&self) -> View {
        match self {
            // Both the Active Faces and FIB Routes tables live on Overview.
            SelectedEntity::Face(_) | SelectedEntity::Route(_) => View::Overview,
        }
    }
}

/// Selected entity for the inspector pane. `None` = nothing selected, pane
/// renders empty (collapsed). Global so the center tables and the pane share it.
pub static SELECTED_ENTITY: GlobalSignal<Option<SelectedEntity>> = Signal::global(|| None);

/// Clear any current selection (used by row toggles and the close button).
pub fn clear_selection() {
    *SELECTED_ENTITY.write() = None;
}

/// Whether the inspector pane is actually showing right now — a selection
/// exists and the active view matches its `relevant_view`. The shell uses this
/// to reserve bottom-sheet space on mobile so obscured rows stay scrollable.
pub fn inspector_visible() -> bool {
    SELECTED_ENTITY
        .read()
        .as_ref()
        .map(|s| s.relevant_view() == *crate::app::ACTIVE_VIEW.read())
        .unwrap_or(false)
}

fn fmt_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1_048_576 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else if n < 1_073_741_824 {
        format!("{:.1} MiB", n as f64 / 1_048_576.0)
    } else {
        format!("{:.2} GiB", n as f64 / 1_073_741_824.0)
    }
}

fn link_type_label(v: u64) -> &'static str {
    match v {
        0 => "point-to-point",
        1 => "multi-access",
        254 => "ad-hoc",
        _ => "unknown",
    }
}

fn scope_label(v: u64) -> &'static str {
    if v == 1 { "local" } else { "non-local" }
}

#[component]
pub fn Inspector() -> Element {
    let selected = SELECTED_ENTITY.read().clone();
    let Some(sel) = selected else {
        return rsx! {};
    };
    // Hide the pane when the user has navigated away from the entity's view.
    if *crate::app::ACTIVE_VIEW.read() != sel.relevant_view() {
        return rsx! {};
    }
    match sel {
        SelectedEntity::Face(id) => rsx! { FaceInspector { face_id: id } },
        SelectedEntity::Route(prefix) => rsx! { RouteInspector { prefix } },
    }
}

#[component]
fn FaceInspector(face_id: u64) -> Element {
    let ctx = use_context::<AppCtx>();
    let faces = ctx.faces.read();
    let face = faces.iter().find(|f| f.face_id == face_id);

    rsx! {
        aside { class: "inspector",
            div { class: "inspector-header",
                span { class: "inspector-title", "Face {face_id}" }
                button {
                    class: "inspector-close",
                    title: "Close",
                    onclick: move |_| clear_selection(),
                    "✕"
                }
            }
            match face {
                None => rsx! {
                    div { class: "inspector-body",
                        div { class: "inspector-empty", "Face {face_id} is no longer present." }
                    }
                },
                Some(face) => {
                    let remote = face.remote_uri.clone().unwrap_or_else(|| "—".into());
                    let local = face.local_uri.clone().unwrap_or_else(|| "—".into());
                    let kind_class = face.kind_badge_class();
                    let kind = face.kind_label();
                    let persistency = face.persistency.to_string();
                    let scope = scope_label(face.face_scope);
                    let link = link_type_label(face.link_type);
                    let mtu = face.mtu;
                    let in_bytes = fmt_bytes(face.n_in_bytes);
                    let out_bytes = fmt_bytes(face.n_out_bytes);
                    let n_in_int = face.n_in_interests;
                    let n_out_int = face.n_out_interests;
                    let n_in_data = face.n_in_data;
                    let n_out_data = face.n_out_data;
                    let n_in_nacks = face.n_in_nacks;
                    let n_out_nacks = face.n_out_nacks;
                    // NFD FaceFlags bits (read-only): runtime-mutable via
                    // faces/update, surfaced here as on/off status.
                    let local_fields = face.flags & 0b001 != 0;
                    let lp_reliability = face.flags & 0b010 != 0;
                    let cong_marking = face.flags & 0b100 != 0;
                    // Routes whose nexthop is this face — cross-nav targets.
                    let routes_via: Vec<String> = ctx
                        .routes
                        .read()
                        .iter()
                        .filter(|e| e.nexthops.iter().any(|nh| nh.face_id == face_id))
                        .map(|e| e.prefix.clone())
                        .collect();
                    // Recent per-face throughput (same data as the traffic view).
                    let tp_read = ctx.face_throughput.read();
                    let sparkline = tp_read
                        .get(&face_id)
                        .filter(|h| !h.is_empty())
                        .map(|h| render_throughput_bars(h, 44));
                    rsx! {
                        div { class: "inspector-body",
                            div { class: "inspector-section",
                                span { class: "inspector-section-title", "Identity" }
                                span { class: "{kind_class}", "{kind}" }
                                dl { class: "inspector-kv",
                                    dt { "Remote" }   dd { class: "mono", "{remote}" }
                                    dt { "Local" }    dd { class: "mono", "{local}" }
                                    dt { "Persistency" } dd { "{persistency}" }
                                    dt { "Scope" }    dd { class: "mono", "{scope}" }
                                    dt { "Link type" } dd { class: "mono", "{link}" }
                                    if let Some(m) = mtu {
                                        dt { "MTU" }  dd { class: "mono", "{m} B" }
                                    }
                                }
                            }
                            div { class: "inspector-section",
                                span { class: "inspector-section-title", "Counters" }
                                table { class: "inspector-counters",
                                    thead {
                                        tr { th { "" } th { "In" } th { "Out" } }
                                    }
                                    tbody {
                                        tr { td { "Interests" } td { class: "mono", "{n_in_int}" } td { class: "mono", "{n_out_int}" } }
                                        tr { td { "Data" }      td { class: "mono", "{n_in_data}" } td { class: "mono", "{n_out_data}" } }
                                        tr { td { "Nacks" }     td { class: "mono", "{n_in_nacks}" } td { class: "mono", "{n_out_nacks}" } }
                                        tr { td { "Bytes" }     td { class: "mono", "{in_bytes}" } td { class: "mono", "{out_bytes}" } }
                                    }
                                }
                            }
                            div { class: "inspector-section",
                                span { class: "inspector-section-title", "Link service" }
                                dl { class: "inspector-kv",
                                    dt { "Local fields" }
                                    dd { class: if local_fields { "flag-on" } else { "flag-off" },
                                        if local_fields { "on" } else { "off" }
                                    }
                                    dt { "LP reliability" }
                                    dd { class: if lp_reliability { "flag-on" } else { "flag-off" },
                                        if lp_reliability { "on" } else { "off" }
                                    }
                                    dt { "Congestion marking" }
                                    dd { class: if cong_marking { "flag-on" } else { "flag-off" },
                                        if cong_marking { "on" } else { "off" }
                                    }
                                }
                            }
                            if let Some(spark) = sparkline {
                                div { class: "inspector-section",
                                    span { class: "inspector-section-title", "Throughput" }
                                    {spark}
                                }
                            }
                            div { class: "inspector-section",
                                span { class: "inspector-section-title", "Routes via this face" }
                                if routes_via.is_empty() {
                                    div { class: "inspector-empty", "No routes forward through this face." }
                                } else {
                                    div { class: "inspector-links",
                                        for prefix in routes_via.iter() {
                                            {
                                                let p = prefix.clone();
                                                rsx! {
                                                    button {
                                                        class: "inspector-link mono",
                                                        title: "Inspect this route",
                                                        onclick: move |_| {
                                                            *SELECTED_ENTITY.write() = Some(SelectedEntity::Route(p.clone()));
                                                        },
                                                        "{prefix}"
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        div { class: "inspector-footer",
                            button {
                                class: "btn btn-danger btn-sm",
                                onclick: move |_| {
                                    ctx.cmd.send(DashCmd::FaceDestroy(face_id));
                                    clear_selection();
                                },
                                "Destroy face"
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn RouteInspector(prefix: String) -> Element {
    let ctx = use_context::<AppCtx>();
    let routes = ctx.routes.read();
    let rib = ctx.rib_entries.read();
    let strategies = ctx.strategies.read();

    let fib = routes.iter().find(|e| e.prefix == prefix);
    let rib_entry = rib.iter().find(|e| e.prefix == prefix);
    let current_strat_uri = strategies
        .iter()
        .find(|s| s.prefix == prefix)
        .map(|s| s.strategy.clone());
    let present = fib.is_some() || rib_entry.is_some();
    let prefix_close = prefix.clone();
    let strat_prefix = prefix.clone();
    let add_prefix = prefix.clone();

    // Add-nexthop form state.
    let mut nh_face: Signal<String> = use_signal(String::new);
    let mut nh_cost: Signal<String> = use_signal(|| "10".to_string());

    rsx! {
        aside { class: "inspector",
            div { class: "inspector-header",
                span { class: "inspector-title", "Route" }
                button {
                    class: "inspector-close",
                    title: "Close",
                    onclick: move |_| clear_selection(),
                    "✕"
                }
            }
            div { class: "inspector-body",
                if !present {
                    div { class: "inspector-empty", "Route {prefix_close} is no longer present." }
                } else {
                    div { class: "inspector-section",
                        span { class: "inspector-section-title", "Prefix" }
                        div { class: "mono", style: "word-break:break-all;", "{prefix}" }
                    }
                    div { class: "inspector-section",
                        span { class: "inspector-section-title", "Strategy" }
                        select {
                            class: "axis-select",
                            onchange: move |e| {
                                let val = e.value();
                                if val == "__unset__" || val.is_empty() {
                                    ctx.cmd.send(DashCmd::StrategyUnset(strat_prefix.clone()));
                                } else {
                                    ctx.cmd.send(DashCmd::StrategySet { prefix: strat_prefix.clone(), strategy: val });
                                }
                            },
                            option {
                                value: "__unset__",
                                selected: current_strat_uri.is_none(),
                                "— default —"
                            }
                            for (uri, label) in KNOWN_STRATEGIES {
                                option {
                                    value: "{uri}",
                                    selected: current_strat_uri.as_deref() == Some(*uri),
                                    "{label}"
                                }
                            }
                        }
                    }
                    // FIB nexthops — click a face to inspect it; Remove drops
                    // that specific nexthop (the table's Remove only hit the
                    // first one).
                    if let Some(entry) = fib {
                        div { class: "inspector-section",
                            span { class: "inspector-section-title", "FIB nexthops" }
                            if entry.nexthops.is_empty() {
                                div { class: "inspector-empty", "none" }
                            } else {
                                for nh in entry.nexthops.iter() {
                                    {
                                        let fid = nh.face_id;
                                        let cost = nh.cost;
                                        let rm_prefix = prefix.clone();
                                        rsx! {
                                            div { class: "inspector-nh",
                                                button {
                                                    class: "inspector-link mono",
                                                    title: "Inspect face {fid}",
                                                    onclick: move |_| {
                                                        *SELECTED_ENTITY.write() = Some(SelectedEntity::Face(fid));
                                                    },
                                                    "face {fid}"
                                                }
                                                span { class: "mono", style: "color:var(--text-muted);", "cost {cost}" }
                                                button {
                                                    class: "btn btn-danger btn-sm",
                                                    onclick: move |_| ctx.cmd.send(DashCmd::RouteRemove {
                                                        prefix: rm_prefix.clone(),
                                                        face_id: fid,
                                                    }),
                                                    "Remove"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        div { class: "inspector-section",
                            span { class: "inspector-section-title", "Add nexthop" }
                            div { class: "inspector-addnh",
                                input {
                                    r#type: "text",
                                    placeholder: "face id",
                                    value: "{nh_face}",
                                    oninput: move |e| nh_face.set(e.value()),
                                }
                                input {
                                    r#type: "text",
                                    placeholder: "cost",
                                    value: "{nh_cost}",
                                    oninput: move |e| nh_cost.set(e.value()),
                                }
                                button {
                                    class: "btn btn-primary btn-sm",
                                    onclick: move |_| {
                                        let parsed = nh_face.read().trim().parse::<u64>();
                                        let cost = nh_cost.read().trim().parse::<u64>().unwrap_or(10);
                                        if let Ok(fid) = parsed {
                                            ctx.cmd.send(DashCmd::RouteAdd {
                                                prefix: add_prefix.clone(),
                                                face_id: fid,
                                                cost,
                                            });
                                            nh_face.set(String::new());
                                        }
                                    },
                                    "Add"
                                }
                            }
                        }
                    }
                    // RIB routes — origin, flags, and expiration the table hides.
                    if let Some(entry) = rib_entry {
                        div { class: "inspector-section",
                            span { class: "inspector-section-title", "RIB routes" }
                            table { class: "inspector-counters",
                                thead {
                                    tr { th { "Origin" } th { "Cost" } th { "Flags" } th { "Expires" } }
                                }
                                tbody {
                                    for r in entry.routes.iter() {
                                        {
                                            let expires = r.expiration_period
                                                .map(|ms| format!("{} s", ms / 1000))
                                                .unwrap_or_else(|| "—".into());
                                            rsx! {
                                                tr {
                                                    td { class: "mono", "{r.origin_label()}" }
                                                    td { class: "mono", "{r.cost}" }
                                                    td { class: "mono", "{r.flags_label()}" }
                                                    td { class: "mono", "{expires}" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn face_selection_carries_id_and_view() {
        let sel = SelectedEntity::Face(7);
        assert_eq!(sel.face_id(), Some(7));
        assert_eq!(sel.route_prefix(), None);
        assert_eq!(sel.relevant_view(), View::Overview);
    }

    #[test]
    fn route_selection_carries_prefix_and_view() {
        let sel = SelectedEntity::Route("/example/uav".into());
        assert_eq!(sel.route_prefix(), Some("/example/uav"));
        assert_eq!(sel.face_id(), None);
        assert_eq!(sel.relevant_view(), View::Overview);
    }

    #[test]
    fn byte_formatting_scales() {
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(2048), "2.0 KiB");
        assert!(fmt_bytes(5_000_000).ends_with("MiB"));
    }

    #[test]
    fn link_and_scope_labels() {
        assert_eq!(link_type_label(0), "point-to-point");
        assert_eq!(link_type_label(254), "ad-hoc");
        assert_eq!(scope_label(1), "local");
        assert_eq!(scope_label(0), "non-local");
    }
}
