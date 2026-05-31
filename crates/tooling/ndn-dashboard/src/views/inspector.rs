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
use crate::views::View;

/// The entity currently shown in the inspector. One variant today; extends to
/// `Route`, `Identity`, `CsEntry`, … as each surface is migrated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectedEntity {
    Face(u64),
}

impl SelectedEntity {
    /// The face id, when a face is selected.
    pub fn face_id(self) -> Option<u64> {
        match self {
            SelectedEntity::Face(id) => Some(id),
        }
    }

    /// The nav view this selection is relevant to. The inspector only renders
    /// when the active view matches, so navigating away hides stale detail
    /// without having to clear the selection from every nav handler.
    pub fn relevant_view(self) -> View {
        match self {
            SelectedEntity::Face(_) => View::Overview,
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
    let selected = *SELECTED_ENTITY.read();
    let Some(sel) = selected else {
        return rsx! {};
    };
    // Hide the pane when the user has navigated away from the entity's view.
    if *crate::app::ACTIVE_VIEW.read() != sel.relevant_view() {
        return rsx! {};
    }
    match sel {
        SelectedEntity::Face(id) => rsx! { FaceInspector { face_id: id } },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn face_selection_carries_id_and_view() {
        let sel = SelectedEntity::Face(7);
        assert_eq!(sel.face_id(), Some(7));
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
