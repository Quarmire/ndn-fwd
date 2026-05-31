//! Compose — "what I publish" on the attached engine.
//!
//! The synthesis note (§8) splits the dashboard into three buckets; Compose is
//! the publishing axis. Producer/dataset/RDR authoring surfaces will grow here.
//! For now it renders the honest, already-polled signal of what this engine
//! serves: RIB prefixes registered by a local application or client
//! (route origin `app`/`client`), as opposed to prefixes learned from routing
//! (`nlsr`/`dvr`/`static`). That is precisely the set of names a producer on
//! this engine has announced it will answer.

use dioxus::prelude::*;

use crate::app::AppCtx;
use crate::resizable::use_col_widths;

/// Route origins that mean "a producer/client on this engine registered this
/// prefix" rather than "this prefix was learned from a routing protocol".
fn is_local_publish(origin: u64) -> bool {
    matches!(origin, 0 /* app */ | 65 /* client */)
}

#[component]
pub fn Compose() -> Element {
    let ctx = use_context::<AppCtx>();
    let rib_entries = ctx.rib_entries.read();

    // (prefix, origin-label, face_id) for every locally-published route.
    let published: Vec<(String, &'static str, u64)> = rib_entries
        .iter()
        .flat_map(|entry| {
            entry
                .routes
                .iter()
                .filter(|r| is_local_publish(r.origin))
                .map(move |r| {
                    let origin = if r.origin == 0 { "app" } else { "client" };
                    (entry.prefix.clone(), origin, r.face_id)
                })
        })
        .collect();

    // Prefix is variable-length; origin + face columns are fixed.
    let cols = use_col_widths(&[360.0, 120.0, 120.0]);

    rsx! {
        div { class: "section",
            div { class: "section-title", "Published Prefixes" }
            p { class: "muted", style: "margin:0 0 12px;font-size:13px;",
                "Names this engine answers because a local producer or client registered them. "
                "Prefixes learned from routing appear under Engine → Routing."
            }
            if published.is_empty() {
                div { class: "empty",
                    "No locally-published prefixes. A producer registers a prefix when it serves data on this engine."
                }
            } else {
                {cols.overlay()}
                div { class: "resizable-wrap",
                    table { class: "resizable",
                        {cols.colgroup()}
                        thead {
                            tr {
                                th { "Prefix" {cols.handle(0)} }
                                th { "Origin" {cols.handle(1)} }
                                th { class: "col-actions", "Face" }
                            }
                        }
                        tbody {
                            for (prefix, origin, face_id) in published.iter() {
                                tr {
                                    td { class: "mono", "{prefix}" }
                                    td { class: "mono", "{origin}" }
                                    td { class: "mono", "{face_id}" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
