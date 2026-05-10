// rsx! macro expansion hides function calls from the dead_code lint.
#![allow(dead_code)]
use dioxus::prelude::*;

use crate::app::{AppCtx, DashCmd};
use crate::types::RibRoute;

fn origin_label(origin: u64) -> String {
    match origin {
        0 => "app".to_string(),
        64 => "autoreg".to_string(),
        65 => "client".to_string(),
        66 => "autoconf".to_string(),
        127 => "dvr".to_string(),
        128 => "nlsr".to_string(),
        129 => "prefix-ann".to_string(),
        255 => "static".to_string(),
        n => n.to_string(),
    }
}

fn flags_label(route: &RibRoute) -> String {
    route.flags_label()
}

#[component]
pub fn Routes() -> Element {
    let ctx = use_context::<AppCtx>();
    let routes = ctx.routes.read();
    let rib_entries = ctx.rib_entries.read();
    let faces = ctx.faces.read();

    let mut new_prefix: Signal<String> = use_signal(String::new);
    let mut new_face_id: Signal<String> = use_signal(String::new);
    let mut new_cost: Signal<String> = use_signal(|| "10".to_string());

    rsx! {
        // ── FIB table ────────────────────────────────────────────────────────
        div { class: "section",
            div { class: "section-title", "FIB — Forwarding Information Base" }
            if routes.is_empty() {
                div { class: "empty", "No entries in FIB." }
            } else {
                table {
                    thead {
                        tr {
                            th { "Prefix" }
                            th { "Face ID" }
                            th { "Remote URI" }
                            th { "Cost" }
                            th { "" }
                        }
                    }
                    tbody {
                        for entry in routes.iter() {
                            {
                                let prefix = entry.prefix.clone();
                                let first_face = entry.nexthops.first().map(|nh| nh.face_id);
                                rsx! {
                                    for nh in entry.nexthops.iter() {
                                        {
                                            let face_id = nh.face_id;
                                            let cost = nh.cost;
                                            let remote_uri = faces.iter()
                                                .find(|f| f.face_id == face_id)
                                                .and_then(|f| f.remote_uri.as_deref())
                                                .unwrap_or("—")
                                                .to_string();
                                            let pfx = prefix.clone();
                                            rsx! {
                                                tr {
                                                    td { class: "mono", "{pfx}" }
                                                    td { class: "mono", "{face_id}" }
                                                    td { class: "mono", "{remote_uri}" }
                                                    td { class: "mono", "{cost}" }
                                                    td {
                                                        if Some(face_id) == first_face {
                                                            button {
                                                                class: "btn btn-danger btn-sm",
                                                                onclick: move |_| {
                                                                    ctx.cmd.send(DashCmd::RouteRemove {
                                                                        prefix: pfx.clone(),
                                                                        face_id,
                                                                    });
                                                                },
                                                                "Remove"
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

            // ── Add route form ───────────────────────────────────────────────
            div { class: "form-row",
                div { class: "form-group",
                    label { r#for: "rt-prefix", "Name Prefix" }
                    input {
                        id: "rt-prefix",
                        r#type: "text",
                        placeholder: "/ndn",
                        value: "{new_prefix}",
                        oninput: move |e| new_prefix.set(e.value()),
                    }
                }
                div { class: "form-group",
                    label { r#for: "rt-face", "Face ID" }
                    input {
                        id: "rt-face",
                        r#type: "number",
                        placeholder: "1",
                        value: "{new_face_id}",
                        style: "width:80px",
                        oninput: move |e| new_face_id.set(e.value()),
                    }
                }
                div { class: "form-group",
                    label { r#for: "rt-cost", "Cost" }
                    input {
                        id: "rt-cost",
                        r#type: "number",
                        value: "{new_cost}",
                        style: "width:80px",
                        oninput: move |e| new_cost.set(e.value()),
                    }
                }
                button {
                    class: "btn btn-primary",
                    onclick: move |_| {
                        let prefix  = new_prefix.read().trim().to_string();
                        let face_id = new_face_id.read().trim().parse::<u64>().unwrap_or(0);
                        let cost    = new_cost.read().trim().parse::<u64>().unwrap_or(10);
                        if !prefix.is_empty() {
                            ctx.cmd.send(DashCmd::RouteAdd { prefix, face_id, cost });
                            new_prefix.set(String::new());
                            new_face_id.set(String::new());
                        }
                    },
                    "Add Route"
                }
            }
        }

        // ── RIB table ────────────────────────────────────────────────────────
        div { class: "section",
            div { class: "section-title", "RIB — Routing Information Base" }
            if rib_entries.is_empty() {
                div { class: "empty", "No entries in RIB (or router does not expose rib/list)." }
            } else {
                table {
                    thead {
                        tr {
                            th { "Prefix" }
                            th { "Face ID" }
                            th { "Origin" }
                            th { "Cost" }
                            th { "Flags" }
                            th { "Expiry" }
                        }
                    }
                    tbody {
                        for entry in rib_entries.iter() {
                            for route in entry.routes.iter() {
                                {
                                    let face_id = route.face_id;
                                    let origin = origin_label(route.origin);
                                    let flags = flags_label(route);
                                    let expiry = route.expiration_period
                                        .map(|ms| format!("{}s", ms / 1000))
                                        .unwrap_or_else(|| "—".to_string());
                                    rsx! {
                                        tr {
                                            td { class: "mono", "{entry.prefix}" }
                                            td { class: "mono", "{face_id}" }
                                            td { class: "mono", "{origin}" }
                                            td { class: "mono", "{route.cost}" }
                                            td { class: "mono", "{flags}" }
                                            td { class: "mono", "{expiry}" }
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
