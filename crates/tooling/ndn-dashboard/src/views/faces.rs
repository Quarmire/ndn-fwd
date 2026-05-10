// rsx! macro expansion hides function calls from the dead_code lint.
#![allow(dead_code)]
use dioxus::prelude::*;

use crate::app::{AppCtx, DashCmd};

fn link_type_label(v: u64) -> &'static str {
    match v {
        0 => "p2p",
        1 => "multi-access",
        254 => "ad-hoc",
        _ => "?",
    }
}

fn scope_label(v: u64) -> &'static str {
    if v == 1 { "local" } else { "non-local" }
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

#[component]
pub fn Faces() -> Element {
    let ctx = use_context::<AppCtx>();
    let faces = ctx.faces.read();

    let mut new_uri: Signal<String> = use_signal(String::new);
    // Which face ID has the expanded detail row open (None = none).
    let mut expanded: Signal<Option<u64>> = use_signal(|| None);

    rsx! {
        // ── Face table ──────────────────────────────────────────────────────
        div { class: "section",
            div { class: "section-title", "Active Faces" }
            if faces.is_empty() {
                div { class: "empty", "No faces registered." }
            } else {
                table {
                    thead {
                        tr {
                            th { "ID" }
                            th { "Kind" }
                            th { "Remote URI" }
                            th { "Persistency" }
                            th { "Scope" }
                            th { "Link" }
                            th { "↓ Int" }
                            th { "↑ Int" }
                            th { "↓ Data" }
                            th { "↑ Data" }
                            th { "↓ Bytes" }
                            th { "↑ Bytes" }
                            th { "" }
                        }
                    }
                    tbody {
                        for face in faces.iter() {
                            {
                                let face_id = face.face_id;
                                let is_expanded = *expanded.read() == Some(face_id);
                                let local_uri = face.local_uri.clone().unwrap_or_default();
                                let mtu = face.mtu;
                                let n_in_nacks = face.n_in_nacks;
                                let n_out_nacks = face.n_out_nacks;
                                let link = link_type_label(face.link_type);
                                let scope = scope_label(face.face_scope);
                                let in_bytes = fmt_bytes(face.n_in_bytes);
                                let out_bytes = fmt_bytes(face.n_out_bytes);
                                rsx! {
                                    tr {
                                        onclick: move |_| {
                                            let cur = *expanded.read();
                                            expanded.set(if cur == Some(face_id) { None } else { Some(face_id) });
                                        },
                                        style: "cursor:pointer;",
                                        td { class: "mono", "{face.face_id}" }
                                        td {
                                            span {
                                                class: "{face.kind_badge_class()}",
                                                "{face.kind_label()}"
                                            }
                                        }
                                        td { class: "mono",
                                            "{face.remote_uri.as_deref().unwrap_or(\"—\")}"
                                        }
                                        td { "{face.persistency}" }
                                        td { class: "mono", "{scope}" }
                                        td { class: "mono", "{link}" }
                                        td { class: "mono", "{face.n_in_interests}" }
                                        td { class: "mono", "{face.n_out_interests}" }
                                        td { class: "mono", "{face.n_in_data}" }
                                        td { class: "mono", "{face.n_out_data}" }
                                        td { class: "mono", "{in_bytes}" }
                                        td { class: "mono", "{out_bytes}" }
                                        td {
                                            button {
                                                class: "btn btn-danger btn-sm",
                                                onclick: move |e| {
                                                    e.stop_propagation();
                                                    ctx.cmd.send(DashCmd::FaceDestroy(face_id));
                                                },
                                                "Destroy"
                                            }
                                        }
                                    }
                                    // ── Expandable detail row ───────────────
                                    if is_expanded {
                                        tr {
                                            td { colspan: "13",
                                                style: "background:var(--bg-secondary);padding:8px 16px;font-size:12px;",
                                                div { style: "display:flex;gap:32px;flex-wrap:wrap;",
                                                    div {
                                                        div { style: "font-weight:600;margin-bottom:4px;", "URIs" }
                                                        div { class: "mono",
                                                            "remote: {face.remote_uri.as_deref().unwrap_or(\"—\")}"
                                                        }
                                                        div { class: "mono",
                                                            "local:  {local_uri}"
                                                        }
                                                        if let Some(m) = mtu {
                                                            div { class: "mono", "mtu:    {m} B" }
                                                        }
                                                    }
                                                    div {
                                                        div { style: "font-weight:600;margin-bottom:4px;", "Counters" }
                                                        div { class: "mono",
                                                            "in:  interests={face.n_in_interests}  data={face.n_in_data}  nacks={n_in_nacks}  bytes={in_bytes}"
                                                        }
                                                        div { class: "mono",
                                                            "out: interests={face.n_out_interests}  data={face.n_out_data}  nacks={n_out_nacks}  bytes={out_bytes}"
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

            // ── Create face form ─────────────────────────────────────────────
            div { class: "form-row",
                div { class: "form-group", style: "flex:1;",
                    label { r#for: "face-uri", "Face URI" }
                    input {
                        id: "face-uri",
                        r#type: "text",
                        placeholder: "udp4://192.168.1.1:6363",
                        value: "{new_uri}",
                        oninput: move |e| new_uri.set(e.value()),
                        onkeydown: move |e| {
                            if e.key() == Key::Enter {
                                let uri = new_uri.read().trim().to_string();
                                if !uri.is_empty() {
                                    ctx.cmd.send(DashCmd::FaceCreate(uri));
                                    new_uri.set(String::new());
                                }
                            }
                        },
                    }
                }
                button {
                    class: "btn btn-primary",
                    onclick: move |_| {
                        let uri = new_uri.read().trim().to_string();
                        if !uri.is_empty() {
                            ctx.cmd.send(DashCmd::FaceCreate(uri));
                            new_uri.set(String::new());
                        }
                    },
                    "Create Face"
                }
            }
            div { style: "margin-top:8px;font-size:12px;color:var(--text-muted);",
                "Supported: udp4://<ip>:6363  tcp4://<ip>:6363  ws://<ip>:9696  unix:///path  shm://name  ether://<iface>"
            }
            div { style: "margin-top:4px;font-size:11px;color:var(--text-muted);",
                "Click a row to expand URIs and detailed counters."
            }
        }
    }
}
