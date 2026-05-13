//! Read-only view for `/localhost/nfd/rate-limit/list`.
//!
//! Same pattern as `coding`: on-demand fetch via `MgmtClient`. The
//! set/unset UI is a follow-up.

use dioxus::prelude::*;

use ndn_config::ControlParameters;
use ndn_ipc::MgmtClient;

fn direction_label(code: Option<u8>) -> &'static str {
    use ndn_config::control_parameters::rl_direction;
    match code {
        Some(c) if c == rl_direction::INBOUND => "inbound",
        Some(c) if c == rl_direction::OUTBOUND => "outbound",
        Some(_) => "unknown",
        None => "—",
    }
}

fn overflow_label(code: Option<u8>) -> &'static str {
    use ndn_config::control_parameters::rl_overflow;
    match code {
        Some(c) if c == rl_overflow::NACK => "nack",
        Some(c) if c == rl_overflow::DROP => "drop",
        Some(c) if c == rl_overflow::QUEUE => "queue",
        Some(_) => "unknown",
        None => "—",
    }
}

async fn fetch_cells() -> Result<Vec<ControlParameters>, String> {
    let path = crate::forwarder_profile::selected().1;
    let path = path.to_string_lossy().into_owned();
    let client = MgmtClient::connect(path).await.map_err(|e| e.to_string())?;
    client.rate_limit_list().await.map_err(|e| e.to_string())
}

#[component]
pub fn RateLimit() -> Element {
    let mut tick: Signal<u32> = use_signal(|| 0u32);
    let cells = use_resource(move || async move {
        let _ = tick.read();
        fetch_cells().await
    });

    rsx! {
        div { class: "section",
            div { class: "section-title", "Rate-Limit Cells" }
            p { class: "muted",
                "Admission-control cells, fetched from "
                code { "/localhost/nfd/rate-limit/list" }
                ". The "
                code { "Overflow events" }
                " column is the running per-cell denial counter."
            }
            div { class: "form-row", style: "margin-bottom:0.5rem;",
                button {
                    class: "btn btn-secondary btn-sm",
                    onclick: move |_| { tick.with_mut(|t| *t += 1); },
                    "Refresh"
                }
            }
            match cells.read_unchecked().as_ref() {
                None => rsx! { div { class: "empty", "Loading…" } },
                Some(Err(e)) => rsx! {
                    div { class: "error", "Failed to fetch: {e}" }
                },
                Some(Ok(entries)) if entries.is_empty() => rsx! {
                    div { class: "empty",
                        "No rate-limit cells installed. The "
                        code { "rate-limit" }
                        " feature must be enabled and "
                        code { "[[rate-limit.policy]]" }
                        " configured in the forwarder TOML, or "
                        "installed at runtime via mgmt."
                    }
                },
                Some(Ok(entries)) => rsx! {
                    table {
                        thead {
                            tr {
                                th { "Face" }
                                th { "Prefix" }
                                th { "Dir" }
                                th { "Interest pps" }
                                th { "Burst" }
                                th { "Data bps" }
                                th { "Overflow" }
                                th { "Events" }
                            }
                        }
                        tbody {
                            for cp in entries.iter() {
                                tr {
                                    td { class: "mono",
                                        "{cp.face_id.map(|v| v.to_string()).unwrap_or_else(|| String::from(\"*\"))}"
                                    }
                                    td { class: "mono",
                                        "{cp.name.as_ref().map(|n| n.to_string()).unwrap_or_else(|| String::from(\"*\"))}"
                                    }
                                    td { "{direction_label(cp.rl_direction)}" }
                                    td { class: "mono",
                                        "{cp.rl_interest_pps.map(|v| v.to_string()).unwrap_or_else(|| String::from(\"—\"))}"
                                    }
                                    td { class: "mono",
                                        "{cp.rl_interest_burst.map(|v| v.to_string()).unwrap_or_else(|| String::from(\"—\"))}"
                                    }
                                    td { class: "mono",
                                        "{cp.rl_data_bps.map(|v| v.to_string()).unwrap_or_else(|| String::from(\"—\"))}"
                                    }
                                    td { "{overflow_label(cp.rl_overflow)}" }
                                    td { class: "mono",
                                        "{cp.count.map(|v| v.to_string()).unwrap_or_else(|| String::from(\"0\"))}"
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
