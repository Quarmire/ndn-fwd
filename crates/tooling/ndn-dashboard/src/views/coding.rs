//! Read-only view for `/localhost/nfd/coding/list`.
//!
//! Fetches via `MgmtClient::coding_list()` on first mount and on
//! manual refresh. The set/unset form is intentionally not wired
//! yet — adding it requires plumbing new `DashCmd` variants and
//! AppCtx polling, which is its own follow-up. Operators use
//! `ndn-ctl` (or the management protocol directly) to install
//! policies; this view lets them inspect what's installed.

use dioxus::prelude::*;

use ndn_config::ControlParameters;
use ndn_ipc::MgmtClient;

fn role_label(code: Option<u8>) -> &'static str {
    use ndn_config::control_parameters::fec_role;
    match code {
        Some(c) if c == fec_role::PRODUCED => "produced",
        Some(c) if c == fec_role::CONSUMED => "consumed",
        Some(_) => "unknown",
        None => "—",
    }
}

fn field_label(code: Option<u8>) -> &'static str {
    use ndn_config::control_parameters::fec_field;
    match code {
        Some(c) if c == fec_field::GF8 => "gf8",
        Some(_) => "unknown",
        None => "gf8",
    }
}

async fn fetch_policies() -> Result<Vec<ControlParameters>, String> {
    let path = crate::forwarder_profile::selected().1;
    let path = path.to_string_lossy().into_owned();
    let client = MgmtClient::connect(path).await.map_err(|e| e.to_string())?;
    client.coding_list().await.map_err(|e| e.to_string())
}

#[component]
pub fn Coding() -> Element {
    // `tick` bumps to force a re-fetch on Refresh click.
    let mut tick: Signal<u32> = use_signal(|| 0u32);
    let policies = use_resource(move || async move {
        let _ = tick.read();
        fetch_policies().await
    });

    rsx! {
        div { class: "section",
            div { class: "section-title", "Coding Policies" }
            p { class: "muted",
                "Producer-side systematic FEC policies, fetched from "
                code { "/localhost/nfd/coding/list" }
                ". Manage via "
                code { "/localhost/nfd/coding/set" }
                " and "
                code { "/localhost/nfd/coding/unset" }
                " (or the "
                code { "ndn-ctl" }
                " equivalent)."
            }
            div { class: "form-row", style: "margin-bottom:0.5rem;",
                button {
                    class: "btn btn-secondary btn-sm",
                    onclick: move |_| { tick.with_mut(|t| *t += 1); },
                    "Refresh"
                }
            }
            match policies.read_unchecked().as_ref() {
                None => rsx! { div { class: "empty", "Loading…" } },
                Some(Err(e)) => rsx! {
                    div { class: "error", "Failed to fetch: {e}" }
                },
                Some(Ok(entries)) if entries.is_empty() => rsx! {
                    div { class: "empty",
                        "No coding policies installed. The "
                        code { "fec" }
                        " feature must be enabled and "
                        code { "[[coding.policy]]" }
                        " configured in the forwarder TOML, or installed "
                        "at runtime via mgmt."
                    }
                },
                Some(Ok(entries)) => rsx! {
                    table {
                        thead {
                            tr {
                                th { "Prefix" }
                                th { "Role" }
                                th { "K" }
                                th { "N" }
                                th { "Field" }
                            }
                        }
                        tbody {
                            for cp in entries.iter() {
                                tr {
                                    td { class: "mono",
                                        "{cp.name.as_ref().map(|n| n.to_string()).unwrap_or_else(|| String::from(\"—\"))}"
                                    }
                                    td { "{role_label(cp.fec_role)}" }
                                    td { class: "mono",
                                        "{cp.fec_k.map(|v| v.to_string()).unwrap_or_else(|| String::from(\"—\"))}"
                                    }
                                    td { class: "mono",
                                        "{cp.fec_n.map(|v| v.to_string()).unwrap_or_else(|| String::from(\"—\"))}"
                                    }
                                    td { "{field_label(cp.fec_field)}" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
