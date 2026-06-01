//! Trust Context summary — the friendly entry point to the Identity bucket.
//!
//! Read-only. Frames the node's current security state as the two questions a
//! fleet operator actually asks: *who does this node trust* (anchors + CA) and
//! *who is it* (local identities, with cert expiry up front), with links into
//! the detailed Security tabs for management. Everything here comes from data
//! the dashboard already polls.
//!
//! Deliberately honest about its limits (see the drone-fleet note): it shows
//! the trust *roots*, not a roster of remote fleet members' certs (that needs
//! CA enumeration that isn't wired), and it does not yet show context-sync
//! bundle distribution state.

use std::collections::BTreeMap;

use dioxus::prelude::*;

use crate::app::AppCtx;
use crate::types::SecurityKeyInfo;
use crate::views::View;

fn goto_security() {
    *crate::app::ACTIVE_VIEW.write() = View::Security;
}

#[component]
pub fn TrustContext() -> Element {
    let ctx = use_context::<AppCtx>();
    let anchors = ctx.security_anchors.read();
    let keys = ctx.security_keys.read();
    let ca = ctx.ca_info.read();
    // Prefer the dashboard's own provisioned operator identity (what it signs
    // as) over the forwarder's reported identity, which is often ephemeral.
    let _ = crate::app_shared::KEYRING_GEN.read();
    let op_identity = crate::operator_keyring::active_identity_name();
    let active = op_identity
        .clone()
        .unwrap_or_else(|| ctx.identity_name.read().clone());
    let ephemeral = op_identity.is_none() && *ctx.identity_is_ephemeral.read();
    let machine =
        crate::views::engine_pill::live_machine_trust(ephemeral, !active.trim().is_empty());

    // Group local keys by their owning identity.
    let mut identities: BTreeMap<&str, Vec<&SecurityKeyInfo>> = BTreeMap::new();
    for k in keys.iter() {
        identities.entry(k.identity_name()).or_default().push(k);
    }

    rsx! {
        div { class: "section",
            div { class: "section-title", "Trust Context" }
            p { class: "muted", style: "margin:0;font-size:13px;",
                "Who this node trusts, and who it is. Open "
                button {
                    class: "inspector-link",
                    style: "display:inline;padding:0;",
                    onclick: move |_| goto_security(),
                    "Security"
                }
                " for full management."
            }
        }

        // ── This machine (where your key lives) ────────────────────────
        div { class: "section",
            div { class: "section-title", "This machine" }
            dl { class: "inspector-kv",
                dt { "Signing key" }
                dd {
                    "{machine.residence}"
                    if machine.persists {
                        span { class: "badge badge-gray", style: "margin-left:8px;font-size:9px;", "persists" }
                    } else {
                        span { class: "badge badge-green", style: "margin-left:8px;font-size:9px;", "not stored" }
                    }
                }
                if machine.prompts {
                    dt { "Per-action" }
                    dd { "Each signature needs an explicit confirmation (fob touch / popup)." }
                }
            }
            if let Some(caveat) = machine.caveat.as_ref() {
                div { class: "readonly-banner", style: "margin-top:10px;",
                    span { class: "readonly-banner-icon", "⚠" }
                    span { "{caveat}" }
                }
            }
            p { class: "muted", style: "margin:8px 0 0;font-size:12px;",
                "Signing with a key that never touches this machine (a phone or hardware fob holds it) is planned but not yet available — for an untrusted machine, use an ephemeral identity so nothing persists."
            }
        }

        // ── Trusted roots ──────────────────────────────────────────────
        div { class: "section",
            div { class: "section-hdr",
                span { class: "section-title", "Trusted roots" }
                button {
                    class: "btn btn-secondary btn-sm",
                    onclick: move |_| goto_security(),
                    "Manage anchors →"
                }
            }
            if anchors.is_empty() {
                div { class: "empty",
                    "No trust anchors. This node validates nothing by default (zero-trust) — adopt an anchor to start trusting a context."
                }
            } else {
                p { class: "muted", style: "margin:0 0 8px;font-size:12px;",
                    "Roots that validate incoming data. Compare the fingerprint out-of-band before trusting."
                }
                for a in anchors.iter() {
                    div { class: "mono", style: "padding:3px 0;font-size:13px;", "{a.name}" }
                }
            }
        }

        // ── Certificate authority ──────────────────────────────────────
        div { class: "section",
            div { class: "section-title", "Certificate authority" }
            if let Some(ca) = ca.as_ref() {
                dl { class: "inspector-kv",
                    dt { "Prefix" }   dd { class: "mono", "{ca.ca_prefix}" }
                    if !ca.ca_info.is_empty() {
                        dt { "Info" }  dd { "{ca.ca_info}" }
                    }
                    dt { "Max validity" } dd { "{ca.max_validity_days} days" }
                    dt { "Challenges" }   dd { "{ca.challenges.join(\", \")}" }
                }
            } else {
                div { class: "empty",
                    "No CA reachable on this context. Enrolled certs require a NDNCERT CA; adopted anchors do not."
                }
            }
        }

        // ── Your identities (the operator keyring — portable) ──────────
        div { class: "section",
            div { class: "section-hdr",
                span { class: "section-title", "Your identities" }
                button {
                    class: "btn btn-secondary btn-sm",
                    onclick: move |_| goto_security(),
                    "Manage identities →"
                }
            }
            {
                let op = crate::operator_keyring::list_identities();
                if op.is_empty() {
                    rsx! {
                        div { class: "empty",
                            "No signing identities yet — generate or import one in Security → Identities."
                        }
                    }
                } else {
                    rsx! {
                        table {
                            thead { tr { th { "Identity" } th { "Algorithm" } th { "Fingerprint" } } }
                            tbody {
                                for id in op.iter() {
                                    tr {
                                        td { class: "mono",
                                            "{id.identity}"
                                            if id.active {
                                                span { class: "badge badge-green", style: "margin-left:8px;font-size:9px;", "active signer" }
                                            }
                                        }
                                        td { "{id.algorithm}" }
                                        td { class: "mono", style: "font-size:11px;", "{id.fingerprint}" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // ── This appliance's keys (the forwarder's own keystore) ───────
        div { class: "section",
            div { class: "section-title", "This appliance's keys" }
            if identities.is_empty() {
                div { class: "empty", "This forwarder holds no keys of its own (it may sign with an ephemeral key)." }
            } else {
                table {
                    thead {
                        tr {
                            th { "Identity" }
                            th { "Keys" }
                            th { "Cert" }
                            th { "Validity" }
                        }
                    }
                    tbody {
                        for (id, ks) in identities.iter() {
                            {
                                let is_active = *id == active;
                                let n_keys = ks.len();
                                let with_cert = ks.iter().filter(|k| k.has_cert).count();
                                // Expiry badge from a cert-bearing key, else the first.
                                let badge_key = ks.iter().find(|k| k.has_cert).copied().or_else(|| ks.first().copied());
                                let (badge_class, badge_label) = badge_key
                                    .map(|k| k.expiry_badge())
                                    .unwrap_or(("badge badge-gray", "—".to_string()));
                                rsx! {
                                    tr {
                                        td { class: "mono",
                                            "{id}"
                                            if is_active {
                                                span { class: "badge badge-green", style: "margin-left:8px;font-size:9px;",
                                                    if ephemeral { "active · ephemeral" } else { "active" }
                                                }
                                            }
                                        }
                                        td { "{n_keys}" }
                                        td {
                                            if with_cert > 0 {
                                                span { style: "color:var(--green);", "✓ {with_cert}" }
                                            } else {
                                                span { style: "color:var(--text-faint);", "none" }
                                            }
                                        }
                                        td { span { class: "{badge_class}", "{badge_label}" } }
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
