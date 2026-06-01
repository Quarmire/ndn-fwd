//! Security view — identity management, trust anchors, certificate chain,
//! DID explorer, NDNCERT CA panel, YubiKey integration, and the mgmt-access
//! policy editor.

use crate::app::{AppCtx, DashCmd, ToastLevel, push_toast};
use crate::edu_gloss::EduGloss;
use crate::types::{
    AnchorInfo, CaInfo, ChallengeAttestation, FailureDiagnosis, MgmtAccessPolicySnapshot,
    SchemaRuleApplied, SchemaRuleInfo, SecurityKeyInfo, TrustChainStep, TrustValidationResult,
    TrustVerdict, ValidationStats,
};
use crate::views::onboarding::encode_did_ndn;
use crate::views::security_did::{
    DidDocumentPanel, DidLensToggle, DidResolutionL2Frame, IdentityInspectorLens, ResolveAnyDidBox,
    did_doc_view_for_identity,
};
use dioxus::prelude::*;
use std::collections::VecDeque;

const TAB_IDENTITIES: u8 = 0;
const TAB_TRUST: u8 = 1;
const TAB_CHAIN: u8 = 2;
const TAB_DID: u8 = 3;
const TAB_CA: u8 = 4;
const TAB_YUBIKEY: u8 = 5;
const TAB_MGMT_ACCESS: u8 = 7;
const TAB_AUDIT: u8 = 8;

#[component]
pub fn Security() -> Element {
    let ctx = use_context::<AppCtx>();
    let keys = ctx.security_keys.read();
    let anchors = ctx.security_anchors.read();
    let schema = ctx.schema_rules.read();
    let is_ephemeral = *ctx.identity_is_ephemeral.read();
    let identity_name = ctx.identity_name.read().clone();
    let pib_path = ctx.identity_pib_path.read().clone();

    let mut active_tab: Signal<u8> = use_signal(|| TAB_IDENTITIES);
    let new_key_name: Signal<String> = use_signal(String::new);

    {
        let pending = *crate::app_shared::ACTIVE_SECURITY_TAB.read();
        if let Some(tab_id) = pending {
            active_tab.set(tab_id);
            *crate::app_shared::ACTIVE_SECURITY_TAB.write() = None;
        }
    }

    let tabs: &[(&str, u8)] = &[
        ("Identities", TAB_IDENTITIES),
        ("Trust & Schema", TAB_TRUST),
        ("Cert Chain", TAB_CHAIN),
        ("DID", TAB_DID),
        ("CA / NDNCERT", TAB_CA),
        ("YubiKey", TAB_YUBIKEY),
        ("Mgmt Access", TAB_MGMT_ACCESS),
        ("Audit log", TAB_AUDIT),
    ];

    rsx! {
        div { class: "section",

            if is_ephemeral && !identity_name.is_empty() {
                div {
                    style: "margin-bottom:16px;padding:12px 14px;\
                            background:var(--yellow-bg,#2a2400)22;\
                            border:1px solid var(--yellow,#f5c518)66;\
                            border-radius:6px;font-size:12px;",
                    div {
                        style: "font-weight:600;color:var(--yellow,#f5c518);margin-bottom:6px;",
                        "Ephemeral identity active — keys will not survive a restart"
                    }
                    div { style: "color:var(--text-muted);margin-bottom:8px;",
                        "The router is signing data as "
                        span { class: "mono", "{identity_name}" }
                        " using an in-memory key. This identity is not persisted."
                    }
                    div { style: "color:var(--text-muted);font-size:11px;",
                        "To use a persistent identity, set "
                        span { class: "mono", "[security] identity" }
                        " and "
                        span { class: "mono", "pib_path" }
                        " in your router config, or use the "
                        strong { "Config" }
                        " tab. Run "
                        span { class: "mono", "ndn-sec keygen <name>" }
                        " to create keys first."
                    }
                }
            }

            if !is_ephemeral && !identity_name.is_empty() {
                div {
                    style: "margin-bottom:16px;padding:8px 12px;\
                            background:var(--green-bg,#002a00)22;\
                            border:1px solid var(--green,#3fb950)44;\
                            border-radius:6px;font-size:11px;\
                            display:flex;gap:12px;align-items:center;",
                    span { class: "badge badge-green", "persistent" }
                    span { style: "color:var(--text-muted);",
                        "Identity: "
                        span { class: "mono", "{identity_name}" }
                        if let Some(ref p) = pib_path {
                            span { style: "margin-left:8px;", "  PIB: " span { class: "mono", "{p}" } }
                        }
                    }
                }
            }

            // Sticky sub-nav: the resolve-DID box, SafeBag picker,
            // and tab bar stay visible while the active-tab body
            // scrolls below them. `.view-sticky-nav` clamps total
            // height + scrolls internally if the operator has many
            // tabs / a long picker label on a short viewport.
            div { class: "view-sticky-nav",
                ResolveAnyDidBox {}
                crate::views::safebag_import::SafeBagImportPicker {}
                div { class: "tab-bar",
                    for (label, tab_i) in tabs {
                        {
                            let tab_i = *tab_i;
                            let is_active = *active_tab.read() == tab_i;
                            rsx! {
                                button {
                                    class: if is_active { "btn btn-primary btn-sm" } else { "btn btn-secondary btn-sm" },
                                    onclick: move |_| active_tab.set(tab_i),
                                    "{label}"
                                }
                            }
                        }
                    }
                }
            }

            match *active_tab.read() {
                TAB_IDENTITIES => rsx! { IdentitiesTab { keys: keys.clone(), new_key_name } },
                TAB_TRUST      => rsx! { TrustTab { anchors: anchors.clone(), rules: schema.clone() } },
                TAB_CHAIN      => rsx! { ChainTab { keys: keys.clone(), anchors: anchors.clone() } },
                TAB_DID        => rsx! { DidTab { keys: keys.clone() } },
                TAB_CA         => rsx! { CaTab {} },
                TAB_YUBIKEY    => rsx! { YubikeyTab {} },
                TAB_MGMT_ACCESS=> rsx! { MgmtAccessTab {} },
                TAB_AUDIT      => rsx! { AuditLogTab {} },
                _              => rsx! {},
            }

            if *ctx.trust_inspector_open.read() {
                TrustPathInspector {}
            }
        }
    }
}

#[component]
fn IdentitiesTab(keys: Vec<SecurityKeyInfo>, mut new_key_name: Signal<String>) -> Element {
    let ctx = use_context::<AppCtx>();
    let mut selected: Signal<Option<String>> = use_signal(|| None);
    let groups = group_keys_by_identity(&keys);

    let initial = groups.first().map(|(name, _)| name.clone());
    use_effect(move || {
        if selected.read().is_none()
            && let Some(name) = initial.clone()
        {
            selected.set(Some(name));
        }
    });

    let selected_name = selected.read().clone();
    let active_identity_name = ctx.identity_name.read().clone();
    let is_ephemeral = *ctx.identity_is_ephemeral.read();

    rsx! {
        div { class: "section-title", "Identities" }

        // Education card — §9 EduGloss seam.
        div { class: "edu-card",
            div { style: "display:flex;gap:12px;align-items:flex-start;",
                div { style: "font-size:28px;flex-shrink:0;", "🪪" }
                div {
                    div { style: "font-size:13px;font-weight:600;color:var(--accent);margin-bottom:4px;",
                        EduGloss { term: "Identity" }
                        " · "
                        EduGloss { term: "Key" }
                        " · "
                        EduGloss { term: "Cert" }
                    }
                    div { style: "font-size:12px;color:var(--text-muted);line-height:1.6;",
                        "Each "
                        EduGloss { term: "Identity" }
                        " owns one or more keys; each key may carry a "
                        EduGloss { term: "Cert" }
                        " that binds it to a validity window. Click a node on the left to inspect its keys and certs."
                    }
                }
            }
        }

        // ── Your identities (the operator keyring — portable) ──────────
        crate::views::identity_export::OperatorIdentityPanel {}
        crate::views::identity_export::PreprovisionPanel {}
        div {
            style: "display:flex;flex-wrap:wrap;gap:8px;margin:6px 0 24px;",
            crate::views::safebag_import::SafeBagImportPicker {}
            button {
                class: "btn btn-secondary",
                onclick: move |_| {
                    crate::app_shared::ENROLLMENT_WIZARD_STATE.write().open = true;
                },
                "+ Join via NDNCERT"
            }
        }

        // ── This appliance's keys (the forwarder's own keystore) ───────
        div { class: "section-title", style: "font-size:13px;margin-top:8px;",
            "This appliance's keys"
        }
        div { style: "font-size:11px;color:var(--text-muted);margin-bottom:10px;",
            "Keys held by the forwarder you're attached to — its own signing identity, "
            "separate from yours above."
        }

        if keys.is_empty() {
            div { class: "empty",
                "This forwarder holds no keys of its own (it may sign with an ephemeral key, or have no security configured)."
            }
        } else {
            div { style: "display:grid;grid-template-columns:minmax(260px,320px) 1fr;gap:16px;align-items:start;",
                IdentityTree {
                    groups: groups.clone(),
                    selected: selected_name.clone(),
                    active_identity_name: active_identity_name.clone(),
                    on_select: move |name: String| selected.set(Some(name)),
                }

                {
                    let inspected = selected_name
                        .as_ref()
                        .and_then(|name| groups.iter().find(|(n, _)| n == name).map(|(_, keys)| (name.clone(), keys.clone())));
                    match inspected {
                        Some((name, group_keys)) => rsx! {
                            IdentityInspector {
                                identity_name: name.clone(),
                                keys: group_keys,
                                is_active_identity: name == active_identity_name,
                                is_active_ephemeral: is_ephemeral,
                            }
                        },
                        None => rsx! {
                            div { class: "empty", "Select an identity from the tree to inspect its keys and certs." }
                        },
                    }
                }
            }
        }

        div { class: "form-row", style: "margin-top:14px;",
            div { class: "form-group",
                label { "Generate a key in the forwarder's keystore" }
                input {
                    r#type: "text",
                    placeholder: "/ndn/myrouter/key",
                    value: "{new_key_name}",
                    oninput: move |e| new_key_name.set(e.value()),
                    style: "width:320px;",
                }
            }
            button {
                class: "btn btn-secondary",
                onclick: move |_| {
                    let name = new_key_name.read().trim().to_string();
                    if !name.is_empty() {
                        ctx.cmd.send(DashCmd::SecurityGenerate(name));
                        new_key_name.set(String::new());
                    }
                },
                "Generate (forwarder)"
            }
        }
    }
}

fn group_keys_by_identity(keys: &[SecurityKeyInfo]) -> Vec<(String, Vec<SecurityKeyInfo>)> {
    use std::collections::BTreeMap;
    let mut grouped: BTreeMap<String, Vec<SecurityKeyInfo>> = BTreeMap::new();
    for k in keys {
        grouped
            .entry(k.identity_name().to_owned())
            .or_default()
            .push(k.clone());
    }
    for (_, ks) in grouped.iter_mut() {
        ks.sort_by(|a, b| a.key_id().cmp(b.key_id()));
    }
    grouped.into_iter().collect()
}

#[component]
fn IdentityTree(
    groups: Vec<(String, Vec<SecurityKeyInfo>)>,
    selected: Option<String>,
    active_identity_name: String,
    on_select: EventHandler<String>,
) -> Element {
    rsx! {
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px;min-height:280px;",
            div { style: "font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;margin-bottom:8px;",
                "Identity tree"
            }
            for (id_name, group_keys) in groups.iter() {
                {
                    let id_name_owned = id_name.clone();
                    let is_selected = selected.as_deref() == Some(id_name.as_str());
                    let is_active = id_name == &active_identity_name;
                    let row_bg = if is_selected { "var(--accent-dim)" } else { "transparent" };
                    let row_border = if is_selected { "var(--accent-solid)" } else { "transparent" };
                    rsx! {
                        div {
                            style: "border:1px solid {row_border};background:{row_bg};border-radius:6px;padding:6px 8px;margin-bottom:4px;cursor:pointer;",
                            onclick: move |_| on_select.call(id_name_owned.clone()),
                            div { style: "display:flex;gap:6px;align-items:center;",
                                span { style: "font-size:13px;", "🌐" }
                                span { class: "mono", style: "font-size:12px;color:var(--text);flex:1;word-break:break-all;", "{id_name}" }
                                if is_active {
                                    span { class: "badge badge-green", style: "font-size:9px;", "active" }
                                }
                            }
                            div { style: "margin-top:4px;padding-left:18px;",
                                for k in group_keys.iter() {
                                    {
                                        let kid = k.key_id().to_owned();
                                        let has_cert = k.has_cert;
                                        rsx! {
                                            div {
                                                style: "display:flex;gap:6px;align-items:center;padding:2px 0;font-size:11px;color:var(--text-muted);",
                                                span { "{key_glyph(has_cert)}" }
                                                span { class: "mono", "KEY/{kid}" }
                                                if has_cert {
                                                    span { style: "color:var(--green);", "·" }
                                                    span { style: "font-size:10px;color:var(--green);", "cert" }
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
            if groups.is_empty() {
                div { class: "empty", style: "padding:8px;font-size:11px;", "No identities to display." }
            }
        }
    }
}

fn key_glyph(has_cert: bool) -> &'static str {
    if has_cert { "●" } else { "○" }
}

#[component]
fn IdentityInspector(
    identity_name: String,
    keys: Vec<SecurityKeyInfo>,
    is_active_identity: bool,
    is_active_ephemeral: bool,
) -> Element {
    let ctx = use_context::<AppCtx>();
    let active_certs = keys.iter().filter(|k| k.has_cert).count();
    let total_keys = keys.len();

    let lens: Signal<IdentityInspectorLens> = use_signal(|| IdentityInspectorLens::KeysCerts);

    rsx! {
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px;",
            div { style: "display:flex;justify-content:space-between;align-items:flex-start;gap:8px;margin-bottom:10px;",
                div {
                    div { class: "mono", style: "font-size:14px;color:var(--text);word-break:break-all;", "{identity_name}" }
                    div { style: "margin-top:4px;display:flex;gap:6px;flex-wrap:wrap;font-size:11px;",
                        if is_active_identity && !is_active_ephemeral {
                            span { class: "badge badge-green", "active · persistent" }
                        }
                        if is_active_identity && is_active_ephemeral {
                            span { class: "badge badge-yellow", "active · ephemeral" }
                        }
                        if !is_active_identity {
                            span { class: "badge badge-gray", "not active" }
                        }
                        span { class: "badge badge-blue", "{total_keys} key{plural(total_keys)}" }
                        span { class: "badge badge-blue", "{active_certs} cert{plural(active_certs)}" }
                    }
                }
                DidLensToggle { lens }
            }

            match *lens.read() {
                IdentityInspectorLens::KeysCerts => rsx! {
                    if keys.is_empty() {
                        div { class: "empty", "This identity has no keys." }
                    } else {
                        for k in keys.iter() {
                            {
                                let k_owned = k.clone();
                                rsx! {
                                    CertCard {
                                        info: k_owned,
                                        on_delete: move |name: String| {
                                            ctx.cmd.send(DashCmd::SecurityKeyDelete(name));
                                        },
                                    }
                                }
                            }
                        }
                    }
                },
                IdentityInspectorLens::DidDocument => rsx! {
                    DidDocumentPanel { doc: did_doc_view_for_identity(&identity_name, &keys) }
                },
            }
        }
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

#[component]
fn CertCard(info: SecurityKeyInfo, on_delete: EventHandler<String>) -> Element {
    let ctx = use_context::<AppCtx>();
    let name = info.name.clone();
    let name_for_delete = name.clone();
    let name_for_trace = name.clone();
    let kid = info.key_id().to_owned();
    let (badge_class, badge_label) = info.expiry_badge();
    let has_cert = info.has_cert;
    let valid_until_s = info.valid_until_unix_s();
    let valid_from_s = info.valid_from_unix_s();
    let now_s = now_unix_s_opt();

    rsx! {
        div { style: "border:1px solid var(--border);border-radius:6px;padding:12px;margin-top:10px;",
            div { style: "display:flex;justify-content:space-between;gap:8px;align-items:center;margin-bottom:6px;",
                div {
                    span { class: "mono", style: "font-size:12px;color:var(--text);", "KEY/{kid}" }
                    span { style: "margin-left:8px;font-size:11px;color:var(--text-muted);",
                        if has_cert { "active cert" } else { "no cert" }
                    }
                }
                span { class: "{badge_class}", "{badge_label}" }
            }

            div { class: "mono", style: "font-size:10px;color:var(--text-muted);word-break:break-all;margin-bottom:8px;", "{name}" }

            ValidityTimeline {
                start_unix_s: valid_from_s,
                end_unix_s: valid_until_s,
                now_unix_s: now_s,
                alert_within_days: 30,
            }

            div { style: "display:flex;gap:6px;flex-wrap:wrap;margin-top:10px;",
                button {
                    class: "btn btn-secondary btn-sm",
                    onclick: {
                        let identity = info.identity_name().to_owned();
                        move |_| {
                            let keys = ctx.security_keys.read().clone();
                            let identity = identity.clone();
                            let current_keys: Vec<_> = keys
                                .into_iter()
                                .filter(|k| k.identity_name() == identity)
                                .collect();
                            let mut st = crate::app_shared::KEY_ROTATION_STATE.write();
                            st.open = true;
                            st.identity_name = identity;
                            st.current_keys = current_keys;
                        }
                    },
                    "Renew"
                }
                button {
                    class: "btn btn-secondary btn-sm",
                    onclick: move |_| push_toast(
                        "Forwarder-held keys can't be exported over the wire. \
                         To export an identity, generate it under \"Operator identity \
                         (in dashboard)\" and use its Export SafeBag.",
                        ToastLevel::Info,
                    ),
                    "Export SafeBag"
                }
                button {
                    class: "btn btn-secondary btn-sm",
                    onclick: move |_| push_toast(
                        "Phase C: §5 sub-flow — set-as-active ceremony",
                        ToastLevel::Info,
                    ),
                    "Set as active"
                }
                button {
                    class: "btn btn-secondary btn-sm",
                    "data-tooltip": "§4.2 TrustPathInspector — walk the chain from this cert up to an anchor",
                    onclick: move |_| {
                        ctx.cmd.send(DashCmd::SecurityValidateTrace(name_for_trace.clone()));
                        let mut open = ctx.trust_inspector_open;
                        open.set(true);
                    },
                    "Trace ↑"
                }
                button {
                    class: "btn btn-danger btn-sm",
                    onclick: move |_| on_delete.call(name_for_delete.clone()),
                    "Delete"
                }
            }
        }
    }
}

/// Renders the cert's issued window with a "now" marker; degrades to an
/// endpoint-only gauge when `start_unix_s` is `None`.
#[component]
fn ValidityTimeline(
    start_unix_s: Option<u64>,
    end_unix_s: Option<u64>,
    now_unix_s: Option<u64>,
    alert_within_days: u64,
) -> Element {
    let Some(end) = end_unix_s else {
        return rsx! {
            div { style: "padding:6px 8px;border-radius:4px;background:var(--surface);border:1px solid var(--border-subtle);font-size:11px;color:var(--text-muted);",
                "No expiry on this cert (permanent, or no cert present)."
            }
        };
    };

    let now = now_unix_s.unwrap_or(end);
    let alert_secs = alert_within_days.saturating_mul(86_400);

    let (fill_pct, fill_color, end_status) = match start_unix_s {
        Some(start) if end > start => {
            let span = end - start;
            let elapsed = now.saturating_sub(start).min(span);
            let pct = ((elapsed as f64 / span as f64) * 100.0).clamp(0.0, 100.0);
            let remaining = end.saturating_sub(now);
            let color = if remaining == 0 {
                "var(--red,#f85149)"
            } else if remaining < alert_secs {
                "var(--yellow,#f5c518)"
            } else {
                "var(--green,#3fb950)"
            };
            (pct, color, expiry_label(now, end))
        }
        _ => {
            let remaining = end.saturating_sub(now);
            let pct = if remaining == 0 {
                100.0
            } else if remaining < alert_secs {
                100.0 - (remaining as f64 / alert_secs as f64) * 100.0
            } else {
                10.0
            };
            let color = if remaining == 0 {
                "var(--red,#f85149)"
            } else if remaining < alert_secs {
                "var(--yellow,#f5c518)"
            } else {
                "var(--green,#3fb950)"
            };
            (pct, color, expiry_label(now, end))
        }
    };

    let start_label = start_unix_s
        .map(format_unix_date)
        .unwrap_or_else(|| "—".into());
    let end_label = format_unix_date(end);
    let fill_pct_int = fill_pct.round() as i64;

    rsx! {
        div { style: "border:1px solid var(--border-subtle);border-radius:4px;padding:8px;background:var(--surface);",
            div { style: "display:flex;justify-content:space-between;font-size:10px;color:var(--text-muted);margin-bottom:4px;",
                span { "{start_label}" }
                span { "{end_label}" }
            }
            div { style: "position:relative;height:12px;background:var(--bg);border:1px solid var(--border-subtle);border-radius:2px;overflow:hidden;",
                div {
                    style: "width:{fill_pct_int}%;height:100%;background:{fill_color};transition:width .3s;",
                }
                div {
                    style: "position:absolute;top:-2px;bottom:-2px;left:{fill_pct_int}%;width:2px;background:var(--text);",
                }
            }
            div { style: "margin-top:4px;font-size:11px;color:var(--text-muted);text-align:right;",
                "{end_status}"
            }
        }
    }
}

fn expiry_label(now: u64, end: u64) -> String {
    if now >= end {
        return "expired".into();
    }
    let remaining = end - now;
    let days = remaining / 86_400;
    if days == 0 {
        let hours = remaining / 3_600;
        if hours == 0 {
            format!("{} min until expiry", remaining / 60)
        } else {
            format!("{hours} h until expiry")
        }
    } else if days == 1 {
        "1 day until expiry".into()
    } else {
        format!("{days} days until expiry")
    }
}

fn format_unix_date(secs: u64) -> String {
    let mut days = (secs / 86_400) as i64;
    let mut year = 1970i64;
    loop {
        let yd = if is_leap(year) { 366 } else { 365 };
        if days < yd as i64 {
            break;
        }
        days -= yd as i64;
        year += 1;
    }
    let months_normal: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let months_leap: [i64; 12] = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let months = if is_leap(year) {
        months_leap
    } else {
        months_normal
    };
    let mut month = 0usize;
    while month < 12 && days >= months[month] {
        days -= months[month];
        month += 1;
    }
    let day = days + 1;
    format!("{year:04}-{:02}-{:02}", month + 1, day)
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[cfg(not(target_arch = "wasm32"))]
fn now_unix_s_opt() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

#[cfg(target_arch = "wasm32")]
fn now_unix_s_opt() -> Option<u64> {
    None
}

#[component]
fn TrustTab(anchors: Vec<AnchorInfo>, rules: Vec<SchemaRuleInfo>) -> Element {
    let ctx = use_context::<AppCtx>();
    let mut new_rule: Signal<String> = use_signal(String::new);
    let mut bulk_rules: Signal<String> = use_signal(String::new);
    let mut show_bulk: Signal<bool> = use_signal(|| false);
    let mut raw_mode: Signal<bool> = use_signal(|| false);

    let validation = *ctx.validation_stats.read();
    let history = ctx.validation_history.read().clone();

    rsx! {
        div { class: "edu-card",
            div { style: "display:flex;gap:12px;align-items:flex-start;",
                div { style: "font-size:28px;flex-shrink:0;", "⚓" }
                div {
                    div { style: "font-size:13px;font-weight:600;color:var(--accent);margin-bottom:4px;",
                        EduGloss { term: "Trust anchor" }
                        " · "
                        EduGloss { term: "Schema rule" }
                        " · live validation"
                    }
                    div { style: "font-size:12px;color:var(--text-muted);line-height:1.6;",
                        "Anchors are the roots of trust this forwarder accepts; schema rules say which key is allowed to sign data at each name. Every anchor or schema change here is appended to the dashboard's "
                        EduGloss { term: "Schema journal" }
                        " so the trust posture's history is reconstructable."
                    }
                }
            }
        }

        TrustAnchorList { anchors: anchors.clone() }

        TrustSchemaList {
            rules: rules.clone(),
            raw_mode: *raw_mode.read(),
            new_rule: new_rule.read().clone(),
            bulk_rules: bulk_rules.read().clone(),
            show_bulk: *show_bulk.read(),
            on_toggle_raw_mode: move |_: ()| {
                let prev = *raw_mode.read();
                raw_mode.set(!prev);
            },
            on_set_new_rule: move |s: String| new_rule.set(s),
            on_set_bulk: move |s: String| bulk_rules.set(s),
            on_toggle_show_bulk: move |_: ()| {
                let prev = *show_bulk.read();
                show_bulk.set(!prev);
            },
            on_add_rule: move |_: ()| {
                let r = new_rule.peek().trim().to_string();
                if !r.is_empty() {
                    ctx.cmd.send(DashCmd::SchemaRuleAdd(r));
                    new_rule.set(String::new());
                }
            },
            on_remove_rule: move |idx: u64| {
                ctx.cmd.send(DashCmd::SchemaRuleRemove(idx));
            },
            on_apply_bulk: move |_: ()| {
                let body = bulk_rules.peek().clone();
                ctx.cmd.send(DashCmd::SchemaSet(body));
                show_bulk.set(false);
                bulk_rules.set(String::new());
            },
            on_clear_all: move |_: ()| {
                ctx.cmd.send(DashCmd::SchemaSet(String::new()));
                show_bulk.set(false);
                bulk_rules.set(String::new());
            },
        }

        LiveValidationChart { stats: validation, history }
    }
}

/// Parse cert bytes (raw/base64/hex) and fire `security/anchor-add` for the
/// cert's own key name. Returns the installed name on success so the caller
/// can toast it. `ctx` is `Copy`, so this is safe to call from async file
/// handlers as well as sync onclick handlers.
fn install_anchor_cert(ctx: AppCtx, bytes: &[u8]) -> Result<String, String> {
    let (name, wire) = crate::views::safebag_import::parse_anchor_cert(bytes)?;
    ctx.cmd.send(DashCmd::SecurityAnchorAdd {
        name: name.clone(),
        fingerprint_hex: crate::views::safebag_import::cert_fingerprint_hex(&wire),
        cert_wire_hex: crate::views::safebag_import::hex_encode(&wire),
    });
    Ok(name)
}

#[component]
fn TrustAnchorList(anchors: Vec<AnchorInfo>) -> Element {
    let ctx = use_context::<AppCtx>();
    // Add-anchor form state. `paste` holds pasted base64/hex/raw cert text;
    // a file pick routes its bytes through the same parse path.
    let mut show_add: Signal<bool> = use_signal(|| false);
    let mut paste: Signal<String> = use_signal(String::new);
    let mut add_error: Signal<Option<String>> = use_signal(|| None);

    rsx! {
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:14px;",
            div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;",
                div { style: "font-size:12px;font-weight:600;color:var(--text);",
                    EduGloss { term: "Trust anchor" }
                    " list"
                }
                span { style: "font-size:10px;color:var(--text-muted);",
                    if anchors.is_empty() { "none configured" } else { "{anchors.len()} configured" }
                }
            }
            if anchors.is_empty() {
                div { class: "empty",
                    "No trust anchors configured. Interests and Data packets bypass the validator."
                }
            } else {
                for a in anchors.iter() {
                    div { style: "display:flex;gap:10px;padding:8px 0;border-top:1px solid var(--border-subtle);font-size:12px;align-items:flex-start;",
                        span { style: "font-size:16px;", "⚓" }
                        div { style: "flex:1;",
                            div { class: "mono", style: "color:var(--text);word-break:break-all;", "{a.name}" }
                            div { style: "font-size:10px;color:var(--text-muted);margin-top:2px;",
                                match a.source.as_deref() {
                                    Some("mgmt") => "Authorizes signed management commands (trust_anchor_pib).",
                                    Some("localhop") => "Authorizes /localhop registration (localhop_trust_anchor_pib).",
                                    Some("engine") => "Validates incoming Data and certificates (engine keystore).",
                                    Some(other) => other,
                                    None => "Trust anchor.",
                                }
                            }
                        }
                        button {
                            class: "btn btn-secondary btn-sm",
                            style: "font-size:10px;",
                            onclick: {
                                let key_name = a.name.clone();
                                move |_| ctx.cmd.send(DashCmd::SecurityAnchorRemove { name: key_name.clone() })
                            },
                            "Remove"
                        }
                    }
                }
            }

            // Add-anchor: file upload OR paste, parsed in-browser into the
            // cert's own key name + wire, then fired at `security/anchor-add`.
            div { style: "display:flex;gap:8px;margin-top:12px;",
                label {
                    class: "btn btn-secondary btn-sm",
                    style: "cursor:pointer;",
                    "+ Add from file"
                    input {
                        r#type: "file",
                        accept: ".cert,.ndnc,.der,.b64,.pem,application/octet-stream,text/plain",
                        style: "display:none;",
                        onchange: move |evt| {
                            let files = evt.files();
                            if let Some(file) = files.first().cloned() {
                                spawn(async move {
                                    match file.read_bytes().await {
                                        Ok(bytes) => match install_anchor_cert(ctx, &bytes) {
                                            Ok(name) => push_toast(
                                                format!("Installing trust anchor {name}…"),
                                                ToastLevel::Info,
                                            ),
                                            Err(e) => push_toast(
                                                format!("Add anchor failed: {e}"),
                                                ToastLevel::Error,
                                            ),
                                        },
                                        Err(_) => push_toast(
                                            "Couldn't read the selected file".to_owned(),
                                            ToastLevel::Error,
                                        ),
                                    }
                                });
                            }
                        },
                    }
                }
                button {
                    class: if *show_add.read() { "btn btn-primary btn-sm" } else { "btn btn-secondary btn-sm" },
                    onclick: move |_| {
                        let prev = *show_add.read();
                        show_add.set(!prev);
                        add_error.set(None);
                    },
                    "+ Paste cert"
                }
            }

            if *show_add.read() {
                div { style: "margin-top:10px;padding:10px;background:var(--surface);border:1px solid var(--border);border-radius:6px;",
                    div { style: "font-size:10px;color:var(--text-muted);margin-bottom:6px;",
                        "Paste a certificate as base64 (from "
                        span { class: "mono", "ndn-sec certdump" }
                        " / "
                        span { class: "mono", "ndnsec cert-dump" }
                        "), hex, or raw wire. The key name is read from the cert itself."
                    }
                    textarea {
                        style: "width:100%;min-height:80px;font-family:var(--font-mono);font-size:11px;padding:6px 8px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;color:var(--text);",
                        value: "{paste}",
                        oninput: move |e| {
                            paste.set(e.value());
                            add_error.set(None);
                        },
                    }
                    if let Some(err) = add_error.read().clone() {
                        div { style: "font-size:11px;color:var(--red,#f85149);margin-top:6px;", "{err}" }
                    }
                    div { style: "display:flex;justify-content:flex-end;margin-top:8px;",
                        button {
                            class: "btn btn-primary btn-sm",
                            disabled: paste.read().trim().is_empty(),
                            onclick: move |_| {
                                let text = paste.peek().clone();
                                match install_anchor_cert(ctx, text.as_bytes()) {
                                    Ok(name) => {
                                        push_toast(
                                            format!("Installing trust anchor {name}…"),
                                            ToastLevel::Info,
                                        );
                                        paste.set(String::new());
                                        show_add.set(false);
                                        add_error.set(None);
                                    }
                                    Err(e) => add_error.set(Some(e)),
                                }
                            },
                            "Add trust anchor"
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn TrustSchemaList(
    rules: Vec<SchemaRuleInfo>,
    raw_mode: bool,
    new_rule: String,
    bulk_rules: String,
    show_bulk: bool,
    on_toggle_raw_mode: EventHandler<()>,
    on_set_new_rule: EventHandler<String>,
    on_set_bulk: EventHandler<String>,
    on_toggle_show_bulk: EventHandler<()>,
    on_add_rule: EventHandler<()>,
    on_remove_rule: EventHandler<u64>,
    on_apply_bulk: EventHandler<()>,
    on_clear_all: EventHandler<()>,
) -> Element {
    rsx! {
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:14px;",
            div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;",
                div { style: "font-size:12px;font-weight:600;color:var(--text);",
                    EduGloss { term: "Schema rule" }
                    " list"
                    if !rules.is_empty() {
                        span { style: "margin-left:8px;", class: "badge badge-blue", "{rules.len()}" }
                    }
                }
                div { style: "display:flex;gap:6px;",
                    button {
                        class: if raw_mode { "btn btn-primary btn-sm" } else { "btn btn-secondary btn-sm" },
                        onclick: move |_| on_toggle_raw_mode.call(()),
                        if raw_mode { "Guided" } else { "Raw" }
                    }
                }
            }

            if rules.is_empty() {
                div { class: "empty",
                    "No trust schema rules configured. All "
                    EduGloss { term: "Signed Data" }
                    " is accepted (security profile = disabled)."
                }
            } else if !raw_mode {
                // Permissions as sentences: each rule read as plain English.
                for rule in rules.iter() {
                    {
                        let idx = rule.index as u64;
                        rsx! {
                            div { class: "schema-rule",
                                span { class: "badge badge-gray", style: "flex-shrink:0;", "{rule.index}" }
                                span { class: "schema-rule-text",
                                    "Data matching "
                                    span { class: "mono", style: "color:var(--accent);", "{rule.data_pattern}" }
                                    " is trusted only when signed by a key matching "
                                    span { class: "mono", style: "color:var(--green);", "{rule.key_pattern}" }
                                    "."
                                }
                                button {
                                    class: "btn btn-secondary btn-sm",
                                    "data-tooltip": "Phase C: guided schema-rule editor",
                                    onclick: move |_| push_toast(
                                        "Phase C: §11.6 — guided schema-rule editor",
                                        ToastLevel::Info,
                                    ),
                                    "Edit"
                                }
                                button {
                                    class: "btn btn-danger btn-sm",
                                    onclick: move |_| on_remove_rule.call(idx),
                                    "Remove"
                                }
                            }
                        }
                    }
                }
            } else {
                pre {
                    style: "background:var(--bg);border:1px solid var(--border-subtle);border-radius:4px;padding:10px;font-size:11px;color:var(--text);overflow:auto;",
                    for r in rules.iter() {
                        "[{r.index}] {r.data_pattern} => {r.key_pattern}\n"
                    }
                }
            }

            div { style: "margin-top:14px;padding-top:12px;border-top:1px solid var(--border-subtle);",
                div { style: "font-size:11px;color:var(--text-muted);margin-bottom:6px;",
                    "Format: "
                    span { class: "mono", "/data/<node>/<type> => /data/<node>/KEY/<id>" }
                }
                div { class: "form-row",
                    div { class: "form-group", style: "flex:1;",
                        input {
                            r#type: "text",
                            placeholder: "/sensor/<node>/<type> => /sensor/<node>/KEY/<id>",
                            value: "{new_rule}",
                            oninput: move |e| on_set_new_rule.call(e.value()),
                            style: "width:100%;",
                        }
                    }
                    button {
                        class: "btn btn-primary",
                        disabled: new_rule.trim().is_empty(),
                        onclick: move |_| on_add_rule.call(()),
                        "Add rule"
                    }
                }
            }

            div { style: "margin-top:14px;border:1px solid var(--border);border-radius:6px;overflow:hidden;",
                div { style: "display:flex;justify-content:space-between;align-items:center;padding:10px 14px;background:var(--surface);",
                    div { style: "font-size:12px;font-weight:600;color:var(--text);", "Bulk replace" }
                    button {
                        class: "btn btn-secondary btn-sm",
                        onclick: move |_| on_toggle_show_bulk.call(()),
                        if show_bulk { "▲ Cancel" } else { "▼ Edit" }
                    }
                }
                if show_bulk {
                    div { style: "padding:12px;border-top:1px solid var(--border);",
                        div { style: "font-size:11px;color:var(--text-muted);margin-bottom:8px;",
                            "One rule per line. Empty input clears all rules. Replaces the entire schema."
                        }
                        textarea {
                            style: "width:100%;height:120px;background:var(--bg);border:1px solid var(--border-subtle);border-radius:4px;padding:8px;font-family:monospace;font-size:11px;color:var(--text);resize:vertical;",
                            placeholder: "/sensor/<node>/<type> => /sensor/<node>/KEY/<id>\n/admin/<**rest> => /admin/KEY/<id>",
                            value: "{bulk_rules}",
                            oninput: move |e| on_set_bulk.call(e.value()),
                        }
                        div { style: "display:flex;gap:8px;margin-top:8px;",
                            button {
                                class: "btn btn-primary",
                                onclick: move |_| on_apply_bulk.call(()),
                                "Apply schema"
                            }
                            button {
                                class: "btn btn-danger",
                                onclick: move |_| on_clear_all.call(()),
                                "Clear all rules"
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn LiveValidationChart(stats: Option<ValidationStats>, history: VecDeque<(u64, u64)>) -> Element {
    let present = stats.as_ref().map(|s| s.validator_present).unwrap_or(false);
    let verified = stats.as_ref().map(|s| s.verified_per_sec).unwrap_or(0);
    let rejected = stats.as_ref().map(|s| s.rejected_per_sec).unwrap_or(0);

    let (chip_class, chip_label) = match stats.as_ref() {
        None => ("badge badge-gray", "polling…"),
        Some(s) if !s.validator_present => ("badge badge-yellow", "no validator wired"),
        Some(_) if verified == 0 && rejected == 0 => {
            ("badge badge-gray", "validator present · no traffic last 1s")
        }
        Some(_) => ("badge badge-green", "live"),
    };

    rsx! {
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px;",
            div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;",
                div { style: "font-size:12px;font-weight:600;color:var(--text);",
                    "Live validation activity"
                }
                span { class: "{chip_class}", "{chip_label}" }
            }
            div { style: "display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px;",
                CounterTile {
                    label: "Verified / sec",
                    value: verified,
                    color: "var(--green,#3fb950)",
                }
                CounterTile {
                    label: "Rejected / sec",
                    value: rejected,
                    color: "var(--red,#f85149)",
                }
            }
            Sparkline { history }
            if !present {
                div { style: "margin-top:10px;padding:8px 10px;font-size:11px;color:var(--text-muted);background:var(--surface);border:1px dashed var(--border-subtle);border-radius:4px;line-height:1.5;",
                    "v1 forwarders report "
                    span { class: "mono", "validator_present=false" }
                    " when no PIB/validator is wired, and counter plumbing on "
                    span { class: "mono", "ndn_security::Validator" }
                    " is a tracked Phase B follow-up. The chart re-paints as soon as the verbs return real data."
                }
            }
        }
    }
}

#[component]
fn CounterTile(label: &'static str, value: u64, color: String) -> Element {
    rsx! {
        div { style: "background:var(--bg);border:1px solid var(--border-subtle);border-radius:4px;padding:10px;",
            div { style: "font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;",
                "{label}"
            }
            div { style: "font-size:20px;font-weight:600;color:{color};margin-top:4px;",
                "{value}"
            }
        }
    }
}

#[component]
fn Sparkline(history: VecDeque<(u64, u64)>) -> Element {
    let n = history.len();
    if n == 0 {
        return rsx! {
            div { style: "height:48px;border:1px dashed var(--border-subtle);border-radius:4px;display:flex;align-items:center;justify-content:center;font-size:11px;color:var(--text-muted);",
                "no samples yet"
            }
        };
    }
    let max = history
        .iter()
        .map(|(v, r)| (*v).max(*r))
        .max()
        .unwrap_or(0)
        .max(1);
    let width = 320.0_f64;
    let height = 48.0_f64;
    let step = if n > 1 {
        width / (n as f64 - 1.0)
    } else {
        width
    };

    let mut verified_path = String::new();
    let mut rejected_path = String::new();
    for (i, (v, r)) in history.iter().enumerate() {
        let x = (i as f64) * step;
        let yv = height - (*v as f64 / max as f64) * height;
        let yr = height - (*r as f64 / max as f64) * height;
        if i == 0 {
            verified_path.push('M');
            rejected_path.push('M');
        } else {
            verified_path.push('L');
            rejected_path.push('L');
        }
        use std::fmt::Write as _;
        let _ = write!(verified_path, " {x:.1} {yv:.1} ");
        let _ = write!(rejected_path, " {x:.1} {yr:.1} ");
    }

    let max_label = max.to_string();
    rsx! {
        div { style: "position:relative;background:var(--bg);border:1px solid var(--border-subtle);border-radius:4px;padding:6px;",
            svg {
                width: "100%",
                height: "{height}",
                view_box: "0 0 {width} {height}",
                preserve_aspect_ratio: "none",
                path {
                    d: "{verified_path}",
                    fill: "none",
                    stroke: "var(--green,#3fb950)",
                    "stroke-width": "1.5",
                }
                path {
                    d: "{rejected_path}",
                    fill: "none",
                    stroke: "var(--red,#f85149)",
                    "stroke-width": "1.5",
                }
            }
            div { style: "position:absolute;top:4px;right:8px;font-size:9px;color:var(--text-muted);",
                "max {max_label}/s"
            }
        }
    }
}

#[component]
fn ChainTab(
    keys: Vec<crate::types::SecurityKeyInfo>,
    anchors: Vec<crate::types::AnchorInfo>,
) -> Element {
    let has_anchor = !anchors.is_empty();
    let has_identity = !keys.is_empty();
    let identity = keys.first();
    let has_cert = identity.map(|k| k.has_cert).unwrap_or(false);
    let identity_name = identity
        .map(|k| k.name.clone())
        .unwrap_or_else(|| "(none)".to_string());
    let anchor_name = anchors
        .first()
        .map(|a| a.name.clone())
        .unwrap_or_else(|| "(none)".to_string());
    let (expiry_cls, expiry_lbl) = identity
        .map(|k| k.expiry_badge())
        .unwrap_or(("badge badge-gray", "—".to_string()));

    rsx! {
        div { class: "section-title", "Certificate Chain" }
        div { style: "color:var(--text-muted);font-size:12px;margin-bottom:16px;",
            "Shows the chain from your trust anchor down to your identity certificate. "
            "Every link must be valid for your packets to be accepted by the network."
        }

        div { style: "overflow-x:auto;",
            div { class: "trust-chain",
                {chain_node("🔑", "Trust Anchor", &anchor_name, if has_anchor { "ok" } else { "missing" }, "Root of trust — the certificate everyone in your network must trust.\nConfigure in router TOML: security.trust_anchor")}
                div { class: "chain-arrow", style: "color:var(--border);", "→" }

                {chain_node("📜", "CA Certificate", "Signed by anchor", if has_anchor { "ok" } else { "missing" }, "The Certificate Authority that signs identity certificates.\nEnroll via CA / NDNCERT tab to get one.")}
                div { class: "chain-arrow", style: "color:var(--border);", "→" }

                {chain_node("🪪", "Your Identity", &identity_name, if has_cert { "ok" } else if has_identity { "warn" } else { "missing" }, "Your router's identity certificate.\nMust be signed by a CA that chains back to the trust anchor.")}
            }
        }

        div { style: "display:flex;gap:10px;flex-wrap:wrap;margin-top:16px;",
            div { style: "flex:1;min-width:160px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:12px;",
                div { style: "font-size:11px;color:var(--text-muted);margin-bottom:6px;", "IDENTITY" }
                div { class: "mono", style: "font-size:12px;word-break:break-all;", "{identity_name}" }
            }
            div { style: "flex:1;min-width:140px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:12px;",
                div { style: "font-size:11px;color:var(--text-muted);margin-bottom:6px;", "CERT EXPIRY" }
                span { class: "{expiry_cls}", "{expiry_lbl}" }
            }
            div { style: "flex:1;min-width:140px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:12px;",
                div { style: "font-size:11px;color:var(--text-muted);margin-bottom:6px;", "TRUST ANCHOR" }
                if has_anchor {
                    span { class: "badge badge-green", "configured" }
                } else {
                    span { class: "badge badge-red", "not configured" }
                }
            }
        }

        if !has_cert && has_identity {
            div { style: "margin-top:14px;padding:12px;background:var(--yellow-bg)22;border:1px solid var(--yellow)44;border-radius:6px;font-size:12px;color:var(--yellow);",
                "⚠ Your identity key has no certificate. Go to the "
                strong { "CA / NDNCERT" }
                " tab to enroll and get a certificate signed by your trust anchor."
            }
        }
    }
}

fn chain_node(icon: &str, label: &str, name: &str, status: &str, tooltip: &str) -> Element {
    let border_color = match status {
        "ok" => "var(--green)",
        "warn" => "var(--yellow)",
        "missing" => "var(--border)",
        _ => "var(--border)",
    };
    let opacity = if status == "missing" { "0.45" } else { "1" };
    rsx! {
        div {
            "data-tooltip": "{tooltip}",
            style: "background:var(--surface2);border:1px solid {border_color};border-radius:8px;padding:12px 16px;text-align:center;min-width:120px;cursor:help;opacity:{opacity};",
            div { style: "font-size:22px;margin-bottom:4px;", "{icon}" }
            div { style: "font-size:11px;font-weight:600;color:var(--text);margin-bottom:2px;", "{label}" }
            div { style: "font-size:10px;color:var(--text-muted);word-break:break-all;max-width:130px;", "{name}" }
        }
    }
}

#[component]
fn DidTab(keys: Vec<crate::types::SecurityKeyInfo>) -> Element {
    let mut copied = use_signal(|| false);
    let first_key = keys.first().cloned();

    let identity_name = first_key
        .as_ref()
        .map(|k| k.name.clone())
        .unwrap_or_default();
    let did_ndn = if identity_name.is_empty() {
        String::new()
    } else {
        format!("did:ndn:{}", encode_did_ndn(&identity_name))
    };
    let did_key_note = "Requires public key bytes — not yet available via management API";

    let did_doc_preview = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{did_ndn}","verificationMethod":[{{"id":"{did_ndn}#key-1","type":"Ed25519VerificationKey2020","controller":"{did_ndn}","publicKeyMultibase":"<Ed25519 pubkey>"}}]}}"#
    );

    rsx! {
        div { class: "section-title", "DID Explorer" }

        div { class: "edu-card",
            div { style: "display:flex;gap:12px;align-items:flex-start;",
                div { style: "font-size:28px;flex-shrink:0;", "🔗" }
                div {
                    div { style: "font-size:13px;font-weight:600;color:var(--purple);margin-bottom:4px;",
                        "Decentralized Identifiers (W3C DIDs)"
                    }
                    div { style: "font-size:12px;color:var(--text-muted);line-height:1.6;",
                        "A DID is a self-sovereign, cryptographically verifiable identifier — no central authority needed. "
                        "NDN names map directly to DIDs: your NDN name "
                        span { class: "signed-packet", "{identity_name}" }
                        " becomes a globally unique, portable identity."
                    }
                }
            }
        }

        if identity_name.is_empty() {
            div { class: "empty",
                "No identity key found. Generate a key in the Identities tab first."
            }
        } else {
            div { style: "margin-bottom:18px;",
                div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;",
                    div { style: "font-size:12px;font-weight:600;color:var(--text);",
                        span { style: "color:var(--purple);", "did:ndn" }
                        span { style: "color:var(--text-muted);", " — NDN name encoded as a W3C DID" }
                    }
                    button {
                        class: "did-copy-btn",
                        onclick: move |_| {
                            copied.set(true);
                        },
                        if *copied.read() { "✓ Copied" } else { "Copy" }
                    }
                }
                div { class: "did-value", "{did_ndn}" }
                div { style: "font-size:11px;color:var(--text-muted);",
                    "DID document resolves to the NDN certificate at the signed certificate name."
                }
            }

            div { style: "margin-bottom:18px;",
                div { style: "font-size:12px;font-weight:600;color:var(--text);margin-bottom:6px;",
                    span { style: "color:var(--purple);", "did:key" }
                    span { style: "color:var(--text-muted);", " — public key multibase encoding" }
                }
                div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:10px;font-size:11px;color:var(--text-muted);font-style:italic;",
                    "{did_key_note}"
                }
            }

            div {
                div { style: "font-size:12px;font-weight:600;color:var(--text);margin-bottom:6px;", "DID Document (preview)" }
                div { class: "yk-cmd", "{did_doc_preview}" }
            }

            div { style: "display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:16px;",
                DidExplainCard {
                    title: "No Central Registry",
                    body: "NDN names are hierarchically delegated. Anyone with the parent namespace can issue sub-names — like DNS but without a single root authority.",
                }
                DidExplainCard {
                    title: "Self-Certifying",
                    body: "The DID is derived from your public key. Verifying a signature proves ownership without contacting any third party.",
                }
                DidExplainCard {
                    title: "Portable",
                    body: "Your DID travels with your certificate. Move between routers or networks — your identity stays the same.",
                }
                DidExplainCard {
                    title: "Interoperable",
                    body: "did:ndn DIDs resolve via the NDN network. did:key DIDs are self-contained and work without any network access.",
                }
            }
        }
    }
}

#[component]
fn DidExplainCard(title: &'static str, body: &'static str) -> Element {
    rsx! {
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:12px;",
            div { style: "font-size:12px;font-weight:600;color:var(--purple);margin-bottom:4px;", "{title}" }
            div { style: "font-size:11px;color:var(--text-muted);line-height:1.5;", "{body}" }
        }
    }
}

const DISCOVERY_WINDOW_SECS: u64 = 10 * 60;

#[component]
fn CaTab() -> Element {
    let ctx = use_context::<AppCtx>();
    let mut show_token_form = use_signal(|| false);
    let mut token_name = use_signal(String::new);
    let mut last_token = use_signal(String::new);
    let mut promote_open: Signal<bool> = use_signal(|| false);
    let mut promote_prefill: Signal<String> = use_signal(String::new);
    let ca = ctx.ca_info.read().clone();
    let anchors = ctx.security_anchors.read().clone();
    let identity_name = ctx.identity_name.read().clone();
    let is_ephemeral = *ctx.identity_is_ephemeral.read();

    rsx! {
        div { class: "section-title", "Certificate Authorities" }

        div { class: "edu-card",
            div { style: "display:flex;gap:12px;align-items:flex-start;",
                div { style: "font-size:28px;flex-shrink:0;", "🏛" }
                div {
                    div { style: "font-size:13px;font-weight:600;color:var(--accent);margin-bottom:4px;",
                        EduGloss { term: "CA" }
                        " · "
                        EduGloss { term: "NDNCERT" }
                    }
                    div { style: "font-size:12px;color:var(--text-muted);line-height:1.6;",
                        "A CA issues certs that bind your identity key to a name. The Trusted tier below holds the CAs your forwarder validates against today. Discovered CAs are surfaced via service discovery; promote one only after you've matched its fingerprint out-of-band — same trust-on-first-connect ceremony as SSH."
                    }
                }
            }
        }

        TrustedCaList {
            local_ca: ca.clone(),
            anchors: anchors.clone(),
            on_promote_from_anchor: move |name: String| {
                promote_prefill.set(name);
                promote_open.set(true);
            },
        }

        DiscoveredCaList {
            on_promote: move |name: String| {
                promote_prefill.set(name);
                promote_open.set(true);
            },
        }

        div { style: "margin-top:14px;",
            button {
                class: "btn btn-primary",
                onclick: move |_| {
                    promote_prefill.set(String::new());
                    promote_open.set(true);
                },
                "+ Promote CA by name"
            }
        }

        if let Some(ref info) = ca {
            div { style: "background:var(--green-dark);border:1px solid var(--green)44;border-radius:6px;padding:14px;margin-bottom:14px;margin-top:18px;",
                div { style: "font-size:12px;font-weight:600;color:var(--green);margin-bottom:8px;",
                    "CA Active on this router"
                }
                div { style: "display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px;",
                    div { style: "color:var(--text-muted);", "CA Prefix" }
                    div { style: "font-family:monospace;color:var(--text);", "{info.ca_prefix}" }
                    div { style: "color:var(--text-muted);", "Description" }
                    { let ca_desc = if info.ca_info.is_empty() { "—".to_string() } else { info.ca_info.clone() };
                      rsx! { div { style: "color:var(--text);", "{ca_desc}" } } }
                    div { style: "color:var(--text-muted);", "Max Validity" }
                    div { style: "color:var(--text);", "{info.max_validity_days} days" }
                    div { style: "color:var(--text-muted);", "Challenges" }
                    div { style: "display:flex;gap:4px;flex-wrap:wrap;",
                        for ch in &info.challenges {
                            span { class: "badge badge-blue", "{ch}" }
                        }
                    }
                }
            }

            div { style: "margin:16px 0;",
                div { style: "font-size:12px;font-weight:600;color:var(--text);margin-bottom:10px;", "Enrollment Protocol Flow" }
                div { class: "enroll-steps",
                    EnrollStep { label: "PROBE", desc: "Check namespace", status: "done" }
                    div { class: "enroll-step-line done" }
                    EnrollStep { label: "NEW", desc: "Submit key + ECDH", status: "done" }
                    div { class: "enroll-step-line" }
                    EnrollStep { label: "CHALLENGE", desc: "Verify identity", status: "active" }
                    div { class: "enroll-step-line" }
                    EnrollStep { label: "CERT", desc: "Receive certificate", status: "" }
                }
            }

            div { style: "display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px;",
                InfoKv { label: "Protocol", val: "NDNCERT 0.3" }
                InfoKv { label: "Key Exchange", val: "P-256 ECDH" }
                InfoKv { label: "Encryption", val: "AES-GCM-128 + HKDF-SHA256" }
                InfoKv { label: "Wire Format", val: "NDN TLV" }
            }
        }

        div { style: "border:1px solid var(--border);border-radius:6px;overflow:hidden;",
            div { style: "display:flex;justify-content:space-between;align-items:center;padding:12px 14px;background:var(--surface2);",
                div { style: "font-size:12px;font-weight:600;color:var(--text);", "Zero-Touch Provisioning Tokens" }
                if ca.is_some() {
                    button {
                        class: "btn btn-secondary btn-sm",
                        onclick: move |_| { let v = *show_token_form.read(); show_token_form.set(!v); },
                        if *show_token_form.read() { "▲ Cancel" } else { "+ Add Token" }
                    }
                }
            }
            if *show_token_form.read() {
                div { style: "padding:14px;border-top:1px solid var(--border);",
                    div { class: "form-row",
                        div { class: "form-group",
                            label { "Token description (label for this token)" }
                            input {
                                r#type: "text",
                                placeholder: "e.g. router-3-provisioning",
                                value: "{token_name}",
                                oninput: move |e| token_name.set(e.value()),
                                style: "width:260px;",
                            }
                        }
                        button {
                            class: "btn btn-primary",
                            onclick: move |_| {
                                let desc = token_name.read().clone();
                                ctx.cmd.send(DashCmd::SecurityTokenAdd(desc));
                                token_name.set(String::new());
                                show_token_form.set(false);
                                last_token.set("Token generated — check router logs for value".to_string());
                            },
                            "Generate Token"
                        }
                    }
                    if !last_token.read().is_empty() {
                        div { class: "yk-seed", style: "margin-top:8px;", "{last_token}" }
                    }
                }
            }
            if ca.is_none() {
                div { style: "padding:16px;text-align:center;color:var(--text-muted);font-size:13px;",
                    "Enable this router as a CA (add ca_prefix to TOML) to manage ZTP tokens."
                }
            } else {
                div { style: "padding:12px 14px;color:var(--text-muted);font-size:12px;",
                    "Generated tokens are logged by the router at INFO level. Future versions will list active tokens here."
                }
            }
        }

        if *promote_open.read() {
            PromoteToTrustedModal {
                prefill_name: promote_prefill.read().clone(),
                initiator_name: identity_name.clone(),
                is_initiator_ephemeral: is_ephemeral,
                on_close: move |_: ()| promote_open.set(false),
            }
        }

        // §5.5 — pending device-approval list.
        crate::views::ca_approvals::CaApprovalsPanel {}
    }
}

#[component]
fn EnrollStep(label: &'static str, desc: &'static str, status: &'static str) -> Element {
    let dot_class = match status {
        "done" => "enroll-step-dot done",
        "active" => "enroll-step-dot active",
        _ => "enroll-step-dot",
    };
    rsx! {
        div { class: "enroll-step",
            div { class: "{dot_class}" }
            div { style: "font-size:11px;font-weight:600;color:var(--text);", "{label}" }
            div { style: "font-size:10px;color:var(--text-muted);", "{desc}" }
        }
    }
}

#[component]
fn InfoKv(label: &'static str, val: &'static str) -> Element {
    rsx! {
        div { style: "background:var(--bg);border:1px solid var(--border-subtle);border-radius:4px;padding:8px 10px;",
            div { style: "font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;", "{label}" }
            div { style: "font-size:12px;color:var(--text);margin-top:2px;font-weight:500;", "{val}" }
        }
    }
}

#[component]
fn YubikeyTab() -> Element {
    let ctx = use_context::<AppCtx>();
    let mut hotp_seed: Signal<Option<String>> = use_signal(|| None);
    let mut hotp_counter: Signal<u64> = use_signal(|| 0);
    let mut show_cmd: Signal<bool> = use_signal(|| false);
    let mut piv_name: Signal<String> = use_signal(String::new);

    let yk_status = ctx.yubikey_status.read().clone();

    rsx! {
        div { class: "section-title", "YubiKey Integration" }

        div { class: "edu-card",
            div { style: "display:flex;gap:12px;align-items:flex-start;",
                div { style: "font-size:28px;flex-shrink:0;", "🔐" }
                div {
                    div { style: "font-size:13px;font-weight:600;color:var(--green);margin-bottom:4px;",
                        "Hardware-Backed Security"
                    }
                    div { style: "font-size:12px;color:var(--text-muted);line-height:1.6;",
                        "A YubiKey stores cryptographic keys in tamper-resistant hardware — private keys never leave the device. "
                        "Two modes are supported: "
                        strong { style: "color:var(--text);", "PIV (slot 9a)" }
                        " for hardware-backed signing, and "
                        strong { style: "color:var(--text);", "HOTP slot 2" }
                        " for one-press headless device bootstrapping."
                    }
                }
            }
        }

        div { style: "display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px;",
            div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:16px;",
                div { style: "font-size:16px;margin-bottom:8px;", "🔑" }
                div { style: "font-size:13px;font-weight:600;color:var(--text);margin-bottom:4px;", "PIV Signing Key" }
                div { style: "font-size:11px;color:var(--text-muted);line-height:1.5;margin-bottom:10px;",
                    "Store your NDN identity private key in YubiKey PIV slot 9a. All packet signing happens on-device — even a compromised OS cannot steal your key."
                }
                div { style: "display:flex;gap:8px;margin-bottom:8px;",
                    button {
                        class: "btn btn-secondary btn-sm",
                        onclick: move |_| { ctx.cmd.send(DashCmd::YubikeyDetect); },
                        "Detect YubiKey"
                    }
                }
                if let Some(ref st) = yk_status {
                    {
                        let (badge_class, text) = if st.starts_with("YubiKey: present") {
                            ("badge badge-green", st.as_str())
                        } else {
                            ("badge badge-red", st.as_str())
                        };
                        rsx! {
                            div { style: "margin-bottom:8px;",
                                span { class: "{badge_class}", "{text}" }
                            }
                        }
                    }
                }
                div { class: "form-group", style: "margin-bottom:6px;",
                    label { "Identity name for PIV key" }
                    input {
                        r#type: "text",
                        placeholder: "/ndn/example/router1/KEY/v=0",
                        value: "{piv_name}",
                        oninput: move |e| piv_name.set(e.value()),
                    }
                }
                button {
                    class: "btn btn-primary btn-sm",
                    disabled: piv_name.read().is_empty(),
                    onclick: move |_| {
                        let n = piv_name.read().clone();
                        if !n.is_empty() {
                            ctx.cmd.send(DashCmd::YubikeyGeneratePiv(n));
                        }
                    },
                    "Generate in Slot 9a"
                }
                if let Some(ref st) = yk_status {
                    if st.starts_with("Generated.") {
                        div { style: "margin-top:8px;",
                            div { style: "font-size:11px;color:var(--text-muted);margin-bottom:4px;",
                                "P-256 public key (base64url, 65 bytes uncompressed):"
                            }
                            div { class: "yk-seed", style: "word-break:break-all;",
                                "{st}"
                            }
                        }
                    }
                }
            }
            div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:16px;",
                div { style: "font-size:16px;margin-bottom:8px;", "🖱" }
                div { style: "font-size:13px;font-weight:600;color:var(--text);margin-bottom:4px;", "HOTP Bootstrapping" }
                div { style: "font-size:11px;color:var(--text-muted);line-height:1.5;margin-bottom:10px;",
                    "Program slot 2 with an HMAC-SHA1 seed. Pressing the button emits a 6-digit one-time code — enough to authenticate a headless router during NDNCERT enrollment."
                }
                span { class: "badge badge-green", "Available now" }
            }
        }

        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px;",
            div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;",
                div { style: "font-size:13px;font-weight:600;color:var(--text);", "Generate HOTP Seed" }
                button {
                    class: "btn btn-primary btn-sm",
                    onclick: move |_| {
                        let seed = generate_hotp_seed();
                        hotp_seed.set(Some(seed));
                        hotp_counter.set(0);
                        show_cmd.set(false);
                    },
                    "Generate New Seed"
                }
            }

            if let Some(ref seed) = *hotp_seed.read() {
                div { style: "font-size:11px;color:var(--text-muted);margin-bottom:4px;", "HMAC-SHA1 seed (hex, 20 bytes):" }
                div { class: "yk-seed", "{seed}" }

                div { class: "form-row",
                    div { class: "form-group",
                        label { "Initial counter (must match YubiKey — default 0)" }
                        input {
                            r#type: "number",
                            min: "0",
                            value: "{hotp_counter}",
                            style: "width:120px;",
                            oninput: move |e| {
                                if let Ok(n) = e.value().parse::<u64>() {
                                    hotp_counter.set(n);
                                }
                            },
                        }
                    }
                    button {
                        class: "btn btn-secondary btn-sm",
                        onclick: move |_| { let v = *show_cmd.read(); show_cmd.set(!v); },
                        if *show_cmd.read() { "Hide command" } else { "Show ykpersonalize command" }
                    }
                }

                if *show_cmd.read() {
                    {
                        let s = seed.clone();
                        let c = *hotp_counter.read();
                        rsx! {
                            div { style: "margin-top:10px;",
                                div { style: "font-size:11px;color:var(--text-muted);margin-bottom:4px;",
                                    "Run on the provisioning machine (YubiKey connected via USB):"
                                }
                                div { class: "yk-cmd",
                                    "ykpersonalize -2 -o oath-hotp -o append-cr -a {s}"
                                }
                                div { style: "font-size:11px;color:var(--text-muted);margin-top:8px;",
                                    "Then configure the CA with this seed + counter via the CA / NDNCERT tab or router TOML:"
                                }
                                div { class: "yk-cmd",
                                    "[cert.challenges.yubikey-hotp]\n"
                                    "seed = \"{s}\"\n"
                                    "initial_counter = {c}\n"
                                    "window = 20"
                                }
                            }
                        }
                    }
                }
            } else {
                div { style: "text-align:center;padding:20px;color:var(--text-muted);font-size:13px;",
                    "Click \"Generate New Seed\" to create a fresh HMAC-SHA1 seed for a YubiKey slot 2."
                }
            }
        }

        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:16px;",
            div { style: "font-size:13px;font-weight:600;color:var(--text);margin-bottom:10px;", "Headless Bootstrap Flow" }
            BootstrapStep { n: 1, step: "Admin provisions",   desc: "Generate seed here → run ykpersonalize on the YubiKey", first: true }
            BootstrapStep { n: 2, step: "Ship device",        desc: "YubiKey is plugged into the headless router", first: false }
            BootstrapStep { n: 3, step: "Router enrolls",     desc: "Router starts NDNCERT enrollment automatically on boot", first: false }
            BootstrapStep { n: 4, step: "Operator presses",   desc: "Press YubiKey button → 6-digit OTP emitted via USB HID", first: false }
            BootstrapStep { n: 5, step: "Certificate issued", desc: "CA verifies OTP against HOTP counter → cert issued", first: false }
        }
    }
}

fn generate_hotp_seed() -> String {
    let mut seed = [0u8; 20];
    let _ = getrandom::getrandom(&mut seed);
    seed.iter().map(|b| format!("{b:02x}")).collect()
}

#[component]
fn BootstrapStep(n: u8, step: &'static str, desc: &'static str, first: bool) -> Element {
    let border = if first {
        ""
    } else {
        "border-top:1px solid var(--border-subtle);"
    };
    rsx! {
        div { style: "display:flex;gap:10px;padding:8px 0;{border}",
            div { style: "width:24px;height:24px;border-radius:50%;background:var(--accent-dim);border:1px solid var(--accent-solid)44;display:flex;align-items:center;justify-content:center;font-size:11px;color:var(--accent);flex-shrink:0;",
                "{n}"
            }
            div {
                div { style: "font-size:12px;font-weight:600;color:var(--text);", "{step}" }
                div { style: "font-size:11px;color:var(--text-muted);", "{desc}" }
            }
        }
    }
}

#[component]
fn MgmtAccessTab() -> Element {
    let ctx = use_context::<AppCtx>();
    let live = ctx.mgmt_access_policy.read().clone();
    let is_ephemeral = *ctx.identity_is_ephemeral.read();
    let pib_path = ctx.identity_pib_path.read().clone();

    let mut draft: Signal<Option<MgmtAccessPolicySnapshot>> =
        use_signal(|| None::<MgmtAccessPolicySnapshot>);
    {
        let mut draft_for_init = draft;
        let live_for_init = live.clone();
        use_effect(move || {
            if draft_for_init.read().is_none()
                && let Some(p) = live_for_init.clone()
            {
                draft_for_init.set(Some(p));
            }
        });
    }

    rsx! {
        div { class: "section-title", "Management access control" }

        div { class: "edu-card",
            div { style: "display:flex;gap:12px;align-items:flex-start;",
                div { style: "font-size:28px;flex-shrink:0;", "🛡" }
                div {
                    div { style: "font-size:13px;font-weight:600;color:var(--accent);margin-bottom:4px;",
                        EduGloss { term: "MgmtAccessPolicy" }
                    }
                    div { style: "font-size:12px;color:var(--text-muted);line-height:1.6;",
                        "Controls which clients can issue management commands and how they're authenticated. "
                        "Edits to the configurable rows below take effect live; rows marked "
                        span { class: "badge badge-gray", "pending_restart" }
                        " require a forwarder restart. Every change is bridged into the dashboard's "
                        EduGloss { term: "Audit log" }
                        " so the policy history is reconstructable."
                    }
                }
            }
        }

        match live {
            None => rsx! {
                div { class: "empty",
                    "Waiting for /localhost/nfd/security/policy-get response… (this dashboard polls every 3 s)"
                }
            },
            Some(_) => {
                let d = draft.read().clone();
                let view = d.unwrap_or_default();
                rsx! {
                    MgmtAccessEditor {
                        view: view.clone(),
                        is_ephemeral,
                        pib_path: pib_path.clone(),
                        on_toggle_require_signed: move |v: bool| {
                            let snapshot = draft.peek().clone();
                            if let Some(mut cur) = snapshot {
                                cur.require_signed_commands = v;
                                draft.set(Some(cur));
                            }
                        },
                        on_toggle_localhop_disabled: move |v: bool| {
                            let snapshot = draft.peek().clone();
                            if let Some(mut cur) = snapshot {
                                cur.localhop_disabled = v;
                                draft.set(Some(cur));
                            }
                        },
                        on_toggle_ephemeral_allowed: move |v: bool| {
                            let snapshot = draft.peek().clone();
                            if let Some(mut cur) = snapshot {
                                cur.ephemeral_allowed = v;
                                draft.set(Some(cur));
                            }
                        },
                        on_set_validator_anchor: move |s: String| {
                            let snapshot = draft.peek().clone();
                            if let Some(mut cur) = snapshot {
                                cur.validator_anchor = (!s.trim().is_empty()).then(|| s.trim().to_owned());
                                draft.set(Some(cur));
                            }
                        },
                        on_submit: move |snapshot: MgmtAccessPolicySnapshot| {
                            ctx.cmd.send(DashCmd::SecurityPolicySet(snapshot));
                        },
                        on_reset: move |_: ()| {
                            let cur = ctx.mgmt_access_policy.peek().clone();
                            draft.set(cur);
                        },
                    }
                }
            }
        }
    }
}

#[component]
fn MgmtAccessEditor(
    view: MgmtAccessPolicySnapshot,
    is_ephemeral: bool,
    pib_path: Option<String>,
    on_toggle_require_signed: EventHandler<bool>,
    on_toggle_localhop_disabled: EventHandler<bool>,
    on_toggle_ephemeral_allowed: EventHandler<bool>,
    on_set_validator_anchor: EventHandler<String>,
    on_submit: EventHandler<MgmtAccessPolicySnapshot>,
    on_reset: EventHandler<()>,
) -> Element {
    let anchor_value = view.validator_anchor.clone().unwrap_or_default();

    rsx! {
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:14px;",
            div { style: "font-size:12px;font-weight:600;color:var(--text);margin-bottom:8px;",
                "Hardcoded floors"
                span {
                    style: "margin-left:8px;font-size:10px;font-weight:500;color:var(--text-muted);",
                    "compiled in — cannot be relaxed at runtime"
                }
            }
            FloorRow {
                label: "Mgmt command rate limit",
                value: "100 / minute",
                detail: "Excess commands return STATUS 429. Raise by recompiling with a tuned `MgmtHandles` rate-limit config.",
            }
            FloorRow {
                label: "Replay window (SignatureTime)",
                value: format!("±{} s", view.replay_window_secs),
                detail: "Signed commands carrying a SignatureTime outside this window are rejected as replays (audit N.10). Floor: 60 s.",
            }
            FloorRow {
                label: "TLS WebSocket",
                value: "no silent downgrade",
                detail: "If a face advertises TLS, the forwarder refuses to downgrade to plaintext on reconnect.",
            }
            FloorRow {
                label: "In-browser build",
                value: "limited surface",
                detail: "When the forwarder is hosted inside a browser tab (?engine=local) certain mgmt operations refuse — no FilePib mutation, no YubiKey, no system signer.",
            }
        }

        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:14px;",
            div { style: "font-size:12px;font-weight:600;color:var(--text);margin-bottom:10px;",
                "Configurable defaults"
                span {
                    style: "margin-left:8px;font-size:10px;font-weight:500;color:var(--text-muted);",
                    "live edits — applied without a forwarder restart"
                }
            }

            BoolRow {
                label: "Require signed commands",
                checked: view.require_signed_commands,
                description: "When ON, every management Interest must be a Signed Interest verified by the validator. When OFF (default for new forwarders) anyone with WebSocket access can issue commands.",
                consequence: "Turning this OFF allows unsigned mgmt commands on this forwarder.",
                on_change: move |v| on_toggle_require_signed.call(v),
            }
            BoolRow {
                label: "Localhop commands disabled",
                checked: view.localhop_disabled,
                description: "When ON, /localhop/nfd/* command Interests are rejected with STATUS 403 regardless of signing — useful when no localhop trust anchor is configured.",
                consequence: "Turning this OFF lets neighbours on the same link issue mgmt commands via /localhop/nfd/* (signed only if `require_signed_commands` is also ON).",
                on_change: move |v| on_toggle_localhop_disabled.call(v),
            }
            BoolRow {
                label: "Allow ephemeral signing identity",
                checked: view.ephemeral_allowed,
                description: "When ON, the forwarder may sign management responses with an in-memory ephemeral key when no PIB identity is configured. When OFF, mgmt responses are refused until a persistent identity is loaded.",
                consequence: "Turning this OFF without a configured persistent identity will break the dashboard's connection.",
                on_change: move |v| on_toggle_ephemeral_allowed.call(v),
            }

            div { style: "padding:10px 0;border-top:1px solid var(--border-subtle);",
                div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;",
                    div { style: "font-size:12px;color:var(--text);",
                        "Validator anchor (mgmt signing anchor)"
                        span { style: "margin-left:8px;", class: "badge badge-gray", "pending_restart" }
                    }
                }
                div { style: "font-size:11px;color:var(--text-muted);margin-bottom:6px;",
                    "The "
                    EduGloss { term: "Trust anchor" }
                    " the forwarder uses to verify signed management commands. Changing this requires a forwarder restart — the Validator rebuilds at startup."
                }
                input {
                    r#type: "text",
                    placeholder: "/lab/router-ca/KEY/k0",
                    value: "{anchor_value}",
                    oninput: move |e| on_set_validator_anchor.call(e.value()),
                    style: "width:100%;",
                }
            }
        }

        div { style: "display:flex;gap:8px;margin-bottom:14px;",
            button {
                class: "btn btn-primary",
                onclick: {
                    let snapshot = view.clone();
                    move |_| on_submit.call(snapshot.clone())
                },
                "Apply policy"
            }
            button {
                class: "btn btn-secondary",
                onclick: move |_| on_reset.call(()),
                "Reset to live"
            }
        }

        if is_ephemeral || pib_path.is_none() {
            div { style: "border:1px solid var(--yellow,#f5c518)44;background:#2a240022;border-radius:8px;padding:14px;",
                div { style: "font-size:12px;font-weight:600;color:var(--yellow,#f5c518);margin-bottom:6px;",
                    "Empty-PIB alternative — file-emitted bootstrap token"
                }
                div { style: "font-size:11px;color:var(--text-muted);line-height:1.6;",
                    "For deployments that want out-of-band-only mgmt-access bootstrap, configure the forwarder to write a one-time token to /run/ndn-fwd/bootstrap-token on cold boot. The operator reads the token over SSH and enters it here to enable signing without an in-band identity creation flow."
                }
                div { style: "margin-top:8px;font-size:11px;color:var(--text-muted);",
                    "Render-only in this checkpoint; the token-entry flow lands with the §5 sub-flows in Phase C."
                }
            }
        }

        div { style: "margin-top:14px;padding:10px 12px;background:#2a000022;border:1px solid var(--red,#f85149)55;border-radius:6px;font-size:11px;color:var(--text-muted);line-height:1.6;",
            span { style: "color:var(--red,#f85149);font-weight:600;", "⚠ " }
            "If this dashboard is connected over an unauthenticated channel (plain WebSocket on a non-local interface, no TLS), anyone reaching the bind interface can issue management commands as you. Restrict the bind interface, or move to a TLS WebSocket face."
        }
    }
}

#[component]
fn FloorRow(label: &'static str, value: String, detail: &'static str) -> Element {
    rsx! {
        div { style: "display:flex;justify-content:space-between;gap:12px;padding:8px 0;border-top:1px solid var(--border-subtle);",
            div { style: "flex:1;",
                div { style: "font-size:12px;color:var(--text);", "{label}" }
                div { style: "font-size:11px;color:var(--text-muted);margin-top:2px;", "{detail}" }
            }
            div { style: "min-width:120px;text-align:right;",
                span { class: "badge badge-gray", "compiled-in floor" }
                div { class: "mono", style: "font-size:11px;color:var(--text);margin-top:4px;", "{value}" }
            }
        }
    }
}

#[component]
fn BoolRow(
    label: &'static str,
    checked: bool,
    description: &'static str,
    consequence: &'static str,
    on_change: EventHandler<bool>,
) -> Element {
    rsx! {
        div { style: "padding:10px 0;border-top:1px solid var(--border-subtle);",
            label {
                style: "display:flex;gap:10px;align-items:flex-start;cursor:pointer;",
                input {
                    r#type: "checkbox",
                    checked,
                    onchange: move |e| on_change.call(e.value() == "true"),
                    style: "margin-top:2px;",
                }
                div { style: "flex:1;",
                    div { style: "font-size:12px;color:var(--text);font-weight:500;",
                        "{label}"
                        if !checked {
                            span { style: "margin-left:8px;", class: "badge badge-yellow", "consequence: {consequence}" }
                        }
                    }
                    div { style: "font-size:11px;color:var(--text-muted);margin-top:2px;line-height:1.5;",
                        "{description}"
                    }
                }
            }
        }
    }
}

#[component]
fn TrustPathInspector() -> Element {
    let ctx = use_context::<AppCtx>();
    let result = ctx.trust_validation.read().clone();

    rsx! {
        div {
            style: "position:fixed;inset:0;background:rgba(0,0,0,.30);z-index:60;",
            onclick: move |_| {
                let mut open = ctx.trust_inspector_open;
                open.set(false);
            },
            div {
                style: "position:absolute;top:0;right:0;bottom:0;width:min(520px,95vw);\
                        background:var(--surface);border-left:1px solid var(--border);\
                        box-shadow:-4px 0 16px rgba(0,0,0,.3);overflow-y:auto;\
                        padding:18px 20px;",
                onclick: move |e| {
                    e.stop_propagation();
                },

                TrustPathHeader { result: result.clone() }

                match result {
                    None => rsx! {
                        div { class: "empty",
                            "Walking the trust path… (the dashboard fires "
                            span { class: "mono", "security/validate" }
                            " and renders the response here)"
                        }
                    },
                    Some((target, parsed)) => rsx! {
                        TrustPathBody { target, result: parsed }
                    },
                }
            }
        }
    }
}

#[component]
fn TrustPathHeader(result: Option<(String, TrustValidationResult)>) -> Element {
    let ctx = use_context::<AppCtx>();
    let (verdict_chip_class, verdict_chip_label) = match result.as_ref() {
        None => ("badge badge-gray", "polling…"),
        Some((_, r)) if r.verdict.is_valid() => ("badge badge-green", "valid"),
        Some(_) => ("badge badge-red", "invalid"),
    };
    rsx! {
        div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;",
            div {
                div { style: "font-size:14px;font-weight:600;color:var(--text);",
                    "Trust path inspector"
                }
                div { style: "font-size:11px;color:var(--text-muted);margin-top:2px;",
                    EduGloss { term: "Trust path" }
                    " · §4.2"
                }
            }
            div { style: "display:flex;gap:8px;align-items:center;",
                span { class: "{verdict_chip_class}", "{verdict_chip_label}" }
                button {
                    class: "btn btn-secondary btn-sm",
                    onclick: move |_| {
                        let mut open = ctx.trust_inspector_open;
                        open.set(false);
                    },
                    "Close"
                }
            }
        }
    }
}

#[component]
fn TrustPathBody(target: String, result: TrustValidationResult) -> Element {
    rsx! {
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:14px;",
            div { style: "font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;",
                "Target"
            }
            div { class: "mono", style: "font-size:11px;color:var(--text);margin-top:4px;word-break:break-all;",
                "{target}"
            }
        }

        DidResolutionL2Frame { result: result.clone() }

        VerdictBox { verdict: result.verdict.clone() }

        ChainSteps { chain: result.chain.clone() }

        SchemaRulesApplied { rules: result.schema_rules_applied.clone() }

        if let Some(diag) = result.failure_diagnosis.as_ref() {
            FailureDiagnosisPanel { diagnosis: diag.clone() }
        }

        ChallengeAttestationsPanel { attestations: result.challenge_attestations.clone() }
    }
}

#[component]
fn VerdictBox(verdict: TrustVerdict) -> Element {
    match verdict {
        TrustVerdict::Valid => rsx! {
            div { style: "border:1px solid var(--green,#3fb950)55;background:#00220022;border-radius:6px;padding:10px 12px;margin-bottom:14px;",
                div { style: "font-size:12px;font-weight:600;color:var(--green,#3fb950);",
                    "✓ Valid"
                }
                div { style: "font-size:11px;color:var(--text-muted);margin-top:4px;",
                    "The cert chains back to an installed "
                    EduGloss { term: "Trust anchor" }
                    " and every link satisfies the active schema rules."
                }
            }
        },
        TrustVerdict::Invalid { failed_at, reason } => rsx! {
            div { style: "border:1px solid var(--red,#f85149)55;background:#22000022;border-radius:6px;padding:10px 12px;margin-bottom:14px;",
                div { style: "font-size:12px;font-weight:600;color:var(--red,#f85149);",
                    "✗ Invalid"
                }
                div { style: "font-size:11px;color:var(--text-muted);margin-top:6px;",
                    "Failed at "
                    span { class: "mono", style: "color:var(--text);", "{failed_at}" }
                }
                div { style: "font-size:11px;color:var(--text-muted);margin-top:4px;line-height:1.5;",
                    "Reason: {reason}"
                }
            }
        },
    }
}

#[component]
fn ChainSteps(chain: Vec<TrustChainStep>) -> Element {
    rsx! {
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:14px;",
            div { style: "display:flex;justify-content:space-between;font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;margin-bottom:6px;",
                span { "Chain steps" }
                span { "{chain.len()} step(s)" }
            }
            if chain.is_empty() {
                div { class: "empty",
                    "No chain steps to render. v1 forwarders only check anchor-set membership; the full chain walk lands when "
                    span { class: "mono", "ndn_security::Validator::trace" }
                    " is plumbed."
                }
            } else {
                for (i, step) in chain.iter().enumerate() {
                    {
                        let last = i + 1 == chain.len();
                        rsx! {
                            div { style: "padding:8px 0;border-top:1px solid var(--border-subtle);",
                                div { style: "display:flex;gap:6px;align-items:flex-start;",
                                    span { style: "font-size:14px;flex-shrink:0;",
                                        if last { "⚓" } else { "🪪" }
                                    }
                                    div { style: "flex:1;",
                                        div { class: "mono", style: "font-size:11px;color:var(--text);word-break:break-all;",
                                            "{step.name}"
                                        }
                                        div { style: "font-size:10px;color:var(--text-muted);margin-top:2px;",
                                            "signed by "
                                            span { class: "mono", "{step.signed_by}" }
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

#[component]
fn SchemaRulesApplied(rules: Vec<SchemaRuleApplied>) -> Element {
    rsx! {
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:10px;margin-bottom:14px;",
            div { style: "display:flex;justify-content:space-between;font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;margin-bottom:6px;",
                span { "Schema rules applied" }
                span { "{rules.len()} rule(s)" }
            }
            if rules.is_empty() {
                div { style: "font-size:11px;color:var(--text-muted);",
                    "No schema rules evaluated in this trace. v1 stub only checks anchor membership; per-step schema matching lands with the validator-trace API."
                }
            } else {
                for r in rules.iter() {
                    div { style: "padding:6px 0;border-top:1px solid var(--border-subtle);font-size:11px;display:flex;gap:6px;align-items:center;",
                        if r.matches {
                            span { class: "badge badge-green", "match" }
                        } else {
                            span { class: "badge badge-red", "no match" }
                        }
                        span { class: "mono", style: "color:var(--accent);", "{r.data_pattern}" }
                        span { style: "color:var(--text-muted);", "=>" }
                        span { class: "mono", style: "color:var(--green);", "{r.key_pattern}" }
                    }
                }
            }
        }
    }
}

#[component]
fn FailureDiagnosisPanel(diagnosis: FailureDiagnosis) -> Element {
    rsx! {
        div { style: "border:1px solid var(--yellow,#f5c518)55;background:#2a240022;border-radius:6px;padding:10px;margin-bottom:14px;",
            div { style: "font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;",
                "Diagnosis"
            }
            div { style: "font-size:12px;color:var(--yellow,#f5c518);margin-top:4px;font-weight:600;",
                "{diagnosis.kind}"
            }
            div { style: "font-size:11px;color:var(--text-muted);margin-top:4px;line-height:1.5;",
                "{diagnosis.hint}"
            }
        }
    }
}

#[component]
fn ChallengeAttestationsPanel(attestations: Vec<ChallengeAttestation>) -> Element {
    if attestations.is_empty() {
        return rsx! {
            div {
                style: "background:var(--surface2);border:1px dashed var(--border-subtle);border-radius:6px;padding:8px 10px;font-size:11px;color:var(--text-muted);",
                title: "NDNCERT records how each challenge was satisfied in the cert's AdditionalDescription. Empty when the cert was issued without attestations enabled.",
                "Challenge attestations: "
                span { class: "mono", "none recorded" }
            }
        };
    }
    rsx! {
        div { style: "background:var(--surface2);border:1px solid var(--border-subtle);border-radius:6px;padding:8px 10px;margin-top:10px;",
            div {
                style: "font-size:11px;color:var(--text-muted);margin-bottom:6px;",
                title: "How the subject proved control during NDNCERT enrollment — carried in the cert's signed AdditionalDescription.",
                "Challenge attestations"
            }
            for att in attestations.iter() {
                div { style: "display:flex;gap:8px;align-items:baseline;padding:3px 0;",
                    span {
                        class: "mono",
                        style: "background:var(--surface3,#1c2333);border:1px solid var(--border-subtle);border-radius:4px;padding:1px 6px;font-size:11px;color:var(--text);",
                        "{att.kind}"
                    }
                    if !att.detail.is_empty() {
                        span { style: "font-size:11px;color:var(--text-muted);", "{att.detail}" }
                    }
                }
            }
        }
    }
}

use crate::security_chains::{AuditLogEntry, AuditOutcome, audit_chain_snapshot};

#[derive(Clone, Copy, PartialEq, Eq)]
enum OutcomeFilter {
    Any,
    Accepted,
    Rejected,
    Info,
    Warning,
}

impl OutcomeFilter {
    fn matches(self, o: AuditOutcome) -> bool {
        match self {
            Self::Any => true,
            Self::Accepted => matches!(o, AuditOutcome::Accepted),
            Self::Rejected => matches!(o, AuditOutcome::Rejected),
            Self::Info => matches!(o, AuditOutcome::Info),
            Self::Warning => matches!(o, AuditOutcome::Warning),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Info => "info",
            Self::Warning => "warning",
        }
    }

    fn all() -> [OutcomeFilter; 5] {
        [
            Self::Any,
            Self::Accepted,
            Self::Rejected,
            Self::Info,
            Self::Warning,
        ]
    }
}

fn outcome_class(o: AuditOutcome) -> &'static str {
    match o {
        AuditOutcome::Accepted => "badge badge-green",
        AuditOutcome::Rejected => "badge badge-red",
        AuditOutcome::Info => "badge badge-blue",
        AuditOutcome::Warning => "badge badge-yellow",
    }
}

fn outcome_label(o: AuditOutcome) -> &'static str {
    match o {
        AuditOutcome::Accepted => "accepted",
        AuditOutcome::Rejected => "rejected",
        AuditOutcome::Info => "info",
        AuditOutcome::Warning => "warning",
    }
}

#[component]
fn AuditLogTab() -> Element {
    let entries = audit_chain_snapshot();

    let mut subject_filter: Signal<String> = use_signal(String::new);
    let mut outcome_filter: Signal<OutcomeFilter> = use_signal(|| OutcomeFilter::Any);
    let mut since_unix_s: Signal<String> = use_signal(String::new);
    let mut until_unix_s: Signal<String> = use_signal(String::new);
    let mut show_export: Signal<bool> = use_signal(|| false);

    let filtered = filter_entries(
        &entries,
        &subject_filter.read(),
        *outcome_filter.read(),
        parse_unix_s(&since_unix_s.read()),
        parse_unix_s(&until_unix_s.read()),
    );

    rsx! {
        div { class: "section-title", "Security audit log" }

        div { class: "edu-card",
            div { style: "display:flex;gap:12px;align-items:flex-start;",
                div { style: "font-size:28px;flex-shrink:0;", "📜" }
                div {
                    div { style: "font-size:13px;font-weight:600;color:var(--accent);margin-bottom:4px;",
                        EduGloss { term: "Audit log" }
                    }
                    div { style: "font-size:12px;color:var(--text-muted);line-height:1.6;",
                        "Every entry is a signed NDN Data packet at "
                        span { class: "mono", "<chain>/seq=N" }
                        " with "
                        span { class: "mono", "prev_entry_hash" }
                        " linkage. The dashboard's process-local signer signs each entry; cross-restart re-verification needs a persisted dashboard identity (v2 follow-up)."
                    }
                }
            }
        }

        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px;margin-bottom:14px;",
            div { style: "display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end;",
                div { class: "form-group", style: "flex:1;min-width:200px;",
                    label { style: "font-size:11px;color:var(--text-muted);", "Subject substring" }
                    input {
                        r#type: "text",
                        placeholder: "e.g. security/policy-set",
                        value: "{subject_filter}",
                        oninput: move |e| subject_filter.set(e.value()),
                        style: "width:100%;",
                    }
                }
                div { class: "form-group", style: "min-width:140px;",
                    label { style: "font-size:11px;color:var(--text-muted);", "Outcome" }
                    select {
                        value: "{outcome_filter.read().label()}",
                        onchange: move |e| {
                            let v = match e.value().as_str() {
                                "accepted" => OutcomeFilter::Accepted,
                                "rejected" => OutcomeFilter::Rejected,
                                "info"     => OutcomeFilter::Info,
                                "warning"  => OutcomeFilter::Warning,
                                _          => OutcomeFilter::Any,
                            };
                            outcome_filter.set(v);
                        },
                        for opt in OutcomeFilter::all() {
                            option { value: "{opt.label()}", "{opt.label()}" }
                        }
                    }
                }
                div { class: "form-group", style: "min-width:150px;",
                    label { style: "font-size:11px;color:var(--text-muted);", "Since (unix s)" }
                    input {
                        r#type: "text",
                        placeholder: "1717…",
                        value: "{since_unix_s}",
                        oninput: move |e| since_unix_s.set(e.value()),
                        style: "width:100%;",
                    }
                }
                div { class: "form-group", style: "min-width:150px;",
                    label { style: "font-size:11px;color:var(--text-muted);", "Until (unix s)" }
                    input {
                        r#type: "text",
                        placeholder: "1717…",
                        value: "{until_unix_s}",
                        oninput: move |e| until_unix_s.set(e.value()),
                        style: "width:100%;",
                    }
                }
                button {
                    class: "btn btn-secondary btn-sm",
                    onclick: move |_| {
                        subject_filter.set(String::new());
                        outcome_filter.set(OutcomeFilter::Any);
                        since_unix_s.set(String::new());
                        until_unix_s.set(String::new());
                    },
                    "Clear filters"
                }
            }
        }

        div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;",
            div { style: "font-size:11px;color:var(--text-muted);",
                "Showing "
                span { style: "color:var(--text);font-weight:600;", "{filtered.len()}" }
                " of "
                span { style: "color:var(--text);font-weight:600;", "{entries.len()}" }
                " entries"
            }
            button {
                class: "btn btn-secondary btn-sm",
                disabled: filtered.is_empty(),
                onclick: move |_| show_export.set(true),
                "Export filtered…"
            }
        }

        AuditLogStream { entries: filtered.clone() }

        if *show_export.read() {
            AuditExportModal {
                entries: filtered.clone(),
                on_close: move |_: ()| show_export.set(false),
            }
        }
    }
}

fn filter_entries(
    all: &[AuditLogEntry],
    subject: &str,
    outcome: OutcomeFilter,
    since: Option<u64>,
    until: Option<u64>,
) -> Vec<AuditLogEntry> {
    let needle = subject.trim().to_lowercase();
    all.iter()
        .filter(|e| {
            if !needle.is_empty() && !e.subject.to_lowercase().contains(&needle) {
                return false;
            }
            if !outcome.matches(e.outcome) {
                return false;
            }
            let ts_s = e.ts_unix_ns / 1_000_000_000;
            if let Some(s) = since
                && ts_s < s
            {
                return false;
            }
            if let Some(u) = until
                && ts_s > u
            {
                return false;
            }
            true
        })
        .cloned()
        .collect()
}

fn parse_unix_s(s: &str) -> Option<u64> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    t.parse::<u64>().ok()
}

#[component]
fn AuditLogStream(entries: Vec<AuditLogEntry>) -> Element {
    if entries.is_empty() {
        return rsx! {
            div { class: "empty",
                "No audit entries match the active filter. As you edit mgmt-access policy (§4.5) or take other audited actions, entries appear here head→tail."
            }
        };
    }
    rsx! {
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;overflow:hidden;",
            for (i, entry) in entries.iter().enumerate() {
                {
                    let last = i + 1 == entries.len();
                    let bottom_border = if last { "" } else { "border-bottom:1px solid var(--border-subtle);" };
                    let ts_label = format_unix_ns(entry.ts_unix_ns);
                    let outcome = entry.outcome;
                    let subject = entry.subject.clone();
                    let detail = entry.detail.clone();
                    rsx! {
                        div { style: "padding:10px 12px;{bottom_border}",
                            div { style: "display:flex;gap:8px;align-items:center;margin-bottom:4px;",
                                span { class: "{outcome_class(outcome)}", "{outcome_label(outcome)}" }
                                span { class: "mono", style: "font-size:11px;color:var(--text);", "{subject}" }
                                span { style: "margin-left:auto;font-size:10px;color:var(--text-muted);", "{ts_label}" }
                            }
                            div { style: "font-size:11px;color:var(--text-muted);word-break:break-all;line-height:1.5;",
                                "{detail}"
                            }
                        }
                    }
                }
            }
        }
    }
}

fn format_unix_ns(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    let nanos = ns % 1_000_000_000;
    let date = format_unix_date(secs);
    let day_secs = secs % 86_400;
    let h = day_secs / 3600;
    let m = (day_secs % 3600) / 60;
    let s = day_secs % 60;
    let ms = nanos / 1_000_000;
    format!("{date} {h:02}:{m:02}:{s:02}.{ms:03}Z")
}

#[component]
fn AuditExportModal(entries: Vec<AuditLogEntry>, on_close: EventHandler<()>) -> Element {
    let mut include_names: Signal<bool> = use_signal(|| true);
    let mut hash_names: Signal<bool> = use_signal(|| false);
    let mut copied: Signal<bool> = use_signal(|| false);

    let body = serialize_export(&entries, *include_names.read(), *hash_names.read());

    rsx! {
        div {
            style: "position:fixed;inset:0;background:rgba(0,0,0,.40);z-index:70;display:flex;align-items:center;justify-content:center;",
            onclick: move |_| on_close.call(()),
            div {
                style: "background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:18px 20px;width:min(600px,95vw);max-height:85vh;overflow:auto;",
                onclick: move |e| { e.stop_propagation(); },
                div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;",
                    div { style: "font-size:14px;font-weight:600;color:var(--text);", "Export audit log" }
                    button {
                        class: "btn btn-secondary btn-sm",
                        onclick: move |_| on_close.call(()),
                        "Close"
                    }
                }
                div { style: "font-size:11px;color:var(--text-muted);margin-bottom:12px;line-height:1.5;",
                    "Two-checkbox scrub per §11.3. Stable hashes are SHA-256(name) truncated to 64 bits — deterministic across exports so correlation across shared logs remains possible without revealing the original names."
                }
                label { style: "display:flex;gap:8px;align-items:center;margin-bottom:6px;font-size:12px;cursor:pointer;",
                    input {
                        r#type: "checkbox",
                        checked: *include_names.read(),
                        onchange: move |e| include_names.set(e.value() == "true"),
                    }
                    span { "Include identity names" }
                }
                label { style: "display:flex;gap:8px;align-items:center;margin-bottom:14px;font-size:12px;cursor:pointer;",
                    input {
                        r#type: "checkbox",
                        checked: *hash_names.read(),
                        onchange: move |e| hash_names.set(e.value() == "true"),
                    }
                    span { "Replace with stable hashes" }
                }
                div { style: "font-size:11px;color:var(--text-muted);margin-bottom:6px;",
                    "{entries.len()} entries · {body.len()} bytes"
                }
                pre {
                    style: "background:var(--bg);border:1px solid var(--border-subtle);border-radius:4px;padding:10px;font-size:11px;max-height:300px;overflow:auto;",
                    "{body}"
                }
                div { style: "display:flex;gap:8px;margin-top:12px;",
                    button {
                        class: if *copied.read() { "btn btn-success" } else { "btn btn-primary" },
                        onclick: {
                            let body = body.clone();
                            move |_| {
                                copy_to_clipboard(&body);
                                copied.set(true);
                            }
                        },
                        if *copied.read() { "✓ Copied" } else { "Copy to clipboard" }
                    }
                }
            }
        }
    }
}

fn serialize_export(entries: &[AuditLogEntry], include_names: bool, hash_names: bool) -> String {
    use serde_json::{Map, Value};

    let mut arr = Vec::with_capacity(entries.len());
    for e in entries {
        let mut obj = Map::new();
        obj.insert(
            "ts_unix_ns".into(),
            Value::Number(serde_json::Number::from(e.ts_unix_ns)),
        );
        obj.insert(
            "outcome".into(),
            Value::String(outcome_label(e.outcome).into()),
        );
        obj.insert("subject".into(), Value::String(e.subject.clone()));
        let detail = scrub_detail(&e.detail, include_names, hash_names);
        obj.insert("detail".into(), Value::String(detail));
        arr.push(Value::Object(obj));
    }
    let wrapped = serde_json::json!({
        "format": "ndn-dashboard.audit-log.v1",
        "include_names": include_names,
        "hash_names": hash_names,
        "entries": arr,
    });
    serde_json::to_string_pretty(&wrapped).unwrap_or_default()
}

fn scrub_detail(detail: &str, include_names: bool, hash_names: bool) -> String {
    let mut out = String::with_capacity(detail.len());
    for token in detail.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        if let Some((k, v)) = token.split_once('=')
            && v.starts_with('/')
        {
            out.push_str(k);
            out.push('=');
            match (include_names, hash_names) {
                (true, false) => out.push_str(v),
                (true, true) => {
                    out.push_str(v);
                    out.push_str(" (hash=");
                    out.push_str(&stable_hash(v));
                    out.push(')');
                }
                (false, true) => {
                    out.push_str("hash=");
                    out.push_str(&stable_hash(v));
                }
                (false, false) => out.push_str("<scrubbed>"),
            }
            continue;
        }
        out.push_str(token);
    }
    out
}

fn stable_hash(name: &str) -> String {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    let digest = h.finalize();
    let mut out = String::with_capacity(16);
    for b in &digest[..8] {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(feature = "desktop")]
fn copy_to_clipboard(s: &str) {
    if let Ok(mut cb) = arboard::Clipboard::new() {
        let _ = cb.set_text(s.to_owned());
    }
}

#[cfg(not(feature = "desktop"))]
fn copy_to_clipboard(s: &str) {
    let s = s.to_owned();
    wasm_bindgen_futures::spawn_local(async move {
        let Some(window) = web_sys::window() else {
            return;
        };
        let nav = window.navigator();
        let nav_js: wasm_bindgen::JsValue = nav.into();
        let clipboard =
            match js_sys::Reflect::get(&nav_js, &wasm_bindgen::JsValue::from_str("clipboard")) {
                Ok(v) if !v.is_undefined() && !v.is_null() => v,
                _ => {
                    tracing::warn!(
                        target: "dashboard.security",
                        "clipboard API unavailable — falling back to render-only"
                    );
                    return;
                }
            };
        let write_fn =
            match js_sys::Reflect::get(&clipboard, &wasm_bindgen::JsValue::from_str("writeText")) {
                Ok(v) if v.is_function() => v,
                _ => return,
            };
        let func: js_sys::Function = write_fn.into();
        let promise = match func.call1(&clipboard, &wasm_bindgen::JsValue::from_str(&s)) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    target: "dashboard.security",
                    error = ?e,
                    "clipboard writeText invocation failed"
                );
                return;
            }
        };
        let promise: js_sys::Promise = promise.into();
        if let Err(e) = wasm_bindgen_futures::JsFuture::from(promise).await {
            tracing::warn!(
                target: "dashboard.security",
                error = ?e,
                "clipboard writeText rejected (permission denied or restricted context)"
            );
        }
    });
}

#[component]
fn TrustedCaList(
    local_ca: Option<CaInfo>,
    anchors: Vec<AnchorInfo>,
    on_promote_from_anchor: EventHandler<String>,
) -> Element {
    let trusted_count = anchors.len() + if local_ca.is_some() { 1 } else { 0 };
    rsx! {
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px;margin-top:14px;margin-bottom:10px;",
            div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;",
                div { style: "font-size:12px;font-weight:600;color:var(--text);",
                    "Trusted"
                    span { style: "margin-left:8px;font-size:10px;font-weight:500;color:var(--text-muted);",
                        "{trusted_count} root(s)"
                    }
                }
                span { class: "badge badge-green", "active" }
            }

            if let Some(info) = local_ca.as_ref() {
                CaRow {
                    name: info.ca_prefix.clone(),
                    badge_text: "local · self-signed",
                    badge_class: "badge badge-green",
                    detail: if info.ca_info.is_empty() {
                        format!("max validity {}d · {} challenge(s)", info.max_validity_days, info.challenges.len())
                    } else {
                        format!("{} · max validity {}d", info.ca_info, info.max_validity_days)
                    },
                    on_promote: None,
                }
            }

            for a in anchors.iter() {
                CaRow {
                    name: a.name.clone(),
                    badge_text: "anchor",
                    badge_class: "badge badge-blue",
                    detail: "Installed trust anchor — promotes were journaled to schema-journal at install time.".to_string(),
                    on_promote: Some(EventHandler::new({
                        let name = a.name.clone();
                        let cb = on_promote_from_anchor;
                        move |_: ()| cb.call(name.clone())
                    })),
                }
            }

            if trusted_count == 0 {
                div { class: "empty",
                    "No trusted CAs configured. Run the forwarder with a "
                    EduGloss { term: "Trust anchor" }
                    " or promote a discovered CA below."
                }
            }
        }
    }
}

#[component]
fn CaRow(
    name: String,
    badge_text: &'static str,
    badge_class: &'static str,
    detail: String,
    on_promote: Option<EventHandler<()>>,
) -> Element {
    rsx! {
        div { style: "padding:10px 0;border-top:1px solid var(--border-subtle);display:flex;gap:10px;align-items:flex-start;",
            span { style: "font-size:18px;flex-shrink:0;", "🏛" }
            div { style: "flex:1;",
                div { style: "display:flex;gap:6px;align-items:center;flex-wrap:wrap;",
                    span { class: "mono", style: "font-size:12px;color:var(--text);", "{name}" }
                    span { class: "{badge_class}", "{badge_text}" }
                }
                div { style: "font-size:11px;color:var(--text-muted);margin-top:4px;line-height:1.5;",
                    "{detail}"
                }
            }
            if let Some(cb) = on_promote {
                button {
                    class: "btn btn-secondary btn-sm",
                    onclick: move |_| cb.call(()),
                    "Re-verify"
                }
            }
        }
    }
}

#[component]
fn DiscoveredCaList(on_promote: EventHandler<String>) -> Element {
    let _ = on_promote;
    rsx! {
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:10px;",
            div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;",
                div { style: "font-size:12px;font-weight:600;color:var(--text);",
                    "Discovered"
                    span { style: "margin-left:8px;font-size:10px;font-weight:500;color:var(--text-muted);",
                        "0 in window"
                    }
                }
                span { class: "badge badge-gray", "no wire yet" }
            }
            div { class: "empty",
                "Service-discovery CA probes will surface here as they arrive. v1 forwarders don't yet emit the wire signal; once "
                span { class: "mono", "security/ca-discovered" }
                " lands, discovered CAs show up with a "
                span { class: "mono", "{DISCOVERY_WINDOW_SECS}" }
                "-second time-window (§11.4 mitigation 3) and require the TOFU ceremony to promote."
            }
        }
    }
}

#[component]
fn PromoteToTrustedModal(
    prefill_name: String,
    initiator_name: String,
    is_initiator_ephemeral: bool,
    on_close: EventHandler<()>,
) -> Element {
    let ctx = use_context::<AppCtx>();
    let mut name: Signal<String> = use_signal(|| prefill_name.clone());
    let mut fingerprint: Signal<String> = use_signal(String::new);
    let mut cert_wire: Signal<String> = use_signal(String::new);
    let mut acknowledged: Signal<bool> = use_signal(|| false);
    let mut journaled: Signal<bool> = use_signal(|| false);

    let fp_text = fingerprint.read().clone();
    let fp_bytes = parse_fingerprint_hex(&fp_text);
    let fp_valid = fp_bytes.as_ref().map(|b| b.len() >= 4).unwrap_or(false);
    let name_valid = !name.read().trim().is_empty();
    let cert_text = cert_wire.read().clone();
    let cert_present = !cert_text.trim().is_empty();
    let cert_parses = parse_fingerprint_hex(&cert_text).is_some();
    let cert_ok = !cert_present || cert_parses;
    let can_confirm =
        name_valid && fp_valid && cert_ok && *acknowledged.read() && !*journaled.read();
    let _ = initiator_name;
    let _ = is_initiator_ephemeral;

    rsx! {
        div {
            style: "position:fixed;inset:0;background:rgba(0,0,0,.40);z-index:75;display:flex;align-items:center;justify-content:center;",
            onclick: move |_| on_close.call(()),
            div {
                style: "background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:18px 22px;width:min(640px,95vw);max-height:90vh;overflow:auto;",
                onclick: move |e| { e.stop_propagation(); },

                div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;",
                    div { style: "font-size:14px;font-weight:600;color:var(--text);",
                        "Promote CA to trusted"
                    }
                    button {
                        class: "btn btn-secondary btn-sm",
                        onclick: move |_| on_close.call(()),
                        "Close"
                    }
                }
                div { style: "font-size:11px;color:var(--text-muted);margin-bottom:14px;line-height:1.5;",
                    EduGloss { term: "TOFU" }
                    " ceremony (§11.4) — verify the fingerprint via an out-of-band channel (a printed card, a signed Slack message, a phone call) before promoting. The decision is appended to the dashboard's "
                    EduGloss { term: "Schema journal" }
                    ", so future audits can replay what you trusted and when."
                }

                div { class: "form-group", style: "margin-bottom:10px;",
                    label { style: "font-size:11px;color:var(--text-muted);",
                        "CA anchor name"
                    }
                    input {
                        r#type: "text",
                        placeholder: "/lab/router-ca/KEY/k0",
                        value: "{name}",
                        oninput: move |e| name.set(e.value()),
                        style: "width:100%;",
                    }
                }

                div { class: "form-group", style: "margin-bottom:10px;",
                    label { style: "font-size:11px;color:var(--text-muted);",
                        "Anchor fingerprint (hex, 8–64 chars)"
                    }
                    input {
                        r#type: "text",
                        placeholder: "ab12cd34ef56…",
                        value: "{fingerprint}",
                        oninput: move |e| fingerprint.set(e.value()),
                        style: "width:100%;",
                    }
                }

                if let Some(bytes) = fp_bytes.as_ref() {
                    FingerprintVisual { bytes: bytes.clone() }
                } else if !fp_text.trim().is_empty() {
                    div { style: "font-size:11px;color:var(--red,#f85149);margin-bottom:10px;",
                        "Fingerprint must be hexadecimal (whitespace and colons ignored)."
                    }
                }

                div { class: "form-group", style: "margin-bottom:10px;",
                    label { style: "font-size:11px;color:var(--text-muted);",
                        "Anchor cert wire (hex, optional — empty ⇒ journal intent only)"
                    }
                    textarea {
                        style: "width:100%;height:80px;background:var(--bg);border:1px solid var(--border-subtle);border-radius:4px;padding:8px;font-family:monospace;font-size:11px;color:var(--text);resize:vertical;",
                        placeholder: "06fd…  (paste the full Data wire of the anchor cert)",
                        value: "{cert_wire}",
                        oninput: move |e| cert_wire.set(e.value()),
                    }
                    if cert_present && !cert_parses {
                        div { style: "font-size:11px;color:var(--red,#f85149);margin-top:4px;",
                            "Cert wire must be hexadecimal (whitespace, colons, and hyphens ignored)."
                        }
                    } else if cert_present {
                        div { style: "font-size:11px;color:var(--green,#3fb950);margin-top:4px;",
                            "✓ Will fire "
                            span { class: "mono", "security/anchor-add" }
                            " on confirm."
                        }
                    } else {
                        div { style: "font-size:11px;color:var(--text-muted);margin-top:4px;",
                            "No cert wire — journals the TOFU decision but doesn't install the anchor on the forwarder."
                        }
                    }
                }

                label { style: "display:flex;gap:8px;align-items:flex-start;margin:12px 0;font-size:12px;cursor:pointer;line-height:1.5;",
                    input {
                        r#type: "checkbox",
                        checked: *acknowledged.read(),
                        onchange: move |e| acknowledged.set(e.value() == "true"),
                        style: "margin-top:3px;",
                    }
                    span {
                        "I confirmed this fingerprint with the CA operator via an out-of-band channel. I understand promoting accepts every cert this CA issues from this point forward."
                    }
                }

                if *journaled.read() {
                    div { style: "padding:10px;background:#00220022;border:1px solid var(--green,#3fb950)55;border-radius:4px;font-size:11px;color:var(--text);margin-bottom:10px;",
                        if cert_present {
                            "✓ Anchor-add fired and promotion journaled. The forwarder now trusts this anchor for subsequent validations."
                        } else {
                            "✓ TOFU decision journaled (intent-only). Re-open with the cert wire to install the anchor on the forwarder."
                        }
                    }
                }

                div { style: "display:flex;gap:8px;justify-content:flex-end;",
                    button {
                        class: if can_confirm { "btn btn-primary" } else { "btn btn-secondary" },
                        disabled: !can_confirm,
                        onclick: {
                            let fp_val = fp_bytes.clone().unwrap_or_default();
                            move |_| {
                                let name_val = name.peek().trim().to_owned();
                                let cert_hex_val = cert_wire.peek().trim().to_owned();
                                let fp_hex: String =
                                    fp_val.iter().map(|b| format!("{b:02x}")).collect();
                                ctx.cmd.send(DashCmd::SecurityAnchorAdd {
                                    name: name_val,
                                    fingerprint_hex: fp_hex,
                                    cert_wire_hex: cert_hex_val,
                                });
                                journaled.set(true);
                            }
                        },
                        if cert_present { "Promote & install" } else { "Journal intent only" }
                    }
                }
            }
        }
    }
}

#[component]
fn FingerprintVisual(bytes: Vec<u8>) -> Element {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let hex_grouped = group_hex(&hex);
    let words = fingerprint_words(&bytes);
    rsx! {
        div { style: "background:var(--bg);border:1px solid var(--border-subtle);border-radius:4px;padding:10px;margin-bottom:10px;",
            div { style: "font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px;",
                "Hex"
            }
            div { class: "mono", style: "font-size:12px;color:var(--text);word-break:break-all;margin-bottom:8px;",
                "{hex_grouped}"
            }
            div { style: "font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px;",
                "Word-pair (PGP biometric-style)"
            }
            div { style: "font-size:12px;color:var(--text);font-weight:500;",
                "{words}"
            }
            div { style: "font-size:10px;color:var(--text-muted);margin-top:6px;",
                "Read the words aloud to verify with the CA operator; the encoding is deterministic so the same bytes always produce the same words."
            }
        }
    }
}

fn parse_fingerprint_hex(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '-')
        .collect();
    if cleaned.len() < 2 || !cleaned.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for chunk in cleaned.as_bytes().chunks(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

fn group_hex(hex: &str) -> String {
    let mut out = String::with_capacity(hex.len() + hex.len() / 4);
    for (i, c) in hex.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// PGP-biometric-style word encoding using fixed 32-word even/odd lists.
/// Renders the first 6 bytes as 3 word-pairs.
fn fingerprint_words(bytes: &[u8]) -> String {
    let take = bytes.len().min(6);
    let mut out = String::new();
    for (i, b) in bytes.iter().take(take).enumerate() {
        let word = if i % 2 == 0 {
            EVEN_WORDS[(b % 32) as usize]
        } else {
            ODD_WORDS[(b % 32) as usize]
        };
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    if bytes.len() > take {
        out.push_str(" …");
    }
    out
}

const EVEN_WORDS: [&str; 32] = [
    "amber", "anchor", "apple", "atlas", "basil", "beacon", "birch", "bronze", "canyon", "cedar",
    "cobalt", "coral", "crystal", "dahlia", "delta", "ember", "falcon", "forest", "garnet",
    "harbor", "ivory", "jasper", "kestrel", "lichen", "marble", "nectar", "onyx", "pebble",
    "quartz", "raven", "spruce", "thistle",
];

const ODD_WORDS: [&str; 32] = [
    "Aspen", "Boreal", "Citrus", "Drift", "Echo", "Fjord", "Glen", "Hazel", "Iris", "Juniper",
    "Krill", "Lumen", "Marrow", "Nimbus", "Otter", "Pollen", "Quill", "Radian", "Sable", "Talon",
    "Umber", "Verdant", "Willow", "Xenon", "Yarrow", "Zephyr", "Astral", "Briar", "Cinder",
    "Drake", "Equinox", "Frost",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_chains::{AuditLogEntry, AuditOutcome};

    fn mk(ts_s: u64, outcome: AuditOutcome, subject: &str, detail: &str) -> AuditLogEntry {
        AuditLogEntry {
            ts_unix_ns: ts_s * 1_000_000_000,
            outcome,
            subject: subject.into(),
            detail: detail.into(),
        }
    }

    fn sample() -> Vec<AuditLogEntry> {
        vec![
            mk(
                1_700_000_000,
                AuditOutcome::Accepted,
                "security/policy-set",
                "initiator=/lab/alice/KEY/k1 policy_content_hash=ab12",
            ),
            mk(
                1_700_000_100,
                AuditOutcome::Rejected,
                "security/anchor-remove",
                "by=/lab/bob/KEY/k0 reason=sig-invalid",
            ),
            mk(
                1_700_000_200,
                AuditOutcome::Info,
                "rib/register",
                "name=/lab/alice/data face=4 cost=0",
            ),
        ]
    }

    #[test]
    fn filter_subject_substring_is_case_insensitive() {
        let s = sample();
        let f = filter_entries(&s, "POLICY-SET", OutcomeFilter::Any, None, None);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].subject, "security/policy-set");
    }

    #[test]
    fn filter_outcome_dropdown_pins_each_variant() {
        let s = sample();
        assert_eq!(
            filter_entries(&s, "", OutcomeFilter::Accepted, None, None).len(),
            1
        );
        assert_eq!(
            filter_entries(&s, "", OutcomeFilter::Rejected, None, None).len(),
            1
        );
        assert_eq!(
            filter_entries(&s, "", OutcomeFilter::Info, None, None).len(),
            1
        );
        assert_eq!(
            filter_entries(&s, "", OutcomeFilter::Warning, None, None).len(),
            0
        );
        assert_eq!(
            filter_entries(&s, "", OutcomeFilter::Any, None, None).len(),
            3
        );
    }

    #[test]
    fn filter_time_range_inclusive_at_boundaries() {
        let s = sample();
        let f = filter_entries(&s, "", OutcomeFilter::Any, Some(1_700_000_100), None);
        assert_eq!(f.len(), 2);
        let f = filter_entries(&s, "", OutcomeFilter::Any, None, Some(1_700_000_100));
        assert_eq!(f.len(), 2);
        let f = filter_entries(
            &s,
            "",
            OutcomeFilter::Any,
            Some(1_700_000_100),
            Some(1_700_000_100),
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].subject, "security/anchor-remove");
    }

    #[test]
    fn parse_unix_s_blank_is_none() {
        assert_eq!(parse_unix_s(""), None);
        assert_eq!(parse_unix_s("   "), None);
        assert_eq!(parse_unix_s("notanumber"), None);
        assert_eq!(parse_unix_s(" 1700000000 "), Some(1_700_000_000));
    }

    #[test]
    fn export_scrub_same_inputs_same_output() {
        let s = sample();
        let a = serialize_export(&s, true, false);
        let b = serialize_export(&s, true, false);
        assert_eq!(a, b, "deterministic export — no random salts");
        let c = serialize_export(&s, false, true);
        let d = serialize_export(&s, false, true);
        assert_eq!(c, d);
    }

    #[test]
    fn export_scrub_replace_with_stable_hashes_removes_names() {
        let s = sample();
        let scrubbed = serialize_export(&s, false, true);
        assert!(!scrubbed.contains("/lab/alice/KEY/k1"));
        assert!(!scrubbed.contains("/lab/bob/KEY/k0"));
        assert!(scrubbed.contains("hash="));
    }

    #[test]
    fn export_scrub_include_with_hash_preserves_correlation() {
        let s = sample();
        let body = serialize_export(&s, true, true);
        assert!(body.contains("/lab/alice/KEY/k1"));
        assert!(body.contains("(hash="));
    }

    #[test]
    fn export_scrub_drop_entirely_when_both_false() {
        let s = sample();
        let body = serialize_export(&s, false, false);
        assert!(!body.contains("/lab/alice"));
        assert!(body.contains("<scrubbed>"));
    }

    #[test]
    fn stable_hash_is_deterministic() {
        let h1 = stable_hash("/lab/alice/KEY/k1");
        let h2 = stable_hash("/lab/alice/KEY/k1");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 16, "first 8 bytes as hex");
        assert_ne!(h1, stable_hash("/lab/bob/KEY/k0"));
    }

    #[test]
    fn parse_fingerprint_strips_separators() {
        let cases = [
            ("abcd1234", vec![0xab, 0xcd, 0x12, 0x34]),
            ("ab:cd:12:34", vec![0xab, 0xcd, 0x12, 0x34]),
            ("ab-cd-12-34", vec![0xab, 0xcd, 0x12, 0x34]),
            ("ab cd  12\t34\n", vec![0xab, 0xcd, 0x12, 0x34]),
            ("ABCD1234", vec![0xab, 0xcd, 0x12, 0x34]),
        ];
        for (input, expected) in cases {
            assert_eq!(
                parse_fingerprint_hex(input),
                Some(expected.clone()),
                "input: {input}"
            );
        }
    }

    #[test]
    fn parse_fingerprint_rejects_odd_or_nonhex() {
        assert_eq!(parse_fingerprint_hex("abc"), None);
        assert_eq!(parse_fingerprint_hex("ghij"), None);
        assert_eq!(parse_fingerprint_hex("aXcd"), None);
        assert_eq!(parse_fingerprint_hex(""), None);
        assert_eq!(parse_fingerprint_hex("  "), None);
    }

    #[test]
    fn fingerprint_words_is_deterministic_and_uses_even_odd_lists() {
        let bytes = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let w1 = fingerprint_words(&bytes);
        let w2 = fingerprint_words(&bytes);
        assert_eq!(w1, w2);
        assert_eq!(
            w1,
            format!(
                "{} {} {} {} {} {}",
                EVEN_WORDS[0],
                ODD_WORDS[0],
                EVEN_WORDS[0],
                ODD_WORDS[0],
                EVEN_WORDS[0],
                ODD_WORDS[0]
            )
        );

        let bytes2 = vec![0x01, 0x01];
        let w3 = fingerprint_words(&bytes2);
        assert_ne!(w1, w3);

        let bytes3 = vec![0xff, 0xff];
        let w4 = fingerprint_words(&bytes3);
        assert!(!w4.contains('…'), "no ellipsis when bytes <= 6");

        let bytes5 = vec![0u8; 32];
        let w5 = fingerprint_words(&bytes5);
        assert!(w5.ends_with('…'));
    }

    #[test]
    fn group_hex_splits_into_4char_groups() {
        assert_eq!(group_hex("abcd1234"), "abcd 1234");
        assert_eq!(group_hex("ab"), "ab");
        assert_eq!(group_hex("abcd12345678"), "abcd 1234 5678");
    }
}
