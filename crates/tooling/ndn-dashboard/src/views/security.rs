//! Security view — identity management, trust anchors, certificate chain,
//! DID explorer, NDNCERT CA panel, YubiKey integration, and the §4.5
//! mgmt-access policy editor.

use crate::app::{AppCtx, DashCmd, ToastLevel, push_toast};
use crate::edu_gloss::EduGloss;
use crate::types::{
    AnchorInfo, MgmtAccessPolicySnapshot, SchemaRuleInfo, SecurityKeyInfo, ValidationStats,
};
use crate::views::onboarding::encode_did_ndn;
use dioxus::prelude::*;
use std::collections::VecDeque;

// ── Tab IDs ───────────────────────────────────────────────────────────────────

const TAB_IDENTITIES: u8 = 0;
const TAB_TRUST: u8 = 1;
const TAB_CHAIN: u8 = 2;
const TAB_DID: u8 = 3;
const TAB_CA: u8 = 4;
const TAB_YUBIKEY: u8 = 5;
const TAB_MGMT_ACCESS: u8 = 7;

// ── Root component ────────────────────────────────────────────────────────────

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

    let tabs: &[(&str, u8)] = &[
        ("Identities", TAB_IDENTITIES),
        ("Trust & Schema", TAB_TRUST),
        ("Cert Chain", TAB_CHAIN),
        ("DID", TAB_DID),
        ("CA / NDNCERT", TAB_CA),
        ("YubiKey", TAB_YUBIKEY),
        ("Mgmt Access", TAB_MGMT_ACCESS),
    ];

    rsx! {
        div { class: "section",

            // ── Ephemeral identity warning ────────────────────────────────────
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

            // ── Persistent identity info bar ──────────────────────────────────
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

            // ── Tab bar ──────────────────────────────────────────────────────
            div { style: "display:flex;gap:6px;margin-bottom:16px;flex-wrap:wrap;",
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

            match *active_tab.read() {
                TAB_IDENTITIES => rsx! { IdentitiesTab { keys: keys.clone(), new_key_name } },
                TAB_TRUST      => rsx! { TrustTab { anchors: anchors.clone(), rules: schema.clone() } },
                TAB_CHAIN      => rsx! { ChainTab { keys: keys.clone(), anchors: anchors.clone() } },
                TAB_DID        => rsx! { DidTab { keys: keys.clone() } },
                TAB_CA         => rsx! { CaTab {} },
                TAB_YUBIKEY    => rsx! { YubikeyTab {} },
                TAB_MGMT_ACCESS=> rsx! { MgmtAccessTab {} },
                _              => rsx! {},
            }
        }
    }
}

// ── Tab: Identities — §4.1 ───────────────────────────────────────────────────
//
// Phase B step 2 — primary security view layout. Splits keys into a
// left-pane tree (grouped by identity prefix) and a right-pane
// inspector that renders one CertCard per key with a
// ValidityTimeline. v1 actions: [Delete] wires through the existing
// `SecurityKeyDelete` DashCmd; [Renew] / [Export SafeBag] /
// [Set as active] surface "Phase C: §5 sub-flow" toasts so the
// affordance is visible without forging a UX commitment that
// doesn't ship until Phase C.

#[component]
fn IdentitiesTab(keys: Vec<SecurityKeyInfo>, mut new_key_name: Signal<String>) -> Element {
    let ctx = use_context::<AppCtx>();
    let mut selected: Signal<Option<String>> = use_signal(|| None);
    let groups = group_keys_by_identity(&keys);

    // Default selection — first identity if any. The auto-select
    // runs only when nothing has been chosen yet and at least one
    // identity exists.
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
                        "Each identity owns one or more keys; each key may carry a certificate that binds it to a validity window. Click a node on the left to inspect its keys and certs."
                    }
                }
            }
        }

        if keys.is_empty() {
            div { class: "empty",
                "No identity keys found. Security may not be configured, or the PIB is empty."
            }
        } else {
            div { style: "display:grid;grid-template-columns:minmax(260px,320px) 1fr;gap:16px;align-items:start;",
                // Left pane — identity tree.
                IdentityTree {
                    groups: groups.clone(),
                    selected: selected_name.clone(),
                    active_identity_name: active_identity_name.clone(),
                    on_select: move |name: String| selected.set(Some(name)),
                }

                // Right pane — inspector for the selected identity.
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

        // Bottom — affordances for adding identities. Two of three
        // are v1 stubs (§5 SafeBag import, NDNCERT join wizard
        // live in Phase C); generate-key uses the existing
        // `SecurityGenerate` DashCmd so an operator can still
        // populate the PIB from this tab.
        div {
            style: "display:flex;flex-wrap:wrap;gap:8px;margin-top:20px;padding-top:14px;border-top:1px solid var(--border-subtle);",
            button {
                class: "btn btn-secondary",
                onclick: move |_| push_toast(
                    "Phase C: §5 sub-flow — SafeBagImportModal",
                    ToastLevel::Info,
                ),
                "+ Import SafeBag"
            }
            button {
                class: "btn btn-secondary",
                onclick: move |_| push_toast(
                    "Phase C: §5 sub-flow — EnrollmentWizard",
                    ToastLevel::Info,
                ),
                "+ Join via NDNCERT"
            }
        }

        // Generate-key form (existing surface, retained so v1
        // operators can mint a key without leaving this tab).
        div { class: "form-row", style: "margin-top:14px;",
            div { class: "form-group",
                label { "Generate a new Ed25519 identity key" }
                input {
                    r#type: "text",
                    placeholder: "/ndn/myrouter/key",
                    value: "{new_key_name}",
                    oninput: move |e| new_key_name.set(e.value()),
                    style: "width:320px;",
                }
            }
            button {
                class: "btn btn-primary",
                onclick: move |_| {
                    let name = new_key_name.read().trim().to_string();
                    if !name.is_empty() {
                        ctx.cmd.send(DashCmd::SecurityGenerate(name));
                        new_key_name.set(String::new());
                    }
                },
                "Generate"
            }
        }
    }
}

/// Group keys by their identity prefix (`/lab/alice/KEY/k1` →
/// `/lab/alice`). Returns identities in stable sort order so the
/// tree renders deterministically.
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
                            // Indented per-key list under this identity.
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

    rsx! {
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px;",
            // Header
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
            }

            // Per-key CertCards
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
        }
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

#[component]
fn CertCard(info: SecurityKeyInfo, on_delete: EventHandler<String>) -> Element {
    let name = info.name.clone();
    let name_for_delete = name.clone();
    let kid = info.key_id().to_owned();
    let (badge_class, badge_label) = info.expiry_badge();
    let has_cert = info.has_cert;
    let valid_until_s = info.valid_until_unix_s();
    let valid_from_s = info.valid_from_unix_s();
    let now_s = now_unix_s_opt();

    rsx! {
        div { style: "border:1px solid var(--border);border-radius:6px;padding:12px;margin-top:10px;",
            // Top row — key id + cert badge.
            div { style: "display:flex;justify-content:space-between;gap:8px;align-items:center;margin-bottom:6px;",
                div {
                    span { class: "mono", style: "font-size:12px;color:var(--text);", "KEY/{kid}" }
                    span { style: "margin-left:8px;font-size:11px;color:var(--text-muted);",
                        if has_cert { "active cert" } else { "no cert" }
                    }
                }
                span { class: "{badge_class}", "{badge_label}" }
            }

            // Full key/cert name.
            div { class: "mono", style: "font-size:10px;color:var(--text-muted);word-break:break-all;margin-bottom:8px;", "{name}" }

            // Validity timeline.
            ValidityTimeline {
                start_unix_s: valid_from_s,
                end_unix_s: valid_until_s,
                now_unix_s: now_s,
                alert_within_days: 30,
            }

            // Actions — three Phase-C stubs + Delete (live).
            div { style: "display:flex;gap:6px;flex-wrap:wrap;margin-top:10px;",
                button {
                    class: "btn btn-secondary btn-sm",
                    onclick: move |_| push_toast(
                        "Phase C: §5 sub-flow — KeyRotationModal",
                        ToastLevel::Info,
                    ),
                    "Renew"
                }
                button {
                    class: "btn btn-secondary btn-sm",
                    onclick: move |_| push_toast(
                        "Phase C: §5 sub-flow — SafeBag export",
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
                    "data-tooltip": "Phase C — §4.2 TrustPathInspector sidesheet renders here",
                    onclick: move |_| push_toast(
                        "Phase C: §4.2 TrustPathInspector — trace ↑ not wired yet",
                        ToastLevel::Info,
                    ),
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

/// Phase B step 2 — `ValidityTimeline` component. Renders the cert's
/// issued window with a "now" marker. Degrades to an endpoint-only
/// gauge when `start_unix_s` is `None` (the v1 wire format doesn't
/// surface `valid_from` yet; small wire extension follow-up).
#[component]
fn ValidityTimeline(
    start_unix_s: Option<u64>,
    end_unix_s: Option<u64>,
    now_unix_s: Option<u64>,
    alert_within_days: u64,
) -> Element {
    // No cert / permanent cert — render an explanatory line.
    let Some(end) = end_unix_s else {
        return rsx! {
            div { style: "padding:6px 8px;border-radius:4px;background:var(--surface);border:1px solid var(--border-subtle);font-size:11px;color:var(--text-muted);",
                "No expiry on this cert (permanent, or no cert present)."
            }
        };
    };

    let now = now_unix_s.unwrap_or(end);
    let alert_secs = alert_within_days.saturating_mul(86_400);

    // Compute the bar fill + color.
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
            // No start — render a single-axis remaining-time gauge.
            let remaining = end.saturating_sub(now);
            let pct = if remaining == 0 {
                100.0
            } else if remaining < alert_secs {
                // Show the unconsumed fraction of the alert window.
                100.0 - (remaining as f64 / alert_secs as f64) * 100.0
            } else {
                // Beyond the alert window — show a small filled fraction.
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
            // Bar
            div { style: "position:relative;height:12px;background:var(--bg);border:1px solid var(--border-subtle);border-radius:2px;overflow:hidden;",
                div {
                    style: "width:{fill_pct_int}%;height:100%;background:{fill_color};transition:width .3s;",
                }
                // 'now' tick — same position as fill edge.
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
    // No chrono dep — render as ISO date by walking the Gregorian
    // calendar. Y/M/D only, which is what the §4.1 timeline labels
    // need. Accurate well into the next century, which is enough.
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
    // wasm32 clock follow-up tracked in the kickoff cross-cutting
    // list ("`web_time` clock on wasm32"). Until then the timeline
    // renders without a "now" marker on web — start_unix_s/end label
    // still show, just no progress fraction.
    None
}

// ── Tab: Trust & Schema — §4.3 ────────────────────────────────────────────────
//
// Phase B step 3 — combined view of installed trust anchors and the
// active trust schema, with the §4.3 LiveValidationChart hanging
// below. Anchors are read-only in v1 (no anchor-add/anchor-remove
// mgmt verbs yet — buttons surface Phase C: §4.3 sub-flow toasts);
// schema rules use the existing rule-add / rule-remove / set verbs
// and each change appends a `SchemaJournalEntry` (the §2.4 journal
// bridge initialised in `app::App` next to the §11.10 audit chain).
// LiveValidationChart polls `security/validation-stats`; while
// counters are zero across forwarders today, the explicit
// `validator_present` flag drives a "no live data" chip so the
// gap is surfaced rather than silently rendered as zeros.

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
        // Education card.
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

#[component]
fn TrustAnchorList(anchors: Vec<AnchorInfo>) -> Element {
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
                                "Source attribution will surface here once "
                                span { class: "mono", "security/anchor-list" }
                                " is extended to carry it (Phase C wire-format follow-up)."
                            }
                        }
                    }
                }
            }
            // Action row — Phase C stubs per kickoff. Anchor add/remove
            // mgmt verbs aren't wired yet; the affordances exist so
            // the design intent is visible.
            div { style: "display:flex;gap:8px;margin-top:12px;",
                button {
                    class: "btn btn-secondary btn-sm",
                    onclick: move |_| push_toast(
                        "Phase C: §4.3 — anchor-add from file (mgmt verb pending)",
                        ToastLevel::Info,
                    ),
                    "+ Add from file"
                }
                button {
                    class: "btn btn-secondary btn-sm",
                    onclick: move |_| push_toast(
                        "Phase C: §4.3 — anchor-add from name (mgmt verb pending)",
                        ToastLevel::Info,
                    ),
                    "+ Add by name"
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
                        // §11.6 — guided editor is the default; raw-text
                        // tab toggles into a textarea + bulk-edit form
                        // for power users. Syntax highlighting on the
                        // raw view is a follow-up.
                        onclick: move |_| on_toggle_raw_mode.call(()),
                        if raw_mode { "Guided" } else { "Raw" }
                    }
                }
            }

            if rules.is_empty() {
                div { class: "empty",
                    "No trust schema rules configured. All signed Data is accepted (security profile = disabled)."
                }
            } else if !raw_mode {
                // Guided rendering — table per §11.6 default.
                table {
                    thead {
                        tr {
                            th { "Index" }
                            th { "Data Pattern" }
                            th { "" }
                            th { "Key Pattern" }
                            th { "Actions" }
                        }
                    }
                    tbody {
                        for rule in rules.iter() {
                            {
                                let idx = rule.index as u64;
                                rsx! {
                                    tr {
                                        td { span { class: "badge badge-gray", "{rule.index}" } }
                                        td { class: "mono", style: "color:var(--accent);", "{rule.data_pattern}" }
                                        td { style: "color:var(--text-muted);padding:0 6px;", "=>" }
                                        td { class: "mono", style: "color:var(--green);", "{rule.key_pattern}" }
                                        td {
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
                                                style: "margin-left:4px;",
                                                onclick: move |_| on_remove_rule.call(idx),
                                                "Remove"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                // Raw-text rendering — §11.6 raw tab. Plain monospace
                // dump of the rules; syntax highlighting is a later
                // follow-up.
                pre {
                    style: "background:var(--bg);border:1px solid var(--border-subtle);border-radius:4px;padding:10px;font-size:11px;color:var(--text);overflow:auto;",
                    for r in rules.iter() {
                        "[{r.index}] {r.data_pattern} => {r.key_pattern}\n"
                    }
                }
            }

            // Add-rule form.
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

            // Bulk-edit toggle + textarea.
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

    // Surface the gap explicitly. When the validator isn't present
    // (or the wire hasn't returned any data yet), counter values
    // are guaranteed-zero. The chip says so plainly so an operator
    // doesn't mistake "no telemetry yet" for "no traffic to
    // validate".
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
    // Build inline SVG polylines.
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
                // Verified — green
                path {
                    d: "{verified_path}",
                    fill: "none",
                    stroke: "var(--green,#3fb950)",
                    "stroke-width": "1.5",
                }
                // Rejected — red
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

// ── Tab: Certificate Chain ────────────────────────────────────────────────────

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

        // SVG chain diagram
        div { style: "overflow-x:auto;",
            div { class: "trust-chain",
                // Trust Anchor node
                {chain_node("🔑", "Trust Anchor", &anchor_name, if has_anchor { "ok" } else { "missing" }, "Root of trust — the certificate everyone in your network must trust.\nConfigure in router TOML: security.trust_anchor")}
                div { class: "chain-arrow", style: "color:var(--border);", "→" }

                // CA Certificate node
                {chain_node("📜", "CA Certificate", "Signed by anchor", if has_anchor { "ok" } else { "missing" }, "The Certificate Authority that signs identity certificates.\nEnroll via CA / NDNCERT tab to get one.")}
                div { class: "chain-arrow", style: "color:var(--border);", "→" }

                // Identity cert node
                {chain_node("🪪", "Your Identity", &identity_name, if has_cert { "ok" } else if has_identity { "warn" } else { "missing" }, "Your router's identity certificate.\nMust be signed by a CA that chains back to the trust anchor.")}
            }
        }

        // Status summary
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

        // Actions
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

// ── Tab: DID Explorer ─────────────────────────────────────────────────────────

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
    // did:key requires the raw public key bytes; we don't have them in the dashboard
    // yet so we show a placeholder.
    let did_key_note = "Requires public key bytes — not yet available via management API";

    let did_doc_preview = format!(
        r#"{{"@context":"https://www.w3.org/ns/did/v1","id":"{did_ndn}","verificationMethod":[{{"id":"{did_ndn}#key-1","type":"Ed25519VerificationKey2020","controller":"{did_ndn}","publicKeyMultibase":"<Ed25519 pubkey>"}}]}}"#
    );

    rsx! {
        div { class: "section-title", "DID Explorer" }

        // Education card
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
            // did:ndn
            div { style: "margin-bottom:18px;",
                div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;",
                    div { style: "font-size:12px;font-weight:600;color:var(--text);",
                        span { style: "color:var(--purple);", "did:ndn" }
                        span { style: "color:var(--text-muted);", " — NDN name encoded as a W3C DID" }
                    }
                    button {
                        class: "did-copy-btn",
                        onclick: move |_| {
                            // Dioxus desktop: write to clipboard via dioxus_desktop eval
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

            // did:key placeholder
            div { style: "margin-bottom:18px;",
                div { style: "font-size:12px;font-weight:600;color:var(--text);margin-bottom:6px;",
                    span { style: "color:var(--purple);", "did:key" }
                    span { style: "color:var(--text-muted);", " — public key multibase encoding" }
                }
                div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:10px;font-size:11px;color:var(--text-muted);font-style:italic;",
                    "{did_key_note}"
                }
            }

            // DID document preview
            div {
                div { style: "font-size:12px;font-weight:600;color:var(--text);margin-bottom:6px;", "DID Document (preview)" }
                div { class: "yk-cmd", "{did_doc_preview}" }
            }

            // Explainer rows
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

// ── Tab: CA / NDNCERT ─────────────────────────────────────────────────────────

#[component]
fn CaTab() -> Element {
    let ctx = use_context::<AppCtx>();
    let mut show_token_form = use_signal(|| false);
    let mut token_name = use_signal(String::new);
    let mut last_token = use_signal(String::new);
    let ca = ctx.ca_info.read().clone();

    rsx! {
        div { class: "section-title", "CA / NDNCERT" }

        // Live CA status or "not configured" notice
        if let Some(ref info) = ca {
            div { style: "background:var(--green-dark);border:1px solid var(--green)44;border-radius:6px;padding:14px;margin-bottom:14px;",
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
        } else {
            div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:14px;margin-bottom:14px;",
                div { style: "font-size:12px;color:var(--text-muted);", "This router is not acting as a CA. To enable, add to router TOML:" }
                div { class: "yk-cmd", style: "margin-top:8px;",
                    "[security]\n"
                    "ca_prefix = \"/ndn/site\"\n"
                    "ca_info = \"Site CA\"\n"
                    "ca_max_validity_days = 365\n"
                    "ca_challenges = [\"token\", \"pin\"]"
                }
            }
        }

        // Education card
        div { class: "edu-card",
            div { style: "display:flex;gap:12px;align-items:flex-start;",
                div { style: "font-size:28px;flex-shrink:0;", "🏛" }
                div {
                    div { style: "font-size:13px;font-weight:600;color:var(--accent);margin-bottom:4px;",
                        "NDNCERT — Automated Certificate Management"
                    }
                    div { style: "font-size:12px;color:var(--text-muted);line-height:1.6;",
                        "NDNCERT (Named Data Networking Certificate Management Protocol) automates certificate issuance. "
                        "A CA verifies your identity via challenges (PIN, email, possession, or YubiKey OTP) "
                        "and issues a signed certificate bound to your identity key."
                    }
                }
            }
        }

        // Enrollment flow diagram
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

        // Protocol info
        div { style: "display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px;",
            InfoKv { label: "Protocol", val: "NDNCERT 0.3" }
            InfoKv { label: "Key Exchange", val: "P-256 ECDH" }
            InfoKv { label: "Encryption", val: "AES-GCM-128 + HKDF-SHA256" }
            InfoKv { label: "Wire Format", val: "NDN TLV" }
        }

        // Token management — enabled only when CA is active
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

// ── Tab: YubiKey ──────────────────────────────────────────────────────────────

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

        // Education card
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

        // Mode cards
        div { style: "display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px;",
            // PIV Signing Key card — now interactive
            div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:16px;",
                div { style: "font-size:16px;margin-bottom:8px;", "🔑" }
                div { style: "font-size:13px;font-weight:600;color:var(--text);margin-bottom:4px;", "PIV Signing Key" }
                div { style: "font-size:11px;color:var(--text-muted);line-height:1.5;margin-bottom:10px;",
                    "Store your NDN identity private key in YubiKey PIV slot 9a. All packet signing happens on-device — even a compromised OS cannot steal your key."
                }
                // Detect button
                div { style: "display:flex;gap:8px;margin-bottom:8px;",
                    button {
                        class: "btn btn-secondary btn-sm",
                        onclick: move |_| { ctx.cmd.send(DashCmd::YubikeyDetect); },
                        "Detect YubiKey"
                    }
                }
                // Status display
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
                // Generate PIV key form
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

        // HOTP seed generator
        div { style: "background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px;",
            div { style: "display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;",
                div { style: "font-size:13px;font-weight:600;color:var(--text);", "Generate HOTP Seed" }
                button {
                    class: "btn btn-primary btn-sm",
                    onclick: move |_| {
                        // Generate 20 random bytes using system randomness.
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

        // Headless bootstrapping flow
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

/// Generate 20 random bytes as a hex string using OS randomness.
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

// ── Tab: Mgmt Access (§4.5) ───────────────────────────────────────────────────
//
// First Phase B checkpoint. Surfaces the live `MgmtAccessPolicy`
// (polled via `security/policy-get`) and lets the operator flip the
// three runtime-writable booleans, with the `validator_anchor` edit
// surfaced as `pending_restart` (per §4.5.1 the anchor flip requires
// a Validator rebuild the forwarder can't do at runtime). On submit
// the dashboard:
//   1. sends `DashCmd::SecurityPolicySet(policy)` → run_cmd issues
//      `security/policy-set` against the forwarder.
//   2. On a 2xx response, run_cmd computes the SHA-256 over the
//      submitted JSON body and appends a `security/policy-set`
//      `AuditLogEntry` (§11.10 audit bridge) into the dashboard's
//      `AuditLogChain` — desktop-backed by FileStore per §11.1.

#[component]
fn MgmtAccessTab() -> Element {
    let ctx = use_context::<AppCtx>();
    let live = ctx.mgmt_access_policy.read().clone();
    let is_ephemeral = *ctx.identity_is_ephemeral.read();
    let pib_path = ctx.identity_pib_path.read().clone();

    // Editor draft — initialised lazily once a live policy lands. The
    // memo re-syncs the draft when the user switches forwarders
    // (live.replay_window_secs is a stable identity-of-the-snapshot
    // proxy when the rest of the fields shift).
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

        // Education card — §9 EduGloss seam over MgmtAccessPolicy.
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
                            // Re-pull from the live signal to discard edits.
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
        // ── Hardcoded floors per §4.5.1 ──────────────────────────────
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

        // ── Configurable defaults per §4.5.1 ─────────────────────────
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
                description: "When ON, every management Interest must carry a SignatureValue verified by the validator. When OFF (default for new forwarders) anyone with WebSocket access can issue commands.",
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

            // validator_anchor — pending_restart per §4.5.1.
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

        // ── Action row ───────────────────────────────────────────────
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

        // ── §4.5.2 file-emitted bootstrap token — render-only ────────
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

        // ── Unauthenticated-channel warning ──────────────────────────
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
