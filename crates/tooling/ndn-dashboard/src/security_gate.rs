//! Modal first-run gate that fires when `derive_posture` returns anything but
//! `Hardened` and the user hasn't accepted the current variant this session.

#![allow(dead_code)]

use dioxus::prelude::*;

use crate::app::{AppCtx, ConnState};
use crate::app_shared::push_toast;
use crate::security_state::{
    GATE_ACCEPTED, PostureInput, PostureKind, SecurityPosture, accept, derive_posture,
    gate_should_fire,
};
use crate::views::View;

#[component]
#[allow(non_snake_case)]
pub fn SecurityGate() -> Element {
    let ctx = use_context::<AppCtx>();

    // The gate reasons about an attached forwarder's trust posture, so stay
    // silent until we are actually connected. Firing while disconnected or
    // reconnecting — when identity state is empty or stale — surfaced a "no
    // persistent identity" modal for a forwarder the operator hadn't reached.
    // (No hooks run below this point, so the early return is sound.)
    if !matches!(&*ctx.conn.read(), ConnState::Connected) {
        return rsx! {};
    }

    let identity_name_handle = ctx.identity_name.read();
    let identity_is_ephemeral_handle = ctx.identity_is_ephemeral.read();
    let identity_name: &str = identity_name_handle.as_str();
    let identity_is_ephemeral: bool = *identity_is_ephemeral_handle;
    let cert_expiry = *ctx.cert_valid_until_unix_s.read();
    #[cfg(not(target_arch = "wasm32"))]
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs());
    #[cfg(target_arch = "wasm32")]
    let now = web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs());
    let surface_supported = *ctx.security_surface_supported.read();
    let posture = derive_posture(PostureInput {
        identity_name,
        identity_is_ephemeral,
        cert_valid_until_unix_s: cert_expiry,
        now_unix_s: now,
        security_surface_supported: surface_supported,
    });

    let forwarder_id = current_forwarder_id();
    let accepted_handle = GATE_ACCEPTED.read();
    if !gate_should_fire(&posture, accepted_handle.as_ref(), &forwarder_id) {
        return rsx! {};
    }
    drop(accepted_handle);

    rsx! {
        div {
            style: "position:fixed;inset:0;background:rgba(0,0,0,0.55);\
                    z-index:9999;display:flex;align-items:center;\
                    justify-content:center;\
                    padding:env(safe-area-inset-top,12px) env(safe-area-inset-right,12px) \
                            env(safe-area-inset-bottom,12px) env(safe-area-inset-left,12px);",
            // Phone fix: the inner modal needs its own scroll viewport.
            // Without max-height + overflow-y the modal overflows on tall
            // content / short viewports and the user can't reach the
            // checkbox or bottom buttons. Padding clamps narrower on
            // phones via the .gate-modal class in styles.rs.
            div {
                class: "gate-modal",
                style: "background:var(--surface);color:var(--text);border:1px solid var(--border);\
                        border-radius:8px;max-width:720px;width:92%;\
                        max-height:calc(100dvh - 24px);overflow-y:auto;\
                        -webkit-overflow-scrolling:touch;\
                        padding:28px 32px;box-shadow:0 6px 24px var(--shadow);\
                        font-family:system-ui,sans-serif;",
                match posture.kind() {
                    PostureKind::NoIdentity => rsx! { NoIdentityPanel {} },
                    PostureKind::IdentityExpired => rsx! { IdentityExpiredPanel { posture: posture.clone() } },
                    PostureKind::TrustSchemaWeakened => rsx! {
                        TrustSchemaWeakenedPanel { posture: posture.clone() }
                    },
                    PostureKind::SchemaTightened => rsx! {
                        SchemaTightenedPanel { posture: posture.clone() }
                    },
                    PostureKind::Hardened | PostureKind::Unsupported => rsx! {},
                }
            }
        }
    }
}

#[component]
#[allow(non_snake_case)]
fn NoIdentityPanel() -> Element {
    let mut skip_acknowledged: Signal<bool> = use_signal(|| false);

    rsx! {
        h2 { style: "margin:0 0 12px 0;font-size:18px;",
            "⚠  This forwarder has no persistent identity."
        }
        p { style: "margin:0 0 18px 0;line-height:1.5;color:var(--text-muted);",
            "Right now, ndn-fwd signs management responses with an ephemeral key. \
             That key disappears on restart. Other devices have no way to verify \
             that this forwarder is the one they trusted yesterday."
        }
        p { style: "margin:0 0 24px 0;line-height:1.5;color:var(--text-muted);",
            "For research and local testing, that's fine. For anything else, \
             set up a trust identity now."
        }

        // The three Go-To buttons jump the view *and* dismiss the
        // gate — choosing a path is itself an acknowledgement of the
        // current ephemeral posture. The §2 design's "you must
        // acknowledge before you can do anything" rule is satisfied
        // by the act of selecting a remediation path. The gate
        // re-fires per-forwarder, so reconnecting brings it back.
        GateChoice {
            icon: "🔑",
            title: "I have an existing identity",
            description: "Import a SafeBag (.tpb) file — created by ndnsec-export or \
                          ndn-fwd-tokens. The dashboard will load the identity, its key, \
                          and its cert into the local PIB.",
            action_label: "Go to Identities → Import",
            on_action: move |_| {
                jump_to_security_view(SecurityTab::Identities);
                accept(current_forwarder_id(), PostureKind::NoIdentity);
            },
        }
        GateChoice {
            icon: "📡",
            title: "Join an existing zone",
            description: "Enroll with an NDNCERT certificate authority. Used when there's \
                          already a trust anchor for /your/zone you want to belong to.",
            action_label: "Go to CA / NDNCERT",
            on_action: move |_| {
                jump_to_security_view(SecurityTab::Ca);
                accept(current_forwarder_id(), PostureKind::NoIdentity);
            },
        }
        GateChoice {
            icon: "🛠",
            title: "Create a new identity (no zone yet)",
            description: "Generate a self-signed identity. Useful for the first forwarder \
                          in a new zone — this identity becomes the zone's root anchor.",
            action_label: "Go to Identities → Generate",
            on_action: move |_| {
                jump_to_security_view(SecurityTab::Identities);
                accept(current_forwarder_id(), PostureKind::NoIdentity);
            },
        }

        SkipRow {
            label: "Skip — run in ephemeral mode for research/testing. \
                    I understand: no persistent identity, mgmt unauthenticated, \
                    anyone with socket/WebSocket access can issue mgmt commands.",
            checked: skip_acknowledged,
            on_skip: move |_| {
                accept(current_forwarder_id(), PostureKind::NoIdentity);
                skip_acknowledged.set(false);
                push_toast(
                    "Continuing in ephemeral mode. Restart the dashboard to be reminded.",
                    crate::app_shared::ToastLevel::Warning,
                );
            },
        }
    }
}

#[component]
#[allow(non_snake_case)]
fn IdentityExpiredPanel(posture: SecurityPosture) -> Element {
    let mut skip_acknowledged: Signal<bool> = use_signal(|| false);
    let (identity_name, days_ago) = match &posture {
        SecurityPosture::IdentityExpired {
            identity_name,
            days_ago,
        } => (identity_name.clone(), *days_ago),
        _ => return rsx! {},
    };

    rsx! {
        h2 { style: "margin:0 0 12px 0;font-size:18px;",
            "⏰  Your identity certificate expired {days_ago} days ago."
        }
        p { style: "margin:0 0 18px 0;line-height:1.5;color:var(--text-muted);",
            "Identity: "
            code { style: "color:#ddd;", "{identity_name}" }
        }
        p { style: "margin:0 0 24px 0;line-height:1.5;color:var(--text-muted);",
            "Data signed by this identity from now on will not validate at other \
             forwarders that have not also expired their schemas."
        }

        GateChoice {
            icon: "🔄",
            title: "Renew via NDNCERT",
            description: "Issues a fresh cert under the same key. Same identity, new \
                          validity window. Recommended.",
            action_label: "Go to CA → Renew",
            on_action: move |_| {
                jump_to_security_view(SecurityTab::Ca);
                accept(current_forwarder_id(), PostureKind::IdentityExpired);
            },
        }
        GateChoice {
            icon: "🆕",
            title: "Generate a new key under this identity",
            description: "New key pair, new cert. Old key becomes inactive.",
            action_label: "Go to Identities → Rotate",
            on_action: move |_| {
                jump_to_security_view(SecurityTab::Identities);
                accept(current_forwarder_id(), PostureKind::IdentityExpired);
            },
        }

        SkipRow {
            label: "Continue with the expired cert (testing only).".to_string(),
            checked: skip_acknowledged,
            on_skip: move |_| {
                accept(current_forwarder_id(), PostureKind::IdentityExpired);
                skip_acknowledged.set(false);
                push_toast(
                    "Continuing with an expired cert.",
                    crate::app_shared::ToastLevel::Warning,
                );
            },
        }
    }
}

#[component]
#[allow(non_snake_case)]
fn TrustSchemaWeakenedPanel(posture: SecurityPosture) -> Element {
    let mut skip_acknowledged: Signal<bool> = use_signal(|| false);
    let (anchors_removed, rules_removed) = match &posture {
        SecurityPosture::TrustSchemaWeakened {
            anchors_removed,
            rules_removed,
        } => (anchors_removed.clone(), rules_removed.clone()),
        _ => return rsx! {},
    };

    rsx! {
        h2 { style: "margin:0 0 12px 0;font-size:18px;",
            "⚠  Trust schema changed since last session."
        }
        if !anchors_removed.is_empty() {
            p { style: "margin:0 0 8px 0;color:var(--text-muted);", "Anchors removed:" }
            ul { style: "margin:0 0 18px 18px;color:#ddd;",
                for a in anchors_removed.iter() {
                    li { key: "{a}", code { "{a}" } }
                }
            }
        }
        if !rules_removed.is_empty() {
            p { style: "margin:0 0 8px 0;color:var(--text-muted);", "Schema rules removed:" }
            ul { style: "margin:0 0 18px 18px;color:#ddd;",
                for r in rules_removed.iter() {
                    li { key: "{r}", code { "{r}" } }
                }
            }
        }
        p { style: "margin:0 0 24px 0;line-height:1.5;color:var(--text-muted);",
            "This may be a legitimate operator change, or unauthorized tampering."
        }

        GateChoice {
            icon: "📜",
            title: "Investigate in the audit log",
            description: "See who removed what and when (signed chain entries).",
            action_label: "Go to Security → Audit log",
            on_action: move |_| {
                jump_to_security_view(SecurityTab::Audit);
                accept(current_forwarder_id(), PostureKind::TrustSchemaWeakened);
            },
        }

        SkipRow {
            label: "Accept the new schema — I made these changes.".to_string(),
            checked: skip_acknowledged,
            on_skip: move |_| {
                accept(current_forwarder_id(), PostureKind::TrustSchemaWeakened);
                skip_acknowledged.set(false);
                push_toast(
                    "Schema change accepted. The new anchor set is now baseline.",
                    crate::app_shared::ToastLevel::Info,
                );
            },
        }
    }
}

#[component]
#[allow(non_snake_case)]
fn SchemaTightenedPanel(posture: SecurityPosture) -> Element {
    let mut skip_acknowledged: Signal<bool> = use_signal(|| false);
    let orphaned = match &posture {
        SecurityPosture::SchemaTightened { orphaned } => orphaned.clone(),
        _ => return rsx! {},
    };

    rsx! {
        h2 { style: "margin:0 0 12px 0;font-size:18px;",
            "⚠  Pending schema tightening would orphan live certificates."
        }
        p { style: "margin:0 0 8px 0;color:var(--text-muted);line-height:1.5;",
            "A dry-run of the proposed schema against the current cert set found "
            "identities that would stop validating. Apply with a grace window so "
            "both schemas validate during the transition, or re-issue these first."
        }
        if orphaned.is_empty() {
            p { style: "margin:0 0 18px 0;color:#6c6;", "No live certificates would be orphaned." }
        } else {
            p { style: "margin:0 0 8px 0;color:var(--text-muted);", "Would stop validating:" }
            ul { style: "margin:0 0 18px 18px;color:#ddd;",
                for o in orphaned.iter() {
                    li { key: "{o}", code { "{o}" } }
                }
            }
        }

        GateChoice {
            icon: "📜",
            title: "Review the affected identities",
            description: "Inspect each orphaned cert chain before applying the tighter schema.",
            action_label: "Go to Security → Trust & schema",
            on_action: move |_| {
                jump_to_security_view(SecurityTab::Schema);
                accept(current_forwarder_id(), PostureKind::SchemaTightened);
            },
        }

        SkipRow {
            label: "Apply anyway — these identities are expected to be retired.".to_string(),
            checked: skip_acknowledged,
            on_skip: move |_| {
                accept(current_forwarder_id(), PostureKind::SchemaTightened);
                skip_acknowledged.set(false);
                push_toast(
                    "Schema tightening accepted. Orphaned identities will no longer validate.",
                    crate::app_shared::ToastLevel::Info,
                );
            },
        }
    }
}

#[component]
#[allow(non_snake_case)]
fn GateChoice(
    icon: &'static str,
    title: &'static str,
    description: &'static str,
    action_label: &'static str,
    on_action: EventHandler<()>,
) -> Element {
    rsx! {
        div {
            style: "border:1px solid var(--border);border-radius:6px;padding:14px 16px;\
                    margin:0 0 12px 0;",
            div { style: "display:flex;align-items:center;gap:10px;margin-bottom:6px;",
                span { style: "font-size:20px;", "{icon}" }
                span { style: "font-weight:600;color:var(--text);", "{title}" }
            }
            p { style: "margin:0 0 12px 0;color:var(--text-muted);font-size:13px;line-height:1.45;",
                "{description}"
            }
            button {
                style: "background:var(--surface2);color:var(--text);border:1px solid var(--border);\
                        padding:10px 16px;border-radius:6px;cursor:pointer;\
                        font-size:14px;min-height:44px;\
                        white-space:nowrap;line-height:1.2;",
                onclick: move |_| on_action.call(()),
                "{action_label}"
            }
        }
    }
}

#[component]
#[allow(non_snake_case)]
fn SkipRow(label: String, checked: Signal<bool>, on_skip: EventHandler<()>) -> Element {
    let mut checked_w = checked;
    let label_for_render = label.clone();
    rsx! {
        hr { style: "border:none;border-top:1px solid var(--border);margin:18px 0 14px 0;" }
        // The whole label-row is a tap target. The checkbox + label
        // are linked via `for=skip-ack-cb` so tapping the text body
        // toggles the box — the bare checkbox is too small for one-
        // handed phone use. Padding bumps the row to a comfortable
        // 44+px touch target without changing desktop appearance much.
        label {
            r#for: "skip-ack-cb",
            style: "display:flex;align-items:flex-start;gap:12px;\
                    padding:10px 4px;color:var(--text-muted);font-size:13px;\
                    line-height:1.5;cursor:pointer;",
            input {
                id: "skip-ack-cb",
                r#type: "checkbox",
                // Scale up the native checkbox so it's actually
                // reachable on phones.
                style: "margin-top:2px;width:20px;height:20px;flex-shrink:0;cursor:pointer;",
                checked: *checked.read(),
                oninput: move |evt| {
                    checked_w.set(evt.value() == "true");
                },
            }
            span { style: "flex:1;", "{label_for_render}" }
        }
        div { style: "display:flex;justify-content:flex-end;margin-top:14px;",
            button {
                // Skip is a destructive ack — use .btn-danger so
                // both dark + light modes pick up the themed colors
                // from the CSS variable system. The themed --btn-d
                // already has a sensible :hover variant.
                class: if *checked.read() {
                    "btn btn-danger"
                } else {
                    "btn btn-secondary"
                },
                style: "min-height:44px;min-width:160px;padding:12px 20px;\
                        font-size:14px;white-space:nowrap;line-height:1.2;\
                        cursor:".to_owned()
                    + if *checked.read() { "pointer;" } else { "not-allowed;" }
                    + if *checked.read() { "" } else { "opacity:.55;" },
                disabled: !*checked.read(),
                onclick: move |_| {
                    if *checked.read() {
                        on_skip.call(());
                    }
                },
                "Skip & continue"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityTab {
    Identities,
    Anchors,
    Ca,
    Schema,
    Audit,
}

impl SecurityTab {
    /// Mirrors `views::security::TAB_*` constants; keep in sync.
    pub fn tab_id(self) -> u8 {
        match self {
            Self::Identities => 0,
            Self::Anchors => 1,
            Self::Schema => 1,
            Self::Ca => 4,
            Self::Audit => 8,
        }
    }
}

#[cfg(feature = "desktop")]
fn current_forwarder_id() -> String {
    crate::forwarder_profile::selected_profile()
        .machine_name()
        .to_owned()
}

#[cfg(not(feature = "desktop"))]
fn current_forwarder_id() -> String {
    "web-default".to_owned()
}

fn jump_to_security_view(tab: SecurityTab) {
    *crate::app_shared::ACTIVE_VIEW.write() = View::Security;
    *crate::app_shared::ACTIVE_SECURITY_TAB.write() = Some(tab.tab_id());
}
