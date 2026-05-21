//! Modal first-run gate that fires when `derive_posture` returns anything but
//! `Hardened` and the user hasn't accepted the current variant this session.

#![allow(dead_code)]

use dioxus::prelude::*;

use crate::app::AppCtx;
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
                    justify-content:center;",
            div {
                style: "background:#1a1a1a;color:#eee;border:1px solid #444;\
                        border-radius:8px;max-width:720px;width:92%;\
                        padding:28px 32px;box-shadow:0 6px 24px rgba(0,0,0,0.5);\
                        font-family:system-ui,sans-serif;",
                match posture.kind() {
                    PostureKind::NoIdentity => rsx! { NoIdentityPanel {} },
                    PostureKind::IdentityExpired => rsx! { IdentityExpiredPanel { posture: posture.clone() } },
                    PostureKind::TrustSchemaWeakened => rsx! {
                        TrustSchemaWeakenedPanel { posture: posture.clone() }
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
        p { style: "margin:0 0 18px 0;line-height:1.5;color:#bbb;",
            "Right now, ndn-fwd signs management responses with an ephemeral key. \
             That key disappears on restart. Other devices have no way to verify \
             that this forwarder is the one they trusted yesterday."
        }
        p { style: "margin:0 0 24px 0;line-height:1.5;color:#bbb;",
            "For research and local testing, that's fine. For anything else, \
             set up a trust identity now."
        }

        GateChoice {
            icon: "🔑",
            title: "I have an existing identity",
            description: "Import a SafeBag (.tpb) file — created by ndnsec-export or \
                          ndn-fwd-tokens. The dashboard will load the identity, its key, \
                          and its cert into the local PIB.",
            action_label: "Go to Identities → Import",
            on_action: move |_| jump_to_security_view(SecurityTab::Identities),
        }
        GateChoice {
            icon: "📡",
            title: "Join an existing zone",
            description: "Enroll with an NDNCERT certificate authority. Used when there's \
                          already a trust anchor for /your/zone you want to belong to.",
            action_label: "Go to CA / NDNCERT",
            on_action: move |_| jump_to_security_view(SecurityTab::Ca),
        }
        GateChoice {
            icon: "🛠",
            title: "Create a new identity (no zone yet)",
            description: "Generate a self-signed identity. Useful for the first forwarder \
                          in a new zone — this identity becomes the zone's root anchor.",
            action_label: "Go to Identities → Generate",
            on_action: move |_| jump_to_security_view(SecurityTab::Identities),
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
        p { style: "margin:0 0 18px 0;line-height:1.5;color:#bbb;",
            "Identity: "
            code { style: "color:#ddd;", "{identity_name}" }
        }
        p { style: "margin:0 0 24px 0;line-height:1.5;color:#bbb;",
            "Data signed by this identity from now on will not validate at other \
             forwarders that have not also expired their schemas."
        }

        GateChoice {
            icon: "🔄",
            title: "Renew via NDNCERT",
            description: "Issues a fresh cert under the same key. Same identity, new \
                          validity window. Recommended.",
            action_label: "Go to CA → Renew",
            on_action: move |_| jump_to_security_view(SecurityTab::Ca),
        }
        GateChoice {
            icon: "🆕",
            title: "Generate a new key under this identity",
            description: "New key pair, new cert. Old key becomes inactive.",
            action_label: "Go to Identities → Rotate",
            on_action: move |_| jump_to_security_view(SecurityTab::Identities),
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
            p { style: "margin:0 0 8px 0;color:#bbb;", "Anchors removed:" }
            ul { style: "margin:0 0 18px 18px;color:#ddd;",
                for a in anchors_removed.iter() {
                    li { key: "{a}", code { "{a}" } }
                }
            }
        }
        if !rules_removed.is_empty() {
            p { style: "margin:0 0 8px 0;color:#bbb;", "Schema rules removed:" }
            ul { style: "margin:0 0 18px 18px;color:#ddd;",
                for r in rules_removed.iter() {
                    li { key: "{r}", code { "{r}" } }
                }
            }
        }
        p { style: "margin:0 0 24px 0;line-height:1.5;color:#bbb;",
            "This may be a legitimate operator change, or unauthorized tampering."
        }

        GateChoice {
            icon: "📜",
            title: "Investigate in the audit log",
            description: "See who removed what and when (signed chain entries).",
            action_label: "Go to Security → Audit log",
            on_action: move |_| jump_to_security_view(SecurityTab::Audit),
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
fn GateChoice(
    icon: &'static str,
    title: &'static str,
    description: &'static str,
    action_label: &'static str,
    on_action: EventHandler<()>,
) -> Element {
    rsx! {
        div {
            style: "border:1px solid #333;border-radius:6px;padding:14px 16px;\
                    margin:0 0 12px 0;",
            div { style: "display:flex;align-items:center;gap:10px;margin-bottom:6px;",
                span { style: "font-size:20px;", "{icon}" }
                span { style: "font-weight:600;color:#fff;", "{title}" }
            }
            p { style: "margin:0 0 12px 0;color:#aaa;font-size:13px;line-height:1.45;",
                "{description}"
            }
            button {
                style: "background:#2a2a2a;color:#eee;border:1px solid #555;\
                        padding:6px 12px;border-radius:4px;cursor:pointer;",
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
        hr { style: "border:none;border-top:1px solid #333;margin:18px 0 14px 0;" }
        div { style: "display:flex;align-items:flex-start;gap:10px;",
            input {
                r#type: "checkbox",
                style: "margin-top:3px;",
                checked: *checked.read(),
                oninput: move |evt| {
                    checked_w.set(evt.value() == "true");
                },
            }
            label { style: "color:#bbb;font-size:13px;line-height:1.5;flex:1;",
                "{label_for_render}"
            }
        }
        div { style: "display:flex;justify-content:flex-end;margin-top:14px;",
            button {
                style: if *checked.read() {
                    "background:#5a3a3a;color:#fff;border:1px solid #a55;\
                     padding:6px 14px;border-radius:4px;cursor:pointer;"
                } else {
                    "background:#222;color:#666;border:1px solid #333;\
                     padding:6px 14px;border-radius:4px;cursor:not-allowed;"
                },
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
