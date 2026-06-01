//! Always-rendered identity chip and sidebar security dot. Both derive from
//! the same `derive_chip_state` call so label and tooltip can't drift.

#![allow(dead_code)]

use dioxus::prelude::*;

use crate::app::AppCtx;
use crate::security_state::{ChipInput, ChipState, derive_chip_state, derive_sec_dot};

#[cfg(not(target_arch = "wasm32"))]
fn now_unix_s() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}
#[cfg(target_arch = "wasm32")]
fn now_unix_s() -> Option<u64> {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

fn live_chip_state(ctx: &AppCtx) -> ChipState {
    // Subscribe to keyring changes so switching the active operator identity
    // re-renders the chip.
    let _ = crate::app_shared::KEYRING_GEN.read();
    let signed_required = *ctx.mgmt_signed_commands_required.read();
    let surface_supported = *ctx.security_surface_supported.read();
    // When the dashboard holds its own provisioned operator key, "acting as"
    // is that identity — not the forwarder's (often ephemeral) one.
    if let Some(op_identity) = crate::operator_keyring::active_identity_name() {
        return derive_chip_state(ChipInput {
            identity_name: &op_identity,
            identity_is_ephemeral: false,
            cert_valid_until_unix_s: None,
            now_unix_s: now_unix_s(),
            mgmt_signed_commands_required: signed_required,
            security_surface_supported: surface_supported,
        });
    }
    let identity_name = ctx.identity_name.read();
    let is_ephemeral = *ctx.identity_is_ephemeral.read();
    let cert_expiry = *ctx.cert_valid_until_unix_s.read();
    derive_chip_state(ChipInput {
        identity_name: identity_name.as_str(),
        identity_is_ephemeral: is_ephemeral,
        cert_valid_until_unix_s: cert_expiry,
        now_unix_s: now_unix_s(),
        mgmt_signed_commands_required: signed_required,
        security_surface_supported: surface_supported,
    })
}

#[component]
#[allow(non_snake_case)]
pub fn IdentityChip() -> Element {
    let ctx = use_context::<AppCtx>();
    let state = live_chip_state(&ctx);
    let class = state.css_class();
    let icon = state.icon();
    let label = state.label();
    rsx! {
        span {
            class: "{class}",
            title: "{state.label()}",
            span { class: "id-chip-icon", "{icon}" }
            span { class: "id-chip-label", "{label}" }
        }
    }
}

/// The "Acting as" axis of the Attach bar. Renders the active identity as a
/// status chip in the single-context default (note §8 light-touch), and a
/// switchable dropdown once the operator holds more than one identity. Both
/// branches read the operator keyring ([`crate::operator_keyring`]) so display
/// and selection can't drift, and so the Identity nav bucket / extension /
/// mobile can reuse it.
#[component]
#[allow(non_snake_case)]
pub fn IdentityAxisControl() -> Element {
    let ctx = use_context::<AppCtx>();
    // Subscribe to keyring changes so add/import/switch re-renders the axis.
    let _ = crate::app_shared::KEYRING_GEN.read();

    // Prefer the dashboard's own operator identities (portable, what we sign
    // as); fall back to the forwarder-reported identity when the keyring is
    // empty. Each option's value is the key name (stable id); its label is the
    // identity name.
    let held = crate::operator_keyring::list_identities();

    rsx! {
        span { class: "axis-label", "Acting as" }
        if held.len() <= 1 {
            // Zero/one identity → the chip already shows it with status.
            IdentityChip {}
        } else {
            // Switch which operator identity signs on this surface.
            select {
                class: "axis-select",
                onchange: move |e| {
                    if crate::operator_keyring::set_active(&e.value()) {
                        crate::app_shared::bump_keyring_gen();
                        // Re-bind the command client to the newly active signer.
                        ctx.cmd.send(crate::app::DashCmd::Reconnect);
                    }
                },
                for id in held.iter() {
                    option {
                        value: "{id.key_name}",
                        selected: id.active,
                        "{id.identity}  ({id.fingerprint})"
                    }
                }
            }
        }
    }
}

/// Predict what the acting-as identity can do against the attached engine,
/// from the live mgmt-auth policy + active identity (see
/// [`crate::identity_axis::write_capability`]).
fn live_write_capability(ctx: &AppCtx) -> crate::identity_axis::WriteCapability {
    let _ = crate::app_shared::KEYRING_GEN.read();
    let policy = ctx.mgmt_access_policy.read();
    // Prefer the full policy snapshot; fall back to the standalone flag.
    let require_signed = policy
        .as_ref()
        .map(|p| Some(p.require_signed_commands))
        .unwrap_or_else(|| *ctx.mgmt_signed_commands_required.read());
    let ephemeral_allowed = policy
        .as_ref()
        .map(|p| p.ephemeral_allowed)
        .unwrap_or(false);
    // A provisioned operator key in the dashboard's own keyring is a real,
    // non-ephemeral signing identity — predict read-write regardless of the
    // forwarder's own (often ephemeral) identity. The forwarder still
    // validates against its anchor; a refusal surfaces as a command error
    // with bootstrap guidance.
    let provisioned = crate::operator_keyring::is_provisioned();
    let has_identity = provisioned || !ctx.identity_name.read().trim().is_empty();
    let identity_ephemeral = !provisioned && *ctx.identity_is_ephemeral.read();
    let cert_expired = if provisioned {
        false
    } else {
        match (*ctx.cert_valid_until_unix_s.read(), now_unix_s()) {
            (Some(valid_until), Some(now)) => now > valid_until,
            _ => false,
        }
    };
    crate::identity_axis::write_capability(
        require_signed,
        ephemeral_allowed,
        has_identity,
        identity_ephemeral,
        cert_expired,
    )
}

/// Attach-bar badge: what the operator can do here (read-only vs read-write),
/// derived from the engine's auth policy and the acting-as identity.
#[component]
#[allow(non_snake_case)]
pub fn CapabilityBadge() -> Element {
    let ctx = use_context::<AppCtx>();
    let cap = live_write_capability(&ctx);
    rsx! {
        span {
            class: "{cap.badge_class()}",
            style: "flex-shrink:0;",
            title: "{cap.tooltip()}",
            "{cap.label()}"
        }
    }
}

/// Content-area notice shown only when the operator is read-only against this
/// engine — so a refused mutation is understood up front, not discovered by a
/// failed click. A notice (not per-button disabling) because the prediction
/// can't fully verify the cert chain client-side; the engine is the authority.
#[component]
#[allow(non_snake_case)]
pub fn ReadOnlyBanner() -> Element {
    let ctx = use_context::<AppCtx>();
    let cap = live_write_capability(&ctx);
    if !cap.is_read_only() {
        return rsx! {};
    }
    rsx! {
        div { class: "readonly-banner",
            span { class: "readonly-banner-icon", "🔒" }
            span {
                "Read-only — this engine requires signed commands and the identity you're "
                "acting as won't be accepted for changes. Adopt or enroll a trusted identity "
                "to make changes."
            }
        }
    }
}

#[component]
#[allow(non_snake_case)]
pub fn SecDot() -> Element {
    let ctx = use_context::<AppCtx>();
    let state = live_chip_state(&ctx);
    let view = derive_sec_dot(&state);
    let glyph = view.glyph;
    let class = view.css_class;
    let tooltip = view.tooltip.clone();
    rsx! {
        span {
            class: "{class}",
            title: "{tooltip}",
            "data-tooltip": "{tooltip}",
            "{glyph}"
        }
    }
}
