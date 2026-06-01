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
/// switchable dropdown once more than one identity is selectable. Both branches
/// read the same [`IdentityAxis`] view-model so display and selection can't
/// drift, and so the Identity nav bucket / extension / mobile can reuse it.
#[component]
#[allow(non_snake_case)]
pub fn IdentityAxisControl() -> Element {
    let ctx = use_context::<AppCtx>();
    let mut identity_name = ctx.identity_name;
    let axis = crate::identity_axis::IdentityAxis::from_active(
        identity_name.read().as_str(),
        *ctx.identity_is_ephemeral.read(),
    );

    rsx! {
        span { class: "axis-label", "Acting as" }
        if axis.is_single() {
            // One (or zero) identity → the chip already shows it with status.
            IdentityChip {}
        } else {
            // Multi-context: pick which identity signs on this surface.
            // NOTE: this sets the dashboard's active-identity state; binding it
            // to the mgmt-command signer lands with the TrustContext custodian
            // work (Phase 3/4). The branch is unreachable on today's
            // single-identity model and is exercised by identity_axis tests.
            select {
                class: "axis-select",
                onchange: move |e| identity_name.set(e.value()),
                for id in axis.available.iter() {
                    option {
                        value: "{id.name}",
                        selected: axis.active.as_ref().map(|a| a.name == id.name).unwrap_or(false),
                        "{id.name}"
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
