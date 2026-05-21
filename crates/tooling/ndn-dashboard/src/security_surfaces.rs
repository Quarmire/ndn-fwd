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
    let identity_name = ctx.identity_name.read();
    let is_ephemeral = *ctx.identity_is_ephemeral.read();
    let cert_expiry = *ctx.cert_valid_until_unix_s.read();
    let signed_required = *ctx.mgmt_signed_commands_required.read();
    let surface_supported = *ctx.security_surface_supported.read();
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
