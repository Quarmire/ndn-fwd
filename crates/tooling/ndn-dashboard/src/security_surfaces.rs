//! §3 always-rendered security surfaces.
//!
//! [`IdentityChip`] — the §3.1 top-bar chip that reflects the live
//! [`crate::security_state::ChipState`] alongside the connection
//! badge. [`SecDot`] — the §3.2 sidebar glyph that mirrors the same
//! state in a denser, less-prominent form.
//!
//! Both components derive their state from the same
//! `derive_chip_state` call so the chip's label and the dot's
//! tooltip can't drift. The two are split into separate components
//! because the conn-bar and the sidebar render in different parts of
//! the layout tree; deriving twice is cheap (pure function).

#![allow(dead_code)] // wires into the layout once app.rs/app_web.rs adopt the chip

use dioxus::prelude::*;

use crate::app::AppCtx;
use crate::security_state::{ChipInput, ChipState, derive_chip_state, derive_sec_dot};

fn live_chip_state(ctx: &AppCtx) -> ChipState {
    let identity_name = ctx.identity_name.read();
    let is_ephemeral = *ctx.identity_is_ephemeral.read();
    derive_chip_state(ChipInput {
        identity_name: identity_name.as_str(),
        identity_is_ephemeral: is_ephemeral,
        // Phase B: thread the active cert's valid_until + a clock
        // signal through AppCtx so the chip can flip to Expired /
        // ExpiringSoon. Today these dimensions are absent.
        cert_valid_until_unix_s: None,
        now_unix_s: None,
        // Phase B: poll `/localhost/nfd/security/policy-get` and
        // populate this signal. When None, the chip can't show
        // UnsignedMgmt (it stays on Ephemeral / Hardened).
        mgmt_signed_commands_required: None,
    })
}

/// §3.1 — the always-rendered identity chip. Click is a no-op for v1;
/// the identity panel popup (§3.1 inline view) lands when AppCtx
/// gains the cert / anchor data it needs to render.
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

/// §3.2 — the sidebar security dot. Glyph + colour + tooltip per the
/// design table.
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
