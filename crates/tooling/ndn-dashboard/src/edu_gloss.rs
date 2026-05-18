//! `EduGloss` — education seam (§9). Wraps any NDN-jargon atom so the
//! user gets a one-line gloss + wiki link without leaving the flow.
//!
//! Glosses live in `glossary.toml` next to this crate's `Cargo.toml`
//! — single source of truth. The `dash-glossary` CI tool scans the
//! dashboard's source for every `EduGloss { term: "X", … }` callsite
//! and fails the build if `X` is missing from the data file.
//!
//! Render shape: an inline `<abbr>` carrying the gloss as a tooltip;
#![allow(dead_code)] // lands ahead of UI callsites; Phase B+ wires it in
//! when the wiki anchor is non-empty, the term is rendered as a
//! clickable link that opens `docs/wiki/src/<anchor>`. Web and desktop
//! see the same DOM (Dioxus webview parity).

use std::collections::HashMap;
use std::sync::OnceLock;

use dioxus::prelude::*;
use serde::Deserialize;

const GLOSSARY_TOML: &str = include_str!("../glossary.toml");

#[derive(Debug, Clone, Deserialize)]
struct GlossaryFile {
    entries: Vec<GlossaryEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GlossaryEntry {
    pub term: String,
    pub gloss: String,
    #[serde(default)]
    pub extended: Option<String>,
    pub wiki_anchor: String,
}

fn glossary() -> &'static HashMap<String, GlossaryEntry> {
    static MAP: OnceLock<HashMap<String, GlossaryEntry>> = OnceLock::new();
    MAP.get_or_init(|| {
        let parsed: GlossaryFile = toml::from_str(GLOSSARY_TOML)
            .expect("glossary.toml must parse (ci guard runs at build time)");
        parsed
            .entries
            .into_iter()
            .map(|e| (e.term.clone(), e))
            .collect()
    })
}

/// Look up a glossary entry by exact term. Returns `None` when the
/// term is unknown — the `dash-glossary` CI guard prevents this at
/// merge time, but the runtime tolerates absence so the dashboard
/// still renders during local development.
pub fn lookup(term: &str) -> Option<&'static GlossaryEntry> {
    glossary().get(term)
}

/// Inline gloss wrapper. Renders the term (or `children` override) as
/// an `<abbr>`-styled span with the gloss exposed via `title=`.
#[component]
#[allow(non_snake_case)]
pub fn EduGloss(
    /// Lookup key into `glossary.toml`. Pinned by the CI guard.
    term: &'static str,
    /// Optional display text. Defaults to `term`.
    #[props(default = None)]
    display: Option<&'static str>,
) -> Element {
    let entry = lookup(term);
    let shown = display.unwrap_or(term);
    match entry {
        Some(e) => rsx! {
            abbr {
                title: "{e.gloss}",
                style: "text-decoration: underline dotted; cursor: help;",
                "{shown}"
            }
        },
        // Unknown term — surface visibly during development so it
        // gets noticed before the CI guard catches it.
        None => rsx! {
            span {
                style: "background: #fee; color: #c00; padding: 0 2px;",
                title: "EduGloss: term not in glossary.toml",
                "{shown}"
            }
        },
    }
}
