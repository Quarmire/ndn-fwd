//! §8 engine pill — surfaces what kind of dashboard the operator is
//! looking at: a native desktop binary, a browser tab talking to a
//! remote forwarder over WebSocket, or a browser tab running its own
//! in-page forwarder engine via `?engine=local`.
//!
//! The distinction matters because the security/persistence
//! affordances differ: desktop reads/writes a `FilePib` on disk;
//! browser uses `IdbPib` in IndexedDB; browser-engine-local
//! additionally hosts the engine itself inside the same JS realm.

use dioxus::prelude::*;

/// What kind of runtime is the dashboard sitting in. Computed at
/// startup from compile-time features + the `?engine=` query
/// string; the pill renders it next to the conn-bar's identity chip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardRuntime {
    /// Native binary (Dioxus desktop). Talks to a local ndn-fwd
    /// over Unix domain socket via ndn-ipc.
    Desktop,
    /// Browser tab (wasm32 + dioxus/web). Talks to a remote ndn-fwd
    /// over WebSocket via the dashboard's WsMgmtClient.
    Browser,
    /// Browser tab with `?engine=local` — the dashboard hosts its
    /// own `ForwarderEngine` in-page via the browser-engine feature.
    BrowserEngineLocal,
}

impl DashboardRuntime {
    pub fn label(self) -> &'static str {
        match self {
            DashboardRuntime::Desktop => "Desktop",
            DashboardRuntime::Browser => "Browser",
            DashboardRuntime::BrowserEngineLocal => "Browser-engine-local",
        }
    }

    pub fn tooltip(self) -> &'static str {
        match self {
            DashboardRuntime::Desktop => {
                "Native desktop dashboard — Unix-socket mgmt; PIB lives on disk."
            }
            DashboardRuntime::Browser => {
                "Browser dashboard — WebSocket mgmt; PIB lives in IndexedDB."
            }
            DashboardRuntime::BrowserEngineLocal => {
                "Browser dashboard with in-page forwarder engine (?engine=local) — mgmt + PIB live entirely in this tab."
            }
        }
    }

    pub fn glyph(self) -> &'static str {
        match self {
            DashboardRuntime::Desktop => "🖥",
            DashboardRuntime::Browser => "🌐",
            DashboardRuntime::BrowserEngineLocal => "🧪",
        }
    }
}

/// Detect the active runtime at component-render time.
///
/// * Native target → `Desktop`.
/// * wasm32 + `browser-engine` feature + `?engine=local` (resolved
///   by the existing `browser_engine` module) → `BrowserEngineLocal`.
/// * wasm32 otherwise → `Browser`.
///
/// The function is intentionally pure on the visible inputs (the
/// `engine_local` flag); callers pass the resolved boolean so tests
/// can pin each branch.
pub fn classify(target_wasm32: bool, engine_local: bool) -> DashboardRuntime {
    match (target_wasm32, engine_local) {
        (false, _) => DashboardRuntime::Desktop,
        (true, true) => DashboardRuntime::BrowserEngineLocal,
        (true, false) => DashboardRuntime::Browser,
    }
}

#[component]
pub fn EnginePill() -> Element {
    let runtime = current_runtime();
    let label = runtime.label();
    let tooltip = runtime.tooltip();
    let glyph = runtime.glyph();
    rsx! {
        span {
            class: "engine-pill",
            title: "{tooltip}",
            style: "display:inline-flex;gap:6px;align-items:center;padding:3px 10px;font-size:11px;background:var(--surface2);border:1px solid var(--border);border-radius:12px;color:var(--text-muted);",
            span { "{glyph}" }
            span { "{label}" }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn current_runtime() -> DashboardRuntime {
    classify(false, false)
}

#[cfg(target_arch = "wasm32")]
fn current_runtime() -> DashboardRuntime {
    let engine_local = engine_local_query_param();
    classify(true, engine_local)
}

/// Pub-visible runtime classifier for cross-module callers that need
/// to format runtime-specific text (e.g. the §11.2 FDE warning).
pub fn current_runtime_for_test_or_render() -> DashboardRuntime {
    current_runtime()
}

#[cfg(target_arch = "wasm32")]
fn engine_local_query_param() -> bool {
    // ?engine=local on the current page URL flips the browser-engine
    // mode (matching the existing `browser_engine` module's
    // convention). Best-effort — anything unparseable falls back to
    // a remote-WebSocket assumption.
    let Some(window) = web_sys::window() else {
        return false;
    };
    let Ok(search) = window.location().search() else {
        return false;
    };
    let trimmed = search.trim_start_matches('?');
    for kv in trimmed.split('&') {
        if let Some((k, v)) = kv.split_once('=')
            && k == "engine"
            && v == "local"
        {
            return true;
        }
    }
    false
}

// ── §11.2 FDE-detection-with-warning ─────────────────────────────────────────
//
// Per design §11.2, the dashboard warns on the first PIB-IDB write
// when full-disk encryption is verifiably OFF. Reality: from inside
// a browser sandbox there is no API that reveals whether the OS
// disk is encrypted. So the v1 surface is honest about that limit:
// a one-time "we can't verify your FDE state" warning on the first
// IDB-PIB write, gated by a localStorage flag so it doesn't reappear
// once the operator has seen it. Desktop binaries skip the warning
// entirely — operators know their own filesystems.

/// Result of the §11.2 FDE probe. The probe is best-effort; v1
/// returns `Unknown` from the browser sandbox.
///
/// `Off` is never constructed by the v1 probe — it's reserved for a
/// future native FDE probe (fdesetup / manage-bde / cryptsetup) so
/// the warning-text contract can land its branch now.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdeDetection {
    /// Disk encryption verifiably ON (probe confirmed; v1 never
    /// produces this from a browser).
    On,
    /// Disk encryption verifiably OFF (probe confirmed; v1 never
    /// produces this from a browser).
    Off,
    /// Couldn't determine — the design's "acceptable" outcome.
    Unknown,
}

impl FdeDetection {
    pub fn warning_text(self, runtime: DashboardRuntime) -> Option<String> {
        match (self, runtime) {
            (FdeDetection::Off, _) => Some(
                "Disk encryption is OFF on this device. The PIB you're about to write will be recoverable by anyone with physical access to the disk."
                    .to_owned(),
            ),
            (FdeDetection::Unknown, DashboardRuntime::Browser)
            | (FdeDetection::Unknown, DashboardRuntime::BrowserEngineLocal) => Some(
                "The PIB will persist to IndexedDB in this browser. From the browser sandbox the dashboard can't verify whether the OS disk is encrypted; if the device's disk isn't encrypted, the PIB is recoverable by anyone with the device."
                    .to_owned(),
            ),
            // Desktop + Unknown: the operator runs on their own
            // machine and knows their own filesystem; suppress the
            // warning to avoid false-positive noise.
            _ => None,
        }
    }
}

/// Best-effort FDE probe. The browser implementation always returns
/// `Unknown` per the v1 design's "acceptable" outcome.
#[cfg(target_arch = "wasm32")]
pub fn probe_fde() -> FdeDetection {
    FdeDetection::Unknown
}

/// Best-effort FDE probe on native. v1 also returns `Unknown` —
/// shelling out to `fdesetup`, `manage-bde`, or `cryptsetup` per OS
/// is doable but out of scope for the dashboard's first cut; the
/// pill's tooltip already tells the operator the PIB sits on disk.
#[cfg(not(target_arch = "wasm32"))]
pub fn probe_fde() -> FdeDetection {
    FdeDetection::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_native_is_desktop() {
        assert_eq!(classify(false, false), DashboardRuntime::Desktop);
        assert_eq!(classify(false, true), DashboardRuntime::Desktop);
    }

    #[test]
    fn classify_wasm32_engine_local_is_browser_engine_local() {
        assert_eq!(classify(true, true), DashboardRuntime::BrowserEngineLocal);
    }

    #[test]
    fn classify_wasm32_remote_is_browser() {
        assert_eq!(classify(true, false), DashboardRuntime::Browser);
    }

    #[test]
    fn labels_are_distinct_and_non_empty() {
        let runtimes = [
            DashboardRuntime::Desktop,
            DashboardRuntime::Browser,
            DashboardRuntime::BrowserEngineLocal,
        ];
        let labels: Vec<&str> = runtimes.iter().map(|r| r.label()).collect();
        for l in &labels {
            assert!(!l.is_empty());
        }
        // Distinct
        let mut sorted = labels.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), labels.len());
    }

    #[test]
    fn fde_warning_text_browser_unknown_warns_about_idb() {
        let txt = FdeDetection::Unknown
            .warning_text(DashboardRuntime::Browser)
            .expect("browser+unknown must warn");
        assert!(txt.to_lowercase().contains("indexeddb"));
        assert!(
            txt.to_lowercase().contains("verify") || txt.to_lowercase().contains("can't"),
            "warning should be honest about the limit: {txt}"
        );
    }

    #[test]
    fn fde_warning_text_desktop_unknown_is_silent() {
        assert!(
            FdeDetection::Unknown
                .warning_text(DashboardRuntime::Desktop)
                .is_none(),
            "desktop + unknown should suppress (operator knows their own filesystem)"
        );
    }

    #[test]
    fn fde_warning_text_off_warns_unconditionally() {
        for r in [
            DashboardRuntime::Desktop,
            DashboardRuntime::Browser,
            DashboardRuntime::BrowserEngineLocal,
        ] {
            let txt = FdeDetection::Off
                .warning_text(r)
                .expect("OFF must always warn");
            assert!(txt.to_lowercase().contains("disk"));
        }
    }

    #[test]
    fn fde_warning_text_on_suppresses_warning() {
        for r in [
            DashboardRuntime::Desktop,
            DashboardRuntime::Browser,
            DashboardRuntime::BrowserEngineLocal,
        ] {
            assert!(FdeDetection::On.warning_text(r).is_none());
        }
    }

    #[test]
    fn tooltip_mentions_persistence_layer() {
        assert!(
            DashboardRuntime::Desktop
                .tooltip()
                .to_lowercase()
                .contains("pib"),
            "desktop tooltip should mention the PIB"
        );
        assert!(
            DashboardRuntime::Browser
                .tooltip()
                .to_lowercase()
                .contains("indexeddb"),
            "browser tooltip should mention IndexedDB"
        );
        assert!(
            DashboardRuntime::BrowserEngineLocal
                .tooltip()
                .to_lowercase()
                .contains("in-page"),
            "browser-engine-local tooltip should mention in-page engine"
        );
    }
}
