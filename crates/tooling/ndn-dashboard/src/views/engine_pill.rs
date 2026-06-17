//! Runtime-classification pill rendered next to the conn-bar identity chip.

use dioxus::prelude::*;
use ndn_security::custodian::CustodianRef;

/// Computed at startup from compile-time features + the `?engine=` query string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardRuntime {
    /// Native binary; talks to a local ndn-fwd over Unix domain socket.
    Desktop,
    /// wasm32 browser tab; talks to a remote forwarder over WebSocket.
    Browser,
    /// wasm32 + `browser-engine` + `?engine=local` — the dashboard hosts its
    /// own `ForwarderEngine` in-page.
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

/// Pure on `engine_local` so tests can pin each branch.
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

pub fn current_runtime_for_test_or_render() -> DashboardRuntime {
    current_runtime()
}

#[cfg(target_arch = "wasm32")]
fn engine_local_query_param() -> bool {
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

/// FDE probe result; the v1 probe always returns `Unknown` (no browser API
/// reveals OS disk-encryption state). `Off` is reserved for a future native
/// probe so the warning-text contract can land its branch now.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdeDetection {
    On,
    Off,
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
            _ => None,
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub fn probe_fde() -> FdeDetection {
    FdeDetection::Unknown
}

#[cfg(not(target_arch = "wasm32"))]
pub fn probe_fde() -> FdeDetection {
    FdeDetection::Unknown
}

/// What this machine holds of your signing key, and the trust caveat — the
/// honest answer to "what can this machine do with my key, and what happens
/// when I walk away." Surfaced read-only. The key *never touching* the machine
/// (phone/fob remote custodian) is designed (synthesis §5) but not yet built;
/// today the choices are on-disk persistence or an in-memory ephemeral key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineTrust {
    /// The custodian kind backing the signing key on this surface, if any.
    /// `None` when no identity is bound.
    pub custodian: Option<CustodianRef>,
    /// Where the signing key lives on this surface (precise, runtime-aware).
    pub residence: &'static str,
    /// Whether the key persists past this session (on disk / in the browser).
    pub persists: bool,
    /// Whether each signature requires an explicit user action (fob/extension).
    pub prompts: bool,
    /// One-line caveat about trusting this machine with the key, if any.
    pub caveat: Option<String>,
}

/// Which [`CustodianRef`] backs signing on this surface today. Until the mgmt
/// signing path routes through a real `CustodianRegistry`, this is inferred
/// from the runtime + ephemeral flag — but it speaks the canonical custodian
/// vocabulary, so swapping in a live registry later is a one-place change and
/// a future Fob/Extension custodian surfaces correctly.
pub fn active_custodian_ref(
    runtime: DashboardRuntime,
    ephemeral: bool,
    has_identity: bool,
) -> Option<CustodianRef> {
    if !has_identity {
        return None;
    }
    if ephemeral {
        // Ephemeral keys live in process memory regardless of platform.
        return Some(CustodianRef::InPage);
    }
    Some(match runtime {
        DashboardRuntime::Desktop => CustodianRef::OsKeyring,
        DashboardRuntime::Browser | DashboardRuntime::BrowserEngineLocal => CustodianRef::InPage,
    })
}

/// Pure over its inputs so each branch is testable. Derives the machine-trust
/// display from the canonical [`CustodianRef`] (its `key_on_this_machine` /
/// `prompts_per_action` semantics) plus the runtime/ephemeral/FDE context.
pub fn machine_trust_for(
    runtime: DashboardRuntime,
    ephemeral: bool,
    has_identity: bool,
    fde: FdeDetection,
) -> MachineTrust {
    let Some(custodian) = active_custodian_ref(runtime, ephemeral, has_identity) else {
        return MachineTrust {
            custodian: None,
            residence: "No signing key bound",
            persists: false,
            prompts: false,
            caveat: None,
        };
    };

    let on_machine = custodian.key_on_this_machine();
    let prompts = custodian.prompts_per_action();
    // Precise residence: runtime/ephemeral nuance for on-machine kinds, the
    // custodian label for off-machine ones (fob/remote).
    let residence: &'static str = if ephemeral {
        "In-memory (ephemeral)"
    } else {
        match &custodian {
            CustodianRef::OsKeyring => "On-disk keyring (PIB)",
            CustodianRef::InPage => "Browser storage (IndexedDB)",
            other => other.label(),
        }
    };
    let persists = on_machine && !ephemeral;
    let caveat = if ephemeral {
        Some(
            "Nothing is written to disk — this binding ends when the session closes. Safe to use on a machine you don't fully control."
                .to_owned(),
        )
    } else if on_machine {
        // FDE warning is the right "untrusted machine" caveat: silent on desktop
        // (operator knows their own FS), loud about IndexedDB / unencrypted disk.
        fde.warning_text(runtime)
    } else {
        // Fob/remote: the key never touches this machine — the safe option.
        Some("The key stays on the fob/phone and never touches this machine.".to_owned())
    };

    MachineTrust {
        custodian: Some(custodian),
        residence,
        persists,
        prompts,
        caveat,
    }
}

/// Live machine-trust for the current runtime + FDE probe.
pub fn live_machine_trust(ephemeral: bool, has_identity: bool) -> MachineTrust {
    machine_trust_for(current_runtime(), ephemeral, has_identity, probe_fde())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_trust_ephemeral_does_not_persist() {
        let t = machine_trust_for(DashboardRuntime::Desktop, true, true, FdeDetection::Unknown);
        assert_eq!(t.custodian, Some(CustodianRef::InPage));
        assert!(!t.persists);
        assert!(!t.prompts);
        assert!(t.caveat.unwrap().to_lowercase().contains("session"));
    }

    #[test]
    fn machine_trust_desktop_persisted_is_silent_when_fde_unknown() {
        let t = machine_trust_for(
            DashboardRuntime::Desktop,
            false,
            true,
            FdeDetection::Unknown,
        );
        assert_eq!(t.custodian, Some(CustodianRef::OsKeyring));
        assert!(t.persists);
        assert_eq!(t.residence, "On-disk keyring (PIB)");
        assert!(t.caveat.is_none());
    }

    #[test]
    fn active_custodian_ref_maps_runtime_and_ephemeral() {
        assert_eq!(
            active_custodian_ref(DashboardRuntime::Desktop, false, true),
            Some(CustodianRef::OsKeyring)
        );
        assert_eq!(
            active_custodian_ref(DashboardRuntime::Browser, false, true),
            Some(CustodianRef::InPage)
        );
        assert_eq!(
            active_custodian_ref(DashboardRuntime::Desktop, true, true),
            Some(CustodianRef::InPage)
        );
        assert_eq!(
            active_custodian_ref(DashboardRuntime::Desktop, false, false),
            None
        );
    }

    #[test]
    fn machine_trust_browser_warns_about_recoverability() {
        let t = machine_trust_for(
            DashboardRuntime::Browser,
            false,
            true,
            FdeDetection::Unknown,
        );
        assert!(t.persists);
        assert!(t.caveat.is_some());
    }

    #[test]
    fn machine_trust_no_identity() {
        let t = machine_trust_for(
            DashboardRuntime::Desktop,
            false,
            false,
            FdeDetection::Unknown,
        );
        assert!(!t.persists);
        assert!(t.caveat.is_none());
    }

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
