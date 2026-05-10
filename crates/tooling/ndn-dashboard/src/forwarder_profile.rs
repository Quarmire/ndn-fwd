//! Forwarder profile + connection-mode selection.
//!
//! ndn-dashboard manages any of the three production-grade NDN
//! forwarders that all speak the NFD-spec mgmt protocol:
//!
//! | Project  | Forwarder binary |
//! |----------|------------------|
//! | ndn-rs   | `ndn-fwd`        |
//! | ndn-cxx  | `NFD`            |
//! | ndnd     | `YaNFD`          |
//!
//! The per-forwarder differences are *configuration* (socket paths,
//! binary names) and *capability* (which extensions present), not
//! wire format. Profile selection is **runtime**, via the
//! `--forwarder=<name>` CLI flag (desktop) or `?forwarder=<name>`
//! query string (web), defaulting to auto-detect.
//!
//! # Connection modes
//!
//! [`ConnectionMode`] separates *which forwarder* (the profile) from
//! *how the dashboard reaches it*. On desktop the connection is
//! either a Unix-socket attach to a running forwarder or a spawn of
//! the local binary. On web the connection is either a WebSocket
//! to a remote forwarder or — new in this revision — an
//! **in-page WASM engine**: dashboard ships its own
//! [`ndn_engine`] instance that runs entirely in the browser tab,
//! per the Phase 7 work proven by `crates/tooling/dioxus-demo`.
//!
//! See `docs/notes/dashboard-multi-forwarder-2026-05-10.md` for
//! the full design + rationale.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Process-wide selected (profile, socket) — set once in `main()`
/// before Dioxus launches, read by `forwarder_proc` callers and
/// the mgmt connection layer. `OnceLock` instead of Dioxus context
/// because the resolution is process-static and several callers
/// live in free functions outside any component scope.
static SELECTED: OnceLock<(ForwarderProfile, PathBuf)> = OnceLock::new();

pub fn install_selected(profile: ForwarderProfile, socket: PathBuf) {
    let _ = SELECTED.set((profile, socket));
}

/// Returns the installed selection, or `(NdnFwd, NdnFwd's default
/// socket)` if no selection was installed (e.g. unit tests, web
/// builds that haven't called [`install_selected`]).
pub fn selected() -> (ForwarderProfile, PathBuf) {
    SELECTED.get().cloned().unwrap_or_else(|| {
        (
            ForwarderProfile::NdnFwd,
            ForwarderProfile::NdnFwd.default_socket().to_path_buf(),
        )
    })
}

pub fn selected_profile() -> ForwarderProfile {
    selected().0
}

/// Which NDN forwarder the dashboard is talking to.
///
/// Differences across variants are configuration + capability,
/// not wire format — all three speak the NFD-spec management
/// protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwarderProfile {
    /// `ndn-fwd` — this workspace's forwarder. Has demo CA +
    /// WebTransport + WebRTC + SharedWorker face + IssuancePolicy
    /// + SafeBag extensions on top of NFD-spec baseline.
    NdnFwd,
    /// `NFD` — the C++ reference implementation from ndn-cxx
    /// (https://github.com/named-data/NFD).
    Nfd,
    /// `YaNFD` — the Go forwarder from ndnd
    /// (https://github.com/named-data/ndnd).
    YaNfd,
}

/// Capability flags for things outside the NFD-spec mgmt baseline.
///
/// Today the profile returns a static expected list; a follow-on
/// revision queries `/localhost/nfd/status/general` at connect and
/// replaces these with the discovered set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Extension {
    /// `[demo_ca]`-served NDNCERT CA.
    DemoCa,
    /// `[listeners.webtransport]` listener.
    WebTransport,
    /// `[listeners.webrtc]` inbound peer face.
    WebRtcInbound,
    /// SharedWorker face inside the dispatcher.
    SharedWorkerFace,
    /// SafeBag export tooling.
    SafeBagExport,
    /// `IssuancePolicy` post-challenge gate (F7).
    IssuancePolicy,
}

impl ForwarderProfile {
    /// Default management socket path. Operators override via
    /// `--socket=/custom/path`.
    pub fn default_socket(self) -> &'static Path {
        match self {
            // Matches `[management] face_socket` in
            // `binaries/spec/ndn-fwd/ndn-fwd.default.toml`.
            ForwarderProfile::NdnFwd => Path::new("/run/ndn-fwd/ndn-fwd.sock"),
            // NFD's spec default.
            ForwarderProfile::Nfd => Path::new("/var/run/nfd.sock"),
            // YaNFD packaging default per ndnd repo.
            ForwarderProfile::YaNfd => Path::new("/run/nfd/nfd.sock"),
        }
    }

    /// Binary name to look for on `$PATH` when spawning.
    pub fn binary_name(self) -> &'static str {
        match self {
            ForwarderProfile::NdnFwd => {
                if cfg!(windows) {
                    "ndn-fwd.exe"
                } else {
                    "ndn-fwd"
                }
            }
            ForwarderProfile::Nfd => "nfd",
            ForwarderProfile::YaNfd => "yanfd",
        }
    }

    /// Human-readable label for status bars / chooser dropdowns.
    pub fn human_label(self) -> &'static str {
        match self {
            ForwarderProfile::NdnFwd => "ndn-fwd (ndn-rs)",
            ForwarderProfile::Nfd => "NFD (ndn-cxx)",
            ForwarderProfile::YaNfd => "YaNFD (ndnd)",
        }
    }

    /// CLI-friendly machine name accepted by `--forwarder=`.
    pub fn machine_name(self) -> &'static str {
        match self {
            ForwarderProfile::NdnFwd => "ndn-fwd",
            ForwarderProfile::Nfd => "nfd",
            ForwarderProfile::YaNfd => "yanfd",
        }
    }

    /// Parse the CLI / query-string flag value. Accepts the project
    /// name *and* the binary name for ergonomics — operators
    /// reach for whichever they remember.
    pub fn from_cli(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "ndn-rs" | "ndn-fwd" | "ndnfwd" | "ndn_fwd" => Some(Self::NdnFwd),
            "ndn-cxx" | "nfd" => Some(Self::Nfd),
            "ndnd" | "yanfd" | "ya-nfd" => Some(Self::YaNfd),
            _ => None,
        }
    }

    /// Extensions the dashboard *expects* to find on this
    /// forwarder. Static hint today; capability discovery via
    /// `/localhost/nfd/status/general` will override at connect.
    pub fn known_extensions(self) -> &'static [Extension] {
        match self {
            ForwarderProfile::NdnFwd => &[
                Extension::DemoCa,
                Extension::WebTransport,
                Extension::WebRtcInbound,
                Extension::SharedWorkerFace,
                Extension::SafeBagExport,
                Extension::IssuancePolicy,
            ],
            // ndn-cxx ships SafeBag (via ndnsec). YaNFD doesn't.
            // None ship the ndn-rs-specific WT / WebRTC / shared-worker
            // face configs or our demo CA / IssuancePolicy / token-mint
            // extensions.
            ForwarderProfile::Nfd => &[Extension::SafeBagExport],
            ForwarderProfile::YaNfd => &[],
        }
    }

    /// Detection iteration order. ndn-fwd first (we ship in the
    /// same workspace; cheapest local hit), then NFD, then YaNFD.
    pub fn detection_order() -> [ForwarderProfile; 3] {
        [
            ForwarderProfile::NdnFwd,
            ForwarderProfile::Nfd,
            ForwarderProfile::YaNfd,
        ]
    }
}

/// How the dashboard reaches its forwarder.
///
/// `Spawn` and `Attach` are desktop-only; `WebSocket` and
/// `BrowserEngine` are web-only. The variant carries the
/// connection-specific data; the [`ForwarderProfile`] carries the
/// capability / binary metadata orthogonally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionMode {
    /// Spawn the profile's binary as a child process and manage
    /// it (Start/Stop buttons in the desktop UI). Desktop only.
    Spawn {
        profile: ForwarderProfile,
        socket: PathBuf,
    },
    /// Attach to an already-running forwarder over its mgmt
    /// Unix socket. Desktop only. No Start/Stop controls.
    Attach {
        profile: ForwarderProfile,
        socket: PathBuf,
    },
    /// Connect to a remote forwarder over WebSocket (NFD-spec mgmt
    /// tunneled through WS). Web only. The forwarder typically
    /// runs `[listeners.websocket]` to terminate this.
    WebSocket {
        profile: ForwarderProfile,
        url: String,
    },
    /// Run an in-page `ndn_engine` instance. Web only. The
    /// dashboard *is* the forwarder; mgmt Interests are dispatched
    /// to the in-page engine without leaving the tab. Profile is
    /// always `NdnFwd` (we ship ndn-engine). Proven path:
    /// `crates/tooling/dioxus-demo` (see Phase 7).
    BrowserEngine,
}

impl ConnectionMode {
    pub fn profile(&self) -> ForwarderProfile {
        match self {
            ConnectionMode::Spawn { profile, .. }
            | ConnectionMode::Attach { profile, .. }
            | ConnectionMode::WebSocket { profile, .. } => *profile,
            ConnectionMode::BrowserEngine => ForwarderProfile::NdnFwd,
        }
    }

    /// True if the mode supports Start/Stop controls.
    pub fn supports_lifecycle(&self) -> bool {
        matches!(self, ConnectionMode::Spawn { .. })
    }
}

/// Resolve the static (non-I/O) component of mode selection from
/// CLI flags. Returns `None` only when neither flag is supplied
/// AND auto-detect should run.
pub fn resolve_static(
    cli_forwarder: Option<&str>,
    cli_socket: Option<PathBuf>,
) -> Option<(ForwarderProfile, PathBuf)> {
    match (cli_forwarder, cli_socket) {
        (Some(p), Some(s)) => ForwarderProfile::from_cli(p).map(|p| (p, s)),
        (Some(p), None) => {
            let prof = ForwarderProfile::from_cli(p)?;
            Some((prof, prof.default_socket().to_path_buf()))
        }
        (None, Some(s)) => {
            let matched = ForwarderProfile::detection_order()
                .into_iter()
                .find(|p| p.default_socket() == s)
                .unwrap_or(ForwarderProfile::NdnFwd);
            Some((matched, s))
        }
        (None, None) => None,
    }
}

/// Probe each profile's default socket; first existing path wins.
/// Path-existence only today; promoting to live status-Interest
/// probe is the next iteration.
pub fn auto_detect() -> Option<(ForwarderProfile, PathBuf)> {
    for prof in ForwarderProfile::detection_order() {
        let sock = prof.default_socket();
        if sock.exists() {
            return Some((prof, sock.to_path_buf()));
        }
    }
    None
}

/// Web-side equivalent: parse the page query string for
/// `?forwarder=<name>&ws=<url>&engine=local`. Returns the
/// resolved [`ConnectionMode`].
///
/// - `engine=local` → [`ConnectionMode::BrowserEngine`] (overrides).
/// - else `ws=<url>` or fallback → [`ConnectionMode::WebSocket`].
#[cfg(target_arch = "wasm32")]
pub fn resolve_web(query: &str) -> ConnectionMode {
    let mut forwarder = None;
    let mut ws = None;
    let mut engine_local = false;
    for pair in query.trim_start_matches('?').split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let v = urlencoding_decode(v);
            match k {
                "forwarder" => forwarder = ForwarderProfile::from_cli(&v),
                "ws" => ws = Some(v),
                "engine" if v == "local" => engine_local = true,
                _ => {}
            }
        }
    }
    if engine_local {
        return ConnectionMode::BrowserEngine;
    }
    ConnectionMode::WebSocket {
        profile: forwarder.unwrap_or(ForwarderProfile::NdnFwd),
        url: ws.unwrap_or_else(|| "ws://localhost:9696".to_string()),
    }
}

#[cfg(target_arch = "wasm32")]
fn urlencoding_decode(s: &str) -> String {
    // Minimal: handle `%xx` and `+`. Avoids a dep for two characters
    // worth of decoding.
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parse_accepts_project_and_binary_names() {
        // ndn-rs / ndn-fwd → NdnFwd
        assert_eq!(
            ForwarderProfile::from_cli("ndn-rs"),
            Some(ForwarderProfile::NdnFwd)
        );
        assert_eq!(
            ForwarderProfile::from_cli("ndn-fwd"),
            Some(ForwarderProfile::NdnFwd)
        );
        assert_eq!(
            ForwarderProfile::from_cli("NDN-FWD"),
            Some(ForwarderProfile::NdnFwd)
        );
        // ndn-cxx / NFD → Nfd
        assert_eq!(
            ForwarderProfile::from_cli("ndn-cxx"),
            Some(ForwarderProfile::Nfd)
        );
        assert_eq!(
            ForwarderProfile::from_cli("nfd"),
            Some(ForwarderProfile::Nfd)
        );
        // ndnd / YaNFD → YaNfd
        assert_eq!(
            ForwarderProfile::from_cli("ndnd"),
            Some(ForwarderProfile::YaNfd)
        );
        assert_eq!(
            ForwarderProfile::from_cli("yanfd"),
            Some(ForwarderProfile::YaNfd)
        );
        assert_eq!(
            ForwarderProfile::from_cli("ya-nfd"),
            Some(ForwarderProfile::YaNfd)
        );
        assert_eq!(ForwarderProfile::from_cli("garbage"), None);
    }

    #[test]
    fn machine_names_round_trip() {
        for prof in ForwarderProfile::detection_order() {
            assert_eq!(ForwarderProfile::from_cli(prof.machine_name()), Some(prof));
        }
    }

    #[test]
    fn resolve_static_combinations() {
        let r = resolve_static(Some("nfd"), Some(PathBuf::from("/tmp/foo.sock")));
        assert_eq!(
            r,
            Some((ForwarderProfile::Nfd, PathBuf::from("/tmp/foo.sock")))
        );

        let r = resolve_static(Some("nfd"), None).unwrap();
        assert_eq!(r.0, ForwarderProfile::Nfd);
        assert_eq!(r.1, PathBuf::from("/var/run/nfd.sock"));

        let r = resolve_static(None, Some(PathBuf::from("/var/run/nfd.sock"))).unwrap();
        assert_eq!(r.0, ForwarderProfile::Nfd);

        let r = resolve_static(None, Some(PathBuf::from("/tmp/whatever.sock"))).unwrap();
        assert_eq!(r.0, ForwarderProfile::NdnFwd);

        assert_eq!(resolve_static(None, None), None);
    }

    #[test]
    fn unique_human_labels() {
        let labels: std::collections::HashSet<_> = ForwarderProfile::detection_order()
            .iter()
            .map(|p| p.human_label())
            .collect();
        assert_eq!(labels.len(), 3);
    }

    #[test]
    fn connection_mode_profile_extraction() {
        let m = ConnectionMode::Attach {
            profile: ForwarderProfile::Nfd,
            socket: PathBuf::from("/x"),
        };
        assert_eq!(m.profile(), ForwarderProfile::Nfd);
        assert!(!m.supports_lifecycle());

        let m = ConnectionMode::Spawn {
            profile: ForwarderProfile::NdnFwd,
            socket: PathBuf::from("/x"),
        };
        assert!(m.supports_lifecycle());

        assert_eq!(
            ConnectionMode::BrowserEngine.profile(),
            ForwarderProfile::NdnFwd
        );
    }
}
