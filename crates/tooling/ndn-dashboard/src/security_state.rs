//! `SecurityPosture` / `ActiveIdentity` / per-session gate-acceptance memory.
//! `SecurityPosture` is derived from AppCtx signals each render; the
//! `SecurityGate` component consumes the value to decide whether to fire.

#![allow(dead_code)]

use dioxus::prelude::*;

/// Live security posture derived from AppCtx state.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SecurityPosture {
    Hardened,
    /// The forwarder doesn't implement ndn-rs's `security/*` mgmt extensions
    /// (NFD / YaNFD). Gate stays quiet so we don't falsely report `NoIdentity`.
    Unsupported,
    NoIdentity,
    IdentityExpired {
        identity_name: String,
        days_ago: i64,
    },
    /// Anchors / schema rules disappeared since the last session.
    TrustSchemaWeakened {
        anchors_removed: Vec<String>,
        rules_removed: Vec<String>,
    },
    /// A pending schema *tightening* would orphan live certificates — the
    /// dry-run preview of identities that would stop validating if applied.
    /// Fires before the change lands so the operator can apply with a grace
    /// window instead of silently breaking working nodes.
    SchemaTightened {
        orphaned: Vec<String>,
    },
}

impl SecurityPosture {
    /// Per-session gate-acceptance memory keys off this kind, so accepting one
    /// variant doesn't suppress a later re-fire under a different variant.
    pub fn kind(&self) -> PostureKind {
        match self {
            Self::Hardened => PostureKind::Hardened,
            Self::Unsupported => PostureKind::Unsupported,
            Self::NoIdentity => PostureKind::NoIdentity,
            Self::IdentityExpired { .. } => PostureKind::IdentityExpired,
            Self::TrustSchemaWeakened { .. } => PostureKind::TrustSchemaWeakened,
            Self::SchemaTightened { .. } => PostureKind::SchemaTightened,
        }
    }

    pub fn is_hardened(&self) -> bool {
        matches!(self, Self::Hardened)
    }

    /// True for `Hardened` or `Unsupported` — both leave the gate quiet.
    pub fn suppresses_gate(&self) -> bool {
        matches!(self, Self::Hardened | Self::Unsupported)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PostureKind {
    Hardened,
    Unsupported,
    NoIdentity,
    IdentityExpired,
    TrustSchemaWeakened,
    SchemaTightened,
}

impl PostureKind {
    /// Short string code used by the gate-acceptance localStorage
    /// serialization. Stable; do not renumber.
    pub fn as_code(self) -> &'static str {
        match self {
            Self::Hardened => "H",
            Self::Unsupported => "U",
            Self::NoIdentity => "N",
            Self::IdentityExpired => "E",
            Self::TrustSchemaWeakened => "W",
            Self::SchemaTightened => "T",
        }
    }

    pub fn from_code(s: &str) -> Option<Self> {
        Some(match s {
            "H" => Self::Hardened,
            "U" => Self::Unsupported,
            "N" => Self::NoIdentity,
            "E" => Self::IdentityExpired,
            "W" => Self::TrustSchemaWeakened,
            "T" => Self::SchemaTightened,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveIdentity {
    None,
    Ephemeral {
        name: String,
    },
    Persistent {
        name: String,
        /// `u64::MAX` means "permanent" (the FilePib sentinel).
        valid_until_unix_s: u64,
    },
}

impl ActiveIdentity {
    pub fn display_name(&self) -> &str {
        match self {
            Self::None => "(none)",
            Self::Ephemeral { name } | Self::Persistent { name, .. } => name,
        }
    }
}

pub fn derive_posture(input: PostureInput<'_>) -> SecurityPosture {
    // Stay quiet until a probe has actually landed and confirmed the
    // forwarder speaks ndn-rs's `security/*` extensions. `None` = no probe
    // yet (connecting / pre-probe); `Some(false)` = NFD / YaNFD. In neither
    // case is there an ndn-rs identity to reason about, so the gate must not
    // block the operator with a spurious "no persistent identity" modal.
    if input.security_surface_supported != Some(true) {
        return SecurityPosture::Unsupported;
    }
    if input.identity_is_ephemeral || input.identity_name.is_empty() {
        return SecurityPosture::NoIdentity;
    }
    if let Some(expiry_unix_s) = input.cert_valid_until_unix_s
        && let Some(now_unix_s) = input.now_unix_s
        && expiry_unix_s < now_unix_s
    {
        return SecurityPosture::IdentityExpired {
            identity_name: input.identity_name.to_string(),
            days_ago: ((now_unix_s - expiry_unix_s) / 86_400) as i64,
        };
    }
    SecurityPosture::Hardened
}

#[derive(Debug, Clone, Copy)]
pub struct PostureInput<'a> {
    pub identity_name: &'a str,
    pub identity_is_ephemeral: bool,
    pub cert_valid_until_unix_s: Option<u64>,
    /// `None` skips expiry detection.
    pub now_unix_s: Option<u64>,
    /// `Some(true)`: probe returned 2xx. `Some(false)`: 404 (NFD / YaNFD) —
    /// gate stays quiet. `None`: no probe has landed yet.
    pub security_surface_supported: Option<bool>,
}

/// Priority (most-acute first): Expired → UnsignedMgmt → Ephemeral →
/// ExpiringSoon → Hardened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChipState {
    Hardened {
        identity_name: String,
    },
    /// Forwarder doesn't speak ndn-rs's `security/*` extensions.
    Unsupported,
    Ephemeral,
    /// `require_signed_commands == false`; overrides Ephemeral.
    UnsignedMgmt,
    /// `days` in 0..=7.
    ExpiringSoon {
        identity_name: String,
        days: u32,
    },
    Expired {
        identity_name: String,
        days_ago: i64,
    },
}

impl ChipState {
    pub fn label(&self) -> String {
        match self {
            Self::Hardened { identity_name } => identity_name.clone(),
            Self::Unsupported => "NFD COMPAT".into(),
            Self::Ephemeral => "EPHEMERAL".into(),
            Self::UnsignedMgmt => "UNSIGNED MGMT".into(),
            Self::ExpiringSoon { days, .. } => format!("EXPIRES {days}d"),
            Self::Expired { .. } => "EXPIRED".into(),
        }
    }
    pub fn icon(&self) -> &'static str {
        match self {
            Self::Hardened { .. } => "🔐",
            Self::Unsupported => "—",
            Self::Ephemeral => "🔓",
            Self::UnsignedMgmt => "‼",
            Self::ExpiringSoon { .. } => "🔐",
            Self::Expired { .. } => "⏰",
        }
    }
    pub fn css_class(&self) -> &'static str {
        match self {
            Self::Hardened { .. } => "id-chip id-chip-green",
            Self::Unsupported => "id-chip id-chip-gray",
            Self::Ephemeral => "id-chip id-chip-yellow",
            Self::UnsignedMgmt => "id-chip id-chip-red",
            Self::ExpiringSoon { .. } => "id-chip id-chip-amber",
            Self::Expired { .. } => "id-chip id-chip-red",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ChipInput<'a> {
    pub identity_name: &'a str,
    pub identity_is_ephemeral: bool,
    pub cert_valid_until_unix_s: Option<u64>,
    pub now_unix_s: Option<u64>,
    /// `None` ⇒ no `policy-get` poll has landed; doesn't contribute to chip state.
    pub mgmt_signed_commands_required: Option<bool>,
    /// `Some(false)` renders `Unsupported` instead of falling back to `Ephemeral`.
    pub security_surface_supported: Option<bool>,
}

const EXPIRING_SOON_DAYS: u64 = 7;

pub fn derive_chip_state(input: ChipInput<'_>) -> ChipState {
    // Must precede Expired / UnsignedMgmt / Ephemeral so a missing cert-expiry
    // signal doesn't falsely escalate against a non-ndn-rs forwarder.
    if input.security_surface_supported == Some(false) {
        return ChipState::Unsupported;
    }
    if let Some(expiry) = input.cert_valid_until_unix_s
        && let Some(now) = input.now_unix_s
        && expiry < now
    {
        return ChipState::Expired {
            identity_name: input.identity_name.to_string(),
            days_ago: ((now - expiry) / 86_400) as i64,
        };
    }
    if input.mgmt_signed_commands_required == Some(false) {
        return ChipState::UnsignedMgmt;
    }
    if input.identity_is_ephemeral || input.identity_name.is_empty() {
        return ChipState::Ephemeral;
    }
    if let Some(expiry) = input.cert_valid_until_unix_s
        && let Some(now) = input.now_unix_s
        && expiry >= now
    {
        let remaining = expiry - now;
        let days = (remaining / 86_400) as u32;
        if days <= EXPIRING_SOON_DAYS as u32 {
            return ChipState::ExpiringSoon {
                identity_name: input.identity_name.to_string(),
                days,
            };
        }
    }
    ChipState::Hardened {
        identity_name: input.identity_name.to_string(),
    }
}

/// Sidebar `sec_dot` rendering — glyph + colour-class + tooltip per
/// the §3.2 state table. Derived from [`ChipState`] so the chip and
/// the dot stay coupled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecDotView {
    pub glyph: &'static str,
    pub css_class: &'static str,
    pub tooltip: String,
}

pub fn derive_sec_dot(state: &ChipState) -> SecDotView {
    match state {
        ChipState::Hardened { .. } => SecDotView {
            glyph: "🔒",
            css_class: "sec-dot sec-dot-green",
            tooltip: "Trust posture: hardened".into(),
        },
        ChipState::Unsupported => SecDotView {
            glyph: "—",
            css_class: "sec-dot sec-dot-gray",
            tooltip: "Forwarder doesn't implement ndn-rs security/* mgmt extensions \
                      (NFD / YaNFD); security surfaces unavailable"
                .into(),
        },
        ChipState::UnsignedMgmt => SecDotView {
            glyph: "🔓",
            css_class: "sec-dot sec-dot-red",
            tooltip: "Mgmt unsigned — anyone on socket can issue commands".into(),
        },
        ChipState::Ephemeral => SecDotView {
            glyph: "⚠",
            css_class: "sec-dot sec-dot-yellow",
            tooltip: "Ephemeral mode — research only".into(),
        },
        ChipState::Expired { days_ago, .. } => SecDotView {
            glyph: "⏰",
            css_class: "sec-dot sec-dot-red",
            tooltip: format!("Cert expired {days_ago} days ago"),
        },
        ChipState::ExpiringSoon { days, .. } => SecDotView {
            glyph: "🔐",
            css_class: "sec-dot sec-dot-amber",
            tooltip: format!("Cert expires in {days} days"),
        },
    }
}

/// Last posture the user accepted, keyed by `(forwarder_id, kind)`.
/// Accepting on forwarder A does not suppress the gate on forwarder B.
///
/// Persistence: written through to localStorage on wasm
/// (key `"ndn-dashboard.gate-accepted"`) so the gate doesn't re-show
/// on every page reload. On desktop, session-scoped is fine — the
/// process lifetime is the natural acceptance window. `reset_acceptance()`
/// (called on Connect / Reconnect) clears both layers.
pub static GATE_ACCEPTED: GlobalSignal<Option<(String, PostureKind)>> =
    Signal::global(load_gate_accepted_from_storage);

#[cfg(target_arch = "wasm32")]
const GATE_ACCEPTED_LS_KEY: &str = "ndn-dashboard.gate-accepted";

#[cfg(not(target_arch = "wasm32"))]
fn load_gate_accepted_from_storage() -> Option<(String, PostureKind)> {
    None
}

#[cfg(target_arch = "wasm32")]
fn load_gate_accepted_from_storage() -> Option<(String, PostureKind)> {
    let raw = web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|ls| ls.get_item(GATE_ACCEPTED_LS_KEY).ok().flatten())?;
    // Format: `<forwarder_id>\n<posture_kind_code>` — newline is
    // forbidden in forwarder ids so this is unambiguous.
    let (fid, code) = raw.split_once('\n')?;
    let kind = PostureKind::from_code(code)?;
    Some((fid.to_owned(), kind))
}

#[cfg(target_arch = "wasm32")]
fn save_gate_accepted_to_storage(value: &Option<(String, PostureKind)>) {
    let Some(ls) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) else {
        return;
    };
    match value {
        Some((fid, kind)) => {
            let _ = ls.set_item(GATE_ACCEPTED_LS_KEY, &format!("{fid}\n{}", kind.as_code()));
        }
        None => {
            let _ = ls.remove_item(GATE_ACCEPTED_LS_KEY);
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn save_gate_accepted_to_storage(_value: &Option<(String, PostureKind)>) {}

pub fn gate_should_fire(
    current: &SecurityPosture,
    accepted: Option<&(String, PostureKind)>,
    forwarder_id: &str,
) -> bool {
    if current.suppresses_gate() {
        return false;
    }
    !matches!(
        accepted,
        Some((fid, kind)) if fid == forwarder_id && *kind == current.kind()
    )
}

pub fn accept(forwarder_id: impl Into<String>, kind: PostureKind) {
    let value = Some((forwarder_id.into(), kind));
    save_gate_accepted_to_storage(&value);
    *GATE_ACCEPTED.write() = value;
}

/// Call on Connect / Reconnect so a fresh connection re-fires the gate.
pub fn reset_acceptance() {
    save_gate_accepted_to_storage(&None);
    *GATE_ACCEPTED.write() = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(name: &str, ephemeral: bool) -> PostureInput<'_> {
        PostureInput {
            identity_name: name,
            identity_is_ephemeral: ephemeral,
            cert_valid_until_unix_s: None,
            now_unix_s: None,
            security_surface_supported: Some(true),
        }
    }

    #[test]
    fn no_identity_when_ephemeral_or_empty() {
        assert!(matches!(
            derive_posture(input("/lab/alice", true)),
            SecurityPosture::NoIdentity
        ));
        assert!(matches!(
            derive_posture(input("", false)),
            SecurityPosture::NoIdentity
        ));
    }

    #[test]
    fn hardened_when_persistent_no_expiry_data() {
        assert!(derive_posture(input("/lab/alice", false)).is_hardened());
    }

    #[test]
    fn gate_quiet_until_security_probe_lands() {
        // No probe has landed yet (disconnected / connecting): an empty
        // identity must NOT escalate to `NoIdentity`, or the gate would
        // block the operator before we have even reached a forwarder.
        let posture = derive_posture(PostureInput {
            identity_name: "",
            identity_is_ephemeral: true,
            cert_valid_until_unix_s: None,
            now_unix_s: None,
            security_surface_supported: None,
        });
        assert_eq!(posture, SecurityPosture::Unsupported);
        assert!(!gate_should_fire(&posture, None, "ndn-fwd"));
    }

    #[test]
    fn identity_expired_when_cert_past_due() {
        let p = derive_posture(PostureInput {
            identity_name: "/lab/alice",
            identity_is_ephemeral: false,
            cert_valid_until_unix_s: Some(1_700_000_000),
            now_unix_s: Some(1_700_000_000 + 5 * 86_400),
            security_surface_supported: Some(true),
        });
        match p {
            SecurityPosture::IdentityExpired { days_ago, .. } => assert_eq!(days_ago, 5),
            other => panic!("expected IdentityExpired, got {other:?}"),
        }
    }

    fn chip_input(name: &str, ephemeral: bool, signed: Option<bool>) -> ChipInput<'_> {
        ChipInput {
            identity_name: name,
            identity_is_ephemeral: ephemeral,
            cert_valid_until_unix_s: None,
            now_unix_s: None,
            mgmt_signed_commands_required: signed,
            security_surface_supported: Some(true),
        }
    }

    #[test]
    fn chip_state_priority_expired_beats_unsigned() {
        let state = derive_chip_state(ChipInput {
            identity_name: "/lab/alice",
            identity_is_ephemeral: false,
            cert_valid_until_unix_s: Some(1_700_000_000),
            now_unix_s: Some(1_700_000_000 + 3 * 86_400),
            mgmt_signed_commands_required: Some(false),
            security_surface_supported: Some(true),
        });
        assert!(matches!(state, ChipState::Expired { days_ago: 3, .. }));
    }

    #[test]
    fn chip_state_unsigned_beats_ephemeral() {
        let state = derive_chip_state(chip_input("/lab/alice", true, Some(false)));
        assert_eq!(state, ChipState::UnsignedMgmt);
    }

    #[test]
    fn chip_state_ephemeral_when_ephemeral_signed_unknown() {
        let state = derive_chip_state(chip_input("/lab/alice", true, None));
        assert_eq!(state, ChipState::Ephemeral);
    }

    #[test]
    fn chip_state_hardened_when_persistent_no_expiry() {
        let state = derive_chip_state(chip_input("/lab/alice", false, Some(true)));
        assert!(matches!(state, ChipState::Hardened { .. }));
    }

    #[test]
    fn chip_state_expiring_soon_window() {
        let state = derive_chip_state(ChipInput {
            identity_name: "/lab/alice",
            identity_is_ephemeral: false,
            cert_valid_until_unix_s: Some(1_700_000_000 + 3 * 86_400),
            now_unix_s: Some(1_700_000_000),
            mgmt_signed_commands_required: Some(true),
            security_surface_supported: Some(true),
        });
        assert!(matches!(state, ChipState::ExpiringSoon { days: 3, .. }));
    }

    #[test]
    fn chip_state_hardened_when_cert_far_off() {
        let state = derive_chip_state(ChipInput {
            identity_name: "/lab/alice",
            identity_is_ephemeral: false,
            cert_valid_until_unix_s: Some(1_700_000_000 + 90 * 86_400),
            now_unix_s: Some(1_700_000_000),
            mgmt_signed_commands_required: Some(true),
            security_surface_supported: Some(true),
        });
        assert!(matches!(state, ChipState::Hardened { .. }));
    }

    #[test]
    fn sec_dot_renders_for_every_chip_state() {
        let states = [
            ChipState::Hardened {
                identity_name: "/lab/alice".into(),
            },
            ChipState::Unsupported,
            ChipState::Ephemeral,
            ChipState::UnsignedMgmt,
            ChipState::ExpiringSoon {
                identity_name: "/lab/alice".into(),
                days: 3,
            },
            ChipState::Expired {
                identity_name: "/lab/alice".into(),
                days_ago: 5,
            },
        ];
        for s in &states {
            let dot = derive_sec_dot(s);
            assert!(!dot.tooltip.is_empty(), "tooltip empty for {s:?}");
            assert!(dot.css_class.starts_with("sec-dot"));
        }
    }

    #[test]
    fn unsupported_when_forwarder_lacks_security_verbs() {
        let chip = derive_chip_state(ChipInput {
            identity_name: "",
            identity_is_ephemeral: false,
            cert_valid_until_unix_s: None,
            now_unix_s: None,
            mgmt_signed_commands_required: None,
            security_surface_supported: Some(false),
        });
        assert_eq!(
            chip,
            ChipState::Unsupported,
            "chip must render Unsupported, not Ephemeral, against NFD/YaNFD"
        );

        let posture = derive_posture(PostureInput {
            identity_name: "",
            identity_is_ephemeral: false,
            cert_valid_until_unix_s: None,
            now_unix_s: None,
            security_surface_supported: Some(false),
        });
        assert_eq!(posture, SecurityPosture::Unsupported);
        assert!(
            !gate_should_fire(&posture, None, "nfd"),
            "gate must stay quiet against forwarders that don't speak our extensions"
        );
    }

    #[test]
    fn gate_fires_on_any_unaccepted_non_hardened() {
        let fwd_a = "ndn-fwd".to_owned();
        assert!(!gate_should_fire(&SecurityPosture::Hardened, None, &fwd_a));
        assert!(gate_should_fire(&SecurityPosture::NoIdentity, None, &fwd_a));
        let accepted_no_id_a = (fwd_a.clone(), PostureKind::NoIdentity);
        assert!(!gate_should_fire(
            &SecurityPosture::NoIdentity,
            Some(&accepted_no_id_a),
            &fwd_a
        ));
        let accepted_expired_a = (fwd_a.clone(), PostureKind::IdentityExpired);
        assert!(gate_should_fire(
            &SecurityPosture::NoIdentity,
            Some(&accepted_expired_a),
            &fwd_a
        ));
    }

    #[test]
    fn gate_acceptance_is_per_forwarder() {
        let fwd_a = "ndn-fwd".to_owned();
        let fwd_b = "nfd".to_owned();
        let accepted_on_a = (fwd_a, PostureKind::NoIdentity);
        assert!(gate_should_fire(
            &SecurityPosture::NoIdentity,
            Some(&accepted_on_a),
            &fwd_b
        ));
    }
}
