//! §6 state model — `SecurityPosture` / `ActiveIdentity` / per-session
//! gate-acceptance memory.
//!
//! See (internal) §6 and §2.
//! The dashboard derives `SecurityPosture` from the AppCtx signals on
//! every render; the gate (`crate::security_gate::SecurityGate`)
//! consumes the derived value to decide whether to fire.
//!
//! v1 detection coverage:
//! - **`NoIdentity`** — wired today from `identity_is_ephemeral` /
//!   `identity_name`. Fires the gate on first connect or after a
//!   forwarder restart into ephemeral mode.
//! - **`IdentityExpired`** — schema variant + render path land today;
//!   detection is stubbed pending cert-expiry data threading into the
//!   AppCtx. The §4.1 cert inspector will populate this when it lands
//!   (Phase B).
//! - **`TrustSchemaWeakened`** — same: schema variant + render land
//!   today; detection wires when the dashboard's
//!   `SchemaJournalChain` (per `crate::security_chains`) has a prior
//!   snapshot to diff against.

#![allow(dead_code)] // v1 lands ahead of the §4.1 / journal wiring

use dioxus::prelude::*;

/// Live security posture derived from the AppCtx state. The gate uses
/// the variants below to choose which §2 panel to render.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SecurityPosture {
    /// All checks pass. Gate does not fire.
    Hardened,
    /// The connected forwarder does not implement ndn-rs's `security/*`
    /// mgmt extensions (e.g. an NFD or YaNFD forwarder). The dashboard
    /// can't assess identity / anchors / schema posture against this
    /// forwarder, so it MUST NOT default to `NoIdentity` (which would
    /// spuriously fire the gate). Gate stays quiet; chip renders the
    /// `Unsupported` state explicitly. Detection: an explicit
    /// NOT_FOUND from a probe verb like `security/identity-status`.
    Unsupported,
    /// No persistent identity, signing falls back to an ephemeral
    /// in-memory key. §2.2 panel.
    NoIdentity,
    /// Active cert past its `valid_until`. §2.3 panel.
    IdentityExpired {
        identity_name: String,
        days_ago: i64,
    },
    /// Anchors / schema rules disappeared since the last session.
    /// §2.4 panel.
    TrustSchemaWeakened {
        anchors_removed: Vec<String>,
        rules_removed: Vec<String>,
    },
}

impl SecurityPosture {
    /// Variant discriminant for per-session gate-acceptance memory
    /// (the user accepting one variant doesn't suppress a later
    /// re-fire under a different variant).
    pub fn kind(&self) -> PostureKind {
        match self {
            Self::Hardened => PostureKind::Hardened,
            Self::Unsupported => PostureKind::Unsupported,
            Self::NoIdentity => PostureKind::NoIdentity,
            Self::IdentityExpired { .. } => PostureKind::IdentityExpired,
            Self::TrustSchemaWeakened { .. } => PostureKind::TrustSchemaWeakened,
        }
    }

    pub fn is_hardened(&self) -> bool {
        matches!(self, Self::Hardened)
    }

    /// Like `is_hardened` but also returns true for `Unsupported` —
    /// both states leave the gate quiet because the dashboard can't
    /// claim a posture violation against either.
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
}

/// The dashboard's understanding of the current signing identity.
/// Drives the §3.1 IdentityChip (lands later) and the gate's
/// `IdentityExpired` panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveIdentity {
    None,
    Ephemeral {
        name: String,
    },
    Persistent {
        name: String,
        /// Cert valid_until in Unix-epoch seconds. `u64::MAX` means
        /// "permanent" (the FilePib sentinel).
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

/// Derive the current `SecurityPosture` from AppCtx signals. Pure
/// function — easy to unit-test.
///
/// Inputs match the names of the AppCtx fields that source them today;
/// when the §4.1 cert inspector lands and threads expiry into AppCtx,
/// pass the new field here.
pub fn derive_posture(input: PostureInput<'_>) -> SecurityPosture {
    // Forwarder doesn't speak ndn-rs's security extensions (likely
    // NFD or YaNFD). All other axes are unobservable; the gate must
    // stay quiet — otherwise we'd spuriously assert NoIdentity.
    if input.security_surface_supported == Some(false) {
        return SecurityPosture::Unsupported;
    }
    // NoIdentity — the most-common first-run case.
    if input.identity_is_ephemeral || input.identity_name.is_empty() {
        return SecurityPosture::NoIdentity;
    }
    // IdentityExpired — needs cert valid_until. v1 stub: when no
    // expiry data is threaded through, assume Hardened. The schema
    // is here so Phase B can wire it without a struct bump.
    if let Some(expiry_unix_s) = input.cert_valid_until_unix_s
        && let Some(now_unix_s) = input.now_unix_s
        && expiry_unix_s < now_unix_s
    {
        return SecurityPosture::IdentityExpired {
            identity_name: input.identity_name.to_string(),
            days_ago: ((now_unix_s - expiry_unix_s) / 86_400) as i64,
        };
    }
    // TrustSchemaWeakened — needs a snapshot of the prior session's
    // anchor / schema set to diff. Wires in when SchemaJournalChain
    // is populated; for v1 we treat the current state as hardened.
    SecurityPosture::Hardened
}

/// Inputs to [`derive_posture`]. Borrowed view so the caller can pass
/// signal reads without cloning.
#[derive(Debug, Clone, Copy)]
pub struct PostureInput<'a> {
    pub identity_name: &'a str,
    pub identity_is_ephemeral: bool,
    /// Active cert's valid_until in Unix-epoch seconds. `None` while
    /// the cert inspector hasn't published one (v1 default).
    pub cert_valid_until_unix_s: Option<u64>,
    /// Current wall-clock time (Unix-epoch seconds). `None` ⇒ skip
    /// expiry detection.
    pub now_unix_s: Option<u64>,
    /// Whether the connected forwarder implements ndn-rs's
    /// `security/*` mgmt extensions. `Some(true)` ⇒ supported (a
    /// security probe returned 2xx); `Some(false)` ⇒ NOT supported
    /// (the probe returned 404); `None` ⇒ unknown yet (no probe has
    /// landed). When `Some(false)` the gate stays quiet — the
    /// dashboard can't observe any of the other axes against that
    /// forwarder.
    pub security_surface_supported: Option<bool>,
}

// ── §3 surfaces — chip + sidebar dot ────────────────────────────────
//
// The §3.1 IdentityChip and the §3.2 sec_dot are always-rendered
// reflections of the operator's current trust posture. Both derive
// from `derive_chip_state` so the chip's label and the dot's tooltip
// can't drift from each other.

/// Discrete state the chip renders. Priority when multiple apply
/// (most-acute first): Expired → UnsignedMgmt → Ephemeral →
/// ExpiringSoon → Hardened. The §3.1 design table lists these
/// explicitly; this enum is that list compiled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChipState {
    /// Persistent identity + valid cert + signed mgmt. Green padlock.
    Hardened { identity_name: String },
    /// The forwarder doesn't speak ndn-rs's `security/*` extensions
    /// — chip renders explicitly so the operator knows the security
    /// surfaces aren't applicable. Gray, distinct from Ephemeral.
    Unsupported,
    /// Ephemeral in-memory identity. Yellow open padlock.
    Ephemeral,
    /// `require_signed_commands == false` — anyone with socket
    /// access can issue mgmt. Red. Overrides Ephemeral so the
    /// operator sees the worse state.
    UnsignedMgmt,
    /// Active cert expires within `days` (0..=7). Amber padlock.
    ExpiringSoon { identity_name: String, days: u32 },
    /// Active cert past its `valid_until`. Red exclamation.
    Expired {
        identity_name: String,
        days_ago: i64,
    },
}

impl ChipState {
    /// Short label rendered next to the icon.
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
    /// Unicode icon prefix.
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
    /// CSS class for the chip background (uses existing palette
    /// variables via `var(--green)` etc. defined in `styles.rs`).
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

/// Inputs to [`derive_chip_state`]. Same shape as [`PostureInput`]
/// extended with the live mgmt-policy view.
#[derive(Debug, Clone, Copy)]
pub struct ChipInput<'a> {
    pub identity_name: &'a str,
    pub identity_is_ephemeral: bool,
    pub cert_valid_until_unix_s: Option<u64>,
    pub now_unix_s: Option<u64>,
    /// `Some(false)` means the forwarder's mgmt-access policy is
    /// explicitly unsigned (UnsignedMgmt state); `Some(true)` is
    /// signed; `None` means we don't know yet (no policy-get poll
    /// landed). When unknown, this dimension contributes nothing to
    /// the chip state — Ephemeral / Hardened are reported as-is.
    pub mgmt_signed_commands_required: Option<bool>,
    /// Same shape as [`PostureInput::security_surface_supported`]. When
    /// `Some(false)` the chip renders `Unsupported` instead of falling
    /// back to `Ephemeral` (which would lie about the forwarder).
    pub security_surface_supported: Option<bool>,
}

const EXPIRING_SOON_DAYS: u64 = 7;

/// Compute the chip state from the live AppCtx-shaped view. Pure
/// function — unit-tested below.
pub fn derive_chip_state(input: ChipInput<'_>) -> ChipState {
    // Forwarder doesn't support the security verbs — render
    // `Unsupported` so we don't lie about identity/cert state.
    // This must precede Expired / UnsignedMgmt / Ephemeral so a
    // missing cert-expiry signal doesn't falsely escalate.
    if input.security_surface_supported == Some(false) {
        return ChipState::Unsupported;
    }
    // Expired wins over everything — the cert is already invalid.
    if let Some(expiry) = input.cert_valid_until_unix_s
        && let Some(now) = input.now_unix_s
        && expiry < now
    {
        return ChipState::Expired {
            identity_name: input.identity_name.to_string(),
            days_ago: ((now - expiry) / 86_400) as i64,
        };
    }
    // UnsignedMgmt next — explicit policy says any localhost client
    // can issue mgmt commands. Render red even when a persistent
    // identity exists per §3.1.
    if input.mgmt_signed_commands_required == Some(false) {
        return ChipState::UnsignedMgmt;
    }
    // Ephemeral — in-memory key, no persistence.
    if input.identity_is_ephemeral || input.identity_name.is_empty() {
        return ChipState::Ephemeral;
    }
    // ExpiringSoon — persistent identity, valid cert that expires
    // within EXPIRING_SOON_DAYS.
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

// ── Per-session gate-acceptance memory ───────────────────────────────
//
// §6 transition rules: "Accepted this session" is a Signal<bool> keyed
// by (forwarder identity, posture). New connection = new session.
//
// v1 keys by posture kind only — the dashboard's forwarder-identity
// signal isn't stable yet across reconnects. This is a small loss
// (accepting NoIdentity on forwarder A also suppresses the gate on
// forwarder B until reset) and an honest one; flagged as a Phase B
// fix-up so we don't bake forwarder-identity sourcing into the gate
// shape today.

/// The last posture the user accepted in the current session, keyed
/// by `(forwarder_id, kind)`. Accepting `NoIdentity` on forwarder A
/// does NOT suppress the gate on forwarder B — flipping the
/// `--forwarder=` flag re-fires the gate against the new connection.
/// `None` ⇒ no posture accepted yet (gate fires on any non-Hardened).
pub static GATE_ACCEPTED: GlobalSignal<Option<(String, PostureKind)>> = Signal::global(|| None);

/// Returns true if the gate should fire for `current` against
/// `forwarder_id`. The user has already accepted iff the stored
/// `(forwarder_id, kind)` matches both axes.
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

/// Mark `(forwarder_id, kind)` as accepted for the rest of this
/// session. The gate resets on reconnect (call [`reset_acceptance`]
/// from the connect coroutine).
pub fn accept(forwarder_id: impl Into<String>, kind: PostureKind) {
    *GATE_ACCEPTED.write() = Some((forwarder_id.into(), kind));
}

/// Reset acceptance — call this on Connect / Reconnect so a fresh
/// connection re-fires the gate even if the user "skipped" last time.
pub fn reset_acceptance() {
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

    /// Witness: against a forwarder that DOESN'T speak ndn-rs's
    /// `security/*` extensions (e.g. NFD / YaNFD), the chip MUST NOT
    /// fall through to `Ephemeral` / the gate MUST NOT report
    /// `NoIdentity`. Before the cross-forwarder fix landed, both
    /// signals had no surface_supported axis and produced
    /// `Ephemeral` + `NoIdentity` against an empty identity_name —
    /// silently lying about the forwarder.
    #[test]
    fn unsupported_when_forwarder_lacks_security_verbs() {
        // identity_name="" (the dashboard never populated it because
        // /security/identity-status returned NOT_FOUND), no other
        // signals available, security_surface_supported=Some(false).
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

    /// Acceptance on one forwarder MUST NOT suppress the gate on
    /// another. Phase B carry-forward fix from the kickoff §"Open
    /// follow-ups Phase A surfaced".
    #[test]
    fn gate_acceptance_is_per_forwarder() {
        let fwd_a = "ndn-fwd".to_owned();
        let fwd_b = "nfd".to_owned();
        let accepted_on_a = (fwd_a, PostureKind::NoIdentity);
        // Same posture kind, different forwarder → gate still fires.
        assert!(gate_should_fire(
            &SecurityPosture::NoIdentity,
            Some(&accepted_on_a),
            &fwd_b
        ));
    }
}
