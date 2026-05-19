//! §6 state model — `SecurityPosture` / `ActiveIdentity` / per-session
//! gate-acceptance memory.
//!
//! See `docs/notes/dashboard-security-design-2026-05-13.md` §6 and §2.
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
            Self::NoIdentity => PostureKind::NoIdentity,
            Self::IdentityExpired { .. } => PostureKind::IdentityExpired,
            Self::TrustSchemaWeakened { .. } => PostureKind::TrustSchemaWeakened,
        }
    }

    pub fn is_hardened(&self) -> bool {
        matches!(self, Self::Hardened)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PostureKind {
    Hardened,
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

/// The last posture kind the user accepted in the current session.
/// `None` ⇒ no posture accepted yet (gate fires on any non-Hardened).
pub static GATE_ACCEPTED: GlobalSignal<Option<PostureKind>> = Signal::global(|| None);

/// Returns true if the gate should fire for `current`. The user has
/// already accepted a posture iff it matches the current one.
pub fn gate_should_fire(current: &SecurityPosture, accepted: Option<PostureKind>) -> bool {
    if current.is_hardened() {
        return false;
    }
    Some(current.kind()) != accepted
}

/// Mark `kind` as accepted for the rest of this session. The gate
/// resets on reconnect (call [`reset_acceptance`] from the connect
/// coroutine).
pub fn accept(kind: PostureKind) {
    *GATE_ACCEPTED.write() = Some(kind);
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
        });
        match p {
            SecurityPosture::IdentityExpired { days_ago, .. } => assert_eq!(days_ago, 5),
            other => panic!("expected IdentityExpired, got {other:?}"),
        }
    }

    #[test]
    fn gate_fires_on_any_unaccepted_non_hardened() {
        assert!(!gate_should_fire(&SecurityPosture::Hardened, None));
        assert!(gate_should_fire(&SecurityPosture::NoIdentity, None));
        assert!(!gate_should_fire(
            &SecurityPosture::NoIdentity,
            Some(PostureKind::NoIdentity)
        ));
        assert!(gate_should_fire(
            &SecurityPosture::NoIdentity,
            Some(PostureKind::IdentityExpired)
        ));
    }
}
