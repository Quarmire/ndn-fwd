//! Reusable identity/context view-model — the dashboard's single source of
//! "which identities can I act as, and which am I acting as right now?".
//!
//! This is the "Acting as" axis of the two-axis Attach bar (synthesis note §8:
//! engine and identity are independent axes). It is deliberately
//! target-agnostic and dependency-free — pure data + logic over plain
//! `&str`/`bool` — so the Attach bar, the Identity nav bucket, the future
//! browser extension, and mobile all bind to one identity surface, and the
//! native vs. wasm builds share it verbatim.
//!
//! Today the axis is derived from the forwarder-reported active identity
//! ([`from_active`]). It is shaped to swap to the landed `ndn-identity`
//! `TrustContext` keyring (a richer `available` list, anchor fingerprints,
//! custodian/capability metadata) without changing a single call site — see
//! [`IdentityAxis`] and the TODO in [`IdentityRef`].

/// One identity the operator could act as.
///
/// Today this carries a PIB identity name and whether it is ephemeral. It is
/// the seam that grows into a `TrustContext` reference (anchor fingerprint,
/// custodian, capability set) — consumers that render an `IdentityRef` will
/// keep working as those fields are added.
//
// TODO(trust-context): add `anchor_fingerprint`, `custodian`, `capabilities`
// when binding to ndn-identity::TrustContext. Labels are navigation;
// fingerprints are the trust property (note §7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityRef {
    /// Navigation/display name, e.g. `/home/bob`. NOT a trust property.
    pub name: String,
    /// True for an unenrolled / self-signed / ephemeral identity (no CA-issued
    /// cert backing it). Drives the "ephemeral" styling on the chip.
    pub ephemeral: bool,
}

/// The "Acting as" axis: the active identity and every identity selectable on
/// this surface.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentityAxis {
    /// The identity currently signing on this surface, if any.
    pub active: Option<IdentityRef>,
    /// All identities the operator could switch to (includes `active`).
    pub available: Vec<IdentityRef>,
}

impl IdentityAxis {
    /// Single-context default (note §8 light-touch): zero or one selectable
    /// identity means the axis renders as a static chip, not a switchable
    /// dropdown. The two axes "auto-pair" and the bar looks single-axis until
    /// a second context is added.
    pub fn is_single(&self) -> bool {
        self.available.len() <= 1
    }

    /// Build the axis from the forwarder-reported active identity — today's
    /// model. An empty/whitespace name means "no identity" (unattached or a
    /// forwarder with no security surface), yielding an empty axis.
    ///
    /// When the `ndn-identity` keyring lands, add a `from_keyring(&TrustContext
    /// keyring)` constructor alongside this one; every consumer stays the same.
    pub fn from_active(active_name: &str, ephemeral: bool) -> Self {
        let trimmed = active_name.trim();
        if trimmed.is_empty() {
            return Self::default();
        }
        let id = IdentityRef {
            name: trimmed.to_string(),
            ephemeral,
        };
        Self {
            active: Some(id.clone()),
            available: vec![id],
        }
    }
}

/// What the acting-as identity can do against the attached engine's management
/// surface. Reads are always public (NFD serves `*/list` etc. unsigned); this
/// is a *prediction* of whether mutations will be accepted, from the engine's
/// auth policy plus the active identity. The engine still validates every
/// command — this only tells the operator what to expect up front instead of
/// discovering a denial by trying.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteCapability {
    /// Engine auth policy not yet known.
    Unknown,
    /// Engine accepts unsigned commands — anyone connected can mutate.
    Open,
    /// The active identity should be accepted for changes.
    ReadWrite,
    /// Mutations will be refused — no usable signing identity for this engine.
    ReadOnly,
}

impl WriteCapability {
    pub fn label(self) -> &'static str {
        match self {
            WriteCapability::Unknown => "Capability unknown",
            WriteCapability::Open => "Read-write (open)",
            WriteCapability::ReadWrite => "Read-write",
            WriteCapability::ReadOnly => "Read-only",
        }
    }

    /// Carbon badge class — green when you can change things, yellow when an
    /// open engine accepts unsigned writes (a posture worth noticing), gray
    /// for read-only/unknown.
    pub fn badge_class(self) -> &'static str {
        match self {
            WriteCapability::ReadWrite => "badge badge-green",
            WriteCapability::Open => "badge badge-yellow",
            WriteCapability::ReadOnly | WriteCapability::Unknown => "badge badge-gray",
        }
    }

    pub fn tooltip(self) -> &'static str {
        match self {
            WriteCapability::Unknown => "The engine's management auth policy hasn't been read yet.",
            WriteCapability::Open => {
                "This engine accepts unsigned management commands — any connected client can make changes. Enable signed commands in Mgmt Access to lock it down."
            }
            WriteCapability::ReadWrite => {
                "The identity you're acting as should be accepted for changes. The engine still validates each command."
            }
            WriteCapability::ReadOnly => {
                "This engine requires signed commands and the identity you're acting as won't be accepted (none / expired / ephemeral). You can observe but not change anything."
            }
        }
    }

    pub fn is_read_only(self) -> bool {
        matches!(self, WriteCapability::ReadOnly)
    }
}

/// Predict the write capability from polled state. `cert_expired` is the
/// caller's verdict on the active cert (absent-or-past-validity); kept out of
/// here so the function stays pure/testable.
pub fn write_capability(
    require_signed: Option<bool>,
    ephemeral_allowed: bool,
    has_identity: bool,
    identity_ephemeral: bool,
    cert_expired: bool,
) -> WriteCapability {
    match require_signed {
        None => WriteCapability::Unknown,
        Some(false) => WriteCapability::Open,
        Some(true) => {
            // Mutations need a usable signer: a present, non-expired identity,
            // and not an ephemeral one when the engine forbids ephemeral signers.
            let refused =
                !has_identity || (identity_ephemeral && !ephemeral_allowed) || cert_expired;
            if refused {
                WriteCapability::ReadOnly
            } else {
                WriteCapability::ReadWrite
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_open_when_unsigned_accepted() {
        assert_eq!(
            write_capability(Some(false), false, false, false, false),
            WriteCapability::Open
        );
    }

    #[test]
    fn capability_unknown_until_policy_known() {
        assert_eq!(
            write_capability(None, false, true, false, false),
            WriteCapability::Unknown
        );
    }

    #[test]
    fn capability_read_write_with_valid_identity() {
        assert_eq!(
            write_capability(Some(true), false, true, false, false),
            WriteCapability::ReadWrite
        );
    }

    #[test]
    fn capability_read_only_cases() {
        // no identity
        assert_eq!(
            write_capability(Some(true), true, false, false, false),
            WriteCapability::ReadOnly
        );
        // ephemeral when the engine forbids ephemeral signers
        assert_eq!(
            write_capability(Some(true), false, true, true, false),
            WriteCapability::ReadOnly
        );
        // expired cert
        assert_eq!(
            write_capability(Some(true), false, true, false, true),
            WriteCapability::ReadOnly
        );
        // ephemeral is fine when the engine allows it
        assert_eq!(
            write_capability(Some(true), true, true, true, false),
            WriteCapability::ReadWrite
        );
    }

    #[test]
    fn empty_name_is_unattached() {
        let axis = IdentityAxis::from_active("   ", false);
        assert!(axis.active.is_none());
        assert!(axis.available.is_empty());
        assert!(axis.is_single(), "no identities is still single-axis");
    }

    #[test]
    fn single_identity_is_single_axis() {
        let axis = IdentityAxis::from_active("/home/bob", false);
        assert!(axis.is_single());
        assert_eq!(axis.available.len(), 1);
        assert_eq!(axis.active.as_ref().unwrap().name, "/home/bob");
    }

    #[test]
    fn name_is_trimmed() {
        let axis = IdentityAxis::from_active("  /work/acme \n", true);
        let active = axis.active.expect("has active");
        assert_eq!(active.name, "/work/acme");
        assert!(active.ephemeral);
    }

    /// Multi-context is not switchable yet, but the model already represents it
    /// — the dropdown branch in the UI keys off `is_single()`.
    #[test]
    fn multi_identity_is_not_single() {
        let axis = IdentityAxis {
            active: Some(IdentityRef {
                name: "/home/bob".into(),
                ephemeral: false,
            }),
            available: vec![
                IdentityRef {
                    name: "/home/bob".into(),
                    ephemeral: false,
                },
                IdentityRef {
                    name: "/work/acme".into(),
                    ephemeral: false,
                },
            ],
        };
        assert!(!axis.is_single());
    }
}
