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

#[cfg(test)]
mod tests {
    use super::*;

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
