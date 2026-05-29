//! Advanced ndn-rs extension registry view models.

use crate::core::{FeatureState, ForwarderKind, ForwarderProfile};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodingPolicySurface {
    pub prefix: String,
    pub role: &'static str,
    pub generation: &'static str,
    pub state: FeatureState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateLimitCellSurface {
    pub scope: String,
    pub limit: &'static str,
    pub state: FeatureState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputeServiceSurface {
    pub service: String,
    pub status: FeatureState,
    pub diagnostics: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionSurface {
    pub id: &'static str,
    pub title: &'static str,
    pub capability: FeatureState,
    pub docs: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionRegistry {
    pub coding: Vec<CodingPolicySurface>,
    pub rate_limits: Vec<RateLimitCellSurface>,
    pub compute: Vec<ComputeServiceSurface>,
    pub surfaces: Vec<ExtensionSurface>,
}

impl ExtensionRegistry {
    pub fn for_profile(profile: &ForwarderProfile) -> Self {
        let native = profile.kind == ForwarderKind::NdnRs;
        let native_state = if native {
            FeatureState::Enabled
        } else {
            FeatureState::Unsupported
        };
        let compat_state = if native {
            FeatureState::Enabled
        } else {
            FeatureState::ReadOnly
        };

        Self {
            coding: vec![CodingPolicySurface {
                prefix: "/ndn/edge/video".into(),
                role: "producer",
                generation: "k=8 n=12",
                state: native_state,
            }],
            rate_limits: vec![
                RateLimitCellSurface {
                    scope: "mgmt commands".into(),
                    limit: "120/min",
                    state: compat_state,
                },
                RateLimitCellSurface {
                    scope: "face 7".into(),
                    limit: "20k pps",
                    state: native_state,
                },
            ],
            compute: vec![ComputeServiceSurface {
                service: "/ndn/compute/filter".into(),
                status: native_state,
                diagnostics: if native { "ready" } else { "unsupported" },
            }],
            surfaces: vec![
                ExtensionSurface {
                    id: "coding",
                    title: "Network coding",
                    capability: native_state,
                    docs: "docs/wiki/src/reference/extensions/coding.md",
                },
                ExtensionSurface {
                    id: "rate-limit",
                    title: "Rate limit",
                    capability: compat_state,
                    docs: "docs/wiki/src/reference/extensions/rate-limit.md",
                },
                ExtensionSurface {
                    id: "compute",
                    title: "Compute",
                    capability: native_state,
                    docs: "docs/wiki/src/reference/extensions/compute.md",
                },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{PlatformKind, fixtures};

    #[test]
    fn ndnrs_profile_enables_extension_surfaces() {
        let profile = fixtures::ndnrs_profile(PlatformKind::Desktop);
        let registry = ExtensionRegistry::for_profile(&profile);

        assert!(
            registry
                .surfaces
                .iter()
                .all(|surface| surface.capability != FeatureState::Unsupported)
        );
        assert_eq!(registry.compute[0].diagnostics, "ready");
    }

    #[test]
    fn nfd_profile_degrades_native_extensions() {
        let profile = fixtures::nfd_profile();
        let registry = ExtensionRegistry::for_profile(&profile);

        assert_eq!(registry.coding[0].state, FeatureState::Unsupported);
        assert_eq!(registry.rate_limits[0].state, FeatureState::ReadOnly);
    }
}
