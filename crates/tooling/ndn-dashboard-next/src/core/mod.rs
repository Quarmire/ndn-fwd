//! Pure dashboard state, capability models, and mock fixtures.

use serde::{Deserialize, Serialize};

use crate::operations::{AttachState, DashboardRunState, EngineBinding};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlatformKind {
    Browser,
    Desktop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachMode {
    BrowserEngine,
    RemoteWeb,
    LocalDesktop,
    Relay,
}

impl AttachMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::BrowserEngine => "browser engine",
            Self::RemoteWeb => "remote web",
            Self::LocalDesktop => "local desktop",
            Self::Relay => "relay",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForwarderKind {
    NdnRs,
    Nfd,
    YaNfd,
    BrowserEngine,
    Unknown,
}

impl ForwarderKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::NdnRs => "ndn-rs",
            Self::Nfd => "NFD",
            Self::YaNfd => "YaNFD",
            Self::BrowserEngine => "browser engine",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeatureState {
    Unsupported,
    Disabled,
    Degraded,
    ReadOnly,
    Enabled,
}

impl FeatureState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::Disabled => "disabled",
            Self::Degraded => "degraded",
            Self::ReadOnly => "read-only",
            Self::Enabled => "enabled",
        }
    }

    pub fn is_available(self) -> bool {
        matches!(self, Self::ReadOnly | Self::Enabled | Self::Degraded)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub nfd_basic: FeatureState,
    pub ndnrs_native: FeatureState,
    pub observability: FeatureState,
    pub trust_context: FeatureState,
    pub tools: FeatureState,
}

impl CapabilitySet {
    pub fn from_probe_evidence(evidence: &CapabilityEvidence) -> Self {
        if !evidence.nfd_basic {
            return Self::unsupported();
        }

        if evidence.ndnrs_native {
            return Self {
                nfd_basic: FeatureState::Enabled,
                ndnrs_native: FeatureState::Enabled,
                observability: evidence.observability,
                trust_context: evidence.trust_context,
                tools: evidence.tools,
            };
        }

        Self {
            nfd_basic: FeatureState::ReadOnly,
            ndnrs_native: FeatureState::Unsupported,
            observability: FeatureState::Unsupported,
            trust_context: FeatureState::Unsupported,
            tools: FeatureState::ReadOnly,
        }
    }

    pub fn ndnrs_native() -> Self {
        Self {
            nfd_basic: FeatureState::Enabled,
            ndnrs_native: FeatureState::Enabled,
            observability: FeatureState::Enabled,
            trust_context: FeatureState::Enabled,
            tools: FeatureState::Enabled,
        }
    }

    pub fn nfd_read_only() -> Self {
        Self {
            nfd_basic: FeatureState::ReadOnly,
            ndnrs_native: FeatureState::Unsupported,
            observability: FeatureState::Unsupported,
            trust_context: FeatureState::Unsupported,
            tools: FeatureState::ReadOnly,
        }
    }

    pub fn yanfd_read_only() -> Self {
        Self {
            nfd_basic: FeatureState::ReadOnly,
            ndnrs_native: FeatureState::Unsupported,
            observability: FeatureState::Unsupported,
            trust_context: FeatureState::Unsupported,
            tools: FeatureState::ReadOnly,
        }
    }

    pub fn browser_engine() -> Self {
        Self {
            nfd_basic: FeatureState::Enabled,
            ndnrs_native: FeatureState::Enabled,
            observability: FeatureState::Degraded,
            trust_context: FeatureState::Degraded,
            tools: FeatureState::Enabled,
        }
    }

    pub fn unsupported() -> Self {
        Self {
            nfd_basic: FeatureState::Unsupported,
            ndnrs_native: FeatureState::Unsupported,
            observability: FeatureState::Unsupported,
            trust_context: FeatureState::Unsupported,
            tools: FeatureState::Unsupported,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEvidence {
    pub nfd_basic: bool,
    pub ndnrs_native: bool,
    pub observability: FeatureState,
    pub trust_context: FeatureState,
    pub tools: FeatureState,
}

impl CapabilityEvidence {
    pub fn none() -> Self {
        Self {
            nfd_basic: false,
            ndnrs_native: false,
            observability: FeatureState::Unsupported,
            trust_context: FeatureState::Unsupported,
            tools: FeatureState::Unsupported,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwarderProfile {
    pub kind: ForwarderKind,
    pub version: String,
    pub endpoint: String,
    pub attach_mode: AttachMode,
    pub capabilities: CapabilitySet,
}

impl ForwarderProfile {
    pub fn display_name(&self) -> String {
        format!("{} {}", self.kind.label(), self.version)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachTarget {
    pub label: String,
    pub endpoint: String,
    pub mode: AttachMode,
    pub profile_hint: Option<ForwarderKind>,
}

impl AttachTarget {
    pub fn id(&self) -> String {
        format!(
            "{}:{}:{}",
            self.mode.label(),
            self.profile_hint
                .map(ForwarderKind::label)
                .unwrap_or("unknown"),
            self.endpoint
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetPlatformStatus {
    Available,
    NeedsDesktop,
    NeedsBrowser,
    NeedsBridge,
}

impl TargetPlatformStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::NeedsDesktop => "desktop only",
            Self::NeedsBrowser => "browser only",
            Self::NeedsBridge => "bridge required",
        }
    }

    pub fn is_available(self) -> bool {
        self == Self::Available
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedAttachTarget {
    pub id: String,
    pub label: String,
    pub endpoint: String,
    pub mode: AttachMode,
    pub profile_hint: Option<ForwarderKind>,
    pub pinned: bool,
    pub last_connected_unix_s: Option<u64>,
}

impl SavedAttachTarget {
    pub fn from_target(
        target: AttachTarget,
        pinned: bool,
        last_connected_unix_s: Option<u64>,
    ) -> Self {
        Self {
            id: target.id(),
            label: target.label,
            endpoint: target.endpoint,
            mode: target.mode,
            profile_hint: target.profile_hint,
            pinned,
            last_connected_unix_s,
        }
    }

    pub fn attach_target(&self) -> AttachTarget {
        AttachTarget {
            label: self.label.clone(),
            endpoint: self.endpoint.clone(),
            mode: self.mode,
            profile_hint: self.profile_hint,
        }
    }

    pub fn platform_status(&self, platform: PlatformKind) -> TargetPlatformStatus {
        match (platform, self.mode) {
            (PlatformKind::Browser, AttachMode::LocalDesktop) => TargetPlatformStatus::NeedsBridge,
            (PlatformKind::Desktop, AttachMode::BrowserEngine) => {
                TargetPlatformStatus::NeedsBrowser
            }
            _ => TargetPlatformStatus::Available,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardPreferences {
    pub platform: PlatformKind,
    pub density: Density,
    pub selected_target_id: Option<String>,
    pub saved_targets: Vec<SavedAttachTarget>,
    pub recent_targets: Vec<SavedAttachTarget>,
}

impl DashboardPreferences {
    pub fn defaults(platform: PlatformKind, targets: Vec<AttachTarget>) -> Self {
        let mut saved_targets = targets
            .into_iter()
            .enumerate()
            .map(|(index, target)| {
                SavedAttachTarget::from_target(
                    target,
                    index < 2,
                    Some(1_717_200_000 + index as u64),
                )
            })
            .collect::<Vec<_>>();
        saved_targets.sort_by_key(|target| (!target.pinned, target.label.clone()));
        let selected_target_id = saved_targets.first().map(|target| target.id.clone());
        Self {
            platform,
            density: Density::Compact,
            selected_target_id,
            recent_targets: saved_targets.iter().take(3).cloned().collect(),
            saved_targets,
        }
    }

    pub fn selected_target(&self) -> Option<&SavedAttachTarget> {
        self.selected_target_id
            .as_ref()
            .and_then(|id| self.saved_targets.iter().find(|target| &target.id == id))
    }

    pub fn select(&mut self, id: &str) {
        if self.saved_targets.iter().any(|target| target.id == id) {
            self.selected_target_id = Some(id.to_string());
        }
    }

    pub fn remember_connected(&mut self, target: SavedAttachTarget, now_unix_s: u64) {
        let mut target = target;
        target.last_connected_unix_s = Some(now_unix_s);
        self.selected_target_id = Some(target.id.clone());
        upsert_target(&mut self.saved_targets, target.clone());
        upsert_target(&mut self.recent_targets, target);
        self.recent_targets
            .sort_by_key(|target| std::cmp::Reverse(target.last_connected_unix_s.unwrap_or(0)));
        self.recent_targets.truncate(5);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityMatrixRow {
    pub feature: &'static str,
    pub state: FeatureState,
    pub source_probe: &'static str,
    pub explanation: &'static str,
}

pub fn capability_matrix(profile: &ForwarderProfile) -> Vec<CapabilityMatrixRow> {
    vec![
        CapabilityMatrixRow {
            feature: "NFD-compatible management",
            state: profile.capabilities.nfd_basic,
            source_probe: "/localhost/nfd/status/general",
            explanation: match profile.capabilities.nfd_basic {
                FeatureState::Enabled => "Full management surface is available.",
                FeatureState::ReadOnly => "Read datasets are available; writes stay gated.",
                _ => "Common management datasets were not confirmed.",
            },
        },
        CapabilityMatrixRow {
            feature: "ndn-rs native extensions",
            state: profile.capabilities.ndnrs_native,
            source_probe: "/localhost/nfd/ndnrs/capabilities",
            explanation: match profile.capabilities.ndnrs_native {
                FeatureState::Enabled => {
                    "Native Trust, Observe, and Tools extensions can light up."
                }
                _ => "Use the compatible Engine views; native controls remain hidden.",
            },
        },
        CapabilityMatrixRow {
            feature: "Observability spans",
            state: profile.capabilities.observability,
            source_probe: "/localhost/nfd/observability/recent",
            explanation: match profile.capabilities.observability {
                FeatureState::Enabled => "Recent traces and span detail can be fetched.",
                FeatureState::Degraded => "Trace surface exists but is partial or sandbox-limited.",
                FeatureState::Disabled => {
                    "The forwarder supports observability but has it disabled."
                }
                _ => "Show compatible counters and logs instead of native trace views.",
            },
        },
        CapabilityMatrixRow {
            feature: "TrustContext",
            state: profile.capabilities.trust_context,
            source_probe: "/localhost/nfd/security/context",
            explanation: match profile.capabilities.trust_context {
                FeatureState::Enabled => "Trust posture and approval workflows can be shown.",
                FeatureState::Degraded => "Trust UX is available with sandbox limitations.",
                _ => "Do not report missing identity for non-ndn-rs forwarders.",
            },
        },
        CapabilityMatrixRow {
            feature: "Tools",
            state: profile.capabilities.tools,
            source_probe: "/localhost/nfd/tools/list",
            explanation: match profile.capabilities.tools {
                FeatureState::Enabled => "Structured tool runs can stream and pivot to Observe.",
                FeatureState::ReadOnly => "Diagnostics can inspect compatible state only.",
                _ => "Tool actions must be disabled for this target.",
            },
        },
    ]
}

fn upsert_target(targets: &mut Vec<SavedAttachTarget>, target: SavedAttachTarget) {
    if let Some(existing) = targets.iter_mut().find(|existing| existing.id == target.id) {
        *existing = target;
    } else {
        targets.push(target);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustPosture {
    Unsupported,
    None,
    Ephemeral,
    Valid,
    Expired,
    Weakened,
    Error,
}

impl TrustPosture {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unsupported => "trust unsupported",
            Self::None => "no identity",
            Self::Ephemeral => "ephemeral",
            Self::Valid => "trusted",
            Self::Expired => "expired",
            Self::Weakened => "schema weakened",
            Self::Error => "trust error",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservePosture {
    Unsupported,
    Disabled,
    Enabled,
    Degraded,
    Error,
}

impl ObservePosture {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unsupported => "observe unsupported",
            Self::Disabled => "observe disabled",
            Self::Enabled => "observe live",
            Self::Degraded => "observe degraded",
            Self::Error => "observe error",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Density {
    Compact,
    Comfortable,
}

impl Density {
    pub fn label(self) -> &'static str {
        match self {
            Self::Compact => "compact",
            Self::Comfortable => "comfortable",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardState {
    pub platform: PlatformKind,
    pub density: Density,
    pub run_state: DashboardRunState,
    pub attach_state: AttachState,
    pub profile: ForwarderProfile,
    pub trust: TrustPosture,
    pub observe: ObservePosture,
}

impl DashboardState {
    pub fn detached(platform: PlatformKind) -> Self {
        Self {
            platform,
            density: Density::Compact,
            run_state: DashboardRunState::Detached,
            attach_state: AttachState::Detached { last_error: None },
            profile: fixtures::unsupported_profile(),
            trust: TrustPosture::Unsupported,
            observe: ObservePosture::Unsupported,
        }
    }

    pub fn mock_ndnrs(platform: PlatformKind) -> Self {
        Self {
            platform,
            density: Density::Compact,
            run_state: DashboardRunState::Attached,
            attach_state: AttachState::Attached {
                binding: EngineBinding::from_profile(fixtures::ndnrs_profile(platform), platform),
            },
            profile: fixtures::ndnrs_profile(platform),
            trust: TrustPosture::Valid,
            observe: ObservePosture::Enabled,
        }
    }
}

pub mod fixtures {
    use super::*;

    pub fn browser_engine_profile() -> ForwarderProfile {
        ForwarderProfile {
            kind: ForwarderKind::BrowserEngine,
            version: "sandbox".into(),
            endpoint: "tab://engine".into(),
            attach_mode: AttachMode::BrowserEngine,
            capabilities: CapabilitySet::browser_engine(),
        }
    }

    pub fn ndnrs_profile(platform: PlatformKind) -> ForwarderProfile {
        ForwarderProfile {
            kind: ForwarderKind::NdnRs,
            version: "0.1-next".into(),
            endpoint: match platform {
                PlatformKind::Browser => "wss://forwarder.example/ndn".into(),
                PlatformKind::Desktop => "unix:///run/ndn-fwd/mgmt.sock".into(),
            },
            attach_mode: match platform {
                PlatformKind::Browser => AttachMode::RemoteWeb,
                PlatformKind::Desktop => AttachMode::LocalDesktop,
            },
            capabilities: CapabilitySet::ndnrs_native(),
        }
    }

    pub fn nfd_profile() -> ForwarderProfile {
        ForwarderProfile {
            kind: ForwarderKind::Nfd,
            version: "24.x".into(),
            endpoint: "unix:///run/nfd/nfd.sock".into(),
            attach_mode: AttachMode::LocalDesktop,
            capabilities: CapabilitySet::nfd_read_only(),
        }
    }

    pub fn yanfd_profile() -> ForwarderProfile {
        ForwarderProfile {
            kind: ForwarderKind::YaNfd,
            version: "compat".into(),
            endpoint: "tcp://127.0.0.1:6363".into(),
            attach_mode: AttachMode::Relay,
            capabilities: CapabilitySet::yanfd_read_only(),
        }
    }

    pub fn unsupported_profile() -> ForwarderProfile {
        ForwarderProfile {
            kind: ForwarderKind::Unknown,
            version: "unknown".into(),
            endpoint: "detached".into(),
            attach_mode: AttachMode::Relay,
            capabilities: CapabilitySet::unsupported(),
        }
    }
}

pub fn trust_from_capabilities(capabilities: &CapabilitySet, has_identity: bool) -> TrustPosture {
    if !capabilities.trust_context.is_available() {
        TrustPosture::Unsupported
    } else if has_identity {
        TrustPosture::Valid
    } else {
        TrustPosture::None
    }
}

pub fn observe_from_capabilities(capabilities: &CapabilitySet) -> ObservePosture {
    match capabilities.observability {
        FeatureState::Enabled => ObservePosture::Enabled,
        FeatureState::Degraded => ObservePosture::Degraded,
        FeatureState::Disabled => ObservePosture::Disabled,
        FeatureState::ReadOnly | FeatureState::Unsupported => ObservePosture::Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfd_profile_is_read_only_without_native_features() {
        let profile = fixtures::nfd_profile();
        assert_eq!(profile.capabilities.nfd_basic, FeatureState::ReadOnly);
        assert_eq!(profile.capabilities.ndnrs_native, FeatureState::Unsupported);
        assert_eq!(
            observe_from_capabilities(&profile.capabilities),
            ObservePosture::Unsupported
        );
    }

    #[test]
    fn ndnrs_profile_enables_trust_and_observe() {
        let profile = fixtures::ndnrs_profile(PlatformKind::Desktop);
        assert_eq!(
            trust_from_capabilities(&profile.capabilities, true),
            TrustPosture::Valid
        );
        assert_eq!(
            observe_from_capabilities(&profile.capabilities),
            ObservePosture::Enabled
        );
    }

    #[test]
    fn detached_state_does_not_claim_live_capabilities() {
        let state = DashboardState::detached(PlatformKind::Desktop);

        assert_eq!(state.profile.kind, ForwarderKind::Unknown);
        assert_eq!(state.trust, TrustPosture::Unsupported);
        assert_eq!(state.observe, ObservePosture::Unsupported);
        assert_eq!(state.profile.capabilities, CapabilitySet::unsupported());
    }

    #[test]
    fn browser_engine_is_degraded_not_broken() {
        let profile = fixtures::browser_engine_profile();
        assert_eq!(profile.capabilities.observability, FeatureState::Degraded);
        assert_eq!(
            observe_from_capabilities(&profile.capabilities),
            ObservePosture::Degraded
        );
    }

    #[test]
    fn capability_evidence_normalizes_non_native_forwarders_read_only() {
        let capabilities = CapabilitySet::from_probe_evidence(&CapabilityEvidence {
            nfd_basic: true,
            ndnrs_native: false,
            observability: FeatureState::Enabled,
            trust_context: FeatureState::Enabled,
            tools: FeatureState::Enabled,
        });

        assert_eq!(capabilities.nfd_basic, FeatureState::ReadOnly);
        assert_eq!(capabilities.ndnrs_native, FeatureState::Unsupported);
        assert_eq!(capabilities.tools, FeatureState::ReadOnly);
        assert_eq!(capabilities.trust_context, FeatureState::Unsupported);
    }

    #[test]
    fn missing_nfd_probe_normalizes_to_unsupported() {
        let capabilities = CapabilitySet::from_probe_evidence(&CapabilityEvidence {
            nfd_basic: false,
            ndnrs_native: true,
            observability: FeatureState::Enabled,
            trust_context: FeatureState::Enabled,
            tools: FeatureState::Enabled,
        });

        assert_eq!(capabilities, CapabilitySet::unsupported());
    }
}
