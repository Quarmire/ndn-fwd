//! Management attach adapters and capability probing.
//!
//! The milestone-one implementation is mock-backed, but the public surface is
//! the shape the live NFD-compatible and ndn-rs-native clients will implement.

use crate::core::{
    AttachMode, AttachTarget, CapabilityEvidence, CapabilitySet, DashboardState, FeatureState,
    ForwarderKind, ForwarderProfile, PlatformKind, observe_from_capabilities,
    trust_from_capabilities,
};
use crate::operations::{AttachState, DashboardRunState, EngineBinding};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttachError {
    BrowserTransportUnavailable,
    DesktopSocketUnavailable,
    Unauthorized,
    Timeout,
    InvalidResponse,
    UnsupportedProfile,
}

impl AttachError {
    pub fn message(&self) -> &'static str {
        match self {
            Self::BrowserTransportUnavailable => {
                "Browser attach needs a browser-safe NDN transport or relay."
            }
            Self::DesktopSocketUnavailable => {
                "Desktop attach needs a reachable local management socket."
            }
            Self::Unauthorized => "The forwarder rejected the management probe.",
            Self::Timeout => "The management probe timed out before the target responded.",
            Self::InvalidResponse => "The target replied with a malformed management response.",
            Self::UnsupportedProfile => "The target did not expose a known management profile.",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeEndpoint {
    NfdStatusGeneral,
    NfdFacesList,
    NdnRsCapabilities,
    NdnRsObservabilityRecent,
    NdnRsTrustContext,
    NdnRsTools,
}

impl ProbeEndpoint {
    pub fn name(self) -> &'static str {
        match self {
            Self::NfdStatusGeneral => "/localhost/nfd/status/general",
            Self::NfdFacesList => "/localhost/nfd/faces/list",
            Self::NdnRsCapabilities => "/localhost/nfd/ndnrs/capabilities",
            Self::NdnRsObservabilityRecent => "/localhost/nfd/observability/recent",
            Self::NdnRsTrustContext => "/localhost/nfd/security/context",
            Self::NdnRsTools => "/localhost/nfd/tools/list",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    Ok,
    NotFound,
    Unauthorized,
    Timeout,
    InvalidResponse,
    TransportUnavailable,
}

impl ProbeOutcome {
    pub fn is_ok(self) -> bool {
        self == Self::Ok
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeStep {
    pub endpoint: ProbeEndpoint,
    pub outcome: ProbeOutcome,
}

impl ProbeStep {
    pub fn ok(endpoint: ProbeEndpoint) -> Self {
        Self {
            endpoint,
            outcome: ProbeOutcome::Ok,
        }
    }

    pub fn missing(endpoint: ProbeEndpoint) -> Self {
        Self {
            endpoint,
            outcome: ProbeOutcome::NotFound,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeTranscript {
    pub steps: Vec<ProbeStep>,
}

impl ProbeTranscript {
    pub fn new(steps: Vec<ProbeStep>) -> Self {
        Self { steps }
    }

    pub fn outcome(&self, endpoint: ProbeEndpoint) -> Option<ProbeOutcome> {
        self.steps
            .iter()
            .find(|step| step.endpoint == endpoint)
            .map(|step| step.outcome)
    }

    pub fn saw_ok(&self, endpoint: ProbeEndpoint) -> bool {
        self.outcome(endpoint).is_some_and(ProbeOutcome::is_ok)
    }

    pub fn nfd_basic_ok(&self) -> bool {
        self.saw_ok(ProbeEndpoint::NfdStatusGeneral) || self.saw_ok(ProbeEndpoint::NfdFacesList)
    }

    pub fn first_blocking_error(&self) -> Option<AttachError> {
        self.steps.iter().find_map(|step| match step.outcome {
            ProbeOutcome::Ok | ProbeOutcome::NotFound => None,
            ProbeOutcome::Unauthorized => Some(AttachError::Unauthorized),
            ProbeOutcome::Timeout => Some(AttachError::Timeout),
            ProbeOutcome::InvalidResponse => Some(AttachError::InvalidResponse),
            ProbeOutcome::TransportUnavailable => Some(AttachError::UnsupportedProfile),
        })
    }
}

#[derive(Clone, Debug)]
pub struct ProbeResult {
    pub profile: ForwarderProfile,
    pub has_identity: bool,
    pub transcript: ProbeTranscript,
}

pub trait DashboardClient {
    fn attach_targets(&self) -> Vec<AttachTarget>;
    fn probe(&self, target: &AttachTarget) -> Result<ProbeResult, AttachError>;
}

#[derive(Clone, Debug)]
pub struct BrowserEngineClient;

#[derive(Clone, Debug)]
pub struct BrowserRemoteClient {
    pub url: String,
}

#[derive(Clone, Debug)]
pub struct DesktopLocalClient {
    pub socket: String,
}

#[derive(Clone, Debug)]
pub struct RelayClient {
    pub endpoint: String,
    pub profile_hint: ForwarderKind,
}

impl DashboardClient for BrowserEngineClient {
    fn attach_targets(&self) -> Vec<AttachTarget> {
        vec![AttachTarget {
            label: "browser in-page engine".into(),
            endpoint: "tab://engine".into(),
            mode: AttachMode::BrowserEngine,
            profile_hint: Some(ForwarderKind::BrowserEngine),
        }]
    }

    fn probe(&self, target: &AttachTarget) -> Result<ProbeResult, AttachError> {
        normalize_probe(
            PlatformKind::Browser,
            target,
            ProbeTranscript::new(vec![
                ProbeStep::ok(ProbeEndpoint::NfdStatusGeneral),
                ProbeStep::ok(ProbeEndpoint::NfdFacesList),
                ProbeStep::ok(ProbeEndpoint::NdnRsCapabilities),
                ProbeStep {
                    endpoint: ProbeEndpoint::NdnRsObservabilityRecent,
                    outcome: ProbeOutcome::Timeout,
                },
                ProbeStep::ok(ProbeEndpoint::NdnRsTrustContext),
                ProbeStep::ok(ProbeEndpoint::NdnRsTools),
            ]),
            true,
        )
    }
}

impl DashboardClient for BrowserRemoteClient {
    fn attach_targets(&self) -> Vec<AttachTarget> {
        vec![AttachTarget {
            label: "remote ndn-rs".into(),
            endpoint: self.url.clone(),
            mode: AttachMode::RemoteWeb,
            profile_hint: Some(ForwarderKind::NdnRs),
        }]
    }

    fn probe(&self, target: &AttachTarget) -> Result<ProbeResult, AttachError> {
        normalize_probe(
            PlatformKind::Browser,
            target,
            ndnrs_native_transcript(FeatureState::Enabled, FeatureState::Enabled),
            true,
        )
    }
}

impl DashboardClient for DesktopLocalClient {
    fn attach_targets(&self) -> Vec<AttachTarget> {
        vec![AttachTarget {
            label: "local ndn-rs".into(),
            endpoint: self.socket.clone(),
            mode: AttachMode::LocalDesktop,
            profile_hint: Some(ForwarderKind::NdnRs),
        }]
    }

    fn probe(&self, target: &AttachTarget) -> Result<ProbeResult, AttachError> {
        normalize_probe(
            PlatformKind::Desktop,
            target,
            ndnrs_native_transcript(FeatureState::Enabled, FeatureState::Enabled),
            true,
        )
    }
}

impl DashboardClient for RelayClient {
    fn attach_targets(&self) -> Vec<AttachTarget> {
        vec![AttachTarget {
            label: format!("{} relay", self.profile_hint.label()),
            endpoint: self.endpoint.clone(),
            mode: AttachMode::Relay,
            profile_hint: Some(self.profile_hint),
        }]
    }

    fn probe(&self, target: &AttachTarget) -> Result<ProbeResult, AttachError> {
        let transcript = match self.profile_hint {
            ForwarderKind::NdnRs | ForwarderKind::BrowserEngine => {
                ndnrs_native_transcript(FeatureState::Enabled, FeatureState::Enabled)
            }
            ForwarderKind::Nfd | ForwarderKind::YaNfd => compat_read_only_transcript(),
            ForwarderKind::Unknown => ProbeTranscript::new(vec![ProbeStep {
                endpoint: ProbeEndpoint::NfdStatusGeneral,
                outcome: ProbeOutcome::TransportUnavailable,
            }]),
        };
        normalize_probe(PlatformKind::Browser, target, transcript, false)
    }
}

pub struct MockDashboardClient {
    platform: PlatformKind,
}

impl MockDashboardClient {
    pub fn new(platform: PlatformKind) -> Self {
        Self { platform }
    }
}

impl DashboardClient for MockDashboardClient {
    fn attach_targets(&self) -> Vec<AttachTarget> {
        let mut targets = vec![
            AttachTarget {
                label: "ndn-rs native".into(),
                endpoint: match self.platform {
                    PlatformKind::Browser => "wss://forwarder.example/ndn".into(),
                    PlatformKind::Desktop => "unix:///run/ndn-fwd/mgmt.sock".into(),
                },
                mode: match self.platform {
                    PlatformKind::Browser => AttachMode::RemoteWeb,
                    PlatformKind::Desktop => AttachMode::LocalDesktop,
                },
                profile_hint: Some(ForwarderKind::NdnRs),
            },
            AttachTarget {
                label: "NFD compatibility".into(),
                endpoint: "unix:///run/nfd/nfd.sock".into(),
                mode: AttachMode::LocalDesktop,
                profile_hint: Some(ForwarderKind::Nfd),
            },
            AttachTarget {
                label: "YaNFD compatibility".into(),
                endpoint: "relay://yanfd".into(),
                mode: AttachMode::Relay,
                profile_hint: Some(ForwarderKind::YaNfd),
            },
        ];
        if self.platform == PlatformKind::Browser {
            targets.insert(
                0,
                AttachTarget {
                    label: "browser in-page engine".into(),
                    endpoint: "tab://engine".into(),
                    mode: AttachMode::BrowserEngine,
                    profile_hint: Some(ForwarderKind::BrowserEngine),
                },
            );
        }
        targets
    }

    fn probe(&self, target: &AttachTarget) -> Result<ProbeResult, AttachError> {
        let transcript = match target.profile_hint {
            Some(ForwarderKind::BrowserEngine) => ProbeTranscript::new(vec![
                ProbeStep::ok(ProbeEndpoint::NfdStatusGeneral),
                ProbeStep::ok(ProbeEndpoint::NfdFacesList),
                ProbeStep::ok(ProbeEndpoint::NdnRsCapabilities),
                ProbeStep {
                    endpoint: ProbeEndpoint::NdnRsObservabilityRecent,
                    outcome: ProbeOutcome::Timeout,
                },
                ProbeStep::ok(ProbeEndpoint::NdnRsTrustContext),
                ProbeStep::ok(ProbeEndpoint::NdnRsTools),
            ]),
            Some(ForwarderKind::NdnRs) => {
                ndnrs_native_transcript(FeatureState::Enabled, FeatureState::Enabled)
            }
            Some(ForwarderKind::Nfd | ForwarderKind::YaNfd) => compat_read_only_transcript(),
            Some(ForwarderKind::Unknown) | None => {
                return Err(AttachError::UnsupportedProfile);
            }
        };
        let has_identity = matches!(
            target.profile_hint,
            Some(ForwarderKind::NdnRs | ForwarderKind::BrowserEngine)
        );
        normalize_probe(self.platform, target, transcript, has_identity)
    }
}

pub fn normalize_probe(
    platform: PlatformKind,
    target: &AttachTarget,
    transcript: ProbeTranscript,
    has_identity: bool,
) -> Result<ProbeResult, AttachError> {
    if !transcript.nfd_basic_ok() {
        return Err(transcript
            .first_blocking_error()
            .unwrap_or(match target.mode {
                AttachMode::BrowserEngine | AttachMode::RemoteWeb | AttachMode::Relay => {
                    AttachError::BrowserTransportUnavailable
                }
                AttachMode::LocalDesktop => AttachError::DesktopSocketUnavailable,
            }));
    }

    let kind = target.profile_hint.unwrap_or_else(|| {
        if transcript.saw_ok(ProbeEndpoint::NdnRsCapabilities) {
            ForwarderKind::NdnRs
        } else {
            ForwarderKind::Unknown
        }
    });

    let ndnrs_native = transcript.saw_ok(ProbeEndpoint::NdnRsCapabilities)
        || matches!(kind, ForwarderKind::NdnRs | ForwarderKind::BrowserEngine);
    let observability = native_feature_state(
        ndnrs_native,
        transcript.outcome(ProbeEndpoint::NdnRsObservabilityRecent),
        matches!(target.mode, AttachMode::BrowserEngine),
    );
    let trust_context = native_feature_state(
        ndnrs_native,
        transcript.outcome(ProbeEndpoint::NdnRsTrustContext),
        matches!(target.mode, AttachMode::BrowserEngine),
    );
    let tools = native_feature_state(
        ndnrs_native,
        transcript.outcome(ProbeEndpoint::NdnRsTools),
        false,
    );
    let capabilities = CapabilitySet::from_probe_evidence(&CapabilityEvidence {
        nfd_basic: true,
        ndnrs_native,
        observability,
        trust_context,
        tools,
    });

    let profile = ForwarderProfile {
        kind,
        version: match kind {
            ForwarderKind::NdnRs => "probed ndn-rs".into(),
            ForwarderKind::Nfd => "probed NFD".into(),
            ForwarderKind::YaNfd => "probed YaNFD".into(),
            ForwarderKind::BrowserEngine => "sandbox".into(),
            ForwarderKind::Unknown => "unknown".into(),
        },
        endpoint: target.endpoint.clone(),
        attach_mode: target.mode,
        capabilities,
    };

    let _ = platform;
    Ok(ProbeResult {
        profile,
        has_identity,
        transcript,
    })
}

fn native_feature_state(
    ndnrs_native: bool,
    outcome: Option<ProbeOutcome>,
    degrade_when_ok: bool,
) -> FeatureState {
    if !ndnrs_native {
        return FeatureState::Unsupported;
    }

    match outcome {
        Some(ProbeOutcome::Ok) if degrade_when_ok => FeatureState::Degraded,
        Some(ProbeOutcome::Ok) => FeatureState::Enabled,
        Some(ProbeOutcome::NotFound) => FeatureState::Disabled,
        Some(
            ProbeOutcome::Unauthorized | ProbeOutcome::Timeout | ProbeOutcome::InvalidResponse,
        ) => FeatureState::Degraded,
        Some(ProbeOutcome::TransportUnavailable) | None => FeatureState::Unsupported,
    }
}

fn ndnrs_native_transcript(
    observability: FeatureState,
    trust_context: FeatureState,
) -> ProbeTranscript {
    ProbeTranscript::new(vec![
        ProbeStep::ok(ProbeEndpoint::NfdStatusGeneral),
        ProbeStep::ok(ProbeEndpoint::NfdFacesList),
        ProbeStep::ok(ProbeEndpoint::NdnRsCapabilities),
        feature_probe_step(ProbeEndpoint::NdnRsObservabilityRecent, observability),
        feature_probe_step(ProbeEndpoint::NdnRsTrustContext, trust_context),
        ProbeStep::ok(ProbeEndpoint::NdnRsTools),
    ])
}

fn compat_read_only_transcript() -> ProbeTranscript {
    ProbeTranscript::new(vec![
        ProbeStep::ok(ProbeEndpoint::NfdStatusGeneral),
        ProbeStep::ok(ProbeEndpoint::NfdFacesList),
        ProbeStep::missing(ProbeEndpoint::NdnRsCapabilities),
        ProbeStep::missing(ProbeEndpoint::NdnRsObservabilityRecent),
        ProbeStep::missing(ProbeEndpoint::NdnRsTrustContext),
        ProbeStep::missing(ProbeEndpoint::NdnRsTools),
    ])
}

fn feature_probe_step(endpoint: ProbeEndpoint, state: FeatureState) -> ProbeStep {
    let outcome = match state {
        FeatureState::Enabled | FeatureState::ReadOnly => ProbeOutcome::Ok,
        FeatureState::Disabled | FeatureState::Unsupported => ProbeOutcome::NotFound,
        FeatureState::Degraded => ProbeOutcome::Timeout,
    };
    ProbeStep { endpoint, outcome }
}

pub fn state_from_probe(platform: PlatformKind, probe: ProbeResult) -> DashboardState {
    let trust = trust_from_capabilities(&probe.profile.capabilities, probe.has_identity);
    let observe = observe_from_capabilities(&probe.profile.capabilities);
    let binding = EngineBinding::from_profile(probe.profile.clone(), platform);
    DashboardState {
        platform,
        density: crate::core::Density::Compact,
        run_state: DashboardRunState::Attached,
        attach_state: AttachState::Attached { binding },
        profile: probe.profile,
        trust,
        observe,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{FeatureState, ForwarderKind};

    #[test]
    fn browser_client_exposes_browser_engine_target_first() {
        let client = MockDashboardClient::new(PlatformKind::Browser);
        let targets = client.attach_targets();
        assert_eq!(targets[0].mode, AttachMode::BrowserEngine);
    }

    #[test]
    fn probe_normalizes_nfd_as_read_only() {
        let client = MockDashboardClient::new(PlatformKind::Desktop);
        let target = client
            .attach_targets()
            .into_iter()
            .find(|t| t.label == "NFD compatibility")
            .expect("target");
        let probe = client.probe(&target).expect("probe");
        assert_eq!(probe.profile.kind, ForwarderKind::Nfd);
        assert_eq!(probe.profile.capabilities.nfd_basic, FeatureState::ReadOnly);
        assert!(probe.transcript.saw_ok(ProbeEndpoint::NfdStatusGeneral));
        assert!(!probe.transcript.saw_ok(ProbeEndpoint::NdnRsCapabilities));
    }

    #[test]
    fn browser_remote_adapter_probes_nfd_then_native_extensions() {
        let client = BrowserRemoteClient {
            url: "wss://router.example/ndn".into(),
        };
        let target = client.attach_targets().remove(0);
        let probe = client.probe(&target).expect("probe");

        assert_eq!(
            probe.transcript.steps[0].endpoint,
            ProbeEndpoint::NfdStatusGeneral
        );
        assert_eq!(
            probe.profile.capabilities.ndnrs_native,
            FeatureState::Enabled
        );
        assert_eq!(
            probe.profile.capabilities.observability,
            FeatureState::Enabled
        );
    }

    #[test]
    fn browser_engine_degrades_observe_without_breaking_attach() {
        let client = BrowserEngineClient;
        let target = client.attach_targets().remove(0);
        let probe = client.probe(&target).expect("probe");

        assert_eq!(probe.profile.kind, ForwarderKind::BrowserEngine);
        assert_eq!(
            probe.profile.capabilities.observability,
            FeatureState::Degraded
        );
        assert_eq!(
            probe.profile.capabilities.trust_context,
            FeatureState::Degraded
        );
    }

    #[test]
    fn failed_nfd_probe_returns_transport_specific_error() {
        let target = AttachTarget {
            label: "broken".into(),
            endpoint: "unix:///missing.sock".into(),
            mode: AttachMode::LocalDesktop,
            profile_hint: Some(ForwarderKind::Unknown),
        };
        let err = normalize_probe(
            PlatformKind::Desktop,
            &target,
            ProbeTranscript::new(vec![ProbeStep {
                endpoint: ProbeEndpoint::NfdStatusGeneral,
                outcome: ProbeOutcome::TransportUnavailable,
            }]),
            false,
        )
        .expect_err("probe should fail");

        assert_eq!(err, AttachError::UnsupportedProfile);
    }
}
