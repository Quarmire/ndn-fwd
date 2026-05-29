//! Operations-home state and lifecycle rules.
//!
//! These models are intentionally pure. The Dioxus shell renders them, the
//! platform layer executes process work, and the client layer supplies probe
//! evidence.

use serde::{Deserialize, Serialize};

use crate::config::{ConfigDiff, RouterConfigDraft};
use crate::core::{
    AttachMode, CapabilitySet, ForwarderProfile, PlatformKind, SavedAttachTarget,
    TargetPlatformStatus,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DashboardRunState {
    Booting,
    Detached,
    Probing,
    Attached,
    Failed,
    Demo,
}

impl DashboardRunState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Booting => "booting",
            Self::Detached => "detached",
            Self::Probing => "probing",
            Self::Attached => "attached",
            Self::Failed => "attach failed",
            Self::Demo => "demo",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachState {
    Detached {
        last_error: Option<AttachFailure>,
    },
    Probing {
        target: AttachTargetSnapshot,
    },
    Attached {
        binding: EngineBinding,
    },
    Degraded {
        binding: EngineBinding,
        reason: DegradedReason,
    },
    Failed {
        target: AttachTargetSnapshot,
        error: AttachFailure,
    },
}

impl AttachState {
    pub fn run_state(&self) -> DashboardRunState {
        match self {
            Self::Detached { .. } => DashboardRunState::Detached,
            Self::Probing { .. } => DashboardRunState::Probing,
            Self::Attached { .. } => DashboardRunState::Attached,
            Self::Degraded { .. } => DashboardRunState::Attached,
            Self::Failed { .. } => DashboardRunState::Failed,
        }
    }

    pub fn binding(&self) -> Option<&EngineBinding> {
        match self {
            Self::Attached { binding } | Self::Degraded { binding, .. } => Some(binding),
            Self::Detached { .. } | Self::Probing { .. } | Self::Failed { .. } => None,
        }
    }

    pub fn is_attached(&self) -> bool {
        self.binding().is_some()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachTargetSnapshot {
    pub label: String,
    pub endpoint: String,
    pub mode: AttachMode,
}

impl From<&SavedAttachTarget> for AttachTargetSnapshot {
    fn from(target: &SavedAttachTarget) -> Self {
        Self {
            label: target.label.clone(),
            endpoint: target.endpoint.clone(),
            mode: target.mode,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineBinding {
    pub profile: ForwarderProfile,
    pub ownership: EngineOwnership,
    pub target_label: Option<String>,
    pub attached_at_unix_s: Option<u64>,
}

impl EngineBinding {
    pub fn from_profile(profile: ForwarderProfile, platform: PlatformKind) -> Self {
        let ownership = EngineOwnership::inferred(profile.attach_mode, platform);
        Self {
            profile,
            ownership,
            target_label: None,
            attached_at_unix_s: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineOwnership {
    DashboardStarted,
    External,
    BrowserInPage,
    BrowserSharedWorker,
    ExternalCompanion,
    Relay,
    Unknown,
}

impl EngineOwnership {
    pub fn inferred(mode: AttachMode, platform: PlatformKind) -> Self {
        match (mode, platform) {
            (AttachMode::BrowserEngine, _) => Self::BrowserInPage,
            (AttachMode::LocalDesktop, _) => Self::External,
            (AttachMode::RemoteWeb, PlatformKind::Browser) => Self::ExternalCompanion,
            (AttachMode::RemoteWeb, PlatformKind::Desktop) => Self::External,
            (AttachMode::Relay, _) => Self::Relay,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::DashboardStarted => "dashboard-started",
            Self::External => "external",
            Self::BrowserInPage => "in-page engine",
            Self::BrowserSharedWorker => "shared-worker engine",
            Self::ExternalCompanion => "external companion",
            Self::Relay => "relay",
            Self::Unknown => "unknown ownership",
        }
    }

    pub fn can_stop(self) -> bool {
        self == Self::DashboardStarted
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouterLifecycleAction {
    StartRouter,
    StopDashboardStarted,
    Detach,
    Reattach,
    ShutdownSigned,
}

impl RouterLifecycleAction {
    pub fn label(self) -> &'static str {
        match self {
            Self::StartRouter => "Start Router",
            Self::StopDashboardStarted => "Stop",
            Self::Detach => "Detach",
            Self::Reattach => "Reattach",
            Self::ShutdownSigned => "Shutdown",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleActionState {
    pub action: RouterLifecycleAction,
    pub enabled: bool,
    pub reason: Option<String>,
}

impl LifecycleActionState {
    pub fn enabled(action: RouterLifecycleAction) -> Self {
        Self {
            action,
            enabled: true,
            reason: None,
        }
    }

    pub fn unavailable(action: RouterLifecycleAction, reason: impl Into<String>) -> Self {
        Self {
            action,
            enabled: false,
            reason: Some(reason.into()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartRouterTab {
    QuickStart,
    BuildConfig,
    LoadToml,
    Presets,
    CurrentConfig,
}

impl StartRouterTab {
    pub const ALL: [Self; 5] = [
        Self::QuickStart,
        Self::BuildConfig,
        Self::LoadToml,
        Self::Presets,
        Self::CurrentConfig,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::QuickStart => "Quick start",
            Self::BuildConfig => "Build config",
            Self::LoadToml => "Load TOML",
            Self::Presets => "Presets",
            Self::CurrentConfig => "Current config",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartRouterModalModel {
    pub platform: PlatformKind,
    pub active_tab: StartRouterTab,
    pub draft: RouterConfigDraft,
    pub current_config: RouterConfigDraft,
    pub diff: Vec<ConfigDiff>,
    pub can_start: bool,
    pub blocker: Option<String>,
    pub preview_toml: String,
}

impl StartRouterModalModel {
    pub fn new(
        platform: PlatformKind,
        active_tab: StartRouterTab,
        draft: RouterConfigDraft,
        current_config: RouterConfigDraft,
    ) -> Self {
        let diff = draft.diff_from(&current_config);
        let preview = draft.render_toml();
        let (preview_toml, render_error) = match preview {
            Ok(toml) => (toml, None),
            Err(err) => (format!("# render error: {err}"), Some(err)),
        };
        let blocker = if !RouterConfigDraft::can_write(platform) {
            Some(
                "Browsers cannot spawn local ndn-fwd; attach to an in-page engine, remote web target, external companion, or relay."
                    .to_string(),
            )
        } else {
            render_error.map(|err| format!("Router config cannot be rendered: {err}"))
        };
        Self {
            platform,
            active_tab,
            draft,
            current_config,
            diff,
            can_start: blocker.is_none(),
            blocker,
            preview_toml,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachFailure {
    pub message: String,
    pub recovery: String,
}

impl AttachFailure {
    pub fn new(message: impl Into<String>, recovery: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            recovery: recovery.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DegradedReason {
    pub summary: String,
    pub next_action: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationsHomeModel {
    pub run_state: DashboardRunState,
    pub attach_state: AttachState,
    pub selected_target: Option<AttachTargetSnapshot>,
    pub selected_target_status: Option<TargetPlatformStatus>,
    pub lifecycle_actions: Vec<LifecycleActionState>,
    pub capability_summary: CapabilitySummary,
}

impl OperationsHomeModel {
    pub fn new(
        platform: PlatformKind,
        attach_state: AttachState,
        capabilities: CapabilitySet,
        selected_target: Option<&SavedAttachTarget>,
    ) -> Self {
        let selected_target_status = selected_target.map(|target| target.platform_status(platform));
        let selected_target = selected_target.map(AttachTargetSnapshot::from);
        let lifecycle_actions = lifecycle_actions(platform, &attach_state, selected_target_status);
        Self {
            run_state: attach_state.run_state(),
            attach_state,
            selected_target,
            selected_target_status,
            lifecycle_actions,
            capability_summary: CapabilitySummary::from(capabilities),
        }
    }

    pub fn action(&self, action: RouterLifecycleAction) -> Option<&LifecycleActionState> {
        self.lifecycle_actions
            .iter()
            .find(|candidate| candidate.action == action)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilitySummary {
    pub live_engine: bool,
    pub trust_available: bool,
    pub observe_available: bool,
    pub tools_available: bool,
}

impl From<CapabilitySet> for CapabilitySummary {
    fn from(capabilities: CapabilitySet) -> Self {
        Self {
            live_engine: capabilities.nfd_basic.is_available(),
            trust_available: capabilities.trust_context.is_available(),
            observe_available: capabilities.observability.is_available(),
            tools_available: capabilities.tools.is_available(),
        }
    }
}

fn lifecycle_actions(
    platform: PlatformKind,
    attach_state: &AttachState,
    selected_target_status: Option<TargetPlatformStatus>,
) -> Vec<LifecycleActionState> {
    let start = match platform {
        PlatformKind::Desktop => LifecycleActionState::enabled(RouterLifecycleAction::StartRouter),
        PlatformKind::Browser => LifecycleActionState::unavailable(
            RouterLifecycleAction::StartRouter,
            "Browsers cannot start local processes; use an in-page engine, shared-worker engine, external companion, remote web target, or relay.",
        ),
    };

    let stop = match attach_state.binding().map(|binding| binding.ownership) {
        Some(ownership) if ownership.can_stop() => {
            LifecycleActionState::enabled(RouterLifecycleAction::StopDashboardStarted)
        }
        Some(ownership) => LifecycleActionState::unavailable(
            RouterLifecycleAction::StopDashboardStarted,
            format!(
                "Stop is only available for dashboard-started engines; this engine is {}.",
                ownership.label()
            ),
        ),
        None => LifecycleActionState::unavailable(
            RouterLifecycleAction::StopDashboardStarted,
            "Attach to a dashboard-started engine before Stop is available.",
        ),
    };

    let reattach = match selected_target_status {
        Some(status) if status.is_available() => {
            LifecycleActionState::enabled(RouterLifecycleAction::Reattach)
        }
        Some(status) => LifecycleActionState::unavailable(
            RouterLifecycleAction::Reattach,
            format!("Selected target is {} on this platform.", status.label()),
        ),
        None => LifecycleActionState::unavailable(
            RouterLifecycleAction::Reattach,
            "Choose an attach target first.",
        ),
    };

    let detach = if attach_state.is_attached() {
        LifecycleActionState::enabled(RouterLifecycleAction::Detach)
    } else {
        LifecycleActionState::unavailable(
            RouterLifecycleAction::Detach,
            "There is no active engine binding to detach.",
        )
    };

    let shutdown = if attach_state.is_attached() {
        LifecycleActionState::enabled(RouterLifecycleAction::ShutdownSigned)
    } else {
        LifecycleActionState::unavailable(
            RouterLifecycleAction::ShutdownSigned,
            "Attach to an engine before sending a signed Shutdown command.",
        )
    };

    vec![start, reattach, detach, stop, shutdown]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{AttachMode, ForwarderKind, fixtures};

    fn local_target() -> SavedAttachTarget {
        SavedAttachTarget::from_target(
            crate::core::AttachTarget {
                label: "local ndn-fwd".into(),
                endpoint: "unix:///run/ndn-fwd/mgmt.sock".into(),
                mode: AttachMode::LocalDesktop,
                profile_hint: Some(ForwarderKind::NdnRs),
            },
            true,
            None,
        )
    }

    #[test]
    fn detached_desktop_can_start_and_reattach_but_not_stop_or_shutdown() {
        let model = OperationsHomeModel::new(
            PlatformKind::Desktop,
            AttachState::Detached { last_error: None },
            CapabilitySet::unsupported(),
            Some(&local_target()),
        );

        assert_eq!(model.run_state, DashboardRunState::Detached);
        assert!(
            model
                .action(RouterLifecycleAction::StartRouter)
                .expect("start action")
                .enabled
        );
        assert!(
            model
                .action(RouterLifecycleAction::Reattach)
                .expect("reattach action")
                .enabled
        );
        assert!(
            !model
                .action(RouterLifecycleAction::StopDashboardStarted)
                .expect("stop action")
                .enabled
        );
        assert!(
            !model
                .action(RouterLifecycleAction::ShutdownSigned)
                .expect("shutdown action")
                .enabled
        );
    }

    #[test]
    fn browser_cannot_start_local_processes() {
        let model = OperationsHomeModel::new(
            PlatformKind::Browser,
            AttachState::Detached { last_error: None },
            CapabilitySet::unsupported(),
            Some(&local_target()),
        );

        let start = model
            .action(RouterLifecycleAction::StartRouter)
            .expect("start action");
        assert!(!start.enabled);
        assert!(
            start
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("Browsers cannot start local processes")
        );
    }

    #[test]
    fn external_engine_disables_stop_but_allows_signed_shutdown() {
        let profile = fixtures::ndnrs_profile(PlatformKind::Desktop);
        let model = OperationsHomeModel::new(
            PlatformKind::Desktop,
            AttachState::Attached {
                binding: EngineBinding {
                    profile: profile.clone(),
                    ownership: EngineOwnership::External,
                    target_label: Some("local ndn-fwd".into()),
                    attached_at_unix_s: Some(1_717_300_000),
                },
            },
            profile.capabilities,
            Some(&local_target()),
        );

        assert_eq!(model.run_state, DashboardRunState::Attached);
        assert!(
            !model
                .action(RouterLifecycleAction::StopDashboardStarted)
                .expect("stop action")
                .enabled
        );
        assert!(
            model
                .action(RouterLifecycleAction::ShutdownSigned)
                .expect("shutdown action")
                .enabled
        );
    }

    #[test]
    fn dashboard_started_engine_enables_stop() {
        let profile = fixtures::ndnrs_profile(PlatformKind::Desktop);
        let model = OperationsHomeModel::new(
            PlatformKind::Desktop,
            AttachState::Attached {
                binding: EngineBinding {
                    profile: profile.clone(),
                    ownership: EngineOwnership::DashboardStarted,
                    target_label: Some("local ndn-fwd".into()),
                    attached_at_unix_s: Some(1_717_300_000),
                },
            },
            profile.capabilities,
            Some(&local_target()),
        );

        assert!(
            model
                .action(RouterLifecycleAction::StopDashboardStarted)
                .expect("stop action")
                .enabled
        );
    }

    #[test]
    fn start_router_model_blocks_browser_startup() {
        let draft = RouterConfigDraft::preset(crate::config::ConfigPreset::BrowserSandbox);
        let model = StartRouterModalModel::new(
            PlatformKind::Browser,
            StartRouterTab::QuickStart,
            draft.clone(),
            draft,
        );

        assert!(!model.can_start);
        assert!(
            model
                .blocker
                .as_deref()
                .unwrap_or_default()
                .contains("Browsers cannot spawn local ndn-fwd")
        );
    }

    #[test]
    fn start_router_model_allows_desktop_toml_preview() {
        let draft = RouterConfigDraft::preset(crate::config::ConfigPreset::LocalLab);
        let model = StartRouterModalModel::new(
            PlatformKind::Desktop,
            StartRouterTab::QuickStart,
            draft.clone(),
            draft,
        );

        assert!(model.can_start);
        assert!(model.preview_toml.contains("router_name"));
    }
}
