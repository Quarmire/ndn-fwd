//! Mutation command preflight and safety gates.
//!
//! Dashboard mutations are modeled before they are executed so browser,
//! compatibility, and trust constraints can be shown consistently.

use crate::core::{AttachMode, FeatureState, ForwarderKind, ForwarderProfile, TrustPosture};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MutationOperation {
    AdoptTrustContext,
    EnrollCertificate,
    ApproveTrustRequest,
    RejectTrustRequest,
    ImportSafeBag,
    ReviewSchemaChange,
    CreateFace,
    DestroyFace,
    AddRoute,
    RemoveRoute,
    SetStrategy,
    UnsetStrategy,
    SetCsCapacity,
    EraseCs,
    ShutdownForwarder,
    ReconnectForwarder,
}

impl MutationOperation {
    pub fn label(self) -> &'static str {
        match self {
            Self::AdoptTrustContext => "adopt trust context",
            Self::EnrollCertificate => "enroll certificate",
            Self::ApproveTrustRequest => "approve request",
            Self::RejectTrustRequest => "reject request",
            Self::ImportSafeBag => "import SafeBag",
            Self::ReviewSchemaChange => "review schema change",
            Self::CreateFace => "create face",
            Self::DestroyFace => "destroy face",
            Self::AddRoute => "add route",
            Self::RemoveRoute => "remove route",
            Self::SetStrategy => "set strategy",
            Self::UnsetStrategy => "unset strategy",
            Self::SetCsCapacity => "set CS capacity",
            Self::EraseCs => "erase CS",
            Self::ShutdownForwarder => "shutdown forwarder",
            Self::ReconnectForwarder => "reconnect forwarder",
        }
    }

    pub fn requires_trust_context(self) -> bool {
        matches!(
            self,
            Self::AdoptTrustContext
                | Self::EnrollCertificate
                | Self::ApproveTrustRequest
                | Self::RejectTrustRequest
                | Self::ImportSafeBag
                | Self::ReviewSchemaChange
        )
    }

    pub fn requires_signed_management(self) -> bool {
        !matches!(self, Self::ReconnectForwarder)
    }

    pub fn requires_ndnrs_native(self) -> bool {
        matches!(
            self,
            Self::AdoptTrustContext
                | Self::EnrollCertificate
                | Self::ApproveTrustRequest
                | Self::RejectTrustRequest
                | Self::ReviewSchemaChange
        )
    }

    pub fn is_destructive(self) -> bool {
        matches!(
            self,
            Self::DestroyFace
                | Self::RemoveRoute
                | Self::UnsetStrategy
                | Self::EraseCs
                | Self::ShutdownForwarder
                | Self::ImportSafeBag
                | Self::ReviewSchemaChange
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreflightStatus {
    Ready,
    NeedsConfirmation,
    Blocked,
}

impl PreflightStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::NeedsConfirmation => "confirm",
            Self::Blocked => "blocked",
        }
    }

    pub fn allows_execution(self) -> bool {
        matches!(self, Self::Ready | Self::NeedsConfirmation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreflightCheck {
    pub label: &'static str,
    pub passed: bool,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutationPreflight {
    pub operation: MutationOperation,
    pub status: PreflightStatus,
    pub checks: Vec<PreflightCheck>,
}

impl MutationPreflight {
    pub fn can_execute(&self) -> bool {
        self.status.allows_execution()
    }

    pub fn summary(&self) -> &'static str {
        match self.status {
            PreflightStatus::Ready => "All required gates passed.",
            PreflightStatus::NeedsConfirmation => "Ready after explicit operator confirmation.",
            PreflightStatus::Blocked => "Blocked until the failed gates are resolved.",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MutationStatus {
    Pending,
    Running,
    Complete,
    Failed,
    Retryable,
    Blocked,
}

impl MutationStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Complete => "complete",
            Self::Failed => "failed",
            Self::Retryable => "retry",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutationRecord {
    pub operation: MutationOperation,
    pub target: String,
    pub status: MutationStatus,
    pub result: String,
    pub preflight: MutationPreflight,
    pub command: Option<TypedMutationCommand>,
    pub attempts: u8,
}

impl MutationRecord {
    pub fn pending(
        operation: MutationOperation,
        target: impl Into<String>,
        preflight: MutationPreflight,
    ) -> Self {
        Self {
            operation,
            target: target.into(),
            status: MutationStatus::Pending,
            result: "queued".into(),
            preflight,
            command: None,
            attempts: 0,
        }
    }

    pub fn for_command(command: TypedMutationCommand, preflight: MutationPreflight) -> Self {
        Self {
            operation: command.operation(),
            target: command.target(),
            status: MutationStatus::Pending,
            result: "queued".into(),
            preflight,
            command: Some(command),
            attempts: 0,
        }
    }

    pub fn running(mut self) -> Self {
        self.status = MutationStatus::Running;
        self.result = "executing management command".into();
        self.attempts = self.attempts.saturating_add(1);
        self
    }

    fn blocked(
        operation: MutationOperation,
        target: impl Into<String>,
        preflight: MutationPreflight,
    ) -> Self {
        Self {
            operation,
            target: target.into(),
            status: MutationStatus::Blocked,
            result: preflight.summary().into(),
            preflight,
            command: None,
            attempts: 0,
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn complete(
        operation: MutationOperation,
        target: impl Into<String>,
        result: impl Into<String>,
        preflight: MutationPreflight,
    ) -> Self {
        Self {
            operation,
            target: target.into(),
            status: MutationStatus::Complete,
            result: result.into(),
            preflight,
            command: None,
            attempts: 1,
        }
    }

    fn complete_session_action(
        operation: MutationOperation,
        target: impl Into<String>,
        result: impl Into<String>,
        preflight: MutationPreflight,
    ) -> Self {
        Self {
            operation,
            target: target.into(),
            status: MutationStatus::Complete,
            result: result.into(),
            preflight,
            command: None,
            attempts: 1,
        }
    }

    fn failed(
        operation: MutationOperation,
        target: impl Into<String>,
        error: impl Into<String>,
        preflight: MutationPreflight,
    ) -> Self {
        Self {
            operation,
            target: target.into(),
            status: MutationStatus::Failed,
            result: error.into(),
            preflight,
            command: None,
            attempts: 1,
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn retryable(
        operation: MutationOperation,
        target: impl Into<String>,
        error: impl Into<String>,
        preflight: MutationPreflight,
    ) -> Self {
        Self {
            operation,
            target: target.into(),
            status: MutationStatus::Retryable,
            result: error.into(),
            preflight,
            command: None,
            attempts: 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaceCreateCommand {
    pub uri: String,
    pub mtu: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaceDestroyCommand {
    pub face_id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteAddCommand {
    pub prefix: String,
    pub face_id: Option<u64>,
    pub cost: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteRemoveCommand {
    pub prefix: String,
    pub face_id: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrategySetCommand {
    pub prefix: String,
    pub strategy: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrategyUnsetCommand {
    pub prefix: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CsCapacityCommand {
    pub capacity_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CsEraseCommand {
    pub prefix: String,
    pub count: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShutdownForwarderCommand {
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconnectForwarderCommand {
    pub endpoint: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypedMutationCommand {
    FaceCreate(FaceCreateCommand),
    FaceDestroy(FaceDestroyCommand),
    RouteAdd(RouteAddCommand),
    RouteRemove(RouteRemoveCommand),
    StrategySet(StrategySetCommand),
    StrategyUnset(StrategyUnsetCommand),
    CsCapacity(CsCapacityCommand),
    CsErase(CsEraseCommand),
    ShutdownForwarder(ShutdownForwarderCommand),
    ReconnectForwarder(ReconnectForwarderCommand),
}

impl TypedMutationCommand {
    pub fn operation(&self) -> MutationOperation {
        match self {
            Self::FaceCreate(_) => MutationOperation::CreateFace,
            Self::FaceDestroy(_) => MutationOperation::DestroyFace,
            Self::RouteAdd(_) => MutationOperation::AddRoute,
            Self::RouteRemove(_) => MutationOperation::RemoveRoute,
            Self::StrategySet(_) => MutationOperation::SetStrategy,
            Self::StrategyUnset(_) => MutationOperation::UnsetStrategy,
            Self::CsCapacity(_) => MutationOperation::SetCsCapacity,
            Self::CsErase(_) => MutationOperation::EraseCs,
            Self::ShutdownForwarder(_) => MutationOperation::ShutdownForwarder,
            Self::ReconnectForwarder(_) => MutationOperation::ReconnectForwarder,
        }
    }

    pub fn target(&self) -> String {
        match self {
            Self::FaceCreate(command) => command.uri.clone(),
            Self::FaceDestroy(command) => format!("face {}", command.face_id),
            Self::RouteAdd(command) => route_target(&command.prefix, command.face_id),
            Self::RouteRemove(command) => route_target(&command.prefix, command.face_id),
            Self::StrategySet(command) => strategy_target(&command.prefix, Some(&command.strategy)),
            Self::StrategyUnset(command) => strategy_target(&command.prefix, None),
            Self::CsCapacity(command) => cs_capacity_target(command.capacity_bytes),
            Self::CsErase(command) => cs_erase_target(&command.prefix, command.count),
            Self::ShutdownForwarder(command) => {
                if command.reason.trim().is_empty() {
                    "local forwarder".into()
                } else {
                    format!("local forwarder: {}", command.reason.trim())
                }
            }
            Self::ReconnectForwarder(command) => command.endpoint.clone(),
        }
    }

    pub fn replayable(&self) -> bool {
        !matches!(
            self,
            Self::ShutdownForwarder(_) | Self::ReconnectForwarder(_)
        )
    }

    pub fn session_line(&self) -> String {
        match self {
            Self::FaceCreate(command) => format!(
                "face/create uri={} mtu={}",
                command.uri,
                command
                    .mtu
                    .map(|mtu| mtu.to_string())
                    .unwrap_or_else(|| "auto".into())
            ),
            Self::FaceDestroy(command) => format!("faces/destroy face_id={}", command.face_id),
            Self::RouteAdd(command) => format!(
                "rib/register prefix={} face={} cost={}",
                command.prefix,
                command
                    .face_id
                    .map(|face_id| face_id.to_string())
                    .unwrap_or_else(|| "requesting".into()),
                command.cost
            ),
            Self::RouteRemove(command) => format!(
                "rib/unregister prefix={} face={}",
                command.prefix,
                command
                    .face_id
                    .map(|face_id| face_id.to_string())
                    .unwrap_or_else(|| "requesting".into())
            ),
            Self::StrategySet(command) => {
                format!(
                    "strategy-choice/set prefix={} strategy={}",
                    command.prefix, command.strategy
                )
            }
            Self::StrategyUnset(command) => {
                format!("strategy-choice/unset prefix={}", command.prefix)
            }
            Self::CsCapacity(command) => format!("cs/config capacity={}", command.capacity_bytes),
            Self::CsErase(command) => format!(
                "cs/erase prefix={} count={}",
                command.prefix,
                command
                    .count
                    .map(|count| count.to_string())
                    .unwrap_or_else(|| "all".into())
            ),
            Self::ShutdownForwarder(command) => {
                format!("status/shutdown reason={}", command.reason.trim())
            }
            Self::ReconnectForwarder(command) => {
                format!("session/reconnect endpoint={}", command.endpoint)
            }
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MutationSession {
    pub commands: Vec<TypedMutationCommand>,
}

impl MutationSession {
    pub fn record(&mut self, command: TypedMutationCommand) {
        if command.replayable() {
            self.commands.push(command);
        }
    }

    pub fn export_lines(&self) -> Vec<String> {
        self.commands
            .iter()
            .map(TypedMutationCommand::session_line)
            .collect()
    }
}

pub async fn execute_face_create(
    profile: ForwarderProfile,
    trust: TrustPosture,
    command: FaceCreateCommand,
) -> MutationRecord {
    let preflight = preflight_mutation(&profile, trust, MutationOperation::CreateFace);
    let target = command.uri.clone();
    if !preflight.can_execute() {
        return MutationRecord::blocked(MutationOperation::CreateFace, target, preflight);
    }
    execute_face_create_inner(profile, command, preflight).await
}

pub async fn execute_face_destroy(
    profile: ForwarderProfile,
    trust: TrustPosture,
    command: FaceDestroyCommand,
) -> MutationRecord {
    let preflight = preflight_mutation(&profile, trust, MutationOperation::DestroyFace);
    let target = format!("face {}", command.face_id);
    if !preflight.can_execute() {
        return MutationRecord::blocked(MutationOperation::DestroyFace, target, preflight);
    }
    execute_face_destroy_inner(profile, command, preflight).await
}

pub async fn execute_route_add(
    profile: ForwarderProfile,
    trust: TrustPosture,
    command: RouteAddCommand,
) -> MutationRecord {
    let preflight = preflight_mutation(&profile, trust, MutationOperation::AddRoute);
    let target = route_target(&command.prefix, command.face_id);
    if !preflight.can_execute() {
        return MutationRecord::blocked(MutationOperation::AddRoute, target, preflight);
    }
    execute_route_add_inner(profile, command, preflight).await
}

pub async fn execute_route_remove(
    profile: ForwarderProfile,
    trust: TrustPosture,
    command: RouteRemoveCommand,
) -> MutationRecord {
    let preflight = preflight_mutation(&profile, trust, MutationOperation::RemoveRoute);
    let target = route_target(&command.prefix, command.face_id);
    if !preflight.can_execute() {
        return MutationRecord::blocked(MutationOperation::RemoveRoute, target, preflight);
    }
    execute_route_remove_inner(profile, command, preflight).await
}

pub async fn execute_strategy_set(
    profile: ForwarderProfile,
    trust: TrustPosture,
    command: StrategySetCommand,
) -> MutationRecord {
    let preflight = preflight_mutation(&profile, trust, MutationOperation::SetStrategy);
    let target = strategy_target(&command.prefix, Some(&command.strategy));
    if !preflight.can_execute() {
        return MutationRecord::blocked(MutationOperation::SetStrategy, target, preflight);
    }
    execute_strategy_set_inner(profile, command, preflight).await
}

pub async fn execute_strategy_unset(
    profile: ForwarderProfile,
    trust: TrustPosture,
    command: StrategyUnsetCommand,
) -> MutationRecord {
    let preflight = preflight_mutation(&profile, trust, MutationOperation::UnsetStrategy);
    let target = strategy_target(&command.prefix, None);
    if !preflight.can_execute() {
        return MutationRecord::blocked(MutationOperation::UnsetStrategy, target, preflight);
    }
    execute_strategy_unset_inner(profile, command, preflight).await
}

pub async fn execute_cs_set_capacity(
    profile: ForwarderProfile,
    trust: TrustPosture,
    command: CsCapacityCommand,
) -> MutationRecord {
    let preflight = preflight_mutation(&profile, trust, MutationOperation::SetCsCapacity);
    let target = cs_capacity_target(command.capacity_bytes);
    if !preflight.can_execute() {
        return MutationRecord::blocked(MutationOperation::SetCsCapacity, target, preflight);
    }
    execute_cs_set_capacity_inner(profile, command, preflight).await
}

pub async fn execute_cs_erase(
    profile: ForwarderProfile,
    trust: TrustPosture,
    command: CsEraseCommand,
) -> MutationRecord {
    let preflight = preflight_mutation(&profile, trust, MutationOperation::EraseCs);
    let target = cs_erase_target(&command.prefix, command.count);
    if !preflight.can_execute() {
        return MutationRecord::blocked(MutationOperation::EraseCs, target, preflight);
    }
    execute_cs_erase_inner(profile, command, preflight).await
}

pub async fn execute_shutdown_forwarder(
    profile: ForwarderProfile,
    trust: TrustPosture,
    command: ShutdownForwarderCommand,
) -> MutationRecord {
    let preflight = preflight_mutation(&profile, trust, MutationOperation::ShutdownForwarder);
    let target = TypedMutationCommand::ShutdownForwarder(command.clone()).target();
    if !preflight.can_execute() {
        return MutationRecord::blocked(MutationOperation::ShutdownForwarder, target, preflight);
    }
    execute_shutdown_forwarder_inner(profile, command, preflight).await
}

pub async fn execute_reconnect_forwarder(
    profile: ForwarderProfile,
    trust: TrustPosture,
    command: ReconnectForwarderCommand,
) -> MutationRecord {
    let preflight = preflight_mutation(&profile, trust, MutationOperation::ReconnectForwarder);
    let target = command.endpoint.clone();
    if !preflight.can_execute() {
        return MutationRecord::blocked(MutationOperation::ReconnectForwarder, target, preflight);
    }
    let _ = (profile, trust);
    MutationRecord::complete_session_action(
        MutationOperation::ReconnectForwarder,
        target,
        "reconnect requested; attach probe will refresh dashboard state",
        preflight,
    )
}

pub async fn execute_typed_mutation(
    profile: ForwarderProfile,
    trust: TrustPosture,
    command: TypedMutationCommand,
) -> MutationRecord {
    match command {
        TypedMutationCommand::FaceCreate(command) => {
            execute_face_create(profile, trust, command).await
        }
        TypedMutationCommand::FaceDestroy(command) => {
            execute_face_destroy(profile, trust, command).await
        }
        TypedMutationCommand::RouteAdd(command) => execute_route_add(profile, trust, command).await,
        TypedMutationCommand::RouteRemove(command) => {
            execute_route_remove(profile, trust, command).await
        }
        TypedMutationCommand::StrategySet(command) => {
            execute_strategy_set(profile, trust, command).await
        }
        TypedMutationCommand::StrategyUnset(command) => {
            execute_strategy_unset(profile, trust, command).await
        }
        TypedMutationCommand::CsCapacity(command) => {
            execute_cs_set_capacity(profile, trust, command).await
        }
        TypedMutationCommand::CsErase(command) => execute_cs_erase(profile, trust, command).await,
        TypedMutationCommand::ShutdownForwarder(command) => {
            execute_shutdown_forwarder(profile, trust, command).await
        }
        TypedMutationCommand::ReconnectForwarder(command) => {
            execute_reconnect_forwarder(profile, trust, command).await
        }
    }
}

pub fn preflight_mutation(
    profile: &ForwarderProfile,
    trust: TrustPosture,
    operation: MutationOperation,
) -> MutationPreflight {
    let mut checks = Vec::new();

    checks.push(PreflightCheck {
        label: "target",
        passed: profile.capabilities.nfd_basic == FeatureState::Enabled,
        detail: match profile.capabilities.nfd_basic {
            FeatureState::Enabled => "management writes supported".into(),
            FeatureState::ReadOnly => "compatible target is read-only in dashboard-next".into(),
            state => format!("management writes are {}", state.label()),
        },
    });

    if operation.requires_ndnrs_native() {
        checks.push(PreflightCheck {
            label: "native",
            passed: profile.capabilities.ndnrs_native == FeatureState::Enabled,
            detail: match profile.capabilities.ndnrs_native {
                FeatureState::Enabled => "ndn-rs native mutation surface available".into(),
                FeatureState::Degraded => "native mutation surface is sandbox-limited".into(),
                state => format!("native mutation surface is {}", state.label()),
            },
        });
    }

    if operation.requires_trust_context() {
        checks.push(PreflightCheck {
            label: "trust context",
            passed: profile.capabilities.trust_context == FeatureState::Enabled,
            detail: match profile.capabilities.trust_context {
                FeatureState::Enabled => "TrustContext API available".into(),
                FeatureState::Degraded => {
                    "TrustContext API is degraded; mutation stays disabled".into()
                }
                state => format!("TrustContext API is {}", state.label()),
            },
        });
    }

    if operation.requires_signed_management() {
        checks.push(PreflightCheck {
            label: "signature",
            passed: signed_command_ready(trust),
            detail: signed_command_detail(trust).into(),
        });
    }

    checks.push(PreflightCheck {
        label: "platform",
        passed: platform_allows(profile, operation),
        detail: platform_detail(profile, operation).into(),
    });

    let blocked = checks.iter().any(|check| !check.passed);
    let status = if blocked {
        PreflightStatus::Blocked
    } else if operation.is_destructive()
        || matches!(
            operation,
            MutationOperation::AdoptTrustContext
                | MutationOperation::EnrollCertificate
                | MutationOperation::ApproveTrustRequest
                | MutationOperation::RejectTrustRequest
        )
    {
        PreflightStatus::NeedsConfirmation
    } else {
        PreflightStatus::Ready
    };

    MutationPreflight {
        operation,
        status,
        checks,
    }
}

fn signed_command_ready(trust: TrustPosture) -> bool {
    matches!(trust, TrustPosture::Valid | TrustPosture::Weakened)
}

fn signed_command_detail(trust: TrustPosture) -> &'static str {
    match trust {
        TrustPosture::Valid => "active signing identity is trusted",
        TrustPosture::Weakened => "signed command possible, but schema review is required",
        TrustPosture::Ephemeral => "identity must be persisted before signing management commands",
        TrustPosture::Expired => "certificate is expired",
        TrustPosture::None => "no signing identity is available",
        TrustPosture::Unsupported => "target has no TrustContext-backed signing posture",
        TrustPosture::Error => "trust error must be resolved before signing",
    }
}

fn platform_allows(profile: &ForwarderProfile, operation: MutationOperation) -> bool {
    match (profile.attach_mode, operation) {
        (
            AttachMode::BrowserEngine | AttachMode::RemoteWeb | AttachMode::Relay,
            MutationOperation::CreateFace
            | MutationOperation::DestroyFace
            | MutationOperation::AddRoute
            | MutationOperation::RemoveRoute
            | MutationOperation::SetStrategy
            | MutationOperation::UnsetStrategy
            | MutationOperation::SetCsCapacity
            | MutationOperation::EraseCs,
        ) => false,
        (AttachMode::RemoteWeb, MutationOperation::ShutdownForwarder) => false,
        (AttachMode::BrowserEngine, MutationOperation::ShutdownForwarder) => false,
        (AttachMode::BrowserEngine, MutationOperation::ImportSafeBag) => false,
        (_, MutationOperation::ReconnectForwarder) => true,
        _ => profile.kind != ForwarderKind::Unknown,
    }
}

fn platform_detail(profile: &ForwarderProfile, operation: MutationOperation) -> &'static str {
    match (profile.attach_mode, operation) {
        (
            AttachMode::BrowserEngine | AttachMode::RemoteWeb | AttachMode::Relay,
            MutationOperation::CreateFace
            | MutationOperation::DestroyFace
            | MutationOperation::AddRoute
            | MutationOperation::RemoveRoute
            | MutationOperation::SetStrategy
            | MutationOperation::UnsetStrategy
            | MutationOperation::SetCsCapacity
            | MutationOperation::EraseCs,
        ) => "browser/relay mutation transport adapter is not wired yet",
        (AttachMode::RemoteWeb, MutationOperation::ShutdownForwarder) => {
            "remote browser attach cannot shut down the forwarder"
        }
        (AttachMode::BrowserEngine, MutationOperation::ShutdownForwarder) => {
            "browser engine sessions are stopped by closing the runtime"
        }
        (AttachMode::BrowserEngine, MutationOperation::ImportSafeBag) => {
            "browser SafeBag import requires an external custodian handoff"
        }
        (_, MutationOperation::ReconnectForwarder) => "reconnect is a dashboard session action",
        _ if profile.kind == ForwarderKind::Unknown => "attach target is unknown",
        _ => "platform path is available",
    }
}

fn route_target(prefix: &str, face_id: Option<u64>) -> String {
    match face_id {
        Some(face_id) => format!("{prefix} via face {face_id}"),
        None => format!("{prefix} via requesting face"),
    }
}

fn strategy_target(prefix: &str, strategy: Option<&str>) -> String {
    match strategy {
        Some(strategy) => format!("{prefix} -> {strategy}"),
        None => format!("{prefix} strategy"),
    }
}

fn cs_capacity_target(capacity_bytes: u64) -> String {
    format!("{capacity_bytes} bytes")
}

fn cs_erase_target(prefix: &str, count: Option<u64>) -> String {
    match count {
        Some(count) => format!("{prefix} limit {count}"),
        None => format!("{prefix} all matches"),
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn execute_face_create_inner(
    profile: ForwarderProfile,
    command: FaceCreateCommand,
    preflight: MutationPreflight,
) -> MutationRecord {
    let socket = desktop_socket(&profile);
    let client = match ndn_ipc::MgmtClient::connect(&socket).await {
        Ok(client) => client,
        Err(error) => {
            return MutationRecord::retryable(
                MutationOperation::CreateFace,
                command.uri,
                format!("connect {socket}: {error}"),
                preflight,
            );
        }
    };
    let result = match command.mtu {
        Some(mtu) => client.face_create_with_mtu(&command.uri, Some(mtu)).await,
        None => client.face_create(&command.uri).await,
    };
    match result {
        Ok(params) => MutationRecord::complete(
            MutationOperation::CreateFace,
            command.uri,
            format!(
                "face {} created{}",
                params
                    .face_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "unknown".into()),
                params
                    .uri
                    .as_ref()
                    .map(|uri| format!(" for {uri}"))
                    .unwrap_or_default()
            ),
            preflight,
        ),
        Err(error) => MutationRecord::failed(
            MutationOperation::CreateFace,
            command.uri,
            format!("faces/create failed: {error}"),
            preflight,
        ),
    }
}

#[cfg(target_arch = "wasm32")]
async fn execute_face_create_inner(
    _profile: ForwarderProfile,
    command: FaceCreateCommand,
    preflight: MutationPreflight,
) -> MutationRecord {
    MutationRecord::failed(
        MutationOperation::CreateFace,
        command.uri,
        "desktop IPC adapter is unavailable in browser builds",
        preflight,
    )
}

#[cfg(not(target_arch = "wasm32"))]
async fn execute_face_destroy_inner(
    profile: ForwarderProfile,
    command: FaceDestroyCommand,
    preflight: MutationPreflight,
) -> MutationRecord {
    let socket = desktop_socket(&profile);
    let client = match ndn_ipc::MgmtClient::connect(&socket).await {
        Ok(client) => client,
        Err(error) => {
            return MutationRecord::retryable(
                MutationOperation::DestroyFace,
                format!("face {}", command.face_id),
                format!("connect {socket}: {error}"),
                preflight,
            );
        }
    };
    match client.face_destroy(command.face_id).await {
        Ok(params) => MutationRecord::complete(
            MutationOperation::DestroyFace,
            format!("face {}", command.face_id),
            format!(
                "face {} destroyed",
                params.face_id.unwrap_or(command.face_id)
            ),
            preflight,
        ),
        Err(error) => MutationRecord::failed(
            MutationOperation::DestroyFace,
            format!("face {}", command.face_id),
            format!("faces/destroy failed: {error}"),
            preflight,
        ),
    }
}

#[cfg(target_arch = "wasm32")]
async fn execute_face_destroy_inner(
    _profile: ForwarderProfile,
    command: FaceDestroyCommand,
    preflight: MutationPreflight,
) -> MutationRecord {
    MutationRecord::failed(
        MutationOperation::DestroyFace,
        format!("face {}", command.face_id),
        "desktop IPC adapter is unavailable in browser builds",
        preflight,
    )
}

#[cfg(not(target_arch = "wasm32"))]
fn desktop_socket(profile: &ForwarderProfile) -> String {
    profile
        .endpoint
        .strip_prefix("unix://")
        .unwrap_or(&profile.endpoint)
        .to_string()
}

#[cfg(not(target_arch = "wasm32"))]
async fn execute_route_add_inner(
    profile: ForwarderProfile,
    command: RouteAddCommand,
    preflight: MutationPreflight,
) -> MutationRecord {
    let target = route_target(&command.prefix, command.face_id);
    let prefix = match command.prefix.parse::<ndn_packet::Name>() {
        Ok(prefix) => prefix,
        Err(error) => {
            return MutationRecord::failed(
                MutationOperation::AddRoute,
                target,
                format!("invalid prefix: {error}"),
                preflight,
            );
        }
    };
    let socket = desktop_socket(&profile);
    let client = match ndn_ipc::MgmtClient::connect(&socket).await {
        Ok(client) => client,
        Err(error) => {
            return MutationRecord::retryable(
                MutationOperation::AddRoute,
                target,
                format!("connect {socket}: {error}"),
                preflight,
            );
        }
    };
    match client
        .route_add(&prefix, command.face_id, command.cost)
        .await
    {
        Ok(params) => MutationRecord::complete(
            MutationOperation::AddRoute,
            route_target(&command.prefix, command.face_id),
            format!(
                "route {} registered via face {} cost {}",
                params
                    .name
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or(command.prefix),
                params
                    .face_id
                    .map(|face_id| face_id.to_string())
                    .unwrap_or_else(|| "requesting".into()),
                params.cost.unwrap_or(command.cost)
            ),
            preflight,
        ),
        Err(error) => MutationRecord::failed(
            MutationOperation::AddRoute,
            target,
            format!("rib/register failed: {error}"),
            preflight,
        ),
    }
}

#[cfg(target_arch = "wasm32")]
async fn execute_route_add_inner(
    _profile: ForwarderProfile,
    command: RouteAddCommand,
    preflight: MutationPreflight,
) -> MutationRecord {
    MutationRecord::failed(
        MutationOperation::AddRoute,
        route_target(&command.prefix, command.face_id),
        "desktop IPC adapter is unavailable in browser builds",
        preflight,
    )
}

#[cfg(not(target_arch = "wasm32"))]
async fn execute_route_remove_inner(
    profile: ForwarderProfile,
    command: RouteRemoveCommand,
    preflight: MutationPreflight,
) -> MutationRecord {
    let target = route_target(&command.prefix, command.face_id);
    let prefix = match command.prefix.parse::<ndn_packet::Name>() {
        Ok(prefix) => prefix,
        Err(error) => {
            return MutationRecord::failed(
                MutationOperation::RemoveRoute,
                target,
                format!("invalid prefix: {error}"),
                preflight,
            );
        }
    };
    let socket = desktop_socket(&profile);
    let client = match ndn_ipc::MgmtClient::connect(&socket).await {
        Ok(client) => client,
        Err(error) => {
            return MutationRecord::retryable(
                MutationOperation::RemoveRoute,
                target,
                format!("connect {socket}: {error}"),
                preflight,
            );
        }
    };
    match client.route_remove(&prefix, command.face_id).await {
        Ok(params) => MutationRecord::complete(
            MutationOperation::RemoveRoute,
            route_target(&command.prefix, command.face_id),
            format!(
                "route {} unregistered from face {}",
                params
                    .name
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or(command.prefix),
                params
                    .face_id
                    .map(|face_id| face_id.to_string())
                    .unwrap_or_else(|| "requesting".into())
            ),
            preflight,
        ),
        Err(error) => MutationRecord::failed(
            MutationOperation::RemoveRoute,
            target,
            format!("rib/unregister failed: {error}"),
            preflight,
        ),
    }
}

#[cfg(target_arch = "wasm32")]
async fn execute_route_remove_inner(
    _profile: ForwarderProfile,
    command: RouteRemoveCommand,
    preflight: MutationPreflight,
) -> MutationRecord {
    MutationRecord::failed(
        MutationOperation::RemoveRoute,
        route_target(&command.prefix, command.face_id),
        "desktop IPC adapter is unavailable in browser builds",
        preflight,
    )
}

#[cfg(not(target_arch = "wasm32"))]
async fn execute_strategy_set_inner(
    profile: ForwarderProfile,
    command: StrategySetCommand,
    preflight: MutationPreflight,
) -> MutationRecord {
    let target = strategy_target(&command.prefix, Some(&command.strategy));
    let prefix = match command.prefix.parse::<ndn_packet::Name>() {
        Ok(prefix) => prefix,
        Err(error) => {
            return MutationRecord::failed(
                MutationOperation::SetStrategy,
                target,
                format!("invalid prefix: {error}"),
                preflight,
            );
        }
    };
    let strategy = match command.strategy.parse::<ndn_packet::Name>() {
        Ok(strategy) => strategy,
        Err(error) => {
            return MutationRecord::failed(
                MutationOperation::SetStrategy,
                target,
                format!("invalid strategy name: {error}"),
                preflight,
            );
        }
    };
    let socket = desktop_socket(&profile);
    let client = match ndn_ipc::MgmtClient::connect(&socket).await {
        Ok(client) => client,
        Err(error) => {
            return MutationRecord::retryable(
                MutationOperation::SetStrategy,
                target,
                format!("connect {socket}: {error}"),
                preflight,
            );
        }
    };
    match client.strategy_set(&prefix, &strategy).await {
        Ok(params) => MutationRecord::complete(
            MutationOperation::SetStrategy,
            strategy_target(&command.prefix, Some(&command.strategy)),
            format!(
                "strategy {} set for {}",
                params
                    .strategy
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or(command.strategy),
                params
                    .name
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or(command.prefix)
            ),
            preflight,
        ),
        Err(error) => MutationRecord::failed(
            MutationOperation::SetStrategy,
            target,
            format!("strategy-choice/set failed: {error}"),
            preflight,
        ),
    }
}

#[cfg(target_arch = "wasm32")]
async fn execute_strategy_set_inner(
    _profile: ForwarderProfile,
    command: StrategySetCommand,
    preflight: MutationPreflight,
) -> MutationRecord {
    MutationRecord::failed(
        MutationOperation::SetStrategy,
        strategy_target(&command.prefix, Some(&command.strategy)),
        "desktop IPC adapter is unavailable in browser builds",
        preflight,
    )
}

#[cfg(not(target_arch = "wasm32"))]
async fn execute_strategy_unset_inner(
    profile: ForwarderProfile,
    command: StrategyUnsetCommand,
    preflight: MutationPreflight,
) -> MutationRecord {
    let target = strategy_target(&command.prefix, None);
    let prefix = match command.prefix.parse::<ndn_packet::Name>() {
        Ok(prefix) => prefix,
        Err(error) => {
            return MutationRecord::failed(
                MutationOperation::UnsetStrategy,
                target,
                format!("invalid prefix: {error}"),
                preflight,
            );
        }
    };
    let socket = desktop_socket(&profile);
    let client = match ndn_ipc::MgmtClient::connect(&socket).await {
        Ok(client) => client,
        Err(error) => {
            return MutationRecord::retryable(
                MutationOperation::UnsetStrategy,
                target,
                format!("connect {socket}: {error}"),
                preflight,
            );
        }
    };
    match client.strategy_unset(&prefix).await {
        Ok(params) => MutationRecord::complete(
            MutationOperation::UnsetStrategy,
            strategy_target(&command.prefix, None),
            format!(
                "strategy unset for {}",
                params
                    .name
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or(command.prefix)
            ),
            preflight,
        ),
        Err(error) => MutationRecord::failed(
            MutationOperation::UnsetStrategy,
            target,
            format!("strategy-choice/unset failed: {error}"),
            preflight,
        ),
    }
}

#[cfg(target_arch = "wasm32")]
async fn execute_strategy_unset_inner(
    _profile: ForwarderProfile,
    command: StrategyUnsetCommand,
    preflight: MutationPreflight,
) -> MutationRecord {
    MutationRecord::failed(
        MutationOperation::UnsetStrategy,
        strategy_target(&command.prefix, None),
        "desktop IPC adapter is unavailable in browser builds",
        preflight,
    )
}

#[cfg(not(target_arch = "wasm32"))]
async fn execute_cs_set_capacity_inner(
    profile: ForwarderProfile,
    command: CsCapacityCommand,
    preflight: MutationPreflight,
) -> MutationRecord {
    let target = cs_capacity_target(command.capacity_bytes);
    let socket = desktop_socket(&profile);
    let client = match ndn_ipc::MgmtClient::connect(&socket).await {
        Ok(client) => client,
        Err(error) => {
            return MutationRecord::retryable(
                MutationOperation::SetCsCapacity,
                target,
                format!("connect {socket}: {error}"),
                preflight,
            );
        }
    };
    match client.cs_config(Some(command.capacity_bytes)).await {
        Ok(params) => MutationRecord::complete(
            MutationOperation::SetCsCapacity,
            cs_capacity_target(command.capacity_bytes),
            format!(
                "CS capacity set to {} bytes",
                params.capacity.unwrap_or(command.capacity_bytes)
            ),
            preflight,
        ),
        Err(error) => MutationRecord::failed(
            MutationOperation::SetCsCapacity,
            target,
            format!("cs/config failed: {error}"),
            preflight,
        ),
    }
}

#[cfg(target_arch = "wasm32")]
async fn execute_cs_set_capacity_inner(
    _profile: ForwarderProfile,
    command: CsCapacityCommand,
    preflight: MutationPreflight,
) -> MutationRecord {
    MutationRecord::failed(
        MutationOperation::SetCsCapacity,
        cs_capacity_target(command.capacity_bytes),
        "desktop IPC adapter is unavailable in browser builds",
        preflight,
    )
}

#[cfg(not(target_arch = "wasm32"))]
async fn execute_cs_erase_inner(
    profile: ForwarderProfile,
    command: CsEraseCommand,
    preflight: MutationPreflight,
) -> MutationRecord {
    let target = cs_erase_target(&command.prefix, command.count);
    let prefix = match command.prefix.parse::<ndn_packet::Name>() {
        Ok(prefix) => prefix,
        Err(error) => {
            return MutationRecord::failed(
                MutationOperation::EraseCs,
                target,
                format!("invalid prefix: {error}"),
                preflight,
            );
        }
    };
    let socket = desktop_socket(&profile);
    let client = match ndn_ipc::MgmtClient::connect(&socket).await {
        Ok(client) => client,
        Err(error) => {
            return MutationRecord::retryable(
                MutationOperation::EraseCs,
                target,
                format!("connect {socket}: {error}"),
                preflight,
            );
        }
    };
    match client.cs_erase(&prefix, command.count).await {
        Ok(params) => MutationRecord::complete(
            MutationOperation::EraseCs,
            cs_erase_target(&command.prefix, command.count),
            format!(
                "erased {} CS entries under {}",
                params.count.unwrap_or(0),
                params
                    .name
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or(command.prefix)
            ),
            preflight,
        ),
        Err(error) => MutationRecord::failed(
            MutationOperation::EraseCs,
            target,
            format!("cs/erase failed: {error}"),
            preflight,
        ),
    }
}

#[cfg(target_arch = "wasm32")]
async fn execute_cs_erase_inner(
    _profile: ForwarderProfile,
    command: CsEraseCommand,
    preflight: MutationPreflight,
) -> MutationRecord {
    MutationRecord::failed(
        MutationOperation::EraseCs,
        cs_erase_target(&command.prefix, command.count),
        "desktop IPC adapter is unavailable in browser builds",
        preflight,
    )
}

#[cfg(not(target_arch = "wasm32"))]
async fn execute_shutdown_forwarder_inner(
    profile: ForwarderProfile,
    command: ShutdownForwarderCommand,
    preflight: MutationPreflight,
) -> MutationRecord {
    let target = TypedMutationCommand::ShutdownForwarder(command).target();
    let socket = desktop_socket(&profile);
    let client = match ndn_ipc::MgmtClient::connect(&socket).await {
        Ok(client) => client,
        Err(error) => {
            return MutationRecord::retryable(
                MutationOperation::ShutdownForwarder,
                target,
                format!("connect {socket}: {error}"),
                preflight,
            );
        }
    };
    match client.shutdown().await {
        Ok(response) => MutationRecord::complete(
            MutationOperation::ShutdownForwarder,
            target,
            format!("shutdown accepted: {}", response.status_text),
            preflight,
        ),
        Err(error) => MutationRecord::retryable(
            MutationOperation::ShutdownForwarder,
            target,
            format!("status/shutdown failed: {error}"),
            preflight,
        ),
    }
}

#[cfg(target_arch = "wasm32")]
async fn execute_shutdown_forwarder_inner(
    _profile: ForwarderProfile,
    command: ShutdownForwarderCommand,
    preflight: MutationPreflight,
) -> MutationRecord {
    MutationRecord::failed(
        MutationOperation::ShutdownForwarder,
        TypedMutationCommand::ShutdownForwarder(command).target(),
        "desktop IPC adapter is unavailable in browser builds",
        preflight,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{PlatformKind, fixtures};

    #[test]
    fn ndnrs_valid_identity_allows_face_create() {
        let profile = fixtures::ndnrs_profile(PlatformKind::Desktop);
        let preflight =
            preflight_mutation(&profile, TrustPosture::Valid, MutationOperation::CreateFace);

        assert_eq!(preflight.status, PreflightStatus::Ready);
        assert!(preflight.can_execute());
    }

    #[test]
    fn nfd_compat_profile_blocks_writes_in_milestone_one() {
        let profile = fixtures::nfd_profile();
        let preflight = preflight_mutation(
            &profile,
            TrustPosture::Unsupported,
            MutationOperation::AddRoute,
        );

        assert_eq!(preflight.status, PreflightStatus::Blocked);
        assert!(
            preflight
                .checks
                .iter()
                .any(|check| check.label == "target" && !check.passed)
        );
    }

    #[test]
    fn trust_mutation_requires_native_trust_context() {
        let profile = fixtures::browser_engine_profile();
        let preflight = preflight_mutation(
            &profile,
            TrustPosture::Valid,
            MutationOperation::AdoptTrustContext,
        );

        assert_eq!(preflight.status, PreflightStatus::Blocked);
        assert!(
            preflight
                .checks
                .iter()
                .any(|check| check.label == "trust context" && !check.passed)
        );
    }

    #[test]
    fn destructive_operation_needs_confirmation_after_gates_pass() {
        let profile = fixtures::ndnrs_profile(PlatformKind::Desktop);
        let preflight =
            preflight_mutation(&profile, TrustPosture::Valid, MutationOperation::EraseCs);

        assert_eq!(preflight.status, PreflightStatus::NeedsConfirmation);
        assert!(preflight.can_execute());
    }

    #[test]
    fn expired_identity_blocks_signed_command() {
        let profile = fixtures::ndnrs_profile(PlatformKind::Desktop);
        let preflight = preflight_mutation(
            &profile,
            TrustPosture::Expired,
            MutationOperation::SetStrategy,
        );

        assert_eq!(preflight.status, PreflightStatus::Blocked);
        assert!(
            preflight
                .checks
                .iter()
                .any(|check| check.label == "signature" && !check.passed)
        );
    }

    #[test]
    fn browser_remote_face_create_waits_for_browser_safe_write_adapter() {
        let profile = fixtures::ndnrs_profile(PlatformKind::Browser);
        let preflight =
            preflight_mutation(&profile, TrustPosture::Valid, MutationOperation::CreateFace);

        assert_eq!(preflight.status, PreflightStatus::Blocked);
        assert!(
            preflight
                .checks
                .iter()
                .any(|check| check.label == "platform" && !check.passed)
        );
    }

    #[tokio::test]
    async fn blocked_face_create_returns_record_without_ipc() {
        let profile = fixtures::nfd_profile();
        let record = execute_face_create(
            profile,
            TrustPosture::Unsupported,
            FaceCreateCommand {
                uri: "udp4://127.0.0.1:6363".into(),
                mtu: None,
            },
        )
        .await;

        assert_eq!(record.operation, MutationOperation::CreateFace);
        assert_eq!(record.status, MutationStatus::Blocked);
    }

    #[test]
    fn ndnrs_valid_identity_allows_route_add() {
        let profile = fixtures::ndnrs_profile(PlatformKind::Desktop);
        let preflight =
            preflight_mutation(&profile, TrustPosture::Valid, MutationOperation::AddRoute);

        assert_eq!(preflight.status, PreflightStatus::Ready);
        assert!(preflight.can_execute());
    }

    #[test]
    fn route_remove_needs_confirmation_after_gates_pass() {
        let profile = fixtures::ndnrs_profile(PlatformKind::Desktop);
        let preflight = preflight_mutation(
            &profile,
            TrustPosture::Valid,
            MutationOperation::RemoveRoute,
        );

        assert_eq!(preflight.status, PreflightStatus::NeedsConfirmation);
        assert!(preflight.can_execute());
    }

    #[tokio::test]
    async fn blocked_route_add_returns_record_without_ipc() {
        let profile = fixtures::nfd_profile();
        let record = execute_route_add(
            profile,
            TrustPosture::Unsupported,
            RouteAddCommand {
                prefix: "/ndn/test".into(),
                face_id: Some(7),
                cost: 10,
            },
        )
        .await;

        assert_eq!(record.operation, MutationOperation::AddRoute);
        assert_eq!(record.status, MutationStatus::Blocked);
    }

    #[test]
    fn ndnrs_valid_identity_allows_strategy_set() {
        let profile = fixtures::ndnrs_profile(PlatformKind::Desktop);
        let preflight = preflight_mutation(
            &profile,
            TrustPosture::Valid,
            MutationOperation::SetStrategy,
        );

        assert_eq!(preflight.status, PreflightStatus::Ready);
        assert!(preflight.can_execute());
    }

    #[test]
    fn strategy_unset_needs_confirmation_after_gates_pass() {
        let profile = fixtures::ndnrs_profile(PlatformKind::Desktop);
        let preflight = preflight_mutation(
            &profile,
            TrustPosture::Valid,
            MutationOperation::UnsetStrategy,
        );

        assert_eq!(preflight.status, PreflightStatus::NeedsConfirmation);
        assert!(preflight.can_execute());
    }

    #[tokio::test]
    async fn blocked_strategy_set_returns_record_without_ipc() {
        let profile = fixtures::nfd_profile();
        let record = execute_strategy_set(
            profile,
            TrustPosture::Unsupported,
            StrategySetCommand {
                prefix: "/ndn/test".into(),
                strategy: "/ndn/strategy/best-route/v5".into(),
            },
        )
        .await;

        assert_eq!(record.operation, MutationOperation::SetStrategy);
        assert_eq!(record.status, MutationStatus::Blocked);
    }

    #[test]
    fn ndnrs_valid_identity_allows_cs_capacity_set() {
        let profile = fixtures::ndnrs_profile(PlatformKind::Desktop);
        let preflight = preflight_mutation(
            &profile,
            TrustPosture::Valid,
            MutationOperation::SetCsCapacity,
        );

        assert_eq!(preflight.status, PreflightStatus::Ready);
        assert!(preflight.can_execute());
    }

    #[test]
    fn cs_erase_needs_confirmation_after_gates_pass() {
        let profile = fixtures::ndnrs_profile(PlatformKind::Desktop);
        let preflight =
            preflight_mutation(&profile, TrustPosture::Valid, MutationOperation::EraseCs);

        assert_eq!(preflight.status, PreflightStatus::NeedsConfirmation);
        assert!(preflight.can_execute());
    }

    #[tokio::test]
    async fn blocked_cs_capacity_returns_record_without_ipc() {
        let profile = fixtures::nfd_profile();
        let record = execute_cs_set_capacity(
            profile,
            TrustPosture::Unsupported,
            CsCapacityCommand {
                capacity_bytes: 65_536,
            },
        )
        .await;

        assert_eq!(record.operation, MutationOperation::SetCsCapacity);
        assert_eq!(record.status, MutationStatus::Blocked);
    }

    #[test]
    fn shutdown_needs_confirmation_but_reconnect_is_ready() {
        let profile = fixtures::ndnrs_profile(PlatformKind::Desktop);
        let shutdown = preflight_mutation(
            &profile,
            TrustPosture::Valid,
            MutationOperation::ShutdownForwarder,
        );
        let reconnect = preflight_mutation(
            &profile,
            TrustPosture::Unsupported,
            MutationOperation::ReconnectForwarder,
        );

        assert_eq!(shutdown.status, PreflightStatus::NeedsConfirmation);
        assert_eq!(reconnect.status, PreflightStatus::Ready);
    }

    #[tokio::test]
    async fn missing_desktop_socket_returns_retryable_error() {
        let mut profile = fixtures::ndnrs_profile(PlatformKind::Desktop);
        profile.endpoint = "unix:///private/tmp/ndn-dashboard-next-missing.sock".into();
        let record = execute_shutdown_forwarder(
            profile,
            TrustPosture::Valid,
            ShutdownForwarderCommand {
                reason: "test".into(),
            },
        )
        .await;

        assert_eq!(record.operation, MutationOperation::ShutdownForwarder);
        assert_eq!(record.status, MutationStatus::Retryable);
    }

    #[test]
    fn typed_session_records_replayable_commands_only() {
        let mut session = MutationSession::default();
        session.record(TypedMutationCommand::RouteAdd(RouteAddCommand {
            prefix: "/ndn/test".into(),
            face_id: Some(7),
            cost: 10,
        }));
        session.record(TypedMutationCommand::ShutdownForwarder(
            ShutdownForwarderCommand {
                reason: "operator".into(),
            },
        ));

        assert_eq!(session.commands.len(), 1);
        assert_eq!(
            session.export_lines(),
            vec!["rib/register prefix=/ndn/test face=7 cost=10".to_string()]
        );
    }

    #[test]
    fn typed_command_targets_are_constructed_from_command_fields() {
        assert_eq!(
            TypedMutationCommand::StrategySet(StrategySetCommand {
                prefix: "/ndn/video".into(),
                strategy: "/localhost/nfd/strategy/multicast/v=5".into(),
            })
            .target(),
            "/ndn/video -> /localhost/nfd/strategy/multicast/v=5"
        );
        assert_eq!(
            TypedMutationCommand::CsErase(CsEraseCommand {
                prefix: "/ndn/cache".into(),
                count: Some(3),
            })
            .session_line(),
            "cs/erase prefix=/ndn/cache count=3"
        );
    }
}
