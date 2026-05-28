//! Read-only forwarder engine datasets and view models.

use crate::core::{AttachMode, FeatureState, ForwarderKind, ForwarderProfile};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatasetState {
    Fresh,
    Stale { age_s: u64 },
    Disconnected,
    Unsupported,
}

impl DatasetState {
    pub fn label(self) -> String {
        match self {
            Self::Fresh => "fresh".into(),
            Self::Stale { age_s } => format!("stale {age_s}s"),
            Self::Disconnected => "disconnected".into(),
            Self::Unsupported => "unsupported".into(),
        }
    }

    pub fn tone(self) -> &'static str {
        match self {
            Self::Fresh => "good",
            Self::Stale { .. } => "amber",
            Self::Disconnected => "bad",
            Self::Unsupported => "muted",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatasetSource {
    pub name: &'static str,
    pub state: DatasetState,
    pub last_update_unix_s: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwarderStatusView {
    pub version: String,
    pub uptime_s: u64,
    pub start_unix_s: u64,
    pub n_cs_entries: u64,
    pub n_pit_entries: u64,
    pub n_in_interests: u64,
    pub n_out_interests: u64,
    pub n_in_data: u64,
    pub n_out_data: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaceRow {
    pub id: u64,
    pub uri: String,
    pub scope: String,
    pub persistency: String,
    pub state: String,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

impl FaceRow {
    pub fn traffic_label(&self) -> String {
        format!(
            "{} / {}",
            compact_count(self.rx_packets),
            compact_count(self.tx_packets)
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteRow {
    pub prefix: String,
    pub source: String,
    pub face_id: u64,
    pub cost: u64,
    pub flags: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StrategyRow {
    pub prefix: String,
    pub strategy: String,
    pub inherited: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorePitSummary {
    pub cs_capacity: u64,
    pub cs_entries: u64,
    pub cs_hit_rate_pct: u8,
    pub pit_entries: u64,
    pub pit_satisfied_rate_pct: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficSummary {
    pub interest_in_rate: u64,
    pub interest_out_rate: u64,
    pub data_in_rate: u64,
    pub data_out_rate: u64,
    pub satisfaction_rate_pct: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineSnapshot {
    pub status: Option<ForwarderStatusView>,
    pub faces: Vec<FaceRow>,
    pub routes: Vec<RouteRow>,
    pub strategies: Vec<StrategyRow>,
    pub store_pit: Option<StorePitSummary>,
    pub traffic: Option<TrafficSummary>,
    pub sources: Vec<DatasetSource>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnginePollError {
    pub message: String,
}

impl EnginePollError {
    #[cfg(not(target_arch = "wasm32"))]
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineDetail {
    Face(FaceRow),
    Route(RouteRow),
    Strategy(StrategyRow),
    Empty,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineSummary {
    pub profile_kind: ForwarderKind,
    pub read_only: bool,
    pub status: Option<ForwarderStatusView>,
    pub faces: Vec<FaceRow>,
    pub routes: Vec<RouteRow>,
    pub strategies: Vec<StrategyRow>,
    pub store_pit: Option<StorePitSummary>,
    pub traffic: Option<TrafficSummary>,
    pub sources: Vec<DatasetSource>,
    pub detail: EngineDetail,
}

impl EngineSummary {
    pub fn from_snapshot(profile: &ForwarderProfile, snapshot: EngineSnapshot) -> Self {
        let read_only = profile.capabilities.nfd_basic == FeatureState::ReadOnly
            || matches!(profile.kind, ForwarderKind::Nfd | ForwarderKind::YaNfd);
        let detail = snapshot
            .faces
            .first()
            .cloned()
            .map(EngineDetail::Face)
            .or_else(|| snapshot.routes.first().cloned().map(EngineDetail::Route))
            .unwrap_or(EngineDetail::Empty);

        Self {
            profile_kind: profile.kind,
            read_only,
            status: snapshot.status,
            faces: snapshot.faces,
            routes: snapshot.routes,
            strategies: snapshot.strategies,
            store_pit: snapshot.store_pit,
            traffic: snapshot.traffic,
            sources: snapshot.sources,
            detail,
        }
    }

    pub fn mock(profile: &ForwarderProfile) -> Self {
        Self::from_snapshot(profile, EngineSnapshot::mock(profile))
    }

    pub fn filter_faces(&self, query: &str) -> Vec<FaceRow> {
        let query = query.trim().to_lowercase();
        if query.is_empty() {
            return self.faces.clone();
        }
        self.faces
            .iter()
            .filter(|face| {
                face.uri.to_lowercase().contains(&query)
                    || face.id.to_string() == query
                    || face.state.to_lowercase().contains(&query)
            })
            .cloned()
            .collect()
    }

    pub fn search_routes(&self, prefix_query: &str) -> Vec<RouteRow> {
        let query = prefix_query.trim().to_lowercase();
        if query.is_empty() {
            return self.routes.clone();
        }
        self.routes
            .iter()
            .filter(|route| route.prefix.to_lowercase().contains(&query))
            .cloned()
            .collect()
    }

    pub fn disconnected(profile: &ForwarderProfile) -> Self {
        Self::from_snapshot(
            profile,
            EngineSnapshot {
                status: None,
                faces: Vec::new(),
                routes: Vec::new(),
                strategies: Vec::new(),
                store_pit: None,
                traffic: None,
                sources: standard_sources(DatasetState::Disconnected),
            },
        )
    }
}

impl EngineSnapshot {
    pub fn mock(profile: &ForwarderProfile) -> Self {
        match profile.kind {
            ForwarderKind::Unknown => Self {
                status: None,
                faces: Vec::new(),
                routes: Vec::new(),
                strategies: Vec::new(),
                store_pit: None,
                traffic: None,
                sources: standard_sources(DatasetState::Unsupported),
            },
            ForwarderKind::Nfd | ForwarderKind::YaNfd => compatible_snapshot(profile),
            ForwarderKind::NdnRs | ForwarderKind::BrowserEngine => ndnrs_snapshot(profile),
        }
    }
}

pub async fn poll_engine_summary(
    profile: ForwarderProfile,
) -> Result<EngineSummary, EnginePollError> {
    match profile.attach_mode {
        AttachMode::LocalDesktop => poll_desktop_engine_summary(profile).await,
        AttachMode::BrowserEngine | AttachMode::RemoteWeb | AttachMode::Relay => {
            poll_browser_safe_engine_summary(profile).await
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn poll_desktop_engine_summary(
    profile: ForwarderProfile,
) -> Result<EngineSummary, EnginePollError> {
    let socket = profile
        .endpoint
        .strip_prefix("unix://")
        .unwrap_or(&profile.endpoint)
        .to_string();
    let client = ndn_ipc::MgmtClient::connect(&socket)
        .await
        .map_err(|e| EnginePollError::new(format!("connect {socket}: {e}")))?;

    let status = client.status().await.ok().map(|status| {
        let uptime_s = status
            .current_timestamp_ms
            .saturating_sub(status.start_timestamp_ms)
            / 1000;
        ForwarderStatusView {
            version: status.nfd_version,
            uptime_s,
            start_unix_s: status.start_timestamp_ms / 1000,
            n_cs_entries: status.n_cs_entries,
            n_pit_entries: status.n_pit_entries,
            n_in_interests: status.n_in_interests,
            n_out_interests: status.n_out_interests,
            n_in_data: status.n_in_data,
            n_out_data: status.n_out_data,
        }
    });
    let faces_result = client.face_list().await;
    let rib_result = client.rib_list().await;
    let fib_result = client.route_list().await;
    let strategies_result = client.strategy_list().await;

    let faces = faces_result
        .as_ref()
        .map(|faces| {
            faces
                .iter()
                .map(|face| FaceRow {
                    id: face.face_id,
                    uri: face.uri.clone(),
                    scope: face_scope_label(face.face_scope).into(),
                    persistency: face_persistency_label(face.face_persistency).into(),
                    state: "up".into(),
                    rx_packets: face.n_in_interests + face.n_in_data + face.n_in_nacks,
                    tx_packets: face.n_out_interests + face.n_out_data + face.n_out_nacks,
                    rx_bytes: face.n_in_bytes,
                    tx_bytes: face.n_out_bytes,
                })
                .collect()
        })
        .unwrap_or_default();

    let mut routes = Vec::new();
    if let Ok(ribs) = &rib_result {
        for rib in ribs {
            for route in &rib.routes {
                routes.push(RouteRow {
                    prefix: rib.name.to_string(),
                    source: format!("origin {}", route.origin),
                    face_id: route.face_id,
                    cost: route.cost,
                    flags: format!("0x{:x}", route.flags),
                });
            }
        }
    } else if let Ok(fibs) = &fib_result {
        for fib in fibs {
            for hop in &fib.nexthops {
                routes.push(RouteRow {
                    prefix: fib.name.to_string(),
                    source: "fib".into(),
                    face_id: hop.face_id,
                    cost: hop.cost,
                    flags: "read-only".into(),
                });
            }
        }
    }

    let strategies = strategies_result
        .as_ref()
        .map(|strategies| {
            strategies
                .iter()
                .map(|strategy| StrategyRow {
                    prefix: strategy.name.to_string(),
                    strategy: strategy.strategy.to_string(),
                    inherited: strategy.name.to_string() == "/",
                })
                .collect()
        })
        .unwrap_or_default();

    let store_pit = status.as_ref().map(|status| StorePitSummary {
        cs_capacity: status.n_cs_entries.max(1),
        cs_entries: status.n_cs_entries,
        cs_hit_rate_pct: satisfaction_pct(status.n_out_data, status.n_in_interests),
        pit_entries: status.n_pit_entries,
        pit_satisfied_rate_pct: satisfaction_pct(status.n_out_data, status.n_in_interests),
    });
    let traffic = status.as_ref().map(|status| TrafficSummary {
        interest_in_rate: status.n_in_interests,
        interest_out_rate: status.n_out_interests,
        data_in_rate: status.n_in_data,
        data_out_rate: status.n_out_data,
        satisfaction_rate_pct: satisfaction_pct(status.n_out_data, status.n_in_interests),
    });

    let sources = vec![
        source(
            "status/general",
            if status.is_some() {
                DatasetState::Fresh
            } else {
                DatasetState::Disconnected
            },
        ),
        source("faces/list", dataset_state_from_result(&faces_result)),
        source(
            "fib/list + rib/list",
            if fib_result.is_ok() || rib_result.is_ok() {
                DatasetState::Fresh
            } else {
                DatasetState::Disconnected
            },
        ),
        source(
            "strategy-choice/list",
            dataset_state_from_result(&strategies_result),
        ),
        source(
            "cs/info + pit/summary",
            if store_pit.is_some() {
                DatasetState::Fresh
            } else {
                DatasetState::Disconnected
            },
        ),
        source(
            "faces/counters + measurements/list",
            if traffic.is_some() {
                DatasetState::Fresh
            } else {
                DatasetState::Disconnected
            },
        ),
    ];

    Ok(EngineSummary::from_snapshot(
        &profile,
        EngineSnapshot {
            status,
            faces,
            routes,
            strategies,
            store_pit,
            traffic,
            sources,
        },
    ))
}

#[cfg(target_arch = "wasm32")]
async fn poll_desktop_engine_summary(
    profile: ForwarderProfile,
) -> Result<EngineSummary, EnginePollError> {
    Ok(EngineSummary::disconnected(&profile))
}

async fn poll_browser_safe_engine_summary(
    profile: ForwarderProfile,
) -> Result<EngineSummary, EnginePollError> {
    Ok(EngineSummary::mock(&profile))
}

#[cfg(not(target_arch = "wasm32"))]
fn dataset_state_from_result<T, E>(result: &Result<T, E>) -> DatasetState {
    if result.is_ok() {
        DatasetState::Fresh
    } else {
        DatasetState::Disconnected
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn face_scope_label(scope: u64) -> &'static str {
    match scope {
        0 => "non-local",
        1 => "local",
        _ => "unknown",
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn face_persistency_label(persistency: u64) -> &'static str {
    match persistency {
        0 => "persistent",
        1 => "on-demand",
        2 => "permanent",
        _ => "unknown",
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn satisfaction_pct(satisfied: u64, total: u64) -> u8 {
    satisfied
        .saturating_mul(100)
        .checked_div(total)
        .unwrap_or(0)
        .min(100) as u8
}

fn ndnrs_snapshot(profile: &ForwarderProfile) -> EngineSnapshot {
    EngineSnapshot {
        status: Some(ForwarderStatusView {
            version: profile.version.clone(),
            uptime_s: 18_240,
            start_unix_s: 1_717_281_760,
            n_cs_entries: 18_044,
            n_pit_entries: 128,
            n_in_interests: 2_430_000,
            n_out_interests: 2_112_000,
            n_in_data: 1_980_000,
            n_out_data: 2_020_000,
        }),
        faces: vec![
            face(
                7,
                "udp4://10.0.0.2:6363",
                "non-local",
                "persistent",
                "up",
                18_120,
                21_552,
            ),
            face(
                11,
                "webtransport://edge.example",
                "non-local",
                "on-demand",
                "up",
                8_041,
                8_112,
            ),
            face(14, "internal://mgmt", "local", "permanent", "up", 210, 214),
        ],
        routes: vec![
            route("/ndn/site/video", "rib", 7, 10, "child-inherit"),
            route("/localhop/nfd", "management", 14, 0, "local"),
            route("/ndn/edge/tools", "rib", 11, 20, "capture"),
        ],
        strategies: vec![
            strategy("/", "/localhost/nfd/strategy/best-route/v=5", true),
            strategy(
                "/ndn/site/video",
                "/localhost/nfd/strategy/multicast/v=5",
                false,
            ),
            strategy("/ndn/edge/tools", "/localhost/nfd/strategy/cclf/v=1", false),
        ],
        store_pit: Some(StorePitSummary {
            cs_capacity: 65_536,
            cs_entries: 18_044,
            cs_hit_rate_pct: 71,
            pit_entries: 128,
            pit_satisfied_rate_pct: 94,
        }),
        traffic: Some(TrafficSummary {
            interest_in_rate: 832,
            interest_out_rate: 718,
            data_in_rate: 692,
            data_out_rate: 711,
            satisfaction_rate_pct: 92,
        }),
        sources: vec![
            source("status/general", DatasetState::Fresh),
            source("faces/list", DatasetState::Fresh),
            source("fib/list + rib/list", DatasetState::Fresh),
            source("strategy-choice/list", DatasetState::Fresh),
            source("cs/info + pit/summary", DatasetState::Fresh),
            source("faces/counters + measurements/list", DatasetState::Fresh),
        ],
    }
}

fn compatible_snapshot(profile: &ForwarderProfile) -> EngineSnapshot {
    EngineSnapshot {
        status: Some(ForwarderStatusView {
            version: profile.version.clone(),
            uptime_s: 7_220,
            start_unix_s: 1_717_292_780,
            n_cs_entries: 4_220,
            n_pit_entries: 44,
            n_in_interests: 404_100,
            n_out_interests: 398_010,
            n_in_data: 331_022,
            n_out_data: 328_980,
        }),
        faces: vec![
            face(
                1,
                "unix:///run/nfd.sock",
                "local",
                "permanent",
                "up",
                1_440,
                1_399,
            ),
            face(
                260,
                "udp4://192.0.2.10:6363",
                "non-local",
                "persistent",
                "up",
                9_204,
                9_017,
            ),
        ],
        routes: vec![
            route("/localhost/nfd", "management", 1, 0, "local"),
            route("/ndn/testbed", "rib", 260, 10, "child-inherit"),
        ],
        strategies: vec![strategy(
            "/",
            "/localhost/nfd/strategy/best-route/v=5",
            true,
        )],
        store_pit: Some(StorePitSummary {
            cs_capacity: 16_384,
            cs_entries: 4_220,
            cs_hit_rate_pct: 53,
            pit_entries: 44,
            pit_satisfied_rate_pct: 88,
        }),
        traffic: Some(TrafficSummary {
            interest_in_rate: 122,
            interest_out_rate: 119,
            data_in_rate: 106,
            data_out_rate: 107,
            satisfaction_rate_pct: 86,
        }),
        sources: vec![
            source("status/general", DatasetState::Fresh),
            source("faces/list", DatasetState::Fresh),
            source("fib/list + rib/list", DatasetState::Fresh),
            source("strategy-choice/list", DatasetState::Fresh),
            source("cs/info + pit/summary", DatasetState::Stale { age_s: 45 }),
            source(
                "faces/counters + measurements/list",
                DatasetState::Stale { age_s: 45 },
            ),
        ],
    }
}

fn standard_sources(state: DatasetState) -> Vec<DatasetSource> {
    vec![
        source("status/general", state),
        source("faces/list", state),
        source("fib/list + rib/list", state),
        source("strategy-choice/list", state),
        source("cs/info + pit/summary", state),
        source("faces/counters + measurements/list", state),
    ]
}

fn source(name: &'static str, state: DatasetState) -> DatasetSource {
    DatasetSource {
        name,
        state,
        last_update_unix_s: matches!(state, DatasetState::Fresh | DatasetState::Stale { .. })
            .then_some(1_717_300_000),
    }
}

fn face(
    id: u64,
    uri: &str,
    scope: &str,
    persistency: &str,
    state: &str,
    rx_packets: u64,
    tx_packets: u64,
) -> FaceRow {
    FaceRow {
        id,
        uri: uri.into(),
        scope: scope.into(),
        persistency: persistency.into(),
        state: state.into(),
        rx_packets,
        tx_packets,
        rx_bytes: rx_packets * 940,
        tx_bytes: tx_packets * 980,
    }
}

fn route(prefix: &str, source: &str, face_id: u64, cost: u64, flags: &str) -> RouteRow {
    RouteRow {
        prefix: prefix.into(),
        source: source.into(),
        face_id,
        cost,
        flags: flags.into(),
    }
}

fn strategy(prefix: &str, strategy: &str, inherited: bool) -> StrategyRow {
    StrategyRow {
        prefix: prefix.into(),
        strategy: strategy.into(),
        inherited,
    }
}

pub fn compact_count(value: u64) -> String {
    if value >= 1_000_000 {
        format!("{:.1}m", value as f64 / 1_000_000.0)
    } else if value >= 1_000 {
        format!("{:.1}k", value as f64 / 1_000.0)
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{PlatformKind, fixtures};

    #[test]
    fn ndnrs_engine_summary_has_live_native_datasets() {
        let profile = fixtures::ndnrs_profile(PlatformKind::Desktop);
        let summary = EngineSummary::mock(&profile);

        assert!(!summary.read_only);
        assert_eq!(summary.profile_kind, ForwarderKind::NdnRs);
        assert_eq!(summary.faces.len(), 3);
        assert_eq!(summary.routes.len(), 3);
        assert!(
            summary
                .sources
                .iter()
                .all(|source| source.state == DatasetState::Fresh)
        );
    }

    #[test]
    fn nfd_engine_summary_is_read_only_with_stale_native_gaps() {
        let profile = fixtures::nfd_profile();
        let summary = EngineSummary::mock(&profile);

        assert!(summary.read_only);
        assert_eq!(summary.profile_kind, ForwarderKind::Nfd);
        assert_eq!(summary.faces.len(), 2);
        assert!(
            summary
                .sources
                .iter()
                .any(|source| matches!(source.state, DatasetState::Stale { .. }))
        );
    }

    #[test]
    fn disconnected_summary_preserves_panel_states() {
        let profile = fixtures::unsupported_profile();
        let summary = EngineSummary::disconnected(&profile);

        assert!(summary.status.is_none());
        assert!(summary.faces.is_empty());
        assert!(
            summary
                .sources
                .iter()
                .all(|source| source.state == DatasetState::Disconnected)
        );
    }

    #[test]
    fn filters_faces_and_routes_without_mutating_source() {
        let profile = fixtures::ndnrs_profile(PlatformKind::Desktop);
        let summary = EngineSummary::mock(&profile);

        assert_eq!(summary.filter_faces("webtransport").len(), 1);
        assert_eq!(summary.search_routes("video").len(), 1);
        assert_eq!(summary.faces.len(), 3);
    }

    #[tokio::test]
    async fn browser_safe_polling_uses_shared_engine_models() {
        let profile = fixtures::browser_engine_profile();
        let summary = poll_engine_summary(profile).await.expect("browser summary");

        assert_eq!(summary.profile_kind, ForwarderKind::BrowserEngine);
        assert_eq!(summary.sources[0].state, DatasetState::Fresh);
        assert!(!summary.faces.is_empty());
    }
}
