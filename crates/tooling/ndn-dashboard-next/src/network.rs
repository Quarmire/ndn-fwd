//! Fleet, routing, discovery, radio, and topology view models.

use crate::core::{FeatureState, ForwarderKind, ForwarderProfile, TrustPosture};
use crate::engine::{EngineSummary, FaceRow};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FleetNeighborRow {
    pub peer: String,
    pub face_uri: String,
    pub reachability: &'static str,
    pub trust: TrustPosture,
    pub enrollment_action: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryControlState {
    pub protocol: &'static str,
    pub status: FeatureState,
    pub service_prefix: String,
    pub writable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutingControlState {
    pub protocol: &'static str,
    pub status: FeatureState,
    pub routes: usize,
    pub writable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RadioFaceRow {
    pub transport: &'static str,
    pub face: String,
    pub state: String,
    pub support: FeatureState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TopologyEdge {
    pub source: String,
    pub target: String,
    pub via: String,
    pub evidence: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkViewModel {
    pub neighbors: Vec<FleetNeighborRow>,
    pub discovery: DiscoveryControlState,
    pub routing: Vec<RoutingControlState>,
    pub radios: Vec<RadioFaceRow>,
    pub topology: Vec<TopologyEdge>,
    pub degraded: bool,
}

impl NetworkViewModel {
    pub fn from_engine(profile: &ForwarderProfile, summary: &EngineSummary) -> Self {
        let writable = profile.capabilities.ndnrs_native == FeatureState::Enabled;
        let degraded = !matches!(profile.kind, ForwarderKind::NdnRs);
        let neighbors = summary
            .faces
            .iter()
            .filter(|face| !face.uri.starts_with("internal://"))
            .map(|face| FleetNeighborRow {
                peer: peer_from_face(face),
                face_uri: face.uri.clone(),
                reachability: if face.state == "up" {
                    "reachable"
                } else {
                    "degraded"
                },
                trust: if writable {
                    TrustPosture::Valid
                } else {
                    TrustPosture::Unsupported
                },
                enrollment_action: if writable { "enroll" } else { "unavailable" },
            })
            .collect::<Vec<_>>();

        let radios = summary
            .faces
            .iter()
            .map(|face| RadioFaceRow {
                transport: transport_kind(&face.uri),
                face: face.id.to_string(),
                state: face.state.clone(),
                support: radio_support(&face.uri, profile.kind),
            })
            .collect();

        let topology = summary
            .routes
            .iter()
            .map(|route| TopologyEdge {
                source: profile.kind.label().to_string(),
                target: route.prefix.clone(),
                via: format!("face {}", route.face_id),
                evidence: if degraded { "compat route" } else { "rib/fib" },
            })
            .collect();

        Self {
            neighbors,
            discovery: DiscoveryControlState {
                protocol: "service discovery",
                status: if writable {
                    FeatureState::Enabled
                } else {
                    FeatureState::ReadOnly
                },
                service_prefix: "/localhop/ndn-autoconf".into(),
                writable,
            },
            routing: vec![
                RoutingControlState {
                    protocol: "static",
                    status: FeatureState::Enabled,
                    routes: summary.routes.len(),
                    writable,
                },
                RoutingControlState {
                    protocol: "DVR",
                    status: if writable {
                        FeatureState::Degraded
                    } else {
                        FeatureState::Unsupported
                    },
                    routes: summary
                        .routes
                        .iter()
                        .filter(|route| route.source == "dvr")
                        .count(),
                    writable,
                },
                RoutingControlState {
                    protocol: "NLSR",
                    status: if profile.kind == ForwarderKind::Nfd {
                        FeatureState::ReadOnly
                    } else {
                        FeatureState::Unsupported
                    },
                    routes: summary
                        .routes
                        .iter()
                        .filter(|route| route.source.eq_ignore_ascii_case("nlsr"))
                        .count(),
                    writable: false,
                },
            ],
            radios,
            topology,
            degraded,
        }
    }
}

fn peer_from_face(face: &FaceRow) -> String {
    face.uri
        .split("://")
        .nth(1)
        .unwrap_or(&face.uri)
        .split('/')
        .next()
        .unwrap_or(&face.uri)
        .to_string()
}

fn transport_kind(uri: &str) -> &'static str {
    if uri.starts_with("ether://") {
        "ethernet"
    } else if uri.starts_with("ble://") {
        "BLE"
    } else if uri.starts_with("wifi-aware://") {
        "Wi-Fi Aware"
    } else if uri.starts_with("wfb://") {
        "WFB"
    } else if uri.starts_with("webtransport://") {
        "WebTransport"
    } else if uri.starts_with("udp") {
        "UDP"
    } else {
        "local"
    }
}

fn radio_support(uri: &str, kind: ForwarderKind) -> FeatureState {
    match transport_kind(uri) {
        "ethernet" | "BLE" | "Wi-Fi Aware" | "WFB" if kind == ForwarderKind::NdnRs => {
            FeatureState::Enabled
        }
        "ethernet" | "BLE" | "Wi-Fi Aware" | "WFB" => FeatureState::Unsupported,
        _ => FeatureState::ReadOnly,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{PlatformKind, fixtures};
    use crate::engine::EngineSummary;

    #[test]
    fn ndnrs_network_model_keeps_mutable_discovery_and_static_routes() {
        let profile = fixtures::ndnrs_profile(PlatformKind::Desktop);
        let summary = EngineSummary::mock(&profile);
        let model = NetworkViewModel::from_engine(&profile, &summary);

        assert!(model.discovery.writable);
        assert!(
            model
                .routing
                .iter()
                .any(|row| row.protocol == "static" && row.routes > 0)
        );
        assert!(!model.topology.is_empty());
    }

    #[test]
    fn nfd_network_model_degrades_native_controls() {
        let profile = fixtures::nfd_profile();
        let summary = EngineSummary::mock(&profile);
        let model = NetworkViewModel::from_engine(&profile, &summary);

        assert!(model.degraded);
        assert_eq!(model.discovery.status, FeatureState::ReadOnly);
        assert!(
            model
                .neighbors
                .iter()
                .all(|row| row.trust == TrustPosture::Unsupported)
        );
    }
}
