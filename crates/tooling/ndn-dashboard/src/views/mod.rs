// `coding` and `rate_limit` currently call into `ndn-ipc::MgmtClient`
// (Unix-socket only). Wiring them through `WsMgmtClient` for the web
// build is tracked in (internal) §1d.
pub mod ca_approvals;
#[cfg(feature = "desktop")]
pub mod coding;
pub mod compose;
#[cfg(feature = "desktop")]
pub mod config;
pub mod cs;
#[cfg(feature = "desktop")]
pub mod dashboard_config;
pub mod engine_pill;
pub mod enrollment_wizard;
pub mod faces;
pub mod fleet;
pub mod identity_export;
pub mod inspector;
pub mod key_rotation;
pub mod logs;
#[cfg(feature = "desktop")]
pub mod modals;
pub mod onboarding;
pub mod overview;
#[cfg(feature = "desktop")]
pub mod pairing;
pub mod radio;
#[cfg(feature = "desktop")]
pub mod rate_limit;
pub mod routes;
pub mod routing;
pub mod safebag_import;
pub mod security;
pub mod security_did;
pub mod security_did_ext;
#[cfg(feature = "desktop")]
pub mod session;
pub mod strategy;
#[cfg(feature = "desktop")]
pub mod tools;
pub mod traffic;
pub mod trust_context;

/// Which panel is currently visible in the content area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Overview,
    Strategy,
    Coding,
    RateLimit,
    Logs,
    Session,
    Security,
    Fleet,
    Routing,
    Radio,
    Tools,
    Compose,
    TrustContext,
    Pairing,
    DashboardConfig,
    RouterConfig,
}

/// Top-level navigation bucket. The synthesis note (§8, engine/identity split)
/// splits "operating an engine" from "managing my identity" from "what I
/// publish"; the sidebar groups every [`View`] under one of these three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bucket {
    /// The appliance — faces, routes, strategies, CS, logs, config.
    Engine,
    /// Who I am — TrustContexts, anchors, keys, approvals.
    Identity,
    /// What I publish — producers, datasets, RDR objects.
    Compose,
}

impl Bucket {
    pub fn label(self) -> &'static str {
        match self {
            Bucket::Engine => "Engine",
            Bucket::Identity => "Identity",
            Bucket::Compose => "Compose",
        }
    }

    /// Buckets in sidebar order.
    pub const ALL: &'static [Bucket] = &[Bucket::Engine, Bucket::Identity, Bucket::Compose];

    /// The navigable views in this bucket, in display order. Config views
    /// (`DashboardConfig`, `RouterConfig`) are intentionally excluded — they
    /// are reached from the Settings gear, not the bucket nav.
    pub fn views(self) -> &'static [View] {
        match self {
            Bucket::Engine => &[
                View::Overview,
                View::Strategy,
                View::Coding,
                View::RateLimit,
                View::Routing,
                View::Radio,
                View::Logs,
                View::Fleet,
                View::Tools,
            ],
            Bucket::Identity => &[
                View::TrustContext,
                View::Security,
                View::Pairing,
                View::Session,
            ],
            Bucket::Compose => &[View::Compose],
        }
    }
}

impl View {
    pub fn label(self) -> &'static str {
        match self {
            View::Overview => "Overview",
            View::Strategy => "Strategy",
            View::Coding => "Coding",
            View::RateLimit => "Rate Limit",
            View::Logs => "Logs",
            View::Session => "Session",
            View::Security => "Security",
            View::Fleet => "Fleet",
            View::Routing => "Routing",
            View::Radio => "Radio",
            View::Tools => "Tools",
            View::Compose => "Published",
            View::TrustContext => "Trust Context",
            View::Pairing => "Pairing",
            View::DashboardConfig => "Dashboard Config",
            View::RouterConfig => "Router Config",
        }
    }

    /// The bucket this view is navigated under. Settings-reached config views
    /// report the bucket whose Settings gear surfaces them (Engine).
    pub fn bucket(self) -> Bucket {
        match self {
            View::Overview
            | View::Strategy
            | View::Coding
            | View::RateLimit
            | View::Logs
            | View::Fleet
            | View::Routing
            | View::Radio
            | View::Tools
            | View::DashboardConfig
            | View::RouterConfig => Bucket::Engine,
            View::Security | View::Session | View::TrustContext | View::Pairing => {
                Bucket::Identity
            }
            View::Compose => Bucket::Compose,
        }
    }
}

/// Forwarding strategies ndn-fwd registers, in the canonical
/// `/localhost/nfd/strategy/<name>/v=<version>` form — the exact names
/// `ndn-strategy`'s `strategy_name()` builds (best-route/multicast at v=5,
/// self-learning at v=1). The old `/ndn/strategy/...` literals were rejected
/// with `404 unknown strategy`. NFD/YaNFD strategies (ncc/access/asf, different
/// versions) are reached via the Strategy tab's "Custom…" field.
///
/// One source so the three strategy dropdowns (Overview routes, Strategy tab,
/// route inspector) can't drift apart again.
pub const KNOWN_STRATEGIES: &[(&str, &str)] = &[
    ("/localhost/nfd/strategy/best-route/v=5", "Best Route"),
    ("/localhost/nfd/strategy/multicast/v=5", "Multicast"),
    ("/localhost/nfd/strategy/self-learning/v=1", "Self-Learning"),
];

/// Live tally shown on a bucket's sidebar header (Eagle-style source-tree
/// counts, design note §2). Engine = faces, Identity = distinct identities,
/// Compose = locally-published prefixes (app/client route origin).
pub fn bucket_count(
    bucket: Bucket,
    faces: &[crate::types::FaceInfo],
    keys: &[crate::types::SecurityKeyInfo],
    rib: &[crate::types::RibEntryInfo],
) -> usize {
    match bucket {
        Bucket::Engine => faces.len(),
        Bucket::Identity => {
            let mut ids = std::collections::HashSet::new();
            for k in keys {
                ids.insert(k.identity_name());
            }
            ids.len()
        }
        Bucket::Compose => rib
            .iter()
            .filter(|e| e.routes.iter().any(|r| matches!(r.origin, 0 | 65)))
            .count(),
    }
}

#[cfg(test)]
mod nav_tests {
    use super::*;

    /// Every view that appears in a bucket's `views()` list reports that same
    /// bucket from `View::bucket()` — the two mappings can't drift.
    #[test]
    fn bucket_membership_is_consistent() {
        for &bucket in Bucket::ALL {
            for &view in bucket.views() {
                assert_eq!(
                    view.bucket(),
                    bucket,
                    "{view:?} listed under {bucket:?} but bucket() says {:?}",
                    view.bucket()
                );
            }
        }
    }

    #[test]
    fn known_strategies_are_canonical_versioned_names() {
        for (uri, _) in KNOWN_STRATEGIES {
            assert!(
                uri.starts_with("/localhost/nfd/strategy/"),
                "{uri} is not a canonical NFD strategy name"
            );
            let n: ndn_packet::Name = uri.parse().expect("strategy name parses");
            // The version component must survive a parse→Display round-trip
            // (the old `/ndn/strategy/.../v5` form did not encode a version).
            assert_eq!(&n.to_string(), uri, "{uri} does not round-trip");
        }
    }

    #[test]
    fn bucket_counts_reflect_state() {
        use crate::types::{RibEntryInfo, RibRoute, SecurityKeyInfo};
        let key = |name: &str| SecurityKeyInfo {
            name: name.into(),
            has_cert: false,
            valid_until: String::new(),
            public_key_b64: String::new(),
        };
        // Two keys under one identity + one under another = 2 distinct.
        let keys = vec![
            key("/home/bob/KEY/1"),
            key("/home/bob/KEY/2"),
            key("/work/acme/KEY/1"),
        ];
        assert_eq!(bucket_count(Bucket::Identity, &[], &keys, &[]), 2);

        let route = |origin: u64| RibRoute {
            face_id: 1,
            origin,
            cost: 0,
            flags: 0,
            expiration_period: None,
        };
        let rib = vec![
            RibEntryInfo {
                prefix: "/app".into(),
                routes: vec![route(0)],
            }, // app
            RibEntryInfo {
                prefix: "/cli".into(),
                routes: vec![route(65)],
            }, // client
            RibEntryInfo {
                prefix: "/nlsr".into(),
                routes: vec![route(128)],
            }, // learned
        ];
        // Only app(0) + client(65) origins count as "published".
        assert_eq!(bucket_count(Bucket::Compose, &[], &[], &rib), 2);
        // Engine counts faces (none here).
        assert_eq!(bucket_count(Bucket::Engine, &[], &keys, &rib), 0);
    }

    /// The sidebar nav covers all three buckets and is non-empty in each.
    #[test]
    fn three_buckets_each_navigable() {
        assert_eq!(Bucket::ALL.len(), 3);
        for &bucket in Bucket::ALL {
            assert!(
                !bucket.views().is_empty(),
                "{bucket:?} has no navigable views"
            );
        }
    }
}
