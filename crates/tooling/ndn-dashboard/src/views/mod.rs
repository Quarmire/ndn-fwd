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
pub mod key_rotation;
pub mod logs;
#[cfg(feature = "desktop")]
pub mod modals;
pub mod onboarding;
pub mod overview;
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
            Bucket::Identity => &[View::Security, View::Session],
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
            View::Security | View::Session => Bucket::Identity,
            View::Compose => Bucket::Compose,
        }
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
