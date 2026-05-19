// `coding` and `rate_limit` currently call into `ndn-ipc::MgmtClient`
// (Unix-socket only). Wiring them through `WsMgmtClient` for the web
// build is tracked in docs/notes/dashboard-correctness-floor-2026-05-13.md §1d.
#[cfg(feature = "desktop")]
pub mod coding;
#[cfg(feature = "desktop")]
pub mod config;
pub mod cs;
#[cfg(feature = "desktop")]
pub mod dashboard_config;
pub mod enrollment_wizard;
pub mod faces;
pub mod fleet;
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
    DashboardConfig,
    RouterConfig,
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
            View::DashboardConfig => "Dashboard Config",
            View::RouterConfig => "Router Config",
        }
    }

    pub const NAV: &'static [View] = &[
        View::Overview,
        View::Strategy,
        View::Coding,
        View::RateLimit,
        View::Logs,
        View::Session,
        View::Security,
        View::Fleet,
        View::Routing,
        View::Radio,
        View::Tools,
    ];
}
