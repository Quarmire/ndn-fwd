//! `ndn-dashboard-next` — browser-first NDN operator dashboard.

fn main() {
    #[cfg(feature = "web")]
    console_error_panic_hook::set_once();

    #[cfg(feature = "desktop")]
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    dioxus::launch(ndn_dashboard_next::App);
}
