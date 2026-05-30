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

    launch_app();
}

#[cfg(all(feature = "desktop", not(target_arch = "wasm32")))]
fn launch_app() {
    use dioxus::desktop::{Config, WindowBuilder};

    dioxus::LaunchBuilder::desktop()
        .with_cfg(
            Config::new().with_window(
                WindowBuilder::new()
                    .with_title("ndn-dashboard-next")
                    .with_always_on_top(false),
            ),
        )
        .launch(ndn_dashboard_next::App);
}

#[cfg(not(all(feature = "desktop", not(target_arch = "wasm32"))))]
fn launch_app() {
    dioxus::launch(ndn_dashboard_next::App);
}
