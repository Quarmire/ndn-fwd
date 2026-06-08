//! NDN Dashboard — Dioxus application for managing and monitoring an
//! ndn-fwd instance via the NDN management protocol on `/localhost/nfd/`.
//!
//! Desktop mode uses [`ndn_ipc::MgmtClient`] over Unix sockets; web mode
//! uses a pure-Rust WebSocket client compiled to WASM.

#![allow(non_snake_case)]

#[cfg(feature = "desktop")]
mod app;
pub mod app_shared;
mod edu_gloss;
#[cfg(all(feature = "web", not(feature = "desktop")))]
pub mod app {
    pub use crate::app_shared::*;
}
#[cfg(feature = "web")]
mod app_web;
#[cfg(target_arch = "wasm32")]
mod browser_engine;
mod fonts;
#[cfg(feature = "desktop")]
mod forwarder_proc;
#[cfg(feature = "desktop")]
mod notify_sub;
mod resizable;
mod security_gate;
mod security_state;
mod security_surfaces;
pub mod settings;
mod styles;
#[cfg(feature = "desktop")]
pub mod tool_runner;
#[cfg(feature = "desktop")]
mod tray;
mod views;

// UI-agnostic logic + data models now live in `ndn-dashboard-core`; re-export
// them at the crate root so existing `crate::<module>::…` paths keep resolving.
pub use ndn_dashboard_core::{
    forwarder_profile, identity_axis, keyguard, operator_keyring, operator_keyring_store,
    preprovision, security_chains, signed_data_chain, types,
};

#[cfg(feature = "web")]
mod ws_mgmt;
#[cfg(feature = "desktop")]
mod native_mgmt;
#[cfg(feature = "desktop")]
mod remote_signer;

fn main() {
    #[cfg(feature = "desktop")]
    {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .init();

        let (cli_fwd, cli_sock) = parse_forwarder_args();
        let resolved = forwarder_profile::resolve_static(cli_fwd.as_deref(), cli_sock.clone())
            .or_else(forwarder_profile::auto_detect)
            .unwrap_or_else(|| {
                (
                    forwarder_profile::ForwarderProfile::NdnFwd,
                    forwarder_profile::ForwarderProfile::NdnFwd
                        .default_socket()
                        .to_path_buf(),
                )
            });
        tracing::info!(
            forwarder = %resolved.0.human_label(),
            socket = %resolved.1.display(),
            "selected forwarder profile"
        );
        forwarder_profile::install_selected(resolved.0, resolved.1);
    }

    #[cfg(feature = "desktop")]
    {
        use dioxus::desktop::{Config, WindowBuilder};
        // dioxus-desktop defaults `always_on_top` to true outside `dx serve`
        // (Config::new -> dioxus_cli_config::always_on_top().unwrap_or(true)),
        // which pinned the dashboard above every other window. Pin it off and
        // set a real window title (was the default "Dioxus App").
        dioxus::LaunchBuilder::desktop()
            .with_cfg(
                Config::new().with_window(
                    WindowBuilder::new()
                        .with_title("NDN Dashboard")
                        .with_always_on_top(false),
                ),
            )
            .launch(app::App);
    }

    #[cfg(feature = "web")]
    dioxus::launch(app_web::AppWeb);
}

#[cfg(feature = "desktop")]
fn parse_forwarder_args() -> (Option<String>, Option<std::path::PathBuf>) {
    let mut fwd = None;
    let mut sock = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if let Some(v) = a.strip_prefix("--forwarder=") {
            fwd = Some(v.to_string());
        } else if a == "--forwarder" {
            fwd = args.next();
        } else if let Some(v) = a.strip_prefix("--socket=") {
            sock = Some(std::path::PathBuf::from(v));
        } else if a == "--socket" {
            sock = args.next().map(std::path::PathBuf::from);
        }
    }
    (fwd, sock)
}
