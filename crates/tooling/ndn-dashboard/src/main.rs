//! NDN Dashboard — Dioxus application for managing and monitoring
//! an ndn-fwd instance.
//!
//! The dashboard communicates with the router exclusively via the NDN
//! management protocol (TLV Interest/Data on `/localhost/nfd/`).
//!
//! **Desktop** mode uses [`ndn_ipc::MgmtClient`] over Unix sockets with
//! system tray integration and subprocess management.
//!
//! **Web** mode uses a pure-Rust WebSocket client compiled to WASM,
//! demonstrating ndn-rs portability — the same TLV codec and packet types
//! run natively and in the browser.

#![allow(non_snake_case)]

pub mod app_shared;
#[cfg(feature = "desktop")]
mod app;
// On web, `mod app` is a thin re-export of app_shared so that view modules
// that `use crate::app::*` continue to compile without changes.
#[cfg(all(feature = "web", not(feature = "desktop")))]
pub mod app {
    pub use crate::app_shared::*;
}
#[cfg(feature = "web")]
mod app_web;
pub mod forwarder_profile;
#[cfg(target_arch = "wasm32")]
mod browser_engine;
#[cfg(feature = "desktop")]
mod forwarder_proc;
pub mod settings;
mod styles;
#[cfg(feature = "desktop")]
pub mod tool_runner;
#[cfg(feature = "desktop")]
mod tray;
mod types;
mod views;

#[cfg(feature = "web")]
mod ws_mgmt;

fn main() {
    #[cfg(feature = "desktop")]
    {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .init();

        // Resolve forwarder profile from CLI flags before launching the
        // Dioxus runtime. Hand-rolled rather than pulling clap; the
        // surface is two flags. Unknown args fall through to Dioxus.
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
    dioxus::launch(app::App);

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
