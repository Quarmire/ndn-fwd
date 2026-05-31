//! Live management-event subscription.
//!
//! Subscribes to the forwarder's NFD-style notification streams
//! (`/localhost/nfd/<module>/notifications`, mirroring NFD
//! `daemon/mgmt/notification-stream.hpp`) on dedicated connections and asks
//! the main poll loop to refresh the instant an event arrives — so an
//! externally-driven face/route/strategy change shows up without waiting for
//! the 3s poll. We watch `faces`, `rib`, and `strategy-choice`. Desktop only
//! (uses the Unix `MgmtClient`); the web build keeps polling. Against a
//! forwarder without a stream (NFD/YaNFD) the long-poll just times out and
//! retries, so it is a harmless no-op there.

use std::time::Duration;

use dioxus::prelude::*;
use ndn_ipc::MgmtClient;

use crate::app::DashCmd;

/// The notification streams the dashboard subscribes to.
pub const MODULES: [&str; 3] = ["faces", "rib", "strategy-choice"];

/// Long-poll one `module`'s notification stream forever — reconnecting on
/// failure — and send [`DashCmd::RefreshNow`] to `cmd` on each event.
/// `socket_path` is re-read on every (re)connect, so a changed socket is
/// picked up after a Reconnect. Each module runs on its own connection (a
/// single connection would serialise the long-polls).
pub async fn run_subscriber(module: &str, socket_path: Signal<String>, cmd: Coroutine<DashCmd>) {
    loop {
        let path = socket_path.peek().clone();
        let client = match MgmtClient::connect(&path).await {
            Ok(c) => c,
            Err(_) => {
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }
        };

        // Learn the current sequence, then long-poll the next one. The
        // producer holds each "next seq" Interest open until the event fires
        // (or its budget elapses, surfacing here as `Ok(None)` → re-issue).
        let mut next = match client
            .notification(module, None, Duration::from_secs(5))
            .await
        {
            Ok(Some((seq, _))) => seq + 1,
            Ok(None) => 1,
            Err(_) => {
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }
        };
        loop {
            match client
                .notification(module, Some(next), Duration::from_secs(6))
                .await
            {
                Ok(Some((seq, _))) => {
                    cmd.send(DashCmd::RefreshNow);
                    next = seq + 1;
                }
                Ok(None) => {}   // no event in the window — re-issue the same seq
                Err(_) => break, // transport/decode error → reconnect
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
