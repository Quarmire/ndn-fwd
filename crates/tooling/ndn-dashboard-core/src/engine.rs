//! `DashboardEngine` — the headless poll/command core.
//!
//! Holds a [`ManagementClient`] and a [`DashboardState`], polls a forwarder's
//! read datasets, and reports which views changed. UI-framework-free: the
//! Dioxus dashboard copies `DashboardState` into Signals, a native UI reads it
//! over FFI. This is the read/poll half of the generic-send-cmd unification;
//! command dispatch is the next slice.
//!
//! The mapping from wire datasets (`ndn_config::nfd_dataset`,
//! `ndn_mgmt_wire`) to the dashboard's view models lives here, so every UI
//! shares one parse layer instead of duplicating the closures `app.rs` /
//! `app_web.rs` grew independently.

use crate::mgmt::ManagementClient;
use crate::types::{CsInfo, FaceInfo, FibEntry, ForwarderStatus, NextHop, StrategyEntry};
use ndn_config::nfd_dataset;

/// Headless snapshot of a forwarder's forwarding-plane state. Plain data owned
/// by the engine and mutated under `&mut self`; a UI reads snapshots from it.
#[derive(Debug, Default, Clone)]
pub struct DashboardState {
    pub status: Option<ForwarderStatus>,
    pub faces: Vec<FaceInfo>,
    pub routes: Vec<FibEntry>,
    pub cs: Option<CsInfo>,
    pub strategies: Vec<StrategyEntry>,
}

/// Which view a poll refreshed, so a UI re-renders only what changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateUpdate {
    Status,
    Faces,
    Routes,
    Cs,
    Strategies,
}

/// Drives a forwarder over any [`ManagementClient`] transport (web WebSocket,
/// desktop Unix socket, mobile IPC face).
pub struct DashboardEngine<M: ManagementClient> {
    client: M,
    state: DashboardState,
}

impl<M: ManagementClient> DashboardEngine<M> {
    pub fn new(client: M) -> Self {
        Self {
            client,
            state: DashboardState::default(),
        }
    }

    /// The current state snapshot.
    pub fn state(&self) -> &DashboardState {
        &self.state
    }

    /// The underlying client — e.g. for command dispatch by a UI adapter.
    pub fn client_mut(&mut self) -> &mut M {
        &mut self.client
    }

    /// Poll the forwarding-plane read datasets once. Updates `state` in place
    /// and returns which views changed. Each block is best-effort: a forwarder
    /// missing a verb (older / cross-impl) degrades to "no data" without
    /// failing the whole poll.
    pub async fn poll_forwarding(&mut self) -> Vec<StateUpdate> {
        let mut changed = Vec::new();

        if let Ok(resp) = self.client.send_cmd("status", "general", None).await
            && let Ok(gs) = ndn_mgmt_wire::GeneralStatus::decode(resp.body.clone())
        {
            self.state.status = Some(ForwarderStatus::from_general(&gs));
            changed.push(StateUpdate::Status);
        }

        if let Ok(resp) = self.client.send_cmd("faces", "list", None).await
            && resp.is_ok()
        {
            self.state.faces = nfd_dataset::FaceStatus::decode_all(&resp.body)
                .iter()
                .map(face_info)
                .collect();
            changed.push(StateUpdate::Faces);
        }

        if let Ok(resp) = self.client.send_cmd("fib", "list", None).await
            && resp.is_ok()
        {
            self.state.routes = nfd_dataset::FibEntry::decode_all(&resp.body)
                .iter()
                .map(fib_entry)
                .collect();
            changed.push(StateUpdate::Routes);
        }

        if let Ok(resp) = self.client.send_cmd("cs", "info", None).await
            && resp.is_ok()
        {
            self.state.cs = CsInfo::parse(&resp.status_text);
            changed.push(StateUpdate::Cs);
        }

        if let Ok(resp) = self.client.send_cmd("strategy-choice", "list", None).await
            && resp.is_ok()
        {
            self.state.strategies = nfd_dataset::StrategyChoice::decode_all(&resp.body)
                .iter()
                .map(strategy_entry)
                .collect();
            changed.push(StateUpdate::Strategies);
        }

        changed
    }
}

fn face_info(fs: &nfd_dataset::FaceStatus) -> FaceInfo {
    FaceInfo {
        face_id: fs.face_id,
        remote_uri: Some(fs.uri.clone()),
        local_uri: if fs.local_uri.is_empty() {
            None
        } else {
            Some(fs.local_uri.clone())
        },
        persistency: fs.persistency_str().to_string(),
        kind: None,
        face_scope: fs.face_scope,
        link_type: fs.link_type,
        mtu: fs.mtu,
        n_in_interests: fs.n_in_interests,
        n_out_interests: fs.n_out_interests,
        n_in_data: fs.n_in_data,
        n_out_data: fs.n_out_data,
        n_in_bytes: fs.n_in_bytes,
        n_out_bytes: fs.n_out_bytes,
        n_in_nacks: fs.n_in_nacks,
        n_out_nacks: fs.n_out_nacks,
        flags: fs.flags,
    }
}

fn fib_entry(fe: &nfd_dataset::FibEntry) -> FibEntry {
    FibEntry {
        prefix: fe.name.to_string(),
        nexthops: fe
            .nexthops
            .iter()
            .map(|nh| NextHop {
                face_id: nh.face_id,
                cost: nh.cost as u32,
            })
            .collect(),
    }
}

fn strategy_entry(sc: &nfd_dataset::StrategyChoice) -> StrategyEntry {
    StrategyEntry {
        prefix: sc.name.to_string(),
        strategy: sc.strategy.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mgmt::MgmtResponse;
    use async_trait::async_trait;
    use bytes::Bytes;
    use ndn_config::ControlParameters;

    /// Canned forwarder: a real `GeneralStatus` wire for `status/general`,
    /// empty (but `is_ok`) datasets for the lists — exercises the engine's
    /// poll choreography + parse layer without a live socket.
    struct MockClient {
        general: Bytes,
    }

    #[async_trait(?Send)]
    impl ManagementClient for MockClient {
        async fn send_cmd(
            &mut self,
            module: &str,
            verb: &str,
            _params: Option<&ControlParameters>,
        ) -> Result<MgmtResponse, String> {
            let ok = |body: Bytes| {
                Ok(MgmtResponse {
                    status_code: 200,
                    status_text: "OK".to_string(),
                    body,
                })
            };
            match (module, verb) {
                ("status", "general") => ok(self.general.clone()),
                ("faces", "list") | ("fib", "list") | ("strategy-choice", "list") => {
                    ok(Bytes::new())
                }
                ("cs", "info") => ok(Bytes::new()),
                other => Err(format!("unexpected verb: {other:?}")),
            }
        }
    }

    #[tokio::test]
    async fn poll_forwarding_parses_status_and_reports_changes() {
        let gs = ndn_mgmt_wire::GeneralStatus {
            nfd_version: "test-fwd".to_string(),
            n_pit_entries: 7,
            n_fib_entries: 3,
            ..Default::default()
        };
        let mut engine = DashboardEngine::new(MockClient {
            general: gs.encode(),
        });

        let updates = engine.poll_forwarding().await;

        // Every read block ran and reported a change.
        assert!(updates.contains(&StateUpdate::Status));
        assert!(updates.contains(&StateUpdate::Faces));
        assert!(updates.contains(&StateUpdate::Routes));
        assert!(updates.contains(&StateUpdate::Strategies));

        // The status dataset parsed into the view model.
        let st = engine.state();
        let status = st.status.as_ref().expect("status parsed");
        assert_eq!(status.nfd_version, "test-fwd");
        assert_eq!(status.n_pit, 7);
        assert_eq!(status.n_fib, 3);

        // Empty datasets parse to empty collections, not errors.
        assert!(st.faces.is_empty());
        assert!(st.routes.is_empty());
        assert!(st.strategies.is_empty());
    }
}
