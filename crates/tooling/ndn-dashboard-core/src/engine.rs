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

use crate::mgmt::{ManagementClient, MgmtResponse};
use crate::types::{CsInfo, FaceInfo, FibEntry, ForwarderStatus, StrategyEntry};
use ndn_config::{ControlParameters, nfd_dataset};
use ndn_packet::Name;

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

    /// Shared access to the underlying client, for transport-specific reads a
    /// UI still drives directly (datasets the engine doesn't model yet).
    pub fn client(&self) -> &M {
        &self.client
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
                .into_iter()
                .map(FaceInfo::from)
                .collect();
            changed.push(StateUpdate::Faces);
        }

        if let Ok(resp) = self.client.send_cmd("fib", "list", None).await
            && resp.is_ok()
        {
            self.state.routes = nfd_dataset::FibEntry::decode_all(&resp.body)
                .into_iter()
                .map(FibEntry::from)
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
                .into_iter()
                .map(StrategyEntry::from)
                .collect();
            changed.push(StateUpdate::Strategies);
        }

        changed
    }

    // ── command dispatch (forwarding plane) ─────────────────────────────
    //
    // Typed builders construct the `ControlParameters` for a verb and send it,
    // so a UI calls `engine.route_register(prefix, face, cost)` instead of
    // hand-rolling parameters — the logic the Dioxus `run_cmd` arms duplicated
    // now lives once, reusable from a native UI. UI-side effects (audit
    // journaling, error toasts, re-poll) stay in the caller. Security / schema
    // / CA verbs (which carry audit side-effects) are a follow-up slice; the
    // generic `command` escape hatch covers them in the meantime.

    /// Generic command escape hatch — send any `/localhost/nfd/<module>/<verb>`
    /// with optional parameters.
    pub async fn command(
        &mut self,
        module: &str,
        verb: &str,
        params: Option<&ControlParameters>,
    ) -> Result<MgmtResponse, String> {
        self.client.send_cmd(module, verb, params).await
    }

    pub async fn face_create(&mut self, uri: String) -> Result<MgmtResponse, String> {
        let params = ControlParameters {
            uri: Some(uri),
            ..Default::default()
        };
        self.client.send_cmd("faces", "create", Some(&params)).await
    }

    pub async fn face_destroy(&mut self, face_id: u64) -> Result<MgmtResponse, String> {
        let params = ControlParameters {
            face_id: Some(face_id),
            ..Default::default()
        };
        self.client.send_cmd("faces", "destroy", Some(&params)).await
    }

    pub async fn route_register(
        &mut self,
        prefix: &str,
        face_id: u64,
        cost: u64,
    ) -> Result<MgmtResponse, String> {
        let name = parse_name(prefix, "prefix")?;
        let params = ControlParameters {
            name: Some(name),
            // face_id == 0 means "use the requesting face" — leave it unset so
            // the forwarder resolves it from the PIT.
            face_id: (face_id != 0).then_some(face_id),
            cost: Some(cost),
            ..Default::default()
        };
        self.client.send_cmd("rib", "register", Some(&params)).await
    }

    pub async fn route_unregister(
        &mut self,
        prefix: &str,
        face_id: u64,
    ) -> Result<MgmtResponse, String> {
        let name = parse_name(prefix, "prefix")?;
        let params = ControlParameters {
            name: Some(name),
            face_id: (face_id != 0).then_some(face_id),
            ..Default::default()
        };
        self.client.send_cmd("rib", "unregister", Some(&params)).await
    }

    pub async fn strategy_set(
        &mut self,
        prefix: &str,
        strategy: &str,
    ) -> Result<MgmtResponse, String> {
        let name = parse_name(prefix, "prefix")?;
        let strategy_name = parse_name(strategy, "strategy")?;
        let params = ControlParameters {
            name: Some(name),
            strategy: Some(strategy_name),
            ..Default::default()
        };
        self.client
            .send_cmd("strategy-choice", "set", Some(&params))
            .await
    }

    pub async fn strategy_unset(&mut self, prefix: &str) -> Result<MgmtResponse, String> {
        let name = parse_name(prefix, "prefix")?;
        let params = ControlParameters {
            name: Some(name),
            ..Default::default()
        };
        self.client
            .send_cmd("strategy-choice", "unset", Some(&params))
            .await
    }

    pub async fn cs_capacity(&mut self, capacity: u64) -> Result<MgmtResponse, String> {
        let params = ControlParameters {
            capacity: Some(capacity),
            ..Default::default()
        };
        self.client.send_cmd("cs", "config", Some(&params)).await
    }

    pub async fn cs_erase(&mut self, prefix: &str) -> Result<MgmtResponse, String> {
        let name = parse_name(prefix, "prefix")?;
        let params = ControlParameters {
            name: Some(name),
            ..Default::default()
        };
        self.client.send_cmd("cs", "erase", Some(&params)).await
    }

    pub async fn shutdown(&mut self) -> Result<MgmtResponse, String> {
        self.client.send_cmd("status", "shutdown", None).await
    }
}

/// Parse an NDN name argument, turning a parse failure into a UI-displayable
/// error (`what` names the field, e.g. "prefix" / "strategy").
fn parse_name(s: &str, what: &str) -> Result<Name, String> {
    s.parse::<Name>()
        .map_err(|e| format!("invalid {what} '{s}': {e:?}"))
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

    /// Records every command so a builder's `(module, verb, params)` can be
    /// asserted without a live forwarder.
    #[derive(Default)]
    struct RecordingClient {
        calls: Vec<(String, String, Option<ControlParameters>)>,
    }

    #[async_trait(?Send)]
    impl ManagementClient for RecordingClient {
        async fn send_cmd(
            &mut self,
            module: &str,
            verb: &str,
            params: Option<&ControlParameters>,
        ) -> Result<MgmtResponse, String> {
            self.calls
                .push((module.to_string(), verb.to_string(), params.cloned()));
            Ok(MgmtResponse {
                status_code: 200,
                status_text: "OK".to_string(),
                body: Bytes::new(),
            })
        }
    }

    #[tokio::test]
    async fn command_builders_construct_expected_params() {
        let mut engine = DashboardEngine::new(RecordingClient::default());

        engine.route_register("/demo/app", 5, 100).await.unwrap();
        engine.strategy_set("/demo", "/strat/bmf").await.unwrap();
        engine.face_destroy(7).await.unwrap();

        let calls = &engine.client_mut().calls;
        assert_eq!(calls.len(), 3);

        let (m, v, p) = &calls[0];
        assert_eq!((m.as_str(), v.as_str()), ("rib", "register"));
        let p = p.as_ref().unwrap();
        assert_eq!(p.name.as_ref().unwrap().to_string(), "/demo/app");
        assert_eq!(p.face_id, Some(5));
        assert_eq!(p.cost, Some(100));

        let (m, v, p) = &calls[1];
        assert_eq!((m.as_str(), v.as_str()), ("strategy-choice", "set"));
        let p = p.as_ref().unwrap();
        assert_eq!(p.strategy.as_ref().unwrap().to_string(), "/strat/bmf");

        let (m, v, p) = &calls[2];
        assert_eq!((m.as_str(), v.as_str()), ("faces", "destroy"));
        assert_eq!(p.as_ref().unwrap().face_id, Some(7));
    }

    /// face_id == 0 is "the requesting face" — must be left unset, not sent.
    #[tokio::test]
    async fn route_register_omits_zero_face_id() {
        let mut engine = DashboardEngine::new(RecordingClient::default());
        engine.route_register("/x", 0, 0).await.unwrap();
        let (_, _, p) = &engine.client_mut().calls[0];
        assert_eq!(p.as_ref().unwrap().face_id, None);
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
