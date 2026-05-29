//! Structured network testing workflows.

use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
use crate::core::AttachMode;
use crate::core::{FeatureState, ForwarderProfile};
use crate::engine::EngineSummary;
use crate::observe::{ObserveSummary, filter_traces};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolKind {
    Ping,
    Peek,
    Put,
    Iperf,
    TraceLookup,
    RouteDiagnostic,
    FaceDiagnostic,
    Export,
}

impl ToolKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Peek => "peek",
            Self::Put => "put",
            Self::Iperf => "iperf",
            Self::TraceLookup => "trace lookup",
            Self::RouteDiagnostic => "route diagnostic",
            Self::FaceDiagnostic => "face diagnostic",
            Self::Export => "export",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolStatus {
    Pending,
    Running,
    Streaming,
    Complete,
    Failed,
    Cancelled,
}

impl ToolStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Streaming => "streaming",
            Self::Complete => "complete",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolSample {
    pub label: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolRun {
    pub kind: ToolKind,
    pub target_name: String,
    pub status: ToolStatus,
    pub samples: Vec<ToolSample>,
    pub result: Option<String>,
    pub trace_refs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PingWorkflowConfig {
    pub target_name: String,
    pub count: u64,
    pub interval_ms: u64,
    pub lifetime_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IperfWorkflowConfig {
    pub target_name: String,
    pub duration_secs: u64,
    pub initial_window: usize,
    pub cc: String,
    pub min_window: Option<f64>,
    pub max_window: Option<f64>,
    pub ai: Option<f64>,
    pub md: Option<f64>,
    pub cubic_c: Option<f64>,
    pub lifetime_ms: u64,
    pub interval_ms: u64,
    pub reverse: bool,
    pub node_prefix: Option<String>,
    pub sign_mode: String,
}

impl IperfWorkflowConfig {
    pub fn quick(target_name: impl Into<String>) -> Self {
        Self {
            target_name: target_name.into(),
            duration_secs: 1,
            initial_window: 4,
            cc: "aimd".into(),
            min_window: None,
            max_window: None,
            ai: None,
            md: None,
            cubic_c: None,
            lifetime_ms: 800,
            interval_ms: 500,
            reverse: false,
            node_prefix: None,
            sign_mode: "digest_sha256".into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeekWorkflowConfig {
    pub target_name: String,
    pub lifetime_ms: u64,
    pub pipeline: Option<usize>,
    pub save_to: Option<String>,
    pub hex: bool,
    pub meta_only: bool,
    pub can_be_prefix: bool,
}

impl PeekWorkflowConfig {
    pub fn quick(target_name: impl Into<String>) -> Self {
        Self {
            target_name: target_name.into(),
            lifetime_ms: 800,
            pipeline: None,
            save_to: None,
            hex: false,
            meta_only: false,
            can_be_prefix: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutWorkflowConfig {
    pub target_name: String,
    pub payload: Vec<u8>,
    pub chunk_size: usize,
    pub freshness_ms: u64,
    pub timeout_secs: u64,
    pub sign: bool,
    pub hmac: bool,
}

impl PutWorkflowConfig {
    pub fn quick(target_name: impl Into<String>) -> Self {
        Self {
            target_name: target_name.into(),
            payload: b"dashboard-next put payload\n".to_vec(),
            chunk_size: 0,
            freshness_ms: 1000,
            timeout_secs: 1,
            sign: false,
            hmac: false,
        }
    }
}

impl PingWorkflowConfig {
    pub fn quick(target_name: impl Into<String>) -> Self {
        Self {
            target_name: target_name.into(),
            count: 4,
            interval_ms: 200,
            lifetime_ms: 1000,
        }
    }
}

impl ToolRun {
    pub fn new(kind: ToolKind, target_name: impl Into<String>) -> Self {
        Self {
            kind,
            target_name: target_name.into(),
            status: ToolStatus::Pending,
            samples: Vec::new(),
            result: None,
            trace_refs: Vec::new(),
        }
    }

    pub fn start(mut self) -> Self {
        self.status = ToolStatus::Running;
        self
    }

    pub fn push_sample(mut self, label: impl Into<String>, value: impl Into<String>) -> Self {
        self.status = ToolStatus::Streaming;
        self.samples.push(ToolSample {
            label: label.into(),
            value: value.into(),
        });
        self
    }

    pub fn add_sample(&mut self, label: impl Into<String>, value: impl Into<String>) {
        self.status = ToolStatus::Streaming;
        self.samples.push(ToolSample {
            label: label.into(),
            value: value.into(),
        });
    }

    pub fn complete(mut self, result: impl Into<String>) -> Self {
        self.status = ToolStatus::Complete;
        self.result = Some(result.into());
        self
    }

    pub fn fail(mut self, message: impl Into<String>) -> Self {
        self.status = ToolStatus::Failed;
        self.result = Some(message.into());
        self
    }

    pub fn cancel(mut self) -> Self {
        self.status = ToolStatus::Cancelled;
        self.result = Some("cancelled by operator".into());
        self
    }

    pub fn add_trace_ref(mut self, trace_ref: impl Into<String>) -> Self {
        self.trace_refs.push(trace_ref.into());
        self
    }

    pub fn export_text(&self) -> String {
        let mut out = format!(
            "{} {}\nstatus: {}\n",
            self.kind.label(),
            self.target_name,
            self.status.label()
        );
        if let Some(result) = &self.result {
            out.push_str(&format!("result: {result}\n"));
        }
        for sample in &self.samples {
            out.push_str(&format!("{}: {}\n", sample.label, sample.value));
        }
        out
    }
}

pub async fn run_ping_workflow(profile: ForwarderProfile, config: PingWorkflowConfig) -> ToolRun {
    run_ping_workflow_inner(profile, config).await
}

pub async fn run_iperf_workflow(profile: ForwarderProfile, config: IperfWorkflowConfig) -> ToolRun {
    run_iperf_workflow_inner(profile, config).await
}

pub async fn run_peek_workflow(profile: ForwarderProfile, config: PeekWorkflowConfig) -> ToolRun {
    run_peek_workflow_inner(profile, config).await
}

pub async fn run_put_workflow(profile: ForwarderProfile, config: PutWorkflowConfig) -> ToolRun {
    run_put_workflow_inner(profile, config).await
}

pub fn run_trace_lookup(summary: &ObserveSummary, query: &str) -> ToolRun {
    let matches = filter_traces(&summary.recent, query);
    let mut run = ToolRun::new(ToolKind::TraceLookup, query).start();
    run.add_sample("matches", matches.len().to_string());
    for trace in matches.iter().take(4) {
        run.add_sample(trace.root_name.clone(), trace.trace_id.clone());
    }
    match matches.first() {
        Some(trace) => run
            .add_trace_ref(trace.trace_id.clone())
            .complete(format!("{} trace(s) matched", matches.len())),
        None => run.fail("no matching trace"),
    }
}

pub fn run_route_diagnostic(engine: &EngineSummary, target_prefix: &str) -> ToolRun {
    let routes = engine.search_routes(target_prefix);
    let mut run = ToolRun::new(ToolKind::RouteDiagnostic, target_prefix).start();
    run.add_sample("candidate routes", routes.len().to_string());
    for route in routes.iter().take(4) {
        run.add_sample(
            route.prefix.clone(),
            format!("face {} cost {} {}", route.face_id, route.cost, route.flags),
        );
    }
    if let Some(route) = routes.first() {
        run.complete(format!(
            "best visible match {} via face {}",
            route.prefix, route.face_id
        ))
    } else {
        run.fail("no visible route matched")
    }
}

pub fn run_face_diagnostic(engine: &EngineSummary, query: &str) -> ToolRun {
    let faces = engine.filter_faces(query);
    let mut run = ToolRun::new(ToolKind::FaceDiagnostic, query).start();
    run.add_sample("candidate faces", faces.len().to_string());
    for face in faces.iter().take(4) {
        run.add_sample(
            format!("face {}", face.id),
            format!(
                "{} {} rx/tx {}",
                face.state,
                face.scope,
                face.traffic_label()
            ),
        );
    }
    if let Some(face) = faces.first() {
        run.complete(format!(
            "face {} {} {}",
            face.id, face.uri, face.persistency
        ))
    } else {
        run.fail("no visible face matched")
    }
}

pub fn tool_server_controls(profile: &ForwarderProfile) -> Vec<ToolRun> {
    let mut controls = vec![
        ToolRun::new(ToolKind::Ping, "server /ping").start(),
        ToolRun::new(ToolKind::Iperf, "server /iperf").start(),
        ToolRun::new(ToolKind::Put, "serve object").start(),
    ];
    for control in &mut controls {
        control.add_sample("platform", profile.attach_mode.label());
        control.result = Some(
            if matches!(
                profile.capabilities.tools,
                FeatureState::Enabled | FeatureState::ReadOnly | FeatureState::Degraded
            ) {
                "server control available after session manager wiring".into()
            } else {
                "server control unsupported by target".into()
            },
        );
    }
    controls
}

#[cfg(not(target_arch = "wasm32"))]
fn has_tool_transport(profile: &ForwarderProfile) -> Result<String, String> {
    if profile.attach_mode != AttachMode::LocalDesktop {
        return Err(
            "workflow needs a desktop Unix-socket attach until browser-safe tool transport lands"
                .into(),
        );
    }
    if !matches!(
        profile.capabilities.tools,
        FeatureState::Enabled | FeatureState::ReadOnly | FeatureState::Degraded
    ) {
        return Err("selected forwarder does not expose compatible tool transport".into());
    }
    Ok(profile
        .endpoint
        .strip_prefix("unix://")
        .unwrap_or(profile.endpoint.as_str())
        .to_string())
}

#[cfg(not(target_arch = "wasm32"))]
async fn run_ping_workflow_inner(profile: ForwarderProfile, config: PingWorkflowConfig) -> ToolRun {
    use ndn_tools_core::common::{ConnectConfig, EventLevel, ToolData};
    use ndn_tools_core::ping::{PingClientParams, run_client};
    use tokio::sync::mpsc;

    let mut run = ToolRun::new(ToolKind::Ping, config.target_name.clone())
        .start()
        .add_trace_ref(config.target_name.clone());

    let socket = match has_tool_transport(&profile) {
        Ok(socket) => socket,
        Err(message) => return run.fail(message),
    };
    let (tx, mut rx) = mpsc::channel(32);
    let params = PingClientParams {
        conn: ConnectConfig {
            face_socket: socket,
            use_shm: false,
            mtu: None,
        },
        prefix: config.target_name.clone(),
        count: config.count,
        interval_ms: config.interval_ms,
        lifetime_ms: config.lifetime_ms,
    };

    let worker = tokio::spawn(async move { run_client(params, tx).await });
    while let Some(event) = rx.recv().await {
        match event.structured {
            Some(ToolData::PingResult { seq, rtt_us }) => {
                run.add_sample(format!("seq {seq}"), format_rtt(rtt_us));
            }
            Some(ToolData::PingSummary {
                sent,
                received,
                nacks,
                timeouts,
                loss_pct,
                rtt_avg_us,
                rtt_p50_us,
                rtt_p99_us,
                ..
            }) => {
                run.add_sample("sent/recv", format!("{sent}/{received}"));
                run.add_sample("loss", format!("{loss_pct:.1}%"));
                run.add_sample("rtt avg", format_rtt(rtt_avg_us));
                run.add_sample(
                    "rtt p50/p99",
                    format!("{}/{}", format_rtt(rtt_p50_us), format_rtt(rtt_p99_us)),
                );
                run = run.complete(format!(
                    "{received}/{sent} satisfied, {nacks} nacked, {timeouts} timeouts"
                ));
            }
            _ if event.level == EventLevel::Error => {
                run = run.fail(event.text);
            }
            _ => {}
        }
    }

    match worker.await {
        Ok(Ok(())) if run.status == ToolStatus::Complete => run,
        Ok(Ok(())) => run.complete("ping completed without structured summary"),
        Ok(Err(err)) => run.fail(format!("ping failed: {err}")),
        Err(err) => run.fail(format!("ping task failed: {err}")),
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn run_iperf_workflow_inner(
    profile: ForwarderProfile,
    config: IperfWorkflowConfig,
) -> ToolRun {
    use ndn_tools_core::common::{ConnectConfig, EventLevel, ToolData};
    use ndn_tools_core::iperf::{IperfClientParams, run_client};
    use tokio::sync::mpsc;

    let mut run = ToolRun::new(ToolKind::Iperf, config.target_name.clone()).start();
    let socket = match has_tool_transport(&profile) {
        Ok(socket) => socket,
        Err(message) => return run.fail(message),
    };
    let (tx, mut rx) = mpsc::channel(32);
    let params = IperfClientParams {
        conn: ConnectConfig {
            face_socket: socket,
            use_shm: false,
            mtu: None,
        },
        prefix: config.target_name.clone(),
        duration_secs: config.duration_secs,
        initial_window: config.initial_window,
        cc: config.cc,
        min_window: config.min_window,
        max_window: config.max_window,
        ai: config.ai,
        md: config.md,
        cubic_c: config.cubic_c,
        lifetime_ms: config.lifetime_ms,
        quiet: false,
        interval_ms: config.interval_ms,
        reverse: config.reverse,
        node_prefix: config.node_prefix,
        sign_mode: config.sign_mode,
    };
    let worker = tokio::spawn(async move { run_client(params, tx).await });
    while let Some(event) = rx.recv().await {
        match event.structured {
            Some(ToolData::IperfInterval {
                bytes,
                throughput_bps,
                rtt_avg_us,
            }) => {
                run.add_sample("interval bytes", format_bytes(bytes));
                run.add_sample("goodput", format_bps(throughput_bps));
                run.add_sample("rtt avg", format_rtt(rtt_avg_us));
            }
            Some(ToolData::IperfSummary {
                duration_secs,
                transferred_bytes,
                throughput_bps,
                sent,
                received,
                loss_pct,
                rtt_avg_us,
                rtt_p99_us,
            }) => {
                run.add_sample("duration", format!("{duration_secs:.2}s"));
                run.add_sample("transferred", format_bytes(transferred_bytes));
                run.add_sample("goodput", format_bps(throughput_bps));
                run.add_sample("sent/recv", format!("{sent}/{received}"));
                run.add_sample("loss", format!("{loss_pct:.1}%"));
                run.add_sample(
                    "rtt avg/p99",
                    format!("{}/{}", format_rtt(rtt_avg_us), format_rtt(rtt_p99_us)),
                );
                run = run.complete(format_bps(throughput_bps));
            }
            _ if event.level == EventLevel::Error => run = run.fail(event.text),
            _ => {}
        }
    }
    match worker.await {
        Ok(Ok(())) if run.status == ToolStatus::Complete => run,
        Ok(Ok(())) => run.complete("iperf completed without structured summary"),
        Ok(Err(err)) => run.fail(format!("iperf failed: {err}")),
        Err(err) => run.fail(format!("iperf task failed: {err}")),
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn run_peek_workflow_inner(profile: ForwarderProfile, config: PeekWorkflowConfig) -> ToolRun {
    use ndn_tools_core::common::{ConnectConfig, EventLevel, ToolData};
    use ndn_tools_core::peek::{PeekParams, run_peek};
    use tokio::sync::mpsc;

    let mut run = ToolRun::new(ToolKind::Peek, config.target_name.clone())
        .start()
        .add_trace_ref(config.target_name.clone());
    let socket = match has_tool_transport(&profile) {
        Ok(socket) => socket,
        Err(message) => return run.fail(message),
    };
    let (tx, mut rx) = mpsc::channel(32);
    let params = PeekParams {
        conn: ConnectConfig {
            face_socket: socket,
            use_shm: false,
            mtu: None,
        },
        name: config.target_name.clone(),
        lifetime_ms: config.lifetime_ms,
        output: config.save_to.clone(),
        pipeline: config.pipeline,
        hex: config.hex,
        meta_only: config.meta_only,
        verbose: true,
        can_be_prefix: config.can_be_prefix,
    };
    let worker = tokio::spawn(async move { run_peek(params, tx).await });
    while let Some(event) = rx.recv().await {
        match event.structured {
            Some(ToolData::PeekResult {
                name,
                bytes_received,
                saved_to,
            }) => {
                run.add_sample("Data name", name);
                run.add_sample("bytes", format_bytes(bytes_received));
                if let Some(path) = saved_to {
                    run.add_sample("saved", path);
                }
                run = run.complete(format!("received {}", format_bytes(bytes_received)));
            }
            Some(ToolData::FetchProgress { received, total }) => {
                run.add_sample("segments", format!("{received}/{total}"));
            }
            _ if event.level == EventLevel::Error => run = run.fail(event.text),
            _ => {}
        }
    }
    match worker.await {
        Ok(Ok(())) if run.status == ToolStatus::Complete => run,
        Ok(Ok(())) => run.complete("peek completed without structured result"),
        Ok(Err(err)) => run.fail(format!("peek failed: {err}")),
        Err(err) => run.fail(format!("peek task failed: {err}")),
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn run_put_workflow_inner(profile: ForwarderProfile, config: PutWorkflowConfig) -> ToolRun {
    use bytes::Bytes;
    use ndn_tools_core::common::{ConnectConfig, EventLevel};
    use ndn_tools_core::put::{PutParams, run_producer};
    use tokio::sync::mpsc;

    let mut run = ToolRun::new(ToolKind::Put, config.target_name.clone())
        .start()
        .add_trace_ref(config.target_name.clone());
    let socket = match has_tool_transport(&profile) {
        Ok(socket) => socket,
        Err(message) => return run.fail(message),
    };
    let payload_len = config.payload.len();
    let (tx, mut rx) = mpsc::channel(32);
    let params = PutParams {
        conn: ConnectConfig {
            face_socket: socket,
            use_shm: false,
            mtu: Some(payload_len.max(1024)),
        },
        name: config.target_name.clone(),
        data: Bytes::from(config.payload),
        chunk_size: config.chunk_size,
        sign: config.sign,
        hmac: config.hmac,
        freshness_ms: config.freshness_ms,
        timeout_secs: config.timeout_secs,
        quiet: true,
    }
    .chunk_size_or_default();
    let worker = tokio::spawn(async move { run_producer(params, tx).await });
    while let Some(event) = rx.recv().await {
        if event.level == EventLevel::Error {
            run = run.fail(event.text);
        } else if !event.text.trim().is_empty() {
            run.add_sample("event", event.text);
        }
    }
    match worker.await {
        Ok(Ok(())) => {
            run.add_sample("freshness", format!("{} ms", config.freshness_ms));
            run.add_sample("payload", format_bytes(payload_len as u64));
            run.complete("object served for dashboard session")
        }
        Ok(Err(err)) => run.fail(format!("put failed: {err}")),
        Err(err) => run.fail(format!("put task failed: {err}")),
    }
}

#[cfg(target_arch = "wasm32")]
async fn run_ping_workflow_inner(
    _profile: ForwarderProfile,
    config: PingWorkflowConfig,
) -> ToolRun {
    ToolRun::new(ToolKind::Ping, config.target_name)
        .start()
        .fail("browser ping needs the browser-safe tool transport")
}

#[cfg(target_arch = "wasm32")]
async fn run_iperf_workflow_inner(
    _profile: ForwarderProfile,
    config: IperfWorkflowConfig,
) -> ToolRun {
    ToolRun::new(ToolKind::Iperf, config.target_name)
        .start()
        .fail("browser iperf needs the browser-safe tool transport")
}

#[cfg(target_arch = "wasm32")]
async fn run_peek_workflow_inner(
    _profile: ForwarderProfile,
    config: PeekWorkflowConfig,
) -> ToolRun {
    ToolRun::new(ToolKind::Peek, config.target_name)
        .start()
        .fail("browser peek needs the browser-safe tool transport")
}

#[cfg(target_arch = "wasm32")]
async fn run_put_workflow_inner(_profile: ForwarderProfile, config: PutWorkflowConfig) -> ToolRun {
    ToolRun::new(ToolKind::Put, config.target_name)
        .start()
        .fail("browser put needs the browser-safe tool transport")
}

pub fn mock_runs() -> Vec<ToolRun> {
    vec![
        ToolRun::new(ToolKind::Ping, "/demo/router")
            .start()
            .push_sample("rtt p50", "2.1 ms")
            .push_sample("loss", "0%")
            .complete("satisfied 20/20 Interests")
            .add_trace_ref("/demo/router"),
        ToolRun::new(ToolKind::Iperf, "/demo/throughput")
            .start()
            .push_sample("goodput", "184 Mbps")
            .push_sample("jitter", "0.6 ms"),
        ToolRun::new(ToolKind::TraceLookup, "/demo/video/keyframe")
            .start()
            .push_sample("trace", "aaaaaaaa...")
            .complete("linked to Observe"),
    ]
}

#[cfg(not(target_arch = "wasm32"))]
fn format_rtt(rtt_us: u64) -> String {
    if rtt_us >= 1000 {
        format!("{:.2} ms", rtt_us as f64 / 1000.0)
    } else {
        format!("{rtt_us} us")
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn format_bps(bps: f64) -> String {
    if bps >= 1_000_000_000.0 {
        format!("{:.2} Gbps", bps / 1_000_000_000.0)
    } else if bps >= 1_000_000.0 {
        format!("{:.2} Mbps", bps / 1_000_000.0)
    } else if bps >= 1_000.0 {
        format!("{:.2} Kbps", bps / 1_000.0)
    } else {
        format!("{bps:.0} bps")
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.2} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_run_lifecycle_reaches_complete() {
        let run = ToolRun::new(ToolKind::Peek, "/a")
            .start()
            .push_sample("bytes", "128")
            .complete("ok");
        assert_eq!(run.status, ToolStatus::Complete);
        assert_eq!(run.samples.len(), 1);
        assert_eq!(run.result.as_deref(), Some("ok"));
    }

    #[test]
    fn tool_run_failure_keeps_message() {
        let run = ToolRun::new(ToolKind::Ping, "/missing")
            .start()
            .fail("timeout");
        assert_eq!(run.status, ToolStatus::Failed);
        assert_eq!(run.result.as_deref(), Some("timeout"));
    }

    #[test]
    fn ping_config_defaults_to_short_operator_run() {
        let config = PingWorkflowConfig::quick("/demo/router");
        assert_eq!(config.count, 4);
        assert_eq!(config.interval_ms, 200);
        assert_eq!(config.lifetime_ms, 1000);
    }

    #[test]
    fn remaining_tool_configs_are_operator_sized() {
        let iperf = IperfWorkflowConfig::quick("/demo/iperf");
        let peek = PeekWorkflowConfig::quick("/demo/data");
        let put = PutWorkflowConfig::quick("/demo/put");
        assert_eq!(iperf.duration_secs, 1);
        assert_eq!(iperf.initial_window, 4);
        assert_eq!(iperf.cc, "aimd");
        assert_eq!(iperf.lifetime_ms, 800);
        assert_eq!(iperf.interval_ms, 500);
        assert!(!iperf.reverse);
        assert_eq!(iperf.sign_mode, "digest_sha256");
        assert!(peek.pipeline.is_none());
        assert!(peek.save_to.is_none());
        assert_eq!(peek.lifetime_ms, 800);
        assert!(!peek.hex);
        assert!(!peek.meta_only);
        assert!(!peek.can_be_prefix);
        assert_eq!(put.chunk_size, 0);
        assert_eq!(put.freshness_ms, 1000);
        assert_eq!(put.timeout_secs, 1);
        assert!(!put.sign);
        assert!(!put.hmac);
        assert!(!put.payload.is_empty());
    }

    #[test]
    fn tool_run_can_carry_trace_pivot() {
        let run = ToolRun::new(ToolKind::Ping, "/demo").add_trace_ref("/demo");
        assert_eq!(run.trace_refs, vec!["/demo"]);
    }

    #[test]
    fn tool_run_export_and_cancel_are_structured() {
        let run = ToolRun::new(ToolKind::Peek, "/demo")
            .start()
            .push_sample("bytes", "128")
            .complete("ok");
        assert!(run.export_text().contains("bytes: 128"));
        assert_eq!(run.clone().cancel().status, ToolStatus::Cancelled);
    }
}
