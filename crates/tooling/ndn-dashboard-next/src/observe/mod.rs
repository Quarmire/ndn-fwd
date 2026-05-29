//! NDN-native observability view models, live span fetches, and a small OTLP Span decoder.

use crate::core::{AttachMode, FeatureState, ForwarderProfile, ObservePosture};
use std::collections::{BTreeMap, HashMap, HashSet};

pub const DEFAULT_OBSERVABILITY_PREFIX: &str = "/localhost/nfd/observability";
#[cfg(not(target_arch = "wasm32"))]
const MAX_RECENT_SPANS: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpanView {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub target: String,
    pub interest_name: Option<String>,
    pub face_id: Option<i64>,
    pub strategy: Option<String>,
    pub status: SpanStatus,
    pub duration_us: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpanStatus {
    Unset,
    Ok,
    Error,
}

impl SpanStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unset => "unset",
            Self::Ok => "ok",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceView {
    pub trace_id: String,
    pub span_count: usize,
    pub root_name: String,
    pub duration_us: u64,
    pub has_pit_fanout: bool,
    pub spans: Vec<SpanView>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpanTreeRow {
    pub span: SpanView,
    pub depth: usize,
    pub child_count: usize,
    pub orphaned_parent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PitFanOutRow {
    pub span_name: String,
    pub face_id: Option<i64>,
    pub interest_name: Option<String>,
    pub status: SpanStatus,
    pub duration_us: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeExportState {
    Unknown,
    NotAttached,
    Ready,
    Error,
    Unavailable,
}

impl BridgeExportState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "bridge unknown",
            Self::NotAttached => "bridge not attached",
            Self::Ready => "bridge observed",
            Self::Error => "bridge error",
            Self::Unavailable => "bridge unavailable",
        }
    }

    pub fn tone(self) -> &'static str {
        match self {
            Self::Ready => "good",
            Self::Unknown | Self::NotAttached => "amber",
            Self::Unavailable => "muted",
            Self::Error => "bad",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeExportStatus {
    pub state: BridgeExportState,
    pub detail: String,
}

impl BridgeExportStatus {
    pub fn new(state: BridgeExportState, detail: impl Into<String>) -> Self {
        Self {
            state,
            detail: detail.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEvidenceRow {
    pub seq: u64,
    pub target: String,
    pub level: String,
    pub message: String,
    pub matched_by: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecentSpanRef {
    pub trace_id: String,
    pub span_id: String,
}

impl RecentSpanRef {
    pub fn new(trace_id: impl Into<String>, span_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            span_id: span_id.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserveSourceState {
    Live,
    Empty,
    Unsupported,
    Disabled,
    Degraded,
    Error,
}

impl ObserveSourceState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Live => "live spans",
            Self::Empty => "no spans",
            Self::Unsupported => "not supported",
            Self::Disabled => "disabled",
            Self::Degraded => "degraded",
            Self::Error => "fetch error",
        }
    }

    pub fn tone(self) -> &'static str {
        match self {
            Self::Live => "good",
            Self::Empty | Self::Disabled | Self::Degraded => "amber",
            Self::Unsupported => "muted",
            Self::Error => "bad",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObserveSummary {
    pub posture: ObservePosture,
    pub prefix: String,
    pub source: ObserveSourceState,
    pub guidance: Option<String>,
    pub bridge_status: BridgeExportStatus,
    pub recent_logs: Vec<LogEvidenceRow>,
    pub recent: Vec<TraceView>,
}

impl ObserveSummary {
    pub fn mock(profile: &ForwarderProfile, posture: ObservePosture) -> Self {
        let unsupported = profile.capabilities.observability == FeatureState::Unsupported;
        let recent = if unsupported {
            vec![]
        } else {
            vec![mock_trace()]
        };
        Self {
            posture,
            prefix: DEFAULT_OBSERVABILITY_PREFIX.into(),
            source: if unsupported {
                ObserveSourceState::Unsupported
            } else {
                ObserveSourceState::Degraded
            },
            guidance: if unsupported {
                Some("NFD-compatible management is available, but ndn-rs native trace Data is not advertised by this forwarder.".into())
            } else {
                Some("Mock spans stand in until a browser-safe observe transport or local ndn-rs publisher is connected.".into())
            },
            bridge_status: BridgeExportStatus::new(
                BridgeExportState::NotAttached,
                "No ndn-otel-bridge heartbeat or log evidence is attached to this dashboard session.",
            ),
            recent_logs: Vec::new(),
            recent,
        }
    }

    pub fn guidance(
        posture: ObservePosture,
        source: ObserveSourceState,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            posture,
            prefix: DEFAULT_OBSERVABILITY_PREFIX.into(),
            source,
            guidance: Some(detail.into()),
            bridge_status: BridgeExportStatus::new(
                match source {
                    ObserveSourceState::Disabled
                    | ObserveSourceState::Unsupported
                    | ObserveSourceState::Error => BridgeExportState::Unavailable,
                    _ => BridgeExportState::NotAttached,
                },
                "Bridge/export status is unavailable until native span publishing is reachable.",
            ),
            recent_logs: Vec::new(),
            recent: Vec::new(),
        }
    }

    pub fn from_spans(prefix: impl Into<String>, spans: Vec<SpanView>) -> Self {
        let recent = group_spans(spans);
        let source = if recent.is_empty() {
            ObserveSourceState::Empty
        } else {
            ObserveSourceState::Live
        };
        let guidance = if recent.is_empty() {
            Some("Observability is enabled, but /recent did not list cached spans yet. Run traffic or a dashboard tool, then refresh.".into())
        } else {
            None
        };
        Self {
            posture: ObservePosture::Enabled,
            prefix: prefix.into(),
            source,
            guidance,
            bridge_status: BridgeExportStatus::new(
                BridgeExportState::Unknown,
                "Span Data is available, but no ndn-otel-bridge heartbeat endpoint is defined yet.",
            ),
            recent_logs: Vec::new(),
            recent,
        }
    }

    pub fn with_logs(mut self, logs: Vec<LogEvidenceRow>) -> Self {
        self.bridge_status = bridge_status_from_logs(&logs, self.source);
        self.recent_logs = logs;
        self
    }
}

pub async fn poll_observe_summary(
    profile: ForwarderProfile,
    posture: ObservePosture,
) -> ObserveSummary {
    match posture {
        ObservePosture::Unsupported => ObserveSummary::guidance(
            posture,
            ObserveSourceState::Unsupported,
            "This attach target does not advertise ndn-rs observability. Engine counters remain available for NFD/YaNFD-compatible profiles.",
        ),
        ObservePosture::Disabled => ObserveSummary::guidance(
            posture,
            ObserveSourceState::Disabled,
            "The forwarder reports observability support, but the publisher is disabled. Enable the ndn-rs observability config and expose the configured prefix.",
        ),
        ObservePosture::Degraded => {
            let mut summary = ObserveSummary::mock(&profile, posture);
            summary.source = ObserveSourceState::Degraded;
            summary.guidance = Some(match profile.attach_mode {
                AttachMode::BrowserEngine => {
                    "Browser-engine spans are local to the in-page engine; this view uses the same TraceView model while the browser publisher transport is wired."
                }
                AttachMode::RemoteWeb | AttachMode::Relay => {
                    "This target needs a browser-safe observe transport or approved relay before live span Data can be fetched."
                }
                AttachMode::LocalDesktop => {
                    "The target exposes partial observability; live fetches are limited until ndn-rs native span endpoints are enabled."
                }
            }.into());
            summary
        }
        ObservePosture::Error => ObserveSummary::guidance(
            posture,
            ObserveSourceState::Error,
            "The last observability probe failed. Check attach transport, prefix routing, and publisher health.",
        ),
        ObservePosture::Enabled => match profile.attach_mode {
            AttachMode::LocalDesktop => fetch_desktop_observe_summary(&profile).await,
            AttachMode::BrowserEngine | AttachMode::RemoteWeb | AttachMode::Relay => {
                let mut summary = ObserveSummary::mock(&profile, ObservePosture::Degraded);
                summary.guidance = Some(
                    "Live span fetch is enabled in the model; this attach mode still needs its browser-safe NDN transport implementation."
                        .into(),
                );
                summary
            }
        },
    }
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_desktop_observe_summary(profile: &ForwarderProfile) -> ObserveSummary {
    let logs = fetch_desktop_recent_logs(&profile.endpoint)
        .await
        .unwrap_or_default();
    match fetch_desktop_spans(&profile.endpoint, DEFAULT_OBSERVABILITY_PREFIX).await {
        Ok(spans) => {
            ObserveSummary::from_spans(DEFAULT_OBSERVABILITY_PREFIX, spans).with_logs(logs)
        }
        Err(err) => ObserveSummary::guidance(
            ObservePosture::Error,
            ObserveSourceState::Error,
            format!(
                "Could not fetch live observability Data from {}: {err}",
                profile.endpoint
            ),
        ),
    }
}

#[cfg(target_arch = "wasm32")]
async fn fetch_desktop_observe_summary(_profile: &ForwarderProfile) -> ObserveSummary {
    ObserveSummary::guidance(
        ObservePosture::Error,
        ObserveSourceState::Error,
        "Desktop Unix-socket observability fetches are unavailable in the browser build.",
    )
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_desktop_recent_logs(
    endpoint: &str,
) -> Result<Vec<LogEvidenceRow>, ObserveFetchError> {
    let socket = endpoint.strip_prefix("unix://").unwrap_or(endpoint);
    let client = ndn_ipc::MgmtClient::connect(socket)
        .await
        .map_err(|err| ObserveFetchError::Transport(err.to_string()))?;
    let response = client
        .log_get_recent(0)
        .await
        .map_err(|err| ObserveFetchError::Fetch(err.to_string()))?;
    Ok(parse_recent_log_response(&response.status_text))
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_desktop_spans(
    endpoint: &str,
    prefix: &str,
) -> Result<Vec<SpanView>, ObserveFetchError> {
    let socket = endpoint.strip_prefix("unix://").unwrap_or(endpoint);
    let mut consumer = ndn_app::Consumer::connect(socket)
        .await
        .map_err(|err| ObserveFetchError::Transport(err.to_string()))?;
    let recent_name: ndn_packet::Name = format!("{prefix}/recent")
        .parse()
        .map_err(|_| ObserveFetchError::InvalidName)?;
    let recent_data = consumer
        .fetch(recent_name)
        .await
        .map_err(|err| ObserveFetchError::Fetch(err.to_string()))?;
    let refs = parse_recent_listing(
        recent_data
            .content()
            .map_or(&[][..], |bytes| bytes.as_ref()),
    )?;
    let mut spans = Vec::new();
    for span_ref in refs.into_iter().take(MAX_RECENT_SPANS) {
        let span_name: ndn_packet::Name = span_data_name(prefix, &span_ref)
            .parse()
            .map_err(|_| ObserveFetchError::InvalidName)?;
        let span_data = consumer
            .fetch(span_name)
            .await
            .map_err(|err| ObserveFetchError::Fetch(err.to_string()))?;
        let Some(content) = span_data.content() else {
            continue;
        };
        spans.push(decode_otlp_span(content).map_err(ObserveFetchError::Decode)?);
    }
    Ok(spans)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ObserveFetchError {
    #[error("transport unavailable: {0}")]
    Transport(String),
    #[error("fetch failed: {0}")]
    Fetch(String),
    #[error("invalid observability Data name")]
    InvalidName,
    #[error("malformed recent span listing")]
    MalformedRecent,
    #[error("span decode failed: {0}")]
    Decode(DecodeError),
}

pub fn parse_recent_listing(bytes: &[u8]) -> Result<Vec<RecentSpanRef>, ObserveFetchError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ObserveFetchError::MalformedRecent)?;
    let mut refs = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let Some((trace_id, span_id)) = line.split_once('/') else {
            return Err(ObserveFetchError::MalformedRecent);
        };
        if !is_hex_of_len(trace_id, 32) || !is_hex_of_len(span_id, 16) {
            return Err(ObserveFetchError::MalformedRecent);
        }
        refs.push(RecentSpanRef::new(trace_id, span_id));
    }
    Ok(refs)
}

pub fn span_data_name(prefix: &str, span_ref: &RecentSpanRef) -> String {
    format!(
        "{}/traces/{}/spans/{}",
        prefix.trim_end_matches('/'),
        span_ref.trace_id,
        span_ref.span_id
    )
}

pub fn parse_recent_log_response(body: &str) -> Vec<LogEvidenceRow> {
    body.lines()
        .skip(1)
        .enumerate()
        .map(|(index, line)| parse_log_line(index as u64 + 1, line))
        .collect()
}

fn parse_log_line(seq: u64, line: &str) -> LogEvidenceRow {
    let (level, target, message) = parse_tracing_line(line);
    LogEvidenceRow {
        seq,
        target,
        level,
        message,
        matched_by: String::new(),
    }
}

fn parse_tracing_line(line: &str) -> (String, String, String) {
    let level = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"]
        .into_iter()
        .find(|level| line.contains(level))
        .unwrap_or("LOG")
        .to_ascii_lowercase();
    let target = line
        .split_whitespace()
        .find(|part| part.ends_with(':') && part.contains('.'))
        .map(|part| part.trim_end_matches(':').to_string())
        .unwrap_or_else(|| "runtime".into());
    (level, target, line.to_string())
}

pub fn filter_traces(traces: &[TraceView], query: &str) -> Vec<TraceView> {
    let terms: Vec<String> = query
        .split_whitespace()
        .map(|term| term.to_ascii_lowercase())
        .collect();
    if terms.is_empty() {
        return traces.to_vec();
    }

    traces
        .iter()
        .filter(|trace| terms.iter().all(|term| trace_matches(trace, term)))
        .cloned()
        .collect()
}

pub fn correlated_logs_for_trace(
    trace: &TraceView,
    logs: &[LogEvidenceRow],
) -> Vec<LogEvidenceRow> {
    let needles = trace_log_needles(trace);
    logs.iter()
        .filter_map(|row| {
            let haystack = format!(
                "{} {} {}",
                row.target.to_ascii_lowercase(),
                row.level.to_ascii_lowercase(),
                row.message.to_ascii_lowercase()
            );
            let matched = needles
                .iter()
                .find(|needle| !needle.value.is_empty() && haystack.contains(&needle.value));
            matched.map(|needle| {
                let mut row = row.clone();
                row.matched_by = needle.label.clone();
                row
            })
        })
        .take(8)
        .collect()
}

fn trace_log_needles(trace: &TraceView) -> Vec<LogNeedle> {
    let mut needles = vec![
        LogNeedle::new("trace id", &trace.trace_id),
        LogNeedle::new("root span", &trace.root_name),
    ];
    for span in &trace.spans {
        needles.push(LogNeedle::new("span id", &span.span_id));
        needles.push(LogNeedle::new("span name", &span.name));
        needles.push(LogNeedle::new("target", &span.target));
        if let Some(name) = span.interest_name.as_deref() {
            needles.push(LogNeedle::new("Interest", name));
        }
        if let Some(face_id) = span.face_id {
            needles.push(LogNeedle::new("face", face_id.to_string()));
        }
        if let Some(strategy) = span.strategy.as_deref() {
            needles.push(LogNeedle::new("strategy", strategy));
        }
    }
    needles
}

struct LogNeedle {
    label: String,
    value: String,
}

impl LogNeedle {
    fn new(label: impl Into<String>, value: impl ToString) -> Self {
        Self {
            label: label.into(),
            value: value.to_string().to_ascii_lowercase(),
        }
    }
}

pub fn span_tree_rows(trace: &TraceView) -> Vec<SpanTreeRow> {
    let span_index: HashMap<&str, usize> = trace
        .spans
        .iter()
        .enumerate()
        .map(|(index, span)| (span.span_id.as_str(), index))
        .collect();
    let mut children: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    let mut roots = Vec::new();

    for (index, span) in trace.spans.iter().enumerate() {
        match span.parent_span_id.as_deref() {
            Some(parent) if span_index.contains_key(parent) => {
                children.entry(parent).or_default().push(index);
            }
            _ => roots.push(index),
        }
    }

    for indexes in children.values_mut() {
        indexes.sort_by(|left, right| trace.spans[*left].span_id.cmp(&trace.spans[*right].span_id));
    }
    roots.sort_by(|left, right| trace.spans[*left].span_id.cmp(&trace.spans[*right].span_id));

    let mut rows = Vec::new();
    let mut visited = HashSet::new();
    for root in roots {
        push_span_tree_row(
            root,
            0,
            trace,
            &children,
            &span_index,
            &mut visited,
            &mut rows,
        );
    }
    for index in 0..trace.spans.len() {
        if !visited.contains(&index) {
            push_span_tree_row(
                index,
                0,
                trace,
                &children,
                &span_index,
                &mut visited,
                &mut rows,
            );
        }
    }
    rows
}

pub fn bridge_status_from_logs(
    logs: &[LogEvidenceRow],
    source: ObserveSourceState,
) -> BridgeExportStatus {
    if matches!(
        source,
        ObserveSourceState::Unsupported | ObserveSourceState::Disabled | ObserveSourceState::Error
    ) {
        return BridgeExportStatus::new(
            BridgeExportState::Unavailable,
            "NDN-native span publishing is not available for bridge export.",
        );
    }

    if logs.iter().any(|row| {
        row.message.contains("ndn-otel-bridge")
            && row.message.to_ascii_lowercase().contains("error")
    }) {
        return BridgeExportStatus::new(
            BridgeExportState::Error,
            "Recent logs mention ndn-otel-bridge errors.",
        );
    }

    if logs
        .iter()
        .any(|row| row.message.contains("ndn-otel-bridge"))
    {
        return BridgeExportStatus::new(
            BridgeExportState::Ready,
            "Recent logs mention ndn-otel-bridge activity.",
        );
    }

    BridgeExportStatus::new(
        BridgeExportState::NotAttached,
        "No ndn-otel-bridge activity was observed in recent forwarder logs.",
    )
}

fn push_span_tree_row(
    index: usize,
    depth: usize,
    trace: &TraceView,
    children: &BTreeMap<&str, Vec<usize>>,
    span_index: &HashMap<&str, usize>,
    visited: &mut HashSet<usize>,
    rows: &mut Vec<SpanTreeRow>,
) {
    if !visited.insert(index) {
        return;
    }

    let span = &trace.spans[index];
    let child_indexes = children
        .get(span.span_id.as_str())
        .cloned()
        .unwrap_or_default();
    rows.push(SpanTreeRow {
        span: span.clone(),
        depth,
        child_count: child_indexes.len(),
        orphaned_parent: span
            .parent_span_id
            .as_deref()
            .is_some_and(|parent| !span_index.contains_key(parent)),
    });

    for child in child_indexes {
        push_span_tree_row(child, depth + 1, trace, children, span_index, visited, rows);
    }
}

pub fn pit_fanout_rows(trace: &TraceView) -> Vec<PitFanOutRow> {
    trace
        .spans
        .iter()
        .filter(|span| span.name.starts_with("pit."))
        .map(|span| PitFanOutRow {
            span_name: span.name.clone(),
            face_id: span.face_id,
            interest_name: span.interest_name.clone(),
            status: span.status,
            duration_us: span.duration_us,
        })
        .collect()
}

fn trace_matches(trace: &TraceView, term: &str) -> bool {
    text_matches(&trace.trace_id, term)
        || text_matches(&trace.root_name, term)
        || trace.spans.iter().any(|span| span_matches(span, term))
}

fn span_matches(span: &SpanView, term: &str) -> bool {
    text_matches(&span.trace_id, term)
        || text_matches(&span.span_id, term)
        || span
            .parent_span_id
            .as_deref()
            .is_some_and(|value| text_matches(value, term))
        || text_matches(&span.name, term)
        || text_matches(&span.target, term)
        || span
            .interest_name
            .as_deref()
            .is_some_and(|value| text_matches(value, term))
        || span
            .face_id
            .map(|face| face.to_string().contains(term))
            .unwrap_or(false)
        || span
            .strategy
            .as_deref()
            .is_some_and(|value| text_matches(value, term))
        || text_matches(span.status.label(), term)
}

fn text_matches(value: &str, term: &str) -> bool {
    value.to_ascii_lowercase().contains(term)
}

fn is_hex_of_len(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn group_spans(mut spans: Vec<SpanView>) -> Vec<TraceView> {
    spans.sort_by(|a, b| a.trace_id.cmp(&b.trace_id).then(a.span_id.cmp(&b.span_id)));
    let mut traces = Vec::new();
    let mut current: Option<TraceView> = None;
    for span in spans {
        if current
            .as_ref()
            .map(|trace| trace.trace_id != span.trace_id)
            .unwrap_or(true)
        {
            if let Some(trace) = current.take() {
                traces.push(trace);
            }
            current = Some(TraceView {
                trace_id: span.trace_id.clone(),
                span_count: 0,
                root_name: span.name.clone(),
                duration_us: 0,
                has_pit_fanout: false,
                spans: Vec::new(),
            });
        }
        let trace = current.as_mut().expect("trace exists");
        trace.duration_us = trace.duration_us.saturating_add(span.duration_us);
        trace.has_pit_fanout |= span.name == "pit.satisfy" || span.name == "pit.nack";
        trace.span_count += 1;
        trace.spans.push(span);
    }
    if let Some(trace) = current {
        traces.push(trace);
    }
    traces
}

pub fn decode_otlp_span(bytes: &[u8]) -> Result<SpanView, DecodeError> {
    let mut reader = ProtoReader::new(bytes);
    let mut trace_id = None;
    let mut span_id = None;
    let mut parent_span_id = None;
    let mut name = None;
    let mut start = 0u64;
    let mut end = 0u64;
    let mut target = String::new();
    let mut interest_name = None;
    let mut face_id = None;
    let mut strategy = None;
    let mut status = SpanStatus::Unset;

    while !reader.is_empty() {
        let (field, wire) = reader.read_key()?;
        match (field, wire) {
            (1, Wire::Len) => trace_id = Some(hex(reader.read_len()?)),
            (2, Wire::Len) => span_id = Some(hex(reader.read_len()?)),
            (4, Wire::Len) => parent_span_id = Some(hex(reader.read_len()?)),
            (5, Wire::Len) => name = Some(String::from_utf8_lossy(reader.read_len()?).to_string()),
            (7, Wire::Fixed64) => start = reader.read_fixed64()?,
            (8, Wire::Fixed64) => end = reader.read_fixed64()?,
            (9, Wire::Len) => {
                let attr = decode_attr(reader.read_len()?)?;
                match attr.key.as_str() {
                    "ndn.target" => target = attr.value,
                    "interest.name" => interest_name = Some(attr.value),
                    "face.id" => face_id = attr.value.parse().ok(),
                    "strategy.name" => strategy = Some(attr.value),
                    _ => {}
                }
            }
            (15, Wire::Len) => status = decode_status(reader.read_len()?)?,
            _ => reader.skip(wire)?,
        }
    }

    Ok(SpanView {
        trace_id: trace_id.ok_or(DecodeError::MissingField("trace_id"))?,
        span_id: span_id.ok_or(DecodeError::MissingField("span_id"))?,
        parent_span_id,
        name: name.ok_or(DecodeError::MissingField("name"))?,
        target,
        interest_name,
        face_id,
        strategy,
        status,
        duration_us: end.saturating_sub(start) / 1000,
    })
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("malformed protobuf")]
    Malformed,
    #[error("missing OTLP span field {0}")]
    MissingField(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wire {
    Varint,
    Fixed64,
    Len,
}

struct ProtoReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ProtoReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn read_key(&mut self) -> Result<(u64, Wire), DecodeError> {
        let key = self.read_varint()?;
        let wire = match key & 0x07 {
            0 => Wire::Varint,
            1 => Wire::Fixed64,
            2 => Wire::Len,
            _ => return Err(DecodeError::Malformed),
        };
        Ok((key >> 3, wire))
    }

    fn read_varint(&mut self) -> Result<u64, DecodeError> {
        let mut out = 0u64;
        let mut shift = 0;
        loop {
            let b = *self.bytes.get(self.pos).ok_or(DecodeError::Malformed)?;
            self.pos += 1;
            out |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(out);
            }
            shift += 7;
            if shift > 63 {
                return Err(DecodeError::Malformed);
            }
        }
    }

    fn read_len(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.read_varint()? as usize;
        let end = self.pos.checked_add(len).ok_or(DecodeError::Malformed)?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(DecodeError::Malformed)?;
        self.pos = end;
        Ok(slice)
    }

    fn read_fixed64(&mut self) -> Result<u64, DecodeError> {
        let end = self.pos.checked_add(8).ok_or(DecodeError::Malformed)?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(DecodeError::Malformed)?;
        self.pos = end;
        Ok(u64::from_le_bytes(slice.try_into().expect("8 bytes")))
    }

    fn skip(&mut self, wire: Wire) -> Result<(), DecodeError> {
        match wire {
            Wire::Varint => {
                self.read_varint()?;
            }
            Wire::Fixed64 => {
                self.read_fixed64()?;
            }
            Wire::Len => {
                self.read_len()?;
            }
        }
        Ok(())
    }
}

struct Attr {
    key: String,
    value: String,
}

fn decode_attr(bytes: &[u8]) -> Result<Attr, DecodeError> {
    let mut reader = ProtoReader::new(bytes);
    let mut key = String::new();
    let mut value = String::new();
    while !reader.is_empty() {
        let (field, wire) = reader.read_key()?;
        match (field, wire) {
            (1, Wire::Len) => key = String::from_utf8_lossy(reader.read_len()?).to_string(),
            (2, Wire::Len) => value = decode_any_value(reader.read_len()?)?,
            _ => reader.skip(wire)?,
        }
    }
    Ok(Attr { key, value })
}

fn decode_any_value(bytes: &[u8]) -> Result<String, DecodeError> {
    let mut reader = ProtoReader::new(bytes);
    while !reader.is_empty() {
        let (field, wire) = reader.read_key()?;
        match (field, wire) {
            (1, Wire::Len) => return Ok(String::from_utf8_lossy(reader.read_len()?).to_string()),
            (3, Wire::Varint) => return Ok((reader.read_varint()? as i64).to_string()),
            (4, Wire::Varint) => return Ok((reader.read_varint()? != 0).to_string()),
            _ => reader.skip(wire)?,
        }
    }
    Ok(String::new())
}

fn decode_status(bytes: &[u8]) -> Result<SpanStatus, DecodeError> {
    let mut reader = ProtoReader::new(bytes);
    let mut status = SpanStatus::Unset;
    while !reader.is_empty() {
        let (field, wire) = reader.read_key()?;
        match (field, wire) {
            (3, Wire::Varint) => {
                status = match reader.read_varint()? {
                    1 => SpanStatus::Ok,
                    2 => SpanStatus::Error,
                    _ => SpanStatus::Unset,
                };
            }
            _ => reader.skip(wire)?,
        }
    }
    Ok(status)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn mock_trace() -> TraceView {
    let spans = vec![
        SpanView {
            trace_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            span_id: "0000000000000001".into(),
            parent_span_id: None,
            name: "interest".into(),
            target: "fwd.pipeline".into(),
            interest_name: Some("/demo/video/keyframe".into()),
            face_id: Some(7),
            strategy: Some("best-route".into()),
            status: SpanStatus::Ok,
            duration_us: 3400,
        },
        SpanView {
            trace_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            span_id: "0000000000000002".into(),
            parent_span_id: Some("0000000000000001".into()),
            name: "pit.satisfy".into(),
            target: "fwd.pit".into(),
            interest_name: Some("/demo/video/keyframe".into()),
            face_id: Some(11),
            strategy: None,
            status: SpanStatus::Ok,
            duration_us: 120,
        },
    ];
    group_spans(spans).remove(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn encode_len(out: &mut Vec<u8>, field: u64, payload: &[u8]) {
        out.push(((field << 3) | 2) as u8);
        out.push(payload.len() as u8);
        out.extend_from_slice(payload);
    }

    fn encode_fixed64(out: &mut Vec<u8>, field: u64, value: u64) {
        out.push(((field << 3) | 1) as u8);
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn attr(key: &str, value: &str) -> Bytes {
        let mut any = Vec::new();
        encode_len(&mut any, 1, value.as_bytes());
        let mut out = Vec::new();
        encode_len(&mut out, 1, key.as_bytes());
        encode_len(&mut out, 2, &any);
        Bytes::from(out)
    }

    #[test]
    fn decode_minimal_otlp_span() {
        let mut span = Vec::new();
        encode_len(&mut span, 1, &[0x11; 16]);
        encode_len(&mut span, 2, &[0x22; 8]);
        encode_len(&mut span, 5, b"interest");
        encode_fixed64(&mut span, 7, 1_000);
        encode_fixed64(&mut span, 8, 11_000);
        encode_len(&mut span, 9, &attr("interest.name", "/a/b"));
        encode_len(&mut span, 9, &attr("ndn.target", "fwd.pipeline"));
        let decoded = decode_otlp_span(&span).expect("decode");
        assert_eq!(decoded.trace_id, "11111111111111111111111111111111");
        assert_eq!(decoded.span_id, "2222222222222222");
        assert_eq!(decoded.interest_name.as_deref(), Some("/a/b"));
        assert_eq!(decoded.duration_us, 10);
    }

    #[test]
    fn grouping_marks_pit_fanout() {
        let trace = mock_trace();
        assert!(trace.has_pit_fanout);
        assert_eq!(trace.span_count, 2);
    }

    #[test]
    fn parses_recent_span_listing() {
        let refs = parse_recent_listing(
            b"11111111111111111111111111111111/2222222222222222\n33333333333333333333333333333333/4444444444444444\n",
        )
        .expect("recent listing");
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].trace_id, "11111111111111111111111111111111");
        assert_eq!(refs[0].span_id, "2222222222222222");
    }

    #[test]
    fn rejects_malformed_recent_span_listing() {
        assert_eq!(
            parse_recent_listing(b"not-a-trace").unwrap_err(),
            ObserveFetchError::MalformedRecent
        );
        assert_eq!(
            parse_recent_listing(b"11111111111111111111111111111111/nothex").unwrap_err(),
            ObserveFetchError::MalformedRecent
        );
    }

    #[test]
    fn builds_span_data_name_from_recent_ref() {
        let span_ref = RecentSpanRef::new("11111111111111111111111111111111", "2222222222222222");
        assert_eq!(
            span_data_name("/localhost/nfd/observability/", &span_ref),
            "/localhost/nfd/observability/traces/11111111111111111111111111111111/spans/2222222222222222"
        );
    }

    #[test]
    fn filters_traces_by_all_operator_fields() {
        let trace = mock_trace();
        let traces = vec![trace.clone()];
        for query in [
            "aaaaaaaa",
            "interest",
            "fwd.pit",
            "11",
            "best-route",
            "ok",
            "/demo/video",
        ] {
            let filtered = filter_traces(&traces, query);
            assert_eq!(filtered, vec![trace.clone()], "query {query}");
        }
    }

    #[test]
    fn filters_traces_by_all_query_terms() {
        let trace = mock_trace();
        let traces = vec![trace.clone()];
        assert_eq!(filter_traces(&traces, "best-route ok"), vec![trace]);
        assert!(filter_traces(&traces, "best-route error").is_empty());
        assert!(filter_traces(&traces, "missing").is_empty());
    }

    #[test]
    fn builds_parent_child_span_tree_rows() {
        let trace = mock_trace();
        let rows = span_tree_rows(&trace);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].span.name, "interest");
        assert_eq!(rows[0].depth, 0);
        assert_eq!(rows[0].child_count, 1);
        assert_eq!(rows[1].span.name, "pit.satisfy");
        assert_eq!(rows[1].depth, 1);
        assert!(!rows[1].orphaned_parent);
    }

    #[test]
    fn span_tree_marks_missing_parents_as_orphaned_roots() {
        let mut trace = mock_trace();
        trace.spans[1].parent_span_id = Some("missing-parent".into());
        let rows = span_tree_rows(&trace);
        let orphan = rows
            .iter()
            .find(|row| row.span.name == "pit.satisfy")
            .expect("pit row");
        assert_eq!(orphan.depth, 0);
        assert!(orphan.orphaned_parent);
    }

    #[test]
    fn extracts_pit_fanout_rows() {
        let trace = mock_trace();
        let rows = pit_fanout_rows(&trace);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].span_name, "pit.satisfy");
        assert_eq!(rows[0].face_id, Some(11));
        assert_eq!(rows[0].status, SpanStatus::Ok);
    }

    #[test]
    fn parses_recent_log_response_into_evidence_rows() {
        let rows = parse_recent_log_response(
            "42\n2026-05-28T00:00:00Z  INFO fwd.pipeline: received /demo/video/keyframe",
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].seq, 1);
        assert_eq!(rows[0].level, "info");
        assert_eq!(rows[0].target, "fwd.pipeline");
    }

    #[test]
    fn correlates_logs_under_selected_trace() {
        let trace = mock_trace();
        let logs = vec![
            LogEvidenceRow {
                seq: 1,
                target: "fwd.pipeline".into(),
                level: "info".into(),
                message: "received /demo/video/keyframe".into(),
                matched_by: String::new(),
            },
            LogEvidenceRow {
                seq: 2,
                target: "other".into(),
                level: "info".into(),
                message: "unrelated".into(),
                matched_by: String::new(),
            },
        ];
        let rows = correlated_logs_for_trace(&trace, &logs);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].seq, 1);
        assert!(!rows[0].matched_by.is_empty());
    }

    #[test]
    fn bridge_status_uses_recent_log_evidence() {
        let logs = vec![LogEvidenceRow {
            seq: 7,
            target: "bridge".into(),
            level: "info".into(),
            message: "ndn-otel-bridge starting".into(),
            matched_by: String::new(),
        }];
        assert_eq!(
            bridge_status_from_logs(&logs, ObserveSourceState::Live).state,
            BridgeExportState::Ready
        );
        assert_eq!(
            bridge_status_from_logs(&[], ObserveSourceState::Disabled).state,
            BridgeExportState::Unavailable
        );
    }
}
