//! `ndn-otel-bridge` — OTLP/HTTP-protobuf bridge for NDN-native spans.
//!
//! Consumes spans from an `ndn-fwd` observability prefix and forwards
//! them to a standard OTLP backend (Jaeger / Tempo / Honeycomb /
//! Datadog) so operators who want existing OTel tooling don't have to
//! abandon it.
//!
//! See `docs/wiki/src/operations/opentelemetry.md` for the operator
//! guide and `.claude/prompts/observability/phase3-otel-and-trace-id.md`
//! §C for the design.
//!
//! ## Flow
//!
//! ```text
//!   ndn-fwd (publisher)
//!        │
//!        ▼  Interest /<prefix>/recent
//!   bridge.poll()  ────►  list of (trace_id, span_id)
//!        │
//!        ▼  Interest /<prefix>/traces/.../spans/...
//!   bridge.fetch_span()  ────►  OTLP Span protobuf bytes
//!        │
//!        ▼  batch
//!   bridge.flush()  ────►  POST /v1/traces  (OTLP/HTTP-protobuf)
//!                          to <endpoint>
//! ```
//!
//! ## Why OTLP/HTTP-protobuf, not /gRPC
//!
//! gRPC needs tonic + h2 + a tower stack — too heavy for a sidecar
//! that does one thing.  OTLP also defines an HTTP/1.1+protobuf
//! profile (`Content-Type: application/x-protobuf`, POST to
//! `/v1/traces`) accepted by every OTLP collector.  reqwest handles
//! the transport in ~10 LOC.

use std::collections::HashSet;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::{BufMut, BytesMut};
use clap::Parser;
use ndn_app::Consumer;
use ndn_packet::{Name, NameComponent};

#[derive(Parser, Debug)]
#[command(version, about = "Forward NDN-native spans to an OTLP backend")]
struct Cli {
    /// Forwarder Unix socket (matches ndn-fwd's `[management] face_socket`).
    #[arg(long, default_value = "/run/nfd/nfd.sock")]
    socket: PathBuf,

    /// NDN prefix the publisher serves under.
    #[arg(long, default_value = "/localhost/nfd/observability")]
    ndn_prefix: String,

    /// OTLP/HTTP-protobuf endpoint. Default is OpenTelemetry
    /// Collector / Jaeger all-in-one OTLP HTTP receiver.
    #[arg(long, default_value = "http://localhost:4318/v1/traces")]
    otlp_endpoint: String,

    /// Max spans per OTLP POST.  Larger batches reduce HTTP overhead
    /// at the cost of higher tail latency.
    #[arg(long, default_value_t = 100)]
    batch_size: usize,

    /// Time-based flush trigger.  Whichever fires first
    /// (batch_size OR batch_timeout) ships the batch.
    #[arg(long, default_value = "5s")]
    batch_timeout: humantime::Duration,

    /// How often the bridge polls `/recent` for new span IDs.
    #[arg(long, default_value = "1s")]
    poll_interval: humantime::Duration,

    /// `service.name` resource attribute used in the OTLP payload.
    #[arg(long, default_value = "ndn-rs")]
    service_name: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    tracing::info!(
        endpoint = %cli.otlp_endpoint,
        ndn_prefix = %cli.ndn_prefix,
        batch_size = cli.batch_size,
        "ndn-otel-bridge starting"
    );

    let prefix = Name::from_str(&cli.ndn_prefix)
        .with_context(|| format!("parse ndn_prefix {:?}", cli.ndn_prefix))?;
    let recent_name = append_component(&prefix, b"recent");

    let mut consumer = Consumer::connect(&cli.socket)
        .await
        .with_context(|| format!("connect to {:?}", cli.socket))?;

    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .build()?;

    let mut seen: HashSet<([u8; 16], [u8; 8])> = HashSet::new();
    let mut batch: Vec<bytes::Bytes> = Vec::new();
    let mut last_flush = std::time::Instant::now();
    let flush_every: Duration = *cli.batch_timeout;
    let poll_every: Duration = *cli.poll_interval;

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown — flushing remaining batch");
                flush(&http, &cli, &mut batch, &cli.service_name).await?;
                return Ok(());
            }
            _ = tokio::time::sleep(poll_every) => {
                if let Err(e) = poll_once(
                    &mut consumer,
                    &recent_name,
                    &prefix,
                    &mut seen,
                    &mut batch,
                ).await {
                    tracing::warn!(error = ?e, "poll failed; will retry");
                }
                let now = std::time::Instant::now();
                if batch.len() >= cli.batch_size || (!batch.is_empty() && now.duration_since(last_flush) >= flush_every) {
                    if let Err(e) = flush(&http, &cli, &mut batch, &cli.service_name).await {
                        tracing::warn!(error = ?e, "flush failed; will retry on next batch");
                    }
                    last_flush = now;
                }
            }
        }
    }
}

async fn poll_once(
    consumer: &mut Consumer,
    recent_name: &Name,
    prefix: &Name,
    seen: &mut HashSet<([u8; 16], [u8; 8])>,
    batch: &mut Vec<bytes::Bytes>,
) -> Result<()> {
    let data = consumer.fetch(recent_name.clone()).await?;
    let content = data.content().cloned().unwrap_or_default();
    let text = std::str::from_utf8(&content).context("recent body not utf8")?;
    for line in text.lines() {
        let Some((trace_hex, span_hex)) = line.split_once('/') else {
            continue;
        };
        let Some((trace_id, span_id)) = decode_pair(trace_hex, span_hex) else {
            continue;
        };
        if !seen.insert((trace_id, span_id)) {
            continue;
        }
        let span_name = span_data_name(prefix, &trace_id, &span_id);
        match consumer.fetch(span_name).await {
            Ok(span_data) => {
                if let Some(body) = span_data.content().cloned() {
                    batch.push(body);
                }
            }
            Err(e) => {
                tracing::debug!(error = ?e, "span fetch failed (likely evicted from cache)");
            }
        }
    }
    Ok(())
}

async fn flush(
    http: &reqwest::Client,
    cli: &Cli,
    batch: &mut Vec<bytes::Bytes>,
    service_name: &str,
) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }
    let body = encode_export_request(service_name, batch);
    let resp = http
        .post(&cli.otlp_endpoint)
        .header("Content-Type", "application/x-protobuf")
        .body(body)
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("OTLP POST returned {status}: {text}");
    }
    tracing::info!(count = batch.len(), "OTLP batch flushed");
    batch.clear();
    Ok(())
}

fn append_component(prefix: &Name, comp: &[u8]) -> Name {
    let mut name = prefix.clone();
    name = name.append_component(NameComponent::generic(bytes::Bytes::copy_from_slice(comp)));
    name
}

fn span_data_name(prefix: &Name, trace_id: &[u8; 16], span_id: &[u8; 8]) -> Name {
    let mut name = prefix.clone();
    name = name.append_component(NameComponent::generic(bytes::Bytes::from_static(b"traces")));
    name = name.append_component(NameComponent::generic(bytes::Bytes::from(hex_lower(trace_id))));
    name = name.append_component(NameComponent::generic(bytes::Bytes::from_static(b"spans")));
    name = name.append_component(NameComponent::generic(bytes::Bytes::from(hex_lower(span_id))));
    name
}

fn hex_lower(bytes: &[u8]) -> Vec<u8> {
    let lut = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(lut[(b >> 4) as usize]);
        out.push(lut[(b & 0x0F) as usize]);
    }
    out
}

fn decode_pair(trace_hex: &str, span_hex: &str) -> Option<([u8; 16], [u8; 8])> {
    if trace_hex.len() != 32 || span_hex.len() != 16 {
        return None;
    }
    let mut trace_id = [0u8; 16];
    for i in 0..16 {
        trace_id[i] = u8::from_str_radix(&trace_hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    let mut span_id = [0u8; 8];
    for i in 0..8 {
        span_id[i] = u8::from_str_radix(&span_hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some((trace_id, span_id))
}

// ── OTLP/HTTP-protobuf encoding ───────────────────────────────────

/// Wrap a batch of pre-encoded `Span` protobufs in an
/// `ExportTraceServiceRequest` payload.
///
/// `ExportTraceServiceRequest`
///   = field 1: repeated ResourceSpans
///
/// `ResourceSpans`
///   = field 1: Resource
///     field 2: repeated ScopeSpans
///
/// `Resource`
///   = field 1: repeated KeyValue ("service.name" = service)
///
/// `ScopeSpans`
///   = field 2: repeated Span (already-encoded `body`)
fn encode_export_request(service_name: &str, spans: &[bytes::Bytes]) -> bytes::Bytes {
    let resource = encode_resource(service_name);
    let mut scope_spans = BytesMut::with_capacity(spans.iter().map(|s| s.len() + 4).sum::<usize>());
    for span in spans {
        encode_len_prefixed(&mut scope_spans, 2, span);
    }
    let mut resource_spans = BytesMut::new();
    encode_len_prefixed(&mut resource_spans, 1, &resource);
    encode_len_prefixed(&mut resource_spans, 2, &scope_spans);

    let mut out = BytesMut::new();
    encode_len_prefixed(&mut out, 1, &resource_spans);
    out.freeze()
}

fn encode_resource(service_name: &str) -> BytesMut {
    let mut kv = BytesMut::new();
    // KeyValue.key (field 1, string)
    encode_len_prefixed(&mut kv, 1, b"service.name");
    // KeyValue.value (field 2, AnyValue)
    let mut any = BytesMut::new();
    encode_len_prefixed(&mut any, 1, service_name.as_bytes()); // AnyValue.string_value
    encode_len_prefixed(&mut kv, 2, &any);

    let mut out = BytesMut::new();
    encode_len_prefixed(&mut out, 1, &kv); // Resource.attributes
    out
}

fn encode_len_prefixed<B: AsRef<[u8]>>(out: &mut BytesMut, field: u32, payload: B) {
    let payload = payload.as_ref();
    write_varint(out, ((field << 3) | 2) as u64);
    write_varint(out, payload.len() as u64);
    out.put_slice(payload);
}

fn write_varint(out: &mut BytesMut, mut v: u64) {
    while v >= 0x80 {
        out.put_u8(((v as u8) & 0x7F) | 0x80);
        v >>= 7;
    }
    out.put_u8(v as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_request_wraps_spans() {
        let span_a = bytes::Bytes::from_static(&[1, 2, 3]);
        let span_b = bytes::Bytes::from_static(&[4, 5]);
        let wire = encode_export_request("test", &[span_a, span_b]);
        // Outer ExportTraceServiceRequest field 1, wire=LEN → tag 0x0A
        assert_eq!(wire[0], 0x0A);
    }

    #[test]
    fn decode_pair_roundtrip() {
        let (t, s) = decode_pair(
            "0102030405060708090a0b0c0d0e0f10",
            "a1a2a3a4a5a6a7a8",
        )
        .expect("decode");
        assert_eq!(t[0], 0x01);
        assert_eq!(t[15], 0x10);
        assert_eq!(s[0], 0xA1);
    }

    #[test]
    fn decode_pair_rejects_wrong_length() {
        assert!(decode_pair("short", "a1a2a3a4a5a6a7a8").is_none());
        assert!(decode_pair("0102030405060708090a0b0c0d0e0f10", "short").is_none());
    }
}
