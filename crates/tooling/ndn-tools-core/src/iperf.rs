//! Embeddable NDN iperf tool logic (bandwidth measurement).
//!
//! Two modes:
//! - **Server** — registers a prefix, responds to Interests, supports session negotiation
//!   and reverse-mode (server becomes consumer).
//! - **Client** — sliding-window consumer with AIMD/CUBIC/Fixed congestion control.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::Bytes;
use serde_json::json;
use tokio::sync::mpsc;

use ndn_ipc::ForwarderClient;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Data, Interest, Name};
use ndn_security::{Ed25519Signer, HmacSha256Signer, Signer as NdnSigner};
use ndn_transport::CongestionController;

use crate::common::{ConnectConfig, ToolData, ToolEvent};

// ── Per-flow signing state ────────────────────────────────────────────────────

/// Per-flow signing mode, set during session negotiation.
#[derive(Clone)]
enum FlowSignMode {
    /// No signature fields — non-conformant, benchmarking only.
    None,
    /// NDN DigestSha256 (fast path, single allocation, in-place hash).
    DigestSha256,
    /// BLAKE3 digest (DigestBlake3, type 6, registered on the NDN TLV SignatureType registry).
    DigestBlake3,
    /// HMAC-SHA256 or Ed25519 via a boxed `Signer`.
    Custom(Arc<dyn NdnSigner>),
}

type FlowSigners = Arc<std::sync::RwLock<HashMap<String, FlowSignMode>>>;

/// Map a negotiated sign-mode string to a `FlowSignMode`.
///
/// - `"none"`:         no signature (benchmarking only)
/// - `"blake3"`:       DigestBlake3 (type 6, NDN TLV registry)
/// - `"hmac"`:         HMAC-SHA256 keyed by `flow_id`
/// - `"ed25519"`:      server-wide ephemeral Ed25519 key
/// - `"digest_sha256"` / `""` / unrecognised: DigestSha256
fn make_sign_mode(sign_mode: &str, flow_id: &str, ed25519: &Arc<Ed25519Signer>) -> FlowSignMode {
    match sign_mode {
        "none" => FlowSignMode::None,
        "blake3" => FlowSignMode::DigestBlake3,
        "hmac" => {
            let kn: ndn_packet::Name = format!("/iperf-key/{flow_id}")
                .parse()
                .unwrap_or_else(|_| "/iperf-key/unknown".parse().unwrap());
            FlowSignMode::Custom(Arc::new(HmacSha256Signer::new(flow_id.as_bytes(), kn)))
        }
        "ed25519" => FlowSignMode::Custom(Arc::clone(ed25519) as Arc<dyn NdnSigner>),
        _ => FlowSignMode::DigestSha256,
    }
}

/// Apply per-packet signing to a `DataBuilder` according to the negotiated mode.
fn sign_data(builder: DataBuilder, mode: &FlowSignMode) -> bytes::Bytes {
    match mode {
        FlowSignMode::None => builder.sign_none(),
        FlowSignMode::DigestSha256 => builder.sign_digest_sha256(),
        FlowSignMode::DigestBlake3 => builder.sign_digest_blake3(),
        FlowSignMode::Custom(s) => {
            let sig_type = s.sig_type();
            builder.sign_sync(sig_type, None, |region| {
                s.sign_sync(region)
                    .unwrap_or_else(|_| bytes::Bytes::from_static(&[0u8; 32]))
            })
        }
    }
}

// ── Parameter types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IperfServerParams {
    pub conn: ConnectConfig,
    pub prefix: String,
    pub payload_size: usize,
    pub freshness_ms: u64,
    pub quiet: bool,
    /// Interval for reporting statistics, in milliseconds.
    pub interval_ms: u64,
}

#[derive(Debug, Clone)]
pub struct IperfClientParams {
    pub conn: ConnectConfig,
    pub prefix: String,
    pub duration_secs: u64,
    pub initial_window: usize,
    /// Congestion control: "aimd", "cubic", or "fixed".
    pub cc: String,
    pub min_window: Option<f64>,
    pub max_window: Option<f64>,
    pub ai: Option<f64>,
    pub md: Option<f64>,
    pub cubic_c: Option<f64>,
    pub lifetime_ms: u64,
    pub quiet: bool,
    /// Interval for reporting per-interval statistics, in milliseconds.
    pub interval_ms: u64,
    pub reverse: bool,
    pub node_prefix: Option<String>,
    /// Signing mode for session negotiation: "none" | "ed25519" | "hmac".
    pub sign_mode: String,
}

// ── Internal connection helper ────────────────────────────────────────────────

async fn connect_client(conn: &ConnectConfig) -> Result<ForwarderClient> {
    if conn.use_shm {
        Ok(ForwarderClient::connect(&conn.face_socket).await?)
    } else {
        Ok(ForwarderClient::connect_unix_only(&conn.face_socket).await?)
    }
}

// ── Shared helpers ────────────────────────────────────────────────────────────

fn extract_seq(raw: &Bytes) -> Option<u64> {
    let data = Data::decode(raw.clone()).ok()?;
    let last = data.name.components().last()?;
    std::str::from_utf8(&last.value).ok()?.parse().ok()
}

fn format_throughput(bytes: u64, duration: Duration) -> String {
    let secs = duration.as_secs_f64();
    if secs == 0.0 {
        return "0 bps".into();
    }
    let bps = bytes as f64 * 8.0 / secs;
    if bps >= 1_000_000_000.0 {
        format!("{:.2} Gbps", bps / 1_000_000_000.0)
    } else if bps >= 1_000_000.0 {
        format!("{:.2} Mbps", bps / 1_000_000.0)
    } else if bps >= 1_000.0 {
        format!("{:.2} Kbps", bps / 1_000.0)
    } else {
        format!("{:.0} bps", bps)
    }
}

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

fn throughput_bps(bytes: u64, duration: Duration) -> f64 {
    let secs = duration.as_secs_f64();
    if secs == 0.0 {
        0.0
    } else {
        bytes as f64 * 8.0 / secs
    }
}

// ── Interval counters (lock-free) ─────────────────────────────────────────────

struct IntervalCounters {
    bytes: AtomicU64,
    pkts: AtomicU64,
    rtt_sum: AtomicU64,
    rtt_count: AtomicU64,
}

impl IntervalCounters {
    fn new() -> Self {
        Self {
            bytes: AtomicU64::new(0),
            pkts: AtomicU64::new(0),
            rtt_sum: AtomicU64::new(0),
            rtt_count: AtomicU64::new(0),
        }
    }
    fn record(&self, bytes: u64) {
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        self.pkts.fetch_add(1, Ordering::Relaxed);
    }
    fn record_rtt(&self, rtt_us: u64) {
        self.rtt_sum.fetch_add(rtt_us, Ordering::Relaxed);
        self.rtt_count.fetch_add(1, Ordering::Relaxed);
    }
    /// Atomically drain and return (bytes, pkts, rtt_sum, rtt_count).
    fn drain(&self) -> (u64, u64, u64, u64) {
        (
            self.bytes.swap(0, Ordering::Relaxed),
            self.pkts.swap(0, Ordering::Relaxed),
            self.rtt_sum.swap(0, Ordering::Relaxed),
            self.rtt_count.swap(0, Ordering::Relaxed),
        )
    }
}

// ── Session negotiation types ─────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize, Default)]
struct SessionRequest {
    #[serde(default)]
    duration: u64,
    #[serde(default)]
    signing: String,
    #[serde(default)]
    size: usize,
    #[serde(default)]
    reverse: bool,
    #[serde(default)]
    callback: String,
}

#[derive(Debug, serde::Serialize)]
struct SessionResponse {
    signing: String,
    size: usize,
    reverse: bool,
    session_id: String,
}

// ── Server ────────────────────────────────────────────────────────────────────

pub async fn run_server(params: IperfServerParams, tx: mpsc::Sender<ToolEvent>) -> Result<()> {
    let prefix: Name = params.prefix.parse()?;
    let client = connect_client(&params.conn).await?;
    client.register_prefix(&prefix).await?;

    match client.mgmt.service_announce(&prefix).await {
        Ok(_) => {
            let _ = tx
                .send(ToolEvent::info(format!(
                    "  service discovery: announced {prefix}"
                )))
                .await;
        }
        Err(e) => {
            let _ = tx
                .send(ToolEvent::info(format!(
                    "  service discovery: not available ({e}), skipping"
                )))
                .await;
        }
    }

    let transport = if client.is_shm() { "SHM" } else { "Unix" };
    let _ = tx
        .send(ToolEvent::info(format!(
            "ndn-iperf server: prefix={prefix}  transport={transport}  default-payload={}B",
            params.payload_size
        )))
        .await;
    let _ = tx
        .send(ToolEvent::info(
            "  negotiation: enabled — clients may send /<prefix>/<flow-id>/session",
        ))
        .await;
    let _ = tx
        .send(ToolEvent::info(
            "  reverse:   enabled — clients may request reverse-mode testing",
        ))
        .await;
    if params.freshness_ms > 0 {
        let _ = tx
            .send(ToolEvent::info(format!(
                "  freshness: {}ms",
                params.freshness_ms
            )))
            .await;
    }
    let _ = tx
        .send(ToolEvent::info(
            "  waiting for Interests... (Ctrl-C to stop)",
        ))
        .await;

    // Server-wide ephemeral Ed25519 key (benchmark only — key is fixed, not secret).
    let ed25519_signer = Arc::new(Ed25519Signer::from_seed(
        &[0x49u8; 32],
        "/iperf-server-key".parse().unwrap(),
    ));
    // Per-flow signer state: populated by session negotiation, consumed by data loop.
    let flow_signers: FlowSigners = Arc::new(std::sync::RwLock::new(HashMap::new()));

    let counters = Arc::new(IntervalCounters::new());
    let start = Instant::now();

    if !params.quiet {
        let c2 = counters.clone();
        let tx2 = tx.clone();
        let interval_dur = Duration::from_millis(params.interval_ms);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval_dur);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if tx2.is_closed() {
                    break;
                }
                let (bytes, pkts, rtt_sum, rtt_count) = c2.drain();
                let elapsed = start.elapsed();
                let tp = format_throughput(bytes, interval_dur);
                let bps = throughput_bps(bytes, interval_dur);
                let rtt_avg_us = if rtt_count > 0 {
                    rtt_sum / rtt_count
                } else {
                    0
                };
                let rtt_str = if rtt_count > 0 {
                    format!("rtt={:.0}us", rtt_sum as f64 / rtt_count as f64)
                } else {
                    "rtt=n/a".into()
                };
                let _ = tx2
                    .send(
                        ToolEvent::info(format!(
                            "[{:>6.1}s]  {tp:>14}  {pkts:>8} pkt/s  {rtt_str}",
                            elapsed.as_secs_f64()
                        ))
                        .with_data(ToolData::IperfInterval {
                            bytes,
                            throughput_bps: bps,
                            rtt_avg_us,
                        }),
                    )
                    .await;
            }
        });
    }

    let freshness = (params.freshness_ms > 0).then(|| Duration::from_millis(params.freshness_ms));

    let mut total_interests: u64 = 0;
    let mut total_sent: u64 = 0;
    let mut non_interest: u64 = 0;

    loop {
        if tx.is_closed() {
            break;
        }

        let raw = match client.recv().await {
            Some(b) => b,
            None => {
                let _ = tx
                    .send(ToolEvent::info(format!(
                        "  connection closed after {total_interests} Interests"
                    )))
                    .await;
                break;
            }
        };

        let interest = match Interest::decode(raw) {
            Ok(i) => i,
            Err(_) => {
                non_interest += 1;
                continue;
            }
        };
        total_interests += 1;

        let components = interest.name.components();
        let prefix_len = prefix.components().len();

        // Session negotiation: /<prefix>/<flow-id>/session[/<params-digest>]
        // The Interest carries AppParameters, so a ParametersSha256DigestComponent
        // is appended to the name by the encoder — giving prefix_len + 3 total
        // components rather than prefix_len + 2.  Use >= to accept both.
        if components.len() >= prefix_len + 2 {
            let marker = std::str::from_utf8(&components[prefix_len + 1].value).unwrap_or("");
            if marker == "session" {
                let res = handle_session_negotiation(
                    &interest,
                    &client,
                    &prefix,
                    &ServerDefaults {
                        conn: &params.conn,
                        payload_size: params.payload_size,
                        freshness_ms: params.freshness_ms,
                        flow_signers: &flow_signers,
                        ed25519_signer: &ed25519_signer,
                    },
                    tx.clone(),
                )
                .await;
                if let Err(e) = res {
                    let _ = tx
                        .send(ToolEvent::warn(format!("  session negotiation error: {e}")))
                        .await;
                }
                continue;
            }
        }

        // Normal data serving — look up per-flow signer (set during session negotiation).
        let flow_id_str = components
            .get(prefix_len)
            .and_then(|c| std::str::from_utf8(&c.value).ok())
            .unwrap_or("")
            .to_string();
        let sign_mode = flow_signers
            .read()
            .unwrap()
            .get(&flow_id_str)
            .cloned()
            .unwrap_or(FlowSignMode::DigestSha256);

        let payload = vec![0xAAu8; params.payload_size];
        let mut builder = DataBuilder::new((*interest.name).clone(), &payload);
        if let Some(f) = freshness {
            builder = builder.freshness(f);
        }
        let data = sign_data(builder, &sign_mode);

        let data_len = data.len() as u64;
        if let Err(e) = client.send(data).await {
            let _ = tx
                .send(ToolEvent::error(format!("  send error: {e}")))
                .await;
            break;
        }
        total_sent += 1;
        counters.record(data_len);
    }

    let elapsed = start.elapsed();
    let _ = tx.send(ToolEvent::summary(String::new())).await;
    let _ = tx.send(ToolEvent::summary("--- server summary ---")).await;
    let _ = tx
        .send(ToolEvent::summary(format!(
            "  uptime:    {:.1}s",
            elapsed.as_secs_f64()
        )))
        .await;
    let _ = tx
        .send(ToolEvent::summary(format!(
            "  interests: {total_interests}"
        )))
        .await;
    let _ = tx
        .send(ToolEvent::summary(format!("  data sent: {total_sent}")))
        .await;
    if non_interest > 0 {
        let _ = tx
            .send(ToolEvent::summary(format!(
                "  non-interest: {non_interest}"
            )))
            .await;
    }

    Ok(())
}

struct ServerDefaults<'a> {
    conn: &'a ConnectConfig,
    payload_size: usize,
    freshness_ms: u64,
    flow_signers: &'a FlowSigners,
    ed25519_signer: &'a Arc<Ed25519Signer>,
}

async fn handle_session_negotiation(
    interest: &Interest,
    client: &ForwarderClient,
    server_prefix: &Name,
    defaults: &ServerDefaults<'_>,
    tx: mpsc::Sender<ToolEvent>,
) -> Result<()> {
    let default_size = defaults.payload_size;
    let freshness_ms = defaults.freshness_ms;
    let req: SessionRequest = interest
        .app_parameters()
        .and_then(|b| serde_json::from_slice(b).ok())
        .unwrap_or_default();

    let flow_id = interest
        .name
        .components()
        .get(server_prefix.components().len())
        .map(|c| String::from_utf8_lossy(&c.value).to_string())
        .unwrap_or_default();

    let agreed_size = if req.size > 0 { req.size } else { default_size };
    let agreed_sign = match req.signing.as_str() {
        "ed25519" => "ed25519",
        "hmac" => "hmac",
        "blake3" => "blake3",
        "digest_sha256" => "digest_sha256",
        "none" => "none",
        _ => "digest_sha256",
    };

    // Register per-flow sign mode so the main data loop can sign packets for this flow.
    let sign_mode = make_sign_mode(agreed_sign, &flow_id, defaults.ed25519_signer);
    defaults
        .flow_signers
        .write()
        .unwrap()
        .insert(flow_id.clone(), sign_mode);

    let _ = tx.send(
        ToolEvent::info(format!(
            "  session {flow_id}: size={agreed_size}B sign={agreed_sign} duration={}s reverse={}",
            req.duration, req.reverse,
        ))
        .with_data(ToolData::IperfClientConnected {
            flow_id:      flow_id.clone(),
            duration_secs: req.duration,
            sign_mode:    agreed_sign.to_string(),
            payload_size: agreed_size,
            reverse:      req.reverse,
        })
    ).await;

    let resp = SessionResponse {
        signing: agreed_sign.to_string(),
        size: agreed_size,
        reverse: req.reverse,
        session_id: flow_id.clone(),
    };
    let resp_json = serde_json::to_vec(&resp)?;
    let freshness = (freshness_ms > 0).then(|| Duration::from_millis(freshness_ms));

    let mut builder = DataBuilder::new((*interest.name).clone(), &resp_json);
    if let Some(f) = freshness {
        builder = builder.freshness(f);
    }
    client.send(builder.build()).await?;

    // Reverse mode: spawn a consumer task that fetches from the client.
    if req.reverse && !req.callback.is_empty() {
        let callback_prefix: Name = req.callback.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
        let duration = req.duration;
        let size = agreed_size;
        let conn = defaults.conn.clone();
        let server_prefix = server_prefix.clone();
        let tx2 = tx.clone();

        tokio::spawn(async move {
            let _ = tx2
                .send(ToolEvent::info(format!(
                    "  reverse session {flow_id}: fetching from {callback_prefix} for {duration}s"
                )))
                .await;
            if let Err(e) = run_reverse_consumer(
                &conn,
                &callback_prefix,
                &server_prefix,
                &flow_id,
                duration,
                size,
                tx2.clone(),
            )
            .await
            {
                let _ = tx2
                    .send(ToolEvent::warn(format!(
                        "  reverse session {flow_id}: error: {e}"
                    )))
                    .await;
            }
        });
    }

    Ok(())
}

async fn run_reverse_consumer(
    conn: &ConnectConfig,
    callback_prefix: &Name,
    server_prefix: &Name,
    flow_id: &str,
    duration_secs: u64,
    _payload_hint: usize,
    tx: mpsc::Sender<ToolEvent>,
) -> Result<()> {
    let client = connect_client(conn).await?;
    let mut cc = CongestionController::aimd();
    let lifetime = Duration::from_millis(4000);
    let deadline = Instant::now() + Duration::from_secs(duration_secs);
    let interval_dur = Duration::from_secs(1);
    let counters = Arc::new(IntervalCounters::new());
    let start = Instant::now();
    let flow_id = flow_id.to_string();

    let interval_task = {
        let c2 = counters.clone();
        let tx2 = tx.clone();
        let flow_id2 = flow_id.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval_dur);
            ticker.tick().await;
            let mut idx = 0u64;
            loop {
                ticker.tick().await;
                if tx2.is_closed() {
                    break;
                }
                idx += 1;
                let (bytes, pkts, rtt_sum, rtt_count) = c2.drain();
                let bps = throughput_bps(bytes, interval_dur);
                let rtt_avg_us = if rtt_count > 0 {
                    rtt_sum / rtt_count
                } else {
                    0
                };
                let rtt_str = if rtt_count > 0 {
                    format!("rtt={:.0}us", rtt_sum as f64 / rtt_count as f64)
                } else {
                    "rtt=n/a".into()
                };
                let _ = tx2
                    .send(
                        ToolEvent::info(format!(
                            "  [reverse {idx:>4}s]  {:>14}  {pkts:>8} pkt/s  {rtt_str}",
                            format_throughput(bytes, interval_dur)
                        ))
                        .with_data(ToolData::IperfInterval {
                            bytes,
                            throughput_bps: bps,
                            rtt_avg_us,
                        }),
                    )
                    .await;
                let _ = &flow_id2; // suppress unused warning
            }
        })
    };

    let mut timestamps: HashMap<u64, (Instant, u32)> = HashMap::new();
    let mut next_seq: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut received: u64 = 0;
    let mut in_flight: usize = 0;
    let mut rtts: Vec<u64> = Vec::new();
    let mut srtt_us: f64 = 50_000.0;
    let mut past_deadline = false;
    let check_interval = Duration::from_millis(100);
    const MAX_RETRIES: u32 = 3;

    let sent = loop {
        let timeout = if past_deadline {
            Duration::from_millis(500)
        } else {
            check_interval
        };
        match tokio::time::timeout(timeout, client.recv()).await {
            Ok(Some(data_bytes)) => {
                let data_len = data_bytes.len() as u64;
                total_bytes += data_len;
                received += 1;
                let rtt_us = extract_seq(&data_bytes).and_then(|seq| {
                    timestamps.remove(&seq).map(|(t0, _)| {
                        in_flight = in_flight.saturating_sub(1);
                        t0.elapsed().as_micros() as u64
                    })
                });
                cc.on_data();
                if let Some(rtt) = rtt_us {
                    rtts.push(rtt);
                    counters.record_rtt(rtt);
                    srtt_us = srtt_us * 0.875 + rtt as f64 * 0.125;
                }
                counters.record(data_len);
                if !past_deadline {
                    if Instant::now() < deadline {
                        let allowed = cc.window().floor() as usize;
                        while in_flight < allowed {
                            let name = callback_prefix.clone().append(format!("{next_seq}"));
                            client
                                .send(InterestBuilder::new(name).lifetime(lifetime).build())
                                .await?;
                            timestamps.insert(next_seq, (Instant::now(), 0));
                            next_seq += 1;
                            in_flight += 1;
                        }
                    } else {
                        past_deadline = true;
                    }
                }
                if past_deadline && timestamps.is_empty() {
                    break next_seq;
                }
            }
            Ok(None) => break next_seq,
            Err(_) => {
                if Instant::now() >= deadline {
                    past_deadline = true;
                }
                if past_deadline && timestamps.is_empty() {
                    break next_seq;
                }
                let rto =
                    Duration::from_micros((srtt_us * 3.0) as u64).max(Duration::from_millis(200));
                let now = Instant::now();
                let stale: Vec<(u64, u32)> = timestamps
                    .iter()
                    .filter(|(_, (t0, _))| now.duration_since(*t0) >= rto)
                    .map(|(&sq, &(_, r))| (sq, r))
                    .collect();
                let mut gave_up = vec![];
                let mut retx = vec![];
                for (seq, retries) in stale {
                    if retries >= MAX_RETRIES {
                        gave_up.push(seq);
                    } else {
                        retx.push((seq, retries));
                    }
                }
                for seq in gave_up {
                    timestamps.remove(&seq);
                    in_flight = in_flight.saturating_sub(1);
                }
                if !retx.is_empty() {
                    cc.on_timeout();
                    for (seq, retries) in retx {
                        let name = callback_prefix.clone().append(format!("{seq}"));
                        client
                            .send(InterestBuilder::new(name).lifetime(lifetime).build())
                            .await?;
                        timestamps.insert(seq, (Instant::now(), retries + 1));
                    }
                }
            }
        }
        if !past_deadline && Instant::now() < deadline {
            let allowed = cc.window().floor() as usize;
            while in_flight < allowed {
                let name = callback_prefix.clone().append(format!("{next_seq}"));
                client
                    .send(InterestBuilder::new(name).lifetime(lifetime).build())
                    .await?;
                timestamps.insert(next_seq, (Instant::now(), 0));
                next_seq += 1;
                in_flight += 1;
            }
        }
    };

    interval_task.abort();

    let elapsed = start.elapsed();
    let lost = sent.saturating_sub(received);

    // Publish result so the client can retrieve it.
    let result_name = server_prefix.clone().append(&flow_id).append("result");
    let result_json = json!({
        "flow_id": flow_id,
        "duration_s": elapsed.as_secs_f64(),
        "transferred_bytes": total_bytes,
        "throughput": format_throughput(total_bytes, elapsed),
        "sent": sent, "received": received, "lost": lost,
        "rtt_us": if !rtts.is_empty() {
            let mut rs = rtts.clone(); rs.sort_unstable(); let n = rs.len();
            json!({ "avg": rs.iter().sum::<u64>() / n as u64, "min": rs[0], "max": rs[n-1], "p50": rs[n/2], "p99": rs[n*99/100] })
        } else { json!(null) }
    });
    let result_wire = DataBuilder::new(result_name, result_json.to_string().as_bytes())
        .freshness(Duration::from_secs(300))
        .build();
    let _ = client.send(result_wire).await;

    let _ = tx
        .send(ToolEvent::summary(format!(
            "  reverse session {flow_id}: done — {} in {:.2}s = {}",
            format_bytes(total_bytes),
            elapsed.as_secs_f64(),
            format_throughput(total_bytes, elapsed)
        )))
        .await;

    Ok(())
}

// ── Client ────────────────────────────────────────────────────────────────────

pub async fn run_client(params: IperfClientParams, tx: mpsc::Sender<ToolEvent>) -> Result<()> {
    let prefix: Name = params.prefix.parse()?;
    let client = connect_client(&params.conn).await?;

    let transport = if client.is_shm() { "SHM" } else { "Unix" };
    let lifetime = Duration::from_millis(params.lifetime_ms);

    let mut cc = match params.cc.as_str() {
        "aimd" => CongestionController::aimd(),
        "cubic" => CongestionController::cubic(),
        "fixed" => CongestionController::fixed(params.initial_window as f64),
        other => anyhow::bail!("unknown cc: {other}"),
    };
    cc = cc
        .with_window(params.initial_window as f64)
        .with_ssthresh(params.initial_window as f64);
    if let Some(v) = params.min_window {
        cc = cc.with_min_window(v);
    }
    if let Some(v) = params.max_window {
        cc = cc.with_max_window(v);
    }
    if let Some(v) = params.ai {
        cc = cc.with_additive_increase(v);
    }
    if let Some(v) = params.md {
        cc = cc.with_decrease_factor(v);
    }
    if let Some(v) = params.cubic_c {
        cc = cc.with_cubic_c(v);
    }

    let cc_name = match &cc {
        CongestionController::Aimd { .. } => "aimd",
        CongestionController::Cubic { .. } => "cubic",
        CongestionController::Fixed { .. } => "fixed",
    };

    // Unique flow ID.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let flow_id = format!("{:016x}", ((std::process::id() as u64) << 32) | ts as u64);
    let flow_prefix = prefix.clone().append(&flow_id);

    let callback_prefix: Option<Name> = if params.reverse {
        let np = params
            .node_prefix
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("node_prefix required for reverse mode"))?;
        Some(
            format!("{np}/iperf-reverse/{flow_id}")
                .parse()
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        )
    } else {
        None
    };

    // Reverse mode: connect and register the callback prefix BEFORE sending the
    // session negotiation.  The server spawns its consumer immediately after
    // sending the session response, so the FIB entry must already exist or the
    // first batch of Interests will be dropped and retried (or given up).
    let producer_client: Option<ForwarderClient> = if let Some(ref cb_prefix) = callback_prefix {
        let pc = connect_client(&params.conn).await?;
        pc.register_prefix(cb_prefix).await?;
        let _ = tx
            .send(ToolEvent::info(format!(
                "  registered callback prefix: {cb_prefix}"
            )))
            .await;
        Some(pc)
    } else {
        None
    };

    // Session negotiation.
    let session_name = flow_prefix.clone().append("session");
    let session_req = json!({
        "duration": params.duration_secs, "signing": params.sign_mode, "size": 0,
        "reverse": params.reverse,
        "callback": callback_prefix.as_ref().map(|p| p.to_string()).unwrap_or_default(),
    });
    client
        .send(
            InterestBuilder::new(session_name)
                .app_parameters(session_req.to_string().as_bytes())
                .lifetime(lifetime)
                .build(),
        )
        .await?;

    let _ = tx
        .send(ToolEvent::info(format!(
            "ndn-iperf client: prefix={prefix}  transport={transport}  flow={flow_id}"
        )))
        .await;
    let _ = tx
        .send(ToolEvent::info(format!(
            "  duration={}s  window={}  cc={cc_name}  lifetime={}ms",
            params.duration_secs, params.initial_window, params.lifetime_ms
        )))
        .await;
    if params.reverse {
        let _ = tx
            .send(ToolEvent::info(format!(
                "  mode=REVERSE (server fetches from {})",
                callback_prefix.as_ref().unwrap()
            )))
            .await;
    }

    match tokio::time::timeout(lifetime + Duration::from_millis(500), client.recv()).await {
        Ok(Some(raw)) => {
            if let Ok(data) = Data::decode(raw)
                && let Some(content) = data.content()
                && let Ok(resp) = serde_json::from_slice::<serde_json::Value>(content)
            {
                let _ = tx
                    .send(ToolEvent::info(format!(
                        "  negotiated: size={}B sign={} reverse={}",
                        resp["size"], resp["signing"], resp["reverse"]
                    )))
                    .await;
            }
        }
        Ok(None) => anyhow::bail!("connection closed during negotiation"),
        Err(_) => {
            let _ = tx
                .send(ToolEvent::warn(
                    "  session negotiation timeout — server may not support it, proceeding",
                ))
                .await;
        }
    }

    if params.reverse
        && let Some(cb_prefix) = callback_prefix
    {
        let pc = producer_client.expect("producer_client must be set when reverse=true");
        return run_reverse_producer(
            pc,
            &cb_prefix,
            &prefix,
            &flow_id,
            params.duration_secs,
            &params.sign_mode,
            tx,
        )
        .await;
    }

    let _ = tx.send(ToolEvent::info("  testing...")).await;

    let counters = Arc::new(IntervalCounters::new());
    let start = Instant::now();
    let deadline = start + Duration::from_secs(params.duration_secs);

    let interval_task = if !params.quiet {
        let c2 = counters.clone();
        let tx2 = tx.clone();
        let interval_dur = Duration::from_millis(params.interval_ms);
        Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval_dur);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if tx2.is_closed() {
                    break;
                }
                let (bytes, pkts, rtt_sum, rtt_count) = c2.drain();
                let elapsed = start.elapsed();
                let bps = throughput_bps(bytes, interval_dur);
                let rtt_avg_us = if rtt_count > 0 {
                    rtt_sum / rtt_count
                } else {
                    0
                };
                let rtt_str = if rtt_count > 0 {
                    format!("rtt={:.0}us", rtt_sum as f64 / rtt_count as f64)
                } else {
                    "rtt=n/a".into()
                };
                let _ = tx2
                    .send(
                        ToolEvent::info(format!(
                            "[{:>6.1}s]  {:>14}  {pkts:>8} pkt/s  {rtt_str}",
                            elapsed.as_secs_f64(),
                            format_throughput(bytes, interval_dur)
                        ))
                        .with_data(ToolData::IperfInterval {
                            bytes,
                            throughput_bps: bps,
                            rtt_avg_us,
                        }),
                    )
                    .await;
            }
        }))
    } else {
        None
    };

    let mut timestamps: HashMap<u64, (Instant, u32)> = HashMap::new();
    let mut next_seq: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut received: u64 = 0;
    let mut retx_count: u64 = 0;
    let mut timed_out: u64 = 0;
    let mut rtts: Vec<u64> = Vec::new();
    let mut in_flight: usize = 0;
    let mut srtt_us: f64 = 50_000.0;
    const MAX_RETRIES: u32 = 3;

    let window = params.initial_window.min(cc.window().floor() as usize);
    for _ in 0..window {
        let name = flow_prefix.clone().append(format!("{next_seq}"));
        client
            .send(InterestBuilder::new(name).lifetime(lifetime).build())
            .await?;
        timestamps.insert(next_seq, (Instant::now(), 0));
        next_seq += 1;
        in_flight += 1;
    }

    let drain_timeout = Duration::from_millis(500);
    let mut past_deadline = false;
    let check_interval = Duration::from_millis(100);

    let sent = loop {
        let timeout = if past_deadline {
            drain_timeout
        } else {
            check_interval
        };
        match tokio::time::timeout(timeout, client.recv()).await {
            Ok(Some(data_bytes)) => {
                let data_len = data_bytes.len() as u64;
                total_bytes += data_len;
                received += 1;
                let rtt_us = extract_seq(&data_bytes).and_then(|seq| {
                    timestamps.remove(&seq).map(|(t0, _)| {
                        in_flight = in_flight.saturating_sub(1);
                        t0.elapsed().as_micros() as u64
                    })
                });
                cc.on_data();
                if let Some(rtt) = rtt_us {
                    rtts.push(rtt);
                    counters.record_rtt(rtt);
                    srtt_us = srtt_us * 0.875 + rtt as f64 * 0.125;
                }
                counters.record(data_len);
                if !past_deadline {
                    if Instant::now() < deadline {
                        let allowed = cc.window().floor() as usize;
                        while in_flight < allowed {
                            let name = flow_prefix.clone().append(format!("{next_seq}"));
                            client
                                .send(InterestBuilder::new(name).lifetime(lifetime).build())
                                .await?;
                            timestamps.insert(next_seq, (Instant::now(), 0));
                            next_seq += 1;
                            in_flight += 1;
                        }
                    } else {
                        past_deadline = true;
                    }
                }
                if past_deadline && timestamps.is_empty() {
                    break next_seq;
                }
            }
            Ok(None) => {
                let _ = tx.send(ToolEvent::warn("  connection closed")).await;
                break next_seq;
            }
            Err(_) => {
                if past_deadline {
                    if timestamps.is_empty() {
                        break next_seq;
                    }
                    let now = Instant::now();
                    timestamps.retain(|_, (t0, _)| now.duration_since(*t0) < drain_timeout);
                    if timestamps.is_empty() {
                        break next_seq;
                    }
                    continue;
                }
                if Instant::now() >= deadline {
                    past_deadline = true;
                    continue;
                }
                let rto =
                    Duration::from_micros((srtt_us * 3.0) as u64).max(Duration::from_millis(200));
                let now = Instant::now();
                let max_retx = (cc.window() / 2.0).max(2.0) as usize;
                let mut stale: Vec<(u64, u32)> = timestamps
                    .iter()
                    .filter(|(_, (t0, _))| now.duration_since(*t0) >= rto)
                    .map(|(&sq, &(_, r))| (sq, r))
                    .collect();
                let mut gave_up = Vec::new();
                stale.retain(|&(seq, r)| {
                    if r >= MAX_RETRIES {
                        gave_up.push(seq);
                        false
                    } else {
                        true
                    }
                });
                for seq in gave_up {
                    timestamps.remove(&seq);
                    in_flight = in_flight.saturating_sub(1);
                    timed_out += 1;
                }
                stale.truncate(max_retx);
                if !stale.is_empty() {
                    cc.on_timeout();
                    for (seq, retries) in stale {
                        let name = flow_prefix.clone().append(format!("{seq}"));
                        client
                            .send(InterestBuilder::new(name).lifetime(lifetime).build())
                            .await?;
                        timestamps.insert(seq, (Instant::now(), retries + 1));
                        retx_count += 1;
                    }
                }
            }
        }
    };

    // Drop the interval reporter so its tx2 clone is released, allowing the
    // bridge channel to close and signal completion to the dashboard.
    if let Some(h) = interval_task {
        h.abort();
    }

    let actual_elapsed = start.elapsed();
    let in_flight_at_end = timestamps.len() as u64;
    let effective_sent = sent.saturating_sub(in_flight_at_end);
    let lost = effective_sent.saturating_sub(received);
    let loss_pct = if effective_sent > 0 {
        lost as f64 / effective_sent as f64 * 100.0
    } else {
        0.0
    };
    let bps = throughput_bps(total_bytes, actual_elapsed);

    let _ = tx.send(ToolEvent::summary(String::new())).await;
    let _ = tx
        .send(ToolEvent::summary("--- ndn-iperf results ---"))
        .await;
    let _ = tx
        .send(ToolEvent::summary("  mode:        forward (client→server)"))
        .await;
    let _ = tx
        .send(ToolEvent::summary(format!(
            "  duration:    {:.2}s",
            actual_elapsed.as_secs_f64()
        )))
        .await;
    let _ = tx
        .send(ToolEvent::summary(format!(
            "  transferred: {} ({total_bytes} bytes)",
            format_bytes(total_bytes)
        )))
        .await;
    let _ = tx
        .send(ToolEvent::summary(format!(
            "  throughput:  {}",
            format_throughput(total_bytes, actual_elapsed)
        )))
        .await;
    let _ = tx
        .send(ToolEvent::summary(format!(
            "  packets:     {sent} sent, {received} received, {lost} lost ({loss_pct:.1}% loss)"
        )))
        .await;
    if in_flight_at_end > 0 {
        let _ = tx
            .send(ToolEvent::summary(format!(
                "  in-flight:   {in_flight_at_end} (excluded from loss)"
            )))
            .await;
    }
    if retx_count > 0 {
        let _ = tx
            .send(ToolEvent::summary(format!("  retransmits: {retx_count}")))
            .await;
    }
    if timed_out > 0 {
        let _ = tx
            .send(ToolEvent::summary(format!(
                "  timed out:   {timed_out} (gave up after {MAX_RETRIES} retries)"
            )))
            .await;
    }

    let (rtt_avg_us, rtt_p99_us) = if !rtts.is_empty() {
        rtts.sort_unstable();
        let n = rtts.len();
        let avg = rtts.iter().sum::<u64>() / n as u64;
        let p99 = rtts[n * 99 / 100];
        let _ = tx
            .send(ToolEvent::summary(format!(
                "  RTT:         avg={avg}us min={}us max={}us",
                rtts[0],
                rtts[n - 1]
            )))
            .await;
        let _ = tx
            .send(ToolEvent::summary(format!(
                "               p50={}us p95={}us p99={p99}us",
                rtts[n / 2],
                rtts[n * 95 / 100]
            )))
            .await;
        (avg, p99)
    } else {
        (0, 0)
    };

    let _ = tx
        .send(
            ToolEvent::summary(String::new()).with_data(ToolData::IperfSummary {
                duration_secs: actual_elapsed.as_secs_f64(),
                transferred_bytes: total_bytes,
                throughput_bps: bps,
                sent: effective_sent,
                received,
                loss_pct,
                rtt_avg_us,
                rtt_p99_us,
            }),
        )
        .await;

    Ok(())
}

/// Called by `run_client` in reverse mode.
///
/// `client` is already connected and has `callback_prefix` registered — the
/// caller must register the prefix BEFORE sending the session negotiation so
/// the server can start sending Interests immediately upon receiving the
/// session response.
async fn run_reverse_producer(
    client: ForwarderClient,
    callback_prefix: &Name,
    server_prefix: &Name,
    flow_id: &str,
    duration_secs: u64,
    sign_mode: &str,
    tx: mpsc::Sender<ToolEvent>,
) -> Result<()> {
    let _ = tx.send(ToolEvent::info(format!(
        "  reverse mode: serving data on {callback_prefix} for {duration_secs}s  sign={sign_mode}"
    ))).await;

    // Build a per-session ephemeral Ed25519 key for the client producer side.
    let ed25519_signer = Arc::new(Ed25519Signer::from_seed(
        &[0x52u8; 32],
        "/iperf-client-key".parse().unwrap(),
    ));
    let sign_mode_val = make_sign_mode(sign_mode, flow_id, &ed25519_signer);

    let payload = vec![0xAAu8; 8192];
    let deadline = Instant::now() + Duration::from_secs(duration_secs);

    loop {
        if Instant::now() >= deadline {
            break;
        }
        match tokio::time::timeout(Duration::from_millis(100), client.recv()).await {
            Ok(Some(raw)) => {
                if let Ok(interest) = Interest::decode(raw) {
                    let builder = DataBuilder::new((*interest.name).clone(), &payload);
                    let data = sign_data(builder, &sign_mode_val);
                    let _ = client.send(data).await;
                }
            }
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    let _ = tx
        .send(ToolEvent::info(
            "  reverse mode: test complete, fetching result...",
        ))
        .await;

    let result_name = server_prefix.clone().append(flow_id).append("result");
    let _ = client
        .send(
            InterestBuilder::new(result_name)
                .lifetime(Duration::from_secs(10))
                .build(),
        )
        .await;

    match tokio::time::timeout(Duration::from_secs(12), client.recv()).await {
        Ok(Some(raw)) => {
            if let Ok(data) = Data::decode(raw)
                && let Some(content) = data.content()
                && let Ok(v) = serde_json::from_slice::<serde_json::Value>(content)
            {
                let dur = v["duration_s"].as_f64().unwrap_or(0.0);
                let xfer = v["transferred_bytes"].as_u64().unwrap_or(0);
                let sent = v["sent"].as_u64().unwrap_or(0);
                let recv = v["received"].as_u64().unwrap_or(0);
                let lost = v["lost"].as_u64().unwrap_or(0);
                let tp = v["throughput"].as_str().unwrap_or("n/a");
                let bps = xfer as f64 * 8.0 / dur.max(0.001);
                let _ = tx.send(ToolEvent::summary(String::new())).await;
                let _ = tx
                    .send(ToolEvent::summary(
                        "--- ndn-iperf reverse results (server→client) ---",
                    ))
                    .await;
                let _ = tx
                    .send(ToolEvent::summary(format!("  duration:    {dur:.2}s")))
                    .await;
                let _ = tx
                    .send(ToolEvent::summary(format!(
                        "  transferred: {}",
                        format_bytes(xfer)
                    )))
                    .await;
                let _ = tx
                    .send(ToolEvent::summary(format!("  throughput:  {tp}")))
                    .await;
                let _ = tx
                    .send(ToolEvent::summary(format!(
                        "  packets:     {sent} sent, {recv} received, {lost} lost"
                    )))
                    .await;
                let loss_pct = if sent > 0 {
                    lost as f64 / sent as f64 * 100.0
                } else {
                    0.0
                };
                let _ = tx
                    .send(
                        ToolEvent::summary(String::new()).with_data(ToolData::IperfSummary {
                            duration_secs: dur,
                            transferred_bytes: xfer,
                            throughput_bps: bps,
                            sent,
                            received: recv,
                            loss_pct,
                            rtt_avg_us: 0,
                            rtt_p99_us: 0,
                        }),
                    )
                    .await;
            }
        }
        _ => {
            let _ = tx
                .send(ToolEvent::warn("  could not retrieve server result"))
                .await;
        }
    }

    Ok(())
}
