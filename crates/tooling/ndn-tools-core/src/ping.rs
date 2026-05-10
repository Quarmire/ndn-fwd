//! Embeddable NDN ping tool logic.
//!
//! Provides server and client modes for measuring round-trip time to a named prefix.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::mpsc;

use ndn_app::{AppError, Consumer, KeyChain};
use ndn_ipc::ForwarderClient;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::{Interest, Name};
use ndn_security::Signer;

use crate::common::{ConnectConfig, EventLevel, ToolData, ToolEvent};

// ── Parameter types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PingServerParams {
    pub conn: ConnectConfig,
    /// Name prefix to register and respond on.
    pub prefix: String,
    /// Data freshness period in milliseconds (0 = omit).
    pub freshness_ms: u64,
    /// Sign Data packets with Ed25519.
    pub sign: bool,
}

#[derive(Debug, Clone)]
pub struct PingClientParams {
    pub conn: ConnectConfig,
    /// Name prefix to ping.
    pub prefix: String,
    /// Number of pings to send (0 = unlimited).
    pub count: u64,
    /// Interval between pings in milliseconds.
    pub interval_ms: u64,
    /// Interest lifetime in milliseconds.
    pub lifetime_ms: u64,
}

// ── Server ────────────────────────────────────────────────────────────────────

/// Run the ping server. Registers `params.prefix` and responds to every
/// incoming Interest with an empty Data packet.
///
/// Emits [`ToolEvent`]s to `tx` until the router disconnects, `tx` is dropped,
/// or the task is cancelled.
pub async fn run_server(params: PingServerParams, tx: mpsc::Sender<ToolEvent>) -> Result<()> {
    let prefix: Name = params.prefix.parse()?;
    let client = if params.conn.use_shm {
        ForwarderClient::connect(&params.conn.face_socket).await?
    } else {
        ForwarderClient::connect_unix_only(&params.conn.face_socket).await?
    };
    client.register_prefix(&prefix).await?;

    let freshness = (params.freshness_ms > 0).then(|| Duration::from_millis(params.freshness_ms));

    let signer: Option<Arc<dyn Signer>> = if params.sign {
        let keychain = KeyChain::ephemeral(prefix.to_string().as_str())?;
        let signer = keychain.signer()?;
        let _ = tx
            .send(ToolEvent::info(format!(
                "Signing with {} ({:?})",
                signer.key_name(),
                signer.sig_type(),
            )))
            .await;
        Some(signer)
    } else {
        None
    };

    let _ = tx
        .send(ToolEvent::info(format!("PING SERVER {prefix} (listening)")))
        .await;

    let mut served: u64 = 0;
    loop {
        // Exit cleanly if the caller stopped listening.
        if tx.is_closed() {
            break;
        }

        let raw = match client.recv().await {
            Some(b) => b,
            None => break,
        };
        let interest = match Interest::decode(raw) {
            Ok(i) => i,
            Err(_) => continue,
        };

        let payload = served.to_be_bytes();
        let mut builder = DataBuilder::new((*interest.name).clone(), &payload);
        if let Some(f) = freshness {
            builder = builder.freshness(f);
        }

        let data = if let Some(ref signer) = signer {
            let sig_type = signer.sig_type();
            let key_name = signer.key_name().clone();
            let s = signer.clone();
            builder
                .sign(sig_type, Some(&key_name), |region| {
                    let owned = region.to_vec();
                    async move { s.sign(&owned).await.expect("signing failed") }
                })
                .await
        } else {
            builder.sign_digest_sha256()
        };

        client.send(data).await?;
        served += 1;
        let _ = tx
            .send(ToolEvent::info(format!(
                "  reply #{served}: {}",
                interest.name
            )))
            .await;
    }

    Ok(())
}

// ── Client ────────────────────────────────────────────────────────────────────

/// Run the ping client. Sends `params.count` ping Interests (0 = unlimited)
/// and measures RTT. Emits per-packet [`ToolEvent`]s with [`ToolData::PingResult`]
/// and a final [`ToolData::PingSummary`].
pub async fn run_client(params: PingClientParams, tx: mpsc::Sender<ToolEvent>) -> Result<()> {
    let prefix: Name = params.prefix.parse()?;
    let mut consumer = Consumer::connect(&params.conn.face_socket).await?;
    let lifetime_dur = Duration::from_millis(params.lifetime_ms);
    let interval_dur = Duration::from_millis(params.interval_ms);

    let unlimited = params.count == 0;
    let display_count = if unlimited {
        "∞".to_string()
    } else {
        params.count.to_string()
    };
    let _ = tx
        .send(ToolEvent::info(format!(
            "PING {} — {display_count} packets, interval {}ms, lifetime {}ms",
            prefix, params.interval_ms, params.lifetime_ms,
        )))
        .await;

    let mut rtt_results: Vec<u64> = Vec::new();
    let mut timeouts: u64 = 0;
    let mut nacks: u64 = 0;
    let mut seq: u64 = 0;
    let start = Instant::now();

    loop {
        if !unlimited && seq >= params.count {
            break;
        }
        if tx.is_closed() {
            break;
        }

        let name = prefix.clone().append("ping").append(seq.to_string());
        let wire = InterestBuilder::new(name.clone())
            .lifetime(lifetime_dur)
            .build();

        let t0 = Instant::now();
        match consumer.fetch_wire(wire, lifetime_dur).await {
            Ok(data) => {
                let rtt_us = t0.elapsed().as_micros() as u64;
                rtt_results.push(rtt_us);
                let text = format!("  {}: seq={seq} rtt={}", data.name, format_rtt(rtt_us));
                let _ = tx
                    .send(ToolEvent::info(text).with_data(ToolData::PingResult { seq, rtt_us }))
                    .await;
            }
            Err(AppError::Nacked { reason }) => {
                let rtt_us = t0.elapsed().as_micros() as u64;
                nacks += 1;
                let _ = tx
                    .send(ToolEvent::warn(format!(
                        "  seq={seq}: nack ({reason:?}), rtt={}",
                        format_rtt(rtt_us)
                    )))
                    .await;
            }
            Err(AppError::Timeout) => {
                timeouts += 1;
                let _ = tx
                    .send(ToolEvent::warn(format!("  seq={seq}: timeout")))
                    .await;
            }
            Err(e) => {
                let _ = tx
                    .send(ToolEvent::error(format!("  seq={seq}: error ({e})")))
                    .await;
                break;
            }
        }

        seq += 1;
        if unlimited || seq < params.count {
            tokio::time::sleep(interval_dur).await;
        }
    }

    let elapsed = start.elapsed();
    let sent = seq;
    let received = rtt_results.len() as u64;
    let loss_pct = if sent > 0 {
        (sent - received) as f64 / sent as f64 * 100.0
    } else {
        0.0
    };

    let _ = tx.send(ToolEvent::summary(String::new())).await;
    let _ = tx
        .send(ToolEvent::summary(format!(
            "--- {prefix} ping statistics ---"
        )))
        .await;
    let _ = tx.send(ToolEvent::summary(format!(
        "{sent} transmitted, {received} received, {nacks} nacked, {loss_pct:.1}% loss, time {:.1}s",
        elapsed.as_secs_f64(),
    ))).await;

    let (rtt_min_us, rtt_avg_us, rtt_max_us, rtt_p50_us, rtt_p99_us, rtt_stddev) =
        compute_rtt_stats(&mut rtt_results, &tx).await;

    if timeouts > 0 {
        let _ = tx
            .send(ToolEvent::summary(format!("{timeouts} timeouts")))
            .await;
    }

    let _ = tx
        .send(
            ToolEvent::summary(String::new()).with_data(ToolData::PingSummary {
                sent,
                received,
                nacks,
                timeouts,
                loss_pct,
                rtt_min_us,
                rtt_avg_us,
                rtt_max_us,
                rtt_p50_us,
                rtt_p99_us,
                rtt_stddev,
            }),
        )
        .await;

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Compute and emit the RTT statistics line, returning the key values.
async fn compute_rtt_stats(
    rtt_results: &mut [u64],
    tx: &mpsc::Sender<ToolEvent>,
) -> (u64, u64, u64, u64, u64, f64) {
    if rtt_results.is_empty() {
        return (0, 0, 0, 0, 0, 0.0);
    }
    rtt_results.sort_unstable();
    let min = rtt_results[0];
    let max = *rtt_results.last().unwrap();
    let avg = rtt_results.iter().sum::<u64>() / rtt_results.len() as u64;
    let p50 = rtt_results[rtt_results.len() / 2];
    let p99 = rtt_results[(rtt_results.len() as f64 * 0.99) as usize];
    let avg_f = avg as f64;
    let var = rtt_results
        .iter()
        .map(|&r| (r as f64 - avg_f).powi(2))
        .sum::<f64>()
        / rtt_results.len() as f64;
    let stddev = var.sqrt();

    let _ = tx
        .send(ToolEvent {
            text: format!(
                "rtt min/avg/max/p50/p99/stddev = {}/{}/{}/{}/{}/{:.0} µs",
                format_rtt(min),
                format_rtt(avg),
                format_rtt(max),
                format_rtt(p50),
                format_rtt(p99),
                stddev,
            ),
            level: EventLevel::Summary,
            structured: None,
        })
        .await;

    (min, avg, max, p50, p99, stddev)
}

pub fn format_rtt(us: u64) -> String {
    if us >= 1_000_000 {
        format!("{:.1}s", us as f64 / 1_000_000.0)
    } else if us >= 1_000 {
        format!("{:.2}ms", us as f64 / 1_000.0)
    } else {
        format!("{us}µs")
    }
}
