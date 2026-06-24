//! Active **hop-distance traceroute**: how many forwarder hops away a name is.
//!
//! Like IP traceroute it ramps the hop limit (NDN `HopLimit`, the analogue of IP TTL):
//! a forwarder decrements `HopLimit` on ingress and drops the Interest when it reaches 0
//! (`ndn-engine` decode stage), so a too-small `HopLimit` never reaches a responder and
//! the probe times out. The smallest `HopLimit` that draws a response is the forwarder-hop
//! distance to the target.
//!
//! Unlike IP traceroute it does **not** name each intermediate router: NDN forwarders
//! drop a hop-limited Interest silently and do not self-identify (no TTL-exceeded ICMP
//! equivalent), so the per-hop lines are `*` until the target is reached. Per-hop node
//! identity would need forwarder cooperation (a hop-limit-exceeded responder that signs
//! its node name) — a forwarder-side feature, not this tool.
//!
//! It probes a ping-style responder (`<prefix>/ping/<seq>`, fresh per probe so the
//! Content Store never aliases an earlier hop's answer), so run an `ndn-ping` /
//! `ndnpingserver` at the target.

use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::mpsc;

use ndn_app::{AppError, Consumer};
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;

use crate::common::{ConnectConfig, ToolData, ToolEvent};
use crate::ping::format_rtt;

#[derive(Debug, Clone)]
pub struct TracerouteParams {
    pub conn: ConnectConfig,
    /// Prefix of a ping-style responder to probe.
    pub prefix: String,
    /// Highest hop limit to try before giving up.
    pub max_hops: u8,
    /// Probes per hop limit (tolerates loss; the first response wins the hop).
    pub probes: u8,
    /// Per-probe Interest lifetime / timeout, in milliseconds.
    pub lifetime_ms: u64,
}

/// Ramp `HopLimit` from 1 until a response returns (the target's forwarder-hop distance)
/// or `max_hops` is exhausted. Emits a [`ToolData::TracerouteHop`] per hop and a final
/// [`ToolData::TracerouteSummary`].
pub async fn run_client(params: TracerouteParams, tx: mpsc::Sender<ToolEvent>) -> Result<()> {
    let prefix: Name = params.prefix.parse()?;
    let mut consumer = Consumer::connect(&params.conn.face_socket).await?;
    let lifetime = Duration::from_millis(params.lifetime_ms);
    let probes = params.probes.max(1);

    let _ = tx
        .send(ToolEvent::info(format!(
            "TRACEROUTE {prefix} — up to {} hops, {probes} probe(s)/hop, lifetime {}ms",
            params.max_hops, params.lifetime_ms,
        )))
        .await;

    let mut seq: u64 = 0;
    let mut reached_at: Option<u8> = None;

    for hop in 1..=params.max_hops {
        if tx.is_closed() {
            break;
        }
        let mut hop_rtt: Option<u64> = None;
        let mut nack_reason: Option<String> = None;

        for _ in 0..probes {
            // Fresh name per probe: the CS can't alias a shorter hop's earlier answer,
            // and the responder replies fresh.
            let name = prefix.clone().append("ping").append(seq.to_string());
            seq += 1;
            let wire = InterestBuilder::new(name)
                .hop_limit(hop)
                .must_be_fresh()
                .lifetime(lifetime)
                .build();

            let t0 = Instant::now();
            match consumer.fetch_wire(wire, lifetime).await {
                Ok(_) => {
                    hop_rtt = Some(t0.elapsed().as_micros() as u64);
                    break;
                }
                Err(AppError::Nacked { reason }) => {
                    nack_reason = Some(
                        reason
                            .map(|r| format!("{r:?}"))
                            .unwrap_or_else(|| "Unspecified".to_string()),
                    );
                }
                Err(AppError::Timeout) => {}
                Err(e) => {
                    let _ = tx
                        .send(ToolEvent::error(format!("  hop {hop}: error ({e})")))
                        .await;
                    return Ok(());
                }
            }
        }

        match hop_rtt {
            Some(rtt) => {
                let _ = tx
                    .send(
                        ToolEvent::info(format!("  hop {hop}: reached, rtt={}", format_rtt(rtt)))
                            .with_data(ToolData::TracerouteHop {
                                hop,
                                reached: true,
                                rtt_us: Some(rtt),
                            }),
                    )
                    .await;
                reached_at = Some(hop);
                break;
            }
            None => {
                // A Nack means there is no route at all (not a distance) — surface it and
                // stop, as a longer hop limit won't help.
                if let Some(reason) = nack_reason {
                    let _ = tx
                        .send(
                            ToolEvent::warn(format!("  hop {hop}: nack ({reason}) — no route"))
                                .with_data(ToolData::TracerouteHop {
                                    hop,
                                    reached: false,
                                    rtt_us: None,
                                }),
                        )
                        .await;
                    break;
                }
                let _ = tx
                    .send(
                        ToolEvent::info(format!("  hop {hop}: {}", "* ".repeat(probes as usize)))
                            .with_data(ToolData::TracerouteHop {
                                hop,
                                reached: false,
                                rtt_us: None,
                            }),
                    )
                    .await;
            }
        }
    }

    match reached_at {
        Some(hops) => {
            let _ = tx
                .send(
                    ToolEvent::summary(format!("--- {prefix} is {hops} forwarder-hop(s) away ---"))
                        .with_data(ToolData::TracerouteSummary {
                            hops,
                            reached: true,
                        }),
                )
                .await;
        }
        None => {
            let _ = tx
                .send(
                    ToolEvent::summary(format!(
                        "--- {prefix} not reached within {} hops ---",
                        params.max_hops
                    ))
                    .with_data(ToolData::TracerouteSummary {
                        hops: params.max_hops,
                        reached: false,
                    }),
                )
                .await;
        }
    }

    Ok(())
}
