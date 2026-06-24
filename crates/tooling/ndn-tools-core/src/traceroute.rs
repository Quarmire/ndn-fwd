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
use bytes::Bytes;
use tokio::sync::mpsc;

use ndn_app::{AppError, Consumer};
use ndn_packet::encode::InterestBuilder;
use ndn_packet::{Data, Name, NameComponent};

use crate::common::{ConnectConfig, ToolData, ToolEvent};
use crate::ping::format_rtt;

/// Wire contract with `ndn-engine`'s traceroute responder — the shared
/// [`ndn_packet::traceroute_wire`] constants (single source of truth, G9.3): the `32=TRH`
/// name marker requesting a hop-identity reply, and the magic prefix on that reply's
/// Content carrying the responding node's name URI.
use ndn_packet::traceroute_wire::{HOP_IDENTITY_MAGIC, TRACEROUTE_KEYWORD};

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
    /// Mark probes so hops running a responder reply with their identity (per-hop names),
    /// continuing the walk until the destination answers. Hops without a responder still
    /// show as `*`.
    pub identify: bool,
}

/// The recovered node name from a hop-identity reply, or `None` if the Content is the
/// destination producer's own answer (no magic prefix).
fn hop_identity(data: &Data) -> Option<Name> {
    let content = data.content()?;
    let rest = content.strip_prefix(HOP_IDENTITY_MAGIC)?;
    std::str::from_utf8(rest).ok()?.parse().ok()
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

    // What a hop's probes resolved to.
    enum Outcome {
        Timeout,
        Nack(String),
        /// Destination answered → distance found.
        Reached(u64),
        /// An intermediate hop named itself (identify mode) → keep ramping.
        Hop(Box<Name>, u64),
    }

    let trace_marker = NameComponent::keyword(Bytes::from_static(TRACEROUTE_KEYWORD));
    let mut seq: u64 = 0;
    let mut reached_at: Option<u8> = None;

    for hop in 1..=params.max_hops {
        if tx.is_closed() {
            break;
        }
        let mut outcome = Outcome::Timeout;

        for _ in 0..probes {
            // Fresh name per probe: the CS can't alias a shorter hop's earlier answer,
            // and the responder replies fresh. In identify mode the `32=TRH` marker asks
            // an expiring hop to name itself.
            let mut name = prefix.clone().append("ping").append(seq.to_string());
            if params.identify {
                name = name.append_component(trace_marker.clone());
            }
            seq += 1;
            let wire = InterestBuilder::new(name)
                .hop_limit(hop)
                .must_be_fresh()
                .lifetime(lifetime)
                .build();

            let t0 = Instant::now();
            match consumer.fetch_wire(wire, lifetime).await {
                Ok(data) => {
                    let rtt = t0.elapsed().as_micros() as u64;
                    outcome = match params.identify.then(|| hop_identity(&data)).flatten() {
                        Some(node) => Outcome::Hop(Box::new(node), rtt), // an intermediate hop
                        None => Outcome::Reached(rtt),         // the destination itself
                    };
                    break;
                }
                Err(AppError::Nacked { reason }) => {
                    outcome = Outcome::Nack(
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

        match outcome {
            Outcome::Reached(rtt) => {
                let _ = tx
                    .send(
                        ToolEvent::info(format!("  hop {hop}: reached, rtt={}", format_rtt(rtt)))
                            .with_data(ToolData::TracerouteHop {
                                hop,
                                reached: true,
                                rtt_us: Some(rtt),
                                node: None,
                            }),
                    )
                    .await;
                reached_at = Some(hop);
                break;
            }
            Outcome::Hop(node, rtt) => {
                let _ = tx
                    .send(
                        ToolEvent::info(format!("  hop {hop}: {node} rtt={}", format_rtt(rtt)))
                            .with_data(ToolData::TracerouteHop {
                                hop,
                                reached: false,
                                rtt_us: Some(rtt),
                                node: Some(node.to_string()),
                            }),
                    )
                    .await;
                // Not the destination — keep ramping to the next hop.
            }
            Outcome::Nack(reason) => {
                // A Nack means no route at all (not a distance) — a longer hop limit
                // won't help, so stop.
                let _ = tx
                    .send(
                        ToolEvent::warn(format!("  hop {hop}: nack ({reason}) — no route"))
                            .with_data(ToolData::TracerouteHop {
                                hop,
                                reached: false,
                                rtt_us: None,
                                node: None,
                            }),
                    )
                    .await;
                break;
            }
            Outcome::Timeout => {
                let _ = tx
                    .send(
                        ToolEvent::info(format!("  hop {hop}: {}", "* ".repeat(probes as usize)))
                            .with_data(ToolData::TracerouteHop {
                                hop,
                                reached: false,
                                rtt_us: None,
                                node: None,
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
