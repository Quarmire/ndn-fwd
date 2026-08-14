//! `[[face]] kind="radio"` — the **wireless medium as one face**, with its
//! **cognitive control loop** running inside the forwarder.
//!
//! A radio face is not a link to one peer; it is the shared broadcast
//! neighbourhood, reached through one or more *radio capabilities*. This module
//! turns a [`RadioDeviceConfig`] list into a [`RadioMediumFace`] the forwarder
//! mounts like any other face (each device → one [`RadioBearer`]: RX unions across
//! them, TX fans out), **and** stands up the cognition loop over it:
//!
//! - **SENSE** — the medium face publishes every captured frame's RSSI/rate into a
//!   [`LinkSignalStore`]; libusb radios additionally run a frame-free occupancy
//!   sampler. Both feed the shared `MediumState`.
//! - **DECIDE** — a background task ticks [`RadioControl`] every ~500 ms; its
//!   `RadioPolicy` reads the medium + name context and emits a per-radio plan.
//! - **ACT** — each radio's [`MediumActuator`] sets the decided rate as driver state
//!   (`FrameIo::set_rate`, so every `inject` uses it — no USB, no cell), and on a
//!   libusb radio the same actuator also retunes channel / TX power via its knobs.
//!
//! Backend + actuation availability is build/platform-gated: the userspace USB
//! Wi-Fi drivers and their channel/power/occupancy actuation need `radio-libusb`
//! (Linux); `af-packet`/`halow` monitor bearers need Linux (rate-only cognition,
//! channel tuned out of band). An unavailable driver is skipped with a warning; the
//! face mounts if any capability came up.
//!
//! **How the TX rate is controlled, per backend.** The `NDN_RADIO_*` rate/knob env
//! vars (`NDN_RADIO_TX_RATE`, `NDN_RADIO_TX_2T`, `NDN_RADIO_TX_RAW`, …) are read only
//! by the **libusb** drivers — they do nothing on an `af-packet` bearer. An af-packet
//! radio's transmit rate is **plan-only**: it comes solely from the cognition plan
//! (DECIDE → the `MediumActuator`'s `set_rate`, applied as the injected frame's
//! radiotap rate). So to bound an af-packet TX rate you either let the worst-receiver
//! cap do it dynamically (a peer's advertised `max_rx_mcs`) or pin it statically with
//! [`RadioDeviceConfig::max_mcs`]/[`max_nss`](RadioDeviceConfig::max_nss) — there is no
//! env knob for it.

use std::sync::atomic::{AtomicBool, AtomicU16};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_config::RadioDeviceConfig;
use ndn_engine::{Fib, FibEntry, ForwarderEngine};
use ndn_packet::{Name, NameComponent};
use ndn_transport::link_service::{LinkServiceFeature, LpLinkService};
use ndn_transport::{Face, FaceId, FacePersistency, Transport};
use tokio_util::sync::CancellationToken;

use ndn_face_monitor_wifi::{
    ContextSource, LinkSignalStore, LossMeter, MediumActuator, RadioBearer, RadioControl, RadioId,
    RadioMediumFace, spawn_control_loop,
};

/// Link-FEC generation size on the medium face (`k` source frames per generation).
const FEC_K: usize = 4;
use ndn_radio_cognition::{NameContext, RadioPolicy, prefix_hash};

/// A [`ContextSource`] backed by the engine's FIB: the medium's active name-contexts
/// are every prefix routed out this face. This is the engine-aware hook — it holds
/// `engine.fib()`, which `FaceFactory::create` cannot reach — and it feeds the *same*
/// [`spawn_control_loop`] the bare factory drives with static contexts.
struct FibContextSource {
    fib: Arc<Fib>,
    face: FaceId,
}

impl ContextSource for FibContextSource {
    fn active(&self) -> Vec<NameContext> {
        active_contexts(&self.fib.dump(), self.face)
    }
}

/// The engine-aware hook, ready to hand to
/// [`RadioMediumFaceFactory::with_context_source`](ndn_face_monitor_wifi::RadioMediumFaceFactory::with_context_source):
/// a builder that captures the FIB and yields a per-face [`FibContextSource`]. With
/// this a *data-driven* `add_face_of_kind("wfb", …)` face gets FIB-derived contexts,
/// exactly like [`mount_radio_face`].
pub fn fib_context_builder(
    fib: Arc<Fib>,
) -> Arc<dyn Fn(FaceId) -> Arc<dyn ContextSource> + Send + Sync> {
    Arc::new(move |face| {
        Arc::new(FibContextSource {
            fib: fib.clone(),
            face,
        }) as Arc<dyn ContextSource>
    })
}

/// How often the cognition loop re-decides (the per-RTT control cadence).
const TICK: Duration = Duration::from_millis(500);

/// One brought-up radio capability: the bearer the medium face carries, plus the
/// optional control handles (channel/power knobs and channel) the cognition loop
/// needs. Portable bearers (af-packet) leave `knobs`/`channel` `None` — rate-only.
struct BuiltBearer {
    bearer: RadioBearer,
    #[cfg_attr(not(feature = "radio-libusb"), allow(dead_code))]
    knobs: Option<Arc<dyn ndn_face_monitor_wifi::RadioKnobs>>,
    #[cfg_attr(not(feature = "radio-libusb"), allow(dead_code))]
    channel: Option<u8>,
    /// The highest HT/VHT MCS this radio can *decode* (`LEGACY_ONLY_RX` = legacy OFDM
    /// only). The node advertises the max over its radios so peers cap the data rate they
    /// reach it at. The 8812au decodes legacy only on 5 GHz (measured), full HT on 2.4.
    rx_mcs: u8,
}

/// Build the `kind="radio"` medium face `id`, mount it on `engine`, and spawn its
/// cognition control loop (cancelled with `cancel`). Errors only if no capability
/// could be brought up.
pub fn mount_radio_face(
    engine: &ForwarderEngine,
    cancel: &CancellationToken,
    id: FaceId,
    radios: &[RadioDeviceConfig],
) -> Result<(), String> {
    // 1. Bring up each capability.
    let mut built = Vec::new();
    for (i, dev) in radios.iter().enumerate() {
        let rid = RadioId(i as u16);
        match build_bearer(rid, dev) {
            Ok(Some(b)) => built.push(b),
            Ok(None) => tracing::warn!(
                target: "face.radio", driver = %dev.driver,
                "radio driver not available on this build/platform; capability skipped",
            ),
            Err(e) => tracing::error!(
                target: "face.radio", driver = %dev.driver, error = %e,
                "radio capability failed to come up; skipped",
            ),
        }
    }
    if built.is_empty() {
        return Err("no radio capability could be brought up".into());
    }

    // 2. The SENSE→DECIDE bridges: a link-signal store (RSSI) and, for the loss loop,
    //    a shared FEC-redundancy cell (ACT) + a residual-loss meter (SENSE).
    let signals = Arc::new(LinkSignalStore::new());
    let fec_redundancy = Arc::new(AtomicU16::new(0));
    let loss = Arc::new(LossMeter::default());
    // Worst-overheard-receiver rate cap (ACT): set true when a legacy-only-RX neighbour is
    // heard, flipping the data plane to the basic legacy rate so it reaches that neighbour.
    let force_legacy = Arc::new(AtomicBool::new(false));
    // A parity floor for known-lossy links (the face-level loss signal can't see
    // single-frame loss): `NDN_RADIO_FEC_MIN=2` pins R≥2. Default 0 = fully driven.
    let fec_floor: u16 = std::env::var("NDN_RADIO_FEC_MIN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // This node's id + reception-report cadence, for cooperative sensing. The id must be
    // stable and distinct per node (it is the neighbour key others record); take it from
    // `NDN_RADIO_NODE_ID`, else an FNV-1a of `/etc/hostname`, else 0 (reports off). The
    // interval defaults to 1 s, tunable via `NDN_RADIO_REPORT_MS` (0 = off).
    let node_id: u64 = std::env::var("NDN_RADIO_NODE_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|h| prefix_hash(&[h.trim().as_bytes()]) | 1)
        })
        .unwrap_or(0);
    let report_ms: u64 = std::env::var("NDN_RADIO_REPORT_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);

    // 3. Build the cognition control plane and bind every radio to it.
    let mut control = RadioControl::new(RadioPolicy::default())
        .with_signals(signals.clone())
        .with_node_id(node_id)
        .with_report_interval(report_ms)
        .with_tick_interval(TICK);
    for b in &built {
        control.register_radio(b.bearer.id, id, b.bearer.cap.clone());
        // ACT: rate as driver state (`FrameIo::set_rate`); on a libusb radio the same
        // actuator retunes channel/power via knobs; and it writes the decided link-FEC
        // redundancy into the shared cell the medium face's coder reads.
        control.add_actuator(Arc::new(
            MediumActuator::new(b.bearer.id, b.bearer.radio.clone(), b.knobs.clone())
                .with_fec_redundancy(fec_redundancy.clone(), fec_floor),
        ));
    }
    // Advertise this node's RX capability = the best (max) over its radios: it is
    // reachable if *any* radio decodes, so a node with an a81a + a legacy-only 8812au is
    // still HT-reachable. Only a node whose every radio is legacy-only advertises
    // `LEGACY_ONLY_RX`, forcing peers that reach it to a legacy data rate.
    let self_rx_mcs = built
        .iter()
        .map(|b| b.rx_mcs)
        .max()
        .unwrap_or(ndn_face_monitor_wifi::FULL_RX_MCS);
    control.set_self_rx_mcs(self_rx_mcs);
    // Active name-contexts are refreshed from the FIB in the loop below (every prefix
    // routed out this face), so cognition decides per name we actually transmit.

    // 4. Data plane, then run the *shared* control loop with a FIB-backed context
    //    source (every ~2 s it re-derives the active names from routes) and hang it on
    //    the transport so it dies with the face. Same `spawn_control_loop` the factory
    //    drives with static contexts — only the source differs.
    let bearers: Vec<RadioBearer> = built.iter().map(|b| b.bearer.clone()).collect();
    let mut running = RadioMediumFace::new(id, bearers)
        .with_signal_sink(signals)
        // Link-FEC: outbound generations carry `k + R` coded frames (R from the shared
        // cell the actuator writes), and the RX side recovers losses + measures residual
        // loss into `loss` — the loss-recovery loop the cognition plane closes. The
        // tail-flush window is short so a lone frame (e.g. a ping Interest) doesn't wait
        // for a full generation.
        .with_link_fec(FEC_K, Duration::from_millis(20), fec_redundancy, loss.clone())
        // Worst-overheard-receiver rate cap: when a legacy-only-RX neighbour is heard, the
        // data plane drops to the basic legacy rate so it reaches that neighbour.
        .with_legacy_gate(force_legacy.clone())
        .build();

    // Aggregate demand at the *routable* prefix: FIB longest-prefix match on the peeked
    // Interest/Data name → truncate to the matched depth → the same `prefix_hash` key
    // `FibContextSource` derives, so demand contexts and decide contexts align. `None`
    // when the name isn't routed via this face (skip the demand event). This is the
    // control plane's only view of the FIB — supplied by the host, not a dep.
    let demand_fib = engine.fib();
    let demand_face = id;
    control.set_prefix_key(Box::new(move |comps: &[&[u8]]| -> Option<u64> {
        let name = Name::from_components(
            comps
                .iter()
                .map(|c| NameComponent::generic(Bytes::copy_from_slice(c))),
        );
        let (depth, entry) = demand_fib.lpm_with_depth(&name)?;
        if !entry.nexthops.iter().any(|n| n.face_id == demand_face) {
            return None;
        }
        Some(prefix_hash(
            &comps.iter().take(depth).copied().collect::<Vec<_>>(),
        ))
    }));

    let control = Arc::new(control);
    #[cfg(feature = "radio-libusb")]
    for b in &built {
        if let (Some(knobs), Some(ch)) = (&b.knobs, b.channel) {
            let _ = control.start_occupancy_sampling(b.bearer.id, ch, knobs.clone(), TICK);
        }
    }

    let source: Arc<dyn ContextSource> = Arc::new(FibContextSource {
        fib: engine.fib(),
        face: id,
    });

    // Loss feedback: every ~2 s fold the measured residual loss into each radio's
    // per-layer residual (`observe_phy_per`) — the signal `RadioPolicy::fec_redundancy`
    // sizes the parity budget from. This closes the loop: residual loss → higher R →
    // more parity on air → residual falls → R backs off.
    let loss_control = control.clone();
    let radio_ids: Vec<RadioId> = built.iter().map(|b| b.bearer.id).collect();
    running.attach_task(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(TICK * 4);
        loop {
            ticker.tick().await;
            let residual = loss.take_ratio();
            for rid in &radio_ids {
                loss_control.observe_phy_per(*rid, residual);
            }
        }
    }));

    // Worst-overheard-receiver rate cap (ACT): every ~2 s, if any fresh neighbour advertised
    // legacy-only RX, flip the shared gate so the data plane injects at the basic legacy rate
    // (reports already do via `send_robust`). Clears when no such neighbour remains — the
    // group rate rises back to the cognition-decided MCS. The doctrine §5 loop, closed.
    let legacy_control = control.clone();
    let legacy_gate = force_legacy.clone();
    running.attach_task(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(TICK * 4);
        loop {
            ticker.tick().await;
            let now = legacy_control.now_ms();
            let need_legacy =
                legacy_control.worst_neighbor_rx_mcs(now) == Some(ndn_face_monitor_wifi::LEGACY_ONLY_RX);
            let was = legacy_gate.swap(need_legacy, std::sync::atomic::Ordering::Relaxed);
            if was != need_legacy {
                tracing::info!(
                    target: "face.radio", legacy = need_legacy,
                    "data-rate cap {} (legacy-only-RX neighbour {})",
                    if need_legacy { "engaged" } else { "released" },
                    if need_legacy { "present" } else { "gone" },
                );
            }
        }
    }));

    running.attach_task(spawn_control_loop(control.clone(), source, TICK, 4));
    // Mount the cognition control as a `LinkServiceFeature` so it observes this face's
    // forwarding events — on_egress Interest → demand, on_ingress Data → satisfy —
    // feeding the joint policy real per-name demand instead of the zeros it decided on
    // before the consolidation dropped this seam. (spawn_control_loop still refreshes
    // the FIB-derived active contexts + ticks; the feature's own tick is idempotent
    // under the actuator's change-cache.)
    let running = Arc::new(running);

    // Reception-report broadcast: periodically wrap this node's report as named Data on
    // /localhop/radio/report/<node> and inject it on the medium. Neighbours route it to
    // `ingest_report` (cooperative sensing), which populates their radio-neighbour set —
    // the multiplicity (distinct from PIT fan-out) that `effective_receivers` pools over
    // for the phy^n receiver gain. Gated internally by cadence + node_id; exits on
    // shutdown or once the bearers close (send error). Not attached to the face because
    // it needs the transport handle the face also owns — the cancel token bounds it.
    if report_ms > 0 && node_id != 0 {
        let bcast_tx = running.clone();
        let bcast_control = control.clone();
        let bcast_cancel = cancel.child_token();
        let period = Duration::from_millis(report_ms.min(1000).max(50));
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(period);
            loop {
                tokio::select! {
                    _ = bcast_cancel.cancelled() => break,
                    _ = ticker.tick() => {
                        if let Some(frame) = bcast_control.broadcast_report_frame() {
                            // Reports go at the basic legacy rate (MostRobust) so every
                            // neighbour decodes them — incl. legacy-only-RX radios like the
                            // 8812au on 5 GHz — not the cognition-optimised data rate.
                            // NDN_RADIO_REPORT_DATA (diagnostic) instead sends via the data
                            // path (CONSERVATIVE intent) to exercise the HT→VHT rate mapping.
                            let r = if std::env::var("NDN_RADIO_REPORT_DATA").is_ok() {
                                bcast_tx.send_bytes(frame).await
                            } else {
                                bcast_tx.send_robust(frame).await
                            };
                            if r.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
            tracing::debug!(target: "face.radio", face = %id, "reception-report broadcast stopped");
        });
    }

    let feature: Arc<dyn LinkServiceFeature> = control;
    let ls = LpLinkService::new().with_extra_feature(feature);
    let face = Face::from_parts(running, Arc::new(ls));
    engine.add_composed_face(face, cancel.child_token(), FacePersistency::OnDemand);

    tracing::info!(target: "face.radio", face = %id, radios = built.len(), "radio medium face mounted with cognition loop");
    Ok(())
}

/// The cognition loop's active name-contexts, derived from the FIB: every prefix
/// currently routed **out this radio face** is a name the node transmits on the
/// medium, so each becomes an origin [`NameContext`] the policy decides a plan for.
/// Falls back to a single root context when no route points here yet, so the loop
/// still senses the medium. Pure over the FIB dump — unit-testable without an engine.
fn active_contexts(entries: &[(Name, Arc<FibEntry>)], face: FaceId) -> Vec<NameContext> {
    let mut ctxs: Vec<NameContext> = entries
        .iter()
        .filter(|(_, e)| e.nexthops.iter().any(|n| n.face_id == face))
        .map(|(name, _)| NameContext::new(name_prefix_hash(name)))
        .collect();
    if ctxs.is_empty() {
        ctxs.push(NameContext::new(prefix_hash(&[b"/"])));
    }
    ctxs
}

/// Cognition's canonical prefix key for a `Name` — FNV-1a over its components, the
/// same [`prefix_hash`] the sense bus keys demand/consistency on.
fn name_prefix_hash(name: &Name) -> u64 {
    let comps: Vec<&[u8]> = name.components().iter().map(|c| c.value.as_ref()).collect();
    prefix_hash(&comps)
}

fn build_bearer(rid: RadioId, dev: &RadioDeviceConfig) -> Result<Option<BuiltBearer>, String> {
    match dev.driver.as_str() {
        "rtl8822e" => build_rtl8822e(rid, dev),
        "rtl8812au" => build_rtl8812au(rid, dev),
        "af-packet" | "halow" => build_afpacket(rid, dev),
        _ => Ok(None),
    }
}

/// Which specific USB dongle to claim, from the config's backend-agnostic `address` string (the USB
/// driver reads it as a `"<bus>-<port>"` topology address or `"#<index>"`) — so a node with two
/// identical Realtek dongles can pin the spare to the radio face and leave the kernel Wi-Fi mesh on
/// the other. Unset ⇒ the first device found.
#[cfg(feature = "radio-libusb")]
fn device_select(dev: &RadioDeviceConfig) -> ndn_face_monitor_wifi::DeviceSelect {
    use ndn_face_monitor_wifi::DeviceSelect;
    dev.address.as_deref().map(DeviceSelect::parse).unwrap_or_default()
}

#[cfg(feature = "radio-libusb")]
fn build_rtl8812au(rid: RadioId, dev: &RadioDeviceConfig) -> Result<Option<BuiltBearer>, String> {
    use ndn_face_monitor_wifi::{
        FrameFormat, RadioCapability, FrameIo, RadioKnobs, Rtl8812auBackend,
    };
    let ch = dev
        .channel
        .ok_or_else(|| "rtl8812au requires a channel".to_string())?;
    // The 8812au defaults to `Raw80211` (its NAN path); the NDN medium face needs the
    // LLC/SNAP-wrapped `RawNdn` frame so injected packets decode as NDN on the peer.
    // `usb-addr`/`usb-index` pin a specific dongle when several identical ones share the host.
    let backend = Rtl8812auBackend::open_select(&device_select(dev))
        .map_err(|e| format!("{e:?}"))?
        .with_format(FrameFormat::RawNdn { ethertype: 0x8624 });
    let backend = Arc::new(backend);
    backend.bring_up_monitor(ch).map_err(|e| format!("{e:?}"))?;
    if let Some(p) = dev.tx_power {
        let _ = backend.set_tx_power(p);
    }
    // Operator opt-ins for the radio's full capability, beyond the regulatory-calibrated
    // default (#38). NDN_RADIO_TX_2T=1 drives both antenna paths; NDN_RADIO_TX_RAW=<0-63>
    // writes the raw TXAGC index (can exceed licensed EIRP — explicit opt-in only).
    if std::env::var("NDN_RADIO_TX_2T").is_ok() {
        let _ = backend.set_tx_2t(true);
    }
    if let Some(raw) = std::env::var("NDN_RADIO_TX_RAW")
        .ok()
        .and_then(|s| s.trim().parse::<u8>().ok())
    {
        let _ = backend.set_tx_power_raw(raw);
        tracing::warn!(raw, "8812au: RAW TXAGC override active (may exceed licensed EIRP)");
    }
    // The 8812au now exposes the `RadioKnobs` seam: its per-rate TXAGC index is a
    // validated dB power knob (#38), plus channel / EDCCA / frame-free occupancy. So
    // cognition drives this bearer's TX power (reciprocity backoff), not just its data
    // plane. Share one backend as both the data-plane radio and the control knobs.
    let knobs: Arc<dyn RadioKnobs> = backend.clone();
    let radio: Arc<dyn FrameIo> = backend;
    let cap = RadioCapability::wifi_monitor_2ghz(vec![ch]).with_wifi_caps(dev.max_mcs, dev.max_nss);
    // The 8812au RX decodes HT and VHT on 5 GHz (bisection 2026-07-24: it decoded 8812au HT
    // and a81a VHT cleanly). The earlier LEGACY_ONLY_RX marking was wrong — it blamed the
    // 8812au RX for what was actually the a81a's broken HT *TX* (now routed to VHT). Full RX.
    let rx_mcs = ndn_face_monitor_wifi::FULL_RX_MCS;
    Ok(Some(BuiltBearer {
        bearer: RadioBearer::wifi(rid, radio, cap),
        knobs: Some(knobs),
        channel: Some(ch),
        rx_mcs,
    }))
}

#[cfg(not(feature = "radio-libusb"))]
fn build_rtl8812au(_rid: RadioId, _dev: &RadioDeviceConfig) -> Result<Option<BuiltBearer>, String> {
    Ok(None) // needs the `radio-libusb` feature (Linux userspace USB driver)
}

#[cfg(feature = "radio-libusb")]
fn build_rtl8822e(rid: RadioId, dev: &RadioDeviceConfig) -> Result<Option<BuiltBearer>, String> {
    use ndn_face_monitor_wifi::{FrameIo, LibUsbRtl88xxBackend, RadioCapability, RadioKnobs};
    let ch = dev
        .channel
        .ok_or_else(|| "rtl8822e requires a channel".to_string())?;
    // Target the `0bda:a81a` (RTL8812EU, driven by the 8822E halmac) *specifically*:
    // an 8812AU (`0x8812`/`0x881a`) is also in `RTL88XX_PIDS`, so a plain `open()`
    // can grab the wrong Realtek device (it reads chip id 0x04, not 0x17, and the
    // 8822E power sequence then fails on it). `usb-addr`/`usb-index` pin *which* a81a when a node
    // has two (e.g. one on the kernel mesh, one spare) — the multi-radio-note ask.
    let backend = Arc::new(
        LibUsbRtl88xxBackend::open_monitor_pid_select(0xa81a, &device_select(dev), ch)
            .map_err(|e| format!("{e:?}"))?,
    );
    if let Some(p) = dev.tx_power {
        let _ = backend.set_tx_power(p as u32);
    }
    let radio: Arc<dyn FrameIo> = backend.clone();
    let knobs: Arc<dyn RadioKnobs> = backend;
    let cap = RadioCapability::wifi_monitor_5ghz(vec![ch]).with_wifi_caps(dev.max_mcs, dev.max_nss);
    Ok(Some(BuiltBearer {
        bearer: RadioBearer::wifi(rid, radio, cap),
        knobs: Some(knobs),
        channel: Some(ch),
        // **Single RX chain, not full HT/VHT.** This userspace RTL8812EU (88xx backend) brings up one
        // RX chain, so it decodes single-stream HT (MCS 0–7) + legacy but *no* 2-stream frame at any
        // index (field-measured 2026-08-13: MCS 0–7 decode, 8–15 do not). Advertising `FULL_RX_MCS`
        // here made a peer transmit 2-stream MCS 9 that this radio could never decode — a one-way link.
        // The worst-receiver cap in `RadioPolicy` reads this and pins the peer's data rate to
        // single-stream ≤ MCS 7. (Not `LEGACY_ONLY_RX`: MCS 0–7 *do* work, and legacy-6M would throw
        // away ~10× the throughput.)
        rx_mcs: ndn_face_monitor_wifi::SINGLE_STREAM_HT_RX_MCS,
    }))
}

#[cfg(not(feature = "radio-libusb"))]
fn build_rtl8822e(_rid: RadioId, _dev: &RadioDeviceConfig) -> Result<Option<BuiltBearer>, String> {
    Ok(None) // needs the `radio-libusb` feature (Linux userspace USB driver)
}

#[cfg(target_os = "linux")]
fn build_afpacket(rid: RadioId, dev: &RadioDeviceConfig) -> Result<Option<BuiltBearer>, String> {
    use ndn_face_monitor_wifi::{AfPacketBackend, FrameFormat, FrameIo, RadioCapability};
    let iface = dev
        .interface
        .as_deref()
        .ok_or_else(|| format!("{} requires an interface", dev.driver))?;
    let channels: Vec<u8> = dev.channel.into_iter().collect();
    let (fmt, cap) = if dev.driver == "halow" {
        (
            FrameFormat::RawNdnS1g { ethertype: 0x8624 },
            RadioCapability::wifi_halow_s1g(channels),
        )
    } else {
        (
            FrameFormat::RawNdn { ethertype: 0x8624 },
            RadioCapability::wifi_monitor_5ghz(channels),
        )
    };
    // Static per-radio rate ceilings (config `max-mcs`/`max-nss`) — the declarative way to cap an
    // af-packet TX (which has no NDN_RADIO_* env knobs; its rate is plan-only). Cognition reads the
    // clamped ceiling, so this bounds the transmit rate with no other plumbing.
    let cap = cap.with_wifi_caps(dev.max_mcs, dev.max_nss);
    let backend = AfPacketBackend::new(iface, fmt)
        .map_err(|e| format!("{e:?}"))?
        .with_capability(cap.clone());
    let radio: Arc<dyn FrameIo> = Arc::new(backend);
    // af-packet has no in-band channel/power knobs (tuned out of band via `iw`), so
    // cognition is rate-only here.
    Ok(Some(BuiltBearer {
        bearer: RadioBearer::wifi(rid, radio, cap),
        knobs: None,
        channel: dev.channel,
        rx_mcs: ndn_face_monitor_wifi::FULL_RX_MCS, // kernel af-packet radios decode full HT
    }))
}

#[cfg(not(target_os = "linux"))]
fn build_afpacket(_rid: RadioId, _dev: &RadioDeviceConfig) -> Result<Option<BuiltBearer>, String> {
    Ok(None) // af-packet / HaLow monitor bearers are Linux-only
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_engine::FibNexthop;
    use std::str::FromStr;

    fn to(face: FaceId, cost: u32) -> FibNexthop {
        FibNexthop { face_id: face, cost }
    }

    #[test]
    fn active_contexts_are_the_prefixes_routed_out_this_face() {
        let radio = FaceId(7);
        let other = FaceId(2);
        let entries = vec![
            (
                Name::from_str("/a/b").unwrap(),
                Arc::new(FibEntry { nexthops: vec![to(radio, 0)] }),
            ),
            (
                Name::from_str("/c").unwrap(),
                Arc::new(FibEntry { nexthops: vec![to(other, 0)] }),
            ),
            (
                Name::from_str("/d").unwrap(),
                Arc::new(FibEntry { nexthops: vec![to(other, 5), to(radio, 10)] }),
            ),
        ];

        let ctxs = active_contexts(&entries, radio);
        assert_eq!(ctxs.len(), 2, "only /a/b and /d route out the radio face");
        let want_ab = name_prefix_hash(&Name::from_str("/a/b").unwrap());
        assert!(ctxs.iter().any(|c| c.prefix_hash == want_ab), "keys are the canonical prefix hash");
        assert!(ctxs.iter().all(|c| c.is_origin), "FIB-routed prefixes are origin contexts");
    }

    #[test]
    fn empty_fib_falls_back_to_a_root_context() {
        let ctxs = active_contexts(&[], FaceId(7));
        assert_eq!(ctxs.len(), 1);
        assert_eq!(ctxs[0].prefix_hash, prefix_hash(&[b"/"]));
    }
}
