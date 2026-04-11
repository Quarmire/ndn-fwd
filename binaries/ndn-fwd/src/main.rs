//! Standalone NDN forwarder binary.
//!
//! `ndn-router` wraps [`ndn_engine::ForwarderEngine`] with TOML config loading,
//! face setup (UDP, TCP, Multicast, Ethernet, WebSocket, Serial), neighbor
//! discovery, routing protocols, and an NDN-native management socket
//! (NFD-compatible Interest/Data protocol on `/localhost/nfd/`).
//!
//! # Usage
//!
//! ```text
//! ndn-router                    # start with built-in defaults
//! ndn-router -c router.toml    # load config from file
//! ndn-router --help
//! ```
//!
//! Set `RUST_LOG=info` for status, `RUST_LOG=ndn_engine=trace` for pipeline tracing.

use std::collections::VecDeque;
use std::io::Write as IoWrite;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use ndn_config::{CsConfig, ForwarderConfig};
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine};
use ndn_faces::local::InProcFace;
use ndn_packet::Name;
use ndn_security::{FilePib, SecurityManager};
use ndn_store::{ErasedContentStore, LruCs, NullCs, ShardedCs};

// NDN-native management: face listener + Interest/Data handler.
mod mgmt_ndn;

// ─── Runtime filter reload ────────────────────────────────────────────────────

type FilterFn = Box<dyn Fn(&str) + Send + Sync + 'static>;

/// Callback to apply a new filter string to the running tracing subscriber.
/// Set once during `init_tracing` and used by the management handler.
pub(crate) static APPLY_FILTER: OnceLock<FilterFn> = OnceLock::new();

/// Current active filter string (kept in sync with `APPLY_FILTER` calls).
pub(crate) static LOG_FILTER: OnceLock<Mutex<String>> = OnceLock::new();

/// Monotonic sequence counter — each log line gets a unique, ever-increasing id.
/// The dashboard uses this to request only *new* lines each poll cycle.
pub(crate) static LOG_SEQ: AtomicU64 = AtomicU64::new(0);

type LogRingInner = VecDeque<(u64, String)>;

/// In-memory ring buffer of the last 500 log lines.
/// Each entry is `(seq, line)` where `seq` is from `LOG_SEQ`.
/// The dashboard calls `log/get-recent` with the last seq it saw and receives
/// only newer entries, eliminating the duplication problem.
pub(crate) static LOG_RING: OnceLock<Arc<Mutex<LogRingInner>>> = OnceLock::new();

/// `tracing_subscriber::fmt` writer that appends to `LOG_RING`.
struct RingWriter {
    ring: Arc<Mutex<LogRingInner>>,
}

impl IoWrite for RingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let line = String::from_utf8_lossy(buf).trim_end_matches('\n').to_string();
        if !line.is_empty() && let Ok(mut r) = self.ring.lock() {
            let seq = LOG_SEQ.fetch_add(1, Ordering::Relaxed);
            r.push_back((seq, line));
            if r.len() > 500 { r.pop_front(); }
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

struct RingMakeWriter {
    ring: Arc<Mutex<LogRingInner>>,
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RingMakeWriter {
    type Writer = RingWriter;
    fn make_writer(&'a self) -> Self::Writer {
        RingWriter { ring: Arc::clone(&self.ring) }
    }
}

// ─── Entry point ──────────────────────────────────────────────────────────────

/// Parsed CLI arguments.
struct CliArgs {
    config_path: Option<PathBuf>,
    log_level: Option<String>,
}

/// Parse `argv` into CLI arguments.
fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path = None;
    let mut log_level = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                i += 1;
                if let Some(p) = args.get(i) {
                    config_path = Some(PathBuf::from(p));
                }
            }
            "--log-level" => {
                i += 1;
                if let Some(l) = args.get(i) {
                    log_level = Some(l.clone());
                }
            }
            _ => {}
        }
        i += 1;
    }
    CliArgs {
        config_path,
        log_level,
    }
}

/// Initialise the tracing subscriber.
///
/// **Precedence** (highest wins):
/// 1. `RUST_LOG` environment variable
/// 2. `--log-level` CLI flag
/// 3. `[logging] level` from the config file
///
/// When `[logging] file` is set, logs are written to *both* stderr and the
/// file. The file appender is non-blocking so log writes never stall the
/// forwarder.
///
/// Returns an optional guard that must be held for the lifetime of the
/// process — dropping it flushes the file appender.
fn init_tracing(
    config: &ndn_config::LoggingConfig,
    cli_log_level: Option<&str>,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    // Resolve filter: RUST_LOG > --log-level > config level.
    let filter_str = if std::env::var("RUST_LOG").is_ok() {
        // EnvFilter::from_default_env() will pick up RUST_LOG automatically,
        // but we still need a string for the file layer's filter.
        std::env::var("RUST_LOG").unwrap()
    } else if let Some(cli) = cli_log_level {
        cli.to_owned()
    } else {
        config.level.clone()
    };

    // Store the initial filter string for runtime querying.
    let _ = LOG_FILTER.set(Mutex::new(filter_str.clone()));

    // Initialise the ring buffer (safe to call multiple times — OnceLock).
    // Initialise the ring buffer (safe to call multiple times — OnceLock).
    let _ = LOG_RING.get_or_init(|| Arc::new(Mutex::new(VecDeque::<(u64, String)>::new())));

    // Wrap the EnvFilter in a reload layer so it can be changed at runtime.
    let (filter_layer, filter_handle) =
        tracing_subscriber::reload::Layer::new(EnvFilter::new(&filter_str));

    // Register the reload callback used by the management handler.
    let _ = APPLY_FILTER.set(Box::new(move |s: &str| {
        let new_filter = EnvFilter::new(s);
        if let Err(e) = filter_handle.reload(new_filter) {
            tracing::warn!(error = %e, "failed to reload log filter");
        }
        if let Some(m) = LOG_FILTER.get()
            && let Ok(mut guard) = m.lock()
        {
            *guard = s.to_owned();
        }
    }));

    let stderr_layer = tracing_subscriber::fmt::layer()
        .compact()
        .with_target(true)
        .with_thread_ids(false)
        .with_ansi(false);

    // If a log file is configured, set up a non-blocking file appender.
    if let Some(ref path) = config.file {
        let log_path = std::path::Path::new(path);

        // Create parent directories if they don't exist.
        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let file_appender = tracing_appender::rolling::never(
            log_path.parent().unwrap_or(std::path::Path::new(".")),
            log_path
                .file_name()
                .unwrap_or(std::ffi::OsStr::new("ndn-router.log")),
        );
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        let file_layer = tracing_subscriber::fmt::layer()
            .compact()
            .with_target(true)
            .with_thread_ids(false)
            .with_ansi(false)
            .with_writer(non_blocking);

        let ring_layer = LOG_RING.get().map(|ring| {
            tracing_subscriber::fmt::layer()
                .compact()
                .with_target(true)
                .with_thread_ids(false)
                .with_ansi(false)
                .with_writer(RingMakeWriter { ring: Arc::clone(ring) })
        });
        tracing_subscriber::registry()
            .with(filter_layer)
            .with(stderr_layer)
            .with(file_layer)
            .with(ring_layer)
            .init();

        Some(guard)
    } else {
        let ring_layer = LOG_RING.get().map(|ring| {
            tracing_subscriber::fmt::layer()
                .compact()
                .with_target(true)
                .with_thread_ids(false)
                .with_ansi(false)
                .with_writer(RingMakeWriter { ring: Arc::clone(ring) })
        });
        tracing_subscriber::registry()
            .with(filter_layer)
            .with(stderr_layer)
            .with(ring_layer)
            .init();

        None
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = parse_args();

    // Load config or use defaults (before tracing init so we have the
    // logging section available).
    let fwd_config = if let Some(ref path) = cli.config_path {
        ForwarderConfig::from_file(path)?
    } else {
        ForwarderConfig::default()
    };

    // Initialise tracing — must hold the guard until shutdown.
    let _log_guard = init_tracing(&fwd_config.logging, cli.log_level.as_deref());

    if let Some(ref path) = cli.config_path {
        tracing::info!(path = %path.display(), "loading config");
    } else {
        tracing::info!("no config file specified, using defaults");
    }
    if let Some(ref file) = fwd_config.logging.file {
        tracing::info!(path = %file, "logging to file");
    }

    // Resolve CS capacity: prefer [cs] section, fall back to engine.cs_capacity_mb.
    let cs_cap_mb = if fwd_config.cs.capacity_mb != 0 {
        fwd_config.cs.capacity_mb
    } else {
        fwd_config.engine.cs_capacity_mb
    };

    let engine_config = EngineConfig {
        cs_capacity_bytes: cs_cap_mb * 1024 * 1024,
        pipeline_channel_cap: fwd_config.engine.pipeline_channel_cap,
        pipeline_threads: fwd_config.engine.pipeline_threads,
    };

    // ── NDN management: pre-register management AppFace ───────────────────────
    //
    // An AppFace is registered with the engine before build so it gets a
    // run_face_reader task.  After build, /localhost/ndn-ctl is added to the
    // FIB pointing at this face.  The NDN management handler reads Interests
    // from the AppHandle side and writes Data responses back.
    const MGMT_FACE_ID: u32 = 0xFFFF_0001;
    let (mgmt_app_face, mgmt_handle) = InProcFace::new(ndn_transport::FaceId(MGMT_FACE_ID), 64);

    let security_result = load_security(&fwd_config);
    let pib: Option<Arc<FilePib>> = security_result.as_ref().and_then(|(_, path)| {
        FilePib::open(path).ok().map(Arc::new)
    });

    let cs = build_cs(&fwd_config.cs);
    let admission: Arc<dyn ndn_store::CsAdmissionPolicy> =
        match fwd_config.cs.admission_policy.as_str() {
            "admit-all" => Arc::new(ndn_store::AdmitAllPolicy),
            _ => Arc::new(ndn_store::DefaultAdmissionPolicy),
        };

    let security_profile = match fwd_config.security.profile.as_str() {
        "disabled" => ndn_security::SecurityProfile::Disabled,
        "accept-signed" => ndn_security::SecurityProfile::AcceptSigned,
        _ => ndn_security::SecurityProfile::Default,
    };

    let mut builder = EngineBuilder::new(engine_config)
        .face(mgmt_app_face)
        .content_store(cs)
        .admission_policy(admission)
        .security_profile(security_profile);
    if let Some((mgr, _)) = security_result {
        builder = builder.security(mgr);
    }

    // ── Discovery wiring ─────────────────────────────────────────────────────
    //
    // If [discovery] node_name is set, build CompositeDiscovery(ND + SD) and
    // attach it to the engine.  Multicast face IDs are pre-allocated here so
    // they can be handed to UdpNeighborDiscovery / EtherNeighborDiscovery before
    // build(); the actual face sockets are created after build() in the face loop.
    //
    // `discovery_sd` is kept alive alongside the engine so the management
    // handler can call publish()/withdraw() at runtime (Task 6).
    let discovery_sd: Option<std::sync::Arc<ndn_discovery::ServiceDiscoveryProtocol>>;
    let discovery_claimed: Vec<ndn_packet::Name>;
    let pre_allocated_multicast: Vec<(ndn_transport::FaceId, usize)>; // (face_id, config_index)
    // Pre-allocated EtherMulticast face IDs: (face_id, config_index).
    let pre_allocated_ether_mc: Vec<(ndn_transport::FaceId, usize)>;
    // Runtime-mutable handles shared between protocols and the management handler.
    // Initialized to None; set in the discovery wiring block when applicable.
    let mut mgmt_discovery_cfg: Option<Arc<RwLock<ndn_discovery::DiscoveryConfig>>> = None;
    // DVR is not yet wired in the router binary (future work); always None for now.
    let mgmt_dvr_cfg: Option<Arc<RwLock<ndn_routing::DvrConfig>>> = None;

    if fwd_config.discovery.enabled() {
        let node_name_str = fwd_config
            .discovery
            .resolved_node_name()
            .expect("node_name required when discovery is enabled");
        let node_name: ndn_packet::Name = node_name_str
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid discovery node_name: {e}"))?;

        // Determine which transports to run discovery on.
        let disc_transport = fwd_config
            .discovery
            .discovery_transport
            .as_deref()
            .unwrap_or("udp");
        let use_udp = disc_transport == "udp" || disc_transport == "both";
        let use_ether = disc_transport == "ether" || disc_transport == "both";

        // Pre-allocate a FaceId for each UDP multicast face in config.
        let mut multicast_ids: Vec<ndn_transport::FaceId> = Vec::new();
        let mut mc_map: Vec<(ndn_transport::FaceId, usize)> = Vec::new();
        if use_udp {
            for (idx, face_cfg) in fwd_config.faces.iter().enumerate() {
                if matches!(face_cfg, ndn_config::FaceConfig::Multicast { .. }) {
                    let id = builder.alloc_face_id();
                    multicast_ids.push(id);
                    mc_map.push((id, idx));
                }
            }
        }
        pre_allocated_multicast = mc_map;

        // Pre-allocate a FaceId for each EtherMulticast face in config.
        let mut ether_mc_map: Vec<(ndn_transport::FaceId, usize)> = Vec::new();
        if use_ether {
            for (idx, face_cfg) in fwd_config.faces.iter().enumerate() {
                if matches!(face_cfg, ndn_config::FaceConfig::EtherMulticast { .. }) {
                    let id = builder.alloc_face_id();
                    ether_mc_map.push((id, idx));
                }
            }
        }
        pre_allocated_ether_mc = ether_mc_map;

        // Build DiscoveryConfig from profile + overrides.
        let profile_name = fwd_config.discovery.profile.as_deref().unwrap_or("lan");
        let profile = match profile_name {
            "static" => ndn_discovery::DiscoveryProfile::Static,
            "campus" => ndn_discovery::DiscoveryProfile::Campus,
            "mobile" => ndn_discovery::DiscoveryProfile::Mobile,
            "high-mobility" => ndn_discovery::DiscoveryProfile::HighMobility,
            "asymmetric" => ndn_discovery::DiscoveryProfile::Asymmetric,
            _ => ndn_discovery::DiscoveryProfile::Lan,
        };
        let mut disc_cfg = ndn_discovery::DiscoveryConfig::for_profile(&profile);
        if let Some(ms) = fwd_config.discovery.hello_interval_base_ms {
            disc_cfg.hello_interval_base = std::time::Duration::from_millis(ms);
        }
        if let Some(ms) = fwd_config.discovery.hello_interval_max_ms {
            disc_cfg.hello_interval_max = std::time::Duration::from_millis(ms);
        }
        if let Some(v) = fwd_config.discovery.liveness_miss_count {
            disc_cfg.liveness_miss_count = v;
        }
        if let Some(v) = fwd_config.discovery.swim_indirect_fanout {
            disc_cfg.swim_indirect_fanout = v;
        }
        if let Some(v) = fwd_config.discovery.gossip_fanout {
            disc_cfg.gossip_fanout = v;
        }

        let mut protocols: Vec<std::sync::Arc<dyn ndn_discovery::DiscoveryProtocol>> = Vec::new();

        // ── UDP neighbor discovery ─────────────────────────────────────────────
        if use_udp {
            // Determine the UDP unicast listen port so it can be advertised in
            // hellos.  Peers use this port to create a true unicast face instead
            // of pointing at the multicast source port (which would send data as
            // multicast).  Default to 6363 (the IANA-assigned NDN port).
            let unicast_port: u16 = fwd_config
                .faces
                .iter()
                .find_map(|f| match f {
                    ndn_config::FaceConfig::Udp { bind, remote: None } => bind
                        .as_deref()
                        .unwrap_or("0.0.0.0:6363")
                        .parse::<std::net::SocketAddr>()
                        .ok()
                        .map(|a| a.port()),
                    _ => None,
                })
                .unwrap_or(6363);

            let nd = ndn_discovery::UdpNeighborDiscovery::new_multi(
                multicast_ids,
                node_name.clone(),
                disc_cfg.clone(),
            )
            .with_unicast_port(unicast_port);
            // Capture the shared config handle before moving `nd` into Arc.
            mgmt_discovery_cfg = Some(nd.core.config_handle());
            protocols.push(std::sync::Arc::new(nd));
            tracing::info!(node=%node_name, "UDP neighbor discovery enabled");
        }

        // ── Ethernet neighbor discovery (Linux only) ───────────────────────────
        #[cfg(target_os = "linux")]
        if use_ether {
            for (ether_id, idx) in &pre_allocated_ether_mc {
                let iface = match &fwd_config.faces[*idx] {
                    ndn_config::FaceConfig::EtherMulticast { interface } => interface.as_str(),
                    _ => unreachable!(),
                };
                match ndn_faces::l2::get_interface_mac(iface) {
                    Ok(local_mac) => {
                        let ether_nd = ndn_faces::l2::EtherNeighborDiscovery::new_with_config(
                            *ether_id,
                            iface,
                            node_name.clone(),
                            local_mac,
                            disc_cfg.clone(),
                        );
                        protocols.push(std::sync::Arc::new(ether_nd));
                        tracing::info!(iface=%iface, node=%node_name, "Ethernet neighbor discovery enabled");
                    }
                    Err(e) => {
                        tracing::warn!(iface=%iface, error=%e, "failed to get interface MAC, skipping Ethernet ND");
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        if use_ether {
            tracing::warn!(
                "Ethernet neighbor discovery is only supported on Linux; ignoring discovery_transport=ether/both"
            );
        }

        let mut svc_cfg = ndn_discovery::ServiceDiscoveryConfig::default();
        if let Some(v) = fwd_config.discovery.relay_records {
            svc_cfg.relay_records = v;
        }
        if let Some(v) = fwd_config.discovery.auto_fib_cost {
            svc_cfg.auto_fib_cost = v;
        }
        if let Some(v) = fwd_config.discovery.auto_fib_ttl_multiplier {
            svc_cfg.auto_fib_ttl_multiplier = v;
        }

        let sd = std::sync::Arc::new(ndn_discovery::ServiceDiscoveryProtocol::new(
            node_name.clone(),
            svc_cfg,
        ));
        // Register served_prefixes from config via the existing publish() API.
        for prefix_str in &fwd_config.discovery.served_prefixes {
            match prefix_str.parse::<ndn_packet::Name>() {
                Ok(prefix) => {
                    sd.publish(ndn_discovery::ServiceRecord::new(prefix, node_name.clone()));
                    tracing::info!(prefix=%prefix_str, "discovery: registered served prefix");
                }
                Err(e) => {
                    tracing::warn!(prefix=%prefix_str, error=%e, "discovery: invalid served_prefix, skipping");
                }
            }
        }
        protocols.push(
            std::sync::Arc::clone(&sd) as std::sync::Arc<dyn ndn_discovery::DiscoveryProtocol>
        );

        let composite = ndn_discovery::CompositeDiscovery::new(protocols)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        // Collect all claimed prefixes from child protocols before the composite
        // is consumed by the builder (needed for management security enforcement).
        let claimed: Vec<ndn_packet::Name> = composite.all_claimed_prefixes();
        builder = builder.discovery(composite);
        discovery_sd = Some(sd);
        discovery_claimed = claimed;
        tracing::info!(node=%node_name, transport=%disc_transport, "discovery enabled");
    } else {
        pre_allocated_multicast = Vec::new();
        pre_allocated_ether_mc = Vec::new();
        discovery_sd = None;
        discovery_claimed = Vec::new();
    }
    // Keep discovery_sd alive for management handler use.
    let mgmt_discovery_sd = discovery_sd;
    let mgmt_discovery_claimed = discovery_claimed;
    // Silence unused-variable lint on non-Linux where cfg-guarded code that
    // reads pre_allocated_ether_mc is compiled out.
    #[cfg(not(target_os = "linux"))]
    let _ = &pre_allocated_ether_mc;

    let (engine, shutdown) = builder.build().await?;

    // Apply static FIB routes from config.
    for route in &fwd_config.routes {
        let name = parse_name(&route.prefix);
        engine
            .fib()
            .add_nexthop(&name, ndn_transport::FaceId(route.face as u32), route.cost);
        tracing::info!(prefix = %route.prefix, face = route.face, cost = route.cost, "route added");
    }

    // Register the management prefix in the FIB so the pipeline routes
    // /localhost/ndn-ctl/... Interests to the management AppFace.
    engine.fib().add_nexthop(
        &mgmt_ndn::mgmt_prefix(),
        ndn_transport::FaceId(MGMT_FACE_ID),
        0,
    );

    // ── Startup face listeners from config ──────────────────────────────────
    //
    // If no [[face]] entries are configured, start default UDP and TCP
    // listeners on 0.0.0.0:6363 (matches NFD default behavior).

    let cancel = CancellationToken::new();

    let face_configs: std::borrow::Cow<'_, [ndn_config::FaceConfig]> =
        if fwd_config.faces.is_empty() {
            tracing::info!("no [[face]] in config, using defaults: udp+tcp on 0.0.0.0:6363");
            std::borrow::Cow::Owned(vec![
                ndn_config::FaceConfig::Udp {
                    bind: Some("0.0.0.0:6363".into()),
                    remote: None,
                },
                ndn_config::FaceConfig::Tcp {
                    bind: Some("0.0.0.0:6363".into()),
                    remote: None,
                },
            ])
        } else {
            std::borrow::Cow::Borrowed(&fwd_config.faces)
        };

    for (face_idx, face_cfg) in face_configs.iter().enumerate() {
        match face_cfg {
            ndn_config::FaceConfig::Udp { bind, .. } => {
                if let Some(addr) =
                    parse_bind_addr(bind.as_deref().unwrap_or("0.0.0.0:6363"), "UDP")
                {
                    let eng = engine.clone();
                    let c = cancel.clone();
                    tokio::spawn(async move {
                        mgmt_ndn::run_udp_listener(addr, eng, c).await;
                    });
                }
            }
            ndn_config::FaceConfig::Tcp { bind, .. } => {
                if let Some(addr) =
                    parse_bind_addr(bind.as_deref().unwrap_or("0.0.0.0:6363"), "TCP")
                {
                    let eng = engine.clone();
                    let c = cancel.clone();
                    tokio::spawn(async move {
                        mgmt_ndn::run_tcp_listener(addr, eng, c).await;
                    });
                }
            }
            ndn_config::FaceConfig::Multicast {
                group,
                port,
                interface,
            } => {
                let iface: std::net::Ipv4Addr = interface
                    .as_deref()
                    .unwrap_or("0.0.0.0")
                    .parse()
                    .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
                let group_addr: std::net::Ipv4Addr = match group.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::error!(group=%group, error=%e, "invalid multicast group address");
                        continue;
                    }
                };
                // Use the pre-allocated ID if discovery reserved one for this face.
                let id = pre_allocated_multicast
                    .iter()
                    .find(|(_, idx)| *idx == face_idx)
                    .map(|(fid, _)| *fid)
                    .unwrap_or_else(|| engine.faces().alloc_id());
                let port = *port;
                let eng = engine.clone();
                let c = cancel.child_token();
                tokio::spawn(async move {
                    match ndn_faces::net::MulticastUdpFace::new(iface, port, group_addr, id).await {
                        Ok(face) => {
                            eng.add_face_with_persistency(
                                face,
                                c,
                                ndn_transport::FacePersistency::Permanent,
                            );
                            tracing::info!(group=%group_addr, port=%port, iface=%iface, face=%id, "multicast UDP face created");
                        }
                        Err(e) => {
                            tracing::error!(group=%group_addr, port=%port, error=%e, "failed to create multicast UDP face");
                        }
                    }
                });
            }
            ndn_config::FaceConfig::Unix { .. } => {
                // Unix faces are handled by the face listener below.
                tracing::warn!("unix face config ignored (use [management] face_socket)");
            }
            ndn_config::FaceConfig::WebSocket { bind, .. } => {
                let Some(bind_str) = bind.as_deref() else {
                    tracing::error!("websocket face requires 'bind' address");
                    continue;
                };
                if let Some(addr) = parse_bind_addr(bind_str, "WebSocket") {
                    let eng = engine.clone();
                    let c = cancel.clone();
                    tokio::spawn(async move {
                        run_ws_listener(addr, eng, c).await;
                    });
                }
            }
            ndn_config::FaceConfig::Serial { path, baud } => {
                #[cfg(feature = "serial")]
                {
                    let id = engine.faces().alloc_id();
                    match ndn_faces::serial::serial_face_open(id, path, *baud) {
                        Ok(face) => {
                            let c = cancel.child_token();
                            engine.add_face(face, c);
                            tracing::info!(port=%path, baud=%baud, face=%id, "serial face opened");
                        }
                        Err(e) => {
                            tracing::error!(port=%path, error=%e, "failed to open serial face");
                        }
                    }
                }
                #[cfg(not(feature = "serial"))]
                {
                    let _ = (path, baud);
                    tracing::warn!("serial face support not compiled in");
                }
            }
            ndn_config::FaceConfig::EtherMulticast { interface } => {
                #[cfg(target_os = "linux")]
                {
                    // Use pre-allocated ID if EtherND reserved one for this
                    // config index; otherwise allocate a fresh one.
                    let id = pre_allocated_ether_mc
                        .iter()
                        .find(|(_, ci)| *ci == face_idx)
                        .map(|(id, _)| *id)
                        .unwrap_or_else(|| engine.faces().alloc_id());
                    match ndn_faces::l2::MulticastEtherFace::new(id, interface) {
                        Ok(face) => {
                            let c = cancel.child_token();
                            engine.add_face_with_persistency(
                                face,
                                c,
                                ndn_transport::FacePersistency::Permanent,
                            );
                            tracing::info!(iface=%interface, face=%id, "multicast ethernet face opened");
                        }
                        Err(e) => {
                            tracing::error!(iface=%interface, error=%e, "failed to open multicast ethernet face");
                        }
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = interface;
                    tracing::warn!("ether-multicast face only supported on Linux");
                }
            }
        }
    }

    tracing::info!("engine running");

    // ── NDN management ────────────────────────────────────────────────────────

    let face_socket = fwd_config.management.face_socket.clone();
    tracing::info!(socket = %face_socket, prefix = "/localhost/nfd", "NDN management active");

    let ndn_handler_task = tokio::spawn(mgmt_ndn::run_ndn_mgmt_handler(
        mgmt_handle,
        engine.clone(),
        cancel.clone(),
        mgmt_discovery_sd.clone(),
        mgmt_discovery_claimed.clone(),
        Arc::new(fwd_config.clone()),
        pib.clone(),
        mgmt_ndn::MgmtHandles {
            discovery_cfg: mgmt_discovery_cfg,
            dvr_cfg: mgmt_dvr_cfg,
        },
    ));
    let listener_engine = engine.clone();
    let listener_cancel = cancel.clone();
    let ndn_listener_task = tokio::spawn(async move {
        mgmt_ndn::run_face_listener(&face_socket, listener_engine, listener_cancel).await;
    });

    // Wait for Ctrl-C.
    tokio::signal::ctrl_c().await?;

    tracing::info!("shutting down");
    cancel.cancel();

    let _ = ndn_handler_task.await;
    let _ = ndn_listener_task.await;

    shutdown.shutdown().await;
    Ok(())
}

// ─── WebSocket listener ──────────────────────────────────────────────────────

/// Accept WebSocket connections and create a `WebSocketFace` for each.
#[cfg(feature = "websocket")]
async fn run_ws_listener(
    bind_addr: std::net::SocketAddr,
    engine: ForwarderEngine,
    cancel: CancellationToken,
) {
    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(addr=%bind_addr, error=%e, "ws-listener: bind failed");
            return;
        }
    };

    let local = listener.local_addr().unwrap_or(bind_addr);
    tracing::info!(addr=%local, "WebSocket listener ready");

    loop {
        let (stream, peer) = tokio::select! {
            _ = cancel.cancelled() => break,
            r = listener.accept() => match r {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error=%e, "ws-listener: accept error");
                    continue;
                }
            },
        };

        let ws =
            match tokio_tungstenite::accept_async(tokio_tungstenite::MaybeTlsStream::Plain(stream))
                .await
            {
                Ok(ws) => ws,
                Err(e) => {
                    tracing::warn!(peer=%peer, error=%e, "ws-listener: handshake failed");
                    continue;
                }
            };

        let face_id = engine.faces().alloc_id();
        let face = ndn_faces::net::WebSocketFace::from_stream(
            face_id,
            ws,
            peer.to_string(),
            local.to_string(),
        );
        let conn_cancel = cancel.child_token();
        engine.add_face(face, conn_cancel);
        tracing::info!(face=%face_id, peer=%peer, "ws-listener: accepted connection");
    }

    tracing::info!("WebSocket listener stopped");
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Load the router's security identity from the PIB specified in `[security]`.
///
/// When `auto_init` is enabled and no keys exist, generates a new identity
/// with a self-signed certificate.  Returns `Some(SecurityManager)` on
/// success; `None` on failure or when no identity is configured.  Failures
/// are non-fatal: the router starts without a security identity and logs a
/// warning instead.
fn load_security(cfg: &ForwarderConfig) -> Option<(SecurityManager, PathBuf)> {
    let identity_uri = cfg.security.identity.as_ref()?;

    let pib_path = cfg
        .security
        .pib_path
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(default_pib_path);

    let identity = parse_name(identity_uri);

    if cfg.security.auto_init {
        match SecurityManager::auto_init(&identity, &pib_path) {
            Ok((mgr, generated)) => {
                if generated {
                    tracing::info!(
                        identity = %identity_uri,
                        pib = %pib_path.display(),
                        "auto-initialized new security identity"
                    );
                } else {
                    tracing::info!(
                        identity = %identity_uri,
                        pib = %pib_path.display(),
                        "loaded existing security identity from PIB"
                    );
                }
                return Some((mgr, pib_path));
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    identity = %identity_uri,
                    "auto-init failed; starting without security identity"
                );
                return None;
            }
        }
    }

    let pib = match FilePib::open(&pib_path) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                error = %e,
                pib = %pib_path.display(),
                "PIB not found; starting without security identity"
            );
            return None;
        }
    };

    match SecurityManager::from_pib(&pib, &identity) {
        Ok(mgr) => {
            tracing::info!(
                identity = %identity_uri,
                pib = %pib_path.display(),
                "loaded security identity from PIB"
            );
            Some((mgr, pib_path))
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                identity = %identity_uri,
                "failed to load security identity; starting without it"
            );
            None
        }
    }
}

/// Default PIB path: `$HOME/.ndn/pib`.
fn default_pib_path() -> PathBuf {
    let mut p = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"));
    p.push(".ndn");
    p.push("pib");
    p
}

/// Parse a bind address string into a `SocketAddr`, logging errors on failure.
fn parse_bind_addr(bind: &str, label: &str) -> Option<std::net::SocketAddr> {
    match bind.parse() {
        Ok(a) => Some(a),
        Err(e) => {
            tracing::error!(bind=%bind, error=%e, "invalid {label} bind address");
            None
        }
    }
}

/// Parse a URI-style NDN name like `/ndn/test` into a `Name`.
fn parse_name(uri: &str) -> Name {
    uri.parse().unwrap_or_else(|_| Name::root())
}

/// Build a content store from config.
fn build_cs(cfg: &CsConfig) -> Arc<dyn ErasedContentStore> {
    let cap = cfg.capacity_mb * 1024 * 1024;
    match cfg.variant.as_str() {
        "null" => {
            tracing::info!("content store disabled (variant=null)");
            Arc::new(NullCs)
        }
        "sharded-lru" => {
            let n = cfg.shards.unwrap_or(4);
            tracing::info!(
                variant = "sharded-lru",
                shards = n,
                capacity_mb = cfg.capacity_mb,
                "content store"
            );
            Arc::new(ShardedCs::new(
                (0..n).map(|_| LruCs::new(cap / n)).collect(),
            ))
        }
        _ => {
            tracing::info!(
                variant = "lru",
                capacity_mb = cfg.capacity_mb,
                "content store"
            );
            Arc::new(LruCs::new(cap))
        }
    }
}
