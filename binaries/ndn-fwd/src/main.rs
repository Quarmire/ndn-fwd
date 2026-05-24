//! `ndn-fwd` — the standalone NDN forwarder binary. Wraps
//! [`ndn_engine::ForwarderEngine`] with TOML config, face setup, neighbour
//! discovery, routing protocols, and NFD-compatible management on
//! `/localhost/nfd/`.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use anyhow::Result;
use tokio_util::sync::CancellationToken;

use ndn_config::ForwarderConfig;
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_security::FilePib;

use ndn_mgmt as mgmt_ndn;

fn build_obs_retention(
    cfg: &ndn_config::ObservabilityTomlConfig,
) -> ndn_observability::SpanRetention {
    let default = ndn_observability::SpanRetention::default();
    let window = if cfg.retention.is_empty() {
        default.window
    } else {
        humantime::parse_duration(&cfg.retention).unwrap_or(default.window)
    };
    let max_bytes = if cfg.max_bytes == 0 {
        default.max_bytes
    } else {
        cfg.max_bytes
    };
    let max_spans = if cfg.max_spans == 0 {
        default.max_spans
    } else {
        cfg.max_spans
    };
    ndn_observability::SpanRetention {
        window,
        max_bytes,
        max_spans,
    }
}

mod demo_ca;
#[cfg(feature = "smtp")]
mod smtp_email;
mod installs;
mod face_setup;
mod host_helpers;
mod security_init;
mod tracing_init;
mod transport_listeners;

pub(crate) use face_setup::{FaceSetupState, run_face_setup};
pub(crate) use host_helpers::{
    build_cs, load_coding_handler, load_localhop_validator, load_mgmt_validator,
    load_rate_limit_pair, parse_bind_addr, parse_name,
};
pub(crate) use security_init::load_security;
use tracing_init::{build_log_inspector, init_tracing};

struct CliArgs {
    config_path: Option<PathBuf>,
    log_level: Option<String>,
    list_modules: bool,
}

fn parse_args() -> CliArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut config_path = None;
    let mut log_level = None;
    let mut list_modules = false;
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
            "--modules" => {
                list_modules = true;
            }
            _ => {}
        }
        i += 1;
    }
    CliArgs {
        config_path,
        log_level,
        list_modules,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = parse_args();

    if cli.list_modules {
        for target in ndn_engine::observability::targets::enumerate() {
            println!("{target}");
        }
        return Ok(());
    }

    // Load config before tracing init so the logging section is available.
    // Hold the raw TOML so cfg-gated parsers (fec, rate-limit) can read
    // their own sections without re-loading or coupling `ForwarderConfig`
    // to draft/extension crates.
    let raw_toml: Option<String> = match cli.config_path.as_ref() {
        Some(path) => Some(std::fs::read_to_string(path)?),
        None => None,
    };
    let fwd_config = match raw_toml.as_deref() {
        Some(s) => s.parse::<ForwarderConfig>()?,
        None => ForwarderConfig::default(),
    };

    // Build the span publisher first so it can attach to the tracing
    // subscriber before any spans open. Installed on the engine after build.
    let obs_publisher: Option<Arc<ndn_observability::SpanPublisher>> =
        if fwd_config.observability.publish_to_ndn {
            use std::str::FromStr;
            let obs_cfg = &fwd_config.observability;
            let prefix = ndn_packet::Name::from_str(&obs_cfg.ndn_prefix)
                .unwrap_or_else(|_| ndn_packet::Name::from_str("/localhost/nfd/observability")
                    .expect("static"));
            let retention = build_obs_retention(obs_cfg);
            Some(ndn_observability::SpanPublisher::new(prefix, retention))
        } else {
            None
        };

    // Hold the tracing guard until shutdown. `obs_layer` (Some when
    // observability is enabled) wires the LP `TraceContext` propagation
    // hooks below.
    let tracing_handles = init_tracing(
        &fwd_config.logging,
        cli.log_level.as_deref(),
        obs_publisher
            .clone()
            .map(|p| (p, fwd_config.observability.sample)),
    );
    let _log_guard = tracing_handles.log_guard;
    let obs_layer = tracing_handles.obs_layer;

    tracing::warn!(
        target: "engine",
        "NOTICE: ndn-rs is primarily AI-authored and not yet proven spec-compliant. \
         See (internal) and \
         testbed/EXPECTED_FAILURES.md for known issues. Do not use as a reference \
         implementation of NDN."
    );

    if let Some(ref path) = cli.config_path {
        tracing::info!(target: "engine", path = %path.display(), "loading config");
    } else {
        tracing::info!(target: "engine", "no config file specified, using defaults");
    }
    if let Some(ref file) = fwd_config.logging.file {
        tracing::info!(target: "engine", path = %file, "logging to file");
    }

    // Prefer [cs].capacity_mb, fall back to engine.cs_capacity_mb.
    let cs_cap_mb = if fwd_config.cs.capacity_mb != 0 {
        fwd_config.cs.capacity_mb
    } else {
        fwd_config.engine.cs_capacity_mb
    };

    let engine_config = EngineConfig {
        cs_capacity_bytes: cs_cap_mb * 1024 * 1024,
        pipeline_channel_cap: fwd_config.engine.pipeline_channel_cap,
        pipeline_threads: fwd_config.engine.pipeline_threads,
        reflexive: ndn_engine::ReflexiveConfig {
            enabled: fwd_config.reflexive.enabled,
            max_per_face: fwd_config.reflexive.max_per_face,
            max_lifetime: std::time::Duration::from_millis(fwd_config.reflexive.max_lifetime_ms),
        },
        ..EngineConfig::default()
    };

    let security_init = load_security(&fwd_config);
    // Capture the identity signer before `security_init.mgr` moves into the
    // EngineBuilder; DV's `StaticTrust`/`LvsTrust` modes consume it.
    let identity_signer: Option<std::sync::Arc<dyn ndn_security::Signer>> =
        security_init.mgr.any_signer();
    let mgmt_validator = load_mgmt_validator(&fwd_config.security.mgmt)?;
    let mut localhop_validator = load_localhop_validator(&fwd_config.security.mgmt)?;

    // Prepare the demo CA's in-process face and ephemeral identity before
    // build so the face can be attached, and splice its self-signed cert
    // into the localhop validator anchors so issued certs work without an
    // on-disk PIB.
    let demo_ca_artifacts = if fwd_config.demo_ca.enabled {
        let (face, spawn) = demo_ca::prepare(&fwd_config.demo_ca)?;
        localhop_validator = Some(demo_ca::install_localhop_anchor(
            &spawn.keychain,
            localhop_validator,
        )?);
        Some((face, spawn))
    } else {
        None
    };
    let pib: Option<Arc<FilePib>> = security_init
        .pib_path
        .as_ref()
        .and_then(|path| FilePib::open(path).ok().map(Arc::new));
    let security_is_ephemeral = security_init.is_ephemeral;

    let cs = build_cs(&fwd_config.cs);
    let admission: Arc<dyn ndn_store::CsAdmissionPolicy> =
        match fwd_config.cs.admission_policy.as_str() {
            "admit-all" => Arc::new(ndn_store::AdmitAllPolicy),
            _ => Arc::new(ndn_store::DefaultAdmissionPolicy),
        };

    let security_profile = if !fwd_config.security.validator_enabled {
        ndn_security::SecurityProfile::Disabled
    } else {
        match fwd_config.security.profile.as_str() {
            "disabled" => ndn_security::SecurityProfile::Disabled,
            "accept-signed" => ndn_security::SecurityProfile::AcceptSigned,
            _ => ndn_security::SecurityProfile::Default,
        }
    };

    // Parse [coding] and [rate-limit] from the same raw TOML.
    #[cfg(feature = "fec")]
    let coding_handler_arc: Option<Arc<ndn_coding::CodingMgmtHandler>> = match raw_toml.as_deref() {
        Some(s) => Some(load_coding_handler(s)?),
        None => None,
    };
    #[cfg(feature = "rate-limit")]
    let (rate_limit_handler_arc, rate_limit_hook): (
        Option<Arc<ndn_ratelimit::RateLimitMgmtHandler>>,
        Option<Arc<dyn ndn_engine::RateLimitHook>>,
    ) = match raw_toml.as_deref() {
        Some(s) => load_rate_limit_pair(s)?,
        None => (None, None),
    };

    let mut builder = EngineBuilder::new(engine_config)
        .content_store(cs)
        .admission_policy(admission)
        .security_profile(security_profile)
        .security(security_init.mgr);

    #[cfg(feature = "rate-limit")]
    {
        builder = builder.with_rate_limit_hook(rate_limit_hook.clone());
    }

    let demo_ca_spawn = match demo_ca_artifacts {
        Some((face, spawn)) => {
            builder = builder.face(face);
            Some(spawn)
        }
        None => None,
    };

    for rule_cfg in &fwd_config.security.rules {
        let rule_text = format!("{} => {}", rule_cfg.data, rule_cfg.key);
        match ndn_security::SchemaRule::parse(&rule_text) {
            Ok(rule) => {
                builder = builder.schema_rule(rule);
            }
            Err(e) => {
                tracing::warn!(
                    target: "security",
                    data = %rule_cfg.data,
                    key = %rule_cfg.key,
                    error = %e,
                    "ignoring invalid [[security.rule]] in config"
                );
            }
        }
    }

    // Multicast and auto-enumerated face IDs are allocated before `build`
    // so discovery protocols can reference them; the actual face sockets
    // are bound after build in the face setup loop. `discovery_sd` outlives
    // build so the management handler can call `publish`/`withdraw`.
    let discovery_sd: Option<std::sync::Arc<ndn_discovery::ServiceDiscoveryProtocol>>;
    let discovery_claimed: Vec<ndn_packet::Name>;
    let pre_allocated_multicast: Vec<(ndn_transport::FaceId, usize)>;
    let pre_allocated_ether_mc: Vec<(ndn_transport::FaceId, usize)>;
    let auto_ether_pre_alloc: Vec<(ndn_transport::FaceId, String)>;
    let auto_udp_pre_alloc: Vec<(ndn_transport::FaceId, String, std::net::Ipv4Addr)>;
    let mgmt_discovery_cfg: Option<Arc<RwLock<ndn_discovery::DiscoveryConfig>>> = None;

    let auto_ether_ifaces: Vec<ndn_face_native::iface::InterfaceInfo> =
        if fwd_config.face_system.ether.auto_multicast {
            let list = ndn_face_native::iface::list_interfaces();
            tracing::debug!(
                target: "face.system",
                total = list.len(),
                "interface enumeration for ether auto_multicast"
            );
            list.into_iter()
                .filter(|i| i.is_up && i.is_multicast && !i.is_loopback)
                .filter(|i| {
                    ndn_face_native::iface::interface_allowed(
                        &i.name,
                        &fwd_config.face_system.ether.whitelist,
                        &fwd_config.face_system.ether.blacklist,
                    )
                })
                .collect()
        } else {
            vec![]
        };

    let auto_udp_ifaces: Vec<(String, std::net::Ipv4Addr)> =
        if fwd_config.face_system.udp.auto_multicast {
            let list = ndn_face_native::iface::list_interfaces();
            tracing::debug!(
                target: "face.system",
                total = list.len(),
                "interface enumeration for udp auto_multicast"
            );
            list.into_iter()
                .filter(|i| i.is_up && i.is_multicast && !i.is_loopback)
                .filter(|i| {
                    ndn_face_native::iface::interface_allowed(
                        &i.name,
                        &fwd_config.face_system.udp.whitelist,
                        &fwd_config.face_system.udp.blacklist,
                    )
                })
                .flat_map(|i| {
                    let name = i.name.clone();
                    i.ipv4_addrs.into_iter().map(move |a| (name.clone(), a))
                })
                .collect()
        } else {
            vec![]
        };

    if fwd_config.discovery.enabled() {
        let node_name_str = fwd_config
            .discovery
            .resolved_node_name()
            .expect("node_name required when discovery is enabled");
        let node_name: ndn_packet::Name = node_name_str
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid discovery node_name: {e}"))?;

        let disc_transport = fwd_config
            .discovery
            .discovery_transport
            .as_deref()
            .unwrap_or("udp");
        let use_udp = disc_transport == "udp" || disc_transport == "both";
        let use_ether = disc_transport == "ether" || disc_transport == "both";

        let mut mc_map: Vec<(ndn_transport::FaceId, usize)> = Vec::new();
        if use_udp {
            for (idx, face_cfg) in fwd_config.faces.iter().enumerate() {
                if matches!(face_cfg, ndn_config::FaceConfig::Multicast { .. }) {
                    let id = builder.alloc_face_id();
                    mc_map.push((id, idx));
                }
            }
        }
        pre_allocated_multicast = mc_map;

        let mut auto_udp_ids: Vec<(ndn_transport::FaceId, String, std::net::Ipv4Addr)> = Vec::new();
        if use_udp {
            for (iface_name, addr) in &auto_udp_ifaces {
                let id = builder.alloc_face_id();
                auto_udp_ids.push((id, iface_name.clone(), *addr));
            }
        }

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

        let mut auto_ether_ids: Vec<(ndn_transport::FaceId, String)> = Vec::new();
        if use_ether {
            for iface_info in &auto_ether_ifaces {
                let id = builder.alloc_face_id();
                auto_ether_ids.push((id, iface_info.name.clone()));
            }
        }
        auto_ether_pre_alloc = auto_ether_ids.clone();
        auto_udp_pre_alloc = auto_udp_ids;

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
        let mut protocols: Vec<std::sync::Arc<dyn ndn_discovery::DiscoveryProtocol>> = Vec::new();

        if use_udp {
            let nd = ndn_discovery::NeighborProbeProtocol::new(
                node_name.clone(),
                disc_cfg.hello_interval_base,
                disc_cfg.liveness_miss_count as u8,
            );
            protocols.push(std::sync::Arc::new(nd));
            tracing::info!(target: "discovery", node=%node_name, "neighbor liveness probe enabled");
        }

        // Ethernet neighbor discovery is Linux-only.
        #[cfg(target_os = "linux")]
        if use_ether {
            for (ether_id, idx) in &pre_allocated_ether_mc {
                let iface = match &fwd_config.faces[*idx] {
                    ndn_config::FaceConfig::EtherMulticast { interface } => interface.as_str(),
                    _ => unreachable!(),
                };
                match ndn_face_native::l2::get_interface_mac(iface) {
                    Ok(local_mac) => {
                        let ether_nd = ndn_discovery::EtherNeighborDiscovery::new_with_config(
                            *ether_id,
                            iface,
                            node_name.clone(),
                            local_mac,
                            disc_cfg.clone(),
                        );
                        protocols.push(std::sync::Arc::new(ether_nd));
                        tracing::info!(target: "discovery", iface=%iface, node=%node_name, "Ethernet neighbor discovery enabled");
                    }
                    Err(e) => {
                        tracing::warn!(target: "discovery", iface=%iface, error=%e, "failed to get interface MAC, skipping Ethernet ND");
                    }
                }
            }
            for (ether_id, iface_name) in &auto_ether_ids {
                match ndn_face_native::l2::get_interface_mac(iface_name) {
                    Ok(local_mac) => {
                        let ether_nd = ndn_discovery::EtherNeighborDiscovery::new_with_config(
                            *ether_id,
                            iface_name.as_str(),
                            node_name.clone(),
                            local_mac,
                            disc_cfg.clone(),
                        );
                        protocols.push(std::sync::Arc::new(ether_nd));
                        tracing::info!(target: "discovery", iface=%iface_name, node=%node_name, "Ethernet neighbor discovery enabled (auto)");
                    }
                    Err(e) => {
                        tracing::warn!(target: "discovery", iface=%iface_name, error=%e, "failed to get interface MAC, skipping auto Ethernet ND");
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        if use_ether {
            tracing::warn!(
                target: "discovery",
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
            ndn_discovery::sd_root().clone(),
            svc_cfg,
        ));
        for prefix_str in &fwd_config.discovery.served_prefixes {
            match prefix_str.parse::<ndn_packet::Name>() {
                Ok(prefix) => {
                    sd.publish(ndn_discovery::ServiceRecord::new(prefix, node_name.clone()));
                    tracing::info!(target: "discovery", prefix=%prefix_str, "discovery: registered served prefix");
                }
                Err(e) => {
                    tracing::warn!(target: "discovery", prefix=%prefix_str, error=%e, "discovery: invalid served_prefix, skipping");
                }
            }
        }
        protocols.push(
            std::sync::Arc::clone(&sd) as std::sync::Arc<dyn ndn_discovery::DiscoveryProtocol>
        );

        let composite = ndn_discovery::CompositeDiscovery::new(protocols)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        // Collect claimed prefixes before the composite moves into the
        // builder; mgmt enforcement needs the list.
        let claimed: Vec<ndn_packet::Name> = composite.all_claimed_prefixes();
        builder.register_discovery(std::sync::Arc::new(composite));
        discovery_sd = Some(sd);
        discovery_claimed = claimed;
        tracing::info!(target: "discovery", node=%node_name, transport=%disc_transport, "discovery enabled");
    } else {
        pre_allocated_multicast = Vec::new();
        pre_allocated_ether_mc = Vec::new();
        discovery_sd = None;
        discovery_claimed = Vec::new();
        auto_ether_pre_alloc = Vec::new();
        auto_udp_pre_alloc = Vec::new();
    }
    let mgmt_discovery_sd = discovery_sd;
    let mgmt_discovery_claimed = discovery_claimed;
    #[cfg(not(target_os = "linux"))]
    let _ = &pre_allocated_ether_mc;
    #[cfg(not(target_os = "linux"))]
    let _ = &auto_ether_pre_alloc;
    #[cfg(not(target_os = "linux"))]
    let _ = &auto_ether_ifaces;

    // Map each `[[face]]` config entry (by zero-based index) to a stable
    // FaceId: reuse the ids discovery already pre-allocated for multicast /
    // Ethernet-multicast faces, and allocate fresh ones for every other entry.
    // Both `[[route]] face = N` resolution and the face-setup loop use this, so
    // a route's `face` index always points at the face that entry creates.
    let face_ids_by_index: Vec<ndn_transport::FaceId> = fwd_config
        .faces
        .iter()
        .enumerate()
        .map(|(idx, _)| {
            pre_allocated_multicast
                .iter()
                .chain(pre_allocated_ether_mc.iter())
                .find(|(_, i)| *i == idx)
                .map(|(id, _)| *id)
                .unwrap_or_else(|| builder.alloc_face_id())
        })
        .collect();

    // NLSR and DV wire in via `InstallableProtocol`: async pre-build (UDP
    // binds) in `prepare`; InProcFace pairs, FIB writes, neighbour seeds,
    // and Producer mounts run via `install` + `PostBuildQueue`.
    let mut post_build = ndn_engine::PostBuildQueue::new();
    if let Some(installer) = installs::nlsr::prepare(&fwd_config, &mut builder).await {
        builder = builder.install(std::sync::Arc::new(installer), &mut post_build);
    }
    if let Some(installer) =
        installs::dv::prepare(&fwd_config, &mut builder, identity_signer.clone()).await
    {
        builder = builder.install(std::sync::Arc::new(installer), &mut post_build);
    }

    let (engine, shutdown) = builder.build().await?;

    // CCLF: advertise this node's network-layer presence so neighbors count it
    // for density (A-LAL). The strategy is selected per-prefix via
    // strategy-choice; this only opts the node into being *seen*.
    #[cfg(feature = "cclf")]
    if let Some(ref presence) = fwd_config.cclf.presence_name {
        match presence.parse::<ndn_packet::Name>() {
            Ok(name) => {
                ndn_strategy_cclf::native::CclfStrategy::advertise_presence(&name);
                tracing::info!(%presence, "CCLF: advertising A-LAL presence");
            }
            Err(e) => {
                tracing::warn!(%presence, error = %e, "CCLF: invalid presence_name; not advertising")
            }
        }
    }

    // Single cancel token shared by every spawned task (Producer mounts,
    // listeners, mgmt). Created before `post_build.apply` so installer-
    // deferred Producer tasks bind to the same shutdown signal.
    let cancel = CancellationToken::new();

    post_build.apply(&engine, &cancel);

    for route in &fwd_config.routes {
        // `route.face` is a zero-based index into `[[face]]` (see RouteConfig);
        // resolve it to the FaceId that entry was assigned.
        let Some(&face_id) = face_ids_by_index.get(route.face) else {
            tracing::error!(
                target: "engine",
                prefix = %route.prefix,
                face_index = route.face,
                faces = face_ids_by_index.len(),
                "route references a [[face]] index out of range; skipping",
            );
            continue;
        };
        let name = parse_name(&route.prefix);
        engine.fib().add_nexthop(&name, face_id, route.cost);
        tracing::info!(target: "engine", prefix = %route.prefix, face_index = route.face, face = face_id.0, cost = route.cost, "route added");
    }

    // `/localhost/nfd` + `/localhop/nfd` FIB entries are installed by
    // `ndn_mgmt::mount_management` below.

    if let Some(spawn) = demo_ca_spawn {
        engine.fib().add_nexthop(&spawn.prefix, spawn.face_id, 0);
        tracing::info!(
            target: "demo_ca",
            prefix = %spawn.prefix,
            face = spawn.face_id.0,
            "demo CA FIB entry installed"
        );
        if let Some(ns) = &spawn.cert_namespace {
            // Cost +1 so a more-specific browser-registered prefix wins LPM.
            engine.fib().add_nexthop(ns, spawn.face_id, 1);
            tracing::info!(
                target: "demo_ca",
                namespace = %ns,
                face = spawn.face_id.0,
                "demo CA cert-fetch namespace FIB entry installed"
            );
        }
        demo_ca::spawn(spawn, &fwd_config.demo_ca, &engine)?;
    }

    // Face listeners, WT/WebRTC listeners, auto-multicast face creation,
    // and the interface hotplug watcher all live in `face_setup`.
    run_face_setup(
        &engine,
        &cancel,
        &fwd_config,
        FaceSetupState {
            face_ids_by_index,
            auto_udp_pre_alloc,
            auto_ether_pre_alloc,
            auto_udp_ifaces,
            auto_ether_ifaces,
        },
    )
    .await;

    let face_socket = fwd_config.management.face_socket.clone();
    tracing::info!(target: "engine", socket = %face_socket, prefix = "/localhost/nfd", "NDN management active");

    // BLE peripheral listener owner + `ble` mgmt backend. Starts advertising
    // now when `[listeners.ble].enabled`; otherwise dormant until
    // `/localhost/nfd/ble/start`.
    #[cfg(all(feature = "bluetooth", any(target_os = "linux", target_os = "macos")))]
    let ble_handler: Option<Arc<dyn mgmt_ndn::BleMgmtBackend>> = {
        use mgmt_ndn::BleMgmtBackend as _;
        let ble_cfg = fwd_config.listeners.ble.clone().unwrap_or_default();
        let ctrl = Arc::new(transport_listeners::BleControl::new(
            engine.clone(),
            cancel.clone(),
            ble_cfg.adapter.clone(),
            ble_cfg.local_name.clone(),
        ));
        if ble_cfg.enabled {
            let _ = ctrl.start().await;
        }
        Some(ctrl as Arc<dyn mgmt_ndn::BleMgmtBackend>)
    };
    #[cfg(not(all(feature = "bluetooth", any(target_os = "linux", target_os = "macos"))))]
    let ble_handler: Option<Arc<dyn mgmt_ndn::BleMgmtBackend>> = None;

    let ndn_handler_task = tokio::spawn(mgmt_ndn::mount_management(
        &engine,
        cancel.clone(),
        mgmt_discovery_sd.clone(),
        mgmt_discovery_claimed.clone(),
        Arc::new(fwd_config.clone()),
        pib.clone(),
        mgmt_ndn::MgmtHandles {
            discovery_cfg: mgmt_discovery_cfg,
            security_is_ephemeral,
            // None when [security.mgmt].trust_anchor_pib is unset. With
            // require_signed_commands=true and no validator, every command
            // is rejected (fail-secure).
            command_validator: mgmt_validator,
            // None rejects /localhop/nfd/... with STATUS 403 (equivalent
            // to NFD's `m_isLocalhopEnabled = false`).
            localhop_command_validator: localhop_validator,
            require_signed_commands: fwd_config.security.mgmt.require_signed_commands,
            command_replay_cache: None,
            // Sign mgmt responses with the daemon identity when one exists,
            // else fall back to DigestSha256 (ephemeral boots still answer).
            command_response_signer: engine.security().and_then(|m| m.any_signer()),
            log_inspector: build_log_inspector(),
            #[cfg(feature = "fec")]
            coding_handler: coding_handler_arc
                .clone()
                .map(|h| h as Arc<dyn mgmt_ndn::CodingHandler>),
            #[cfg(not(feature = "fec"))]
            coding_handler: None,
            #[cfg(feature = "rate-limit")]
            rate_limit_handler: rate_limit_handler_arc
                .clone()
                .map(|h| h as Arc<dyn mgmt_ndn::RateLimitMgmtBackend>),
            #[cfg(not(feature = "rate-limit"))]
            rate_limit_handler: None,
            // The forwarder binary hosts no ComputeService; a process
            // that attaches one wires its `ComputeService::mgmt_backend()`.
            compute_handler: None,
            // Read-only WebTransport cert-status, fed by the WT listeners.
            #[cfg(feature = "webtransport")]
            webtransport_status_handler: Some(std::sync::Arc::new(
                crate::transport_listeners::WtCertStatusReader,
            )),
            #[cfg(not(feature = "webtransport"))]
            webtransport_status_handler: None,
            ble_handler,
            // Wired to the CA's PendingApprovalStore when a device-approval CA
            // runs; the demo CA (Nop/Token) registers none.
            approval_handler: None,
            // Runtime-mutable mgmt-access policy. `policy-set` hot-flips
            // booleans; validator-anchor changes are `pending_restart`
            // until a Validator rebuild path exists.
            runtime_policy: Some(std::sync::Arc::new(std::sync::RwLock::new(
                mgmt_ndn::MgmtAccessPolicy::from_config(&fwd_config),
            ))),
        },
    ));
    // Install the pre-built span publisher on the engine: registers the
    // prefix in the FIB and spawns the serve loop that turns Interests
    // into cached Data wires.
    if let Some(publisher) = obs_publisher.as_ref() {
        let obs_cfg = &fwd_config.observability;
        ndn_observability::mount_observability(&engine, cancel.clone(), Arc::clone(publisher));

        // PIT-aggregation fan-out: each satisfy/Nack event becomes a
        // Span in the consumer's trace, parented to nothing (the
        // consumer-side chain stitches it).
        let fan_out_publisher = Arc::clone(publisher);
        ndn_engine::observability::fan_out::install_sink(Arc::new(move |ev| {
            use ndn_engine::observability::fan_out::FanOutKind;
            use ndn_observability::{Attr, Span, SpanKind, StatusCode};

            let now_nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            let (name, kind, status, mut attrs) = match ev.kind {
                FanOutKind::DataSatisfy => (
                    "pit.satisfy".to_string(),
                    SpanKind::Internal,
                    StatusCode::Ok,
                    vec![],
                ),
                FanOutKind::Nack { reason_code } => (
                    "pit.nack".to_string(),
                    SpanKind::Internal,
                    StatusCode::Error,
                    vec![Attr::int("nack.reason", reason_code as i64)],
                ),
            };
            attrs.push(Attr::str("interest.name", ev.name_uri.clone()));
            attrs.push(Attr::int("face.id", ev.face_id as i64));
            let span_id_seed = {
                use std::sync::atomic::{AtomicU64, Ordering};
                static SEED: AtomicU64 = AtomicU64::new(1);
                SEED.fetch_add(1, Ordering::Relaxed)
            };
            let span = Span {
                trace_id: ev.trace_id.0,
                span_id: span_id_seed.to_be_bytes(),
                parent_span_id: None,
                name,
                kind,
                start_unix_nano: now_nanos,
                end_unix_nano: now_nanos,
                attributes: attrs,
                status_code: status,
                status_message: String::new(),
            };
            fan_out_publisher.publish(&span);
        }));

        // LP `TraceContext` propagation: the egress source asks the
        // observability layer for an outbound context per frame; the
        // ingress sink stamps inbound contexts onto the per-task override
        // so downstream pipeline spans stitch to the remote parent.
        if obs_cfg.propagate_to_peers
            && let Some(layer) = obs_layer.as_ref()
        {
            let egress_layer = layer.clone();
            ndn_transport::link_service::features::install_global_egress_source(Arc::new(
                move || Some(egress_layer.current_outbound_context()),
            ));
            let ingress_layer = layer.clone();
            ndn_transport::link_service::features::install_global_ingress_sink(Arc::new(
                move |tc| {
                    ingress_layer.set_inbound_trace_id(tc.trace_id.0);
                },
            ));
            tracing::info!(
                target: "engine",
                "[observability] LP TraceContext propagation enabled (propagate_to_peers=true)"
            );
        }

        tracing::info!(
            target: "engine",
            prefix = %publisher.prefix(),
            sample = obs_cfg.sample,
            propagate_to_peers = obs_cfg.propagate_to_peers,
            "[observability] NDN-native span publisher active"
        );
    }

    let listener_engine = engine.clone();
    let listener_cancel = cancel.clone();
    let ndn_listener_task = tokio::spawn(async move {
        mgmt_ndn::run_face_listener(&face_socket, listener_engine, listener_cancel).await;
    });

    tokio::signal::ctrl_c().await?;

    tracing::info!(target: "engine", "shutting down");
    cancel.cancel();

    let _ = ndn_handler_task.await;
    let _ = ndn_listener_task.await;

    shutdown.shutdown().await;
    Ok(())
}
