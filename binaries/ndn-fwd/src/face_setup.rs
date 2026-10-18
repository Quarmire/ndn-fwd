//! Face listener, auto-multicast, and hotplug-watcher bootstrap.

// Setup helpers and imports are cfg-gated per face-transport feature; the live
// set varies by feature flags (file-scoped suppression is intentional). The
// bootstrap fns legitimately thread many collaborators, hence too_many_arguments.
#![allow(unused_imports, dead_code, clippy::too_many_arguments)]

use std::sync::Arc;

use ndn_config::ForwarderConfig;
use ndn_engine::ForwarderEngine;
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

use ndn_mgmt as mgmt_ndn;

#[cfg(feature = "webrtc")]
use crate::transport_listeners::run_webrtc_listener;
use crate::transport_listeners::run_ws_listener;
#[cfg(feature = "webtransport")]
use crate::transport_listeners::run_wt_listener;

pub struct FaceSetupState {
    /// FaceId assigned to each `[[face]]` config entry, indexed by its
    /// zero-based position (mirrors `[[route]] face`). Built in `main` so the
    /// route table and this loop agree on which FaceId each entry gets.
    pub face_ids_by_index: Vec<FaceId>,
    pub auto_udp_pre_alloc: Vec<(FaceId, String, std::net::Ipv4Addr)>,
    pub auto_ether_pre_alloc: Vec<(FaceId, String)>,
    pub auto_udp_ifaces: Vec<(String, std::net::Ipv4Addr)>,
    pub auto_ether_ifaces: Vec<ndn_face::iface::InterfaceInfo>,
}

/// Spawn every face listener, WebTransport / WebRTC listener, auto-
/// enumerated multicast face creator, and the interface hotplug watcher.
/// Returns once spawns are issued; tasks run until `cancel` fires.
///
/// Fails when a UDP listener's port is held by another process (see
/// [`udp_listener_in_use`]).
pub async fn run_face_setup(
    engine: &ForwarderEngine,
    cancel: &CancellationToken,
    fwd_config: &ForwarderConfig,
    state: FaceSetupState,
    monitors: Arc<crate::monitors::MonitorRegistry>,
) -> anyhow::Result<Vec<Arc<dyn ndn_mgmt_wire::ControlSurface>>> {
    let FaceSetupState {
        face_ids_by_index,
        auto_udp_pre_alloc,
        auto_ether_pre_alloc,
        auto_udp_ifaces,
        auto_ether_ifaces,
    } = state;
    let cancel = cancel.clone();
    #[cfg(not(target_os = "linux"))]
    let _ = &auto_ether_pre_alloc;
    #[cfg(not(target_os = "linux"))]
    let _ = &auto_ether_ifaces;

    run_face_setup_inner(
        engine,
        &cancel,
        fwd_config,
        face_ids_by_index,
        auto_udp_pre_alloc,
        auto_ether_pre_alloc,
        auto_udp_ifaces,
        auto_ether_ifaces,
        monitors,
    )
    .await
}

#[allow(clippy::needless_pass_by_value, unused_variables)]
async fn run_face_setup_inner(
    engine: &ForwarderEngine,
    cancel: &CancellationToken,
    fwd_config: &ForwarderConfig,
    face_ids_by_index: Vec<FaceId>,
    auto_udp_pre_alloc: Vec<(FaceId, String, std::net::Ipv4Addr)>,
    auto_ether_pre_alloc: Vec<(FaceId, String)>,
    auto_udp_ifaces: Vec<(String, std::net::Ipv4Addr)>,
    auto_ether_ifaces: Vec<ndn_face::iface::InterfaceInfo>,
    monitors: Arc<crate::monitors::MonitorRegistry>,
) -> anyhow::Result<Vec<Arc<dyn ndn_mgmt_wire::ControlSurface>>> {
    // Cognition/telemetry surfaces produced while mounting faces (currently the
    // radio medium face); handed to `MgmtHandles.control_surfaces` by the caller.
    // Only the `radio` arm pushes into this, so it is not mutated without it.
    #[cfg_attr(not(feature = "radio"), allow(unused_mut))]
    let mut control_surfaces: Vec<Arc<dyn ndn_mgmt_wire::ControlSurface>> = Vec::new();
    // Resolve a config-face index to its pre-assigned FaceId; fall back to a
    // fresh id for the synthetic default listeners (empty `[[face]]`).
    let id_for = |idx: usize| {
        face_ids_by_index
            .get(idx)
            .copied()
            .unwrap_or_else(|| engine.faces().alloc_id())
    };
    use crate::parse_bind_addr;
    let engine = engine.clone();
    // With no `[[face]]` entries, start default UDP + TCP listeners on
    // 0.0.0.0:6363 (matches NFD).
    let face_configs: std::borrow::Cow<'_, [ndn_config::FaceConfig]> = if fwd_config
        .faces
        .is_empty()
    {
        tracing::info!(target: "face.system", "no [[face]] in config, using defaults: udp+tcp on 0.0.0.0:6363");
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

    // Bind every UDP listener before any peer face is created: a peer face
    // joins its listener's port (`ConnectedPort::Listener`), so the listener
    // must claim the port first. A port another process holds is fatal.
    let mut bound_udp_listeners = std::collections::BTreeMap::new();
    for (face_idx, face_cfg) in face_configs.iter().enumerate() {
        if let ndn_config::FaceConfig::Udp { bind, remote: None } = face_cfg
            && let Some(addr) =
                parse_bind_addr(bind.as_deref().unwrap_or("0.0.0.0:6363"), "UDP")
        {
            match mgmt_ndn::bind_udp_listener(addr, fwd_config.face_system.udp.rx_sockets) {
                Ok(listener) => {
                    bound_udp_listeners.insert(face_idx, listener);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                    return Err(udp_listener_in_use(addr));
                }
                Err(e) => {
                    tracing::error!(target: "face.udp", addr=%addr, error=%e, "udp-listener: bind failed");
                }
            }
        }
    }
    // What the listeners actually hold (a port-0 listener resolved, a failed
    // bind absent): a peer face shares only a port one of them holds.
    let udp_listeners: Vec<std::net::SocketAddr> = bound_udp_listeners
        .values()
        .map(mgmt_ndn::UdpListener::local_addr)
        .collect();

    for (face_idx, face_cfg) in face_configs.iter().enumerate() {
        match face_cfg {
            ndn_config::FaceConfig::Udp { bind, remote } => {
                if let Some(remote_addr) = remote {
                    let peer: std::net::SocketAddr = match remote_addr.parse() {
                        Ok(a) => a,
                        Err(e) => {
                            tracing::error!(target: "face.udp", addr = %remote_addr, error = %e, "invalid UDP remote address");
                            continue;
                        }
                    };
                    let face_id = id_for(face_idx);
                    let bind_addr = match bind.as_deref() {
                        // An unparsable bind is refused (and logged), not
                        // replaced by an address nobody configured.
                        Some(b) => match parse_bind_addr(b, "UDP") {
                            Some(addr) => Some(addr),
                            None => continue,
                        },
                        None => None,
                    };
                    let local_port = peer_face_port(bind_addr, &udp_listeners);
                    let eng = engine.clone();
                    tokio::spawn(async move {
                        match ndn_face::net::UdpFace::bind_connected(local_port, peer, face_id)
                            .await
                        {
                            Ok(face) => {
                                let c = CancellationToken::new();
                                tracing::info!(target: "face.udp", face = face_id.0, remote = %peer, local = ?ndn_transport::Transport::local_uri(&face), port = ?local_port, "udp pre-connected face created");
                                // PERMANENT, not Persistent. This is a
                                // statically CONFIGURED peer endpoint, so it
                                // must outlive I/O errors: a Persistent face is
                                // destroyed on the first recv/send error, and
                                // nothing recreates it, while the RIB routes
                                // that named its face id survive and now point
                                // at a face that no longer exists. The node is
                                // then silently ONE-WAY -- it still answers
                                // Interests arriving on a fresh on-demand face
                                // but can never send any of its own.
                                //
                                // Observed on the fleet: a GCS forwarder
                                // restart destroyed this face on BOTH ends of
                                // the same link. iuas-01 kept `out:
                                // interests=0` toward the GCS for hours while
                                // its routes still said face 3, so its SVS sync
                                // never reached the GCS and every NDNSF service
                                // call to it timed out, with telemetry degraded
                                // but not dead. Every other configured face in
                                // this file is already Permanent; this one was
                                // the outlier.
                                eng.add_face_with_persistency(
                                    face,
                                    c,
                                    ndn_transport::FacePersistency::Permanent,
                                );
                            }
                            Err(e) => {
                                tracing::error!(target: "face.udp", remote = %peer, bind = %local_port.addr(), error = %e, "failed to create UDP face");
                            }
                        }
                    });
                } else if let Some(listener) = bound_udp_listeners.remove(&face_idx) {
                    let eng = engine.clone();
                    let c = cancel.clone();
                    tokio::spawn(async move {
                        mgmt_ndn::run_udp_listener(listener, eng, c).await;
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
                        tracing::error!(target: "face.udp", group=%group, error=%e, "invalid multicast group address");
                        continue;
                    }
                };
                let id = id_for(face_idx);
                let port = *port;
                let eng = engine.clone();
                let c = cancel.child_token();
                tokio::spawn(async move {
                    match ndn_face::net::MulticastUdpFace::new(iface, port, group_addr, id).await {
                        Ok(face) => {
                            eng.add_face_with_persistency(
                                face,
                                c,
                                ndn_transport::FacePersistency::Permanent,
                            );
                            tracing::info!(target: "face.udp", group=%group_addr, port=%port, iface=%iface, face=%id, "multicast UDP face created");
                        }
                        Err(e) => {
                            tracing::error!(target: "face.udp", group=%group_addr, port=%port, error=%e, "failed to create multicast UDP face");
                        }
                    }
                });
            }
            ndn_config::FaceConfig::Unix { .. } => {
                tracing::warn!(target: "face.system", "unix face config ignored (use [management] face_socket)");
            }
            ndn_config::FaceConfig::WebSocket { bind, .. } => {
                let Some(bind_str) = bind.as_deref() else {
                    tracing::error!(target: "face.ws", "websocket face requires 'bind' address");
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
            ndn_config::FaceConfig::WebTransport {
                remote,
                cert_sha256,
                webpki,
            } => {
                #[cfg(feature = "webtransport")]
                {
                    // FaceUri scheme is wts://; the dialed URL is https://.
                    let url = remote
                        .strip_prefix("wts://")
                        .map(|rest| format!("https://{rest}"))
                        .unwrap_or_else(|| remote.clone());
                    let tls = if *webpki {
                        Some(ndn_transport::ClientTls::WebPki)
                    } else {
                        cert_sha256
                            .as_deref()
                            .and_then(ndn_config::parse_cert_sha256_hex)
                            .map(|h| ndn_transport::ClientTls::CertHashes(vec![h]))
                    };
                    let Some(tls) = tls else {
                        tracing::error!(target: "face.wt", remote=%remote, "web-transport dial face: invalid/missing cert_sha256 (or webpki)");
                        continue;
                    };
                    let id = id_for(face_idx);
                    let eng = engine.clone();
                    let c = cancel.child_token();
                    tokio::spawn(async move {
                        match ndn_face_webtransport::WebTransportFace::connect(id, &url, tls).await
                        {
                            Ok(face) => {
                                eng.add_face(face, c);
                                tracing::info!(target: "face.wt", face=%id, remote=%url, "WebTransport dial face connected");
                            }
                            Err(e) => {
                                tracing::error!(target: "face.wt", remote=%url, error=%e, "WebTransport dial failed");
                            }
                        }
                    });
                }
                #[cfg(not(feature = "webtransport"))]
                {
                    let _ = (remote, cert_sha256, webpki);
                    tracing::warn!(target: "face.wt", "web-transport dial face ignored (webtransport feature not compiled in)");
                }
            }
            // This device's QUIC link socket: started with `[[peer]]` by `links`.
            ndn_config::FaceConfig::Quic { bind, .. } => {
                #[cfg(not(feature = "quic"))]
                tracing::warn!(target: "face.quic", bind = %bind, "[[face]] kind = \"quic\" ignored: this ndn-fwd was built without the quic feature");
                #[cfg(feature = "quic")]
                let _ = bind;
            }
            ndn_config::FaceConfig::Serial { path, baud } => {
                #[cfg(feature = "serial")]
                {
                    let id = id_for(face_idx);
                    match ndn_face_serial::serial_face_open(id, path, *baud) {
                        Ok(face) => {
                            let c = cancel.child_token();
                            engine.add_face(face, c);
                            tracing::info!(target: "face.system", port=%path, baud=%baud, face=%id, "serial face opened");
                        }
                        Err(e) => {
                            tracing::error!(target: "face.system", port=%path, error=%e, "failed to open serial face");
                        }
                    }
                }
                #[cfg(not(feature = "serial"))]
                {
                    let _ = (path, baud);
                    tracing::warn!(target: "face.system", "serial face support not compiled in");
                }
            }
            ndn_config::FaceConfig::EtherMulticast { interface } => {
                #[cfg(target_os = "linux")]
                {
                    let id = id_for(face_idx);
                    match ndn_face::l2::MulticastEtherFace::new(id, interface) {
                        Ok(face) => {
                            let c = cancel.child_token();
                            engine.add_face_with_persistency(
                                face,
                                c,
                                ndn_transport::FacePersistency::Permanent,
                            );
                            tracing::info!(target: "face.eth", iface=%interface, face=%id, "multicast ethernet face opened");
                        }
                        Err(e) => {
                            tracing::error!(target: "face.eth", iface=%interface, error=%e, "failed to open multicast ethernet face");
                        }
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = interface;
                    tracing::warn!(target: "face.eth", "ether-multicast face only supported on Linux");
                }
            }
            ndn_config::FaceConfig::Ether {
                interface,
                peer_mac,
                io,
                bpf_object,
            } => {
                #[cfg(all(
                    feature = "l2",
                    any(target_os = "linux", target_os = "macos", target_os = "windows")
                ))]
                {
                    let mac: ndn_transport::MacAddr = match peer_mac.parse() {
                        Ok(m) => m,
                        Err(_) => {
                            tracing::error!(target: "face.eth", peer_mac=%peer_mac, "invalid ether peer-mac");
                            continue;
                        }
                    };
                    let id = id_for(face_idx);
                    let want_afxdp = io.as_deref() == Some("afxdp");
                    // `bpf_object` is only consumed by the af-xdp branch below.
                    #[cfg(not(all(target_os = "linux", feature = "af-xdp")))]
                    let _ = &bpf_object;

                    // AF_XDP kernel-bypass backend (Linux + `af-xdp` feature).
                    #[cfg(all(target_os = "linux", feature = "af-xdp"))]
                    if want_afxdp {
                        // A `bpf-object` path overrides the embedded default
                        // redirect program (`bpf/redirect.bpf.o`).
                        let opened = match bpf_object.clone() {
                            Some(obj) => {
                                ndn_face_afxdp::AfXdpFace::new(id, interface, 0, mac, obj.into())
                            }
                            None => ndn_face_afxdp::AfXdpFace::new_with_embedded_redirect(
                                id, interface, 0, mac,
                            ),
                        };
                        match opened {
                            Ok(face) => {
                                engine.add_face_with_persistency(
                                    face,
                                    cancel.child_token(),
                                    ndn_transport::FacePersistency::Permanent,
                                );
                                tracing::info!(target: "face.eth", iface=%interface, peer=%peer_mac, face=%id, "af_xdp ethernet face opened");
                            }
                            Err(e) => {
                                tracing::error!(target: "face.eth", iface=%interface, error=%e, "failed to open af_xdp ethernet face");
                            }
                        }
                        continue;
                    }
                    #[cfg(not(all(target_os = "linux", feature = "af-xdp")))]
                    if want_afxdp {
                        tracing::warn!(target: "face.eth", iface=%interface, "ether io=afxdp needs ndn-fwd built --features af-xdp on Linux; using af_packet");
                    }

                    match ndn_face::l2::NamedEtherFace::new(
                        id,
                        ndn_packet::Name::root(),
                        mac,
                        interface.clone(),
                        ndn_face::l2::RadioFaceMetadata::default(),
                    ) {
                        Ok(face) => {
                            let c = cancel.child_token();
                            engine.add_face_with_persistency(
                                face,
                                c,
                                ndn_transport::FacePersistency::Permanent,
                            );
                            tracing::info!(target: "face.eth", iface=%interface, peer=%peer_mac, face=%id, "unicast ethernet face opened");
                        }
                        Err(e) => {
                            tracing::error!(target: "face.eth", iface=%interface, peer=%peer_mac, error=%e, "failed to open unicast ethernet face");
                        }
                    }
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
                {
                    let _ = (interface, peer_mac, io, bpf_object);
                    tracing::warn!(target: "face.eth", "ether unicast face not supported on this platform");
                }
            }
            ndn_config::FaceConfig::Radio { radios } => {
                // The wireless medium as one face: N radio capabilities, RX union +
                // TX fan-out, driven by the cognitive control plane.
                #[cfg(feature = "radio")]
                {
                    let id = id_for(face_idx);
                    // Builds the bearers, mounts the medium face (engine pairs the
                    // LpLinkService by kind: Wfb → LP framing on), spawns the
                    // cognition control loop, and returns a read-only telemetry
                    // surface for the mgmt `ext/list` dataset plus one
                    // link-quality probe per radio for the `[monitors]` registry.
                    match crate::radio_face::mount_radio_face(&engine, cancel, id, radios) {
                        Ok((surface, link_probes)) => {
                            control_surfaces.push(surface);
                            for (radio_id, probe) in link_probes {
                                crate::monitors::spawn_polling(
                                    monitors.clone(),
                                    &format!("link-{radio_id}"),
                                    "link",
                                    std::time::Duration::from_secs(5),
                                    cancel.clone(),
                                    probe,
                                );
                            }
                        }
                        Err(e) => {
                            // A configured radio face that cannot come up is a DEPLOYMENT FAILURE,
                            // not something to log and run past: `mount_radio_face` only errors when
                            // NONE of the configured radios came up, so the cell's entire purpose is
                            // dead. Continuing would leave a forwarder with the `/muas` route but no
                            // radio — which the fabric's process+routes health check reads as `ok`,
                            // defeating its auto-rollback (field 2026-09-10). Exit non-zero so the
                            // backend unit fails and the fabric reverts to the last good cell.
                            tracing::error!(
                                target: "face.radio", error = %e,
                                "configured radio face could not be brought up — exiting so the                                  fabric health gate trips and rolls back (not running radio-less)",
                            );
                            std::process::exit(1);
                        }
                    }
                }
                #[cfg(not(feature = "radio"))]
                {
                    let _ = radios;
                    tracing::warn!(target: "face.radio", "radio face support not compiled in (build with --features radio)");
                }
            }
        }
    }

    #[cfg(feature = "webtransport")]
    if let Some(wt_cfg) = fwd_config.listeners.webtransport.clone()
        && wt_cfg.enabled
    {
        let eng = engine.clone();
        let c = cancel.clone();
        tokio::spawn(async move { run_wt_listener(wt_cfg, eng, c).await });
    }

    // Polls the signaling relay, accepts SDP offers as `WebRtcFace`s, and
    // registers them. Operators allocate session ids via
    // `[listeners.webrtc].session_ids`; new ids are picked up on listener
    // restart.
    #[cfg(feature = "webrtc")]
    if let Some(rtc_cfg) = fwd_config.listeners.webrtc.clone()
        && rtc_cfg.enabled
        && !rtc_cfg.session_ids.is_empty()
    {
        let eng = engine.clone();
        let c = cancel.clone();
        tokio::spawn(async move { run_webrtc_listener(rtc_cfg, eng, c).await });
    }

    // The BLE peripheral listener is owned by `BleControl` (the `ble` mgmt
    // backend) so config-auto-start and `/localhost/nfd/ble/{start,stop}` share
    // one lifecycle; it is started from `main.rs` after the engine is built.

    // With discovery on, `auto_*_pre_alloc` carry the pre-allocated
    // FaceIds; otherwise fresh ids are allocated here. Sockets are bound
    // either way.
    #[cfg(target_os = "linux")]
    for (pre_id, iface_name) in &auto_ether_pre_alloc {
        let id = *pre_id;
        match ndn_face::l2::MulticastEtherFace::new(id, iface_name) {
            Ok(face) => {
                let c = cancel.child_token();
                engine.add_face_with_persistency(
                    face,
                    c,
                    ndn_transport::FacePersistency::Permanent,
                );
                tracing::info!(target: "face.eth", iface=%iface_name, face=%id, "auto multicast ethernet face opened");
            }
            Err(e) => {
                tracing::error!(target: "face.eth", iface=%iface_name, error=%e, "auto multicast ethernet face failed");
            }
        }
    }
    let udp_ad_hoc = fwd_config.face_system.udp.ad_hoc;
    for (pre_id, iface_name, addr) in &auto_udp_pre_alloc {
        let id = *pre_id;
        let addr = *addr;
        let iface_name = iface_name.clone();
        let eng = engine.clone();
        let c = cancel.child_token();
        tokio::spawn(async move {
            match ndn_face::net::MulticastUdpFace::ndn_default(addr, id).await {
                Ok(face) => {
                    let face = if udp_ad_hoc { face.ad_hoc() } else { face };
                    eng.add_face_with_persistency(
                        face,
                        c,
                        ndn_transport::FacePersistency::Permanent,
                    );
                    tracing::info!(target: "face.udp", iface=%iface_name, addr=%addr, face=%id, "auto multicast UDP face opened");
                }
                Err(e) => {
                    tracing::error!(target: "face.udp", iface=%iface_name, addr=%addr, error=%e, "auto multicast UDP face failed");
                }
            }
        });
    }
    // Auto-multicast enumeration + interface hotplug now live in the reusable
    // `ndn_face::provision` module (shared with the mobile/in-browser
    // engines via the `FaceSink` seam). When neighbour discovery pre-allocated
    // the startup faces above, skip the provisioner's initial enumeration to
    // avoid double-creating them — but still run the hotplug watcher so later
    // interfaces are picked up.
    let provision_cfg = ndn_face::provision::MulticastProvisionConfig {
        udp_auto: fwd_config.face_system.udp.auto_multicast,
        udp_ad_hoc,
        udp_whitelist: fwd_config.face_system.udp.whitelist.clone(),
        udp_blacklist: fwd_config.face_system.udp.blacklist.clone(),
        ether_auto: fwd_config.face_system.ether.auto_multicast,
        ether_whitelist: fwd_config.face_system.ether.whitelist.clone(),
        ether_blacklist: fwd_config.face_system.ether.blacklist.clone(),
        watch_interfaces: fwd_config.face_system.watch_interfaces,
    };
    let pre_allocated = !auto_udp_pre_alloc.is_empty() || !auto_ether_pre_alloc.is_empty();
    if pre_allocated {
        if provision_cfg.watch_interfaces {
            ndn_face::provision::spawn_hotplug_watcher(
                engine.clone(),
                provision_cfg,
                cancel.child_token(),
            );
        }
    } else {
        ndn_face::provision::provision(&engine, &provision_cfg, cancel);
    }

    tracing::info!(target: "engine", "engine running");
    Ok(control_surfaces)
}

/// The error for a UDP listener whose port another process holds.
///
/// The listener refuses to share it: `SO_REUSEPORT` admits any socket of the
/// same user, so two forwarders on one port would land in one reuse group and
/// the kernel would split inbound datagrams between them, each seeing only
/// part of its neighbours' traffic, with no error anywhere. The claim itself
/// is in `ndn_face::net::sockopt::bind_listener_udp`.
fn udp_listener_in_use(addr: std::net::SocketAddr) -> anyhow::Error {
    anyhow::anyhow!(
        "UDP port {port} is already in use by another process (another ndn-fwd on this \
         host?), so the UDP listener on {addr} cannot start: two forwarders on one port \
         would silently split its traffic. Give this forwarder another port in its UDP \
         listener ([[face]] kind = \"udp\", bind = \"{ip}:<port>\"; no [[face]] means \
         0.0.0.0:6363), or stop the process holding port {port}.",
        port = addr.port(),
        ip = addr.ip(),
    )
}

/// The local address and port policy of a configured UDP peer face
/// (`[[face]] kind = "udp"` with `remote`, optional `bind`), given the
/// addresses this forwarder's UDP listeners are bound to. A specific `bind`
/// IP is the one bound; an unspecified one, or no `bind`, binds the address
/// that routes to the peer.
///
/// With a listener, the face binds the listener's port beside it and
/// connects to the peer. An ephemeral port (the previous `0.0.0.0:0`) made our
/// datagrams arrive at the neighbour from a source it had no face for, so it
/// minted a second, on-demand face for us; split across two faces, a
/// neighbour survives `nexthops_excluding(in_face)` and Interests are
/// forwarded back to their origin (12 wire copies per Interest against NFD's
/// 9, ~35% more packets on a shared medium). The listener's port keeps the
/// source symmetric; connecting makes the kernel deliver this peer's datagrams
/// to the face rather than to the wildcard listener.
///
/// Without a listener there is no port to be symmetric with, and the face
/// takes an ephemeral port of its own. Binding the well-known 6363 shared
/// (`SO_REUSEPORT`) let every such forwarder on one host bind the same address
/// and connect to the same hub: one 4-tuple for all of them, one face on the
/// hub, and every reply delivered to one of them while the others' Interests
/// went unanswered. A `bind` port no listener of ours holds is bound
/// exclusively, so a clash with another process fails loudly instead.
fn peer_face_port(
    bind: Option<std::net::SocketAddr>,
    listeners: &[std::net::SocketAddr],
) -> ndn_face::net::ConnectedPort {
    use ndn_face::net::ConnectedPort;
    use std::net::SocketAddr;
    // A listener holds `b` when it is bound to the same port on the same
    // address, or either of them on every address.
    let holds = |l: &SocketAddr, b: &SocketAddr| {
        l.port() == b.port()
            && (l.ip() == b.ip() || l.ip().is_unspecified() || b.ip().is_unspecified())
    };
    let any = |port: u16| SocketAddr::from(([0, 0, 0, 0], port));
    match bind {
        Some(b) if b.port() != 0 && listeners.iter().any(|l| holds(l, &b)) => {
            ConnectedPort::Listener(b)
        }
        Some(b) => ConnectedPort::Exclusive(b),
        None => listeners
            .first()
            .map_or(ConnectedPort::Exclusive(any(0)), |l| ConnectedPort::Listener(any(l.port()))),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;
    use ndn_config::{FaceConfig, ForwarderConfig};
    use ndn_face::net::{ConnectedPort, UdpFace};
    use ndn_transport::{FaceId, Transport};

    use super::peer_face_port;

    /// The addresses of a config's UDP listeners, as they would bind.
    fn udp_listener_addrs(faces: &[FaceConfig]) -> Vec<std::net::SocketAddr> {
        faces
            .iter()
            .filter_map(|f| match f {
                FaceConfig::Udp { bind, remote: None } => {
                    bind.as_deref().unwrap_or("0.0.0.0:6363").parse().ok()
                }
                _ => None,
            })
            .collect()
    }

    /// The local address each `[[face]] kind = "udp"` entry with `remote` binds.
    fn peer_face_ports(toml: &str) -> Vec<ConnectedPort> {
        let cfg: ForwarderConfig = toml.parse().unwrap();
        let listeners = udp_listener_addrs(&cfg.faces);
        cfg.faces
            .iter()
            .filter_map(|f| match f {
                FaceConfig::Udp {
                    bind,
                    remote: Some(_),
                } => Some(peer_face_port(bind.as_deref().map(a), &listeners)),
                _ => None,
            })
            .collect()
    }

    fn a(s: &str) -> std::net::SocketAddr {
        s.parse().unwrap()
    }

    /// A peer face joins only a port a bound listener holds on its address;
    /// a port-0 listener is shared at the port it resolved to. A configured
    /// IP is kept as given.
    #[test]
    fn a_peer_face_joins_only_what_a_listener_holds() {
        use ConnectedPort::{Exclusive, Listener};
        let on_one_ip = [a("10.0.0.1:6363")];
        assert_eq!(peer_face_port(Some(a("10.0.0.2:6363")), &on_one_ip), Exclusive(a("10.0.0.2:6363")));
        assert_eq!(peer_face_port(Some(a("10.0.0.1:6363")), &on_one_ip), Listener(a("10.0.0.1:6363")));
        assert_eq!(peer_face_port(Some(a("0.0.0.0:6363")), &[]), Exclusive(a("0.0.0.0:6363")));
        assert_eq!(peer_face_port(None, &[a("127.0.0.1:40123")]), Listener(a("0.0.0.0:40123")));
        assert_eq!(peer_face_port(Some(a("0.0.0.0:0")), &[a("0.0.0.0:0")]), Exclusive(a("0.0.0.0:0")));
    }

    #[test]
    fn a_peer_face_shares_a_port_only_with_its_own_listener() {
        use ConnectedPort::{Exclusive, Listener};
        let device = "[[face]]\nkind = \"udp\"\nremote = \"127.0.0.1:16363\"\n";
        assert_eq!(peer_face_ports(device), [Exclusive(a("0.0.0.0:0"))]);

        let node = "[[face]]\nkind = \"udp\"\n\n\
                    [[face]]\nkind = \"udp\"\nremote = \"10.0.0.2:6363\"\n";
        assert_eq!(peer_face_ports(node), [Listener(a("0.0.0.0:6363"))]);

        let hub = "[[face]]\nkind = \"udp\"\nbind = \"127.0.0.1:16363\"\n\n\
                   [[face]]\nkind = \"udp\"\nremote = \"10.0.0.2:6363\"\n\n\
                   [[face]]\nkind = \"udp\"\nremote = \"10.0.0.3:6363\"\nbind = \"0.0.0.0:16363\"\n\n\
                   [[face]]\nkind = \"udp\"\nremote = \"10.0.0.4:6363\"\nbind = \"10.0.0.9:7000\"\n";
        assert_eq!(
            peer_face_ports(hub),
            [
                Listener(a("0.0.0.0:16363")),
                Listener(a("0.0.0.0:16363")),
                Exclusive(a("10.0.0.9:7000")),
            ]
        );
    }

    /// The live failure: two forwarders on 127.0.0.1, each configured with
    /// only a UDP face toward one hub, must be two sources to the hub, and
    /// each must get the replies sent to it.
    #[tokio::test]
    async fn two_forwarders_on_one_ip_each_get_their_replies() {
        let hub = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let hub_addr = hub.local_addr().unwrap();
        let device = format!("[[face]]\nkind = \"udp\"\nremote = \"{hub_addr}\"\n");
        let port = peer_face_ports(&device)[0];
        let a = UdpFace::bind_connected(port, hub_addr, FaceId(1))
            .await
            .unwrap();
        let b = UdpFace::bind_connected(port, hub_addr, FaceId(1))
            .await
            .unwrap();

        a.send_bytes(Bytes::from_static(b"from a")).await.unwrap();
        b.send_bytes(Bytes::from_static(b"from b")).await.unwrap();
        let mut buf = [0u8; 64];
        let mut sources = Vec::new();
        for _ in 0..2 {
            let (n, src) = hub.recv_from(&mut buf).await.unwrap();
            // Answer each source with what it sent, as the hub's face for
            // that source does.
            hub.send_to(&buf[..n], src).await.unwrap();
            sources.push(src);
        }
        assert_ne!(
            sources[0], sources[1],
            "the hub saw one source for two forwarders"
        );

        for (name, face, sent) in [("a", &a, &b"from a"[..]), ("b", &b, &b"from b"[..])] {
            let got = tokio::time::timeout(Duration::from_secs(2), face.recv_bytes())
                .await
                .unwrap_or_else(|_| panic!("forwarder {name} got no reply"))
                .unwrap();
            assert_eq!(&got[..], sent, "forwarder {name} got another's reply");
        }
    }
}
