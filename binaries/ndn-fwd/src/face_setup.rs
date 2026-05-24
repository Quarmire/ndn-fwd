//! Face listener, auto-multicast, and hotplug-watcher bootstrap.

#![allow(unused_imports, dead_code, clippy::too_many_arguments)]

use std::sync::Arc;

use ndn_config::ForwarderConfig;
use ndn_engine::ForwarderEngine;
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

use ndn_mgmt as mgmt_ndn;

#[cfg(feature = "webrtc")]
use crate::transport_listeners::run_webrtc_listener;
use crate::transport_listeners::{run_ws_listener, run_wt_listener};

pub struct FaceSetupState {
    pub pre_allocated_multicast: Vec<(FaceId, usize)>,
    pub pre_allocated_ether_mc: Vec<(FaceId, usize)>,
    pub auto_udp_pre_alloc: Vec<(FaceId, String, std::net::Ipv4Addr)>,
    pub auto_ether_pre_alloc: Vec<(FaceId, String)>,
    pub auto_udp_ifaces: Vec<(String, std::net::Ipv4Addr)>,
    pub auto_ether_ifaces: Vec<ndn_face_native::iface::InterfaceInfo>,
}

/// Spawn every face listener, WebTransport / WebRTC listener, auto-
/// enumerated multicast face creator, and the interface hotplug watcher.
/// Returns once spawns are issued; tasks run until `cancel` fires.
pub async fn run_face_setup(
    engine: &ForwarderEngine,
    cancel: &CancellationToken,
    fwd_config: &ForwarderConfig,
    state: FaceSetupState,
) {
    let FaceSetupState {
        pre_allocated_multicast,
        pre_allocated_ether_mc,
        auto_udp_pre_alloc,
        auto_ether_pre_alloc,
        auto_udp_ifaces,
        auto_ether_ifaces,
    } = state;
    let cancel = cancel.clone();
    #[cfg(not(target_os = "linux"))]
    let _ = &pre_allocated_ether_mc;
    #[cfg(not(target_os = "linux"))]
    let _ = &auto_ether_pre_alloc;
    #[cfg(not(target_os = "linux"))]
    let _ = &auto_ether_ifaces;

    run_face_setup_inner(
        engine,
        &cancel,
        fwd_config,
        pre_allocated_multicast,
        pre_allocated_ether_mc,
        auto_udp_pre_alloc,
        auto_ether_pre_alloc,
        auto_udp_ifaces,
        auto_ether_ifaces,
    )
    .await;
}

#[allow(clippy::needless_pass_by_value, unused_variables)]
async fn run_face_setup_inner(
    engine: &ForwarderEngine,
    cancel: &CancellationToken,
    fwd_config: &ForwarderConfig,
    pre_allocated_multicast: Vec<(FaceId, usize)>,
    pre_allocated_ether_mc: Vec<(FaceId, usize)>,
    auto_udp_pre_alloc: Vec<(FaceId, String, std::net::Ipv4Addr)>,
    auto_ether_pre_alloc: Vec<(FaceId, String)>,
    auto_udp_ifaces: Vec<(String, std::net::Ipv4Addr)>,
    auto_ether_ifaces: Vec<ndn_face_native::iface::InterfaceInfo>,
) {
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
                    let face_id = engine.faces().alloc_id();
                    let local: std::net::SocketAddr = if peer.is_ipv4() {
                        "0.0.0.0:0".parse().unwrap()
                    } else {
                        "[::]:0".parse().unwrap()
                    };
                    let eng = engine.clone();
                    tokio::spawn(async move {
                        match ndn_face_native::net::UdpFace::bind(local, peer, face_id).await {
                            Ok(face) => {
                                let c = CancellationToken::new();
                                tracing::info!(target: "face.udp", face = face_id.0, remote = %peer, "udp pre-connected face created");
                                eng.add_face_with_persistency(
                                    face,
                                    c,
                                    ndn_transport::FacePersistency::Persistent,
                                );
                            }
                            Err(e) => {
                                tracing::error!(target: "face.udp", remote = %peer, error = %e, "failed to create UDP face");
                            }
                        }
                    });
                } else if let Some(addr) =
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
                        tracing::error!(target: "face.udp", group=%group, error=%e, "invalid multicast group address");
                        continue;
                    }
                };
                let id = pre_allocated_multicast
                    .iter()
                    .find(|(_, idx)| *idx == face_idx)
                    .map(|(fid, _)| *fid)
                    .unwrap_or_else(|| engine.faces().alloc_id());
                let port = *port;
                let eng = engine.clone();
                let c = cancel.child_token();
                tokio::spawn(async move {
                    match ndn_face_native::net::MulticastUdpFace::new(iface, port, group_addr, id).await {
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
                    let id = engine.faces().alloc_id();
                    let eng = engine.clone();
                    let c = cancel.child_token();
                    tokio::spawn(async move {
                        match ndn_face_webtransport::WebTransportFace::connect(id, &url, tls).await {
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
            ndn_config::FaceConfig::Quic {
                remote,
                cert_sha256,
                webpki,
            } => {
                #[cfg(feature = "quic")]
                {
                    let authority = remote.strip_prefix("quic://").unwrap_or(remote).to_owned();
                    let tls = if *webpki {
                        Some(ndn_transport::ClientTls::WebPki)
                    } else {
                        cert_sha256
                            .as_deref()
                            .and_then(ndn_config::parse_cert_sha256_hex)
                            .map(|h| ndn_transport::ClientTls::CertHashes(vec![h]))
                    };
                    let Some(tls) = tls else {
                        tracing::error!(target: "face.quic", remote=%remote, "quic dial face: invalid/missing cert_sha256 (or webpki)");
                        continue;
                    };
                    let id = engine.faces().alloc_id();
                    let eng = engine.clone();
                    let c = cancel.child_token();
                    tokio::spawn(async move {
                        // The connector (endpoint) is dropped after connect; the
                        // face's streams keep the connection + driver alive.
                        match ndn_face_quic::QuicConnector::new(tls) {
                            Ok(connector) => match connector.connect_authority(id, &authority).await {
                                Ok(face) => {
                                    eng.add_face(face, c);
                                    tracing::info!(target: "face.quic", face=%id, remote=%authority, "QUIC dial face connected");
                                }
                                Err(e) => tracing::error!(target: "face.quic", remote=%authority, error=%e, "QUIC dial failed"),
                            },
                            Err(e) => tracing::error!(target: "face.quic", error=%e, "QUIC connector setup failed"),
                        }
                    });
                }
                #[cfg(not(feature = "quic"))]
                {
                    let _ = (remote, cert_sha256, webpki);
                    tracing::warn!(target: "face.quic", "quic dial face ignored (quic feature not compiled in)");
                }
            }
            ndn_config::FaceConfig::Serial { path, baud } => {
                #[cfg(feature = "serial")]
                {
                    let id = engine.faces().alloc_id();
                    match ndn_face_native::serial::serial_face_open(id, path, *baud) {
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
                    let id = pre_allocated_ether_mc
                        .iter()
                        .find(|(_, ci)| *ci == face_idx)
                        .map(|(id, _)| *id)
                        .unwrap_or_else(|| engine.faces().alloc_id());
                    match ndn_face_native::l2::MulticastEtherFace::new(id, interface) {
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
                    let id = engine.faces().alloc_id();
                    match ndn_face_native::l2::NamedEtherFace::new(
                        id,
                        ndn_packet::Name::root(),
                        mac,
                        interface.clone(),
                        ndn_face_native::l2::RadioFaceMetadata::default(),
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
                    let _ = (interface, peer_mac);
                    tracing::warn!(target: "face.eth", "ether unicast face not supported on this platform");
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

    #[cfg(feature = "quic")]
    if let Some(quic_cfg) = fwd_config.listeners.quic.clone()
        && quic_cfg.enabled
    {
        let eng = engine.clone();
        let c = cancel.clone();
        tokio::spawn(async move { crate::transport_listeners::run_quic_listener(quic_cfg, eng, c).await });
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
        match ndn_face_native::l2::MulticastEtherFace::new(id, iface_name) {
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
    #[cfg(target_os = "linux")]
    if auto_ether_pre_alloc.is_empty() {
        for iface_info in &auto_ether_ifaces {
            let id = engine.faces().alloc_id();
            match ndn_face_native::l2::MulticastEtherFace::new(id, &iface_info.name) {
                Ok(face) => {
                    let c = cancel.child_token();
                    engine.add_face_with_persistency(
                        face,
                        c,
                        ndn_transport::FacePersistency::Permanent,
                    );
                    tracing::info!(target: "face.eth", iface=%iface_info.name, face=%id, "auto multicast ethernet face opened");
                }
                Err(e) => {
                    tracing::error!(target: "face.eth", iface=%iface_info.name, error=%e, "auto multicast ethernet face failed");
                }
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    if !auto_ether_ifaces.is_empty() {
        tracing::warn!(
            target: "face.eth",
            count = auto_ether_ifaces.len(),
            "ether auto_multicast: EtherMulticast faces only supported on Linux, skipping"
        );
    }

    let udp_ad_hoc = fwd_config.face_system.udp.ad_hoc;
    for (pre_id, iface_name, addr) in &auto_udp_pre_alloc {
        let id = *pre_id;
        let addr = *addr;
        let iface_name = iface_name.clone();
        let eng = engine.clone();
        let c = cancel.child_token();
        tokio::spawn(async move {
            match ndn_face_native::net::MulticastUdpFace::ndn_default(addr, id).await {
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
    if auto_udp_pre_alloc.is_empty() {
        for (iface_name, addr) in &auto_udp_ifaces {
            let id = engine.faces().alloc_id();
            let addr = *addr;
            let iface_name = iface_name.clone();
            let eng = engine.clone();
            let c = cancel.child_token();
            tokio::spawn(async move {
                match ndn_face_native::net::MulticastUdpFace::ndn_default(addr, id).await {
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
    }

    if fwd_config.face_system.watch_interfaces {
        let (watcher_tx, mut watcher_rx) =
            tokio::sync::mpsc::channel::<ndn_face_native::iface_watcher::InterfaceEvent>(64);
        let watcher_cancel = cancel.child_token();
        tokio::spawn(ndn_face_native::iface_watcher::watch_interfaces(
            watcher_tx,
            watcher_cancel,
        ));

        let watcher_engine = engine.clone();
        let watcher_fwd_cfg = fwd_config.face_system.clone();
        let watcher_cancel2 = cancel.child_token();
        let watcher_udp_ad_hoc = udp_ad_hoc;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = watcher_cancel2.cancelled() => break,
                    event = watcher_rx.recv() => {
                        let Some(event) = event else { break };
                        match event {
                            ndn_face_native::iface_watcher::InterfaceEvent::Added(iface_name) => {
                                #[cfg(target_os = "linux")]
                                if watcher_fwd_cfg.ether.auto_multicast
                                    && ndn_face_native::iface::interface_allowed(
                                        &iface_name,
                                        &watcher_fwd_cfg.ether.whitelist,
                                        &watcher_fwd_cfg.ether.blacklist,
                                    )
                                {
                                    let id = watcher_engine.faces().alloc_id();
                                    match ndn_face_native::l2::MulticastEtherFace::new(id, &iface_name) {
                                        Ok(face) => {
                                            watcher_engine.add_face_with_persistency(
                                                face,
                                                watcher_cancel2.child_token(),
                                                ndn_transport::FacePersistency::Permanent,
                                            );
                                            tracing::info!(target: "face.eth", iface=%iface_name, face=%id, "hotplug: multicast ethernet face added");
                                        }
                                        Err(e) => {
                                            tracing::warn!(target: "face.eth", iface=%iface_name, error=%e, "hotplug: failed to open multicast ethernet face");
                                        }
                                    }
                                }

                                if watcher_fwd_cfg.udp.auto_multicast
                                    && ndn_face_native::iface::interface_allowed(
                                        &iface_name,
                                        &watcher_fwd_cfg.udp.whitelist,
                                        &watcher_fwd_cfg.udp.blacklist,
                                    )
                                {
                                    let ifaces = ndn_face_native::iface::list_interfaces();
                                    if let Some(info) = ifaces.iter().find(|i| i.name == iface_name) {
                                        for &addr in &info.ipv4_addrs {
                                            let id = watcher_engine.faces().alloc_id();
                                            let eng = watcher_engine.clone();
                                            let cancel3 = watcher_cancel2.child_token();
                                            let name2 = iface_name.clone();
                                            tokio::spawn(async move {
                                                match ndn_face_native::net::MulticastUdpFace::ndn_default(addr, id).await {
                                                    Ok(face) => {
                                                        let face = if watcher_udp_ad_hoc { face.ad_hoc() } else { face };
                                                        eng.add_face_with_persistency(face, cancel3, ndn_transport::FacePersistency::Permanent);
                                                        tracing::info!(target: "face.udp", iface=%name2, addr=%addr, face=%id, "hotplug: multicast UDP face added");
                                                    }
                                                    Err(e) => {
                                                        tracing::warn!(target: "face.udp", iface=%name2, addr=%addr, error=%e, "hotplug: failed to open multicast UDP face");
                                                    }
                                                }
                                            });
                                        }
                                    }
                                }
                            }
                            ndn_face_native::iface_watcher::InterfaceEvent::Removed(iface_name) => {
                                // Faces on this interface use `dev://<iface>` as `local_uri`.
                                let target_uri = format!("dev://{iface_name}");
                                let face_table = watcher_engine.faces();
                                for face_id in face_table.face_ids() {
                                    if let Some(face) = face_table.get(face_id)
                                        && face.local_uri().as_deref() == Some(&target_uri)
                                        && let Some(tok) = watcher_engine.face_token(face_id)
                                    {
                                        tok.cancel();
                                        tracing::info!(target: "face.system", iface=%iface_name, face=%face_id, "hotplug: face removed");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    tracing::info!(target: "engine", "engine running");
}
