//! NLSR install adapter. [`prepare`] runs the async pre-build (UDP
//! neighbour binds) and returns an installer that allocates Hello / Sync
//! / LSA `InProcFace` pairs, builds the runtime `NlsrProtocol`, and
//! queues the three Producer `serve` tasks plus their FIB writes.

use std::sync::Arc;

use ndn_engine::{EngineBuilder, InstallableProtocol, PostBuildQueue, RoutingProtocol};
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

pub struct NlsrInstaller {
    cfg: ndn_routing::NlsrConfig,
    own_router: Name,
    /// One pre-bound UDP face per neighbour; transports are already
    /// staged on the builder.
    neighbour_face_ids: Vec<(Name, FaceId)>,
}

/// Opens one UDP face per configured neighbour and stages it on the
/// builder. Returns `None` if NLSR is disabled.
pub async fn prepare(
    fwd_config: &ndn_config::ForwarderConfig,
    builder: &mut EngineBuilder,
) -> Option<NlsrInstaller> {
    if !fwd_config.routing.nlsr.enabled {
        return None;
    }
    let nlsr_toml = &fwd_config.routing.nlsr;
    let network: Name = nlsr_toml
        .network
        .parse()
        .unwrap_or_else(|_| "/ndn".parse().unwrap());
    let own_router: Name = nlsr_toml.router.parse().unwrap_or_else(|_| {
        tracing::warn!(target: "routing.nlsr", router = %nlsr_toml.router, "NLSR: invalid router name");
        Name::root()
    });
    let lsa_prefix = ndn_routing::NlsrConfig::default_lsa_prefix(&network);
    let sync_prefix = ndn_routing::NlsrConfig::default_sync_prefix(&network);
    let neighbors = nlsr_toml
        .neighbors
        .iter()
        .map(|n| ndn_routing::NeighborConfig {
            name: n.name.parse().unwrap_or_else(|_| Name::root()),
            face_uri: n.face_uri.clone(),
            link_cost: n.link_cost,
        })
        .collect();
    let name_prefixes: Vec<Name> = nlsr_toml
        .name_prefixes
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    let cfg = ndn_routing::NlsrConfig {
        own_router: own_router.clone(),
        network,
        lsa_prefix,
        sync_prefix,
        neighbors,
        name_prefixes,
        lsa_refresh_secs: nlsr_toml.lsa_refresh_secs,
        adj_lsa_build_interval_secs: nlsr_toml.adj_lsa_build_interval_secs,
        routing_calc_interval_secs: nlsr_toml.routing_calc_interval_secs,
        hello_interval_secs: nlsr_toml.hello_interval_secs,
        hello_retries: nlsr_toml.hello_retries,
        hello_timeout_secs: nlsr_toml.hello_timeout_secs,
        sync_interest_lifetime_ms: nlsr_toml.sync_interest_lifetime_ms,
        trust_policy: None,
        max_faces_per_prefix: nlsr_toml.max_faces_per_prefix,
    };

    let mut neighbour_face_ids: Vec<(Name, FaceId)> = Vec::new();
    for n in &nlsr_toml.neighbors {
        let uri = &n.face_uri;
        let addr_str = uri
            .strip_prefix("udp4://")
            .or_else(|| uri.strip_prefix("udp://"))
            .unwrap_or(uri);
        let peer: std::net::SocketAddr = match addr_str.parse() {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(target: "routing.nlsr", uri=%uri, error=%e, "NLSR: skipping neighbour with unparseable URI");
                continue;
            }
        };
        let local: std::net::SocketAddr = if peer.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let face_id = builder.alloc_face_id();
        match ndn_face::net::UdpFace::bind(local, peer, face_id).await {
            Ok(face) => {
                builder.add_face(face);
                let neighbour_name = n.name.parse().unwrap_or_else(|_| Name::root());
                neighbour_face_ids.push((neighbour_name.clone(), face_id));
                tracing::info!(
                    target: "routing.nlsr",
                    neighbor = %neighbour_name,
                    remote = %peer,
                    neighbor_face = face_id.0,
                    "NLSR neighbour UDP face created",
                );
            }
            Err(e) => {
                tracing::warn!(target: "routing.nlsr", remote=%peer, error=%e, "NLSR: failed to open neighbour UDP face");
            }
        }
    }

    Some(NlsrInstaller {
        cfg,
        own_router,
        neighbour_face_ids,
    })
}

impl InstallableProtocol for NlsrInstaller {
    fn install(self: Arc<Self>, builder: &mut EngineBuilder, post_build: &mut PostBuildQueue) {
        // Consumer faces whose Interests carry an NDNLPv2 NextHopFaceId
        // (PSync/Hello pin each Interest to a neighbour face). The forwarder
        // honours NextHopFaceId only from faces that opted into LocalFields
        // (the FaceUpdateCommand contract NLSR-over-NFD relies on); enable it
        // post-build on exactly these local consumer faces.
        let mut local_fields_face_ids = Vec::new();
        let mut hello_neighbor_handles = Vec::with_capacity(self.neighbour_face_ids.len());
        for (neighbour_name, _) in &self.neighbour_face_ids {
            let hello_consumer_id = builder.alloc_face_id();
            let (hf, hh) = InProcFace::new(hello_consumer_id, 64);
            builder.add_face(hf);
            local_fields_face_ids.push(hello_consumer_id);
            hello_neighbor_handles.push((neighbour_name.clone(), hh));
            tracing::info!(
                target: "routing.nlsr",
                neighbor = %neighbour_name,
                hello_face = hello_consumer_id.0,
                "NLSR Hello consumer face allocated",
            );
        }

        let sync_lsa_consumer_id = builder.alloc_face_id();
        let (sync_lsa_face, sync_lsa_handle) = InProcFace::new(sync_lsa_consumer_id, 256);
        builder.add_face(sync_lsa_face);
        local_fields_face_ids.push(sync_lsa_consumer_id);

        let hello_producer_id = builder.alloc_face_id();
        let (hp_face, hello_producer_handle) = InProcFace::new(hello_producer_id, 64);
        builder.add_face(hp_face);

        let sync_producer_id = builder.alloc_face_id();
        let (sp_face, sync_producer_handle) = InProcFace::new(sync_producer_id, 256);
        builder.add_face(sp_face);

        let lsa_producer_id = builder.alloc_face_id();
        let (lp_face, lsa_producer_handle) = InProcFace::new(lsa_producer_id, 256);
        builder.add_face(lp_face);

        let io = ndn_routing::nlsr::NlsrIo {
            neighbor_face_ids: self.neighbour_face_ids.clone(),
            hello_neighbor_handles,
            sync_lsa_handle,
        };
        let nlsr = ndn_routing::NlsrProtocol::with_io(self.cfg.clone(), io);

        builder
            .register_routing_protocol(Arc::clone(&nlsr) as Arc<dyn ndn_engine::RoutingProtocol>);
        tracing::info!(target: "routing.nlsr", router = %self.own_router, "NLSR routing protocol enabled");

        // Status bridge at `/localhost/nlsr/status` reuses the ndnd-shape
        // `Status` TLV so `ndnd dvc status` parses either NLSR or DV.
        // NLSR counters map: `nLsdbEntries` → `n_rib_entries`,
        // `nRoutingEntries` → `n_fib_entries`, `nNeighbors` →
        // `n_neighbors`.
        let nlsr_for_status = Arc::clone(&nlsr);
        let status_prefix: Name = "/localhost/nlsr/status".parse().expect("static prefix");
        ndn_mgmt::mount_routing_status(builder, post_build, status_prefix, move || {
            build_nlsr_status_tlv(&nlsr_for_status)
        });

        let hello_fib_prefix = self
            .own_router
            .clone()
            .append(b"nlsr" as &[u8])
            .append(b"INFO" as &[u8]);
        let sync_fib_prefix = self.cfg.sync_prefix.clone();
        let lsa_fib_prefix = self.cfg.lsa_prefix.clone();

        post_build.add_fib_entry(hello_fib_prefix.clone(), hello_producer_id, 0);
        post_build.add_fib_entry(sync_fib_prefix.clone(), sync_producer_id, 0);
        post_build.add_fib_entry(lsa_fib_prefix.clone(), lsa_producer_id, 0);

        // Opt the NextHopFaceId-emitting consumer faces into LocalFields so the
        // forwarder honours their pinned Interests (see comment at face alloc).
        post_build.defer(move |engine, _cancel| {
            for face_id in local_fields_face_ids {
                engine.set_local_fields(face_id, true);
            }
        });

        let nlsr_for_hello = Arc::clone(&nlsr);
        let nlsr_for_sync = Arc::clone(&nlsr);
        let nlsr_for_lsa = Arc::clone(&nlsr);

        post_build.defer(move |_engine, cancel| {
            spawn_hello_producer(nlsr_for_hello, hello_producer_handle, cancel.clone());
            spawn_sync_producer(nlsr_for_sync, sync_producer_handle, cancel.clone());
            spawn_lsa_producer(nlsr_for_lsa, lsa_producer_handle, cancel.clone());
            tracing::info!(
                target: "routing.nlsr",
                hello = %hello_fib_prefix,
                sync = %sync_fib_prefix,
                lsa = %lsa_fib_prefix,
                "NLSR: Producer FIB entries installed and producers running",
            );
        });
    }
}

fn spawn_hello_producer(
    nlsr: Arc<ndn_routing::NlsrProtocol>,
    handle: ndn_face::local::InProcHandle,
    cancel: CancellationToken,
) {
    let hello_proto = nlsr.hello_protocol();
    tokio::spawn(async move {
        use ndn_app::Producer;
        let conn = Arc::new(ndn_app::InProcConnection::new(handle)) as Arc<dyn ndn_app::Connection>;
        let producer = Producer::new(conn, Name::root());
        let serve_fut = producer.serve(|interest, responder| {
            let hello = hello_proto.clone();
            async move {
                if let Some(wire) = hello.handle_incoming_interest(&interest.name) {
                    let _ = responder.respond_bytes(wire).await;
                }
            }
        });
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {}
            _ = serve_fut => {}
        }
    });
}

fn spawn_sync_producer(
    nlsr: Arc<ndn_routing::NlsrProtocol>,
    handle: ndn_face::local::InProcHandle,
    cancel: CancellationToken,
) {
    let sync_in_tx = nlsr.sync_inbound_sender();
    tokio::spawn(async move {
        use ndn_app::Producer;
        let conn = Arc::new(ndn_app::InProcConnection::new(handle)) as Arc<dyn ndn_app::Connection>;
        let producer = Producer::new(conn, Name::root());
        let serve_fut = producer.serve(move |interest, responder| {
            let tx = sync_in_tx.clone();
            async move {
                let wire = interest.raw().clone();
                let (reply_tx, reply_rx) = tokio::sync::oneshot::channel::<bytes::Bytes>();
                if tx
                    .send(ndn_sync::PSyncInbound {
                        bytes: wire,
                        reply: Some(reply_tx),
                    })
                    .await
                    .is_err()
                {
                    return;
                }
                // Cap below PSync's 1s Interest lifetime so callbacks
                // don't pile up for Interests the peer has already
                // abandoned.
                if let Ok(Ok(data_wire)) =
                    tokio::time::timeout(std::time::Duration::from_millis(900), reply_rx).await
                {
                    let _ = responder.respond_bytes(data_wire).await;
                }
            }
        });
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {}
            _ = serve_fut => {}
        }
    });
}

fn spawn_lsa_producer(
    nlsr: Arc<ndn_routing::NlsrProtocol>,
    handle: ndn_face::local::InProcHandle,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        use ndn_app::Producer;
        let conn = Arc::new(ndn_app::InProcConnection::new(handle)) as Arc<dyn ndn_app::Connection>;
        let producer = Producer::new(conn, Name::root());
        let serve_fut = producer.serve(move |interest, responder| {
            let nlsr = Arc::clone(&nlsr);
            let wire = interest.raw().clone();
            async move {
                if let Some(data_wire) = nlsr.handle_lsa_interest(wire) {
                    let _ = responder.respond_bytes(data_wire).await;
                }
            }
        });
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {}
            _ = serve_fut => {}
        }
    });
}

/// Encode NLSR status as the ndnd-shape DV `Status` TLV so `dvc status`
/// parses either protocol.
fn build_nlsr_status_tlv(nlsr: &ndn_routing::NlsrProtocol) -> bytes::Bytes {
    use ndn_routing::protocols::dv::tlv::Status;
    let snapshot = nlsr.status();
    let network = snapshot.network.clone().unwrap_or_else(Name::root);
    let router = snapshot.router.clone().unwrap_or_else(Name::root);
    let s = Status {
        version: env!("CARGO_PKG_VERSION").to_string(),
        network_name: network,
        router_name: router,
        n_rib_entries: snapshot.counters.get("nLsdbEntries").copied().unwrap_or(0),
        n_neighbors: snapshot.counters.get("nNeighbors").copied().unwrap_or(0),
        n_fib_entries: snapshot
            .counters
            .get("nRoutingEntries")
            .copied()
            .unwrap_or(0),
    };
    s.encode_content()
}
