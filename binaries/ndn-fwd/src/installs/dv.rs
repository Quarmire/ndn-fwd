//! ndn-dv install adapter. [`prepare`] runs the async pre-build (UDP
//! neighbour binds, trust-anchor reads) and returns an installer that
//! registers `DvProtocol` on the routing and discovery slots and queues
//! neighbour seeds plus PFS multicast FIB entries.

use std::sync::Arc;
use std::time::Duration;

use ndn_engine::{EngineBuilder, InstallableProtocol, PostBuildQueue, RoutingProtocol};
use ndn_face::local::InProcFace;
use ndn_packet::Name;
use ndn_transport::FaceId;

use crate::parse_name;

pub struct DvInstaller {
    dv: Arc<ndn_routing::protocols::dv::DvProtocol>,
    neighbour_seeds: Vec<(Name, FaceId)>,
    pfs_routes: Vec<(Name, FaceId)>,
}

/// Returns `None` if DV is disabled; an error if the network or router name
/// is malformed. A neighbour or trusted key with a malformed name is skipped
/// with an error log. `node_signer` is the node identity's key (DV routing
/// signs as the node, never as a trusted prefix's identity); the `static`
/// and `lvs` trust modes sign with the key it holds at startup and keep it:
/// DV neighbours accept only the keys in their `[routing.dv.trust]
/// trusted_keys`, so a node key that changes at runtime (a daemon on its
/// ephemeral key enrolling its first identity) would silently cut it off
/// from routing. DV moves to the new node key at a restart, once neighbours
/// trust it.
pub async fn prepare(
    fwd_config: &ndn_config::ForwarderConfig,
    builder: &mut EngineBuilder,
    node_signer: Option<Arc<ndn_security::ActiveSigner>>,
) -> anyhow::Result<Option<DvInstaller>> {
    if !fwd_config.routing.dv.enabled {
        return Ok(None);
    }
    let dv_toml = &fwd_config.routing.dv;
    let dv_network = parse_name(&dv_toml.network)
        .map_err(|e| e.context("[routing.dv].network is not a valid NDN name"))?;
    let dv_router = parse_name(&dv_toml.router)
        .map_err(|e| e.context("[routing.dv].router is not a valid NDN name"))?;
    let dv_boot = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut dv_cfg =
        ndn_routing::protocols::dv::DvConfig::new(dv_network.clone(), dv_router.clone(), dv_boot);
    dv_cfg.adv_sync_interval = Duration::from_secs(dv_toml.adv_sync_secs);
    dv_cfg.pfx_sync_interval = Duration::from_secs(dv_toml.pfx_sync_secs);
    dv_cfg.router_dead_interval = Duration::from_secs(dv_toml.router_dead_secs);

    let fetch_id = builder.alloc_face_id();
    let produce_id = builder.alloc_face_id();
    let (fetch_face, fetch_handle) = InProcFace::new(fetch_id, 256);
    let (produce_face, produce_handle) = InProcFace::new(produce_id, 256);
    builder.add_face(fetch_face);
    builder.add_face(produce_face);

    let pfs_group = {
        let mut n = dv_network.clone();
        n = n.append(b"DV" as &[u8]).append(b"PFS" as &[u8]);
        n
    };

    let mut neighbour_seeds: Vec<(Name, FaceId)> = Vec::new();
    let mut pfs_routes: Vec<(Name, FaceId)> = Vec::new();
    for n in &dv_toml.neighbors {
        let neighbour_name = match parse_name(&n.name) {
            Ok(name) => name,
            Err(e) => {
                tracing::error!(target: "routing.dv", neighbor = %n.name, error = %e, "DV: skipping neighbour with invalid name");
                continue;
            }
        };
        let uri = &n.face_uri;
        let addr_str = uri
            .strip_prefix("udp4://")
            .or_else(|| uri.strip_prefix("udp://"))
            .unwrap_or(uri);
        let peer: std::net::SocketAddr = match addr_str.parse() {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(target: "routing.dv", uri=%uri, error=%e, "DV: skipping neighbour with unparseable URI");
                continue;
            }
        };
        let local = super::neighbour_bind(&fwd_config.faces, peer);
        let face_id = builder.alloc_face_id();
        match ndn_face::net::UdpFace::bind(local, peer, face_id).await {
            Ok(face) => {
                builder.add_face(face);
                neighbour_seeds.push((neighbour_name.clone(), face_id));
                pfs_routes.push((pfs_group.clone(), face_id));
                tracing::info!(
                    target: "routing.dv",
                    peer = %neighbour_name,
                    remote = %peer,
                    face = face_id.0,
                    "DV neighbour UDP face created",
                );
            }
            Err(e) => {
                tracing::warn!(target: "routing.dv", remote=%peer, error=%e, "DV: failed to open UDP face for neighbour");
            }
        }
    }

    let dv_signer = node_signer.map(|s| Arc::new(ndn_security::ActiveSigner::new(s.current())));
    let dv_trust = build_trust(dv_toml, dv_signer);
    let dv = ndn_routing::protocols::dv::DvProtocol::with_io_and_trust(
        dv_cfg,
        fetch_handle,
        produce_handle,
        produce_id,
        dv_trust,
    );
    tracing::info!(
        target: "routing.dv",
        router = %dv_router,
        boot = dv_boot,
        neighbours = dv_toml.neighbors.len(),
        "ndn-dv routing protocol enabled",
    );

    Ok(Some(DvInstaller {
        dv,
        neighbour_seeds,
        pfs_routes,
    }))
}

fn build_trust(
    dv_toml: &ndn_config::config::DvTomlConfig,
    node_signer: Option<Arc<ndn_security::ActiveSigner>>,
) -> ndn_routing::protocols::dv::signing::DvTrustHandle {
    match dv_toml.trust.mode.as_str() {
        "insecure" => {
            tracing::info!(target: "routing.dv", "DV trust = DvInsecure (default; wire-compat with ndnd `insecure`)");
            ndn_routing::protocols::dv::signing::DvInsecure::handle()
        }
        "lvs" => {
            use ndn_routing::protocols::dv::signing::DvLvs;
            let try_build = || -> Option<ndn_routing::protocols::dv::signing::DvTrustHandle> {
                let schema_path = dv_toml.trust.schema_file.as_ref()?;
                let schema_bytes = match std::fs::read(schema_path) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::error!(target: "routing.dv", path = %schema_path, error = %e, "LVS schema load FAILED");
                        return None;
                    }
                };
                let model = match ndn_security::LvsModel::decode(&schema_bytes) {
                    Ok(m) => Arc::new(m),
                    Err(e) => {
                        tracing::error!(target: "routing.dv", path = %schema_path, error = ?e, "LVS schema decode FAILED");
                        return None;
                    }
                };
                let mut lt = DvLvs::new(model, node_signer.clone());
                for tk in &dv_toml.trust.trusted_keys {
                    let key_name = match parse_name(&tk.name) {
                        Ok(name) => name,
                        Err(e) => {
                            tracing::error!(target: "routing.dv", key = %tk.name, error = %e, "DV trusted key skipped: invalid key name (lvs mode)");
                            continue;
                        }
                    };
                    match std::fs::read(&tk.public_key_file) {
                        Ok(bytes) => {
                            lt = lt.trust_key(key_name.clone(), bytes::Bytes::from(bytes));
                            tracing::info!(target: "routing.dv", key = %key_name, path = %tk.public_key_file, "DV trusted key loaded (lvs mode)");
                        }
                        Err(e) => {
                            tracing::error!(target: "routing.dv", key = %key_name, path = %tk.public_key_file, error = %e, "DV trusted key load FAILED (lvs mode)");
                        }
                    }
                }
                tracing::info!(target: "routing.dv", schema = %schema_path, keys = dv_toml.trust.trusted_keys.len(), "DV trust = DvLvs");
                Some(lt.handle())
            };
            try_build().unwrap_or_else(|| {
                tracing::error!(target: "routing.dv", "LVS trust build failed; falling back to DvInsecure.");
                ndn_routing::protocols::dv::signing::DvInsecure::handle()
            })
        }
        "static" => {
            use ndn_routing::protocols::dv::signing::DvStaticKeys;
            let mut st = DvStaticKeys::new(node_signer.clone());
            for tk in &dv_toml.trust.trusted_keys {
                let key_name = match parse_name(&tk.name) {
                    Ok(name) => name,
                    Err(e) => {
                        tracing::error!(target: "routing.dv", key = %tk.name, error = %e, "DV trusted key skipped: invalid key name — packets signed with this key will be rejected");
                        continue;
                    }
                };
                match std::fs::read(&tk.public_key_file) {
                    Ok(bytes) => {
                        st = st.trust_key(key_name.clone(), bytes::Bytes::from(bytes));
                        tracing::info!(target: "routing.dv", key = %key_name, path = %tk.public_key_file, "DV trusted key loaded");
                    }
                    Err(e) => {
                        tracing::error!(target: "routing.dv", key = %key_name, path = %tk.public_key_file, error = %e, "DV trusted key load FAILED — packets signed with this key will be rejected");
                    }
                }
            }
            tracing::info!(target: "routing.dv", keys = dv_toml.trust.trusted_keys.len(), "DV trust = DvStaticKeys");
            st.handle()
        }
        other => {
            tracing::warn!(target: "routing.dv", mode = %other, "DV trust mode unknown — falling back to DvInsecure. Supported: insecure | static | lvs");
            ndn_routing::protocols::dv::signing::DvInsecure::handle()
        }
    }
}

impl InstallableProtocol for DvInstaller {
    fn install(self: Arc<Self>, builder: &mut EngineBuilder, post_build: &mut PostBuildQueue) {
        builder
            .register_discovery(Arc::clone(&self.dv) as Arc<dyn ndn_discovery::DiscoveryProtocol>);
        builder.register_routing_protocol(
            Arc::clone(&self.dv) as Arc<dyn ndn_engine::RoutingProtocol>
        );

        for (peer, face_id) in &self.neighbour_seeds {
            post_build.seed_neighbor(peer.clone(), *face_id);
        }
        for (prefix, face_id) in &self.pfs_routes {
            post_build.add_fib_entry(prefix.clone(), *face_id, 0);
            tracing::info!(
                target: "routing.dv",
                prefix = %prefix,
                face = face_id.0,
                "DV Pfx Sync multicast FIB entry queued",
            );
        }

        // Status bridge at `/localhost/nlsr/status` wire-compatible with
        // ndnd's `dvc status`: Interest at that name, reply Content is
        // the binary `Status` TLV.
        let dv_for_status = Arc::clone(&self.dv);
        let status_prefix: Name = "/localhost/nlsr/status".parse().expect("static prefix");
        ndn_mgmt::mount_routing_status(builder, post_build, status_prefix, move || {
            build_dv_status_tlv(&dv_for_status)
        });
    }
}

/// Encode DV status as the ndnd-shape `Status` TLV (matches
/// `ndnd/dv/tlv/definitions.go`).
fn build_dv_status_tlv(dv: &ndn_routing::protocols::dv::DvProtocol) -> bytes::Bytes {
    use ndn_routing::protocols::dv::tlv::Status;
    let snapshot = dv.status();
    let network = snapshot.network.clone().unwrap_or_else(Name::root);
    let router = snapshot.router.clone().unwrap_or_else(Name::root);
    let s = Status {
        version: env!("CARGO_PKG_VERSION").to_string(),
        network_name: network,
        router_name: router,
        n_rib_entries: snapshot.counters.get("nRibEntries").copied().unwrap_or(0),
        n_neighbors: snapshot.counters.get("nNeighbors").copied().unwrap_or(0),
        n_fib_entries: snapshot.counters.get("nFibEntries").copied().unwrap_or(0),
    };
    s.encode_content()
}
