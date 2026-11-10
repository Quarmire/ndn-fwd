//! Extension-transport face provisioners for `faces/create`.
//!
//! `ndn-mgmt` is face-agnostic for the extension transports: it builds the
//! standard ones (UDP/TCP/Ethernet/BLE/SHM) itself but delegates WebTransport
//! (`wts://`) to provisioners the forwarder registers via
//! [`MgmtHandles::face_provisioners`](ndn_mgmt::MgmtHandles). Each is gated
//! by the same feature that links its face crate. `quic://` is refused with
//! the `[[peer]]` config to write instead: a QUIC link is configured by the
//! device it links to (see `links`).

use std::sync::Arc;

use ndn_mgmt::FaceProvisioner;
#[cfg(any(
    feature = "quic",
    feature = "webtransport",
    feature = "spsc-shm",
    feature = "bluetooth"
))]
use ndn_mgmt::{ProvisionError, ProvisionRequest, ProvisionedFace};

/// The provisioners this build links, one per enabled extension transport.
#[allow(unused_mut, clippy::vec_init_then_push)] // pushes are cfg-gated per feature
pub fn face_provisioners() -> Vec<Arc<dyn FaceProvisioner>> {
    let mut v: Vec<Arc<dyn FaceProvisioner>> = Vec::new();
    #[cfg(feature = "quic")]
    v.push(Arc::new(QuicProvisioner));
    #[cfg(feature = "webtransport")]
    v.push(Arc::new(WebTransportProvisioner));
    #[cfg(feature = "spsc-shm")]
    v.push(Arc::new(ShmProvisioner));
    #[cfg(feature = "bluetooth")]
    v.push(Arc::new(BleProvisioner));
    v
}

/// `ble://<name-or-address>[?framing=ndnts|ndnlpv2][&adapter=hci0]` — dial a BLE
/// peripheral as a GATT central. The peripheral (GATT server) is a listener
/// (`[listeners.ble]`), not created here. BLE moved to the `ndn-face-bluetooth`
/// extension crate.
#[cfg(feature = "bluetooth")]
struct BleProvisioner;

#[cfg(feature = "bluetooth")]
#[async_trait::async_trait]
impl FaceProvisioner for BleProvisioner {
    fn handles(&self, uri: &str) -> bool {
        uri.starts_with("ble://")
    }

    async fn provision(
        &self,
        req: ProvisionRequest<'_>,
    ) -> Result<ProvisionedFace, ProvisionError> {
        use ndn_face_bluetooth::BleCentralFace;
        use ndn_transport::{FacePersistency, Transport};
        use tokio_util::sync::CancellationToken;

        let rest = req.uri.strip_prefix("ble://").unwrap_or(req.uri);
        let (target, query) = match rest.split_once('?') {
            Some((t, q)) => (t, Some(q)),
            None => (rest, None),
        };
        let framing = query.and_then(parse_ble_framing);
        let adapter = query.and_then(|q| parse_ble_query(q, "adapter"));

        let face_id = req.engine.faces().alloc_id();
        match BleCentralFace::connect(face_id, target, framing, adapter.as_deref()).await {
            Ok(face) => {
                let remote_uri = face
                    .remote_uri()
                    .unwrap_or_else(|| format!("ble://{target}"));
                req.engine.add_face_with_persistency(
                    face,
                    CancellationToken::new(),
                    FacePersistency::Persistent,
                );
                Ok(ProvisionedFace {
                    face_id,
                    remote_uri: remote_uri.clone(),
                    local_uri: Some(remote_uri),
                    persistency: FacePersistency::Persistent,
                })
            }
            Err(e) => Err(ProvisionError::Server(format!("BLE central failed: {e}"))),
        }
    }
}

/// Parse `framing=ndnts|ndnlpv2` out of a `ble://` URI query string.
#[cfg(feature = "bluetooth")]
fn parse_ble_framing(query: &str) -> Option<ndn_face_bluetooth::BleFraming> {
    let v = parse_ble_query(query, "framing")?;
    match v.to_ascii_lowercase().as_str() {
        "ndnts" => Some(ndn_face_bluetooth::BleFraming::Ndnts),
        "ndnlpv2" => Some(ndn_face_bluetooth::BleFraming::Ndnlpv2),
        _ => None,
    }
}

/// Extract `key=value` from a `&`-separated query string.
#[cfg(feature = "bluetooth")]
fn parse_ble_query(query: &str, key: &str) -> Option<String> {
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
        .map(str::to_owned)
}

/// Add `face`, a face provisioned *for* the requester of `req`, with no more
/// trust than the requester has: a shared-memory face is a program face by
/// its transport, but a validated requester (a TCP or other-user socket
/// client) must not be able to ask for one and so have its Data believed. An
/// internally generated command has no requester face and adds the face as it
/// is.
#[cfg(feature = "spsc-shm")]
fn add_for_requester<F: ndn_transport::Transport + 'static>(
    req: &ProvisionRequest<'_>,
    face: F,
    cancel: tokio_util::sync::CancellationToken,
) {
    match req.source_face {
        Some(from) => {
            req.engine.add_face_inheriting(
                face,
                cancel,
                ndn_transport::FacePersistency::OnDemand,
                from,
            );
        }
        None => req.engine.add_face(face, cancel),
    }
}

/// `shm://<name>` — a zero-copy shared-memory ring face (the app<->engine IPC
/// seam). SHM moved to the `ndn-face-shm` extension crate, so the forwarder
/// dials it through a provisioner rather than ndn-mgmt constructing it.
#[cfg(feature = "spsc-shm")]
struct ShmProvisioner;

#[cfg(feature = "spsc-shm")]
#[async_trait::async_trait]
impl FaceProvisioner for ShmProvisioner {
    fn handles(&self, uri: &str) -> bool {
        uri.starts_with("shm://")
    }

    async fn provision(
        &self,
        req: ProvisionRequest<'_>,
    ) -> Result<ProvisionedFace, ProvisionError> {
        use ndn_transport::FacePersistency;

        let shm_name = req.uri.strip_prefix("shm://").unwrap_or(req.uri);
        let face_id = req.engine.faces().alloc_id();
        // Scope the SHM face's lifetime to the requesting (client) face when
        // known, so it tears down with the client.
        let cancel = req
            .source_face
            .and_then(|sf| req.engine.face_token(sf))
            .map(|t| t.child_token())
            .unwrap_or_default();

        // Capability-scoped (Option-A) path: the client supplied a one-time
        // token in the (signed) face-create command. Create an ANONYMOUS region
        // (no named SHM object / FIFOs) and hand its fds over a token-derived,
        // unguessable control socket — nothing crosses the wire but the token.
        if let Some(tok) = req.params.shm_control_token.as_ref() {
            if tok.len() != 32 {
                return Err(ProvisionError::Server(
                    "shm control token must be 32 bytes".into(),
                ));
            }
            let mut token = [0u8; 32];
            token.copy_from_slice(tok);

            let (face, fds) = match req.params.mtu {
                Some(m) => ndn_face_shm::ShmFace::create_anon_for_mtu(face_id, m as usize),
                None => ndn_face_shm::ShmFace::create_anon(face_id),
            }
            .map_err(|e| ProvisionError::Server(format!("SHM creation failed: {e}")))?;

            let path = ndn_face_shm::control_socket_path(&token);
            let _ = std::fs::remove_file(&path);
            let listener = tokio::net::UnixListener::bind(&path)
                .map_err(|e| ProvisionError::Server(format!("shm control bind: {e}")))?;

            // Serve the fd handoff to the first authorized client, then exit;
            // tied to the face's cancel so it can't leak the listener/socket.
            let serve_cancel = cancel.clone();
            let cleanup_path = path.clone();
            tokio::spawn(async move {
                tokio::select! {
                    r = ndn_face_shm::serve_fd_handoff(listener, token, fds) => {
                        if let Err(e) = r {
                            tracing::warn!(target: "shm", "fd handoff failed: {e}");
                        }
                    }
                    _ = serve_cancel.cancelled() => {}
                }
                let _ = std::fs::remove_file(&cleanup_path);
            });

            add_for_requester(&req, face, cancel);
            return Ok(ProvisionedFace {
                face_id,
                remote_uri: format!("shm://{shm_name}"),
                local_uri: None,
                persistency: FacePersistency::OnDemand,
            });
        }

        // Legacy named-region path (client sent no token).
        let face_result = match req.params.mtu {
            Some(m) => ndn_face_shm::spsc::SpscFace::create_for_mtu(face_id, shm_name, m as usize),
            None => ndn_face_shm::ShmFace::create(face_id, shm_name),
        };
        match face_result {
            Ok(face) => {
                add_for_requester(&req, face, cancel);
                Ok(ProvisionedFace {
                    face_id,
                    remote_uri: format!("shm://{shm_name}"),
                    local_uri: None,
                    persistency: FacePersistency::OnDemand,
                })
            }
            Err(e) => Err(ProvisionError::Server(format!("SHM creation failed: {e}"))),
        }
    }
}

/// `quic://…` — refused with what to do instead: a QUIC link is identified
/// by the other device's key, admitted from the trust data on both sides,
/// and kept up across restarts, so it is configured as a `[[peer]]`, not
/// created by address.
#[cfg(feature = "quic")]
struct QuicProvisioner;

#[cfg(feature = "quic")]
#[async_trait::async_trait]
impl FaceProvisioner for QuicProvisioner {
    fn handles(&self, uri: &str) -> bool {
        uri.starts_with("quic://")
    }

    async fn provision(
        &self,
        req: ProvisionRequest<'_>,
    ) -> Result<ProvisionedFace, ProvisionError> {
        let endpoint = req.uri.strip_prefix("quic://").unwrap_or(req.uri);
        Err(ProvisionError::BadParams(format!(
            "a QUIC link names the device it links to, not only an address: add \
             [[peer]] device = \"/<namespace>/<role>/<device>\" (or key = \"<its fingerprint>\") \
             with endpoint = \"{endpoint}\" to this daemon's config and restart it"
        )))
    }
}

/// `wts://host:port[?cert=<sha256hex>]` — `?cert=` pins a self-signed peer's
/// leaf; absence falls back to WebPKI.
#[cfg(feature = "webtransport")]
struct WebTransportProvisioner;

#[cfg(feature = "webtransport")]
#[async_trait::async_trait]
impl FaceProvisioner for WebTransportProvisioner {
    fn handles(&self, uri: &str) -> bool {
        uri.starts_with("wts://")
    }

    async fn provision(
        &self,
        req: ProvisionRequest<'_>,
    ) -> Result<ProvisionedFace, ProvisionError> {
        use ndn_face_webtransport::WebTransportFace;
        use ndn_transport::{ClientTls, FacePersistency, Transport};
        use tokio_util::sync::CancellationToken;

        let rest = req.uri.strip_prefix("wts://").unwrap_or(req.uri);
        let (authority, query) = match rest.split_once('?') {
            Some((a, q)) => (a, Some(q)),
            None => (rest, None),
        };
        let cert_hex = query.and_then(|q| {
            q.split('&')
                .find_map(|kv| kv.strip_prefix("cert="))
                .map(str::to_owned)
        });
        let tls = match cert_hex {
            Some(hex) => match ndn_config::parse_cert_sha256_hex(&hex) {
                Some(h) => ClientTls::CertHashes(vec![h]),
                None => {
                    return Err(ProvisionError::BadParams(format!(
                        "invalid cert hash (need 64 hex chars): {hex}"
                    )));
                }
            },
            None => ClientTls::WebPki,
        };

        let face_id = req.engine.faces().alloc_id();
        let url = format!("https://{authority}");
        match WebTransportFace::connect(face_id, &url, tls).await {
            Ok(face) => {
                let local_uri = face.local_uri();
                req.engine.add_face_with_persistency(
                    face,
                    CancellationToken::new(),
                    FacePersistency::Persistent,
                );
                Ok(ProvisionedFace {
                    face_id,
                    remote_uri: format!("wts://{authority}"),
                    local_uri,
                    persistency: FacePersistency::Persistent,
                })
            }
            Err(e) => Err(ProvisionError::Server(format!(
                "WebTransport face creation failed: {e}"
            ))),
        }
    }
}

#[cfg(all(test, feature = "spsc-shm"))]
mod tests {
    use super::*;
    use ndn_engine::{EngineBuilder, EngineConfig};
    use ndn_face::local::InProcFace;
    use ndn_transport::{FaceId, FaceTrust};

    const PROGRAM_REQUESTER: u64 = 1;
    const TCP_REQUESTER: u64 = 2;

    /// Provision a capability `shm://` face for the command arriving on
    /// `source`, and return the trust of the face the forwarder created.
    async fn trust_of_shm_face_for(
        engine: &ndn_engine::ForwarderEngine,
        source: Option<FaceId>,
    ) -> FaceTrust {
        let token = ndn_face_shm::mint_token().expect("mint token");
        let params = ndn_mgmt_wire::ControlParameters {
            shm_control_token: Some(bytes::Bytes::copy_from_slice(&token)),
            ..Default::default()
        };
        let provisioned = ShmProvisioner
            .provision(ProvisionRequest {
                uri: "shm://trust-test",
                params: &params,
                source_face: source,
                engine,
            })
            .await
            .unwrap_or_else(|_| panic!("the shm face is provisioned"));
        let trust = engine
            .faces()
            .get(provisioned.face_id)
            .expect("the provisioned face is in the face table")
            .trust();
        engine.remove_face(provisioned.face_id);
        let _ = std::fs::remove_file(ndn_face_shm::control_socket_path(&token));
        trust
    }

    /// A shared-memory face is a program face by its transport, but one the
    /// forwarder opens for a validated requester (a loopback TCP client) must
    /// not be: that client would otherwise launder forged Data through it.
    /// A face for a program requester, or for an internal command, stays a
    /// program face.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_shm_face_has_no_more_trust_than_its_requester() {
        let (program_face, _program_handle) = InProcFace::new(FaceId(PROGRAM_REQUESTER), 16);
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .face(program_face)
            .build()
            .await
            .expect("engine build");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) =
            tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
        let (stream, _) = accepted.unwrap();
        let _tcp_peer = client.unwrap();
        engine.add_face(
            ndn_face::tcp_face_from_stream(FaceId(TCP_REQUESTER), stream),
            tokio_util::sync::CancellationToken::new(),
        );

        assert_eq!(
            trust_of_shm_face_for(&engine, Some(FaceId(TCP_REQUESTER))).await,
            FaceTrust::Validated,
            "a shm face opened for a loopback TCP client is a program face"
        );
        assert_eq!(
            trust_of_shm_face_for(&engine, Some(FaceId(PROGRAM_REQUESTER))).await,
            FaceTrust::Program,
            "a shm face opened for a program requester lost its trust"
        );
        assert_eq!(
            trust_of_shm_face_for(&engine, None).await,
            FaceTrust::Program,
            "a shm face opened by an internal command lost its trust"
        );
        shutdown.shutdown().await;
    }
}
