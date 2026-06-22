//! Extension-transport face provisioners for `faces/create`.
//!
//! `ndn-mgmt` is face-agnostic for the extension transports: it builds the
//! standard ones (UDP/TCP/Ethernet/BLE/SHM) itself but delegates raw QUIC
//! (`quic://`) and WebTransport (`wts://`) to provisioners the forwarder
//! registers via [`MgmtHandles::face_provisioners`](ndn_mgmt::MgmtHandles).
//! Each is gated by the same feature that links its face crate, so a build
//! without `quic`/`webtransport` registers nothing for those schemes.

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

            req.engine.add_face(face, cancel);
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
                req.engine.add_face(face, cancel);
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

/// `quic://host:port?cert=<sha256hex>` (pin) or `quic://host:port?webpki`.
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
        use ndn_face_quic::QuicConnector;
        use ndn_transport::{ClientTls, FacePersistency, Transport};
        use tokio_util::sync::CancellationToken;

        let rest = req.uri.strip_prefix("quic://").unwrap_or(req.uri);
        let (authority, query) = match rest.split_once('?') {
            Some((a, q)) => (a, Some(q)),
            None => (rest, None),
        };
        let params: Vec<&str> = query.map(|q| q.split('&').collect()).unwrap_or_default();
        let cert_hex = params.iter().find_map(|kv| kv.strip_prefix("cert="));
        let webpki = params.iter().any(|kv| *kv == "webpki" || *kv == "webpki=true");

        let tls = if let Some(hex) = cert_hex {
            match ndn_config::parse_cert_sha256_hex(hex) {
                Some(h) => ClientTls::CertHashes(vec![h]),
                None => {
                    return Err(ProvisionError::BadParams(format!(
                        "invalid cert hash (need 64 hex chars): {hex}"
                    )));
                }
            }
        } else if webpki {
            ClientTls::WebPki
        } else {
            return Err(ProvisionError::BadParams(
                "quic:// requires ?cert=<64 hex chars> (pin) or ?webpki".into(),
            ));
        };

        let connector = QuicConnector::new(tls)
            .map_err(|e| ProvisionError::Server(format!("QUIC connector: {e}")))?;
        let face_id = req.engine.faces().alloc_id();
        // The connector (endpoint) may drop after connect; the face's streams
        // keep the connection and its I/O driver alive.
        match connector.connect_authority(face_id, authority).await {
            Ok(face) => {
                let local_uri = face.local_uri();
                req.engine.add_face_with_persistency(
                    face,
                    CancellationToken::new(),
                    FacePersistency::Persistent,
                );
                Ok(ProvisionedFace {
                    face_id,
                    remote_uri: format!("quic://{authority}"),
                    local_uri,
                    persistency: FacePersistency::Persistent,
                })
            }
            Err(e) => Err(ProvisionError::Server(format!(
                "QUIC face creation failed: {e}"
            ))),
        }
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
