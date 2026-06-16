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
#[cfg(any(feature = "quic", feature = "webtransport", feature = "spsc-shm"))]
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
    v
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
        let face_result = match req.params.mtu {
            Some(m) => ndn_face_shm::spsc::SpscFace::create_for_mtu(face_id, shm_name, m as usize),
            None => ndn_face_shm::ShmFace::create(face_id, shm_name),
        };
        match face_result {
            Ok(face) => {
                // Scope the SHM face's lifetime to the requesting (client) face
                // when known, so it tears down with the client.
                let cancel = req
                    .source_face
                    .and_then(|sf| req.engine.face_token(sf))
                    .map(|t| t.child_token())
                    .unwrap_or_default();
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
