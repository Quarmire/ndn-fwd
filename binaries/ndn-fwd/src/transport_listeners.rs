//! WebRTC / WebTransport / WebSocket listener tasks for ndn-fwd.

#![allow(dead_code, unused_imports)]

use std::sync::Arc;

use ndn_engine::ForwarderEngine;
use tokio_util::sync::CancellationToken;

/// Live TLS cert status of each running WebTransport listener, populated at
/// listener start. Process-global because listeners are process-global and the
/// `webtransport` mgmt module reads it without per-listener plumbing.
#[cfg(feature = "webtransport")]
pub static WT_CERT_STATUS: std::sync::LazyLock<std::sync::RwLock<Vec<ndn_mgmt::WtCertStatusInfo>>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(Vec::new()));

/// `WtCertStatusBackend` for the `/localhost/nfd/webtransport/cert-status`
/// dataset; reads the process-global [`WT_CERT_STATUS`].
#[cfg(feature = "webtransport")]
pub struct WtCertStatusReader;

#[cfg(feature = "webtransport")]
impl ndn_mgmt::WtCertStatusBackend for WtCertStatusReader {
    fn cert_status(&self) -> Vec<ndn_mgmt::WtCertStatusInfo> {
        WT_CERT_STATUS.read().map(|g| g.clone()).unwrap_or_default()
    }
}

/// Resolve a config `CertSourceConfig` (self-signed / PEM / ACME) to PEM cert
/// material — the one path shared by the WebTransport and raw-QUIC listeners.
/// `profile` only changes the self-signed validity window
/// ([`ndn_acme::SelfSignedProfile`]): browser-pinnable for WebTransport,
/// long-lived for a pinned QUIC backbone.
#[cfg(any(feature = "webtransport", feature = "quic"))]
async fn resolve_cert_source(
    cert_source: &ndn_config::CertSourceConfig,
    profile: ndn_acme::SelfSignedProfile,
) -> Result<ndn_acme::CertMaterial, String> {
    // `ndn-config` keeps its own mirror of the enum (to stay wasm-clean and
    // ACME-stack-free); round-trip it into `ndn_acme::CertSource` via JSON.
    let cert_source: ndn_acme::CertSource = serde_json::to_string(cert_source)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .ok_or_else(|| "cert_source could not be parsed".to_string())?;
    // Only ACME paths consult the DNS provider; Cloudflare is the only one wired.
    let dns_provider: Option<std::sync::Arc<dyn ndn_acme::DnsProvider>> =
        Some(std::sync::Arc::new(ndn_acme::CloudflareDnsProvider::new()));
    cert_source
        .resolve(dns_provider, profile)
        .await
        .map_err(|e| e.to_string())
}

#[cfg(any(feature = "webtransport", feature = "quic"))]
fn hex32(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// For each configured session-id spawn a loop that calls
/// `WebRtcListener::accept_one`, registers the resulting face, then
/// re-accepts. One peer per session-id at a time.
#[cfg(feature = "webrtc")]
pub async fn run_webrtc_listener(
    cfg: ndn_config::WebRtcListenerConfig,
    engine: ForwarderEngine,
    cancel: CancellationToken,
) {
    use ndn_face_webrtc::IceServers;
    use ndn_rtc_signaling_relay::WebRtcListener;
    use std::time::Duration;

    let servers: IceServers = cfg
        .ice_servers
        .as_ref()
        .and_then(|v| serde_json::to_string(v).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    tracing::info!(
        target: "face.webrtc",
        signaling = %cfg.signaling_url,
        sessions = ?cfg.session_ids,
        "WebRTC listener starting"
    );

    for session_id in cfg.session_ids {
        let listener = WebRtcListener::new(cfg.signaling_url.clone(), servers.clone());
        let eng = engine.clone();
        let c = cancel.clone();
        tokio::spawn(async move {
            loop {
                if c.is_cancelled() {
                    return;
                }
                let accept = tokio::select! {
                    biased;
                    _ = c.cancelled() => return,
                    r = listener.accept_one(&session_id, Duration::from_secs(60)) => r,
                };
                match accept {
                    Ok(mut face) => {
                        let face_id = eng.faces().alloc_id();
                        face.set_id(face_id);
                        tracing::info!(
                            target: "face.webrtc",
                            session = %session_id,
                            face = face_id.0,
                            "accepted WebRTC peer"
                        );
                        eng.add_face(face, c.clone());
                        // Let the just-registered face start before the
                        // next accept_one opens a fresh rendezvous slot.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    Err(e) => {
                        tracing::warn!(
                            target: "face.webrtc",
                            session = %session_id,
                            error = %e,
                            "WebRTC accept failed; retrying after 5s"
                        );
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        });
    }
}

#[cfg(feature = "webtransport")]
pub async fn run_wt_listener(
    cfg: ndn_config::WebTransportListenerConfig,
    engine: ForwarderEngine,
    cancel: CancellationToken,
) {
    use ndn_face_webtransport::{WebTransportListener, WtTlsConfig};

    let bind_addr: std::net::SocketAddr = match cfg.listen.parse() {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(target: "face.wt", listen=%cfg.listen, error=%e, "wt-listener: invalid bind address");
            return;
        }
    };

    // Browser-pinnable: self-signed certs stay under Chrome's 14-day
    // `serverCertificateHashes` limit.
    let material = match resolve_cert_source(
        &cfg.cert_source,
        ndn_acme::SelfSignedProfile::BrowserPinnable,
    )
    .await
    {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(target: "face.wt", error=%e, "wt-listener: cert resolve failed");
            return;
        }
    };

    // Read-only cert-status surface: notAfter / days-remaining / renewal state.
    // Logged and published to the `webtransport/cert-status` mgmt dataset.
    if let Some(status) = ndn_acme::cert_status(&material.cert_chain_pem) {
        tracing::info!(
            target: "face.wt",
            not_after_unix = status.not_after_unix,
            days_remaining = status.days_remaining,
            needs_renewal = status.needs_renewal,
            "WebTransport TLS cert status"
        );
        if let Ok(mut g) = WT_CERT_STATUS.write() {
            g.push(ndn_mgmt::WtCertStatusInfo {
                listen: cfg.listen.clone(),
                not_after_unix: status.not_after_unix,
                days_remaining: status.days_remaining,
                needs_renewal: status.needs_renewal,
            });
        }
    }

    let cert_sha256_hex: Option<String> = material.leaf_sha256().as_ref().map(hex32);
    if let Some(ref hex) = cert_sha256_hex {
        tracing::info!(
            target: "face.wt",
            cert_sha256 = %hex,
            "WebTransport leaf cert SHA-256 (pass to browser as ?cert=<hex> or via --ignore-certificate-errors-spki-list)"
        );
    }

    let tls = WtTlsConfig::Pem {
        cert_chain_pem: material.cert_chain_pem,
        private_key_pem: material.private_key_pem,
    };

    let listener = match WebTransportListener::bind(bind_addr, tls).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(target: "face.wt", addr=%bind_addr, error=%e, "wt-listener: bind failed");
            return;
        }
    };
    tracing::info!(target: "face.wt", addr=%listener.local_addr(), "WebTransport listener ready");

    // Log a copy-paste connect URL with the SPKI hash spliced in. Chrome
    // requires `?cert=<spki-hash>` for self-signed WT certs (W3C
    // WebTransport §`serverCertificateHashes`).
    if let Some(ref hex) = cert_sha256_hex {
        let port = listener.local_addr().port();
        let host = match listener.local_addr().ip() {
            std::net::IpAddr::V4(v4) if v4.is_unspecified() => "127.0.0.1".to_string(),
            std::net::IpAddr::V6(v6) if v6.is_unspecified() => "127.0.0.1".to_string(),
            other => other.to_string(),
        };
        tracing::info!(
            target: "face.wt",
            url = %format!("https://{host}:{port}/ndn?cert={hex}"),
            "wt-listener: open this URL in the browser (cert hash baked in)"
        );
    }

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            r = async {
                let id = engine.faces().alloc_id();
                listener.accept(id).await.map(|f| (id, f))
            } => match r {
                Ok((id, face)) => {
                    let peer = face.remote_addr().to_string();
                    let conn_cancel = cancel.child_token();
                    engine.add_face(face, conn_cancel);
                    tracing::info!(target: "face.wt", face=%id, peer=%peer, "wt-listener: accepted session");
                }
                Err(e) => tracing::warn!(target: "face.wt", error=%e, "wt-listener: accept error"),
            },
        }
    }

    tracing::info!(target: "face.wt", "WebTransport listener stopped");
}

/// Raw-QUIC backbone listener: binds a QUIC endpoint and registers one face per
/// accepted connection. The cert comes from the shared [`resolve_cert_source`]
/// path (self-signed / PEM / ACME), so a QUIC backbone provisions exactly like
/// a WebTransport listener. Logs the leaf cert SHA-256 so operators can pin it
/// on dialers (`quic://host:port?cert=<hex>` / `[[face]] cert_sha256`).
#[cfg(feature = "quic")]
pub async fn run_quic_listener(
    cfg: ndn_config::QuicListenerConfig,
    engine: ForwarderEngine,
    cancel: CancellationToken,
) {
    use ndn_face_quic::{QuicListener, QuicServerTls};

    let bind_addr: std::net::SocketAddr = match cfg.listen.parse() {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(target: "face.quic", listen=%cfg.listen, error=%e, "quic-listener: invalid listen address");
            return;
        }
    };

    // Backbone: a pinned dialer trusts the leaf hash, not the expiry, so a
    // self-signed source gets a long-lived cert (no restart-time pin churn).
    let material = match resolve_cert_source(
        &cfg.cert_source,
        ndn_acme::SelfSignedProfile::Backbone,
    )
    .await
    {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(target: "face.quic", error=%e, "quic-listener: cert resolve failed");
            return;
        }
    };
    if let Some(hex) = material.leaf_sha256().as_ref().map(hex32) {
        tracing::info!(target: "face.quic", addr=%bind_addr, cert_sha256=%hex, "QUIC listener ready (pin this hash on dialers)");
    }
    let tls = QuicServerTls::Pem {
        cert_chain_pem: material.cert_chain_pem,
        private_key_pem: material.private_key_pem,
    };
    let listener = match QuicListener::bind(bind_addr, tls).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(target: "face.quic", addr=%bind_addr, error=%e, "quic-listener: bind failed");
            return;
        }
    };

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            r = async {
                let id = engine.faces().alloc_id();
                listener.accept(id).await.map(|f| (id, f))
            } => match r {
                Ok((id, face)) => {
                    let peer = ndn_transport::Transport::remote_uri(&face).unwrap_or_default();
                    engine.add_face(face, cancel.child_token());
                    tracing::info!(target: "face.quic", face=%id, peer=%peer, "quic-listener: accepted connection");
                }
                Err(e) => tracing::warn!(target: "face.quic", error=%e, "quic-listener: accept error"),
            },
        }
    }
    tracing::info!(target: "face.quic", "QUIC listener stopped");
}

/// BLE peripheral listener: binds the GATT server via [`ndn_face::l2::BleListener`]
/// and registers one face per connecting central.
#[cfg(all(feature = "bluetooth", any(target_os = "linux", target_os = "macos")))]
pub async fn run_ble_listener(
    engine: ForwarderEngine,
    cancel: CancellationToken,
    adapter: Option<String>,
    local_name: Option<String>,
) {
    use ndn_face::l2::BleListener;

    let mut listener = match BleListener::bind(adapter.as_deref(), local_name.as_deref()).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(target: "face.ble", error = %e, "ble-listener: bind failed");
            return;
        }
    };
    tracing::info!(target: "face.ble", "ble-listener: advertising; awaiting centrals");
    loop {
        let id = engine.faces().alloc_id();
        let accept = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            r = listener.accept(id) => r,
        };
        match accept {
            Ok(face) => {
                let conn_cancel = cancel.child_token();
                engine.add_face(face, conn_cancel);
                tracing::info!(target: "face.ble", face = id.0, "ble-listener: central connected");
            }
            Err(e) => {
                tracing::error!(target: "face.ble", error = %e, "ble-listener: stopped");
                break;
            }
        }
    }
    tracing::info!(target: "face.ble", "BLE listener stopped");
}

/// `BleMgmtBackend` for `/localhost/nfd/ble/{list,start,stop}`. Sole owner of
/// the peripheral listener lifecycle (the backends allow only one GATT server
/// per process), so config-auto-start and mgmt start/stop share one token.
#[cfg(all(feature = "bluetooth", any(target_os = "linux", target_os = "macos")))]
pub struct BleControl {
    engine: ForwarderEngine,
    parent_cancel: CancellationToken,
    adapter: Option<String>,
    local_name: Option<String>,
    running: tokio::sync::Mutex<Option<CancellationToken>>,
}

#[cfg(all(feature = "bluetooth", any(target_os = "linux", target_os = "macos")))]
impl BleControl {
    pub fn new(
        engine: ForwarderEngine,
        parent_cancel: CancellationToken,
        adapter: Option<String>,
        local_name: Option<String>,
    ) -> Self {
        Self {
            engine,
            parent_cancel,
            adapter,
            local_name,
            running: tokio::sync::Mutex::new(None),
        }
    }

    async fn do_start(&self) {
        let mut g = self.running.lock().await;
        if g.as_ref().is_some_and(|c| !c.is_cancelled()) {
            return; // already advertising
        }
        let token = self.parent_cancel.child_token();
        let eng = self.engine.clone();
        let c = token.clone();
        let adapter = self.adapter.clone();
        let local_name = self.local_name.clone();
        tokio::spawn(async move { run_ble_listener(eng, c, adapter, local_name).await });
        *g = Some(token);
    }
}

#[cfg(all(feature = "bluetooth", any(target_os = "linux", target_os = "macos")))]
#[async_trait::async_trait]
impl ndn_mgmt::BleMgmtBackend for BleControl {
    async fn status(&self) -> ndn_mgmt::BleStatus {
        let advertising = self
            .running
            .lock()
            .await
            .as_ref()
            .is_some_and(|c| !c.is_cancelled());
        let connected_centrals = self
            .engine
            .faces()
            .face_info()
            .into_iter()
            .filter(|f| f.kind == ndn_transport::FaceKind::Bluetooth)
            .count() as u64;
        ndn_mgmt::BleStatus {
            supported: true,
            advertising,
            adapter: None,
            connected_centrals,
        }
    }

    async fn start(&self) -> Result<(), String> {
        self.do_start().await;
        Ok(())
    }

    async fn stop(&self) -> Result<(), String> {
        if let Some(c) = self.running.lock().await.take() {
            c.cancel();
        }
        Ok(())
    }
}

#[cfg(feature = "websocket")]
pub async fn run_ws_listener(
    bind_addr: std::net::SocketAddr,
    engine: ForwarderEngine,
    cancel: CancellationToken,
) {
    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(target: "face.ws", addr=%bind_addr, error=%e, "ws-listener: bind failed");
            return;
        }
    };

    let local = listener.local_addr().unwrap_or(bind_addr);
    tracing::info!(target: "face.ws", addr=%local, "WebSocket listener ready");

    loop {
        let (stream, peer) = tokio::select! {
            _ = cancel.cancelled() => break,
            r = listener.accept() => match r {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(target: "face.ws", error=%e, "ws-listener: accept error");
                    continue;
                }
            },
        };

        let ws = match tokio_tungstenite::accept_async(tokio_tungstenite::MaybeTlsStream::Plain(
            stream,
        ))
        .await
        {
            Ok(ws) => ws,
            Err(e) => {
                tracing::warn!(target: "face.ws", peer=%peer, error=%e, "ws-listener: handshake failed");
                continue;
            }
        };

        let face_id = engine.faces().alloc_id();
        let face = ndn_face::net::WebSocketFace::from_stream(
            face_id,
            ws,
            peer.to_string(),
            local.to_string(),
        );
        let conn_cancel = cancel.child_token();
        engine.add_face(face, conn_cancel);
        tracing::info!(target: "face.ws", face=%face_id, peer=%peer, "ws-listener: accepted connection");
    }

    tracing::info!(target: "face.ws", "WebSocket listener stopped");
}
