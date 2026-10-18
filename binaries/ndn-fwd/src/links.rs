//! QUIC links: this device's links to the devices `[[peer]]` names, and the
//! links other devices open to it (`[[face]] kind = "quic"`).
//!
//! Admission, enrollment links, routes, redial and the one-link-per-pair
//! rule are `ndn_link`'s; this module gives it the daemon's parts: the
//! `[[peer]]` entries, the link socket, the keyring and served
//! certificates, the engine's faces and RIB, and the key switches of
//! `ActiveIdentity`.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use bytes::Bytes;
use ndn_config::control_parameters::{origin, route_flags};
use ndn_config::{FaceConfig, ForwarderConfig, PeerConfig};
use ndn_engine::ForwarderEngine;
use ndn_engine::rib::RibRoute;
use ndn_face_quic::{KeyFingerprint, LinkEndpoint, LinkKeySource, LinkTransportConfig};
use ndn_link::{ConfiguredEndpoints, FaceSink, LinkHints, LinkSetup, LinkTrust, Links, PeerId, PeerSpec, Route};
use ndn_packet::Name;
use ndn_security::{ActiveSigner, Certificate, Keyring};
use ndn_transport::{Face, FaceId, FacePersistency};
use tokio_util::sync::CancellationToken;

use crate::active_identity::ActiveIdentity;
use crate::own_certs::OwnCertificates;

/// A `[[peer]]`, as `ndn_link` takes it.
fn peer_spec(config: &PeerConfig, all: &[PeerConfig]) -> anyhow::Result<PeerSpec> {
    let parse_name = |s: &str| {
        s.parse::<Name>()
            .map_err(|e| anyhow::anyhow!("[[peer]] {}: {s:?} is not a name: {e}", config.label()))
    };
    Ok(PeerSpec {
        label: config.label(),
        key: config
            .key
            .as_deref()
            .map(|k| {
                KeyFingerprint::from_hex(k)
                    .with_context(|| format!("[[peer]] {}: key is not 64 hex digits", config.label()))
            })
            .transpose()?,
        device: config.device.as_deref().map(parse_name).transpose()?,
        endpoints: config.endpoint.clone(),
        relay: config
            .relay
            .as_deref()
            .and_then(|r| all.iter().position(|p| !std::ptr::eq(p, config) && p.is_named(r)))
            .map(PeerId),
        routes: config
            .routes
            .as_ref()
            .map(|routes| routes.iter().map(|r| parse_name(r)).collect())
            .transpose()?,
        persistent: config.persistent,
        reliability: config.reliability,
    })
}

/// The daemon's trust data: the keyring, the certificates it serves, and
/// the engine's validated-certificate cache.
struct DaemonTrust {
    keyring: Arc<Keyring>,
    own_certs: Arc<OwnCertificates>,
    signer: Arc<ActiveSigner>,
    engine: ForwarderEngine,
}

impl LinkTrust for DaemonTrust {
    fn keyring(&self) -> &Arc<Keyring> {
        &self.keyring
    }

    fn own_chain(&self) -> Vec<Bytes> {
        self.own_certs.chain_of(self.signer.current().key_name())
    }

    fn known_certificate(&self, name: &Name) -> Option<Certificate> {
        self.own_certs.certificate(name).or_else(|| {
            self.engine
                .validator()
                .and_then(|v| v.cert_cache().get_valid(name))
        })
    }

    fn known_certificate_of_key(&self, fingerprint: &KeyFingerprint) -> Option<Certificate> {
        self.engine
            .validator()
            .and_then(|v| v.cert_cache().get_by_key_digest(&fingerprint.0))
    }
}

/// The engine: link faces, and their routes as static RIB routes.
struct EngineFaces(ForwarderEngine);

impl FaceSink for EngineFaces {
    fn alloc_face_id(&self) -> FaceId {
        self.0.faces().alloc_id()
    }

    fn add_face(&self, face: Face, cancel: CancellationToken) {
        self.0.add_composed_face(face, cancel, FacePersistency::Persistent);
    }

    fn remove_face(&self, face: FaceId) {
        self.0.remove_face(face);
    }

    fn add_routes(&self, face: FaceId, routes: &[Route]) {
        let rib = self.0.rib();
        let fib = self.0.fib();
        for route in routes {
            rib.add(
                &route.prefix,
                RibRoute {
                    face_id: face,
                    origin: origin::STATIC,
                    cost: route.cost,
                    flags: route_flags::CHILD_INHERIT,
                    expires_at: None,
                },
            );
            rib.apply_to_fib(&route.prefix, &fib);
        }
    }
}

fn hints() -> LinkHints {
    LinkHints {
        enroll: "`ndn-fwd enroll <invite link>`, or by an admin's approval".into(),
        renew: "`ndn-fwd renew`".into(),
        refresh: "`ndn-fwd context refresh`".into(),
        peer_entry: "[[peer]]".into(),
        expect_key: "add [[peer]] key = \"{key}\" to the other device's config".into(),
    }
}

/// Start this device's links: listen when `[[face]] kind = "quic"` is
/// configured (and not `listen = false`), dial each `[[peer]]` with an
/// endpoint. `None` when the config has neither.
pub(crate) fn spawn(
    engine: &ForwarderEngine,
    keyring: Arc<Keyring>,
    identity: Option<&Arc<ActiveIdentity>>,
    own_certs: Arc<OwnCertificates>,
    config: &ForwarderConfig,
    cancel: CancellationToken,
) -> anyhow::Result<Option<Arc<Links>>> {
    let socket = config.faces.iter().find_map(|f| match f {
        FaceConfig::Quic { bind, listen } => Some((bind.clone(), *listen)),
        _ => None,
    });
    if socket.is_none() && config.peers.is_empty() {
        return Ok(None);
    }
    let identity = identity.context(
        "QUIC links need this device's key, and the daemon runs without one ([security] \
         profile = \"disabled\"); enable security or remove [[peer]] and [[face]] kind = \"quic\"",
    )?;
    let signer = Arc::clone(identity.signer());
    let key = LinkKeySource::current(signer.as_ref()).map_err(|e| anyhow::anyhow!("QUIC links: {e}"))?;
    tracing::info!(
        target: "face.quic",
        fingerprint = %key.fingerprint(),
        key = %key.key_name(),
        "this device's link key (other devices name it in [[peer]] key = \"…\")"
    );
    let peers = config
        .peers
        .iter()
        .map(|p| peer_spec(p, &config.peers))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let transport = LinkTransportConfig::default();
    let socket = socket
        .map(|(bind, listen)| {
            let addr: SocketAddr = bind
                .parse()
                .with_context(|| format!("[[face]] kind = \"quic\": bind {bind:?}"))?;
            LinkEndpoint::bind(addr, Arc::clone(&signer) as Arc<dyn LinkKeySource>, &transport, listen)
                .map(Arc::new)
                .with_context(|| format!("cannot bind the QUIC link socket to {addr}"))
        })
        .transpose()?;
    if let Some(socket) = &socket {
        let addr = socket.local_addr().map(|a| a.to_string()).unwrap_or_default();
        if socket.is_listening() {
            tracing::info!(target: "face.quic", %addr, "listening for QUIC links");
        } else {
            tracing::info!(target: "face.quic", %addr, "dialling QUIC links from this address (listen = false)");
        }
    }
    let links = Links::start(
        LinkSetup {
            peers,
            key: Arc::clone(&signer) as Arc<dyn LinkKeySource>,
            trust: Arc::new(DaemonTrust {
                keyring,
                own_certs,
                signer,
                engine: engine.clone(),
            }),
            faces: Arc::new(EngineFaces(engine.clone())),
            paths: Arc::new(ConfiguredEndpoints),
            socket,
            transport,
            hints: hints(),
        },
        cancel.clone(),
    );
    tokio::spawn(relink_on_switch(Arc::downgrade(&links), identity.switches(), cancel));
    Ok(Some(links))
}

/// Each time this device switches to another key (it enrolled), make its
/// enrollment links for that key's namespace again as full links.
async fn relink_on_switch(
    links: std::sync::Weak<Links>,
    mut switches: tokio::sync::watch::Receiver<u64>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            changed = switches.changed() => if changed.is_err() { return },
        }
        let Some(links) = links.upgrade() else { return };
        links.key_switched();
    }
}
