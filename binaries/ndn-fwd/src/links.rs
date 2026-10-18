//! QUIC links: this device's links to the devices `[[peer]]` names, and the
//! links other devices open to it (`[[face]] kind = "quic"`).
//!
//! A link is identified by the two devices' keys (TLS 1.3 with the NDN keys
//! as raw public keys, `ndn-face-quic`), never by an address. After the
//! handshake each side sends its certificate and issuer chain; a link is
//! admitted from signed data, by either rule:
//!
//! - the certificate validates in a namespace this device holds, its key is
//!   the key the handshake proved, it is not revoked, and the namespace's
//!   link policy (in its trust context) lets the device's role link — and,
//!   when a `[[peer]]` names a `device`, it is that device;
//! - the key is the expected fingerprint of a `[[peer]]` (`key`), for a
//!   device of another namespace or one not enrolled yet.
//!
//! Otherwise the link is closed with a reason the other side logs — unless
//! it can be an **enrollment link**, which carries only a device's
//! enrollment: Interests for the namespace's CA endpoints, its trust context
//! (`<ns>/32=trust-context`) and its certificates, and their answers;
//! nothing else in either direction (`ndn_face_quic::LinkScope`). Two
//! sides make one:
//!
//! - a relay (this device holds a certificate of a role the namespace's
//!   link policy lets relay) admits a device it does not know on an
//!   enrollment link when the namespace's link policy allows them and its
//!   trust context names a CA endpoint; rate-limited, at most
//!   [`ENROLLMENT_LINKS_MAX`] at once ([`ENROLLMENT_LINKS_PER_SOURCE`] from
//!   one address), closed after [`ENROLLMENT_IDLE`] carrying nothing. Its
//!   verdict tells the device;
//! - a device holding no certificate in the namespace of the relay its
//!   `[[peer]]` names, which it therefore cannot confirm yet, links to it
//!   for its enrollment only.
//!
//! Once the device enrolls (its daemon switches to the enrolled key), it
//! closes the enrollment link and dials again, now presenting its
//! certificate: a full link, without anyone doing anything. A link whose
//! certificate a newly adopted version of the trust context revokes is
//! closed at once.
//!
//! Each admitted link is a face (NDNLPv2 over QUIC datagrams) with routes:
//! the `[[peer]]`'s `routes`, else the peer's namespace for a relay (a `node`
//! device this device dials) or the peer's device name, plus the routes of
//! the peers reached through it (`relay`, at a higher cost). Persistent
//! peers are dialled again with backoff whenever their link drops. Between
//! two devices there is one link: when both dial, the link dialled by the
//! device with the smaller key fingerprint stays.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use anyhow::Context as _;
use ndn_cert::approval::MAX_STATUS_HOLD;
use ndn_cert::onboarding::rdr_prefix;
use ndn_cert::roles::{Role, parse_device_key};
use ndn_config::control_parameters::{origin, route_flags};
use ndn_config::{FaceConfig, ForwarderConfig, PeerConfig};
use ndn_engine::ForwarderEngine;
use ndn_engine::rib::RibRoute;
use ndn_face_quic::{
    Admission, Carries, CloseReason, Direction, Handshaken, Incoming, KeyFingerprint, LinkEndpoint,
    LinkError, LinkHandle, LinkHello, LinkKeySource, LinkScope, LinkTransportConfig, LinkVerdict,
    PeerKey, RateLimit,
};
use ndn_packet::{Data, Name};
use ndn_security::{
    ActiveSigner, CertCache, Certificate, Keyring, SignedTrustContext, ValidationResult, Validator,
};
use ndn_transport::reliability::ReliabilityConfig;
use ndn_transport::{Face, FaceId, FacePersistency, LpLinkService};
use tokio_util::sync::CancellationToken;

use crate::active_identity::ActiveIdentity;
use crate::own_certs::OwnCertificates;

/// How long each side has for its hello, and again for its verdict.
const MESSAGE_DEADLINE: Duration = Duration::from_secs(10);
/// Cost of a route to a peer reached through its relay; a direct link to it
/// costs 0, so it wins when it is up.
const VIA_RELAY_COST: u32 = 10;
/// Redial backoff after a drop or a failure that may pass…
const BACKOFF_FIRST: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// …and after a refusal of the key, which only a change of the trust data
/// or the config lifts.
const BACKOFF_REFUSED: Duration = Duration::from_secs(60);
/// Longest certificate chain a link hello is validated through.
const MAX_CHAIN: usize = 8;
/// Enrollment links a relay holds at once…
const ENROLLMENT_LINKS_MAX: usize = 32;
/// …and from one address (several devices may enroll behind one NAT).
const ENROLLMENT_LINKS_PER_SOURCE: usize = 4;
/// An enrollment link that carries nothing this long is closed. Twice the
/// longest a CA holds a STATUS request, so a device waiting for an admin's
/// approval keeps its link.
const ENROLLMENT_IDLE: Duration = Duration::from_secs(2 * MAX_STATUS_HOLD.as_secs());
/// What a relay takes from a device on an enrollment link: Interests,
/// which an enrollment sends a handful of.
const ENROLLMENT_INTERESTS: RateLimit = RateLimit {
    burst: 32,
    per_sec: 4,
};
/// What a device takes from the relay on its enrollment link: answers, one
/// frame per fragment (a trust context or a certificate chain spans
/// several).
const ENROLLMENT_ANSWERS: RateLimit = RateLimit {
    burst: 512,
    per_sec: 128,
};

/// A `[[peer]]`, parsed.
struct Peer {
    label: String,
    key: Option<KeyFingerprint>,
    device: Option<Name>,
    endpoints: Vec<String>,
    /// Index of the `[[peer]]` this one is reached through.
    relay: Option<usize>,
    routes: Option<Vec<Name>>,
    persistent: bool,
    reliability: bool,
    /// Whether another `[[peer]]` is reached through this one.
    is_relay: bool,
}

impl Peer {
    fn from_config(config: &PeerConfig, all: &[PeerConfig]) -> anyhow::Result<Self> {
        let parse_name = |s: &str| {
            s.parse::<Name>()
                .map_err(|e| anyhow::anyhow!("[[peer]] {}: {s:?} is not a name: {e}", config.label()))
        };
        Ok(Self {
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
                .and_then(|r| all.iter().position(|p| !std::ptr::eq(p, config) && p.is_named(r))),
            routes: config
                .routes
                .as_ref()
                .map(|routes| routes.iter().map(|r| parse_name(r)).collect())
                .transpose()?,
            persistent: config.persistent,
            reliability: config.reliability,
            is_relay: all.iter().any(|p| p.relay.as_deref().is_some_and(|r| config.is_named(r))),
        })
    }
}

/// Who the peer is, from its certificate validated in a held namespace.
#[derive(Clone, Debug)]
struct Identity {
    namespace: Name,
    version: u64,
    device: Name,
    role: Role,
    /// The certificate and its issuers, for revocation checks.
    certificates: Vec<Name>,
}

/// What the certificate a peer sent establishes.
enum Identified {
    /// A device of a namespace this device holds.
    Device(Identity),
    /// Nothing this device can use: no certificate, or one this device
    /// cannot validate (the reason). A `[[peer]] key` may still admit it.
    Unknown(String),
}

struct Refusal {
    reason: CloseReason,
    text: String,
}

impl Refusal {
    fn new(reason: CloseReason, text: impl Into<String>) -> Self {
        Self {
            reason,
            text: text.into(),
        }
    }
}

/// Why a link is an enrollment link, on this side.
#[derive(Clone, Debug)]
enum Enrollment {
    /// This relay admitted a device it does not know, for its enrollment in
    /// these namespaces.
    Relay(Vec<Name>),
    /// This device, holding no certificate in the namespace, dialled a relay
    /// of it that it cannot confirm yet.
    Device(Name),
}

struct Admitted {
    fingerprint: KeyFingerprint,
    identity: Option<Identity>,
    peer: Option<usize>,
    enrollment: Option<Enrollment>,
}

impl Admitted {
    fn describe(&self) -> String {
        match &self.identity {
            Some(id) => format!("{} (key {})", id.device, self.fingerprint),
            None => format!("key {}", self.fingerprint),
        }
    }
}

struct LiveLink {
    generation: u64,
    face: FaceId,
    handle: LinkHandle,
    direction: Direction,
    peer: Option<usize>,
    identity: Option<Identity>,
    /// The namespaces this link is an enrollment link for, on either side,
    /// for this device's enrollment: once this device enrolls in one, the
    /// link is made again as a full link.
    enrolling: Vec<Name>,
}

/// Enrollment links this relay holds, in total and by source address.
#[derive(Default)]
struct EnrollmentSlots {
    total: usize,
    by_source: HashMap<IpAddr, usize>,
}

/// One enrollment link's place among [`EnrollmentSlots`], given back when
/// it is dropped (the link ended).
struct EnrollmentSlot {
    links: Weak<Links>,
    source: IpAddr,
}

impl Drop for EnrollmentSlot {
    fn drop(&mut self) {
        let Some(links) = self.links.upgrade() else { return };
        let mut slots = links
            .enrollment_slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        slots.total = slots.total.saturating_sub(1);
        if let Some(n) = slots.by_source.get_mut(&self.source) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                slots.by_source.remove(&self.source);
            }
        }
    }
}

/// This device's QUIC links.
pub(crate) struct Links {
    engine: ForwarderEngine,
    keyring: Arc<Keyring>,
    own_certs: Arc<OwnCertificates>,
    signer: Arc<ActiveSigner>,
    peers: Vec<Peer>,
    transport: LinkTransportConfig,
    /// The configured link socket (`[[face]] kind = "quic"`), listening or
    /// dial-only.
    socket: Option<Arc<LinkEndpoint>>,
    dialers: Mutex<HashMap<bool, Arc<LinkEndpoint>>>,
    live: Mutex<HashMap<KeyFingerprint, LiveLink>>,
    generation: std::sync::atomic::AtomicU64,
    enrollment_slots: Mutex<EnrollmentSlots>,
    /// `[[peer]]`s to dial again once (even when not persistent): their
    /// enrollment link was closed because this device enrolled.
    relink: Mutex<HashSet<usize>>,
    cancel: CancellationToken,
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
        .map(|p| Peer::from_config(p, &config.peers))
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
    let links = Arc::new(Links {
        engine: engine.clone(),
        keyring: Arc::clone(&keyring),
        own_certs,
        signer,
        peers,
        transport,
        socket,
        dialers: Mutex::new(HashMap::new()),
        live: Mutex::new(HashMap::new()),
        generation: std::sync::atomic::AtomicU64::new(0),
        enrollment_slots: Mutex::new(EnrollmentSlots::default()),
        relink: Mutex::new(HashSet::new()),
        cancel,
    });

    let weak = Arc::downgrade(&links);
    keyring.on_revocation(move |ctx, _| {
        if let Some(links) = weak.upgrade() {
            links.close_revoked(ctx);
        }
    });
    tokio::spawn(relink_on_switch(Arc::downgrade(&links), identity.switches()));

    if let Some(socket) = &links.socket {
        let addr = socket.local_addr().map(|a| a.to_string()).unwrap_or_default();
        if socket.is_listening() {
            tracing::info!(target: "face.quic", %addr, "listening for QUIC links");
            tokio::spawn(accept_loop(Arc::downgrade(&links), Arc::clone(socket)));
        } else {
            tracing::info!(target: "face.quic", %addr, "dialling QUIC links from this address (listen = false)");
        }
    }
    for (index, peer) in links.peers.iter().enumerate() {
        if !peer.endpoints.is_empty() {
            tokio::spawn(dial_loop(Arc::downgrade(&links), index));
        }
    }
    Ok(Some(links))
}

impl Links {
    /// Tell every linked device that this one is shutting down.
    pub(crate) async fn shutdown(&self) {
        let text = "the device is shutting down; it links again when it is back";
        let grace = Duration::from_secs(1);
        let dialers: Vec<_> = self
            .dialers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
        for endpoint in self.socket.iter().chain(dialers.iter()) {
            endpoint.close(CloseReason::Shutdown, text, grace).await;
        }
    }

    /// The endpoint to dial `addr` from: the configured link socket when it
    /// has that address family (so the other device sees one address for
    /// this one, the one `bind` picks), else a dial-only socket per family
    /// on an address the system picks.
    fn endpoint_for(&self, addr: SocketAddr) -> anyhow::Result<Arc<LinkEndpoint>> {
        if let Some(socket) = &self.socket
            && socket.local_addr().is_ok_and(|l| l.is_ipv4() == addr.is_ipv4())
        {
            return Ok(Arc::clone(socket));
        }
        let mut dialers = self.dialers.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(endpoint) = dialers.get(&addr.is_ipv4()) {
            return Ok(Arc::clone(endpoint));
        }
        let bind: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse()?
        } else {
            "[::]:0".parse()?
        };
        let endpoint = Arc::new(LinkEndpoint::bind(
            bind,
            Arc::clone(&self.signer) as Arc<dyn LinkKeySource>,
            &self.transport,
            false,
        )?);
        dialers.insert(addr.is_ipv4(), Arc::clone(&endpoint));
        Ok(endpoint)
    }

    /// This device's hello: the certificate of the key it links with now and
    /// that certificate's issuers.
    fn own_hello(&self) -> LinkHello {
        LinkHello {
            certificates: self.own_certs.chain_of(self.signer.current().key_name()),
        }
    }

    fn my_fingerprint(&self) -> Option<KeyFingerprint> {
        LinkKeySource::current(self.signer.as_ref())
            .ok()
            .map(|k| k.fingerprint())
    }

    /// The certificate this device links with now, if it has one.
    fn own_certificate(&self) -> Option<Certificate> {
        let hello = self.own_hello();
        let wire = hello.certificates.first()?;
        let data = Data::decode(wire.clone()).ok()?;
        Certificate::decode(&data).ok()
    }

    /// This device's role in `namespace`, from the certificate it links
    /// with now; `None` when that certificate is not of `namespace`.
    fn own_role_in(&self, namespace: &Name) -> Option<Role> {
        let cert = self.own_certificate()?;
        parse_device_key(namespace, &cert.name).map(|d| d.role)
    }

    /// The namespace of `device` (`/<ns>/<role>/<device>`): the held one it
    /// is in, else its name without the role and device.
    fn namespace_of(&self, device: &Name) -> Name {
        let ctx = self.keyring.context_for(device);
        if !ctx.namespace().is_empty() {
            return ctx.namespace().clone();
        }
        Name::from_components(
            device.components()[..device.len().saturating_sub(2)]
                .iter()
                .cloned(),
        )
    }

    /// The namespaces this relay admits enrollment links for: held ones
    /// whose link policy allows them and whose trust context names a CA
    /// endpoint, where this device holds a certificate of a role the policy
    /// lets relay. `Err`: why none, for the refusal.
    fn enrollment_namespaces(&self) -> Result<Vec<Name>, String> {
        let mut namespaces = Vec::new();
        let mut why_not = Vec::new();
        for ctx in self.keyring.contexts() {
            let ns = ctx.namespace();
            if ns.is_empty() {
                continue;
            }
            let policy = ctx.link_policy();
            if !policy.enrollment_links {
                why_not.push(format!("{ns}'s link policy turns enrollment links off"));
                continue;
            }
            if ctx.ca_endpoints().is_empty() {
                why_not.push(format!("{ns}'s trust context names no CA to enroll at"));
                continue;
            }
            match self.own_role_in(ns) {
                Some(role) if policy.allows_relay(role.as_str()) => namespaces.push(ns.clone()),
                Some(role) => why_not.push(format!(
                    "{ns}'s link policy does not let {role} devices (this one) relay"
                )),
                None => why_not.push(format!("this device holds no certificate in {ns}")),
            }
        }
        if namespaces.is_empty() {
            Err(if why_not.is_empty() {
                "it holds no namespace".into()
            } else {
                why_not.join("; ")
            })
        } else {
            Ok(namespaces)
        }
    }

    /// Take a place for an enrollment link from `source`, or refuse it when
    /// this relay holds as many as it takes.
    fn reserve_enrollment(self: &Arc<Self>, source: IpAddr) -> Result<EnrollmentSlot, Refusal> {
        let mut slots = self
            .enrollment_slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let from_source = slots.by_source.get(&source).copied().unwrap_or(0);
        if slots.total >= ENROLLMENT_LINKS_MAX || from_source >= ENROLLMENT_LINKS_PER_SOURCE {
            return Err(Refusal::new(
                CloseReason::Busy,
                format!(
                    "this relay holds {} enrollment links ({from_source} from your address; it \
                     takes {ENROLLMENT_LINKS_MAX}, {ENROLLMENT_LINKS_PER_SOURCE} from one address); \
                     your device dials again by itself — or enroll it over another path",
                    slots.total
                ),
            ));
        }
        slots.total += 1;
        *slots.by_source.entry(source).or_default() += 1;
        Ok(EnrollmentSlot {
            links: Arc::downgrade(self),
            source,
        })
    }

    /// How this side admits the link: what it tells the peer, and what the
    /// link carries.
    fn admission_for(&self, admitted: &Admitted) -> Admission {
        match &admitted.enrollment {
            None => Admission::default(),
            Some(Enrollment::Relay(namespaces)) => {
                let keyring = Arc::clone(&self.keyring);
                let scoped = namespaces.clone();
                Admission {
                    verdict: LinkVerdict {
                        enrollment_link: Some(namespaces.clone()),
                    },
                    scope: Some(LinkScope {
                        receives: Carries::Interests,
                        sends: Carries::Answers,
                        names: Box::new(move |name: &Name| in_enrollment(&keyring, &scoped, name, true)),
                        rate: ENROLLMENT_INTERESTS,
                        explain: format!(
                            "the enrollment link of key {} carries only that device's enrollment in \
                             {} (Interests for its CA, trust context and certificates, and their \
                             answers); it links fully once it enrolls",
                            admitted.fingerprint,
                            list(namespaces)
                        ),
                    }),
                }
            }
            Some(Enrollment::Device(ns)) => {
                let keyring = Arc::clone(&self.keyring);
                let scoped = vec![ns.clone()];
                let label = admitted
                    .peer
                    .map(|i| self.peers[i].label.clone())
                    .unwrap_or_else(|| admitted.describe());
                Admission {
                    verdict: LinkVerdict::default(),
                    scope: Some(LinkScope {
                        receives: Carries::Answers,
                        sends: Carries::Interests,
                        names: Box::new(move |name: &Name| in_enrollment(&keyring, &scoped, name, false)),
                        rate: ENROLLMENT_ANSWERS,
                        explain: format!(
                            "the link to {label} carries only this device's enrollment in {ns} (its \
                             CA, trust context and certificates) until this device enrolls: `ndn-fwd \
                             enroll <invite link>`, or by an admin's approval"
                        ),
                    }),
                }
            }
        }
    }

    /// This device switched to another key: close each enrollment link for
    /// a namespace that key is certified in, and dial it again, now as an
    /// enrolled device.
    fn relink_enrolled(&self) {
        let Some(cert) = self.own_certificate() else { return };
        let mut closing = Vec::new();
        {
            let live = self.live.lock().unwrap_or_else(PoisonError::into_inner);
            for link in live.values() {
                let Some(ns) = link
                    .enrolling
                    .iter()
                    .find(|ns| parse_device_key(ns, &cert.name).is_some())
                else {
                    continue;
                };
                let text = format!(
                    "this device enrolled in {ns} ({}); it links again as an enrolled device",
                    cert.name
                );
                closing.push((link.handle.clone(), link.face, link.peer, text));
            }
        }
        // Marked before closing, so the dial loop that sees the close dials
        // again.
        self.relink
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(closing.iter().filter_map(|(_, _, peer, _)| *peer));
        for (handle, face, _, text) in closing {
            tracing::info!(target: "face.quic", face = face.0, "{text}");
            handle.close(CloseReason::Enrolled, &text);
        }
    }

    /// Whether `[[peer]]` `index` is to be dialled again once.
    fn take_relink(&self, index: usize) -> bool {
        self.relink
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&index)
    }

    /// What the certificates `hello` carries establish about `key`.
    async fn identify(&self, key: &PeerKey, hello: &LinkHello) -> Result<Identified, Refusal> {
        let Some((leaf_wire, issuers)) = hello.certificates.split_first() else {
            return Ok(Identified::Unknown("it sent no certificate".into()));
        };
        let decode = |wire: &bytes::Bytes| {
            Data::decode(wire.clone())
                .map_err(|e| e.to_string())
                .and_then(|data| Certificate::decode(&data).map(|c| (data, c)).map_err(|e| e.to_string()))
        };
        let (leaf_data, leaf) = decode(leaf_wire).map_err(|e| {
            Refusal::new(CloseReason::Protocol, format!("the certificate in your link hello does not decode: {e}"))
        })?;
        if leaf.public_key != key.ndn_public_key() {
            return Err(Refusal::new(
                CloseReason::CertificateForAnotherKey,
                format!(
                    "the certificate {} you sent is for another key than the one your link \
                     handshake proved ({}); a device links with the key its certificate certifies",
                    leaf.name,
                    key.fingerprint()
                ),
            ));
        }
        let ctx = self.keyring.context_for(&leaf.name);
        if ctx.namespace().is_empty() {
            return Ok(Identified::Unknown(format!(
                "its certificate {} is not of a namespace this device holds",
                leaf.name
            )));
        }
        let ns = ctx.namespace().clone();
        let version = ctx.version();
        if ctx.is_revoked(&leaf.name) {
            return Err(Refusal::new(
                CloseReason::Revoked,
                format!("your key {} is revoked in {ns} (trust context v{version})", leaf.key_name()),
            ));
        }
        let Some(device) = parse_device_key(&ns, &leaf.name) else {
            return Ok(Identified::Unknown(format!(
                "{} is not a device certificate of {ns} (/<namespace>/<role>/<device>/KEY/…)",
                leaf.name
            )));
        };
        if !leaf.is_valid_now() {
            return Ok(Identified::Unknown(format!(
                "its certificate {} is outside its validity period (renew it: `ndn-fwd renew`)",
                leaf.name
            )));
        }
        let mut chain: Vec<Certificate> = Vec::new();
        for wire in issuers.iter().take(MAX_CHAIN) {
            match decode(wire) {
                Ok((_, cert)) => chain.push(cert),
                Err(e) => {
                    return Err(Refusal::new(
                        CloseReason::Protocol,
                        format!("an issuer certificate in your link hello does not decode: {e}"),
                    ));
                }
            }
        }
        if let Some(revoked) = chain.iter().find(|c| ctx.is_revoked(&c.name)) {
            return Err(Refusal::new(
                CloseReason::Revoked,
                format!(
                    "your certificate's issuer {} is revoked in {ns} (trust context v{version})",
                    revoked.name
                ),
            ));
        }
        match self.validate(&leaf_data, &chain).await {
            ValidationResult::Valid(_) => {}
            ValidationResult::Invalid(e) => {
                return Ok(Identified::Unknown(format!(
                    "its certificate {} does not validate in {ns} v{version}: {e}",
                    leaf.name
                )));
            }
            ValidationResult::Pending => {
                return Ok(Identified::Unknown(format!(
                    "its certificate {}'s issuer chain was not sent and is not known here",
                    leaf.name
                )));
            }
        }
        let mut certificates = vec![(*leaf.name).clone()];
        certificates.extend(chain.iter().map(|c| (*c.name).clone()));
        let device_name = ns
            .clone()
            .append(device.role.as_str())
            .append(device.device.as_str());
        Ok(Identified::Device(Identity {
            namespace: ns,
            version,
            device: device_name,
            role: device.role,
            certificates,
        }))
    }

    /// Validate a peer's certificate against the held trust contexts, with
    /// the issuers it sent, then the certificates this device serves or has
    /// cached — never fetching (the link is not up yet) and never adding the
    /// peer's certificates to the engine's cache.
    async fn validate(&self, leaf: &Data, issuers: &[Certificate]) -> ValidationResult {
        let cache = Arc::new(CertCache::new());
        for cert in issuers {
            cache.insert(cert.clone());
        }
        let validator = Validator::with_keyring(Arc::clone(&self.keyring), Arc::clone(&cache), None, MAX_CHAIN);
        let cached = self.engine.validator();
        for _ in 0..MAX_CHAIN {
            match validator.validate_chain_cached(leaf).await {
                (ValidationResult::Pending, Some(missing)) => {
                    let known = self.own_certs.certificate(&missing).or_else(|| {
                        cached
                            .as_ref()
                            .and_then(|v| v.cert_cache().get_valid(&missing))
                    });
                    match known {
                        Some(cert) => cache.insert(cert),
                        None => return ValidationResult::Pending,
                    }
                }
                (result, _) => return result,
            }
        }
        ValidationResult::Pending
    }

    /// Decide whether the link from `key` (which sent `hello`) is admitted.
    /// `dialed` is the `[[peer]]` this device dialed, `None` for a link
    /// another device opened.
    async fn decide(
        &self,
        key: &PeerKey,
        hello: &LinkHello,
        dialed: Option<usize>,
    ) -> Result<Admitted, Refusal> {
        let fingerprint = key.fingerprint();
        let identity = match self.identify(key, hello).await? {
            Identified::Device(id) => Ok(id),
            Identified::Unknown(why) => Err(why),
        };
        let peer = dialed.or_else(|| {
            self.peers.iter().position(|p| {
                p.key == Some(fingerprint)
                    || identity.as_ref().is_ok_and(|id| p.device.as_ref() == Some(&id.device))
            })
        });
        let config = peer.map(|i| &self.peers[i]);
        let key_expected = config.is_some_and(|p| p.key == Some(fingerprint));

        if let Some(p) = config {
            if let Some(expected) = p.key
                && expected != fingerprint
            {
                return Err(Refusal::new(
                    CloseReason::NotTheExpectedDevice,
                    format!(
                        "this device expects {} to link with key {expected}, and yours is \
                         {fingerprint}",
                        p.label
                    ),
                ));
            }
            if let Some(device) = &p.device {
                match &identity {
                    Ok(id) if id.device != *device => {
                        return Err(Refusal::new(
                            CloseReason::NotTheExpectedDevice,
                            format!("this device expects {device} here, and you are {}", id.device),
                        ));
                    }
                    Err(why) if !key_expected => {
                        // Not enrolled in the namespace of the relay it
                        // dialled, this device cannot confirm it yet, and
                        // links to it for its enrollment only.
                        let ns = self.namespace_of(device);
                        if dialed.is_some() && self.own_role_in(&ns).is_none() {
                            return Ok(Admitted {
                                fingerprint,
                                identity: None,
                                peer,
                                enrollment: Some(Enrollment::Device(ns)),
                            });
                        }
                        return Err(Refusal::new(
                            CloseReason::Unrecognized,
                            format!(
                                "this device expects {device} here and cannot confirm you are it: \
                                 {why}. It links once it holds {device}'s namespace, or once its \
                                 [[peer]] names your key"
                            ),
                        ));
                    }
                    _ => {}
                }
            }
        }

        match &identity {
            Ok(id) => {
                let ctx = self.keyring.context_for(&id.device);
                let policy = ctx.link_policy();
                if !policy.allows_link(id.role.as_str()) {
                    return Err(Refusal::new(
                        CloseReason::RoleNotAllowed,
                        format!(
                            "{}'s link policy (trust context v{}) does not let {} devices link",
                            id.namespace, id.version, id.role
                        ),
                    ));
                }
                if config.is_some_and(|p| p.is_relay) && !policy.allows_relay(id.role.as_str()) {
                    return Err(Refusal::new(
                        CloseReason::RoleNotAllowed,
                        format!(
                            "this device reaches others through you, and {}'s link policy (trust \
                             context v{}) does not let {} devices relay",
                            id.namespace, id.version, id.role
                        ),
                    ));
                }
            }
            Err(why) if !key_expected => {
                // A device this relay does not know may enroll over it.
                let no_enrollment_link = if dialed.is_none() && config.is_none() {
                    match self.enrollment_namespaces() {
                        Ok(namespaces) => {
                            return Ok(Admitted {
                                fingerprint,
                                identity: None,
                                peer,
                                enrollment: Some(Enrollment::Relay(namespaces)),
                            });
                        }
                        Err(why_not) => format!(" It admits no enrollment link either: {why_not}."),
                    }
                } else {
                    String::new()
                };
                let held: Vec<String> = self
                    .keyring
                    .contexts()
                    .iter()
                    .map(|c| c.namespace().to_string())
                    .collect();
                let held = if held.is_empty() {
                    "none".to_string()
                } else {
                    held.join(", ")
                };
                return Err(Refusal::new(
                    CloseReason::Unrecognized,
                    format!(
                        "this device links with devices of the namespaces it holds ({held}) and with \
                         the keys its [[peer]] entries expect; your key {fingerprint} is neither \
                         ({why}).{no_enrollment_link} Enroll this device in the namespace, or add \
                         [[peer]] key = \"{fingerprint}\" to the other device's config"
                    ),
                ));
            }
            Err(_) => {}
        }
        Ok(Admitted {
            fingerprint,
            identity: identity.ok(),
            peer,
            enrollment: None,
        })
    }

    /// The routes over a link to the admitted peer: the `[[peer]]`'s
    /// `routes`, else its namespace for a relay this device dials, else its
    /// device name; and the routes of the peers reached through it. An
    /// enrollment link: none on the relay (answers return the way their
    /// Interests came), the namespace on the enrolling device.
    fn routes_for(&self, admitted: &Admitted) -> Vec<(Name, u32)> {
        match &admitted.enrollment {
            Some(Enrollment::Relay(_)) => return Vec::new(),
            Some(Enrollment::Device(ns)) => return vec![(ns.clone(), 0)],
            None => {}
        }
        let default_routes = |peer: Option<&Peer>, identity: Option<&Identity>| -> Vec<Name> {
            if let Some(routes) = peer.and_then(|p| p.routes.clone()) {
                return routes;
            }
            match identity {
                Some(id) if id.role == Role::Node && peer.is_some() => vec![id.namespace.clone()],
                Some(id) => vec![id.device.clone()],
                None => peer.and_then(|p| p.device.clone()).into_iter().collect(),
            }
        };
        let peer = admitted.peer.map(|i| &self.peers[i]);
        let mut routes: Vec<(Name, u32)> = default_routes(peer, admitted.identity.as_ref())
            .into_iter()
            .map(|n| (n, 0))
            .collect();
        if let Some(index) = admitted.peer {
            for reached in self.peers.iter().filter(|p| p.relay == Some(index)) {
                routes.extend(
                    default_routes(Some(reached), None)
                        .into_iter()
                        .map(|n| (n, VIA_RELAY_COST)),
                );
            }
        }
        routes
    }

    fn install_routes(&self, face: FaceId, routes: &[(Name, u32)]) {
        let rib = self.engine.rib();
        let fib = self.engine.fib();
        for (prefix, cost) in routes {
            rib.add(
                prefix,
                RibRoute {
                    face_id: face,
                    origin: origin::STATIC,
                    cost: *cost,
                    flags: route_flags::CHILD_INHERIT,
                    expires_at: None,
                },
            );
            rib.apply_to_fib(prefix, &fib);
        }
    }

    /// Run a handshaken connection to its end: exchange hellos, decide,
    /// admit (or refuse), and register the link. Returns the link's handle
    /// once it is up.
    async fn establish(
        self: &Arc<Self>,
        mut hs: Handshaken,
        dialed: Option<usize>,
    ) -> Result<LinkHandle, LinkError> {
        let remote = hs.remote_address();
        let theirs = hs.exchange_hello(&self.own_hello(), MESSAGE_DEADLINE).await?;
        let admitted = match self.decide(hs.peer_key(), &theirs, dialed).await {
            Ok(a) => a,
            Err(refusal) => {
                tracing::warn!(
                    target: "face.quic",
                    %remote,
                    key = %hs.peer_key().fingerprint(),
                    reason = ?refusal.reason,
                    "refused a link: {}",
                    refusal.text
                );
                hs.refuse(refusal.reason, &refusal.text);
                return Err(LinkError::RefusedHere {
                    reason: refusal.reason,
                    text: refusal.text,
                });
            }
        };
        let slot = match &admitted.enrollment {
            Some(Enrollment::Relay(_)) => match self.reserve_enrollment(remote.ip()) {
                Ok(slot) => Some(slot),
                Err(refusal) => {
                    tracing::warn!(
                        target: "face.quic",
                        %remote,
                        key = %hs.peer_key().fingerprint(),
                        "refused an enrollment link: {}",
                        refusal.text
                    );
                    hs.refuse(refusal.reason, &refusal.text);
                    return Err(LinkError::RefusedHere {
                        reason: refusal.reason,
                        text: refusal.text,
                    });
                }
            },
            _ => None,
        };
        let direction = hs.direction();
        let face_id = self.engine.faces().alloc_id();
        let link = hs
            .admit(face_id, MESSAGE_DEADLINE, self.admission_for(&admitted))
            .await?;
        let reliability = admitted.peer.is_some_and(|i| self.peers[i].reliability);
        let link_service: Arc<dyn ndn_transport::LinkService> = if reliability {
            Arc::new(LpLinkService::with_reliability(ReliabilityConfig::ethernet()))
        } else {
            ndn_transport::default_link_service_for_kind(ndn_transport::FaceKind::Quic)
        };
        let face = Face::from_parts(Arc::new(link.face), link_service);
        let handle = link.handle;
        let peer_enrollment = link.peer_verdict.enrollment_link.unwrap_or_default();
        let mut enrolling = peer_enrollment.clone();
        if let Some(Enrollment::Device(ns)) = &admitted.enrollment
            && !enrolling.contains(ns)
        {
            enrolling.push(ns.clone());
        }
        let Some(generation) =
            self.register(&admitted, direction, face_id, handle.clone(), enrolling)
        else {
            return Err(LinkError::RefusedHere {
                reason: CloseReason::Replaced,
                text: "a link between these two devices already exists".into(),
            });
        };
        self.engine
            .add_composed_face(face, self.cancel.child_token(), FacePersistency::Persistent);
        let routes = self.routes_for(&admitted);
        self.install_routes(face_id, &routes);
        tracing::info!(
            target: "face.quic",
            face = face_id.0,
            %remote,
            peer = %admitted.describe(),
            direction = ?direction,
            routes = ?routes.iter().map(|(n, c)| format!("{n} cost {c}")).collect::<Vec<_>>(),
            "link up"
        );
        self.explain_enrollment(&admitted, &peer_enrollment, face_id);
        let weak = Arc::downgrade(self);
        let watched = handle.clone();
        let fingerprint = admitted.fingerprint;
        let describe = admitted.describe();
        tokio::spawn(async move {
            let why = match slot {
                // An enrollment link that carries nothing for its idle
                // lifetime is closed; the device dials again if it still
                // needs it.
                Some(slot) => {
                    let why = loop {
                        tokio::select! {
                            why = watched.closed() => break why,
                            () = tokio::time::sleep(ENROLLMENT_IDLE / 4) => {}
                        }
                        if watched.scope_idle_for().is_some_and(|idle| idle >= ENROLLMENT_IDLE) {
                            watched.close(
                                CloseReason::Idle,
                                &format!(
                                    "this enrollment link carried nothing for {} s and is closed; \
                                     your device dials again by itself while it enrolls",
                                    ENROLLMENT_IDLE.as_secs()
                                ),
                            );
                        }
                    };
                    drop(slot);
                    why
                }
                None => watched.closed().await,
            };
            tracing::info!(
                target: "face.quic",
                face = face_id.0,
                peer = %describe,
                "link down: {why}"
            );
            if let Some(links) = weak.upgrade() {
                links.unregister(fingerprint, generation);
                links.engine.remove_face(face_id);
            }
        });
        Ok(handle)
    }

    /// Say, once a link is up, what an enrollment link on either side
    /// carries and what makes it a full link.
    fn explain_enrollment(&self, admitted: &Admitted, peer_enrollment: &[Name], face: FaceId) {
        let peer = admitted
            .peer
            .map(|i| self.peers[i].label.clone())
            .unwrap_or_else(|| admitted.describe());
        match &admitted.enrollment {
            Some(Enrollment::Relay(namespaces)) => tracing::info!(
                target: "face.quic",
                face = face.0,
                "admitted {peer} on an enrollment link: it carries only that device's enrollment \
                 in {} (Interests for its CA, trust context and certificates, and their answers); \
                 the device links as an enrolled device once it holds a certificate",
                list(namespaces)
            ),
            Some(Enrollment::Device(ns)) => tracing::info!(
                target: "face.quic",
                face = face.0,
                "linked to {peer} for this device's enrollment in {ns} only: it holds no \
                 certificate in {ns}, so it cannot confirm the device there yet. Enroll it \
                 (`ndn-fwd enroll <invite link>`, or by an admin's approval); the link is made \
                 again as a full link then"
            ),
            None => {}
        }
        if peer_enrollment.is_empty() {
            return;
        }
        let enrolled: Vec<&Name> = peer_enrollment
            .iter()
            .filter(|ns| self.own_role_in(ns).is_some())
            .collect();
        if enrolled.is_empty() {
            tracing::info!(
                target: "face.quic",
                face = face.0,
                "{peer} admitted this device on an enrollment link: it carries only this device's \
                 enrollment in {} until it enrolls (`ndn-fwd enroll <invite link>`, or by an \
                 admin's approval); the link is made again as a full link then",
                list(peer_enrollment)
            );
        } else {
            tracing::warn!(
                target: "face.quic",
                face = face.0,
                "{peer} admitted this device only on an enrollment link, although it holds a \
                 certificate in {}: that device cannot validate it — it may hold an older version \
                 of the trust context (`ndn-fwd context refresh` there) or lack the issuer \
                 chain. This device's key: {}",
                enrolled.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", "),
                admitted.fingerprint
            );
        }
    }

    /// Record an admitted link and return its generation; `None` when the
    /// link already in place stays and this one was closed instead.
    fn register(
        &self,
        admitted: &Admitted,
        direction: Direction,
        face: FaceId,
        handle: LinkHandle,
        enrolling: Vec<Name>,
    ) -> Option<u64> {
        let generation = self
            .generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        let mine = self.my_fingerprint();
        let mut live = self.live.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(existing) = live.get(&admitted.fingerprint) {
            // Each side dialled the other: both keep the link dialled by the
            // device with the smaller fingerprint. Otherwise the newer link
            // replaces the older (the other device dialled again, having lost
            // the older one).
            let keep_existing = existing.direction != direction
                && mine.is_some_and(|mine| {
                    let keep_mine = mine < admitted.fingerprint;
                    (existing.direction == Direction::Dialed) == keep_mine
                });
            let text = "a link between these two devices already exists";
            if keep_existing {
                handle.close(CloseReason::Replaced, text);
                return None;
            }
            existing.handle.close(CloseReason::Replaced, text);
        }
        live.insert(
            admitted.fingerprint,
            LiveLink {
                generation,
                face,
                handle,
                direction,
                peer: admitted.peer,
                identity: admitted.identity.clone(),
                enrolling,
            },
        );
        Some(generation)
    }

    fn unregister(&self, fingerprint: KeyFingerprint, generation: u64) {
        let mut live = self.live.lock().unwrap_or_else(PoisonError::into_inner);
        if live
            .get(&fingerprint)
            .is_some_and(|l| l.generation == generation)
        {
            live.remove(&fingerprint);
        }
    }

    /// The live link to `[[peer]]` `index`, if any.
    fn link_to(&self, index: usize) -> Option<LinkHandle> {
        let live = self.live.lock().unwrap_or_else(PoisonError::into_inner);
        live.values()
            .find(|l| l.peer == Some(index))
            .map(|l| l.handle.clone())
    }

    /// Close each link whose certificate (or an issuer of it) `ctx`, newly
    /// adopted, revokes.
    fn close_revoked(&self, ctx: &Arc<SignedTrustContext>) {
        let live = self.live.lock().unwrap_or_else(PoisonError::into_inner);
        for link in live.values() {
            let Some(id) = &link.identity else { continue };
            if !id.device.has_prefix(ctx.namespace()) {
                continue;
            }
            if let Some(revoked) = id.certificates.iter().find(|c| ctx.is_revoked(c)) {
                let text = format!(
                    "{revoked} is revoked in {} (trust context v{}); this link is closed",
                    ctx.namespace(),
                    ctx.version()
                );
                tracing::warn!(target: "face.quic", face = link.face.0, peer = %id.device, "{text}");
                link.handle.close(CloseReason::Revoked, &text);
            }
        }
    }
}

async fn accept_loop(links: Weak<Links>, listener: Arc<LinkEndpoint>) {
    loop {
        let Some(cancel) = links.upgrade().map(|l| l.cancel.clone()) else {
            return;
        };
        let incoming = tokio::select! {
            () = cancel.cancelled() => return,
            incoming = listener.accept() => incoming,
        };
        let Some(incoming) = incoming else { return };
        let Some(links) = links.upgrade() else { return };
        tokio::spawn(inbound(links, incoming));
    }
}

async fn inbound(links: Arc<Links>, incoming: Incoming) {
    let remote = incoming.remote_address();
    let hs = match incoming.handshake().await {
        Ok(hs) => hs,
        Err(e) => {
            tracing::info!(target: "face.quic", %remote, "inbound link handshake failed: {e}");
            return;
        }
    };
    // A refusal here was logged with its reason where it was decided.
    if let Err(e) = links.establish(hs, None).await
        && !matches!(e, LinkError::RefusedHere { .. })
    {
        tracing::info!(target: "face.quic", %remote, "inbound link did not come up: {e}");
    }
}

/// Keep `[[peer]]` `index` linked: dial its endpoints in order, and again
/// with backoff whenever the link drops (once, unless persistent).
async fn dial_loop(links: Weak<Links>, index: usize) {
    let mut backoff = BACKOFF_FIRST;
    loop {
        let Some(this) = links.upgrade() else { return };
        let cancel = this.cancel.clone();
        let peer = &this.peers[index];
        let persistent = peer.persistent;
        let label = peer.label.clone();

        // Already linked (the other device dialled this one): wait for that
        // link to end.
        if let Some(handle) = this.link_to(index) {
            drop(this);
            tokio::select! {
                () = cancel.cancelled() => return,
                _ = handle.closed() => {}
            }
            if !relink_once(&links, index) && !persistent {
                return;
            }
            continue;
        }

        let attempt = dial_once(&this, index).await;
        drop(this);
        let wait = match attempt {
            Ok(handle) => {
                backoff = BACKOFF_FIRST;
                tokio::select! {
                    () = cancel.cancelled() => return,
                    _ = handle.closed() => {}
                }
                if !relink_once(&links, index) && !persistent {
                    return;
                }
                BACKOFF_FIRST
            }
            Err(e) => {
                let refused = !e.is_transient();
                tracing::warn!(
                    target: "face.quic",
                    peer = %label,
                    retry_in_secs = if refused { BACKOFF_REFUSED } else { backoff }.as_secs_f32(),
                    "link to {label} failed: {e}"
                );
                if !persistent {
                    return;
                }
                if refused {
                    BACKOFF_REFUSED
                } else {
                    let wait = backoff;
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                    wait
                }
            }
        };
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(wait) => {}
        }
    }
}

/// One attempt over every endpoint of `[[peer]]` `index`; the first that
/// links wins, else the last failure.
async fn dial_once(links: &Arc<Links>, index: usize) -> Result<LinkHandle, LinkError> {
    let peer = &links.peers[index];
    let mut last = LinkError::Connect(format!("{} has no endpoint", peer.label));
    for endpoint in &peer.endpoints {
        let addrs: Vec<SocketAddr> = match tokio::net::lookup_host(endpoint.as_str()).await {
            Ok(addrs) => addrs.collect(),
            Err(e) => {
                last = LinkError::Connect(format!("cannot resolve {endpoint}: {e}"));
                continue;
            }
        };
        for addr in addrs {
            let socket = match links.endpoint_for(addr) {
                Ok(s) => s,
                Err(e) => {
                    last = LinkError::Connect(format!("no socket to dial {addr} from: {e:#}"));
                    continue;
                }
            };
            let attempt = async {
                let hs = socket.connect(addr, peer.key).await?;
                links.establish(hs, Some(index)).await
            };
            match attempt.await {
                Ok(handle) => return Ok(handle),
                Err(e) => last = e,
            }
        }
    }
    Err(last)
}

/// Whether `[[peer]]` `index` is to be dialled again once, its enrollment
/// link having been closed because this device enrolled.
fn relink_once(links: &Weak<Links>, index: usize) -> bool {
    links.upgrade().is_some_and(|l| l.take_relink(index))
}

/// Each time this device switches to another key (it enrolled), make its
/// enrollment links for that key's namespace again as full links.
async fn relink_on_switch(links: Weak<Links>, mut switches: tokio::sync::watch::Receiver<u64>) {
    loop {
        let Some(cancel) = links.upgrade().map(|l| l.cancel.clone()) else {
            return;
        };
        tokio::select! {
            () = cancel.cancelled() => return,
            changed = switches.changed() => if changed.is_err() { return },
        }
        let Some(links) = links.upgrade() else { return };
        links.relink_enrolled();
    }
}

/// Whether `name` is within the enrollment in one of `namespaces`: an
/// Interest (or its answer) for the namespace's trust context, for a CA
/// endpoint its held trust context names, or for a key or certificate name
/// in it (`<identity>/KEY/<key-id>[/<issuer>/<version>]`: the certificates
/// an enrollment fetches, the issued one and its issuers). On a relay
/// (`relay`), only while the namespace's link policy still admits
/// enrollment links.
fn in_enrollment(keyring: &Keyring, namespaces: &[Name], name: &Name, relay: bool) -> bool {
    namespaces.iter().any(|ns| {
        if !name.has_prefix(ns) {
            return false;
        }
        let ctx = keyring.contexts().into_iter().find(|c| c.namespace() == ns);
        if relay && !ctx.as_ref().is_some_and(|c| c.admits_enrollment_links()) {
            return false;
        }
        name.has_prefix(&rdr_prefix(ns))
            || ctx.is_some_and(|c| c.ca_endpoints().iter().any(|ca| name.has_prefix(ca)))
            || is_key_or_certificate_name(&name.components()[ns.len()..])
    })
}

/// `…/KEY/<key-id>`, optionally followed by `<issuer>/<version>`.
fn is_key_or_certificate_name(components: &[ndn_packet::NameComponent]) -> bool {
    components
        .iter()
        .position(|c| c.typ == ndn_packet::tlv_type::NAME_COMPONENT && c.value.as_ref() == b"KEY")
        .is_some_and(|key| (1..=3).contains(&(components.len() - key - 1)))
}

fn list(names: &[Name]) -> String {
    names.iter().map(Name::to_string).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_security::LinkPolicy;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn keyring_with(ctx: SignedTrustContext) -> Keyring {
        let keyring = Keyring::new();
        assert!(keyring.adopt(Arc::new(ctx)));
        keyring
    }

    #[test]
    fn an_enrollment_link_carries_only_the_enrollment() {
        let ctx = || {
            SignedTrustContext::hierarchical(n("/home"))
                .with_version(1)
                .with_ca_endpoint(n("/home/CA"))
        };
        let keyring = keyring_with(ctx());
        let ns = [n("/home")];
        let trust_context = rdr_prefix(&ns[0]).append("x");
        for (name, carried) in [
            (trust_context.clone(), true),
            (n("/home/CA/NEW"), true),
            (n("/home/CA/CHALLENGE/abc"), true),
            (n("/home/member/phone/KEY/k1/NDNCERT/v=1"), true),
            (n("/home/KEY/root"), true),
            (n("/home/member/phone/album"), false),
            (n("/home/node/relay/hello"), false),
            (n("/home/member/phone/KEY"), false),
            (n("/home/member/phone/files/KEY/a/b/c/d"), false),
            (n("/elsewhere/CA/NEW"), false),
        ] {
            for relay in [true, false] {
                assert_eq!(in_enrollment(&keyring, &ns, &name, relay), carried, "{name} (relay: {relay})");
            }
        }
        // A relay stops carrying enrollments once the namespace's link
        // policy turns enrollment links off.
        let off = keyring_with(ctx().with_link_policy(LinkPolicy {
            enrollment_links: false,
            ..LinkPolicy::default()
        }));
        assert!(!in_enrollment(&off, &ns, &n("/home/CA/NEW"), true));
        assert!(in_enrollment(&off, &ns, &n("/home/CA/NEW"), false));
    }
}
