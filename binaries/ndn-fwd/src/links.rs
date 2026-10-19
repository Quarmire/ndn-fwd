//! QUIC links: this device's links to the devices `[[peer]]` names, to its
//! relays (the namespace's and `[[relay]]`), and the links other devices
//! open to it (`[[face]] kind = "quic"`).
//!
//! Admission, enrollment links, relays, link modes, routes, redial and the
//! one-link-per-pair rule are `ndn_link`'s; this module gives it the
//! daemon's parts: the config, the link socket, the keyring and served
//! certificates, the device's memberships (every signing identity the
//! engine's key store holds in a held namespace, with its served chain;
//! the link key stays the node key), the engine's faces and RIB, the wake
//! command, and the identity changes of `ActiveIdentity`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use bytes::Bytes;
use ndn_config::{
    FaceConfig, ForwarderConfig, LinkModeConfig, PeerConfig, RelayConfig, RelayServiceConfig,
    ServeConfig,
};
use ndn_engine::ForwarderEngine;
use ndn_face_quic::{KeyFingerprint, LinkEndpoint, LinkKeySource, LinkTransportConfig, RateLimit};
use ndn_link::{
    AdvertisedCandidates, ConfiguredEndpoints, DirectOptions, EngineFaces, HoldLimits,
    HostCandidates, LinkMode, LinkSetup, LinkTrust, Links, OwnMembership, PeerId, PeerSpec, Quotas,
    RelayOptions, RelayService, RelaySource, RelayUse, ServePolicy, WakeNotifier, WakeRequest,
};
use ndn_packet::Name;
use ndn_security::{Certificate, Keyring};
use tokio_util::sync::CancellationToken;

use crate::active_identity::ActiveIdentity;
use crate::own_certs::OwnCertificates;

/// A configured link mode, as `ndn_link` takes it.
fn link_mode(mode: LinkModeConfig, idle_secs: u64) -> LinkMode {
    match mode {
        LinkModeConfig::Always => LinkMode::Always,
        LinkModeConfig::OnDemand => LinkMode::OnDemand {
            idle: Duration::from_secs(idle_secs),
        },
        LinkModeConfig::Off => LinkMode::Off,
    }
}

fn fingerprint(section: &str, label: &str, hex: &str) -> anyhow::Result<KeyFingerprint> {
    KeyFingerprint::from_hex(hex)
        .with_context(|| format!("{section} {label}: key is not 64 hex digits"))
}

fn parse_name(section: &str, label: &str, s: &str) -> anyhow::Result<Name> {
    s.parse::<Name>()
        .map_err(|e| anyhow::anyhow!("{section} {label}: {s:?} is not a name: {e}"))
}

/// The peer specs of the config, `[[peer]]` entries first (`PeerId(i)` for
/// the i-th), then `[[relay]]` entries.
fn peer_specs(config: &ForwarderConfig) -> anyhow::Result<Vec<PeerSpec>> {
    let peers = &config.peers;
    let relays = &config.user_relays;
    let mut specs = Vec::with_capacity(peers.len() + relays.len());
    for peer in peers {
        specs.push(peer_spec(peer, peers, relays)?);
    }
    for relay in relays {
        specs.push(relay_spec(relay)?);
    }
    Ok(specs)
}

/// A `[[peer]]`, as `ndn_link` takes it. Its `relay` names another
/// `[[peer]]` or a `[[relay]]` (whose ids follow the peers').
fn peer_spec(
    config: &PeerConfig,
    peers: &[PeerConfig],
    relays: &[RelayConfig],
) -> anyhow::Result<PeerSpec> {
    let label = config.label();
    let relay = config.relay.as_deref().and_then(|r| {
        peers
            .iter()
            .position(|p| !std::ptr::eq(p, config) && p.is_named(r))
            .or_else(|| {
                relays
                    .iter()
                    .position(|q| q.is_named(r))
                    .map(|i| peers.len() + i)
            })
    });
    Ok(PeerSpec {
        key: config
            .key
            .as_deref()
            .map(|k| fingerprint("[[peer]]", &label, k))
            .transpose()?,
        device: config
            .device
            .as_deref()
            .map(|d| parse_name("[[peer]]", &label, d))
            .transpose()?,
        endpoints: config.endpoint.clone(),
        relay: relay.map(PeerId),
        routes: config
            .routes
            .as_ref()
            .map(|routes| {
                routes
                    .iter()
                    .map(|r| parse_name("[[peer]]", &label, r))
                    .collect()
            })
            .transpose()?,
        persistent: config.persistent,
        reliability: config.reliability,
        direct: config.direct,
        mode: link_mode(config.mode, config.idle_secs),
        hold: config.hold,
        label,
        ..PeerSpec::default()
    })
}

/// A `[[relay]]`: a peer this device uses as a relay the user added.
fn relay_spec(config: &RelayConfig) -> anyhow::Result<PeerSpec> {
    let label = config.label();
    Ok(PeerSpec {
        key: config
            .key
            .as_deref()
            .map(|k| fingerprint("[[relay]]", &label, k))
            .transpose()?,
        device: config
            .device
            .as_deref()
            .map(|d| parse_name("[[relay]]", &label, d))
            .transpose()?,
        endpoints: config.endpoint.clone(),
        mode: link_mode(config.mode, config.idle_secs),
        relay_use: Some(RelayUse {
            source: RelaySource::User,
            preference: config.preference,
        }),
        hold: config.hold,
        label,
        ..PeerSpec::default()
    })
}

/// `[relay_service]`, as `ndn_link` takes it.
fn relay_service(config: &RelayServiceConfig) -> anyhow::Result<RelayService> {
    let quotas = config.quotas().map(|q| {
        // Rates per second, bursts of twice that.
        let rate = |per_sec: u32| RateLimit {
            burst: per_sec.saturating_mul(2),
            per_sec,
        };
        Quotas {
            links_total: q.links_total,
            links_per_namespace: q.links_per_namespace,
            interests_per_key: rate(q.interests_per_key),
            interests_per_namespace: rate(q.interests_per_namespace),
        }
    });
    let serve = match config.serve {
        ServeConfig::Own => ServePolicy::Own,
        ServeConfig::Listed => ServePolicy::Listed {
            roots: config
                .roots
                .iter()
                .map(|r| fingerprint("[relay_service]", "roots", r))
                .collect::<anyhow::Result<_>>()?,
            quotas,
        },
        ServeConfig::Open => ServePolicy::Open {
            quotas: quotas.context("[relay_service] serve = \"open\" has quotas")?,
        },
    };
    Ok(RelayService {
        serve,
        hold: config.hold.then(|| HoldLimits {
            per_device: config.hold_per_device,
            total: config.hold_total,
            max_hold: Duration::from_secs(config.hold_secs),
        }),
        wake: config
            .wake_command
            .clone()
            .map(|argv| Arc::new(WakeCommand { argv }) as Arc<dyn WakeNotifier>),
        asleep_max: Duration::from_secs(config.asleep_secs),
    })
}

/// How long a wake command may run before it is killed.
const WAKE_COMMAND_LIMIT: Duration = Duration::from_secs(10);

/// `[relay_service] wake_command`: run once per wake, without a shell, with
/// `NDN_WAKE_TOKEN` (hex), `NDN_WAKE_DEVICE` (name or empty), `NDN_WAKE_KEY`
/// (fingerprint hex) and `NDN_WAKE_HELD` in its environment; in the
/// background, killed after [`WAKE_COMMAND_LIMIT`]; its output is logged.
struct WakeCommand {
    argv: Vec<String>,
}

impl WakeNotifier for WakeCommand {
    fn wake(&self, request: WakeRequest) {
        let Some((program, args)) = self.argv.split_first() else {
            return;
        };
        let token: String = request.token.iter().map(|b| format!("{b:02x}")).collect();
        let device = request
            .device
            .as_ref()
            .map(|d| d.to_string())
            .unwrap_or_default();
        let mut command = tokio::process::Command::new(program);
        command
            .args(args)
            .env("NDN_WAKE_TOKEN", token)
            .env("NDN_WAKE_DEVICE", &device)
            .env("NDN_WAKE_KEY", request.key.to_string())
            .env("NDN_WAKE_HELD", request.held.to_string())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let program = program.clone();
        let key = request.key;
        tokio::spawn(async move {
            let child = match command.spawn() {
                Ok(child) => child,
                Err(e) => {
                    tracing::warn!(
                        target: "face.quic",
                        %program, %key, error = %e,
                        "cannot run [relay_service] wake_command; check that the program exists and is executable"
                    );
                    return;
                }
            };
            // Dropping the wait on timeout kills the child (kill_on_drop).
            match tokio::time::timeout(WAKE_COMMAND_LIMIT, child.wait_with_output()).await {
                Ok(Ok(out)) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    if out.status.success() {
                        tracing::info!(
                            target: "face.quic",
                            %program, %key, device = %device, held = request.held,
                            stdout = %stdout.trim(), stderr = %stderr.trim(),
                            "woke a sleeping device"
                        );
                    } else {
                        tracing::warn!(
                            target: "face.quic",
                            %program, %key, device = %device, status = %out.status,
                            stdout = %stdout.trim(), stderr = %stderr.trim(),
                            "[relay_service] wake_command failed; the device was not woken"
                        );
                    }
                }
                Ok(Err(e)) => tracing::warn!(
                    target: "face.quic",
                    %program, %key, error = %e,
                    "[relay_service] wake_command could not be waited for"
                ),
                Err(_) => tracing::warn!(
                    target: "face.quic",
                    %program, %key,
                    "[relay_service] wake_command ran longer than {} s and was killed; make it return \
                     once the wake is handed off",
                    WAKE_COMMAND_LIMIT.as_secs()
                ),
            }
        });
    }
}

/// The daemon's trust data: the keyring, the certificates it serves, the
/// identities it signs as, and the engine's validated-certificate cache.
struct DaemonTrust {
    keyring: Arc<Keyring>,
    own_certs: Arc<OwnCertificates>,
    identity: Arc<ActiveIdentity>,
    engine: ForwarderEngine,
}

impl LinkTrust for DaemonTrust {
    fn keyring(&self) -> &Arc<Keyring> {
        &self.keyring
    }

    /// The chain of the node key, which is the link (TLS) key.
    fn own_chain(&self) -> Vec<Bytes> {
        self.own_certs
            .chain_of(self.identity.signer().current().key_name())
    }

    /// Every other identity the engine signs as, in a namespace this device
    /// holds, whose certificate it serves: shown on each link as a
    /// membership bound to it.
    fn own_memberships(&self) -> Vec<OwnMembership> {
        let node = self.identity.signer().current().key_name().clone();
        self.identity
            .signing_identities()
            .into_iter()
            .filter(|si| si.key != node)
            .filter_map(|si| {
                let ctx = self.keyring.context_for(&si.identity);
                if ctx.namespace().is_empty() {
                    return None;
                }
                let chain = self.own_certs.chain_of(&si.key);
                if chain.is_empty() {
                    tracing::debug!(
                        target: "face.quic",
                        key = %si.key,
                        "no served certificate of {}: its membership of {} is not shown on links",
                        si.key,
                        ctx.namespace()
                    );
                    return None;
                }
                Some(OwnMembership {
                    namespace: ctx.namespace().clone(),
                    chain,
                    signer: si.signer,
                })
            })
            .collect()
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

/// Start this device's links whenever it has a key: listen when `[[face]]
/// kind = "quic"` is configured (and not `listen = false`), link to its
/// relays (the namespace's and `[[relay]]`) and each `[[peer]]` by its mode,
/// punch direct paths. `None` when the daemon runs without a key and
/// nothing asks for links.
pub(crate) fn spawn(
    engine: &ForwarderEngine,
    keyring: Arc<Keyring>,
    identity: Option<&Arc<ActiveIdentity>>,
    own_certs: Arc<OwnCertificates>,
    config: &ForwarderConfig,
    cancel: CancellationToken,
) -> anyhow::Result<Option<Arc<Links>>> {
    let socket = config.faces.iter().find_map(|f| match f {
        FaceConfig::Quic {
            bind,
            listen,
            advertise,
        } => Some((bind.clone(), *listen, advertise.clone())),
        _ => None,
    });
    let Some(identity) = identity else {
        if socket.is_some() || !config.peers.is_empty() || !config.user_relays.is_empty() {
            anyhow::bail!(
                "QUIC links need this device's key, and the daemon runs without one ([security] \
                 profile = \"disabled\"); enable security or remove [[peer]], [[relay]] and \
                 [[face]] kind = \"quic\""
            );
        }
        return Ok(None);
    };
    let signer = Arc::clone(identity.signer());
    let key =
        LinkKeySource::current(signer.as_ref()).map_err(|e| anyhow::anyhow!("QUIC links: {e}"))?;
    tracing::info!(
        target: "face.quic",
        fingerprint = %key.fingerprint(),
        key = %key.key_name(),
        "this device's link key (other devices name it in [[peer]] key = \"…\")"
    );
    let peers = peer_specs(config)?;
    let transport = LinkTransportConfig::bounded(
        Duration::from_secs(config.links.keep_alive_secs),
        Duration::from_secs(config.links.idle_timeout_secs),
    )
    .map_err(|e| anyhow::anyhow!("[links]: {e}"))?;
    let advertised = match &socket {
        Some((_, _, advertise)) => advertise
            .iter()
            .map(|a| {
                std::net::ToSocketAddrs::to_socket_addrs(a.as_str()).with_context(|| {
                    format!("[[face]] kind = \"quic\": advertise {a:?} does not resolve")
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect(),
        None => Vec::new(),
    };
    let socket = socket
        .map(|(bind, listen, _)| {
            let addr: SocketAddr = bind
                .parse()
                .with_context(|| format!("[[face]] kind = \"quic\": bind {bind:?}"))?;
            LinkEndpoint::bind(
                addr,
                Arc::clone(&signer) as Arc<dyn LinkKeySource>,
                &transport,
                listen,
            )
            .map(Arc::new)
            .with_context(|| format!("cannot bind the QUIC link socket to {addr}"))
        })
        .transpose()?;
    if let Some(socket) = &socket {
        let addr = socket
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        if socket.is_listening() {
            tracing::info!(target: "face.quic", %addr, "listening for QUIC links");
        } else {
            tracing::info!(target: "face.quic", %addr, "dialling QUIC links from this address (listen = false)");
        }
    }
    let relays = &config.relays;
    let links = Links::start(
        LinkSetup {
            peers,
            key: Arc::clone(&signer) as Arc<dyn LinkKeySource>,
            trust: Arc::new(DaemonTrust {
                keyring,
                own_certs,
                identity: Arc::clone(identity),
                engine: engine.clone(),
            }),
            faces: Arc::new(EngineFaces(engine.clone())),
            paths: Arc::new(ConfiguredEndpoints),
            candidates: vec![
                Arc::new(HostCandidates::default()),
                Arc::new(AdvertisedCandidates(advertised)),
            ],
            socket,
            transport,
            relays: RelayOptions {
                count: relays.count,
                use_namespace: relays.namespace,
                namespace_mode: link_mode(relays.mode, relays.idle_secs),
                namespace_hold: relays.hold,
            },
            service: relay_service(&config.relay_service)?,
            direct: DirectOptions {
                membership: config.direct.membership,
                max_paths: config.direct.max_paths,
            },
        },
        cancel.clone(),
    );
    let tokens = config
        .peers
        .iter()
        .map(|p| &p.wake_token)
        .chain(config.user_relays.iter().map(|r| &r.wake_token));
    for (i, token) in tokens.enumerate() {
        if let Some(token) = token {
            links.set_wake_token(PeerId(i), Some(Bytes::copy_from_slice(token.as_bytes())));
        }
    }
    tokio::spawn(follow_identity_changes(
        Arc::downgrade(&links),
        identity.changes(),
        cancel,
    ));
    Ok(Some(links))
}

/// Each time this device's identities change (it enrolled in a namespace,
/// a signing identity went, or the node key changed), its links show what
/// it holds now: enrollment links for a namespace it is now in, and links
/// whose hello showed other namespaces, are made again.
async fn follow_identity_changes(
    links: std::sync::Weak<Links>,
    mut changes: tokio::sync::watch::Receiver<u64>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            changed = changes.changed() => if changed.is_err() { return },
        }
        let Some(links) = links.upgrade() else { return };
        links.identities_changed();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `[[peer]] relay` naming a `[[relay]]` resolves to that relay's id,
    /// which follows the peers'; `[[relay]]` entries are relays the user
    /// added, with their mode.
    #[test]
    fn relays_follow_peers_and_peer_relay_references_resolve() {
        let fp = "ab".repeat(32);
        let config: ForwarderConfig = format!(
            "[[peer]]\ndevice = \"/home/member/phone\"\nrelay = \"{fp}\"\nmode = \"on-demand\"\nidle_secs = 30\n\
             [[relay]]\nkey = \"{fp}\"\nendpoint = \"relay.example.net:6367\"\npreference = 3\nmode = \"off\"\n"
        )
        .parse()
        .unwrap();
        let specs = peer_specs(&config).unwrap();
        assert_eq!(specs[0].relay, Some(PeerId(1)));
        assert_eq!(
            specs[0].mode,
            LinkMode::OnDemand {
                idle: Duration::from_secs(30)
            }
        );
        assert_eq!(
            specs[1].relay_use,
            Some(RelayUse {
                source: RelaySource::User,
                preference: 3
            })
        );
        assert_eq!(specs[1].mode, LinkMode::Off);
    }
}
