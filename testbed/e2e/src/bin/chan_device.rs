//! `chan-device` — one device of the `channels` scenario: a process that is a forwarder, its QUIC
//! links and the device's data layer, driven by lines on stdin, answered by one JSON object per
//! line on stdout.
//!
//! **Why this is not an `ndn-fwd` daemon with `ndn-heap` beside it.** A channel frame is not an NDN
//! packet: it travels the forwarder's side table (`ndn_engine::side`), and the unix-socket and
//! shared-memory faces of a daemon frame what they carry as TLV packets, which a channel frame
//! (marker octet `0x00`) is not. `ndn_app::IpcConnection::send_side` says so and refuses. The heap
//! node of a channel device therefore runs over an *embedded* engine (`EngineAppExt::app_face`),
//! as `ndn-ext`'s `chan_relay` example runs it; what this process adds to that example is the rest
//! of what a daemon does for a device, from the same crates the daemon uses:
//!
//! - the device's key, certificates and trust contexts from the PIB `ndn-fwd init` and `adopt`
//!   wrote (`SecurityManager::from_pib`, `ndn_cert::load_persisted_contexts`);
//! - the links: `ndn_link::Links` over a `LinkEndpoint` bound to this device's address, the
//!   admission by key and certificate chain, the routes the library installs, `EngineFaces`
//!   as the face sink: the code of `ndn-fwd`'s `links.rs`, with this device's relay (`--relay-*`:
//!   what `[[relay]]` is in a daemon's config) and, for a device that is itself a relay for
//!   another (`--serve-root`: `[relay_service] serve = "listed"` with no quotas), the people it
//!   serves;
//! - the validator of the heap node, with a certificate fetcher over the engine.
//!
//! The relay in the scenario is a real `ndn-fwd` daemon.
//!
//! Verbs (words separated by spaces; `text` is the rest of the line):
//!
//! | verb | answer |
//! |---|---|
//! | `create <space> readers=<ns,…> [writers=<ns,…>]` | the space |
//! | `open <space>` | the space is open here (an error that says `retry` until its record is held) |
//! | `put <space> <path> <text>` | the entry's id |
//! | `item <space> <path>` | the value at the path (`null`: none yet) |
//! | `get <space> <sender device> [verified]` | takes the channel: an `Items`, then the signed ask (asked again while it says retry); the channel's id, mode and checkpoint period. The `Items`' deliveries are printed as `{"ev":"got",…}` and its notices as `{"ev":"notice",…}` |
//! | `leave` | drops the `Items` (the receiver leaves the channel) |
//! | `emit <space> <path> <count> <gap ms> <prefix>` | `count` messages `<prefix>-<i>` of `Heap::emit`, `gap` apart |
//! | `watch <space>` | alerts of the space as `{"ev":"alert",…}` |
//! | `evidence` | the node's channel evidence |
//! | `side` | the forwarder's side table, as `side/list` writes it |
//! | `links` | each link's side-path counters and the faces of the forwarder |
//! | `forge <channel hex> <seq> <name id> <path> <face id> <text>` | seals a frame as a holder of the key and sends it on a face of this forwarder |
//! | `quit` | ends |

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::EngineAppExt;
use ndn_engine::{EngineBuilder, EngineConfig, ForwarderEngine};
use ndn_face_quic::{KeyFingerprint, LinkEndpoint, LinkKey, LinkKeySource, LinkTransportConfig};
use ndn_heap::{
    Alert, Change, Config, EmitOptions, Frontier, GetNotice, GetOptions, Heap, Items, Kind,
    LiveEnd, Name, Node, Readers, Select, Share, Transport, Trust,
};
use ndn_link::{
    ConfiguredEndpoints, DirectOptions, EngineFaces, LinkSetup, LinkTrust, Links, PeerSpec,
    RelayOptions, RelayService, RelaySource, RelayUse, ServePolicy,
};
use ndn_namespace::publish::OwnCertificates;
use ndn_security::{
    CertCache, Certificate, FilePib, Keyring, SecurityManager, SecurityProfile, Validator,
};
use ndn_sync::{DataStore, MemoryStore};
use ndn_transport::SideClass;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Longest certificate chain the validator walks (device → CA → root).
const MAX_CHAIN: usize = 5;
/// How long `get` asks again while the ask says to (the space's record or a key not held yet).
const ASK_WITHIN: Duration = Duration::from_secs(45);

type Fail = Box<dyn std::error::Error + Send + Sync>;

fn name(s: &str) -> Result<Name, String> {
    s.parse::<Name>()
        .map_err(|e| format!("{s:?} is not a name: {e}"))
}

fn names(list: &str) -> Result<Vec<Name>, String> {
    list.split(',')
        .filter(|s| !s.is_empty())
        .map(name)
        .collect()
}

struct Args {
    device: Name,
    pib: PathBuf,
    bind: SocketAddr,
    listen: bool,
    relay: Option<RelayArg>,
    serve_roots: Vec<KeyFingerprint>,
    sync_ms: u64,
    checkpoint_ms: u64,
}

struct RelayArg {
    key: KeyFingerprint,
    device: Name,
    endpoint: String,
}

fn args() -> Result<Args, String> {
    let (mut device, mut pib, mut bind, mut listen) = (None, None, None, false);
    let (mut relay_key, mut relay_device, mut relay_endpoint) = (None, None, None);
    let (mut serve_roots, mut sync_ms, mut checkpoint_ms) = (Vec::new(), 250, 20);
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = || it.next().ok_or(format!("{arg} needs a value"));
        let fp = |hex: String| {
            KeyFingerprint::from_hex(&hex).ok_or_else(|| format!("{hex:?} is not a fingerprint"))
        };
        match arg.as_str() {
            "--device" => device = Some(name(&value()?)?),
            "--pib" => pib = Some(PathBuf::from(value()?)),
            "--bind" => bind = Some(value()?.parse::<SocketAddr>().map_err(|e| e.to_string())?),
            "--listen" => listen = true,
            "--relay-key" => relay_key = Some(fp(value()?)?),
            "--relay-device" => relay_device = Some(name(&value()?)?),
            "--relay-endpoint" => relay_endpoint = Some(value()?),
            "--serve-root" => serve_roots.push(fp(value()?)?),
            "--sync-interval-ms" => sync_ms = value()?.parse().map_err(|e| format!("{e}"))?,
            "--checkpoint-ms" => checkpoint_ms = value()?.parse().map_err(|e| format!("{e}"))?,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let relay = match (relay_key, relay_device, relay_endpoint) {
        (Some(key), Some(device), Some(endpoint)) => Some(RelayArg {
            key,
            device,
            endpoint,
        }),
        (None, None, None) => None,
        _ => return Err("--relay-key, --relay-device and --relay-endpoint go together".into()),
    };
    Ok(Args {
        device: device.ok_or("--device is required")?,
        pib: pib.ok_or("--pib is required")?,
        bind: bind.ok_or("--bind is required")?,
        listen,
        relay,
        serve_roots,
        sync_ms,
        checkpoint_ms,
    })
}

/// The trust the links show and judge by: the keyring of the PIB's contexts, and the chain of the
/// device's key that the PIB stores.
struct DeviceTrust {
    keyring: Arc<Keyring>,
    own_certs: Arc<OwnCertificates>,
    signing_key: Name,
}

impl LinkTrust for DeviceTrust {
    fn keyring(&self) -> &Arc<Keyring> {
        &self.keyring
    }

    fn own_chain(&self) -> Vec<Bytes> {
        self.own_certs.chain_of(&self.signing_key)
    }

    fn known_certificate(&self, name: &Name) -> Option<Certificate> {
        self.own_certs.certificate(name)
    }

    fn known_certificate_of_key(&self, _: &KeyFingerprint) -> Option<Certificate> {
        None
    }
}

/// The certificate Data the PIB stores: every valid certificate of each key, the CA and device
/// certificates of a root device, and the issuer certificates kept beside the PIB (what the
/// daemon serves, `own_certs.rs`).
fn stored_certificates(pib: &FilePib) -> Vec<Bytes> {
    use ndn_cert::namespace::{CA_CERT_FILE, CA_DIR, DEVICE_CERT_FILE};
    let mut certs: Vec<Bytes> = pib
        .list_keys()
        .unwrap_or_default()
        .iter()
        .flat_map(|key| pib.valid_cert_wires(key).unwrap_or_default())
        .collect();
    let legacy = pib.root().join(CA_DIR);
    let mut dirs = vec![legacy.clone()];
    if let Ok(entries) = std::fs::read_dir(&legacy) {
        dirs.extend(
            entries
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.join(CA_CERT_FILE).is_file()),
        );
    }
    for dir in dirs {
        for file in [CA_CERT_FILE, DEVICE_CERT_FILE] {
            if let Ok(wire) = std::fs::read(dir.join(file)) {
                certs.push(Bytes::from(wire));
            }
        }
    }
    certs.extend(ndn_cert::issuers::stored_issuer_certs(pib.root()));
    certs
}

/// What the device holds: its forwarder, links and heap node, and the channel it takes.
struct Device {
    engine: ForwarderEngine,
    links: Arc<Links>,
    node: Node,
    heaps: std::sync::Mutex<Vec<(Name, Heap)>>,
    taken: std::sync::Mutex<Option<Taken>>,
    watchers: std::sync::Mutex<Vec<JoinHandle<()>>>,
}

struct Taken {
    reader: JoinHandle<()>,
}

/// An error line: what happened, whether to ask again, and what to do.
fn failure(message: impl std::fmt::Display, retry: bool) -> Value {
    json!({"message": message.to_string(), "retry": retry})
}

fn heap_failure(e: &ndn_heap::HeapError) -> Value {
    failure(e, matches!(e.next(), ndn_heap::NextStep::RetryLater))
}

impl Device {
    async fn heap(&self, space: &Name) -> Result<Heap, Value> {
        if let Some((_, h)) = self
            .heaps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|(s, _)| s == space)
        {
            return Ok(h.clone());
        }
        match self.node.space(space) {
            Some(h) => Ok(h),
            None => Err(failure(
                format!("{space} is not open here: `open` it (or `create` it) first"),
                false,
            )),
        }
    }

    /// Tell the relays this device uses the space groups of the spaces open here (what a daemon's
    /// links do for the spaces an `ndn-heap` host follows: `Links::set_followed_groups`): a relay
    /// routes exactly those groups over this device's link, so the sync notices of a space
    /// reach it through the relay.
    fn follow_spaces(&self) -> Result<(), Value> {
        let spaces = self.node.spaces();
        let groups = spaces.iter().filter_map(ndn_heap::wire::sync_group_of);
        self.links.set_followed_groups(groups).map_err(|e| {
            failure(
                format!("the relays were not told the spaces followed: {e}"),
                false,
            )
        })
    }

    /// The side table as `side/list` writes it (`ndn-mgmt`'s `modules/side.rs`).
    fn side_text(&self) -> String {
        let side = self.engine.side();
        let s = side.stats();
        let mut text = String::new();
        let _ = writeln!(
            text,
            "routes={} sinks={} frames_in={} bytes_in={} frames_out={} bytes_out={}",
            s.routes, s.sinks, s.frames_in, s.bytes_in, s.frames_out, s.bytes_out
        );
        let _ = writeln!(
            text,
            "drops: unrouted={} wrong_source={} malformed={} class_unsupported={} quota={} \
             quarantined={} sink_full={} sink_error={}",
            s.unrouted,
            s.wrong_source,
            s.malformed,
            s.class_unsupported,
            s.quota,
            s.quarantined,
            s.sink_full,
            s.sink_error
        );
        for route in side.list() {
            let sinks: Vec<String> = route
                .sinks
                .iter()
                .map(|k| format!("{}({:.1}s)", k.face.0, k.expires_in.as_secs_f64()))
                .collect();
            let _ = writeln!(
                text,
                "route id={:016x} source={} sinks=[{}] frames={} bytes={} age={:.1}s",
                route.id,
                route.source.0,
                sinks.join(" "),
                route.frames,
                route.bytes,
                route.age.as_secs_f64()
            );
        }
        let now = side.now();
        for (face, until) in side.quarantined() {
            let _ = writeln!(
                text,
                "quarantined face={} remaining={:.1}s",
                face.0,
                Duration::from_nanos(until.saturating_sub(now)).as_secs_f64()
            );
        }
        text
    }

    fn faces(&self) -> Vec<Value> {
        self.engine
            .faces()
            .face_ids()
            .into_iter()
            .filter_map(|id| self.engine.faces().get(id))
            .map(|f| {
                json!({
                    "id": f.id().0,
                    "kind": format!("{:?}", f.kind()),
                    "remote": f.remote_uri(),
                })
            })
            .collect()
    }

    fn link_report(&self) -> Value {
        let report = self.links.report();
        let links: Vec<Value> = report
            .links
            .iter()
            .map(|l| {
                let s = &l.side;
                json!({
                    "device": l.device.as_ref().map(ToString::to_string),
                    "key": l.key.map(|k| k.to_string()),
                    "linked": !l.paths.is_empty(),
                    "side": {
                        "datagram_tx_frames": s.datagram_tx_frames,
                        "datagram_rx_frames": s.datagram_rx_frames,
                        "stream_tx_frames": s.stream_tx_frames,
                        "stream_rx_frames": s.stream_rx_frames,
                        "refused": s.refused,
                        "dropped_over_quota": s.dropped_over_quota,
                    },
                })
            })
            .collect();
        json!({"links": links, "faces": self.faces()})
    }
}

fn print(v: &Value) {
    println!("{v}");
}

fn got_event(g: &ndn_heap::Got) -> Value {
    let seq = match &g.kind {
        Kind::Emitted(e) => Some(e.seq),
        _ => None,
    };
    json!({
        "ev": "got",
        "path": g.path.to_string(),
        "text": String::from_utf8_lossy(&g.bytes),
        "seq": seq,
        "writer": g.writer.to_string(),
    })
}

fn notice_event(n: &GetNotice) -> Value {
    match n {
        GetNotice::Lagged { missed } => json!({"ev": "notice", "kind": "lagged", "missed": missed}),
        GetNotice::LiveEnded(end) => {
            let (kind, why) = match end {
                LiveEnd::Ended { reason, .. } => ("ended", format!("{reason:?}")),
                LiveEnd::NoPath { why } => ("no-path", why.clone()),
            };
            json!({"ev": "notice", "kind": "live-ended", "end": kind, "why": why})
        }
        GetNotice::Retracted { writer, from, to } => json!({
            "ev": "notice", "kind": "retracted", "writer": writer.to_string(),
            "from": from, "to": to,
        }),
    }
}

fn alert_event(a: &Alert) -> Value {
    match a {
        Alert::ChannelForgery {
            writer,
            channel,
            key_epoch,
            seq,
            via,
        } => json!({
            "ev": "alert", "kind": "channel-forgery", "writer": writer.to_string(),
            "channel": format!("{channel:016x}"), "key_epoch": key_epoch, "seq": seq, "via": via.0,
        }),
        other => json!({"ev": "alert", "kind": "other", "debug": format!("{other:?}")}),
    }
}

async fn run(d: &Arc<Device>, line: &str) -> Result<Value, Value> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let bad = |m: &str| failure(m, false);
    let nm = |s: &str| name(s).map_err(|e| failure(e, false));
    match words.as_slice() {
        ["create", space, options @ ..] => {
            let space = nm(space)?;
            let (mut readers, mut writers) = (Vec::new(), Vec::new());
            for o in options {
                match o.split_once('=') {
                    Some(("readers", v)) => readers = names(v).map_err(|e| bad(&e))?,
                    Some(("writers", v)) => writers = names(v).map_err(|e| bad(&e))?,
                    _ => return Err(bad("create <space> readers=<ns,…> [writers=<ns,…>]")),
                }
            }
            let heap = d
                .node
                .create(
                    &space,
                    Share {
                        readers: Readers::Persons(readers),
                        writers,
                    },
                )
                .await
                .map_err(|e| heap_failure(&e))?;
            d.heaps
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((space.clone(), heap));
            d.follow_spaces()?;
            Ok(json!({"space": space.to_string()}))
        }
        ["open", space] => {
            let space = nm(space)?;
            let heap = d.node.open(&space).await.map_err(|e| heap_failure(&e))?;
            d.heaps
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((space.clone(), heap));
            d.follow_spaces()?;
            Ok(json!({"space": space.to_string()}))
        }
        ["put", space, path, text @ ..] => {
            let heap = d.heap(&nm(space)?).await?;
            let id = heap
                .put(
                    &nm(path)?,
                    Bytes::from(text.join(" ")),
                    ndn_heap::PutOptions::default(),
                )
                .await
                .map_err(|e| heap_failure(&e))?;
            Ok(json!({"seq": id.seq, "device": id.device.to_string()}))
        }
        ["item", space, path] => {
            let heap = d.heap(&nm(space)?).await?;
            let item = heap.get(&nm(path)?).await.map_err(|e| heap_failure(&e))?;
            Ok(json!({"item": item.map(|i| json!({
                "text": String::from_utf8_lossy(&i.bytes),
                "writer": i.writer.to_string(),
            }))}))
        }
        ["get", space, sender, rest @ ..] => {
            let (space, sender) = (nm(space)?, nm(sender)?);
            let heap = d.heap(&space).await?;
            let mut opts = GetOptions::default();
            if rest.first() == Some(&"verified") {
                opts.trust = Trust::Verified;
            }
            if d.taken
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_some()
            {
                return Err(bad("this device already takes a channel: `leave` first"));
            }
            // An `Items` first, then the ask: a session lapses with its last taker.
            let mut items: Items = heap
                .live(Select::Prefix(Name::root()), opts)
                .map_err(|e| heap_failure(&e))?;
            let handle = d.node.handle();
            let deadline = tokio::time::Instant::now() + ASK_WITHIN;
            let info = loop {
                match handle.ask_channel(&space, &sender).await {
                    Ok(info) => break info,
                    Err(e) => {
                        let retry = matches!(e.next(), ndn_heap::NextStep::RetryLater);
                        if !retry || tokio::time::Instant::now() >= deadline {
                            return Err(failure(
                                format!(
                                    "the ask of {sender} for a channel in {space}: {e} (next: {:?})",
                                    e.next()
                                ),
                                false,
                            ));
                        }
                        tracing::info!("the ask of {sender} is asked again: {e}");
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            };
            let reader = tokio::spawn(async move {
                while let Some(next) = items.next().await {
                    print(&match &next {
                        Ok(got) => got_event(got),
                        Err(notice) => notice_event(notice),
                    });
                }
            });
            *d.taken
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Taken { reader });
            Ok(json!({
                "channel": format!("{:016x}", info.channel),
                "mode": format!("{:?}", info.mode),
                "checkpoint_ms": info.checkpoint.map(|p| p.as_millis() as u64),
            }))
        }
        ["leave"] => {
            let taken = d
                .taken
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            let Some(taken) = taken else {
                return Err(bad("this device takes no channel"));
            };
            // Aborting the reader drops the `Items`, the receiver's end of the channel.
            taken.reader.abort();
            let _ = taken.reader.await;
            Ok(json!({}))
        }
        ["emit", space, path, count, gap_ms, prefix] => {
            let heap = d.heap(&nm(space)?).await?;
            let path = nm(path)?;
            let count: u64 = count.parse().map_err(|_| bad("count is a number"))?;
            let gap: u64 = gap_ms.parse().map_err(|_| bad("gap is a number of ms"))?;
            for i in 0..count {
                heap.emit(
                    &path,
                    Bytes::from(format!("{prefix}-{i}")),
                    EmitOptions::latest(),
                )
                .await
                .map_err(|e| failure(format!("emit {i}: {e}"), false))?;
                tokio::time::sleep(Duration::from_millis(gap)).await;
            }
            Ok(json!({"sent": count}))
        }
        ["watch", space] => {
            let space = nm(space)?;
            let heap = d.heap(&space).await?;
            let mut changes = heap
                .watch(&Frontier::new())
                .await
                .map_err(|e| heap_failure(&e))?;
            let task = tokio::spawn(async move {
                while let Some(change) = changes.next().await {
                    if let Ok(Change::Alert(a)) = change {
                        print(&alert_event(&a));
                    }
                }
            });
            d.watchers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(task);
            Ok(json!({}))
        }
        ["evidence"] => {
            let evidence: Vec<Value> = d
                .node
                .channel_evidence()
                .iter()
                .map(|e| {
                    json!({
                        "kind": format!("{:?}", e.kind),
                        "channel": format!("{:016x}", e.channel),
                        "seq0": e.seq0,
                        "ingress": e.ingress.0,
                    })
                })
                .collect();
            Ok(json!({"evidence": evidence}))
        }
        ["side"] => Ok(json!({"text": d.side_text()})),
        ["links"] => Ok(d.link_report()),
        ["forge", channel, seq, name_id, path, face, text @ ..] => {
            let channel = u64::from_str_radix(channel, 16).map_err(|_| bad("channel is hex"))?;
            let seq: u64 = seq.parse().map_err(|_| bad("seq is a number"))?;
            let name_id: u64 = name_id.parse().map_err(|_| bad("name id is a number"))?;
            let face: u64 = face.parse().map_err(|_| bad("face id is a number"))?;
            let frame = d
                .node
                .handle()
                .adversary_data_frame(channel, seq, name_id, &nm(path)?, text.join(" ").as_bytes())
                .ok_or_else(|| bad("this device holds no usable session of that channel"))?;
            let face = d
                .engine
                .faces()
                .get(ndn_transport::FaceId(face))
                .ok_or_else(|| bad("no such face on this forwarder (see `links`)"))?;
            face.send_side(frame, SideClass::Datagram)
                .await
                .map_err(|e| failure(format!("the face did not take the frame: {e:?}"), false))?;
            Ok(json!({"forged_seq": seq}))
        }
        _ => Err(bad(&format!("unknown verb or arguments: {line}"))),
    }
}

async fn start(a: &Args) -> Result<Arc<Device>, Fail> {
    let pib = FilePib::open(&a.pib).map_err(|e| format!("open PIB {}: {e}", a.pib.display()))?;
    let keys = SecurityManager::from_pib(&pib, &a.device)
        .map_err(|e| format!("PIB {}: {e}", a.pib.display()))?;
    ndn_cert::load_persisted_contexts(pib.root(), keys.keyring())
        .map_err(|e| format!("PIB {}: {e}", a.pib.display()))?;
    let keys = Arc::new(keys);
    let keyring = Arc::clone(keys.keyring());
    let signer = keys.identity_signer(&a.device)?;
    let signing_key = signer.key_name().clone();

    let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
        .security_profile(SecurityProfile::Disabled)
        .build()
        .await?;
    shutdown.detach();
    let cancel = CancellationToken::new();
    // Each namespace this device holds runs its sync group with the multicast strategy, as the
    // trust-context library does in a daemon.
    for context in keyring.contexts() {
        if !context.namespace().is_empty() {
            ndn_namespace::sync_group::carry(&engine, context.namespace());
        }
    }
    let own_certs = OwnCertificates::spawn(
        &engine,
        stored_certificates(&pib),
        std::slice::from_ref(&signing_key),
        &keyring,
        cancel.child_token(),
    );

    // The links.
    let link_key = LinkKey::from_signer(Arc::clone(&signer))?;
    let mut peers = Vec::new();
    if let Some(relay) = &a.relay {
        peers.push(PeerSpec {
            label: relay.device.to_string(),
            key: Some(relay.key),
            device: Some(relay.device.clone()),
            endpoints: vec![relay.endpoint.clone()],
            relay_use: Some(RelayUse {
                source: RelaySource::User,
                preference: 0,
            }),
            ..PeerSpec::default()
        });
    }
    let transport = LinkTransportConfig::default();
    let source: Arc<dyn LinkKeySource> = Arc::new(link_key);
    let socket = Arc::new(LinkEndpoint::bind(
        a.bind,
        Arc::clone(&source),
        &transport,
        a.listen,
    )?);
    let service = RelayService {
        serve: if a.serve_roots.is_empty() {
            ServePolicy::Own
        } else {
            ServePolicy::Listed {
                roots: a.serve_roots.clone(),
                quotas: None,
            }
        },
        ..RelayService::default()
    };
    let links = Links::start(
        LinkSetup {
            peers,
            key: source,
            trust: Arc::new(DeviceTrust {
                keyring: Arc::clone(&keyring),
                own_certs,
                signing_key,
            }),
            faces: Arc::new(EngineFaces(engine.clone())),
            paths: Arc::new(ConfiguredEndpoints),
            candidates: Vec::new(),
            socket: Some(socket),
            transport,
            relays: RelayOptions {
                use_namespace: false,
                ..RelayOptions::default()
            },
            service,
            direct: DirectOptions {
                membership: false,
                ..DirectOptions::default()
            },
            reliability: Default::default(),
        },
        cancel.child_token(),
    );

    // The data layer, over an app face of the embedded engine.
    let cache: Arc<CertCache> = keys.cert_cache_arc();
    let fetcher = ndn_app::engine_cert_fetcher(&engine, Arc::clone(&cache), cancel.child_token());
    let validator = Arc::new(Validator::with_keyring(
        Arc::clone(&keyring),
        cache,
        Some(fetcher),
        MAX_CHAIN,
    ));
    let mut config = Config::new();
    config.svs.sync_interval = Duration::from_millis(a.sync_ms);
    config.channel.checkpoint = Duration::from_millis(a.checkpoint_ms);
    let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
    let node = Node::start(
        Transport {
            sync: engine.app_face(cancel.child_token()),
            node: engine.app_node(cancel.child_token()),
        },
        a.device.clone(),
        keys,
        validator,
        store,
        config,
    )
    .await
    .map_err(|e| format!("{}: {e}", a.device))?;
    node.attach_forwarder()
        .map_err(|e| format!("the engine's app face carries channel frames: {e}"))?;
    Ok(Arc::new(Device {
        engine,
        links,
        node,
        heaps: Default::default(),
        taken: Default::default(),
        watchers: Default::default(),
    }))
}

#[tokio::main]
async fn main() {
    tracing_init();
    let args = match args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("chan-device: {e}");
            std::process::exit(2);
        }
    };
    let device = match start(&args).await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("chan-device: {e}");
            std::process::exit(1);
        }
    };
    let key = device
        .links
        .report()
        .key
        .map(|k| k.to_string())
        .unwrap_or_default();
    print(&json!({"ready": {
        "device": args.device.to_string(),
        "writer": device.node.writer().to_string(),
        "link_key": key,
        "bind": args.bind.to_string(),
    }}));
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == "quit" {
            break;
        }
        let verb = line.split_whitespace().next().unwrap_or_default();
        let answer = match run(&device, line).await {
            Ok(ok) => json!({"verb": verb, "ok": ok}),
            Err(error) => json!({"verb": verb, "error": error}),
        };
        print(&answer);
    }
    device.node.shutdown();
}

/// Tracing to stderr, filtered by `RUST_LOG` (the harness appends stderr to the device's log).
fn tracing_init() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}
