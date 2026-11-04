//! `ndn-data` — host one device's data layer (`ndn_data::Device`) on a
//! running `ndn-fwd` and drive its verbs as lines on stdin, one JSON object
//! per line on stdout.
//!
//! Why a tool and not the daemon: the data layer's verbs over forwarder
//! management are slice 7 of the data-layer plan; until then a separate
//! process attached over the face socket exposes them on a real daemon while
//! ndn-fwd itself carries no data-layer code. It wires the library and does
//! nothing else: the device's key and trust contexts come from the daemon's
//! PIB exactly as `ndn-put --pib` loads them, and the device's X25519 seal
//! (recipient) secret is kept in that PIB beside its key
//! (`SecurityManager::put_secret`), made on the first run; the validator is
//! the trust contexts' keyring (their anchors and schemas) with a
//! certificate fetcher over the device's own connection, so a peer's
//! certificate chain is fetched and walked to the anchor on first use. The
//! keyring follows the PIB: every second the host adopts each
//! newer version the daemon stored there (a revocation it pulled or was
//! pushed, one `ndn-fwd revoke` or `readmit` signed), and the data layer
//! re-checks what it holds against it (a version a new revocation's cut
//! does not accept is withdrawn; one it re-admits is fetched and
//! delivered). Entries live in memory for the life of the process, and with
//! `--store <dir>` also one file each under `<dir>`, so a host started again
//! on the same directory resumes its log (and its key's sequence) where it
//! stopped.
//!
//! `--clock-offset-ms <ms>` runs the device's wall clock that many
//! milliseconds off the system's (negative: behind). It changes only the
//! dates the device writes into its versions (`dated_ms`), never what any
//! device accepts: validity of data does not depend on a clock.
//!
//! Two connections to the forwarder: a `Node` (fetching, and serving the
//! device's prefix) and a second one for State Vector Sync. A forwarder
//! client's one reader splits its management replies off its data, so a
//! prefix the layer registers while its receive loops run is answered to the
//! registration, not to them. The namespace's sync group `<ns>/32=sync`
//! needs nothing set up: a daemon holding the namespace's trust context
//! runs it with the `multicast` strategy and routes it over each link to a
//! device of the namespace (data-layer spec §12), beside this connection's
//! registration of it; the other devices' prefixes are routed to them as
//! those links route them.
//!
//! The device's namespace `<ns>` is that of the trust context governing its
//! name in the PIB (`/nt` for `/nt/member/phone`; `/home/bob` for
//! `/home/bob/member/phone` once the PIB holds `/home/bob`'s context). A
//! collection is named `<ns>/32=data/<path>` (`/home/bob/32=data/notes/trip`):
//! the keyword `32=data` marks where the namespace ends. A folder is
//! `<ns>/32=data[/<path>]`; a name without the marker is refused with why.
//!
//! Verbs (one per line; values with spaces in double quotes, `\"` and `\\`
//! escaped inside them):
//!
//! - `share <collection> [rule=merge|log|one-key] [writers=<prefix>,<prefix>...]
//!   [readers=<kind>:<name>,...]`: the members record of a collection of
//!   this device's namespace, its first revision or the next. `rule=merge`
//!   (the default) merges with `/merge/yrs`, `rule=log` keeps every member's
//!   versions (the newest is the latest), `rule=one-key` is written by
//!   exactly one key, which `writers=` names (a key name `<D>/KEY/<id>`, or
//!   this device's name for its own key), read through its signed head.
//!   Writers are key-name prefixes (default: `<ns>`); readers are
//!   `person:<namespace>`, `device:<device name>` or `group:<group name>`
//!   (default: `person:<ns>`), and a collection that lists readers is sealed
//!   to them; `readers=` with nothing after it lists none (not sealed).
//!   Sharing again without a writer or reader removes it: the owner cuts a
//!   removed writer at what this device has seen of it, and seals later
//!   versions in a new epoch a removed reader cannot open.
//! - `put <collection> [--batch <ms>] [--keep forever|until=<ms since the
//!   epoch>|last=<n>] <field>=<value>...`: a version of type `/types/note`
//!   revision 1, kept forever unless `--keep` says otherwise; an empty value
//!   removes the field. A value `@<path>` is the bytes of the file at
//!   `<path>` (`@@…` is a value starting with `@`). A payload larger than a
//!   version carries inline travels in pieces (log and one-key rules). With
//!   `--batch`, the entry waits up to that long in this device's open block
//!   (log and one-key rules: several entries under one signature) and the
//!   tool reads the next line meanwhile; the answer comes once the block is
//!   signed, naming the block, so answers to batched puts may come after
//!   answers to later lines. Every put answer shows the fields it put.
//! - `get <name>`: a collection's merged state (its newest version under
//!   the log and one-key rules), an exact version, state or entry
//!   (`<version>/32=entry/seg=<i>`) by its name, or the entries a range name
//!   (`<collection>/32=range/<range>`) selects. A field value longer than
//!   256 octets is shown as its length and SHA-256, not its bytes.
//! - `range <collection> seq=<low>..<high>|time=<from>..<to>`: `get` of the
//!   range name of a one-key collection: the blocks from seq `low` to `high`
//!   (both included), or the entries dated from `from` (included) to `to`
//!   (excluded), in ms since the epoch.
//! - `watch <collection or folder>`: from now on, every change as its own
//!   line (a version that expired here, too).
//! - `hold <collection> copies=<n> until=<ms since the epoch>
//!   holders=<device>[,<device>...]`: ask the named holder devices (at
//!   least `copies` of them, none this device) to keep the collection,
//!   audit every live lease and repair: the custody, each live lease (holder
//!   key, name, what it holds, until when, this device's last audit) and the
//!   leases this call found broken or unanswered, and the versions asked for
//!   that no kept lease holds and this device does not hold whole (`unkept`:
//!   lost unless a copy turns up).
//! - `prune <collection or version> upto=<writer key>:<seq>[,...]`: drop
//!   this device's own versions up to that point.
//! - `release <collection or version>`: drop this device's copies of the
//!   pieces of large versions once enough named holders prove, to a fresh
//!   audit over every piece while this device serves none of them, that
//!   they keep them (the host's storage policy): how many versions, pieces
//!   and octets, and the versions kept here (`kept`: each name with why).
//! - `cut <key> <file>`: the revocation cut of key `<key>` (`<id>/KEY/<k>`;
//!   a certificate name stands for its key) as this device holds it: every
//!   log entry of that key it holds verified and has not refused, as runs of
//!   seqs per collection (and for its snapshots), written to `<file>` as the
//!   RevocationCut TLV `ndn-fwd revoke <device> --cut <file>` takes. The
//!   answer lists the ranges.
//! - `refused <key>`: the full names (each ending in the implicit SHA-256
//!   digest of the refused packet) of every log entry of `<key>` this device
//!   holds refused because the key is revoked and its cut does not accept
//!   them — refused on arrival or withdrawn later; what `ndn-fwd readmit
//!   <key> <full name>...` takes to re-admit exactly those versions.
//! - `quit` (or end of input).
//!
//! Output lines: `{"ready":{…}}` once the layer runs; per verb
//! `{"verb":…,"ok":{…}}` or `{"verb":…,"error":{"message","retry","next",
//! "next_step"}}` (with `"pruned_by"`, the prune record, when the name was
//! pruned, `"expired"`, the name and its keep, when it expired, and
//! `"outside_cut"`, the revoked key and the cut's signer, when a revocation's
//! cut refuses it); per watched change `{"watch":<collection>,"change":{…}}`.
//! Logs go to stderr.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use clap::Parser;
use futures::StreamExt;
use futures::future::BoxFuture;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::task::JoinSet;

use ndn_app::{IpcConnection, Node, demux_cert_fetcher};
use ndn_data::wire::{Range, log_name, range_name};
use ndn_data::{
    Age, Answer, Audience, Audit, BlockEntry, Breach, Change, Config, Content, Custody, DataError,
    DataLayer, Device, Entries, Frontier, Got, Hold, Keep, Lease, NextStep, Payload, Prune,
    PutOptions, Refusal, Rule, Seq, Share, Timestamp, Transport, TypeId, Version, VersionId,
    Writer,
};
use ndn_ipc::ForwarderClient;
use ndn_packet::Name;
use ndn_security::{CertCache, FilePib, Keyring, RevocationCut, SecurityManager, Validator};
use ndn_sync::{DataStore, MemoryStore};

/// Longest certificate chain the validator walks (device → CA → root).
const MAX_CHAIN: usize = 5;

/// How often the host adopts the newer trust-context versions the daemon
/// stored in its PIB.
const CONTEXT_POLL: Duration = Duration::from_secs(1);

#[derive(Parser)]
#[command(
    name = "ndn-data",
    about = "Host one device's data layer on a running ndn-fwd; verbs on stdin, JSON on stdout"
)]
struct Cli {
    /// The device: its key must be `<device>/KEY/<id>` in the PIB, with a
    /// currently valid certificate (e.g. `/alice/member/phone`, as `ndn-fwd
    /// enroll` certified it).
    #[arg(long)]
    device: String,

    /// The daemon's PIB directory: the device's key and the trust contexts.
    #[arg(long)]
    pib: String,

    /// State Vector Sync's periodic interval in milliseconds (default: SVS's
    /// 30 s). Performance only: how soon devices that were apart notice.
    #[arg(long)]
    sync_interval_ms: Option<u64>,

    /// Keep the device's entries under this directory too (one file each),
    /// so a host started again on it resumes its log where it stopped
    /// (default: in memory only, for the life of the process).
    #[arg(long)]
    store: Option<PathBuf>,

    /// Run the device's wall clock this many milliseconds off the system's
    /// (negative: behind). Only the dates it writes change.
    #[arg(long, default_value_t = 0, allow_negative_numbers = true)]
    clock_offset_ms: i64,

    #[arg(long, default_value_t = ndn_config::ManagementConfig::default().face_socket)]
    face_socket: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    let device: Name = cli
        .device
        .parse()
        .map_err(|e| anyhow!("--device {:?}: {e}", cli.device))?;

    let pib = FilePib::open(&cli.pib).map_err(|e| anyhow!("open PIB {}: {e}", cli.pib))?;
    let keys = SecurityManager::from_pib(&pib, &device).map_err(|e| {
        anyhow!(
            "PIB {}: {e}; enroll this device as {device} first (`ndn-fwd enroll`)",
            cli.pib
        )
    })?;
    ndn_cert::load_persisted_contexts(pib.root(), keys.keyring())
        .map_err(|e| anyhow!("PIB {}: {e}", cli.pib))?;
    let keys = Arc::new(keys);
    let keyring = Arc::clone(keys.keyring());

    let node = Node::connect(&cli.face_socket)
        .await
        .map_err(|e| anyhow!("connect to the forwarder at {}: {e}", cli.face_socket))?;
    let sync = ForwarderClient::connect(&cli.face_socket)
        .await
        .map_err(|e| anyhow!("connect to the forwarder at {}: {e}", cli.face_socket))?;
    let sync = Arc::new(IpcConnection::new(sync));

    let cache = Arc::new(CertCache::new());
    let fetcher = demux_cert_fetcher(node.demux(), Arc::clone(&cache));
    let validator = Arc::new(Validator::with_keyring(
        Arc::clone(keys.keyring()),
        cache,
        Some(fetcher),
        MAX_CHAIN,
    ));

    let mut config = Config::new();
    if let Some(ms) = cli.sync_interval_ms {
        config.svs.sync_interval = Duration::from_millis(ms);
    }
    if cli.clock_offset_ms != 0 {
        let system = Arc::clone(&config.clock);
        let offset = cli.clock_offset_ms;
        config.clock = Arc::new(move || Timestamp(system().0.saturating_add_signed(offset)));
    }
    let store: Arc<dyn DataStore> = match &cli.store {
        Some(dir) => Arc::new(DirStore::open(dir)?),
        None => Arc::new(MemoryStore::new()),
    };
    let layer = Device::start(
        Transport { node, sync },
        device.clone(),
        keys,
        validator,
        store,
        config,
    )
    .await
    .map_err(|e| anyhow!("{device}: {e} (next: {})", next_step(e.next())))?;
    // After the layer listens on the keyring: every newer version adopted
    // from here on re-checks what it holds.
    tokio::spawn(follow_contexts(pib.root().to_path_buf(), keyring));
    println!(
        "{}",
        json!({"ready": {"device": device.to_string(), "writer": layer.writer().key().to_string()}})
    );

    // Batched puts in flight: each prints its answer once its block is
    // signed, while the next lines are read.
    let mut later = JoinSet::new();
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await.context("read stdin")? {
        while later.try_join_next().is_some() {}
        let words = match split(&line) {
            Ok(w) => w,
            Err(e) => {
                println!("{}", usage_error("", &e));
                continue;
            }
        };
        let Some((verb, args)) = words.split_first() else {
            continue;
        };
        if verb == "quit" {
            break;
        }
        let answer = match run(&layer, verb, args).await {
            Ok(Verb::Done(ok)) => json!({"verb": verb, "ok": ok}),
            Ok(Verb::Later(answer)) => {
                let verb = verb.clone();
                later.spawn(async move {
                    let line = match answer.await {
                        Ok(ok) => json!({"verb": verb, "ok": ok}),
                        Err(e) => json!({"verb": verb, "error": data_error(&e)}),
                    };
                    println!("{line}");
                });
                continue;
            }
            Ok(Verb::Usage(why)) => usage_error(verb, &why),
            Err(e) => json!({"verb": verb, "error": data_error(&e)}),
        };
        println!("{answer}");
    }
    // Every batched put still waiting answers before the layer stops.
    while later.join_next().await.is_some() {}
    layer.shutdown();
    Ok(())
}

/// Adopt, every [`CONTEXT_POLL`], each trust-context version stored in the
/// PIB at `pib_root` that is newer than the one `keyring` holds: the daemon
/// stores the versions it adopts (pulled, pushed, or signed there by `ndn-fwd
/// revoke`/`readmit`), and the data layer re-checks what it holds on each
/// adoption. Re-adopting a held version changes nothing; an older one is
/// refused by the keyring (no rollback).
async fn follow_contexts(pib_root: PathBuf, keyring: Arc<Keyring>) {
    let mut tick = tokio::time::interval(CONTEXT_POLL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        match ndn_cert::load_persisted_contexts(&pib_root, &keyring) {
            Ok(read) => {
                for (path, result) in read {
                    if let Err(e) = result {
                        tracing::debug!(path = %path.display(), "stored trust context not adopted: {e}");
                    }
                }
            }
            Err(e) => tracing::warn!(
                pib = %pib_root.display(),
                "trust contexts not read: {e}; newer versions the daemon stores are not \
                 followed until the PIB is readable again"
            ),
        }
    }
}

/// The host's store with `--store <dir>`: what the device keeps, in memory
/// for reads, and each entry also a file of `<dir>` (named by the SHA-256 of
/// its name; holding the name's TLV length as 4 octets big-endian, the
/// name's TLV, then the stored wire), written atomically and owner-only, so
/// a host started again on `<dir>` resumes what it held — its own log, and
/// with it its key's sequence.
struct DirStore {
    memory: MemoryStore,
    dir: PathBuf,
}

impl DirStore {
    /// Open `dir` (made if missing) and read back every entry stored there.
    fn open(dir: &Path) -> Result<Self> {
        ndn_security::secure_fs::create_private_dir_all(dir)
            .map_err(|e| anyhow!("--store {}: {e}", dir.display()))?;
        let memory = MemoryStore::new();
        let entries =
            std::fs::read_dir(dir).map_err(|e| anyhow!("--store {}: {e}", dir.display()))?;
        for entry in entries {
            let path = entry
                .map_err(|e| anyhow!("--store {}: {e}", dir.display()))?
                .path();
            // Skipped: a write's temporary file, cut short by a stop.
            if path.extension().is_none_or(|x| x != STORE_EXT) {
                continue;
            }
            let bytes = std::fs::read(&path).map_err(|e| anyhow!("{}: {e}", path.display()))?;
            let (name, wire) = Self::decode(Bytes::from(bytes)).ok_or_else(|| {
                anyhow!(
                    "{} is not an entry of this store; remove it, or start with another --store",
                    path.display()
                )
            })?;
            memory.insert(name, wire);
        }
        Ok(Self {
            memory,
            dir: dir.to_path_buf(),
        })
    }

    fn decode(bytes: Bytes) -> Option<(Name, Bytes)> {
        let len = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
        let end = 4usize.checked_add(len).filter(|&end| end <= bytes.len())?;
        let name = Name::decode_from_tlv(bytes.slice(4..end)).ok()?;
        Some((name, bytes.slice(end..)))
    }

    fn path(&self, name_tlv: &[u8]) -> PathBuf {
        self.dir
            .join(format!("{}.{STORE_EXT}", hex(&Sha256::digest(name_tlv))))
    }
}

/// The extension of a `--store` entry's file.
const STORE_EXT: &str = "entry";

impl DataStore for DirStore {
    fn insert(&self, name: Name, wire: Bytes) {
        let tlv = name.encode_to_tlv();
        let mut file = Vec::with_capacity(4 + tlv.len() + wire.len());
        file.extend_from_slice(&(tlv.len() as u32).to_be_bytes());
        file.extend_from_slice(&tlv);
        file.extend_from_slice(&wire);
        let path = self.path(&tlv);
        if let Err(e) = ndn_security::secure_fs::write_private(&path, &file) {
            tracing::error!(
                %name,
                path = %path.display(),
                "not written to the store: {e}; held in memory, but a host started again on \
                 this --store loses it: free space or fix the directory's permissions"
            );
        }
        self.memory.insert(name, wire);
    }

    fn get(&self, name: &Name) -> Option<Bytes> {
        self.memory.get(name)
    }

    fn contains(&self, name: &Name) -> bool {
        self.memory.contains(name)
    }

    fn find_under(&self, prefix: &Name) -> Option<Bytes> {
        self.memory.find_under(prefix)
    }

    fn scan_under(&self, prefix: &Name, limit: usize) -> Vec<(Name, Bytes)> {
        self.memory.scan_under(prefix, limit)
    }

    fn remove(&self, name: &Name) {
        self.memory.remove(name);
        let path = self.path(&name.encode_to_tlv());
        match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => tracing::error!(
                %name,
                path = %path.display(),
                "not removed from the store: {e}; a host started again on this --store holds \
                 it again: fix the directory's permissions"
            ),
            _ => {}
        }
    }
}

/// What one verb line came to.
enum Verb {
    Done(Value),
    /// Answered later, while the next lines are read (a batched put).
    Later(BoxFuture<'static, Result<Value, DataError>>),
    /// The line is not a verb this tool knows, or its arguments are wrong.
    Usage(String),
}

async fn run(layer: &Device, verb: &str, args: &[String]) -> Result<Verb, DataError> {
    let usage = |s: &str| Ok(Verb::Usage(s.to_owned()));
    let name = |s: &str| {
        s.parse::<Name>()
            .map_err(|e| format!("{s:?} is no name: {e}"))
    };
    match (verb, args) {
        ("share", [collection, options @ ..]) => {
            let collection = match name(collection) {
                Ok(c) => c,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let share = match share_options(layer.namespace(), options) {
                Ok(s) => s,
                Err(e) => return Ok(Verb::Usage(format!("{e}; {SHARE_USAGE}"))),
            };
            layer.share(&collection, share).await?;
            Ok(Verb::Done(json!({"collection": collection.to_string()})))
        }
        ("share", _) => usage(SHARE_USAGE),
        ("put", [collection, rest @ ..]) => {
            let collection = match name(collection) {
                Ok(c) => c,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let (keep, batch, fields) = match put_options(rest) {
                Ok(o) => o,
                Err(e) => return Ok(Verb::Usage(format!("{e}; {PUT_USAGE}"))),
            };
            let mut content = Content::new();
            for f in fields {
                let Some((field, value)) = f.split_once('=') else {
                    return usage(PUT_USAGE);
                };
                match field_value(value).await {
                    Ok(bytes) => content = content.with(field, bytes),
                    Err(e) => return Ok(Verb::Usage(format!("{field}: {e}; {PUT_USAGE}"))),
                }
            }
            let options = PutOptions {
                type_id: TypeId {
                    name: "/types/note".parse().expect("a valid name"),
                    revision: 1,
                },
                keep,
                batch,
            };
            let layer = layer.clone();
            let put = async move {
                let shown = self::content(&content);
                let id = layer.put(&collection, content, options).await?;
                let version = log_name(layer.name(), Some(&collection), id.seq.0);
                Ok(json!({
                    "writer": id.writer.key().to_string(),
                    "seq": id.seq.0,
                    "name": version.to_string(),
                    "fields": shown,
                }))
            };
            if batch.is_some() {
                Ok(Verb::Later(Box::pin(put)))
            } else {
                put.await.map(Verb::Done)
            }
        }
        ("put", _) => usage(PUT_USAGE),
        ("get", [n]) => {
            let n = match name(n) {
                Ok(n) => n,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            Ok(Verb::Done(answer(layer.get(&n).await?)))
        }
        ("get", _) => usage("usage: get <name>"),
        ("range", [collection, bounds]) => {
            let collection = match name(collection) {
                Ok(c) => c,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let range = match range_bounds(bounds) {
                Ok(r) => r,
                Err(e) => return Ok(Verb::Usage(format!("{e}; {RANGE_USAGE}"))),
            };
            let n = range_name(&collection, &range);
            let mut ok = answer(layer.get(&n).await?);
            ok["name"] = json!(n.to_string());
            Ok(Verb::Done(ok))
        }
        ("range", _) => usage(RANGE_USAGE),
        ("watch", [collection]) => {
            let collection = match name(collection) {
                Ok(c) => c,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let mut changes = layer.watch(&collection, &Frontier::new()).await?;
            let watched = collection.to_string();
            tokio::spawn(async move {
                while let Some(item) = changes.next().await {
                    let line = match item {
                        Ok(c) => json!({"watch": watched, "change": change(&c)}),
                        Err(e) => json!({"watch": watched, "error": data_error(&e)}),
                    };
                    println!("{line}");
                }
            });
            Ok(Verb::Done(json!({"collection": collection.to_string()})))
        }
        ("watch", _) => usage("usage: watch <collection>"),
        ("hold", [collection, options @ ..]) => {
            let collection = match name(collection) {
                Ok(c) => c,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let want = match hold_options(options) {
                Ok(h) => h,
                Err(e) => return Ok(Verb::Usage(format!("{e}; {HOLD_USAGE}"))),
            };
            let c = layer.hold(&collection, want).await?;
            Ok(Verb::Done(json!({"custody": custody(&c)})))
        }
        ("hold", _) => usage(HOLD_USAGE),
        ("prune", [prefix, upto]) => {
            let prefix = match name(prefix) {
                Ok(p) => p,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let upto = match upto_frontier(upto) {
                Ok(f) => f,
                Err(e) => return Ok(Verb::Usage(format!("{e}; {PRUNE_USAGE}"))),
            };
            layer.prune(&prefix, &upto).await?;
            Ok(Verb::Done(json!({
                "prefix": prefix.to_string(),
                "upto": frontier(&upto),
            })))
        }
        ("prune", _) => usage(PRUNE_USAGE),
        ("release", [n]) => {
            let n = match name(n) {
                Ok(n) => n,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let r = layer.release(&n).await?;
            Ok(Verb::Done(json!({
                "name": n.to_string(),
                "versions": r.versions,
                "pieces": r.pieces,
                "bytes": r.bytes,
                "kept": r
                    .kept
                    .iter()
                    .map(|(v, why)| json!({"name": v.to_string(), "why": why}))
                    .collect::<Vec<_>>(),
            })))
        }
        ("release", _) => usage("usage: release <collection or version>"),
        ("cut", [key, file]) => {
            let key = match name(key) {
                Ok(k) => k,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let cut = layer.revocation_cut(&key);
            if let Err(e) = std::fs::write(file, cut.encode()) {
                return Ok(Verb::Usage(format!(
                    "write {file}: {e}; name a file this host may write"
                )));
            }
            let mut ok = revocation_cut(&cut);
            ok["file"] = json!(file);
            Ok(Verb::Done(ok))
        }
        ("cut", _) => usage("usage: cut <key> <file>"),
        ("refused", [key]) => {
            let key = match name(key) {
                Ok(k) => k,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let names = layer.refused_by_revocation(&key);
            Ok(Verb::Done(json!({
                "key": key.to_string(),
                "names": names.iter().map(ToString::to_string).collect::<Vec<_>>(),
            })))
        }
        ("refused", _) => usage("usage: refused <key>"),
        _ => {
            usage("verbs: share, put, get, range, watch, hold, prune, release, cut, refused, quit")
        }
    }
}

const SHARE_USAGE: &str = "usage: share <collection> [rule=merge|log|one-key] \
                           [writers=<prefix>,<prefix>...] [readers=<kind>:<name>,...] (kind \
                           person, device or group; one-key: writers=<the one key or this \
                           device>)";

/// A `share` line's options over the defaults: the merge rule `/merge/yrs`,
/// writers the namespace `ns`, readers the person `ns`. `readers=` with
/// nothing after it lists no readers (the collection is not sealed).
fn share_options(ns: &Name, options: &[String]) -> Result<Share, String> {
    let merge = || Rule::Merge {
        function: "/merge/yrs".parse().expect("a valid name"),
    };
    let name = |s: &str| {
        s.parse::<Name>()
            .map_err(|e| format!("{s:?} is no name: {e}"))
    };
    fn list(v: &str) -> impl Iterator<Item = &str> {
        v.split(',').filter(|s| !s.is_empty())
    }
    let mut share = Share {
        rule: merge(),
        writers: vec![ns.clone()],
        readers: vec![Audience::Person(ns.clone())],
    };
    for o in options {
        match o.split_once('=') {
            Some(("rule", "merge")) => share.rule = merge(),
            Some(("rule", "log")) => share.rule = Rule::Log,
            Some(("rule", "one-key")) => share.rule = Rule::OneKey,
            Some(("rule", r)) => {
                return Err(format!("rule {r:?} is neither merge, log nor one-key"));
            }
            Some(("writers", v)) => share.writers = list(v).map(name).collect::<Result<_, _>>()?,
            Some(("readers", v)) => {
                share.readers = list(v)
                    .map(|r| match r.split_once(':') {
                        Some(("person", n)) => name(n).map(Audience::Person),
                        Some(("device", n)) => name(n).map(Audience::Device),
                        Some(("group", n)) => name(n).map(Audience::Group),
                        _ => Err(format!(
                            "reader {r:?} is not <kind>:<name> with kind person, device or group"
                        )),
                    })
                    .collect::<Result<_, _>>()?;
            }
            _ => return Err(format!("{o:?} is not rule=, writers= or readers=")),
        }
    }
    Ok(share)
}

const PUT_USAGE: &str = "usage: put <collection> [--batch <ms>] [--keep forever|until=<ms since \
                         the epoch>|last=<n>] <field>=<value>... (a value @<path> is the file's \
                         bytes, @@... a value starting with @)";

const RANGE_USAGE: &str = "usage: range <collection> seq=<low>..<high>|time=<from>..<to> (seqs \
                           both included; dates in ms since the epoch, from included, to \
                           excluded)";

const HOLD_USAGE: &str = "usage: hold <collection> copies=<n> until=<ms since the epoch> \
                          holders=<device>[,<device>...]";

const PRUNE_USAGE: &str =
    "usage: prune <collection or version> upto=<writer key>:<seq>[,<writer key>:<seq>...]";

/// A `put` line's `--batch <ms>` and `--keep <keep>` (before the fields)
/// and its fields, at least one: the keep (default forever), the batch
/// delay (default none) and the fields.
fn put_options(words: &[String]) -> Result<(Keep, Option<Duration>, &[String]), String> {
    let (mut keep, mut batch) = (Keep::Forever, None);
    let mut rest = words;
    while let [option, value, more @ ..] = rest
        && option.starts_with("--")
    {
        match option.as_str() {
            "--batch" => {
                let ms = value
                    .parse::<u64>()
                    .map_err(|e| format!("--batch {value:?} is no delay in ms: {e}"))?;
                batch = Some(Duration::from_millis(ms));
            }
            "--keep" => {
                keep = match value.split_once('=') {
                    None if value == "forever" => Keep::Forever,
                    Some(("until", t)) => {
                        Keep::Until(Timestamp(t.parse::<u64>().map_err(|e| {
                            format!("--keep until={t:?} is no date in ms since the epoch: {e}")
                        })?))
                    }
                    Some(("last", n)) => Keep::LastN(
                        n.parse()
                            .map_err(|e| format!("--keep last={n:?} is no count: {e}"))?,
                    ),
                    _ => {
                        return Err(format!(
                            "--keep {value:?} is not forever, until=<ms> or last=<n>"
                        ));
                    }
                };
            }
            _ => return Err(format!("{option:?} is not --batch or --keep")),
        }
        rest = more;
    }
    match rest.first() {
        None => Err("no field to put".into()),
        Some(o) if o.starts_with("--") => Err(format!("{o:?} needs a value")),
        Some(_) => Ok((keep, batch, rest)),
    }
}

/// A `range` line's `seq=<low>..<high>` or `time=<from>..<to>`.
fn range_bounds(word: &str) -> Result<Range, String> {
    let (kind, bounds) = word
        .split_once('=')
        .ok_or_else(|| format!("{word:?} is not seq=<low>..<high> or time=<from>..<to>"))?;
    let (low, high) = bounds
        .split_once("..")
        .ok_or_else(|| format!("{bounds:?} is not <low>..<high>"))?;
    let number = |s: &str| {
        s.parse::<u64>()
            .map_err(|e| format!("{s:?} in {word:?} is no number: {e}"))
    };
    match kind {
        "seq" => Ok(Range::Seqs(number(low)?, number(high)?)),
        "time" => Ok(Range::Times(
            Timestamp(number(low)?),
            Timestamp(number(high)?),
        )),
        _ => Err(format!("{kind:?} is neither seq nor time")),
    }
}

/// A `put` field's value: the text itself, the bytes of the file `@<path>`
/// names, or (`@@…`) the text after its first `@`.
async fn field_value(value: &str) -> Result<Bytes, String> {
    match value.strip_prefix('@') {
        Some(text) if text.starts_with('@') => Ok(Bytes::copy_from_slice(text.as_bytes())),
        Some(path) => tokio::fs::read(path)
            .await
            .map(Bytes::from)
            .map_err(|e| format!("read {path:?}: {e}")),
        None => Ok(Bytes::copy_from_slice(value.as_bytes())),
    }
}

/// A `hold` line's options: `copies=`, `until=` and `holders=` are all
/// required.
fn hold_options(options: &[String]) -> Result<Hold, String> {
    let (mut copies, mut until, mut holders) = (None, None, None);
    for o in options {
        match o.split_once('=') {
            Some(("copies", n)) => {
                copies = Some(n.parse::<u32>().map_err(|e| format!("copies {n:?}: {e}"))?);
            }
            Some(("until", t)) => {
                until = Some(Timestamp(t.parse::<u64>().map_err(|e| {
                    format!("until {t:?} is no date in ms since the epoch: {e}")
                })?));
            }
            Some(("holders", v)) => {
                holders = Some(
                    v.split(',')
                        .filter(|s| !s.is_empty())
                        .map(|h| {
                            h.parse::<Name>()
                                .map_err(|e| format!("holder {h:?} is no name: {e}"))
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                );
            }
            _ => return Err(format!("{o:?} is not copies=, until= or holders=")),
        }
    }
    match (copies, until, holders) {
        (Some(copies), Some(until), Some(holders)) => Ok(Hold {
            copies,
            until,
            holders,
        }),
        _ => Err("copies=, until= and holders= are all required".into()),
    }
}

/// A `prune` line's `upto=<writer key>:<seq>[,...]` as a frontier. A key
/// name may hold `:`, a seq never does: each item splits at its last `:`.
fn upto_frontier(word: &str) -> Result<Frontier, String> {
    let list = word
        .strip_prefix("upto=")
        .ok_or_else(|| format!("{word:?} is not upto=<writer key>:<seq>[,...]"))?;
    let mut upto = Frontier::new();
    for item in list.split(',').filter(|s| !s.is_empty()) {
        let (key, seq) = item
            .rsplit_once(':')
            .ok_or_else(|| format!("{item:?} is not <writer key>:<seq>"))?;
        let key = key
            .parse::<Name>()
            .map_err(|e| format!("{key:?} is no name: {e}"))?;
        let seq = seq
            .parse::<u64>()
            .map_err(|e| format!("seq {seq:?}: {e}"))?;
        upto.include(&VersionId {
            writer: Writer::new(key),
            seq: Seq(seq),
        });
    }
    if upto.is_empty() {
        return Err("upto= names no writer".into());
    }
    Ok(upto)
}

/// A line split into words: whitespace separates them, double quotes keep
/// a value's spaces (`text="on the plane"`), `\"` and `\\` escape inside
/// quotes.
fn split(line: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(e @ ('"' | '\\')) => word.push(e),
                            _ => return Err("only \\\" and \\\\ escape inside quotes".into()),
                        },
                        Some(c) => word.push(c),
                        None => return Err("a quote is not closed".into()),
                    }
                }
            }
            c if c.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                word.push(c);
            }
        }
    }
    if in_word {
        words.push(word);
    }
    Ok(words)
}

fn usage_error(verb: &str, why: &str) -> Value {
    json!({"verb": verb, "error": {
        "message": why,
        "retry": false,
        "next": "fix-command",
        "next_step": "correct the line and send it again",
    }})
}

fn data_error(e: &DataError) -> Value {
    let next = e.next();
    let mut v = json!({
        "message": e.to_string(),
        "retry": e.retry(),
        "next": next_token(next),
        "next_step": next_step(next),
    });
    match e {
        DataError::Pruned { by, .. } => v["pruned_by"] = prune(by),
        DataError::Refused {
            why: Refusal::OutsideCut(cut),
            ..
        } => {
            v["outside_cut"] = json!({
                "of": cut.of.to_string(),
                "signer": cut.signer.key().to_string(),
            });
        }
        DataError::Expired { name, keep: k } => {
            v["expired"] = json!({"name": name.to_string(), "keep": keep(k)});
        }
        _ => {}
    }
    v
}

fn next_token(n: NextStep) -> &'static str {
    match n {
        NextStep::None => "none",
        NextStep::RetryLater => "retry-later",
        NextStep::AskOwner => "ask-owner",
        NextStep::UseOwnerDevice => "use-owner-device",
        NextStep::EditInstead => "edit-instead",
        NextStep::FixLocal => "fix-local",
        NextStep::FixName => "fix-name",
        NextStep::HoldFirst => "hold-first",
        NextStep::FixRequest => "fix-request",
    }
}

fn next_step(n: NextStep) -> &'static str {
    match n {
        NextStep::None => "nothing: the answer is final",
        NextStep::RetryLater => "ask again later, unchanged: no path or holder answered",
        NextStep::AskOwner => {
            "ask the collection's owner for membership, a reading key or re-admission"
        }
        NextStep::UseOwnerDevice => "do it on a device that holds the owner's key",
        NextStep::EditInstead => "remove it with an edit to the collection: it is not yours",
        NextStep::FixLocal => "fix this device: its storage or its keys",
        NextStep::FixName => "ask again with a well-formed name: the message says how",
        NextStep::HoldFirst => {
            "ask holders to keep it (hold) and release it once their audit passes: nothing \
             confirms it is kept anywhere else"
        }
        NextStep::FixRequest => {
            "ask again as the message says: the request, as given, asks for something no \
             device does"
        }
    }
}

fn id(id: &VersionId) -> Value {
    json!({"writer": id.writer.key().to_string(), "seq": id.seq.0})
}

fn ids(ids: &[VersionId]) -> Value {
    Value::Array(ids.iter().map(id).collect())
}

/// A `get`'s answer: what it got and how old it may be.
fn answer(a: Answer) -> Value {
    let mut ok = match a.got {
        Got::State(s) => json!({"state": {
            "name": s.name.to_string(),
            "collection": s.collection.to_string(),
            "at": frontier(&s.at),
            "value": content(&s.value),
        }}),
        Got::Version(v) => json!({"version": version(&v)}),
        Got::Snapshot(s) => json!({"snapshot": {
            "id": id(&s.id),
            "name": s.name.to_string(),
            "pins": s.pins.iter().map(ToString::to_string).collect::<Vec<_>>(),
        }}),
        Got::Entries(e) => json!({"entries": entries(&e)}),
    };
    ok["age"] = match a.age {
        Age::Exact => json!("exact"),
        Age::Newest { unconfirmed_for } => {
            json!({"unconfirmed_for_ms": unconfirmed_for.as_millis() as u64})
        }
    };
    ok
}

/// Entries of one writer's stream: each with its name, block, index, date
/// and fields; the blocks no path answered, the blocks expired here, and
/// the versions in pieces (read by name).
fn entries(e: &Entries) -> Value {
    json!({
        "collection": e.collection.to_string(),
        "writer": e.writer.key().to_string(),
        "entries": e.entries.iter().map(|x| json!({
            "name": x.name.to_string(),
            "id": id(&x.id),
            "index": x.index,
            "dated_ms": x.dated.0,
            "fields": content(&x.content),
        })).collect::<Vec<_>>(),
        "missing": ids(&e.missing),
        "expired": ids(&e.expired),
        "large": ids(&e.large),
    })
}

fn frontier(f: &Frontier) -> Value {
    Value::Array(
        f.iter()
            .map(|(w, s)| json!({"writer": w.key().to_string(), "seq": s.0}))
            .collect(),
    )
}

/// Values longer than this are shown by length and digest, not bytes.
const SHOWN_MAX: usize = 256;

/// Field values as text when they are UTF-8, else as `{"hex": …}`; longer
/// than [`SHOWN_MAX`] octets, as `{"len": …, "sha256": …}`.
fn content(c: &Content) -> Value {
    let mut m = Map::new();
    for (field, value) in c.fields() {
        let v = if value.len() > SHOWN_MAX {
            json!({"len": value.len(), "sha256": hex(&Sha256::digest(value))})
        } else {
            match std::str::from_utf8(value) {
                Ok(s) => json!(s),
                Err(_) => json!({"hex": hex(value)}),
            }
        };
        m.insert(field.to_owned(), v);
    }
    Value::Object(m)
}

/// A revocation cut: its key, its runs of seqs per prefix, its exact
/// (re-admitted) names.
fn revocation_cut(c: &RevocationCut) -> Value {
    json!({
        "key": c.key().to_string(),
        "ranges": c.ranges().iter().map(|r| json!({
            "prefix": r.prefix.to_string(),
            "runs": r.runs.iter().map(|(first, last)| json!([first, last])).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "exact": c.exact().iter().map(ToString::to_string).collect::<Vec<_>>(),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn version(v: &Version) -> Value {
    json!({
        "id": id(&v.id),
        "name": v.name.to_string(),
        "collection": v.collection.to_string(),
        "parents": frontier(&v.parents),
        "type": {"name": v.type_id.name.to_string(), "revision": v.type_id.revision},
        "keep": keep(&v.keep),
        "dated_ms": v.dated.0,
        "payload": match &v.payload {
            Payload::Entry(c) => json!({"entry": content(c)}),
            Payload::Block(es) => json!({"block": es.iter().map(block_entry).collect::<Vec<_>>()}),
            Payload::Large { size } => json!({"large": size}),
        },
    })
}

fn block_entry(e: &BlockEntry) -> Value {
    json!({"dated_ms": e.dated.0, "fields": content(&e.content)})
}

fn keep(k: &Keep) -> Value {
    match k {
        Keep::Forever => json!("forever"),
        Keep::Until(t) => json!({"until_ms": t.0}),
        Keep::LastN(n) => json!({"last": n}),
    }
}

fn change(c: &Change) -> Value {
    match c {
        Change::Version(v) => json!({"version": version(v)}),
        Change::Summary(s) => json!({"summary": {
            "collection": s.collection.to_string(),
            "signer": s.signer.key().to_string(),
            "frontier": frontier(&s.frontier),
            "children": s.children.len(),
        }}),
        Change::Withdrawn { id: i, cut } => json!({"withdrawn": {
            "id": id(i),
            "cut_of": cut.of.to_string(),
            "cut_signer": cut.signer.key().to_string(),
        }}),
        Change::Pruned { id: i, by } => json!({"pruned": {"id": id(i), "by": prune(by)}}),
        Change::Expired { id: i, keep: k } => json!({"expired": {"id": id(i), "keep": keep(k)}}),
        Change::Equivocation { first, second } => json!({"equivocation": {
            "first": version(first),
            "second": version(second),
        }}),
    }
}

fn prune(p: &Prune) -> Value {
    json!({
        "id": id(&p.id),
        "name": p.name.to_string(),
        "prefix": p.prefix.to_string(),
        "upto": frontier(&p.upto),
    })
}

fn custody(c: &Custody) -> Value {
    json!({
        "prefix": c.prefix.to_string(),
        "copies": c.copies,
        "until_ms": c.until.0,
        "leases": c.leases.iter().map(lease).collect::<Vec<_>>(),
        "broken": c.broken.iter().map(lease).collect::<Vec<_>>(),
        "unkept": c.unkept.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
    })
}

fn lease(l: &Lease) -> Value {
    json!({
        "holder": l.holder.key().to_string(),
        "name": l.name.to_string(),
        "prefix": l.prefix.to_string(),
        "holds": frontier(&l.holds),
        "until_ms": l.until.0,
        "audit": match &l.audit {
            Audit::NotAudited => json!("not-audited"),
            Audit::Kept { pieces } => json!({"kept": {"pieces": pieces}}),
            Audit::Broken { piece, breach } => json!({"broken": {
                "piece": piece.to_string(),
                "breach": match breach {
                    Breach::Missing => "missing",
                    Breach::Wrong => "wrong",
                    Breach::Expired => "expired",
                },
            }}),
            Audit::Unanswered { asked, answered } => {
                json!({"unanswered": {"asked": asked, "answered": answered}})
            }
        },
    })
}
