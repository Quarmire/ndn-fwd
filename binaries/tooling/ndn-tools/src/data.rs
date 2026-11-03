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
//! certificate chain is fetched and walked to the anchor on first use;
//! entries live in memory for the life of the process.
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
//! - `share <collection> [rule=merge|log] [writers=<prefix>,<prefix>...]
//!   [readers=<kind>:<name>,...]`: the members record of a collection of
//!   this device's namespace, its first revision or the next. `rule=merge`
//!   (the default) merges with `/merge/yrs`, `rule=log` keeps every member's
//!   versions (the newest is the latest). Writers are key-name prefixes
//!   (default: `<ns>`); readers are `person:<namespace>`,
//!   `device:<device name>` or `group:<group name>` (default:
//!   `person:<ns>`), and a collection that lists readers is sealed to them;
//!   `readers=` with nothing after it lists none (not sealed). Sharing again
//!   without a writer or reader removes it: the owner cuts a removed writer
//!   at what this device has seen of it, and seals later versions in a new
//!   epoch a removed reader cannot open.
//! - `put <collection> <field>=<value>...`: a version of type
//!   `/types/note` revision 1, kept forever; an empty value removes the field.
//!   A value `@<path>` is the bytes of the file at `<path>` (`@@…` is a
//!   value starting with `@`). A payload larger than a version carries
//!   inline travels in pieces (log rule only).
//! - `get <name>`: a collection's merged state (its newest version under
//!   the log rule), or an exact version or state by its name. A field value
//!   longer than 256 octets is shown as its length and SHA-256, not its
//!   bytes.
//! - `watch <collection or folder>`: from now on, every change as its own
//!   line.
//! - `hold <collection> copies=<n> until=<ms since the epoch>`: ask holders
//!   to keep the collection, audit every live lease and repair: the
//!   custody, each live lease (holder key, name, what it holds, until when,
//!   this device's last audit) and the leases this call found broken or
//!   unanswered.
//! - `prune <collection or version> upto=<writer key>:<seq>[,...]`: drop
//!   this device's own versions up to that point.
//! - `release <collection or version>`: drop this device's copies of the
//!   pieces of large versions that a live lease it audited as kept covers
//!   (the host's storage policy): how many versions, pieces and octets.
//! - `quit` (or end of input).
//!
//! Output lines: `{"ready":{…}}` once the layer runs; per verb
//! `{"verb":…,"ok":{…}}` or `{"verb":…,"error":{"message","retry","next",
//! "next_step"}}` (with `"pruned_by"`, the prune record, when the name was
//! pruned); per watched change `{"watch":<collection>,"change":{…}}`.
//! Logs go to stderr.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use clap::Parser;
use futures::StreamExt;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, BufReader};

use ndn_app::{IpcConnection, Node, demux_cert_fetcher};
use ndn_data::{
    Age, Audience, Audit, Breach, Change, Config, Content, Custody, DataError, DataLayer, Device,
    Frontier, Got, Hold, Keep, Lease, NextStep, Payload, Prune, PutOptions, Rule, Seq, Share,
    Timestamp, Transport, TypeId, Version, VersionId, Writer,
};
use ndn_ipc::ForwarderClient;
use ndn_packet::Name;
use ndn_security::{CertCache, FilePib, SecurityManager, Validator};
use ndn_sync::MemoryStore;

/// Longest certificate chain the validator walks (device → CA → root).
const MAX_CHAIN: usize = 5;

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
    let layer = Device::start(
        Transport { node, sync },
        device.clone(),
        keys,
        validator,
        Arc::new(MemoryStore::new()),
        config,
    )
    .await
    .map_err(|e| anyhow!("{device}: {e} (next: {})", next_step(e.next())))?;
    println!(
        "{}",
        json!({"ready": {"device": device.to_string(), "writer": layer.writer().key().to_string()}})
    );

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await.context("read stdin")? {
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
            Ok(Verb::Usage(why)) => usage_error(verb, &why),
            Err(e) => json!({"verb": verb, "error": data_error(&e)}),
        };
        println!("{answer}");
    }
    layer.shutdown();
    Ok(())
}

/// What one verb line came to.
enum Verb {
    Done(Value),
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
        ("put", [collection, fields @ ..]) if !fields.is_empty() => {
            let collection = match name(collection) {
                Ok(c) => c,
                Err(e) => return Ok(Verb::Usage(e)),
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
            let id = layer
                .put(
                    &collection,
                    content,
                    PutOptions {
                        type_id: TypeId {
                            name: "/types/note".parse().expect("a valid name"),
                            revision: 1,
                        },
                        keep: Keep::Forever,
                        batch: None,
                    },
                )
                .await?;
            let version = ndn_data::wire::log_name(layer.name(), Some(&collection), id.seq.0);
            Ok(Verb::Done(json!({
                "writer": id.writer.key().to_string(),
                "seq": id.seq.0,
                "name": version.to_string(),
            })))
        }
        ("put", _) => usage(PUT_USAGE),
        ("get", [n]) => {
            let n = match name(n) {
                Ok(n) => n,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let answer = layer.get(&n).await?;
            let mut ok = match answer.got {
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
            };
            ok["age"] = match answer.age {
                Age::Exact => json!("exact"),
                Age::Newest { unconfirmed_for } => {
                    json!({"unconfirmed_for_ms": unconfirmed_for.as_millis() as u64})
                }
            };
            Ok(Verb::Done(ok))
        }
        ("get", _) => usage("usage: get <name>"),
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
            })))
        }
        ("release", _) => usage("usage: release <collection or version>"),
        _ => usage("verbs: share, put, get, watch, hold, prune, release, quit"),
    }
}

const SHARE_USAGE: &str = "usage: share <collection> [rule=merge|log] \
                           [writers=<prefix>,<prefix>...] [readers=<kind>:<name>,...] (kind \
                           person, device or group)";

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
        readmit: Vec::new(),
    };
    for o in options {
        match o.split_once('=') {
            Some(("rule", "merge")) => share.rule = merge(),
            Some(("rule", "log")) => share.rule = Rule::Log,
            Some(("rule", r)) => return Err(format!("rule {r:?} is neither merge nor log")),
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

const PUT_USAGE: &str = "usage: put <collection> <field>=<value>... (a value @<path> is the \
                         file's bytes, @@... a value starting with @)";

const HOLD_USAGE: &str = "usage: hold <collection> copies=<n> until=<ms since the epoch>";

const PRUNE_USAGE: &str =
    "usage: prune <collection or version> upto=<writer key>:<seq>[,<writer key>:<seq>...]";

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

/// A `hold` line's options: both `copies=` and `until=` are required.
fn hold_options(options: &[String]) -> Result<Hold, String> {
    let (mut copies, mut until) = (None, None);
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
            _ => return Err(format!("{o:?} is not copies= or until=")),
        }
    }
    match (copies, until) {
        (Some(copies), Some(until)) => Ok(Hold { copies, until }),
        _ => Err("both copies= and until= are required".into()),
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
    if let DataError::Pruned { by, .. } = e {
        v["pruned_by"] = prune(by);
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
    }
}

fn id(id: &VersionId) -> Value {
    json!({"writer": id.writer.key().to_string(), "seq": id.seq.0})
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
        "keep": match v.keep {
            Keep::Forever => json!("forever"),
            Keep::Until(t) => json!({"until_ms": t.0}),
            Keep::LastN(n) => json!({"last": n}),
        },
        "dated_ms": v.dated.0,
        "payload": match &v.payload {
            Payload::Entry(c) => json!({"entry": content(c)}),
            Payload::Block(cs) => json!({"block": cs.iter().map(content).collect::<Vec<_>>()}),
            Payload::Large { size } => json!({"large": size}),
        },
    })
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
                },
            }}),
            Audit::Unanswered { asked, answered } => {
                json!({"unanswered": {"asked": asked, "answered": answered}})
            }
        },
    })
}
