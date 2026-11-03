//! `ndn-data` — host one device's data layer (`ndn_data::Device`) on a
//! running `ndn-fwd` and drive its verbs as lines on stdin, one JSON object
//! per line on stdout.
//!
//! Why a tool and not the daemon: the data layer's verbs over forwarder
//! management are slice 7 of the data-layer plan; until then a separate
//! process attached over the face socket exposes them on a real daemon while
//! ndn-fwd itself carries no data-layer code. It wires the library and does
//! nothing else: the device's key and trust contexts come from the daemon's
//! PIB exactly as `ndn-put --pib` loads them; the validator is the trust
//! contexts' keyring (their anchors and schemas) with a certificate fetcher
//! over the device's own connection, so a peer's certificate chain is
//! fetched and walked to the anchor on first use; entries live in memory for
//! the life of the process.
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
//! - `share <collection>`: the members record of a collection of this
//!   device's namespace: merge rule `/merge/yrs`, writers and readers every
//!   key and device of `<ns>`.
//! - `put <collection> <field>=<value>...`: a version of type
//!   `/types/note` revision 1, kept forever; an empty value removes the field.
//! - `get <name>`: a collection's merged state, or an exact version or
//!   state by its name.
//! - `watch <collection or folder>`: from now on, every change as its own
//!   line.
//! - `quit` (or end of input).
//!
//! Output lines: `{"ready":{…}}` once the layer runs; per verb
//! `{"verb":…,"ok":{…}}` or `{"verb":…,"error":{"message","retry","next",
//! "next_step"}}`; per watched change `{"watch":<collection>,"change":{…}}`.
//! Logs go to stderr.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use clap::Parser;
use futures::StreamExt;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, BufReader};

use ndn_app::{IpcConnection, Node, demux_cert_fetcher};
use ndn_data::{
    Age, Audience, Change, Config, Content, DataError, DataLayer, Device, Frontier, Got, Keep,
    NextStep, Payload, PutOptions, Rule, Share, Transport, TypeId, Version, VersionId,
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
        ("share", [collection]) => {
            let collection = match name(collection) {
                Ok(c) => c,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let ns = layer.namespace().clone();
            layer
                .share(
                    &collection,
                    Share {
                        rule: Rule::Merge {
                            function: "/merge/yrs".parse().expect("a valid name"),
                        },
                        writers: vec![ns.clone()],
                        readers: vec![Audience::Person(ns)],
                        readmit: Vec::new(),
                    },
                )
                .await?;
            Ok(Verb::Done(json!({"collection": collection.to_string()})))
        }
        ("share", _) => usage("usage: share <collection>"),
        ("put", [collection, fields @ ..]) if !fields.is_empty() => {
            let collection = match name(collection) {
                Ok(c) => c,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let mut content = Content::new();
            for f in fields {
                let Some((field, value)) = f.split_once('=') else {
                    return usage("usage: put <collection> <field>=<value>...");
                };
                content = content.with(field, Bytes::copy_from_slice(value.as_bytes()));
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
        ("put", _) => usage("usage: put <collection> <field>=<value>..."),
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
        _ => usage("verbs: share, put, get, watch, quit"),
    }
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
    json!({
        "message": e.to_string(),
        "retry": e.retry(),
        "next": next_token(next),
        "next_step": next_step(next),
    })
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

/// Field values as text when they are UTF-8, else as `{"hex": …}`.
fn content(c: &Content) -> Value {
    let mut m = Map::new();
    for (field, value) in c.fields() {
        let v = match std::str::from_utf8(value) {
            Ok(s) => json!(s),
            Err(_) => json!({"hex": value.iter().map(|b| format!("{b:02x}")).collect::<String>()}),
        };
        m.insert(field.to_owned(), v);
    }
    Value::Object(m)
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
        Change::Equivocation { first, second } => json!({"equivocation": {
            "first": version(first),
            "second": version(second),
        }}),
    }
}
