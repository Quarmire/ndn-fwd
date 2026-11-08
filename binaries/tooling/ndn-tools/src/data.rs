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
//! certificate chain is fetched and
//! walked to the anchor on first use. The keyring follows the daemon: on
//! each newer trust-context version the daemon tells of on its trust
//! stream (`/localhost/nfd/security/notifications`: a revocation it pulled
//! or was pushed, one `ndn-fwd revoke` or `readmit` signed), the host
//! adopts the version the daemon stored in the PIB, and the data layer
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
//! `--merge-rule <function>` (repeatable) makes the device know a merge
//! rule beside `/merge/yrs`, by its full name; this program ships one,
//! `/ndn-tools/merge/element/v=1` (`element.rs`: an element of named text
//! settings, each operation made over a basis it names by implicit digest,
//! concurrent writes kept as ordered variants). A collection whose members
//! record names a rule the device does not know is held unreadable: `get`
//! and the puts answer `RuleUnknown` (next: update the program).
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
//! - `share <collection> [rule=merge|merge:<function>|log|one-key]
//!   [writers=<prefix>,<prefix>...] [readers=<kind>:<name>,...]`: the
//!   members record of a collection of this device's namespace, its first
//!   revision or the next. `rule=merge` (the default) merges with
//!   `/merge/yrs`, `rule=merge:<function>` with the rule of that full name,
//!   `rule=log` keeps every member's
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
//! - `share_folder <folder> [options as share]`: the members record of a
//!   folder `<ns>/32=data/<path>`, which governs every collection under it
//!   (each writes and reads by its own record narrowed by the folder's;
//!   one without its own takes the folder's rule, writers and readers).
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
//! - `put_op <collection> [--keep <keep>] <operation>`: a version of a
//!   merge collection carrying the operation the app built, of type
//!   `/types/element`: `hex=<octets>` (any rule's operation as built), or an
//!   element operation as words — `basis=<digest hex>`,
//!   `set:<setting>=<text>`, `change:<setting>=<at>,<delete>,<insert>` (a
//!   splice in characters of the text the basis wrote; a text `@<path>` is
//!   the file's). Without `basis=`, a change's basis is the version that
//!   wrote the changed setting's one variant in the state here (several
//!   variants: name one). The collection's rule checks it before anything
//!   is signed. The answer shows the operation.
//! - `put_group [--keep <keep>] <collection> fields|op <words>... [;
//!   <collection> fields|op <words>...]...`: several versions as one
//!   group, all or none — one per collection, all of one folder — each
//!   `fields` words as `put`'s or `op` words as `put_op`'s. A reader counts
//!   none of them until it holds them all.
//! - `get <name>`: a collection's merged state (its newest version under
//!   the log and one-key rules), an exact version, state or entry
//!   (`<version>/32=entry/seg=<i>`) by its name, or the entries a range name
//!   (`<collection>/32=range/<range>`) selects. A field value longer than
//!   256 octets is shown as its length and SHA-256, not its bytes. A state
//!   lists the versions held here that are not in its value
//!   (`not_counted`, each with why: the rule's, or its group incomplete).
//! - `range <collection> seq=<low>..<high>|time=<from>..<to>`: `get` of the
//!   range name of a one-key collection: the blocks from seq `low` to `high`
//!   (both included), or the entries dated from `from` (included) to `to`
//!   (excluded), in ms since the epoch.
//! - `watch <collection or folder>`: from now on, every change as its own
//!   line (a version that expired here, too; one not counted, with why,
//!   and when it counts), for a folder of every collection under it,
//!   those created later included, each line naming the change's
//!   collection.
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
//! - `suspect <key> [<when>]`: mark key `<key>` (`<id>/KEY/<k>`; a
//!   certificate name stands for its key) suspected since `<when>` — ms
//!   since the epoch or RFC 3339 in UTC (`2026-11-04T10:00:00.123Z`);
//!   default: now, by the device's clock — what the owner does on
//!   reporting a device lost. Kept across restarts. From now on this device
//!   takes no new log entry of the key (a `get` of one is refused,
//!   `suspected`; entries it already holds stay) until a revocation of the
//!   key decides (adopting it ends the mark) or `unsuspect <key>` lifts the
//!   mark (the answer says whether it was suspected).
//! - `cut <key> <file> [--held-before <when>] [--upto <collection>=<seq>]...`
//!   (`<when>` as for `suspect`): the revocation cut of `<key>` as this device
//!   holds it, bounded by this device's own observation: every log entry of
//!   that key it holds verified and has not refused, that it first verified
//!   before `--held-before` (default: the time the key is suspected since)
//!   and, for each `--upto` collection, whose seq is at most `<seq>`. A key
//!   neither suspected nor given `--held-before` is refused: say when the
//!   device was lost. Written to `<file>` as the cut file
//!   `ndn-fwd revoke <device> --cut <file>` takes (`ndn_cert::CutFile`:
//!   the RevocationCut TLV, the bound used, the entries left out and the
//!   cut's manifest
//!   packets). The answer lists the ranges, the bound and, by full name
//!   with digest, the entries of the key this device holds that the bound
//!   left out — written after the device was lost, or held since a time
//!   not recorded; each is re-admitted one by one with `ndn-fwd readmit`
//!   once checked.
//! - `refused <key>`: the full names (each ending in the implicit SHA-256
//!   digest of the refused packet) of every log entry of `<key>` this device
//!   holds refused because the key is revoked and its cut does not accept
//!   them — refused on arrival or withdrawn later; what `ndn-fwd readmit
//!   <key> <full name>...` takes to re-admit exactly those versions.
//! - `offer <folder> role=reader|writer until=<when> tries=<n>` (`<when>`
//!   as for `suspect`): a one-use offer of a folder of this device's
//!   namespace to someone who holds no trust context of it, expiring at
//!   `<when>` by this device's clock, closed for good by the `<n>`-th wrong
//!   try. The answer carries the code: `link` (`ndn-trust://intro/…`, one
//!   QR; it names the relays this namespace advertises, so the joiner's
//!   forwarder reaches this device through one of them before it trusts
//!   anything of this namespace) and `words` (the offer's name and 24
//!   words, without relays). When the joiner asks, this device adopts the
//!   joiner's namespace through its daemon and adds it to the folder's
//!   members with the role.
//! - `join <code>`: join the folder a code offers (its link, or its words
//!   in double quotes): the answer names the folder, the role and the
//!   inviter's namespace, which this device's daemon now holds (adopted
//!   through `security/context-adopt`, as `ndn-ctl adopt` asks, so it also
//!   routes it over its relay links). An offer refused answers
//!   `"introduction"`: the offer and why (`unknown`, `used`, `expired`,
//!   `closed`, `wrong-proof` with `left`, `forged`, `conflict`).
//! - `quit` (or end of input).
//!
//! Output lines: `{"ready":{…}}` once the layer runs; per verb
//! `{"verb":…,"ok":{…}}` or `{"verb":…,"error":{"message","retry","next",
//! "next_step"}}` (with `"pruned_by"`, the prune record, when the name was
//! pruned, `"expired"`, the name and its keep, when it expired, and
//! `"outside_cut"`, the revoked key and the cut's signer, when a revocation's
//! cut refuses it, `"suspected"`, the key and since when, when this device
//! takes nothing new of a suspected key, `"untrusted"`, why, when the
//! chain of its signer is refused, `"rule_unknown"`, the collection and its
//! rule, when this program does not know the rule, and `"group_member"`
//! when a member of its group is refused); per watched change
//! `{"watch":<collection or folder>,"collection":<the change's collection>,
//! "change":{…}}` (a withdrawn version says `why`,
//! with `cut_of` and `cut_signer` when a cut withdrew it; a version not
//! counted is `{"not_counted":{"id","why"}}`, one that counts later
//! `{"counted":{"id"}}`).
//! Logs go to stderr.

mod element;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
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
use ndn_cert::CutFile;
use ndn_cert::report::TrustEvent;
use ndn_data::wire::{Range, log_name, range_name};
use ndn_data::{
    Age, Answer, Audience, Audit, BlockEntry, Breach, Change, Clock, Config, Content, Custody,
    CutBound, DataError, DataLayer, Device, Entries, Equivocal, Frontier, Got, Hold, IntroRefusal,
    Introducer,
    Keep, Lease, MergeRule, NextStep, Offer, Payload, Prune, PutOptions, Refusal, Role, Rule, Seq,
    Share, State, Timestamp, Transport, TypeId, Version, VersionId, Writer, Yrs,
};
use ndn_ipc::events::{EventSubscription, Notice};
use ndn_ipc::{ForwarderClient, MgmtClient};
use ndn_packet::Name;
use ndn_security::{CertCache, FilePib, Keyring, RevocationCut, SecurityManager, Validator};
use ndn_sync::{DataStore, MemoryStore};
use ndn_trust_envelope::TrustEnvelope;

use crate::element::{ElementOp, ElementValue};

/// Longest certificate chain the validator walks (device → CA → root).
const MAX_CHAIN: usize = 5;

/// The rule `--merge-rule <function>` names, among those this program
/// ships.
fn merge_rule(function: &str) -> Result<Arc<dyn MergeRule>> {
    let name: Name = function
        .parse()
        .map_err(|e| anyhow!("--merge-rule {function:?} is no name: {e}"))?;
    let rules: [Arc<dyn MergeRule>; 2] = [Arc::new(Yrs::new()), Arc::new(element::Element::new())];
    rules
        .into_iter()
        .find(|r| *r.function() == name)
        .ok_or_else(|| {
            anyhow!(
                "--merge-rule {name}: this program knows the merge rules /merge/yrs and {}; name \
                 one of them, or run a program that knows {name}",
                element::FUNCTION
            )
        })
}

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

    /// Also know this merge rule, by its full name (repeatable): a
    /// collection that merges with a rule the device does not know is held
    /// unreadable (`RuleUnknown`). The rules this program ships beside
    /// `/merge/yrs`: `/ndn-tools/merge/element/v=1` (see `put_op`).
    #[arg(long = "merge-rule")]
    merge_rules: Vec<String>,

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
    config.rules = cli.merge_rules.iter().try_fold(config.rules, |rules, r| {
        Ok::<_, anyhow::Error>(rules.with(merge_rule(r)?))
    })?;
    // Introductions (`offer`, `join`): the anchor this device shows is its
    // namespace's context as the daemon stored it; another person's is
    // adopted through the daemon, as `ndn-ctl adopt` does.
    config.introducer = Some(Arc::new(DaemonIntroducer {
        face_socket: cli.face_socket.clone(),
        pib_root: pib.root().to_path_buf(),
        namespace: keyring.context_for(&device).namespace().clone(),
        keyring: Arc::clone(&keyring),
    }));
    let store: Arc<dyn DataStore> = match &cli.store {
        Some(dir) => Arc::new(DirStore::open(dir)?),
        None => Arc::new(MemoryStore::new()),
    };
    // The device's clock: `suspect` without a time marks the key from now
    // as the device dates what it verifies.
    let clock = Arc::clone(&config.clock);
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
    tokio::spawn(follow_contexts(
        cli.face_socket.clone(),
        pib.root().to_path_buf(),
        keyring,
    ));
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
        let answer = match run(&layer, &clock, verb, args).await {
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

/// How long one long-poll of the daemon's trust stream waits for an event.
const TRUST_POLL: Duration = Duration::from_secs(30);
/// How long before subscribing to the trust stream again after it failed
/// (a reconnect backoff: while subscribed, the host only waits for events).
const TRUST_RETRY: Duration = Duration::from_secs(3);

/// Follow the trust-context versions the daemon at `face_socket` adopts —
/// pulled, pushed, or signed there by `ndn-fwd revoke`/`readmit` — from its
/// trust stream (`/localhost/nfd/security/notifications`): each
/// `context-updated` event makes the host adopt the version the daemon
/// stored in the PIB at `pib_root` into `keyring`, and the data layer
/// re-checks what it holds on each adoption. A resync (the first notice,
/// and whenever the host fell behind the stream or the daemon restarted)
/// adopts every stored version newer than the held one, so a version told
/// of meanwhile is not missed. Re-adopting a held version changes nothing;
/// an older one is refused by the keyring (no rollback).
async fn follow_contexts(face_socket: String, pib_root: PathBuf, keyring: Arc<Keyring>) {
    loop {
        let mut trust = match EventSubscription::<TrustEvent>::connect(&face_socket).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    socket = %face_socket,
                    "the daemon's trust stream is not reachable: {e}; trust-context versions it \
                     adopts are not followed until it is (subscribing again)"
                );
                tokio::time::sleep(TRUST_RETRY).await;
                continue;
            }
        };
        loop {
            match trust.next(TRUST_POLL).await {
                Ok(None) => {}
                Ok(Some(Notice::Resync { .. })) => adopt_stored(&pib_root, &keyring),
                Ok(Some(Notice::Event {
                    event:
                        TrustEvent::ContextUpdated {
                            namespace, version, ..
                        },
                    ..
                })) => adopt_told(&pib_root, &keyring, &namespace, version),
                Ok(Some(Notice::Event { .. })) => {}
                Err(e) => {
                    tracing::warn!(
                        socket = %face_socket,
                        "the daemon's trust stream failed: {e}; subscribing again (a resync \
                         adopts what was stored meanwhile)"
                    );
                    tokio::time::sleep(TRUST_RETRY).await;
                    break;
                }
            }
        }
    }
}

/// Adopt every trust context stored in the PIB at `pib_root` that is newer
/// than the one `keyring` holds of its namespace — a held namespace only by
/// the continuity rule ([`ndn_cert::adopt_stored_context`]).
fn adopt_stored(pib_root: &Path, keyring: &Keyring) {
    match ndn_cert::load_persisted_contexts(pib_root, keyring) {
        Ok(read) => {
            for (path, result) in read {
                if let Err(e) = result {
                    tracing::debug!(path = %path.display(), "stored trust context not adopted: {e}");
                }
            }
        }
        Err(e) => tracing::warn!(
            pib = %pib_root.display(),
            "trust contexts not read: {e}; newer versions the daemon stores are adopted at the \
             next one it tells of once the PIB is readable again"
        ),
    }
}

/// Adopt version `version` of `namespace`, which the daemon told of: the
/// daemon stores a version in the PIB at `pib_root` before it tells of it,
/// so the stored file holds it (or a newer one). When it does not — the
/// daemon could not store it — nothing is adopted now: the next version the
/// daemon stores and tells of, or the next resync, brings the host up to
/// date.
fn adopt_told(pib_root: &Path, keyring: &Keyring, namespace: &str, version: u64) {
    let ns: Name = match namespace.parse() {
        Ok(ns) => ns,
        Err(e) => {
            tracing::warn!(
                namespace,
                "the daemon told of a namespace that is no name: {e}"
            );
            return;
        }
    };
    if keyring.version_of(&ns).is_some_and(|held| held >= version) {
        return;
    }
    match ndn_cert::read_stored_context(pib_root, &ns) {
        Ok(Some((ctx, data))) if ctx.version() >= version => {
            let stored = ctx.version();
            if let Err(e) = ndn_cert::adopt_stored_context(pib_root, keyring, ctx, &data) {
                tracing::warn!(
                    %ns,
                    stored,
                    held = ?keyring.version_of(&ns),
                    "stored trust context not adopted: {e}; this host keeps the version it holds"
                );
            }
        }
        Ok(stored) => tracing::warn!(
            %ns,
            version,
            stored = ?stored.map(|(ctx, _)| ctx.version()),
            pib = %pib_root.display(),
            "the daemon told of this version but the PIB does not hold it (the daemon could \
             not store it: see its log); not adopted now — the next version it stores, or the \
             next resync, brings this host up to date"
        ),
        Err(e) => tracing::warn!(
            %ns,
            version,
            pib = %pib_root.display(),
            "the stored trust context is not readable: {e}; not adopted now — the next \
             version the daemon stores, or the next resync, brings this host up to date"
        ),
    }
}

/// How long the daemon may take to adopt an anchor link (its context is
/// inline: no fetch).
const ADOPT_LIMIT: Duration = Duration::from_secs(10);

/// The data layer's introductions on a daemon: this device's anchor is its
/// namespace's trust context as the daemon stored it in the PIB; another
/// person's anchor link is adopted by the daemon (`security/context-adopt`,
/// as `ndn-ctl adopt` asks), which validates and stores it and routes the
/// namespace over its relay links, and then by this host's keyring from
/// the PIB, so the layer's validator trusts it before `adopt` answers.
struct DaemonIntroducer {
    face_socket: String,
    pib_root: PathBuf,
    /// This device's namespace (empty: none governs its name).
    namespace: Name,
    keyring: Arc<Keyring>,
}

impl DaemonIntroducer {
    /// Whether the keyring holds `namespace` at `version` or newer, rooted
    /// in the anchor of `fingerprint`.
    fn holds(&self, namespace: &Name, fingerprint: &[u8; 32], version: u64) -> bool {
        let ctx = self.keyring.context_for(namespace);
        ctx.namespace() == namespace
            && ctx.version() >= version
            && ctx
                .anchors()
                .iter()
                .any(|a| ndn_security::anchor_fingerprint(a.value()) == *fingerprint)
    }

    async fn adopt_link(&self, link: &TrustEnvelope) -> Result<(), String> {
        let TrustEnvelope::Anchor {
            namespace: Some(namespace),
            fingerprint: Some(fingerprint),
            version,
            ..
        } = link
        else {
            return Err("not an anchor link naming its namespace and fingerprint".into());
        };
        let ns: Name = namespace
            .parse()
            .map_err(|e| format!("the anchor link's namespace {namespace:?} is no name: {e}"))?;
        let version = version.unwrap_or(0);
        // Asked again (the same key asks again after a lost answer): held.
        if self.holds(&ns, fingerprint, version) {
            return Ok(());
        }
        let client = MgmtClient::connect(&self.face_socket).await.map_err(|e| {
            format!(
                "the daemon at {} is not reachable to adopt {ns}: {e}",
                self.face_socket
            )
        })?;
        let resp = client
            .security_context_adopt(&link.to_uri(), ADOPT_LIMIT)
            .await
            .map_err(|e| format!("asking the daemon to adopt {ns}: {e}"))?;
        if !resp.is_ok() {
            return Err(match ndn_ipc::trust_refusal(&resp) {
                Some(refusal) => format!("the daemon refused to adopt {ns}: {refusal}"),
                None => format!(
                    "the daemon refused to adopt {ns} ({}): {}",
                    resp.status_code, resp.status_text
                ),
            });
        }
        let info: ndn_cert::report::AdoptedContextInfo = serde_json::from_str(&resp.status_text)
            .map_err(|e| {
                format!(
                    "unreadable answer from the daemon ({e}): {}",
                    resp.status_text
                )
            })?;
        adopt_told(&self.pib_root, &self.keyring, &info.namespace, info.version);
        if self.holds(&ns, fingerprint, version) {
            Ok(())
        } else {
            Err(format!(
                "the daemon adopted {ns} v{}, but the PIB at {} gives this host no such version to \
                 adopt: check the PIB is the daemon's",
                info.version,
                self.pib_root.display()
            ))
        }
    }
}

impl Introducer for DaemonIntroducer {
    fn anchor(&self) -> Option<Bytes> {
        if self.namespace.is_empty() {
            return None;
        }
        match ndn_cert::read_stored_context(&self.pib_root, &self.namespace) {
            Ok(Some((_, data))) => Some(data.raw().clone()),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(
                    namespace = %self.namespace,
                    "this device's trust context is not readable from the PIB: {e}"
                );
                None
            }
        }
    }

    fn adopt<'a>(&'a self, link: &'a TrustEnvelope) -> ndn_data::intro::Adopting<'a> {
        Box::pin(self.adopt_link(link))
    }
}

/// The host's store with `--store <dir>`: what the device keeps, in memory
/// for reads, and each entry also a file of `<dir>` (named by the SHA-256 of
/// its name; holding the name's TLV length as 4 octets big-endian, the
/// name's TLV, then the stored wire), written atomically and owner-only, so
/// a host started again on `<dir>` resumes what it held — its own log, and
/// with it its key's sequence.
///
/// Durability: an entry is written to a temporary file, fsynced, and renamed
/// into place (`secure_fs::write_private`), so a returned insert survives
/// `kill -9` and its data survives a power loss; what a power loss can still
/// take is the rename or a removal, until the directory is fsynced — which
/// [`sync`](DataStore::sync) does, once for every write since the last one
/// (group commit). A failed write or removal fails every later `sync`.
struct DirStore {
    memory: MemoryStore,
    dir: PathBuf,
    /// Writes and removals that returned.
    accepted: AtomicU64,
    /// Every accepted one up to this count is known durable.
    durable: AtomicU64,
    /// Held by the one `sync` fsyncing the directory.
    leader: Mutex<()>,
    /// The first write or removal that failed.
    failed: OnceLock<String>,
}

impl DirStore {
    /// Open `dir` (made if missing) and read back every entry stored there.
    fn open(dir: &Path) -> Result<Self> {
        ndn_security::secure_fs::create_private_dir_all(dir)
            .map_err(|e| anyhow!("--store {}: {e}", dir.display()))?;
        // A directory made here must keep its name in its parent across a
        // power loss, or every entry later synced into it goes with it.
        if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::File::open(parent)
                .and_then(|p| p.sync_all())
                .map_err(|e| {
                    anyhow!(
                        "--store {}: fsync of its parent directory failed ({e}); check the \
                         disk, or start with another --store",
                        dir.display()
                    )
                })?;
        }
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
            accepted: AtomicU64::new(0),
            durable: AtomicU64::new(0),
            leader: Mutex::new(()),
            failed: OnceLock::new(),
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

impl DirStore {
    /// Count a write or removal that returned.
    fn accept(&self) {
        self.accepted.fetch_add(1, Ordering::Release);
    }

    /// `Err` once any write or removal failed.
    fn check(&self) -> std::io::Result<()> {
        match self.failed.get() {
            None => Ok(()),
            Some(what) => Err(std::io::Error::other(format!(
                "--store {}: {what}, so a change this store accepted may not be kept and none \
                 can be promised durable any more; fix the cause (free space, the directory's \
                 permissions), then start the host again",
                self.dir.display()
            ))),
        }
    }
}

impl DataStore for DirStore {
    fn insert(&self, name: Name, wire: Bytes) {
        let tlv = name.encode_to_tlv();
        let mut file = Vec::with_capacity(4 + tlv.len() + wire.len());
        file.extend_from_slice(&(tlv.len() as u32).to_be_bytes());
        file.extend_from_slice(&tlv);
        file.extend_from_slice(&wire);
        let path = self.path(&tlv);
        match ndn_security::secure_fs::write_private(&path, &file) {
            Ok(()) => self.accept(),
            Err(e) => {
                tracing::error!(
                    %name,
                    path = %path.display(),
                    "not written to the store: {e}; held in memory, but a host started again \
                     on this --store loses it: free space or fix the directory's permissions"
                );
                let _ = self.failed.set(format!(
                    "{name} was not written to {} ({e})",
                    path.display()
                ));
            }
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
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                tracing::error!(
                    %name,
                    path = %path.display(),
                    "not removed from the store: {e}; a host started again on this --store \
                     holds it again: fix the directory's permissions"
                );
                let _ = self.failed.set(format!(
                    "{name} was not removed from {} ({e})",
                    path.display()
                ));
            }
            _ => self.accept(),
        }
    }

    /// Group commit: returns at once when every write and removal before the
    /// call is already durable; otherwise the leader fsyncs the directory
    /// (each entry's data was fsynced before its rename) for everything
    /// accepted so far, and callers that waited on it re-check.
    fn sync(&self) -> std::io::Result<()> {
        self.check()?;
        let target = self.accepted.load(Ordering::Acquire);
        if self.durable.load(Ordering::Acquire) >= target {
            return Ok(());
        }
        let _leader = self.leader.lock().unwrap_or_else(PoisonError::into_inner);
        if self.durable.load(Ordering::Acquire) < target {
            let upto = self.accepted.load(Ordering::Acquire);
            match std::fs::File::open(&self.dir).and_then(|d| d.sync_all()) {
                Ok(()) => {
                    self.durable.fetch_max(upto, Ordering::Release);
                }
                Err(e) => {
                    let _ = self
                        .failed
                        .set(format!("fsync of the directory failed ({e})"));
                }
            }
        }
        self.check()
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

async fn run(
    layer: &Device,
    clock: &Clock,
    verb: &str,
    args: &[String],
) -> Result<Verb, DataError> {
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
        ("share_folder", [folder, options @ ..]) => {
            let folder = match name(folder) {
                Ok(f) => f,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let share = match share_options(layer.namespace(), options) {
                Ok(s) => s,
                Err(e) => return Ok(Verb::Usage(format!("{e}; {SHARE_FOLDER_USAGE}"))),
            };
            layer.share_folder(&folder, share).await?;
            Ok(Verb::Done(json!({"folder": folder.to_string()})))
        }
        ("share_folder", _) => usage(SHARE_FOLDER_USAGE),
        ("put", [collection, rest @ ..]) => {
            let collection = match name(collection) {
                Ok(c) => c,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let (keep, batch, fields) = match put_options(rest) {
                Ok(o) => o,
                Err(e) => return Ok(Verb::Usage(format!("{e}; {PUT_USAGE}"))),
            };
            let content = match fields_of(fields).await {
                Ok(c) => c,
                Err(e) => return Ok(Verb::Usage(format!("{e}; {PUT_USAGE}"))),
            };
            let options = put_type(NOTE, keep, batch);
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
        ("put_op", [collection, rest @ ..]) => {
            let collection = match name(collection) {
                Ok(c) => c,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let (keep, words) = match keep_option(rest) {
                Ok(o) => o,
                Err(e) => return Ok(Verb::Usage(format!("{e}; {PUT_OP_USAGE}"))),
            };
            let op = match op_of(layer, &collection, words).await {
                Ok(op) => op,
                Err(Bad::Usage(e)) => return Ok(Verb::Usage(format!("{e}; {PUT_OP_USAGE}"))),
                Err(Bad::Data(e)) => return Err(e),
            };
            let shown = op_shown(&op);
            let id = layer
                .put_op(&collection, op, put_type(ELEMENT, keep, None))
                .await?;
            let mut ok = put_answer(layer, &collection, &id);
            ok["op"] = shown;
            Ok(Verb::Done(ok))
        }
        ("put_op", _) => usage(PUT_OP_USAGE),
        ("put_group", [_, ..]) => {
            let (keep, words) = match keep_option(args) {
                Ok(o) => o,
                Err(e) => return Ok(Verb::Usage(format!("{e}; {PUT_GROUP_USAGE}"))),
            };
            let mut items = Vec::new();
            let mut shown = Vec::new();
            for item in words.split(|w| w == ";") {
                let [collection, kind, edit @ ..] = item else {
                    return Ok(Verb::Usage(format!(
                        "item {:?} is not <collection> fields|op <words>...; {PUT_GROUP_USAGE}",
                        item.join(" ")
                    )));
                };
                let collection = match name(collection) {
                    Ok(c) => c,
                    Err(e) => return Ok(Verb::Usage(e)),
                };
                let (edit, show) = match kind.as_str() {
                    "fields" => match fields_of(edit).await {
                        Ok(c) => {
                            let show = json!({"fields": content(&c)});
                            (ndn_data::Edit::Fields(c), show)
                        }
                        Err(e) => {
                            return Ok(Verb::Usage(format!(
                                "{collection}: {e}; {PUT_GROUP_USAGE}"
                            )));
                        }
                    },
                    "op" => match op_of(layer, &collection, edit).await {
                        Ok(op) => {
                            let show = json!({"op": op_shown(&op)});
                            (ndn_data::Edit::Op(op), show)
                        }
                        Err(Bad::Usage(e)) => {
                            return Ok(Verb::Usage(format!(
                                "{collection}: {e}; {PUT_GROUP_USAGE}"
                            )));
                        }
                        Err(Bad::Data(e)) => return Err(e),
                    },
                    other => {
                        return Ok(Verb::Usage(format!(
                            "{collection}: {other:?} is neither fields nor op; {PUT_GROUP_USAGE}"
                        )));
                    }
                };
                shown.push((collection.clone(), show));
                items.push((collection, edit));
            }
            let all_ops = items
                .iter()
                .all(|(_, e)| matches!(e, ndn_data::Edit::Op(_)));
            let options = put_type(if all_ops { ELEMENT } else { NOTE }, keep, None);
            let ids = layer.put_group(items, options).await?;
            let versions = ids
                .iter()
                .zip(shown)
                .map(|(id, (collection, show))| {
                    let mut v = put_answer(layer, &collection, id);
                    v["collection"] = json!(collection.to_string());
                    if let (Value::Object(v), Value::Object(show)) = (&mut v, show) {
                        v.extend(show);
                    }
                    v
                })
                .collect::<Vec<_>>();
            Ok(Verb::Done(json!({"versions": versions})))
        }
        ("put_group", _) => usage(PUT_GROUP_USAGE),
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
            let (layer, target) = (layer.clone(), collection.clone());
            tokio::spawn(async move {
                while let Some(item) = changes.next().await {
                    let lagged = matches!(item, Ok(Change::Lagged { .. }));
                    let line = match item {
                        Ok(c) => json!({
                            "watch": watched,
                            "collection": c.collection().to_string(),
                            "change": change(&c),
                        }),
                        Err(e) => json!({"watch": watched, "error": data_error(&e)}),
                    };
                    println!("{line}");
                    // Fallen behind: read again. The listing is local, so
                    // a whole folder resumes from the empty frontier.
                    if lagged {
                        match layer.watch(&target, &Frontier::new()).await {
                            Ok(again) => changes = again,
                            Err(e) => {
                                println!("{}", json!({"watch": watched, "error": data_error(&e)}));
                                return;
                            }
                        }
                    }
                }
            });
            Ok(Verb::Done(json!({"collection": collection.to_string()})))
        }
        ("watch", _) => usage("usage: watch <collection or folder>"),
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
        ("suspect", [key, since @ ..]) if since.len() <= 1 => {
            let key = match name(key) {
                Ok(k) => k,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let since = match since.first() {
                None => clock(),
                Some(when) => match time(when) {
                    Ok(t) => t,
                    Err(e) => return Ok(Verb::Usage(format!("{e}; {SUSPECT_USAGE}"))),
                },
            };
            layer.suspect(&key, since)?;
            Ok(Verb::Done(
                json!({"key": key.to_string(), "since_ms": since.0}),
            ))
        }
        ("suspect", _) => usage(SUSPECT_USAGE),
        ("unsuspect", [key]) => {
            let key = match name(key) {
                Ok(k) => k,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let was = layer.unsuspect(&key);
            Ok(Verb::Done(
                json!({"key": key.to_string(), "was_suspected": was}),
            ))
        }
        ("unsuspect", _) => usage("usage: unsuspect <key>"),
        ("cut", [key, file, options @ ..]) => {
            let key = match name(key) {
                Ok(k) => k,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let (given, upto) = match cut_options(options) {
                Ok(o) => o,
                Err(e) => return Ok(Verb::Usage(format!("{e}; {CUT_USAGE}"))),
            };
            let held_before = given.or_else(|| layer.suspected(&key));
            if held_before.is_none() && !upto.is_empty() {
                return Ok(Verb::Usage(format!(
                    "{key} is not suspected and the line gives no --held-before: a cut bounded \
                     only by --upto cannot be checked against when the device was lost, and \
                     `ndn-fwd revoke --cut` refuses it; give --held-before <ms since the epoch> \
                     (when the device was lost), or mark the key suspected from then first \
                     (suspect {key} <ms since the epoch>)"
                )));
            }
            // Neither bound: the layer refuses, saying to tell when the
            // device was lost.
            let bound = CutBound { held_before, upto };
            let proposal = layer.revocation_cut(&key, &bound)?;
            let mut cut_file = CutFile::new(proposal.cut);
            cut_file.held_before = held_before.map(|t| t.0);
            cut_file.upto = bound.upto;
            cut_file.left_out = proposal.left_out;
            cut_file.manifest = proposal.manifest;
            if let Err(e) = std::fs::write(file, cut_file.encode()) {
                return Ok(Verb::Usage(format!(
                    "write {file}: {e}; name a file this host may write"
                )));
            }
            let mut ok = revocation_cut(&cut_file.cut);
            ok["file"] = json!(file);
            ok["held_before_ms"] = json!(cut_file.held_before);
            ok["held_before_from"] = json!(if given.is_some() {
                "given"
            } else {
                "suspected"
            });
            ok["upto"] = cut_file
                .upto
                .iter()
                .map(|(c, seq)| json!({"collection": c.to_string(), "seq": seq}))
                .collect();
            ok["left_out"] = cut_file
                .left_out
                .iter()
                .map(|n| json!(n.to_string()))
                .collect();
            ok["manifest_packets"] = json!(cut_file.manifest.len());
            Ok(Verb::Done(ok))
        }
        ("cut", _) => usage(CUT_USAGE),
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
        ("offer", [folder, options @ ..]) => {
            let folder = match name(folder) {
                Ok(f) => f,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let offer = match offer_options(options) {
                Ok(o) => o,
                Err(e) => return Ok(Verb::Usage(format!("{e}; {OFFER_USAGE}"))),
            };
            let (role, until, tries) = (offer.role, offer.until, offer.tries);
            let code = layer.offer(&folder, offer).await?;
            Ok(Verb::Done(json!({
                "folder": folder.to_string(),
                "role": role_word(role),
                "until_ms": until.0,
                "tries": tries,
                "offer": code.offer.to_string(),
                "link": code.link,
                "words": code.words,
            })))
        }
        ("offer", _) => usage(OFFER_USAGE),
        ("join", [code]) => {
            let joined = layer.join(code).await?;
            Ok(Verb::Done(json!({
                "folder": joined.folder.to_string(),
                "role": role_word(joined.role),
                "inviter": joined.inviter.to_string(),
            })))
        }
        ("join", _) => usage(JOIN_USAGE),
        _ => usage(
            "verbs: share, share_folder, put, put_op, put_group, get, range, watch, hold, prune, \
             release, suspect, unsuspect, cut, refused, offer, join, quit",
        ),
    }
}

const SHARE_USAGE: &str = "usage: share <collection> [rule=merge|merge:<function>|log|one-key] \
                           [writers=<prefix>,<prefix>...] [readers=<kind>:<name>,...] (kind \
                           person, device or group; one-key: writers=<the one key or this \
                           device>)";

const SHARE_FOLDER_USAGE: &str = "usage: share_folder <folder> \
                                  [rule=merge|merge:<function>|log|one-key] \
                                  [writers=<prefix>,<prefix>...] [readers=<kind>:<name>,...] \
                                  (kind person, device or group; the folder is <ns>/32=data/<path>, \
                                  and its record governs every collection under it)";

/// A `share` (or `share_folder`) line's options over the defaults: the
/// merge rule `/merge/yrs`, writers the namespace `ns`, readers the person
/// `ns`. `rule=merge:<function>` merges with the rule of that full name.
/// `readers=` with nothing after it lists no readers (not sealed).
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
            Some(("rule", r)) => match r.strip_prefix("merge:") {
                Some(function) => {
                    share.rule = Rule::Merge {
                        function: name(function)?,
                    };
                }
                None => {
                    return Err(format!(
                        "rule {r:?} is neither merge, merge:<function>, log nor one-key"
                    ));
                }
            },
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

const PUT_OP_USAGE: &str = "usage: put_op <collection> [--keep forever|until=<ms>|last=<n>] \
                            hex=<operation> | [basis=<digest hex>] [set:<setting>=<text>]... \
                            [change:<setting>=<at>,<delete>,<insert>]... (an element operation, \
                            /ndn-tools/merge/element/v=1: a change splices, in characters, the \
                            text its basis wrote, by default the version that wrote the \
                            setting's one variant here; a text @<path> is the file's)";

const PUT_GROUP_USAGE: &str = "usage: put_group [--keep forever|until=<ms>|last=<n>] <collection> \
                               fields|op <words>... [; <collection> fields|op <words>...]... \
                               (all or none, one collection each, all of one folder; fields \
                               words as put's, op words as put_op's)";

/// The type of versions `put` writes.
const NOTE: &str = "/types/note";
/// The type of versions `put_op` writes (and `put_group` of operations
/// only).
const ELEMENT: &str = "/types/element";

fn put_type(type_name: &str, keep: Keep, batch: Option<Duration>) -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: type_name.parse().expect("a valid name"),
            revision: 1,
        },
        keep,
        batch,
    }
}

/// What a put answers about the version it wrote: writer, seq and name.
fn put_answer(layer: &Device, collection: &Name, id: &VersionId) -> Value {
    json!({
        "writer": id.writer.key().to_string(),
        "seq": id.seq.0,
        "name": log_name(layer.name(), Some(collection), id.seq.0).to_string(),
    })
}

/// An operation as an answer shows it: an element operation's basis and
/// edits (texts as [`text_shown`]), else its length and SHA-256.
fn op_shown(op: &[u8]) -> Value {
    let Ok(op) = ElementOp::decode(op) else {
        return json!({"len": op.len(), "sha256": hex(&Sha256::digest(op))});
    };
    json!({
        "basis": op.basis.map(|d| hex(&d)),
        "edits": op.edits.iter().map(|e| match e {
            element::Edit::Set { setting, text } => {
                json!({"set": setting, "text": text_shown(text)})
            }
            element::Edit::Change { setting, at, delete, insert } => json!({
                "change": setting, "at": at, "delete": delete, "insert": text_shown(insert),
            }),
        }).collect::<Vec<_>>(),
    })
}

/// A text up to [`SHOWN_MAX`] octets as itself, longer as its length and
/// SHA-256.
fn text_shown(text: &str) -> Value {
    if text.len() > SHOWN_MAX {
        json!({"len": text.len(), "sha256": hex(&Sha256::digest(text))})
    } else {
        json!(text)
    }
}

const RANGE_USAGE: &str = "usage: range <collection> seq=<low>..<high>|time=<from>..<to> (seqs \
                           both included; dates in ms since the epoch, from included, to \
                           excluded)";

const HOLD_USAGE: &str = "usage: hold <collection> copies=<n> until=<ms since the epoch> \
                          holders=<device>[,<device>...]";

const PRUNE_USAGE: &str =
    "usage: prune <collection or version> upto=<writer key>:<seq>[,<writer key>:<seq>...]";

const SUSPECT_USAGE: &str = "usage: suspect <key> [<when>] (since when the key is suspected: \
                             when the device was lost, as ms since the epoch or RFC 3339; \
                             default now)";

const CUT_USAGE: &str = "usage: cut <key> <file> [--held-before <when>] [--upto \
                         <collection>=<seq>]... (<when> as ms since the epoch or RFC 3339; \
                         --held-before defaults to the time the key was suspected since)";

const OFFER_USAGE: &str = "usage: offer <folder> role=reader|writer until=<when> tries=<n> \
                           (a folder of this device's namespace; <when>, the offer's expiry by \
                           this device's clock, as ms since the epoch or RFC 3339; <n> ≥ 1, the \
                           wrong tries that close it)";

const JOIN_USAGE: &str = "usage: join <code> (the code an offer printed: its link \
                          ndn-trust://intro/…, or its words in double quotes)";

/// An `offer` line's options after the folder: `role=`, `until=` and
/// `tries=`, each exactly once.
fn offer_options(words: &[String]) -> Result<Offer, String> {
    let (mut role, mut until, mut tries) = (None, None, None);
    for word in words {
        let (key, value) = word
            .split_once('=')
            .ok_or_else(|| format!("{word:?} is not <option>=<value>"))?;
        let twice = || format!("{key}= is given twice");
        match key {
            "role" if role.is_some() => return Err(twice()),
            "role" => {
                role = Some(match value {
                    "reader" => Role::Reader,
                    "writer" => Role::Writer,
                    other => return Err(format!("role={other:?} is neither reader nor writer")),
                });
            }
            "until" if until.is_some() => return Err(twice()),
            "until" => until = Some(time(value).map_err(|e| format!("until: {e}"))?),
            "tries" if tries.is_some() => return Err(twice()),
            "tries" => {
                let n: u32 = value
                    .parse()
                    .map_err(|e| format!("tries={value:?} is no count: {e}"))?;
                if n == 0 {
                    return Err("tries=0 allows no try: give 1 or more".into());
                }
                tries = Some(n);
            }
            other => return Err(format!("{other:?} is no option of offer")),
        }
    }
    Ok(Offer {
        role: role.ok_or("role= is missing")?,
        until: until.ok_or("until= is missing")?,
        tries: tries.ok_or("tries= is missing")?,
    })
}

/// A role as the lines name it.
fn role_word(role: Role) -> &'static str {
    match role {
        Role::Reader => "reader",
        Role::Writer => "writer",
    }
}

/// A time a line gives: ms since the epoch (`1793808000000`), or RFC 3339
/// in UTC (`2026-11-04T10:00:00Z`, `2026-11-04T10:00:00.123Z`) as
/// `ndn-fwd revoke --lost` takes it and its hints print it.
fn time(when: &str) -> Result<Timestamp, String> {
    if when.bytes().all(|b| b.is_ascii_digit()) {
        return when
            .parse::<u64>()
            .map(Timestamp)
            .map_err(|e| format!("{when:?} is no time in ms since the epoch: {e}"));
    }
    let at = humantime::parse_rfc3339_weak(when)
        .map_err(|e| format!("{when:?} is neither ms since the epoch nor an RFC 3339 time: {e}"))?;
    let ms = at
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| format!("{when:?} is before 1970"))?
        .as_millis();
    u64::try_from(ms)
        .map(Timestamp)
        .map_err(|_| format!("{when:?} is too far in the future"))
}

/// A `cut` line's options after the key and the file: `--held-before
/// <when>` (at most once) and `--upto <collection>=<seq>` (once per
/// collection). A collection name may hold `=`, a seq never does: each
/// `--upto` splits at its last `=`.
fn cut_options(words: &[String]) -> Result<(Option<Timestamp>, BTreeMap<Name, u64>), String> {
    let (mut held_before, mut upto) = (None, BTreeMap::new());
    let mut rest = words;
    while let [option, value, more @ ..] = rest {
        match option.as_str() {
            "--held-before" if held_before.is_some() => {
                return Err("--held-before is given twice".into());
            }
            "--held-before" => {
                held_before = Some(time(value).map_err(|e| format!("--held-before: {e}"))?);
            }
            "--upto" => {
                let (collection, seq) = value
                    .rsplit_once('=')
                    .ok_or_else(|| format!("--upto {value:?} is not <collection>=<seq>"))?;
                let collection = collection
                    .parse::<Name>()
                    .map_err(|e| format!("--upto {collection:?} is no name: {e}"))?;
                let seq = seq
                    .parse::<u64>()
                    .map_err(|e| format!("--upto {value:?}: seq {seq:?}: {e}"))?;
                if upto.insert(collection, seq).is_some() {
                    return Err(format!("--upto names the collection of {value:?} twice"));
                }
            }
            _ => return Err(format!("{option:?} is not --held-before or --upto")),
        }
        rest = more;
    }
    match rest.first() {
        None => Ok((held_before, upto)),
        Some(o) if o == "--held-before" || o == "--upto" => Err(format!("{o:?} needs a value")),
        Some(o) => Err(format!("{o:?} is not --held-before or --upto")),
    }
}

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
            "--keep" => keep = keep_value(value)?,
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

/// A `--keep` value: `forever`, `until=<ms since the epoch>` or
/// `last=<n>`.
fn keep_value(value: &str) -> Result<Keep, String> {
    match value.split_once('=') {
        None if value == "forever" => Ok(Keep::Forever),
        Some(("until", t)) => t
            .parse::<u64>()
            .map(|t| Keep::Until(Timestamp(t)))
            .map_err(|e| format!("--keep until={t:?} is no date in ms since the epoch: {e}")),
        Some(("last", n)) => n
            .parse()
            .map(Keep::LastN)
            .map_err(|e| format!("--keep last={n:?} is no count: {e}")),
        _ => Err(format!(
            "--keep {value:?} is not forever, until=<ms> or last=<n>"
        )),
    }
}

/// A `put_op` or `put_group` line's `--keep <keep>` (before the rest), at
/// most once, and the words after it, at least one.
fn keep_option(words: &[String]) -> Result<(Keep, &[String]), String> {
    let (keep, rest) = match words {
        [option, value, rest @ ..] if option == "--keep" => (keep_value(value)?, rest),
        [option, ..] if option == "--keep" => return Err("--keep needs a value".into()),
        _ => (Keep::Forever, words),
    };
    match rest.first() {
        None => Err("nothing to put".into()),
        Some(o) if o.starts_with("--") => Err(format!("{o:?} is not --keep (given once)")),
        Some(_) => Ok((keep, rest)),
    }
}

/// A line that cannot be done: its words are wrong (answered as usage), or
/// the layer refused what it needed first.
enum Bad {
    Usage(String),
    Data(DataError),
}

impl From<String> for Bad {
    fn from(why: String) -> Self {
        Bad::Usage(why)
    }
}

impl From<DataError> for Bad {
    fn from(e: DataError) -> Self {
        Bad::Data(e)
    }
}

/// The fields of `<field>=<value>` words, at least one (values as
/// [`field_value`] reads them).
async fn fields_of(words: &[String]) -> Result<Content, String> {
    if words.is_empty() {
        return Err("no field to put".into());
    }
    let mut content = Content::new();
    for f in words {
        let (field, value) = f
            .split_once('=')
            .ok_or_else(|| format!("{f:?} is not <field>=<value>"))?;
        content = content.with(
            field,
            field_value(value)
                .await
                .map_err(|e| format!("{field}: {e}"))?,
        );
    }
    Ok(content)
}

/// The operation an `op` line gives for `collection`: `hex=<octets>` alone
/// (any rule's operation, as built), or the words of an element operation
/// (`/ndn-tools/merge/element/v=1`) — `basis=<digest hex>`,
/// `set:<setting>=<text>`, `change:<setting>=<at>,<delete>,<insert>` (texts
/// as field values: `@<path>` a file's text). A change without `basis=`
/// takes as basis the version that wrote the changed setting's one variant
/// in the collection's state here.
async fn op_of(layer: &Device, collection: &Name, words: &[String]) -> Result<Bytes, Bad> {
    if let [only] = words
        && let Some(octets) = only.strip_prefix("hex=")
    {
        return Ok(Bytes::from(unhex(octets)?));
    }
    let mut basis = None;
    let mut edits = Vec::new();
    for w in words {
        if let Some(d) = w.strip_prefix("basis=") {
            basis = Some(digest_of(d)?);
        } else if let Some(rest) = w.strip_prefix("set:") {
            let (setting, value) = rest
                .split_once('=')
                .ok_or_else(|| format!("{w:?} is not set:<setting>=<text>"))?;
            edits.push(element::Edit::Set {
                setting: setting.to_owned(),
                text: field_text(value)
                    .await
                    .map_err(|e| format!("{setting}: {e}"))?,
            });
        } else if let Some(rest) = w.strip_prefix("change:") {
            let not_change = || format!("{w:?} is not change:<setting>=<at>,<delete>,<insert>");
            let (setting, splice) = rest.split_once('=').ok_or_else(not_change)?;
            let mut parts = splice.splitn(3, ',');
            let (Some(at), Some(delete), Some(insert)) = (parts.next(), parts.next(), parts.next())
            else {
                return Err(not_change().into());
            };
            let count = |s: &str| {
                s.parse::<u32>()
                    .map_err(|e| format!("{w:?}: {s:?} is no count of characters: {e}"))
            };
            edits.push(element::Edit::Change {
                setting: setting.to_owned(),
                at: count(at)?,
                delete: count(delete)?,
                insert: field_text(insert)
                    .await
                    .map_err(|e| format!("{setting}: {e}"))?,
            });
        } else {
            return Err(
                format!("{w:?} is not hex=, basis=, set:<setting>= or change:<setting>=").into(),
            );
        }
    }
    if basis.is_none()
        && edits
            .iter()
            .any(|e| matches!(e, element::Edit::Change { .. }))
    {
        let Got::State(state) = layer.get(collection).await?.got else {
            return Err(
                format!("{collection} has no merged state here; give basis=<digest>").into(),
            );
        };
        basis = Some(change_basis(&state, &edits)?);
    }
    let op = ElementOp { basis, edits };
    op.well_formed()?;
    Ok(op.encode())
}

/// The basis of `edits`' changes in `state`: the digest of the version
/// that wrote the one variant of every changed setting.
fn change_basis(state: &State, edits: &[element::Edit]) -> Result<[u8; 32], String> {
    let value = element_value(&state.value).ok_or_else(|| {
        format!(
            "{}'s value is not an element's ({}): give basis=<digest>, or hex=<operation>",
            state.collection,
            element::FUNCTION
        )
    })?;
    let mut basis = None;
    for e in edits {
        let element::Edit::Change { setting, .. } = e else {
            continue;
        };
        let variants = value.settings.get(setting).map_or(&[][..], Vec::as_slice);
        let [one] = variants else {
            return Err(if variants.is_empty() {
                format!("{setting:?} has no text here to change: set it first")
            } else {
                format!(
                    "{setting:?} has {} concurrent variants here: give basis=<digest> of the one \
                     to change (get shows each variant's digest)",
                    variants.len()
                )
            });
        };
        match basis {
            None => basis = Some(one.digest),
            Some(d) if d == one.digest => {}
            Some(_) => {
                return Err(
                    "the changed settings were last written by different versions: \
                            change them in separate operations, or give basis=<digest>"
                        .into(),
                );
            }
        }
    }
    basis.ok_or_else(|| "no edit changes a setting, so there is no basis to find".into())
}

/// A value decoded as an element's, when it is one.
fn element_value(v: &ndn_data::Value) -> Option<ElementValue> {
    v.bytes().and_then(|b| ElementValue::decode(b).ok())
}

/// A text value as [`field_value`] reads it, which must be UTF-8: element
/// settings hold text.
async fn field_text(value: &str) -> Result<String, String> {
    String::from_utf8(field_value(value).await?.into())
        .map_err(|e| format!("not UTF-8 text ({e}): element settings hold text"))
}

/// Octets written as hex.
fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("{s:?} is no hex: an odd number of digits"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            s.get(i..i + 2)
                .and_then(|d| u8::from_str_radix(d, 16).ok())
                .ok_or_else(|| format!("{s:?} is no hex"))
        })
        .collect()
}

/// A digest (32 octets) written as hex.
fn digest_of(s: &str) -> Result<[u8; 32], String> {
    unhex(s)?
        .try_into()
        .map_err(|v: Vec<u8>| format!("{s:?} is {} octets, a digest 32", v.len()))
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
        DataError::Refused { why, .. } => refusal(&mut v, why),
        DataError::Expired { name, keep: k } => {
            v["expired"] = json!({"name": name.to_string(), "keep": keep(k)});
        }
        DataError::RuleUnknown { collection, rule } => {
            v["rule_unknown"] =
                json!({"collection": collection.to_string(), "rule": rule.to_string()});
        }
        DataError::Introduction { offer, why } => {
            let mut i = json!({"offer": offer.to_string(), "why": intro_refusal(why)});
            if let IntroRefusal::WrongProof { left } = why {
                i["left"] = json!(left);
            }
            v["introduction"] = i;
        }
        _ => {}
    }
    v
}

/// An introduction's refusal as the error answers name it.
fn intro_refusal(why: &IntroRefusal) -> &'static str {
    match why {
        IntroRefusal::Unknown => "unknown",
        IntroRefusal::Used => "used",
        IntroRefusal::Expired => "expired",
        IntroRefusal::Closed => "closed",
        IntroRefusal::WrongProof { .. } => "wrong-proof",
        IntroRefusal::Forged => "forged",
        IntroRefusal::Conflict => "conflict",
    }
}

/// The fields of a refusal an error answer carries beside its message:
/// `outside_cut` (the cut key or writer and the cut's signer), `suspected`
/// (the key this device marked suspected, and since when), `untrusted`
/// (why the durable rule refuses an issuer on its chain).
fn refusal(v: &mut Value, why: &Refusal) {
    match why {
        Refusal::OutsideCut(cut) => {
            v["outside_cut"] = json!({
                "of": cut.of.to_string(),
                "signer": cut.signer.key().to_string(),
            });
        }
        Refusal::Suspected { key, since } => {
            v["suspected"] = json!({"key": key.to_string(), "since_ms": since.0});
        }
        Refusal::Untrusted { why } => v["untrusted"] = json!(why),
        Refusal::Group { member, .. } => v["group_member"] = json!(member.to_string()),
        _ => {}
    }
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
        NextStep::UpdateProgram => "update-program",
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
        NextStep::UpdateProgram => {
            "run a program that knows the collection's merge rule: this one holds its versions \
             but reads them under no other rule"
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
        Got::State(s) => json!({"state": state(&s)}),
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

/// A merged state: its name, collection, frontier, value, and the versions
/// held here that are not in the value, each with why.
fn state(s: &State) -> Value {
    json!({
        "name": s.name.to_string(),
        "collection": s.collection.to_string(),
        "at": frontier(&s.at),
        "value": merged(&s.value),
        "not_counted": s.not_counted.iter().map(|(i, why)| json!({"id": id(i), "why": why})).collect::<Vec<_>>(),
    })
}

/// A merged value: fields (`/merge/yrs`) as [`content`]; an element's
/// (`/ndn-tools/merge/element/v=1`, the one rule this program knows with
/// its own encoding) as `{"element": {<setting>: [variant...]}}`, each
/// variant its version (writer, seq), that version's digest (the basis a
/// change names) and its text as [`text_shown`].
fn merged(v: &ndn_data::Value) -> Value {
    match v {
        ndn_data::Value::Fields(c) => content(c),
        ndn_data::Value::Rule(b) => match ElementValue::decode(b) {
            Ok(e) => {
                let settings: Map<String, Value> = e
                    .settings
                    .iter()
                    .map(|(s, variants)| {
                        let variants = variants
                            .iter()
                            .map(|v| {
                                json!({
                                    "writer": v.writer,
                                    "seq": v.seq,
                                    "digest": hex(&v.digest),
                                    "text": text_shown(&v.text),
                                })
                            })
                            .collect();
                        (s.clone(), Value::Array(variants))
                    })
                    .collect();
                json!({"element": settings})
            }
            Err(_) => json!({"rule": {"len": b.len(), "sha256": hex(&Sha256::digest(b))}}),
        },
    }
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
/// (re-admitted) names, the SHA-256 of the key's public key it binds
/// (`key_digest`) and the full name of its manifest's root packet
/// (`manifest`), each `null` when the cut has none.
fn revocation_cut(c: &RevocationCut) -> Value {
    json!({
        "key": c.key().to_string(),
        "ranges": c.ranges().iter().map(|r| json!({
            "prefix": r.prefix.to_string(),
            "runs": r.runs.iter().map(|(first, last)| json!([first, last])).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "exact": c.exact().iter().map(ToString::to_string).collect::<Vec<_>>(),
        "key_digest": c.key_digest().map(|d| hex(d.as_slice())),
        "manifest": c.manifest().map(ToString::to_string),
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
        "parents": frontier(v.parents.frontier()),
        "rule": v.rule.as_ref().map(ToString::to_string),
        "type": {"name": v.type_id.name.to_string(), "revision": v.type_id.revision},
        "keep": keep(&v.keep),
        "dated_ms": v.dated.0,
        "group": v.group.map(|g| json!({"id": g.id, "count": g.count})),
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
        Change::Withdrawn { id: i, why, .. } => {
            let mut w = json!({"id": id(i), "why": why.to_string()});
            match why {
                // A cut: the key or writer cut and who signed the cut.
                Refusal::OutsideCut(cut) => {
                    w["cut_of"] = json!(cut.of.to_string());
                    w["cut_signer"] = json!(cut.signer.key().to_string());
                }
                // An issuer refused by the durable rule: never re-admitted.
                Refusal::Untrusted { .. } => w["untrusted"] = json!(true),
                // A member of its group refused: none of the group counts.
                Refusal::Group { member, .. } => w["group_member"] = json!(member.to_string()),
                _ => {}
            }
            json!({ "withdrawn": w })
        }
        Change::Pruned { id: i, by, .. } => json!({"pruned": {"id": id(i), "by": prune(by)}}),
        Change::Expired { id: i, keep: k, .. } => {
            json!({"expired": {"id": id(i), "keep": keep(k)}})
        }
        Change::NotCounted { id: i, why, .. } => {
            json!({"not_counted": {"id": id(i), "why": why}})
        }
        Change::Counted { id: i, .. } => json!({"counted": {"id": id(i)}}),
        Change::Equivocation { first, second, .. } => json!({"equivocation": {
            "first": equivocal(first),
            "second": equivocal(second),
        }}),
        Change::Lagged { .. } => json!({"lagged": {
            "what_to_do": "changes were dropped while this watch was behind; it lists the collection again from the start"
        }}),
        Change::Untracked { writer, why, .. } => json!({"untracked": {
            "writer": writer.key().to_string(),
            "why": why,
        }}),
    }
}

/// One version of an equivocation: whole when it is of the collection told
/// for, else by name and id only.
fn equivocal(e: &Equivocal) -> Value {
    match e {
        Equivocal::Here(v) => version(v),
        Equivocal::Elsewhere { name, id: i } => json!({
            "id": id(i),
            "name": name.to_string(),
        }),
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
