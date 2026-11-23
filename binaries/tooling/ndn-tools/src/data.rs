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
//! A collection whose members record names a merge rule the device does
//! not know is held unreadable: `get` and the puts answer `RuleUnknown`
//! (next: update the program).
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
//! - `share <collection> [rule=merge|merge:<function>|log]
//!   [writers=<prefix>,<prefix>...] [readers=<kind>:<name>,...]`: the
//!   members record of a collection of this device's namespace, its first
//!   revision or the next. `rule=merge` (the default) is the newest
//!   register, `/ndf/merge/newest/v=1`; `rule=merge:<function>` names the
//!   rule by its full name (a device that does not know it holds the
//!   collection unreadable: `RuleUnknown`, next: update the program);
//!   `rule=log` keeps every member's versions (the newest is the latest).
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
//!   Or a change of the folder's record in force: `add_writers=`,
//!   `remove_writers=` (prefixes), `add_readers=`, `remove_readers=`
//!   (`<kind>:<name>`), applied when the device signs, so a member added
//!   meanwhile (an introduction's admission) stays; a change that changes
//!   nothing signs nothing.
//! - `members <folder or collection>`: the members record in force over
//!   it — rule, writers, readers — whoever signed it; a watch shows each
//!   change of it as `members`.
//! - `put <collection> <field>=<value>...`: a version of type `/types/note`
//!   revision 1, kept forever, into a collection that keeps entries (the log
//!   rule; a register collection answers `use put_op`). A value `@<path>` is
//!   the bytes of the file at `<path>` (`@@…` is a value starting with `@`).
//!   A payload larger than a version carries inline travels in pieces.
//!   Every put answer shows the fields it put.
//! - `put_op <collection> text=<value> | hex=<octets>`: a version of a
//!   register collection (rule `/ndf/merge/newest/v=1`), of type
//!   `/types/bytes`, carrying those bytes; `text=` alone is a removal. A text
//!   `@<path>` is the bytes of the file. The answer shows the bytes.
//! - `get <name>`: a collection's state (the register's value: the newest
//!   version's bytes, as `{"by","bytes"}` with `by` the writer's person in
//!   hex; or, under the log rule, its newest version), or an exact version
//!   by its name. A field value longer than 256 octets is shown as its
//!   length and SHA-256, not its bytes.
//!   Every version shown carries its packet's implicit digest (`digest`,
//!   hex) and, of a register version, its bytes (`bytes`, as in `put_op`).
//! - `watch <collection or folder>`: from now on, every change as its own
//!   line, for a folder of every collection under it,
//!   those created later included, each line naming the change's
//!   collection.
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
//!   `<when>` by this device's clock, closed to an asker by its
//!   `<n>`-th wrong try (and to everyone at the device's overall cap). The
//!   answer carries the code: `link` (`ndn-trust://intro/…`, one
//!   QR; it names the relays this namespace advertises, so the joiner's
//!   forwarder reaches this device through one of them before it trusts
//!   anything of this namespace) and `words` (the offer's name and 24
//!   words, without relays). When the joiner asks, this device adopts the
//!   joiner's namespace through its daemon and adds it to the folder's
//!   members with the role.
//! - `close_offer <offer>`: close an offer this device made (its name, as
//!   `offer` printed it), durably: the offer admits no one new from then on
//!   (every other key's ask is refused as closed) and still answers the key
//!   it admitted until the offer expires. Removing an introduced member
//!   from the folder closes the offers it used the same way.
//! - `join <code>`: join the folder a code offers (its link, or its words
//!   in double quotes): the answer names the folder, the role and the
//!   inviter's namespace, which this device's daemon now holds (adopted
//!   through `security/context-adopt`, as `ndn-ctl adopt` asks, so it also
//!   routes it over its relay links). An offer refused answers
//!   `"introduction"`: the offer and why (`unknown`, `used`, `expired`,
//!   `closed`, `wrong-proof` with `left`, `forged`, `conflict`, `hint` (a
//!   short code's first contact came damaged or does not prove itself:
//!   retry at most three times), `hint-mismatch` (it proves itself, but is
//!   not the inviter the code names: ask for a new code), `gone-unproven`
//!   (it says the offer is closed and cannot prove it: retry), or
//!   `inviter-conflict` when the inviter's namespace overlaps one this
//!   device trusts). The other writers a folder's records list, whose
//!   self-certifying namespaces this device's daemon does not hold, are
//!   adopted by name for the layer alone (data-layer spec §6.3): the host
//!   asks the daemon to carry each in transit (`security/transit`, so this
//!   host runs as a member of a group in the daemon's `[security]
//!   transit_groups` — a capability that changes nothing else of the
//!   daemon's trust — or as an operator) over one management connection it
//!   holds for its whole run, which owns the marks (the daemon releases
//!   them when the host ends), and fetches its trust-context versions over
//!   its own connection; the daemon needs a route to each such namespace.
//! - `signal-subscribe <folder or collection>`: from now on, every signal
//!   of the scope (live data that is never a version and never stored:
//!   `ndn_surface::signal`) from every member as its own line — the newest
//!   per (sender, address), never a backlog. Refused NotMember (ask the
//!   owner) or NotReady (no record or, sealed, no epoch key held yet: ask
//!   again). The device's signals start on the first signal verb, over a
//!   connection to the daemon of their own, which registers this device's
//!   namespace group `<ns>/32=sync` there (`rib/register`).
//! - `signal-open <folder or collection>`: a run over the scope (a fresh
//!   run key, its header signed by this device's key); `signal-send` and
//!   `signal-stream` open one when none is open. `signal-close <scope>`
//!   ends it.
//! - `signal-send <scope> <address> <payload>`: one signal on the scope's
//!   run (address at most 64 octets, payload at most 768): its sequence.
//! - `signal-stream <scope> <address> <count> <hz>`: `count` signals at
//!   `hz` per second (at most 120) on the scope's run, each payload
//!   `n=<i> sent_us=<µs since the epoch>`, answered once all are sent
//!   (while the next lines are read): the run, the first and last sequence,
//!   how long it took.
//! - `signal-stats`: the counters of this device's signals since they
//!   started — sent packets and octets, delivered, and what was dropped,
//!   by why.
//! - `signal-capture <group>`: register `group` (`<ns>/32=sync`) on the
//!   daemon over a connection of its own and print every signal Interest
//!   it is given — what a relay's operator sees of the signals its daemon
//!   forwards. Needs no device: started without `--device` (and `--pib`),
//!   the tool answers this verb and `quit` only.
//! - `quit` (or end of input).
//!
//! Output lines: `{"ready":{…}}` once the layer runs; per verb
//! `{"verb":…,"ok":{…}}` or `{"verb":…,"error":{"message","retry","next",
//! "next_step"}}` (with
//! `"outside_cut"`, the revoked key and the cut's signer, when a revocation's
//! cut refuses it, `"suspected"`, the key and since when, when this device
//! takes nothing new of a suspected key, `"untrusted"`, why, when the
//! chain of its signer is refused, `"rule_unknown"`, the collection and its
//! rule, when this program does not know the rule); per watched change
//! `{"watch":<collection or folder>,"collection":<the change's collection>,
//! "change":{…}}` (a withdrawn version says `why`,
//! with `cut_of` and `cut_signer` when a cut withdrew it); per received signal `{"signal":{"scope",
//! "sender","run","seq","address","payload","expires_ms","local"}}`
//! (address and payload as text, or `{"hex"}` when not UTF-8; with
//! `"latency_us"`, by this host's clock, when the payload carries
//! `sent_us=<µs>`, as a stream's does); per captured signal Interest
//! `{"capture":<group>,"interest":{"name","octets","params_hex",
//! "digest_ok","decodes_as"}}` (`SignalSealed` with its `key_id`, or
//! `SignalBody` with the `scope_digest` (16 octets, hex, of the scope's name:
//! the name itself rides only in a run header) and run it shows, or
//! `undecodable` with
//! why); a signal refusal's error carries `retry_after_ms` when over the
//! sender's rate. `--no-signal-ring` opens no local ring per run.
//! Logs go to stderr.

mod signal;

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

use ndn_app::{Connection, Consumer, IpcConnection, Node, demux_cert_fetcher};
use ndn_cert::CutFile;
use ndn_cert::report::TrustEvent;
use ndn_data::wire::log_name;
use ndn_data::{
    Age, Answer, Audience, Change, Clock, Config, Content, CutBound, DataError, DataLayer, Device,
    Equivocal, Frontier, Got, IntroRefusal, Introducer, Keep, NextStep, Offer, Payload, PutOptions,
    Refusal, Role, Rule, Share, ShareChange, Sharing, State, Timestamp, Transport, TypeId, Version,
    VersionId,
};
use ndn_ipc::events::{EventSubscription, Notice};
use ndn_ipc::{ForwarderClient, MgmtClient};
use ndn_packet::Name;
use ndn_security::{
    CertCache, FilePib, Keyring, RevocationCut, ScopedContext, SecurityManager, Validator,
};
use ndn_surface::signal::SignalOptions;
use ndn_sync::{DataStore, MemoryStore};
use ndn_trust_envelope::TrustEnvelope;

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
    /// enroll` certified it). Without it the tool hosts no device and
    /// answers `signal-capture` and `quit` only (a relay's capture).
    #[arg(long)]
    device: Option<String>,

    /// The daemon's PIB directory: the device's key and the trust contexts
    /// (needed with `--device`).
    #[arg(long)]
    pib: Option<String>,

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

    /// Open no local ring per signal run: this device's signals reach
    /// subscribers on this host through the forwarder only, as they reach
    /// other hosts.
    #[arg(long)]
    no_signal_ring: bool,

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
    let Some(device) = &cli.device else {
        return capture_host(&cli.face_socket).await;
    };
    let device: Name = device
        .parse()
        .map_err(|e| anyhow!("--device {device:?}: {e}"))?;
    let pib_dir = cli.pib.as_deref().ok_or_else(|| {
        anyhow!("--device {device} needs --pib: the daemon's PIB directory holding its key")
    })?;

    let pib = FilePib::open(pib_dir).map_err(|e| anyhow!("open PIB {pib_dir}: {e}"))?;
    let keys = SecurityManager::from_pib(&pib, &device).map_err(|e| {
        anyhow!("PIB {pib_dir}: {e}; enroll this device as {device} first (`ndn-fwd enroll`)")
    })?;
    ndn_cert::load_persisted_contexts(pib.root(), keys.keyring())
        .map_err(|e| anyhow!("PIB {pib_dir}: {e}"))?;
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
    // Introductions (`offer`, `join`): the anchor this device shows is its
    // namespace's context as the daemon stored it; another person's is
    // adopted through the daemon, as `ndn-ctl adopt` does. A writer's
    // namespace adopted for a folder alone is fetched over this host's own
    // connection, which the daemon carries in transit meanwhile — marked
    // over one management connection held for the host's whole run, which
    // owns the marks: the daemon releases them when it closes, however the
    // host ends.
    let connection: Arc<dyn Connection> = node.demux();
    let marks = MgmtClient::connect(&cli.face_socket)
        .await
        .map_err(|e| anyhow!("connect to the forwarder at {}: {e}", cli.face_socket))?;
    config.introducer = Some(Arc::new(DaemonIntroducer {
        face_socket: cli.face_socket.clone(),
        pib_root: pib.root().to_path_buf(),
        namespace: keyring.context_for(&device).namespace().clone(),
        keyring: Arc::clone(&keyring),
        connection,
        marks: Arc::new(marks),
        carried: std::sync::Mutex::new(std::collections::HashSet::new()),
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
    let signals = signal::SignalHost::new(
        layer.clone(),
        cli.face_socket.clone(),
        SignalOptions {
            local_ring: !cli.no_signal_ring,
            ..SignalOptions::default()
        },
    );

    // Signal streams in flight: each prints its answer once done, while
    // the next lines are read.
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
        let outcome = if verb.starts_with("signal-") {
            signals.run(verb, args).await.map_err(|e| signal::error(&e))
        } else {
            run(&layer, &clock, verb, args)
                .await
                .map_err(|e| data_error(&e))
        };
        if let Some(line) = answer_line(verb, outcome, &mut later) {
            println!("{line}");
        }
    }
    // Every signal stream still waiting answers before the layer stops.
    while later.join_next().await.is_some() {}
    signals.shutdown();
    layer.shutdown();
    Ok(())
}

/// The answer line of a verb's outcome (its error already an error
/// object); `None` for a verb answered later, whose line `later` prints
/// once it is done.
fn answer_line(verb: &str, outcome: Result<Verb, Value>, later: &mut JoinSet<()>) -> Option<Value> {
    match outcome {
        Ok(Verb::Done(ok)) => Some(json!({"verb": verb, "ok": ok})),
        Ok(Verb::Later(answer)) => {
            let verb = verb.to_owned();
            later.spawn(async move {
                let line = match answer.await {
                    Ok(ok) => json!({"verb": verb, "ok": ok}),
                    Err(e) => json!({"verb": verb, "error": e}),
                };
                println!("{line}");
            });
            None
        }
        Ok(Verb::Usage(why)) => Some(usage_error(verb, &why)),
        Err(e) => Some(json!({"verb": verb, "error": e})),
    }
}

/// Without `--device`: no data layer and no key, only `signal-capture`
/// (what a relay's operator sees of the signals its daemon forwards) and
/// `quit`.
async fn capture_host(face_socket: &str) -> Result<()> {
    println!("{}", json!({"ready": {"device": null}}));
    let mut later = JoinSet::new();
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
        let outcome = match verb.as_str() {
            "quit" => break,
            "signal-capture" => signal::capture(face_socket, args)
                .await
                .map_err(|e| signal::error(&e)),
            _ => Ok(Verb::Usage(format!(
                "this ndn-data hosts no device (started without --device): it answers \
                 signal-capture and quit; start it with --device and --pib for {verb}"
            ))),
        };
        if let Some(line) = answer_line(verb, outcome, &mut later) {
            println!("{line}");
        }
    }
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

/// How long the daemon may take to adopt an anchor link: an inline context
/// of another kind of namespace needs no fetch, but a self-certifying
/// namespace not held is adopted by name — version 1, the newest's name and
/// the newest, then a walk of at most `ndn_cert::MAX_CATCH_UP_TIME` (40 s)
/// when versions lie in between; the link's inline context is never taken
/// alone.
const ADOPT_LIMIT: Duration = Duration::from_secs(60);

/// The data layer's introductions on a daemon: this device's anchor is its
/// namespace's trust context as the daemon stored it in the PIB; another
/// person's anchor link is adopted by the daemon (`security/context-adopt`,
/// as `ndn-ctl adopt` asks), which validates and stores it and routes the
/// namespace over its relay links — a self-certifying namespace not held by
/// name over the network, the link's version 1 only compared with the
/// fetched one (a different one refused as a fork), never offline — and
/// then by this host's keyring from the PIB, so the layer's validator
/// trusts it before `adopt` answers.
///
/// A writer's self-certifying namespace that a folder's records list, which
/// the daemon does not hold, is adopted for the layer alone
/// (`adopt_scoped`, data-layer spec §6.3): the daemon is asked to carry it
/// in transit first (`security/transit`, one mark) unless this host has it
/// carried already — whether the layer adopts it anew or refreshes from a
/// version it held, one it kept across a restart included — since the
/// daemon refuses that namespace's Data as one not held, the adoption's own
/// fetches of its trust-context versions included; then the versions are
/// fetched over this host's own connection and checked here
/// (`ndn_cert::adopt_scoped`), into no keyring. A mark this adoption took
/// is taken back if it fails, and the one mark of a namespace when the
/// layer releases it (`release_scoped`); releasing one not carried does
/// nothing. Every mark is asked over [`marks`](Self::marks), the connection
/// that owns it: when the host ends — crashed or not — the daemon releases
/// whatever it still holds.
struct DaemonIntroducer {
    face_socket: String,
    pib_root: PathBuf,
    /// This device's namespace (empty: none governs its name).
    namespace: Name,
    keyring: Arc<Keyring>,
    /// This host's own connection to the daemon, which a namespace adopted
    /// for a folder is fetched over.
    connection: Arc<dyn Connection>,
    /// The management connection the transit marks are asked over and
    /// owned by, open for the host's whole run.
    marks: Arc<MgmtClient>,
    /// The namespaces this host has the daemon carry in transit for the
    /// layer: one mark each.
    carried: std::sync::Mutex<std::collections::HashSet<Name>>,
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

    /// Adopt `namespace` for the layer alone, refreshed from `held` when the
    /// layer holds a version already; carried in transit once, whichever.
    async fn adopt_for_folders(
        &self,
        namespace: &Name,
        held: Option<&ScopedContext>,
    ) -> Result<ScopedContext, String> {
        let newly = self
            .carried
            .lock()
            .expect("the host's lock")
            .insert(namespace.clone());
        if newly && let Err(why) = mark_transit(&self.marks, namespace, true).await {
            self.carried
                .lock()
                .expect("the host's lock")
                .remove(namespace);
            return Err(why);
        }
        let mut exchange = HostExchange(Consumer::new(Arc::clone(&self.connection)));
        match ndn_cert::adopt_scoped(None, &mut exchange, namespace, held).await {
            Ok(scoped) => Ok(scoped),
            Err(e) => {
                if newly {
                    self.carried
                        .lock()
                        .expect("the host's lock")
                        .remove(namespace);
                    if let Err(why) = mark_transit(&self.marks, namespace, false).await {
                        tracing::warn!(%namespace, "{why}");
                    }
                }
                Err(format!(
                    "adopting {namespace} by name for the folders that list it as a writer \
                     failed: {e}; its versions there wait, and it is asked again (reach its \
                     devices, through a route to {namespace} on this device's daemon, for it to \
                     succeed)"
                ))
            }
        }
    }
}

/// Ask the daemon over `marks` to carry `namespace` in transit (`carry`:
/// one mark more, owned by that connection) or to take one mark back.
async fn mark_transit(marks: &MgmtClient, namespace: &Name, carry: bool) -> Result<(), String> {
    let what = if carry { "carry" } else { "stop carrying" };
    marks
        .security_transit(namespace, carry)
        .await
        .map(|_| ())
        .map_err(|e| match ndn_ipc::trust_refusal_in(&e) {
            Some(refusal) if refusal.is(ndn_cert::report::code::TRANSIT_NOT_PERMITTED) => format!(
                "the daemon refused to {what} {namespace} in transit: {refusal} (run this host \
                 as a member of a group in the daemon's `[security] transit_groups`, which may \
                 carry namespaces in transit and change nothing else of its trust, then start \
                 it again)"
            ),
            Some(refusal) => {
                format!("the daemon refused to {what} {namespace} in transit: {refusal}")
            }
            None => format!(
                "asking the daemon to {what} {namespace} in transit: {e}; if the daemon \
                 restarted, start this host again (the daemon released this host's marks with \
                 its connection)"
            ),
        })
}

/// Fetches over this host's own connection to the daemon, for an adoption
/// by name: each Interest asked once (the layer asks the adoption again).
struct HostExchange(Consumer);

impl ndn_cert::CaExchange for HostExchange {
    async fn express(&mut self, interest: Bytes) -> Result<ndn_packet::Data, ndn_cert::CertError> {
        self.0
            .fetch_wire(interest, ndn_app::DEFAULT_TIMEOUT)
            .await
            .map_err(|e| ndn_cert::CertError::Transport(e.to_string()))
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

    fn adopt_scoped<'a>(
        &'a self,
        namespace: &'a Name,
        held: Option<&'a ScopedContext>,
    ) -> ndn_data::intro::Scoping<'a> {
        Box::pin(self.adopt_for_folders(namespace, held))
    }

    fn release_scoped(&self, namespace: &Name) {
        if !self
            .carried
            .lock()
            .expect("the host's lock")
            .remove(namespace)
        {
            return;
        }
        let (marks, namespace) = (Arc::clone(&self.marks), namespace.clone());
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(
                %namespace,
                "released with no runtime to tell the daemon on: its mark stays until this host \
                 ends"
            );
            return;
        };
        runtime.spawn(async move {
            if let Err(why) = mark_transit(&marks, &namespace, false).await {
                tracing::warn!(
                    %namespace,
                    "{why}; the daemon keeps carrying it in transit until this host ends"
                );
            }
        });
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
    /// Replied to later, while the next lines are read (a signal stream):
    /// its `ok` object, or its error object.
    Later(BoxFuture<'static, Result<Value, Value>>),
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
            let sharing = match folder_sharing(layer.namespace(), options) {
                Ok(s) => s,
                Err(e) => return Ok(Verb::Usage(format!("{e}; {SHARE_FOLDER_USAGE}"))),
            };
            layer.share_folder(&folder, sharing).await?;
            Ok(Verb::Done(json!({"folder": folder.to_string()})))
        }
        ("share_folder", _) => usage(SHARE_FOLDER_USAGE),
        ("members", [n]) => {
            let n = match name(n) {
                Ok(n) => n,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let share = layer.members(&n).await?;
            Ok(Verb::Done(
                json!({"name": n.to_string(), "members": members(&share)}),
            ))
        }
        ("members", _) => usage("usage: members <folder or collection>"),
        ("put", [collection, rest @ ..]) => {
            let collection = match name(collection) {
                Ok(c) => c,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let content = match fields_of(rest).await {
                Ok(c) => c,
                Err(e) => return Ok(Verb::Usage(format!("{e}; {PUT_USAGE}"))),
            };
            let shown = self::content(&content);
            let id = layer.put(&collection, content, put_type(NOTE)).await?;
            let mut ok = put_answer(layer, &collection, &id);
            ok["fields"] = shown;
            Ok(Verb::Done(ok))
        }
        ("put", _) => usage(PUT_USAGE),
        ("put_op", [collection, rest @ ..]) => {
            let collection = match name(collection) {
                Ok(c) => c,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let op = match op_of(rest).await {
                Ok(op) => op,
                Err(e) => return Ok(Verb::Usage(format!("{e}; {PUT_OP_USAGE}"))),
            };
            let shown = bytes_shown(&op);
            let id = layer.put_op(&collection, op, put_type(BYTES)).await?;
            let mut ok = put_answer(layer, &collection, &id);
            ok["bytes"] = shown;
            Ok(Verb::Done(ok))
        }
        ("put_op", _) => usage(PUT_OP_USAGE),
        ("get", [n]) => {
            let n = match name(n) {
                Ok(n) => n,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            Ok(Verb::Done(answer(layer.get(&n).await?)))
        }
        ("get", _) => usage("usage: get <name>"),
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
                "short": code.short,
                "short_why": code.short_why,
                "share": code.share(),
            })))
        }
        ("offer", _) => usage(OFFER_USAGE),
        ("close_offer", [offer]) => {
            let offer = match name(offer) {
                Ok(o) => o,
                Err(e) => return Ok(Verb::Usage(format!("{e}; {CLOSE_OFFER_USAGE}"))),
            };
            layer.close_offer(&offer).await?;
            Ok(Verb::Done(json!({
                "offer": offer.to_string(),
                "closed": true,
            })))
        }
        ("close_offer", _) => usage(CLOSE_OFFER_USAGE),
        ("join", parts @ [_, ..]) => {
            // A short code is several tokens (a device name, a contact, words): they
            // are one code.
            let code = parts.join(" ");
            let joined = layer.join(&code).await?;
            Ok(Verb::Done(json!({
                "folder": joined.folder.to_string(),
                "role": role_word(joined.role),
                "inviter": joined.inviter.to_string(),
            })))
        }
        ("join", _) => usage(JOIN_USAGE),
        _ => usage(
            "verbs: share, share_folder, members, put, put_op, get, watch, \
             suspect, unsuspect, cut, refused, offer, close_offer, join, \
             signal-subscribe, \
             signal-open, signal-send, signal-stream, signal-close, signal-stats, signal-capture, \
             quit",
        ),
    }
}

const SHARE_USAGE: &str = "usage: share <collection> [rule=merge|merge:<function>|log] \
                           [writers=<prefix>,<prefix>...] [readers=<kind>:<name>,...] (kind \
                           person, device or group)";

const SHARE_FOLDER_USAGE: &str = "usage: share_folder <folder> \
                                  [rule=merge|merge:<function>|log] \
                                  [writers=<prefix>,<prefix>...] [readers=<kind>:<name>,...] \
                                  | [add_writers=<prefix>,...] [remove_writers=<prefix>,...] \
                                  [add_readers=<kind>:<name>,...] \
                                  [remove_readers=<kind>:<name>,...] (kind person, device or \
                                  group; the folder is <ns>/32=data/<path>, and its record \
                                  governs every collection under it; add_/remove_ change the \
                                  record in force when it is signed, keeping whom it does not \
                                  name)";

/// A `share` (or `share_folder`) line's options over the defaults: the
/// merge rule `/ndf/merge/newest/v=1`, writers the namespace `ns`, readers
/// the person `ns`. `rule=merge:<function>` merges with the rule of that
/// full name. `readers=` with nothing after it lists no readers (not sealed).
fn share_options(ns: &Name, options: &[String]) -> Result<Share, String> {
    let merge = || Rule::Merge {
        function: "/ndf/merge/newest/v=1".parse().expect("a valid name"),
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
            Some(("rule", r)) => match r.strip_prefix("merge:") {
                Some(function) => {
                    share.rule = Rule::Merge {
                        function: name(function)?,
                    };
                }
                None => {
                    return Err(format!(
                        "rule {r:?} is neither merge, merge:<function> nor log"
                    ));
                }
            },
            Some(("writers", v)) => share.writers = list(v).map(name).collect::<Result<_, _>>()?,
            Some(("readers", v)) => {
                share.readers = list(v).map(reader).collect::<Result<_, _>>()?;
            }
            _ => return Err(format!("{o:?} is not rule=, writers= or readers=")),
        }
    }
    Ok(share)
}

/// A reader `<kind>:<name>`, kind person, device or group.
fn reader(r: &str) -> Result<Audience, String> {
    let name = |s: &str| {
        s.parse::<Name>()
            .map_err(|e| format!("{s:?} is no name: {e}"))
    };
    match r.split_once(':') {
        Some(("person", n)) => name(n).map(Audience::Person),
        Some(("device", n)) => name(n).map(Audience::Device),
        Some(("group", n)) => name(n).map(Audience::Group),
        _ => Err(format!(
            "reader {r:?} is not <kind>:<name> with kind person, device or group"
        )),
    }
}

/// A `share_folder` line's options: a change of the record in force
/// (`add_writers=`, `remove_writers=`, `add_readers=`, `remove_readers=`),
/// or else the whole record ([`share_options`]); never both.
fn folder_sharing(ns: &Name, options: &[String]) -> Result<Sharing, String> {
    const CHANGE: [&str; 4] = [
        "add_writers",
        "remove_writers",
        "add_readers",
        "remove_readers",
    ];
    let changes = |o: &String| o.split_once('=').is_some_and(|(k, _)| CHANGE.contains(&k));
    if !options.iter().any(changes) {
        return share_options(ns, options).map(Sharing::Whole);
    }
    let names = |v: &str| {
        v.split(',')
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.parse::<Name>()
                    .map_err(|e| format!("{s:?} is no name: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()
    };
    let readers = |v: &str| {
        v.split(',')
            .filter(|s| !s.is_empty())
            .map(reader)
            .collect::<Result<Vec<_>, _>>()
    };
    let mut change = ShareChange::default();
    for o in options {
        match o.split_once('=') {
            Some(("add_writers", v)) => change.add_writers.extend(names(v)?),
            Some(("remove_writers", v)) => change.remove_writers.extend(names(v)?),
            Some(("add_readers", v)) => change.add_readers.extend(readers(v)?),
            Some(("remove_readers", v)) => change.remove_readers.extend(readers(v)?),
            _ => {
                return Err(format!(
                    "{o:?} is no change: a change takes add_writers=, remove_writers=, \
                     add_readers= and remove_readers= only (share the whole record with rule=, \
                     writers= and readers= alone)"
                ));
            }
        }
    }
    Ok(Sharing::Change(change))
}

const PUT_USAGE: &str = "usage: put <collection> <field>=<value>... (a value @<path> is the \
                         file's bytes, @@... a value starting with @)";

const PUT_OP_USAGE: &str = "usage: put_op <collection> text=<value> | hex=<octets> (the \
                            register's write: the collection's newest value, `text=` alone a \
                            removal; a text @<path> is the file's bytes, @@... a text starting \
                            with @)";

/// The type of versions `put` writes.
const NOTE: &str = "/types/note";
/// The type of versions `put_op` writes.
const BYTES: &str = "/types/bytes";

fn put_type(type_name: &str) -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: type_name.parse().expect("a valid name"),
            revision: 1,
        },
        keep: Keep::Forever,
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

const CLOSE_OFFER_USAGE: &str = "usage: close_offer <offer> (the offer's name an offer printed, \
                                 made by this device: it admits no one new, and still answers \
                                 the one it admitted until it expires)";

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

/// The bytes a `put_op` line gives for a register collection: `text=<value>`
/// (a value as [`field_value`] reads it; `text=` alone is empty, a removal)
/// or `hex=<octets>`.
async fn op_of(words: &[String]) -> Result<Bytes, String> {
    let [word] = words else {
        return Err(format!("{} words, not one", words.len()));
    };
    match word.split_once('=') {
        Some(("hex", octets)) => unhex(octets).map(Bytes::from),
        Some(("text", value)) => field_value(value).await,
        _ => Err(format!("{word:?} is neither text= nor hex=")),
    }
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
        DataError::Refused { why, .. } => refusal(&mut v, why),
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
        IntroRefusal::InviterConflict { .. } => "inviter-conflict",
        IntroRefusal::Hint { .. } => "hint",
        IntroRefusal::HintMismatch { .. } => "hint-mismatch",
        IntroRefusal::GoneUnproven { .. } => "gone-unproven",
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

/// A `get`'s answer: what it got and how old it may be.
fn answer(a: Answer) -> Value {
    let mut ok = match a.got {
        Got::State(s) => json!({"state": state(&s)}),
        Got::Version(v) => json!({"version": version(&v)}),
    };
    ok["age"] = match a.age {
        Age::Exact => json!("exact"),
        Age::Newest { unconfirmed_for } => {
            json!({"unconfirmed_for_ms": unconfirmed_for.as_millis() as u64})
        }
    };
    ok
}

/// A merged state: its collection, frontier and value.
fn state(s: &State) -> Value {
    json!({
        "collection": s.collection.to_string(),
        "at": frontier(&s.at),
        "value": value(&s.value),
    })
}

/// A state's value, the newest register's `by ‖ bytes`: `by`, the 32
/// octets of the writer's person (hex; zeros when its key lies under no
/// person's namespace), and `bytes` as [`bytes_shown`] (`""`, with
/// `"removed": true`, when the winner is a removal); `{"empty": true}` while
/// the register holds no version.
fn value(v: &ndn_data::Value) -> Value {
    match v.bytes() {
        Some(b) if b.len() >= 32 => {
            let (by, bytes) = b.split_at(32);
            let mut shown = json!({"by": hex(by), "bytes": bytes_shown(bytes)});
            if bytes.is_empty() {
                shown["removed"] = json!(true);
            }
            shown
        }
        _ => json!({"empty": true}),
    }
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
        m.insert(field.to_owned(), bytes_shown(value));
    }
    Value::Object(m)
}

/// Octets as text when they are UTF-8, else as `{"hex": …}`; longer than
/// [`SHOWN_MAX`] octets, as `{"len": …, "sha256": …}`.
fn bytes_shown(value: &[u8]) -> Value {
    if value.len() > SHOWN_MAX {
        json!({"len": value.len(), "sha256": hex(&Sha256::digest(value))})
    } else {
        match std::str::from_utf8(value) {
            Ok(s) => json!(s),
            Err(_) => json!({"hex": hex(value)}),
        }
    }
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
        "dated_ms": v.dated.0,
        "digest": hex(&v.digest),
        "bytes": v.op.as_deref().map(bytes_shown),
        "payload": match &v.payload {
            Payload::Entry(c) => json!({"entry": content(c)}),
            Payload::Large { size } => json!({"large": size}),
        },
    })
}

/// A members record in force, as `members` answers and `Change::Members`
/// tells it: the rule, writer prefixes and readers (`<kind>:<name>`, as
/// `share_folder` takes them).
fn members(s: &Share) -> Value {
    json!({
        "rule": match &s.rule {
            Rule::Merge { function } => format!("merge:{function}"),
            Rule::Log => "log".into(),
        },
        "writers": s.writers.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "readers": s.readers.iter().map(|r| match r {
            Audience::Person(n) => format!("person:{n}"),
            Audience::Device(n) => format!("device:{n}"),
            Audience::Group(n) => format!("group:{n}"),
        }).collect::<Vec<_>>(),
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
                _ => {}
            }
            json!({ "withdrawn": w })
        }
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
        Change::NotAdopted {
            namespaces, why, ..
        } => json!({"not_adopted": {
            "namespaces": namespaces.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "why": why,
        }}),
        Change::Members { share, .. } => json!({"members": members(share)}),
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
