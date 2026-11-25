//! `ndn-heap` — host one device's data layer (`ndn_heap::Node`) and its
//! introductions (`ndn_invite::Invites`) on a running `ndn-fwd`, and drive
//! their verbs as lines on stdin, one JSON object per line on stdout.
//!
//! Why a tool and not the daemon: a separate process attached over the face
//! socket exposes the data layer on a real daemon while ndn-fwd itself
//! carries no data-layer code. It wires the libraries and does nothing else:
//! the device's key and trust contexts come from the daemon's PIB exactly as
//! `ndn-put --pib` loads them, and the device's X25519 seal (recipient) secret
//! is kept in that PIB beside its key (`SecurityManager::put_secret`), made on
//! the first run; the validator is the trust contexts' keyring (their anchors
//! and schemas) with a certificate fetcher over the device's own connection,
//! so a peer's certificate chain is fetched and walked to the anchor on first
//! use. The keyring follows the daemon: on each newer trust-context version
//! the daemon tells of on its trust stream
//! (`/localhost/nfd/security/notifications`: a revocation it pulled or was
//! pushed, one `ndn-fwd revoke` or `readmit` signed), the host adopts the
//! version the daemon stored in the PIB, and the data layer re-checks what it
//! holds against it (an entry a new revocation's cut does not accept is
//! withdrawn; one it re-admits is fetched and delivered). Entries live in
//! memory for the life of the process, and with `--store <dir>` also one file
//! each under `<dir>`, so a host started again on the same directory resumes
//! its logs (and its key's sequence reservations) where it stopped.
//!
//! `--clock-offset-ms <ms>` runs the device's wall clock that many
//! milliseconds off the system's (negative: behind). It changes only the
//! times the device reads (`until=` of an offer, `suspect` without a time,
//! a cut's bound), never what any device accepts: validity of data does not
//! depend on a clock.
//!
//! `--holder <device>` (repeatable) names a device that keeps copies of the
//! spaces, such as the node `ndn-repo follow` runs on (`/hold/node/repo`): the
//! data layer asks the holders for a held copy of an entry, in the order given,
//! after the vouched relays and within the same bound on asks, so a holder
//! never displaces a relay. A holder is asked for copies alone (never for an
//! epoch key) and is only a place to ask: what it serves is verified like every
//! packet. A name that is empty or no name is refused at the command line.
//!
//! Two connections to the forwarder carry the data layer (fetching and
//! serving the device's prefix; State Vector Sync), a third the introductions'
//! transit marks (below). A space's sync group `<ns>/32=sync/<rest>` needs
//! nothing set up: a daemon holding the namespace's trust context runs it
//! with the `multicast` strategy and routes it over each link to a device of
//! the namespace, beside this connection's registration of it.
//!
//! The device's namespace `<ns>` is that of the trust context governing its
//! name in the PIB (`/nt` for `/nt/member/phone`; `/home/bob` for
//! `/home/bob/member/phone` once the PIB holds `/home/bob`'s context). A
//! **space** is named `<ns>/32=data/<c1>[/<c2>…]` (1 to 4 components,
//! `/home/bob/32=data/notes`): the keyword `32=data` marks where the owner's
//! namespace ends. A **path** inside a space is relative to it, 1 to 8
//! components (`trip/day1`, with or without a leading `/`). A name that is
//! no space (or a path that is no path) is refused with why. A space is
//! opened here by the first verb that names it (`create` makes it; `members`,
//! `put`, `get`, `watch` and `offer` open one made elsewhere that this device
//! is a member of); every space the device held is opened again at start.
//!
//! Verbs (one per line; values with spaces in double quotes, `\"` and `\\`
//! escaped inside them). A value `@<path>` is the bytes of the file at
//! `<path>` (`@@…` is a value starting with `@`):
//!
//! - `create <space> [writers=<ns>,<ns>…] [readers=anyone|<ns>,<ns>…]`: make a
//!   space of this device's namespace. Writers and readers are persons
//!   (namespaces); the owner is an implicit writer and reader. `readers=`
//!   absent or with nothing after it: the owner alone (private, sealed);
//!   `readers=anyone`: a public space (never sealed). Answer `{"space"}`.
//!   Another namespace's space: refused `NotOwner` (next: `use-owner-device`).
//! - `change <space> [add_writers=<ns>,…] [add_readers=<ns>,…] [remove=<ns>,…]`:
//!   one Members entry (owner devices only: any other answers `NotOwner`);
//!   `remove` takes a person from both roles. Answer `{"space","id"}` (the
//!   entry, `id` below).
//! - `members <space>`: the space's members in force, local, whoever signed
//!   them: `{"space","members":{"owner","writers":[…],"readers":"anyone"|[…]},
//!   "known":<bool>}` (`known` false while the space's first Members entry
//!   has not arrived; the lists are then the owner alone). A watch shows each
//!   change of it as `members`.
//! - `put <space> <path> (text=<value>|hex=<octets>) [--durable]`: write the
//!   bytes at the path of the space; an empty value (`text=`) removes the path.
//!   `--durable` returns after a flush that covers the entry (`PutOptions {
//!   durable: Some(true) }`); without it the default of the layer holds (durable
//!   exactly when the space's sync state holds no other device). Answer
//!   `{"space","path","id","removed":<bool>}` plus the value as an item shows
//!   it (`len`, `text`/`hex`/`sha256`).
//! - `get <space> <path>`: the path's value, local, never waiting for the
//!   network: `{"space","path","item":<item>|null}` (`null`: never put, or
//!   removed).
//! - `watch <space>`: from now on, first every current head, then every
//!   change, each as its own line (below), until the process ends. A watch that
//!   lagged resumes by itself (the layer's `Lagged` is shown, then the
//!   watch lists the heads again).
//! - `follow <space>`: carry the space (`Node::follow`): verify, store and serve
//!   it, publish no vector entry, hold no read key. Answer `{"space"}`; a
//!   follower stores nothing it cannot verify, so the host must hold the owner's
//!   trust context (else entries wait, `Pending(adoption)`). **The relays are
//!   told**: for each space this device follows — open here as a member or
//!   carried — of an owner other than its own namespace, the host marks the
//!   space's sync group (`<owner>/32=sync/<space>`, `ndn_heap::wire::sync_group_of`)
//!   on the daemon over its one management connection (`security/transit`),
//!   and the daemon's links tell the relays they use to route exactly that
//!   group to this device, no other space of the same owner (ndn-link.md
//!   §5.10). A daemon that refuses (this host not in its `transit_groups`, no
//!   links, more than 32 spaces) says why: the answer then adds
//!   `{"relays_not_told": "<why>"}` and the space is carried all the same;
//!   the next verb tries again.
//! - `flush`: wait for a flush covering everything written so far. Answer `{}`.
//! - `close`: stop cleanly (refuse new puts, drain, flush, record a clean close
//!   in each space: the next start has no hole), answer `{}`, and end the
//!   process. `quit` (or end of input) stops at once, which the next start
//!   finds unclean (the log tolerates it).
//! - `suspect <key> [<when>]`: mark key `<key>` (`<id>/KEY/<k>`; a
//!   certificate name stands for its key) suspected since `<when>` — ms
//!   since the epoch or RFC 3339 in UTC (`2026-11-04T10:00:00.123Z`);
//!   default: now, by the device's clock — what the owner does on reporting a
//!   device lost. Kept across restarts. From now on this device takes no new
//!   entry of the key (the entry is refused, `suspected`; entries it already
//!   holds stay) until a revocation of the key decides (adopting it ends the
//!   mark) or `unsuspect <key>` lifts the mark (the answer says whether it was
//!   suspected). `suspected <key>`: `{"key","since_ms":<ms>|null}`.
//! - `cut <key> <file> [--held-before <when>] [--upto <space>=<seq>]...`
//!   (`<when>` as for `suspect`): the revocation cut of `<key>` as this device
//!   holds it (`Node::revocation_cut`), bounded by this device's own
//!   observation: every entry of that key it holds verified and has not
//!   refused, that it first verified before `--held-before` (default: the time
//!   the key is suspected since) and, for each `--upto` space, whose seq is at
//!   most `<seq>`. A key neither suspected nor given `--held-before` is
//!   refused: say when the device was lost. Written to `<file>` as the cut file
//!   `ndn-fwd revoke <device> --cut <file>` takes (`ndn_cert::CutFile`). The
//!   answer lists the ranges, the bound and, by full name with digest, the
//!   entries of the key this device holds that the bound left out; each is
//!   re-admitted one by one with `ndn-fwd readmit` once checked.
//! - `refused <key>`: the full names (each ending in the implicit digest of
//!   the refused packet) of every entry of `<key>` this device holds refused
//!   because the key is revoked and its cut does not accept them — refused on
//!   arrival or withdrawn later; what `ndn-fwd readmit <key> <full name>...`
//!   takes to re-admit exactly those entries.
//! - `offer <space> role=reader|writer until=<when> tries=<n>` (`<when>` as
//!   for `suspect`): a one-use offer of a space of this device's namespace to
//!   someone who holds no trust context of it, expiring at `<when>` by this
//!   device's clock, closed to an asker by its `<n>`-th wrong try (and to
//!   everyone at the device's overall cap). Answer `{"space","role","until_ms",
//!   "tries","offer","link","words","short","short_why","share"}`: `offer` the
//!   offer's name (`<D>/32=intro/32=offer/<id>`), `link` (`ndn-trust://intro/…`,
//!   one QR; it names the relays this namespace advertises, so the joiner's
//!   forwarder reaches this device through one of them before it trusts anything
//!   of this namespace), `words` (24 words), `short` (a short code, when this
//!   device can make one; else `null` and `short_why`), `share` (the form to
//!   hand over). When the joiner asks, this device adopts the joiner's namespace
//!   through its daemon and adds her to the space's members with the role.
//! - `close_offer <offer>`: close an offer this device made (its name, as
//!   `offer` printed it), durably: it admits no one new from then on and still
//!   answers the key it admitted until it expires. Answer `{"offer","closed"}`.
//! - `join <code>`: join the space a code offers (its link, its words in double
//!   quotes, or a short code: its tokens are one code): returns once this
//!   person may write (a reader: may read). Answer `{"space","role","inviter"}`
//!   (the inviter's namespace, which this device's daemon now holds, adopted
//!   through `security/context-adopt` as `ndn-ctl adopt` asks, so it also
//!   routes it over its relay links). An offer refused answers
//!   `"introduction"`: `{"why","left"?}` with `why` one of `unknown`, `used`,
//!   `expired`, `closed`, `wrong-proof` (with `left`), `forged`, `conflict`,
//!   `hint`, `hint-mismatch`, `gone-unproven`, `inviter-conflict`; a join not
//!   yet complete (the listing, the epoch key or the admitting entry still on
//!   its way) is `retry-later` and the same line may be sent again. While it
//!   dials, the host carries the inviter's introduction prefixes
//!   (`ndn_invite::introduction_prefixes`: `<D>/32=intro` and `<D>/32=hint`) in
//!   transit on the daemon (`security/transit`), unvalidated, until the dial
//!   ends. The other writers a space's members list, whose self-certifying
//!   namespaces this device's daemon does not hold, are adopted by name for the
//!   layer alone: the host asks the daemon to carry each in transit (so this
//!   host runs as a member of a group in the daemon's `[security]
//!   transit_groups`, or as an operator) over one management connection it holds
//!   for its whole run, which owns the marks (the daemon releases them when the
//!   host ends), and fetches its trust-context versions over its own
//!   connection; the daemon needs a route to each such namespace.
//! - `signal-subscribe <space>`: from now on, every signal of the space (live
//!   data that is never an entry and never stored: `ndn_surface::signal`) from
//!   every member as its own line — the newest per (sender, address), never a
//!   backlog. Refused NotMember (ask the owner) or NotReady (no members record
//!   or, sealed, no epoch key held yet: ask again). The device's signals start
//!   on the first signal verb, over a connection to the daemon of their own.
//! - `signal-open <space>`: a run over the space (a fresh run key, its header
//!   signed by this device's key); `signal-send` and `signal-stream` open one
//!   when none is open. `signal-close <space>` ends it.
//! - `signal-send <space> <address> <payload>`: one signal on the space's run
//!   (address at most 64 octets, payload at most 768): its sequence.
//! - `signal-stream <space> <address> <count> <hz>`: `count` signals at `hz`
//!   per second (at most 120) on the space's run, each payload `n=<i>
//!   sent_us=<µs since the epoch>`, answered once all are sent (while the next
//!   lines are read): the run, the first and last sequence, how long it took.
//! - `signal-stats`: the counters of this device's signals since they started
//!   — sent packets and octets, delivered, and what was dropped, by why.
//! - `signal-capture <route>`: register `route` (the owner's `<owner>/32=sync`,
//!   or a space's group `<owner>/32=sync/<rest>` below it) on the daemon over a
//!   connection of its own and print every push Interest under it (a name
//!   ending `…/32=signal/<digest>`: a signal's push goes to the group of its
//!   space, which the owner's route covers) — what a relay's operator sees of
//!   the signals its daemon forwards. Sync Interests of the group are not shown.
//!   Needs no device: started without `--device` (and `--pib`), the tool
//!   answers this verb and `quit` only (one binary: the e2e names this run
//!   `ndn-heap-capture` in its logs).
//! - `quit` (or end of input).
//!
//! Output lines: `{"ready":{"device","writer"}}` once the layer runs; per verb
//! `{"verb":…,"ok":{…}}` or `{"verb":…,"error":{"message","retry","next",
//! "next_step"}}` with `next` one of `none`, `retry-later`, `ask-owner`,
//! `use-owner-device`, `fix-local`, `fix-name`, `fix-request` (`fix-command`
//! for a line this tool cannot read), and beside them, by cause:
//! `"outside_cut"` (`{"device","keeps_to"}`: the cut device and the seq its
//! tip keeps, when a revocation's cut refuses it), `"suspected"` (`{"key","since_ms"}`,
//! when this device takes nothing new of a suspected key), `"untrusted"` (why,
//! when the chain of its signer is refused), `"introduction"` (above). A write
//! to a space this device is no writer of answers `ask-owner` (`NotAllowed`:
//! the message says why); a sealed space whose key is not held yet answers
//! `retry-later` (`NotReady`, "put again").
//!
//! An **id** is `{"device","seq","digest"}`: the signing device, its seq in
//! the (device, space) log and the entry's signed-region digest (hex). An
//! **item** is `{"path","by","writer","id","len"}` plus the value: `"text"` when
//! it is UTF-8 and at most 256 octets, `"hex"` when it is not, `"sha256"` (hex)
//! alone when it is longer; `by` is the writer's person (a name), `writer` the
//! device.
//!
//! Per watched change `{"watch":<space>,"change":{…}}`, the change one of
//! `{"put":<item>}`, `{"removed":<item>}`, `{"withdrawn":{"id","why"}}` (an
//! entry refused after the fact, its predecessors return; `why` is the
//! refusal's words, with `cut_of` (the device cut) and `keeps_to` (the seq its tip keeps) when a revocation's cut
//! withdrew it and `"untrusted":true` when the durable rule refused its
//! issuer), `{"members":<members>}`, `{"alert":{"kind",…}}` and
//! `{"lagged":{"missed","what_to_do"}}`. An alert's `kind` is `equivocation`
//! (`device`, `seq`: a device signed two packets at one name), `outside-cut`
//! (`id`), `refused` (`id`, `why`, `next`), `rolled-back` (`reserved`, `seen`:
//! re-enrol the device), `gap-signed` (`after`, `resumed`), `unbacked-counter`
//! (`device`, `seen`) or `store-failed` (`why`). Per received signal
//! `{"signal":{"scope","sender","run","seq","address","payload","expires_ms",
//! "local"}}` (address and payload as text, or `{"hex"}` when not UTF-8; with
//! `"latency_us"`, by this host's clock, when the payload carries
//! `sent_us=<µs>`, as a stream's does); per captured signal Interest
//! `{"capture":<group>,"interest":{"name","octets","params_hex","digest_ok",
//! "decodes_as"}}` (`SignalSealed` with its `key_id`, or `SignalBody` with the
//! `scope_digest` (16 octets, hex, of the scope's name: the name itself rides
//! only in a run header) and run it shows, or `undecodable` with why); a signal
//! refusal's error carries `retry_after_ms` when over the sender's rate.
//! `--no-signal-ring` opens no local ring per run. Logs go to stderr.

mod host;
mod shapes;
mod signal;
mod store;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use clap::Parser;
use futures::future::BoxFuture;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::task::JoinSet;

use ndn_app::{Connection, IpcConnection, demux_cert_fetcher};
use ndn_cert::CutFile;
use ndn_heap::{
    Change, Clock, Config, CutBound, Frontier, Heap, HeapError, MembersChange, Node, PutOptions,
    Readers, Share, Timestamp, Transport,
};
use ndn_invite::{IntroPolicy, InviteConfig, InviteError, Invites, Offer, Role};
use ndn_ipc::{ForwarderClient, MgmtClient};
use ndn_packet::Name;
use ndn_security::{CertCache, FilePib, SecurityManager, Validator};
use ndn_surface::signal::SignalOptions;
use ndn_sync::{DataStore, MemoryStore};

use host::{DaemonHost, DaemonMarks, FollowedGroups, carrying_introduction, follow_contexts};
use shapes::{
    heap_error, hex, invite_error, members, next_step, revocation_cut, role_word, usage_error,
    value_fields,
};
use store::DirStore;

/// Longest certificate chain the validator walks (device → CA → root).
const MAX_CHAIN: usize = 5;

#[derive(Parser)]
#[command(
    name = "ndn-heap",
    about = "Host one device's data layer and introductions on a running ndn-fwd; verbs on \
             stdin, JSON on stdout"
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
    /// so a host started again on it resumes its logs where they stopped
    /// (default: in memory only, for the life of the process).
    #[arg(long)]
    store: Option<PathBuf>,

    /// Run the device's wall clock this many milliseconds off the system's
    /// (negative: behind). Only the times it reads change.
    #[arg(long, default_value_t = 0, allow_negative_numbers = true)]
    clock_offset_ms: i64,

    /// A device that holds copies of this device's spaces (a repo follower
    /// of the `ndn-repo follow` kind), by its name, e.g. `/hold/node/repo`;
    /// given once per holder. The data layer asks the holders for a held copy
    /// of an entry, after the vouched relays and within the same bound on
    /// asks; a holder is asked for copies alone and is only a place to ask:
    /// whatever it serves is verified like any packet.
    #[arg(long = "holder", value_name = "DEVICE", value_parser = parse_holder)]
    holder: Vec<Name>,

    /// Open no local ring per signal run: this device's signals reach
    /// subscribers on this host through the forwarder only, as they reach
    /// other hosts.
    #[arg(long)]
    no_signal_ring: bool,

    #[arg(long, default_value_t = ndn_config::ManagementConfig::default().face_socket)]
    face_socket: String,
}

/// One device's data layer and introductions, as the verbs drive them.
struct Hosted {
    node: Node,
    invites: Invites,
    host: Arc<DaemonHost>,
    /// The device's clock: `suspect` without a time marks the key from now,
    /// as the device dates what it verifies.
    clock: Clock,
    /// The groups of the spaces this device follows, told to the daemon.
    follows: FollowedGroups,
    /// The spaces `follow` carries (the layer lists the ones open as a member).
    carried: std::sync::Mutex<Vec<Name>>,
}

impl Hosted {
    /// Tell the daemon the spaces this device follows now: the ones open here
    /// as a member and the ones carried. `Err`: the daemon's words.
    async fn sync_follows(&self) -> Result<(), String> {
        let mut spaces = self.node.spaces();
        spaces.extend(
            self.carried
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .cloned(),
        );
        self.follows.sync(spaces).await
    }
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

    let face = ndn_app::Node::connect(&cli.face_socket)
        .await
        .map_err(|e| anyhow!("connect to the forwarder at {}: {e}", cli.face_socket))?;
    let sync = ForwarderClient::connect(&cli.face_socket)
        .await
        .map_err(|e| anyhow!("connect to the forwarder at {}: {e}", cli.face_socket))?;
    let sync = Arc::new(IpcConnection::new(sync));

    let cache = Arc::new(CertCache::new());
    let fetcher = demux_cert_fetcher(face.demux(), Arc::clone(&cache));
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
    // namespace adopted for a space alone is fetched over this host's own
    // connection, which the daemon carries in transit meanwhile — marked
    // over one management connection held for the host's whole run, which
    // owns the marks: the daemon releases them when it closes, however the
    // host ends. The same marks carry a join's introduction prefixes.
    let connection: Arc<dyn Connection> = face.demux();
    let marks = MgmtClient::connect(&cli.face_socket)
        .await
        .map_err(|e| anyhow!("connect to the forwarder at {}: {e}", cli.face_socket))?;
    let host = Arc::new(DaemonHost {
        face_socket: cli.face_socket.clone(),
        pib_root: pib.root().to_path_buf(),
        namespace: keyring.context_for(&device).namespace().clone(),
        keyring: Arc::clone(&keyring),
        connection,
        marks: Arc::new(DaemonMarks(marks)),
        carried: std::sync::Mutex::new(std::collections::HashSet::new()),
    });
    config.adopter = Some(host.clone());
    config.holders = cli.holder.clone();
    let store: Arc<dyn DataStore> = match &cli.store {
        Some(dir) => Arc::new(DirStore::open(dir)?),
        None => Arc::new(MemoryStore::new()),
    };
    let clock = Arc::clone(&config.clock);
    let node = Node::start(
        Transport { node: face, sync },
        device.clone(),
        keys,
        validator,
        Arc::clone(&store),
        config,
    )
    .await
    .map_err(|e| anyhow!("{device}: {e} (next: {})", next_step(e.next())))?;
    let invites = Invites::start(&node, host.clone(), IntroPolicy::new(), InviteConfig::new())
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
        json!({"ready": {"device": device.to_string(), "writer": node.writer().to_string()}})
    );
    let signals = signal::SignalHost::new(
        node.handle(),
        store,
        cli.face_socket.clone(),
        SignalOptions {
            local_ring: !cli.no_signal_ring,
            ..SignalOptions::default()
        },
    );
    let follows = FollowedGroups::new(Arc::clone(&host.marks), host.namespace.clone());
    let hosted = Hosted {
        node,
        invites,
        host,
        clock,
        follows,
        carried: std::sync::Mutex::default(),
    };
    if let Err(why) = hosted.sync_follows().await {
        tracing::warn!("{why}");
    }

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
        if verb == "close" && args.is_empty() {
            // Every signal stream still waiting answers, then the node
            // drains, flushes and records a clean close in each space.
            while later.join_next().await.is_some() {}
            signals.shutdown();
            hosted.node.close().await;
            println!("{}", json!({"verb": "close", "ok": {}}));
            return Ok(());
        }
        let outcome = if verb.starts_with("signal-") {
            signals.run(verb, args).await.map_err(|e| signal::error(&e))
        } else {
            run(&hosted, verb, args).await.map_err(|e| e.json())
        };
        let line = answer_line(verb, outcome, &mut later);
        if let Err(why) = hosted.sync_follows().await {
            tracing::warn!("{why}");
        }
        if let Some(line) = line {
            println!("{line}");
        }
    }
    // Every signal stream still waiting answers before the layer stops.
    while later.join_next().await.is_some() {}
    signals.shutdown();
    hosted.node.shutdown();
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
                "this ndn-heap hosts no device (started without --device): it answers \
                 signal-capture and quit; start it with --device and --pib for {verb}"
            ))),
        };
        if let Some(line) = answer_line(verb, outcome, &mut later) {
            println!("{line}");
        }
    }
    Ok(())
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

/// Why a verb failed: the data layer's error or the introductions'.
enum Fail {
    Heap(HeapError),
    Invite(InviteError),
}

impl From<HeapError> for Fail {
    fn from(e: HeapError) -> Self {
        Fail::Heap(e)
    }
}

impl From<InviteError> for Fail {
    fn from(e: InviteError) -> Self {
        Fail::Invite(e)
    }
}

impl Fail {
    /// The error object of an answer.
    fn json(&self) -> Value {
        match self {
            Fail::Heap(e) => heap_error(e),
            Fail::Invite(e) => invite_error(e),
        }
    }
}

/// The space `space` of this node: open here already, or one made elsewhere
/// that this device is a member of, opened now.
async fn heap_of(node: &Node, space: &Name) -> Result<Heap, HeapError> {
    match node.space(space) {
        Some(heap) => Ok(heap),
        None => node.open(space).await,
    }
}

async fn run(h: &Hosted, verb: &str, args: &[String]) -> Result<Verb, Fail> {
    let usage = |s: &str| Ok(Verb::Usage(s.to_owned()));
    let name = |s: &str| {
        s.parse::<Name>()
            .map_err(|e| format!("{s:?} is no name: {e}"))
    };
    match (verb, args) {
        ("create", [space, options @ ..]) => {
            let space = match name(space) {
                Ok(s) => s,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let share = match create_options(options) {
                Ok(s) => s,
                Err(e) => return Ok(Verb::Usage(format!("{e}; {CREATE_USAGE}"))),
            };
            h.node.create(&space, share).await?;
            Ok(Verb::Done(json!({"space": space.to_string()})))
        }
        ("create", _) => usage(CREATE_USAGE),
        ("change", [space, options @ ..]) => {
            let space = match name(space) {
                Ok(s) => s,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let change = match change_options(options) {
                Ok(c) => c,
                Err(e) => return Ok(Verb::Usage(format!("{e}; {CHANGE_USAGE}"))),
            };
            let heap = heap_of(&h.node, &space).await?;
            let id = heap.change(change).await?;
            Ok(Verb::Done(
                json!({"space": space.to_string(), "id": shapes::id(&id)}),
            ))
        }
        ("change", _) => usage(CHANGE_USAGE),
        ("members", [space]) => {
            let space = match name(space) {
                Ok(s) => s,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let heap = heap_of(&h.node, &space).await?;
            Ok(Verb::Done(json!({
                "space": space.to_string(),
                "members": members(&heap.members()),
                "known": heap.members_known(),
            })))
        }
        ("members", _) => usage("usage: members <space>"),
        ("put", [space, path, rest @ ..]) => {
            let (space, path) = match (name(space), path_name(path)) {
                (Ok(s), Ok(p)) => (s, p),
                (Err(e), _) | (_, Err(e)) => return Ok(Verb::Usage(format!("{e}; {PUT_USAGE}"))),
            };
            let (value, durable) = match put_options(rest).await {
                Ok(v) => v,
                Err(e) => return Ok(Verb::Usage(format!("{e}; {PUT_USAGE}"))),
            };
            let heap = heap_of(&h.node, &space).await?;
            let options = PutOptions {
                durable: durable.then_some(true),
            };
            let id = heap.put(&path, value.clone(), options).await?;
            let mut ok = json!({
                "space": space.to_string(),
                "path": path.to_string(),
                "id": shapes::id(&id),
                "removed": value.is_empty(),
            });
            let mut shown = serde_json::Map::new();
            value_fields(&value, &mut shown);
            ok.as_object_mut().expect("an object").extend(shown);
            Ok(Verb::Done(ok))
        }
        ("put", _) => usage(PUT_USAGE),
        ("get", [space, path]) => {
            let (space, path) = match (name(space), path_name(path)) {
                (Ok(s), Ok(p)) => (s, p),
                (Err(e), _) | (_, Err(e)) => return Ok(Verb::Usage(format!("{e}; {GET_USAGE}"))),
            };
            let heap = heap_of(&h.node, &space).await?;
            let item = heap.get(&path).await?;
            Ok(Verb::Done(json!({
                "space": space.to_string(),
                "path": path.to_string(),
                "item": item.as_ref().map(shapes::item),
            })))
        }
        ("get", _) => usage(GET_USAGE),
        ("watch", [space]) => {
            let space = match name(space) {
                Ok(s) => s,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let heap = heap_of(&h.node, &space).await?;
            let mut changes = heap.watch(&Frontier::new()).await?;
            let watched = space.to_string();
            tokio::spawn(async move {
                while let Some(item) = changes.next().await {
                    let lagged = matches!(item, Ok(Change::Lagged { .. }));
                    let line = match item {
                        Ok(c) => json!({"watch": watched, "change": shapes::change(&c)}),
                        Err(e) => json!({"watch": watched, "error": heap_error(&e)}),
                    };
                    println!("{line}");
                    // Fallen behind: read again. The listing is local, so
                    // the space resumes from the empty frontier.
                    if lagged {
                        match heap.watch(&Frontier::new()).await {
                            Ok(again) => changes = again,
                            Err(e) => {
                                println!("{}", json!({"watch": watched, "error": heap_error(&e)}));
                                return;
                            }
                        }
                    }
                }
            });
            Ok(Verb::Done(json!({"space": space.to_string()})))
        }
        ("watch", _) => usage("usage: watch <space>"),
        ("follow", [space]) => {
            let space = match name(space) {
                Ok(s) => s,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let follower = h.node.follow(&space).await?;
            h.carried
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(space.clone());
            let mut ok = json!({"space": space.to_string(), "held": follower.held()});
            if let Err(why) = h.sync_follows().await {
                ok["relays_not_told"] = json!(why);
            }
            Ok(Verb::Done(ok))
        }
        ("follow", _) => usage("usage: follow <space>"),
        ("flush", []) => {
            h.node.flush().await?;
            Ok(Verb::Done(json!({})))
        }
        ("flush", _) => usage("usage: flush"),
        ("suspect", [key, since @ ..]) if since.len() <= 1 => {
            let key = match name(key) {
                Ok(k) => k,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let since = match since.first() {
                None => (h.clock)(),
                Some(when) => match time(when) {
                    Ok(t) => t,
                    Err(e) => return Ok(Verb::Usage(format!("{e}; {SUSPECT_USAGE}"))),
                },
            };
            h.node.suspect(&key, since)?;
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
            let was = h.node.unsuspect(&key);
            Ok(Verb::Done(
                json!({"key": key.to_string(), "was_suspected": was}),
            ))
        }
        ("unsuspect", _) => usage("usage: unsuspect <key>"),
        ("suspected", [key]) => {
            let key = match name(key) {
                Ok(k) => k,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let since = h.node.suspected(&key);
            Ok(Verb::Done(
                json!({"key": key.to_string(), "since_ms": since.map(|t| t.0)}),
            ))
        }
        ("suspected", _) => usage("usage: suspected <key>"),
        ("cut", [key, file, options @ ..]) => {
            let key = match name(key) {
                Ok(k) => k,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let (given, upto) = match cut_options(options) {
                Ok(o) => o,
                Err(e) => return Ok(Verb::Usage(format!("{e}; {CUT_USAGE}"))),
            };
            let held_before = given.or_else(|| h.node.suspected(&key));
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
            let proposal = h.node.revocation_cut(&key, &bound)?;
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
                .map(|(space, seq)| json!({"space": space.to_string(), "seq": seq}))
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
            let names = h.node.refused_by_revocation(&key);
            Ok(Verb::Done(json!({
                "key": key.to_string(),
                "names": names.iter().map(ToString::to_string).collect::<Vec<_>>(),
            })))
        }
        ("refused", _) => usage("usage: refused <key>"),
        ("offer", [space, options @ ..]) => {
            let space = match name(space) {
                Ok(s) => s,
                Err(e) => return Ok(Verb::Usage(e)),
            };
            let offer = match offer_options(options) {
                Ok(o) => o,
                Err(e) => return Ok(Verb::Usage(format!("{e}; {OFFER_USAGE}"))),
            };
            let (role, until, tries) = (offer.role, offer.until, offer.tries);
            // The space is opened here, as an offer needs it (a space made
            // elsewhere that this device owns a device of).
            heap_of(&h.node, &space).await?;
            let code = h.invites.offer(&space, offer).await?;
            Ok(Verb::Done(json!({
                "space": space.to_string(),
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
            h.invites.close_offer(&offer).await?;
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
            // The joiner's daemon holds no trust of the inviter yet, so it
            // carries the inviter's introduction prefixes in transit for the
            // length of the join (invite.md §12.1): this host dials nothing,
            // so nothing else tells it a join began. Taken back whatever the
            // outcome.
            let inviter = h.invites.inviter_of(&code)?;
            let joined = carrying_introduction(&h.host.marks, &inviter, h.invites.join(&code))
                .await
                .map_err(InviteError::local)?;
            let joined = joined?;
            Ok(Verb::Done(json!({
                "space": joined.space.to_string(),
                "role": role_word(joined.role),
                "inviter": joined.inviter.to_string(),
            })))
        }
        ("join", _) => usage(JOIN_USAGE),
        _ => usage(
            "verbs: create, change, members, put, get, watch, follow, flush, close, \
             suspect, unsuspect, suspected, cut, refused, offer, close_offer, join, \
             signal-subscribe, \
             signal-open, signal-send, signal-stream, signal-close, signal-stats, signal-capture, \
             quit",
        ),
    }
}

const CREATE_USAGE: &str = "usage: create <space> [writers=<ns>,<ns>...] \
                            [readers=anyone|<ns>,<ns>...] (the space is <ns>/32=data/<name> of \
                            this device's namespace; writers and readers are persons, the owner \
                            is both; readers= absent or empty: the owner alone, sealed; \
                            readers=anyone: a public space)";

const CHANGE_USAGE: &str = "usage: change <space> [add_writers=<ns>,...] [add_readers=<ns>,...] \
                            [remove=<ns>,...] (one Members entry, owner devices only; remove \
                            takes a person from both roles)";

const PUT_USAGE: &str = "usage: put <space> <path> (text=<value>|hex=<octets>) [--durable] (the \
                         path is relative to the space; `text=` alone removes it; a value \
                         @<file> is the file's bytes, @@... a value starting with @; --durable \
                         returns after a flush covering the entry)";

const GET_USAGE: &str = "usage: get <space> <path> (the path is relative to the space)";

const SUSPECT_USAGE: &str = "usage: suspect <key> [<when>] (since when the key is suspected: \
                             when the device was lost, as ms since the epoch or RFC 3339; \
                             default now)";

const CUT_USAGE: &str = "usage: cut <key> <file> [--held-before <when>] [--upto \
                         <space>=<seq>]... (<when> as ms since the epoch or RFC 3339; \
                         --held-before defaults to the time the key was suspected since)";

const OFFER_USAGE: &str = "usage: offer <space> role=reader|writer until=<when> tries=<n> \
                           (a space of this device's namespace; <when>, the offer's expiry by \
                           this device's clock, as ms since the epoch or RFC 3339; <n> ≥ 1, the \
                           wrong tries that close it)";

const JOIN_USAGE: &str = "usage: join <code> (the code an offer printed: its link \
                          ndn-trust://intro/…, its words in double quotes, or a short code)";

const CLOSE_OFFER_USAGE: &str = "usage: close_offer <offer> (the offer's name an offer printed, \
                                 made by this device: it admits no one new, and still answers \
                                 the one it admitted until it expires)";

/// A path of a space as a line gives it: components, with or without a
/// leading `/`.
fn path_name(path: &str) -> Result<Name, String> {
    let text = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    text.parse::<Name>()
        .map_err(|e| format!("{path:?} is no path: {e}"))
}

/// A `--holder`: the name of a device, at least one component.
fn parse_holder(device: &str) -> Result<Name, String> {
    let name = device
        .parse::<Name>()
        .map_err(|e| format!("{device:?} is no name: {e}"))?;
    if name.is_empty() {
        return Err(format!(
            "{device:?} names no device: give the holder's device name, e.g. /hold/node/repo"
        ));
    }
    Ok(name)
}

/// Persons, names separated by commas (none: an empty list).
fn names(list: &str) -> Result<Vec<Name>, String> {
    list.split(',')
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<Name>()
                .map_err(|e| format!("{s:?} is no name: {e}"))
        })
        .collect()
}

/// A `create` line's options: `writers=` (persons besides the owner) and
/// `readers=` (`anyone`, or persons; absent or empty: the owner alone), each
/// at most once.
fn create_options(options: &[String]) -> Result<Share, String> {
    let (mut writers, mut readers) = (None, None);
    for o in options {
        match o.split_once('=') {
            Some(("writers", _)) if writers.is_some() => {
                return Err("writers= is given twice".into());
            }
            Some(("writers", v)) => writers = Some(names(v)?),
            Some(("readers", _)) if readers.is_some() => {
                return Err("readers= is given twice".into());
            }
            Some(("readers", "anyone")) => readers = Some(Readers::Anyone),
            Some(("readers", v)) => readers = Some(Readers::Persons(names(v)?)),
            _ => return Err(format!("{o:?} is not writers= or readers=")),
        }
    }
    Ok(Share {
        readers: readers.unwrap_or(Readers::Persons(Vec::new())),
        writers: writers.unwrap_or_default(),
    })
}

/// A `change` line's options: `add_writers=`, `add_readers=` and `remove=`
/// (persons), at least one person named.
fn change_options(options: &[String]) -> Result<MembersChange, String> {
    let mut change = MembersChange::default();
    for o in options {
        match o.split_once('=') {
            Some(("add_writers", v)) => change.add_writers.extend(names(v)?),
            Some(("add_readers", v)) => change.add_readers.extend(names(v)?),
            Some(("remove", v)) => change.remove.extend(names(v)?),
            _ => {
                return Err(format!(
                    "{o:?} is not add_writers=, add_readers= or remove="
                ));
            }
        }
    }
    if change == MembersChange::default() {
        return Err("the change names no person".into());
    }
    Ok(change)
}

/// A `put` line's words after the path: the value, `text=<value>` (a value
/// as [`field_value`] reads it; `text=` alone is empty, a removal) or
/// `hex=<octets>`, once; and `--durable` (whether to wait for a flush).
async fn put_options(words: &[String]) -> Result<(Bytes, bool), String> {
    let (mut value, mut durable) = (None, false);
    for word in words {
        if word == "--durable" {
            durable = true;
            continue;
        }
        let (key, v) = word
            .split_once('=')
            .ok_or_else(|| format!("{word:?} is neither text=, hex= nor --durable"))?;
        if value.is_some() {
            return Err("the line gives the value twice".into());
        }
        value = Some(match key {
            "text" => field_value(v).await?,
            "hex" => unhex(v).map(Bytes::from)?,
            _ => return Err(format!("{word:?} is neither text=, hex= nor --durable")),
        });
    }
    Ok((value.ok_or("no value: text= or hex=")?, durable))
}

/// An `offer` line's options after the space: `role=`, `until=` and
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
/// <when>` (at most once) and `--upto <space>=<seq>` (once per space). A
/// space name may hold `=` (`32=data`), a seq never does: each `--upto`
/// splits at its last `=`.
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
                let (space, seq) = value
                    .rsplit_once('=')
                    .ok_or_else(|| format!("--upto {value:?} is not <space>=<seq>"))?;
                let space = space
                    .parse::<Name>()
                    .map_err(|e| format!("--upto {space:?} is no name: {e}"))?;
                let seq = seq
                    .parse::<u64>()
                    .map_err(|e| format!("--upto {value:?}: seq {seq:?}: {e}"))?;
                if upto.insert(space, seq).is_some() {
                    return Err(format!("--upto names the space of {value:?} twice"));
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

/// A value a line gives: the text itself, the bytes of the file `@<path>`
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

#[cfg(test)]
mod tests {
    use super::*;

    fn words(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn n(s: &str) -> Name {
        s.parse().expect("a name")
    }

    /// Whitespace separates words, quotes keep a value's spaces, and only
    /// `\"` and `\\` escape inside quotes; an open quote is refused.
    #[test]
    fn a_line_splits_into_words_by_whitespace_and_quotes() {
        assert_eq!(
            split(r#"put /a/32=data/n trip text="on the \"plane\"" --durable"#).unwrap(),
            words(&[
                "put",
                "/a/32=data/n",
                "trip",
                r#"text=on the "plane""#,
                "--durable"
            ])
        );
        assert_eq!(split("  \t ").unwrap(), Vec::<String>::new());
        assert_eq!(split(r#"a "" b"#).unwrap(), words(&["a", "", "b"]));
        assert!(split(r#"put "never closed"#).is_err());
        assert!(split(r#"put "bad \n escape""#).is_err());
    }

    /// A time is ms since the epoch or RFC 3339 in UTC, to the millisecond;
    /// anything else is refused with why.
    #[test]
    fn a_time_is_ms_or_rfc_3339() {
        assert_eq!(time("1793808000000").unwrap(), Timestamp(1_793_808_000_000));
        assert_eq!(
            time("2026-11-04T10:00:00.123Z").unwrap(),
            Timestamp(1_793_786_400_123)
        );
        assert!(time("yesterday").is_err());
        assert!(time("99999999999999999999999").is_err());
    }

    /// A path is relative to its space, with or without a leading `/`.
    #[test]
    fn a_path_is_read_with_or_without_a_leading_slash() {
        assert_eq!(path_name("trip/day1").unwrap(), n("/trip/day1"));
        assert_eq!(path_name("/trip/day1").unwrap(), n("/trip/day1"));
    }

    /// `--holder` is repeatable, each a device name; an empty or malformed one
    /// is refused at the command line, with why.
    #[test]
    fn holders_are_repeatable_device_names() {
        let cli = Cli::try_parse_from([
            "ndn-heap",
            "--holder",
            "/hold/node/repo",
            "--holder",
            "/other/node/repo",
        ])
        .unwrap();
        assert_eq!(
            cli.holder,
            vec![n("/hold/node/repo"), n("/other/node/repo")]
        );
        assert!(Cli::try_parse_from(["ndn-heap"]).unwrap().holder.is_empty());
        let refused = Cli::try_parse_from(["ndn-heap", "--holder", "/"])
            .err()
            .expect("the root names no device")
            .to_string();
        assert!(refused.contains("names no device"), "{refused}");
        assert!(Cli::try_parse_from(["ndn-heap", "--holder", "no-slash"]).is_err());
    }

    /// A space is private to its owner unless the line lists readers, public
    /// with `readers=anyone`, and an option is given once.
    #[test]
    fn create_defaults_to_the_owner_alone_and_reads_anyone() {
        let private = create_options(&[]).unwrap();
        assert_eq!(private.readers, Readers::Persons(Vec::new()));
        assert!(private.writers.is_empty());
        let public = create_options(&words(&["readers=anyone", "writers=/bob,/carol"])).unwrap();
        assert_eq!(public.readers, Readers::Anyone);
        assert_eq!(public.writers, vec![n("/bob"), n("/carol")]);
        let listed = create_options(&words(&["readers=/bob"])).unwrap();
        assert_eq!(listed.readers, Readers::Persons(vec![n("/bob")]));
        assert!(create_options(&words(&["readers=/a", "readers=/b"])).is_err());
        assert!(create_options(&words(&["rule=log"])).is_err());
    }

    /// A change names someone to add or remove.
    #[test]
    fn a_change_names_a_person() {
        let change = change_options(&words(&["add_writers=/bob", "remove=/carol,/dave"])).unwrap();
        assert_eq!(change.add_writers, vec![n("/bob")]);
        assert_eq!(change.remove, vec![n("/carol"), n("/dave")]);
        assert!(change_options(&[]).is_err());
        assert!(change_options(&words(&["add_readers="])).is_err());
        assert!(change_options(&words(&["remove_writers=/bob"])).is_err());
    }

    /// A put's value is text, hex or a file; `text=` alone is a removal; the
    /// value is given once; `--durable` is a flag beside it.
    #[tokio::test]
    async fn a_put_gives_one_value_and_may_ask_for_durability() {
        let (value, durable) = put_options(&words(&["text=hello"])).await.unwrap();
        assert_eq!((&value[..], durable), (&b"hello"[..], false));
        let (value, durable) = put_options(&words(&["--durable", "hex=00ff"]))
            .await
            .unwrap();
        assert_eq!((&value[..], durable), (&[0x00, 0xff][..], true));
        let (removal, _) = put_options(&words(&["text="])).await.unwrap();
        assert!(removal.is_empty(), "an empty text removes the path");
        let (at, _) = put_options(&words(&["text=@@file"])).await.unwrap();
        assert_eq!(&at[..], b"@file");
        assert!(put_options(&words(&["text=a", "hex=00"])).await.is_err());
        assert!(put_options(&words(&["--durable"])).await.is_err());
        assert!(put_options(&words(&["hex=0"])).await.is_err());
        assert!(put_options(&words(&["title=x"])).await.is_err());
    }

    /// An offer line gives role, expiry and tries once each, and at least one
    /// try.
    #[test]
    fn an_offer_needs_role_until_and_tries() {
        let offer =
            offer_options(&words(&["role=writer", "until=1793808000000", "tries=3"])).unwrap();
        assert_eq!(offer.role, Role::Writer);
        assert_eq!(offer.until, Timestamp(1_793_808_000_000));
        assert_eq!(offer.tries, 3);
        assert!(offer_options(&words(&["role=writer", "until=1", "tries=0"])).is_err());
        assert!(offer_options(&words(&["role=writer", "until=1"])).is_err());
        assert!(offer_options(&words(&["role=owner", "until=1", "tries=1"])).is_err());
        assert!(
            offer_options(&words(&[
                "role=reader",
                "role=reader",
                "until=1",
                "tries=1"
            ]))
            .is_err()
        );
    }

    /// A cut line bounds by when the device was lost and, per space, a seq; a
    /// space name's own `=` is not the seq's, and each bound is given once.
    #[test]
    fn a_cut_bounds_by_time_and_by_space_seq() {
        let (held_before, upto) = cut_options(&words(&[
            "--held-before",
            "1793808000000",
            "--upto",
            "/alice/32=data/notes=4",
        ]))
        .unwrap();
        assert_eq!(held_before, Some(Timestamp(1_793_808_000_000)));
        assert_eq!(upto.get(&n("/alice/32=data/notes")), Some(&4));
        assert!(cut_options(&words(&["--held-before"])).is_err());
        assert!(
            cut_options(&words(&[
                "--upto",
                "/a/32=data/n=1",
                "--upto",
                "/a/32=data/n=2"
            ]))
            .is_err()
        );
        assert!(cut_options(&words(&["--when", "1"])).is_err());
    }
}
