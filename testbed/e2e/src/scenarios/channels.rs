//! channels: live data from one device to two people's devices through a relay that holds no
//! context of theirs, and a forged frame exposed by the sender's signed checkpoint — the channel
//! (`ndn_heap::Heap::emit` / `live`, channel.md) on real processes over real QUIC links, each
//! device on a forwarder of its own in a network namespace of its own.
//!
//! The nodes, and where they come from:
//! - **relay** (10.200.0.3): a real `ndn-fwd` daemon, the root device of /cr, listening for links.
//!   `[relay_service] serve = "listed"` with the three people's root fingerprints and no quotas:
//!   an open or quota-bound relay's links never carry channel frames (ndn-link's channel policy),
//!   a listed one without quotas does. It holds no trust context of /cs, /cc or /cd and no route
//!   or peer in its config: its side table and the routes the link library made are all it has.
//! - **sender** (/cs), **carol** (/cc) and **dave** (/cd): `chan-device` processes
//!   (`src/bin/chan_device.rs`), one in each roamer's network namespace (`nat.rs`), the PIB of an
//!   `ndn-fwd init` each. A device cannot be an `ndn-fwd` daemon with `ndn-heap` beside it: the
//!   daemon's unix-socket and shared-memory faces carry NDN packets only, and a channel frame is
//!   not one. `chan-device` is an embedded forwarder (`ndn-engine`), the daemon's link layer
//!   (`ndn-link`, over the same crates `ndn-fwd` uses) and a heap node on the forwarder's app face.
//!
//! The people's gestures: each creates a namespace (`ndn-fwd init`) and adopts the trust contexts
//! of the ones it must know (the sender those of both receivers, whose asks it judges; each
//! receiver the sender's; every device the relay's, which a link to a relay of another namespace
//! needs to carry channel frames: the relay is one it follows). The sender creates a space for
//! the two, each opens it, takes the channel (`get`: the signed ask over the links) and the sender
//! emits.
//!
//! Proves:
//! 1. through the relay, both receivers get every message the sender emits, in order; the
//!    relay's side table (`side/list` over its management socket) has one route for the
//!    channel, sourced at the sender's link, with the two receivers' links as its sinks; the
//!    sender's link carried one copy of each frame (its side-path counter equals the route's
//!    frames at the relay) and the relay sent each to two sinks (frames out are twice frames in),
//!    each receiver's link counting exactly the route's frames;
//! 2. a receiver that drops its `get` is gone from the route's sinks (one is left) and the
//!    other still receives everything while the one that left receives nothing;
//! 3. a key holder's forged frame is exposed by the sender's next checkpoint. Dave, a member
//!    that holds the channel key, is also carol's forwarder (carol's device links to dave's, which
//!    serves her by her root fingerprint: a relay behind the relay). Dave seals a frame under the
//!    channel key at a sequence the sender has not reached (`ndn-heap`'s `adversary` feature: the
//!    one seam that forges) and sends it to carol over his link. Carol's `get` delivers it
//!    (inside the stated window a forged frame is delivered as the sender's), the sender goes on,
//!    and its next checkpoint does not list it: carol raises `Alert::ChannelForgery` for the
//!    sequence and the link, her evidence holds a `Mismatch` for that frame from that link, her
//!    `get` yields `Retracted` over it, her forwarder's `side/list` shows that link barred
//!    (dave's and the relay's show none), the sender's later frames do not reach her over it
//!    while dave, behind no bar, still receives them, and NDN traffic over the barred link works:
//!    an entry the sender puts reaches her.

use std::io::{BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::data_host::CONVERGE;
use super::direct_paths::link_list;
use super::shared::{FAST_LINKS, adopt_offline};
use crate::nat::Nat;
use crate::run::Proc;
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{CaCfg, NodeCfg, QUIC_PORT, addr};

const NS_S: &str = "/cs";
const NS_C: &str = "/cc";
const NS_D: &str = "/cd";
const NS_R: &str = "/cr";
/// The space the sender makes for the two, and the path it emits at.
const SPACE: &str = "/cs/32=data/chan";
const POS: &str = "/pos";
/// The relay daemon's host on the harness's `lo`.
const RELAY: u8 = 3;
/// The host of /cr's root device, the CA the relay enrolls at.
const ROOT: u8 = 4;
/// How long a receiver waits for the messages of a burst.
const BURST: Duration = Duration::from_secs(30);
/// The name id the forged frame binds its path to: one the sender never takes.
const FORGED_NAME_ID: u64 = 4_000;
/// How far past what dave last saw the forged frame's sequence lies: past every sequence the
/// sender has used (data, checkpoints, keep-alives), within what a receiver takes, and within
/// what a burst of the sender's messages passes in about a second.
const AHEAD: u64 = 20;

// ── a device process ────────────────────────────────────────────────────────────────────────

/// One `chan-device`: its stdin, its stdout lines, and what it printed on its own (the messages
/// its `get` delivered, its notices, its alerts).
struct Dev {
    node: String,
    stdin: ChildStdin,
    lines: Receiver<String>,
    events: Vec<Value>,
    /// Whether the lines of the verb in flight (a poll of `links` or `side`) are left out of the
    /// step's transcript.
    quiet: bool,
    log: PathBuf,
    ip: Ipv4Addr,
    /// `ready`: the device's link key, its writer.
    link_key: String,
    writer: String,
    device: String,
}

impl Dev {
    /// Start `chan-device` for `device` on `node` (in its network namespace, with its PIB, on its
    /// address) with `extra` arguments; ready once it says so. The node's producer: stopped
    /// with it, its log shown when a step fails.
    fn start(
        cx: &mut Cx<'_>,
        node: &str,
        device: &str,
        port: u16,
        extra: &[String],
    ) -> StepResult<Dev> {
        let (pib, log, ip, netns) = {
            let n = cx.w.node(node);
            (
                n.pib(),
                n.dir.join("chan-device.log"),
                n.ip,
                n.netns.clone(),
            )
        };
        let mut args = vec![
            "--device".to_owned(),
            device.to_owned(),
            "--pib".to_owned(),
            pib.display().to_string(),
            "--bind".to_owned(),
            format!("{ip}:{port}"),
        ];
        args.extend_from_slice(extra);
        let program = cx.w.bins.dir.join("chan-device");
        cx.note(&format!(
            "$ chan-device {} &  (in {})",
            args.join(" "),
            netns
                .as_ref()
                .map_or("the harness's namespace".to_owned(), |p| p
                    .display()
                    .to_string())
        ));
        let stderr = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .map_err(|e| format!("{}: {e}", log.display()))?;
        let mut command = match &netns {
            Some(ns) => {
                let mut c = Command::new("nsenter");
                c.arg(format!("--net={}", ns.display()))
                    .arg("--")
                    .arg(&program);
                c
            }
            None => Command::new(&program),
        };
        let mut child = command
            .args(&args)
            .env(
                "RUST_LOG",
                std::env::var("NDN_E2E_LOG").unwrap_or_else(|_| "info".into()),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn()
            .map_err(|e| format!("{}: {e}", program.display()))?;
        let stdin = child.stdin.take().ok_or("chan-device: no stdin")?;
        let stdout = child.stdout.take().ok_or("chan-device: no stdout")?;
        let (tx, lines) = channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        cx.w.producers.push((
            node.to_owned(),
            Proc {
                child,
                label: "chan-device".into(),
                log: log.clone(),
            },
        ));
        let mut dev = Dev {
            node: node.to_owned(),
            stdin,
            lines,
            events: Vec::new(),
            quiet: false,
            log,
            ip,
            link_key: String::new(),
            writer: String::new(),
            device: device.to_owned(),
        };
        let ready = dev.answer(cx, "start", Duration::from_secs(30))?;
        let ready = &ready["ready"];
        if ready["device"] != device {
            return Err(format!(
                "{node}: chan-device did not start as {device}: {ready}"
            ));
        }
        dev.link_key = ready["link_key"].as_str().unwrap_or_default().to_owned();
        dev.writer = ready["writer"].as_str().unwrap_or_default().to_owned();
        Ok(dev)
    }

    /// The next line within `within`, as JSON; an event is kept and `None` is returned for it.
    fn line(
        &mut self,
        cx: &mut Cx<'_>,
        what: &str,
        within: Duration,
    ) -> StepResult<Option<Option<Value>>> {
        let line = match self.lines.recv_timeout(within) {
            Ok(line) => line,
            Err(RecvTimeoutError::Timeout) => return Ok(None),
            Err(RecvTimeoutError::Disconnected) => {
                return Err(format!(
                    "{}> {what}: chan-device exited{}",
                    self.node,
                    self.tail()
                ));
            }
        };
        if !self.quiet {
            cx.note(&format!("{}< {line}", self.node));
        }
        let v: Value = serde_json::from_str(&line)
            .map_err(|e| format!("{}: not one JSON object per line ({e}): {line}", self.node))?;
        if v.get("ev").is_some() {
            self.events.push(v);
            return Ok(Some(None));
        }
        Ok(Some(Some(v)))
    }

    /// The next line that is not an event.
    fn answer(&mut self, cx: &mut Cx<'_>, what: &str, within: Duration) -> StepResult<Value> {
        let deadline = Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.line(cx, what, left)? {
                None => {
                    return Err(format!(
                        "{}> {what}: no answer within {}s{}",
                        self.node,
                        within.as_secs(),
                        self.tail()
                    ));
                }
                Some(Some(v)) => return Ok(v),
                Some(None) => {}
            }
        }
    }

    /// One verb line: its `ok` object, or its `error` object.
    fn call_within(
        &mut self,
        cx: &mut Cx<'_>,
        line: &str,
        within: Duration,
    ) -> StepResult<Result<Value, Value>> {
        self.quiet = matches!(line, "links" | "side");
        if !self.quiet {
            cx.note(&format!("{}> {line}", self.node));
        }
        writeln!(self.stdin, "{line}")
            .and_then(|()| self.stdin.flush())
            .map_err(|e| format!("{}: chan-device stdin: {e}{}", self.node, self.tail()))?;
        let mut answer = self.answer(cx, line, within)?;
        match (
            answer.get_mut("ok").map(Value::take),
            answer.get_mut("error").map(Value::take),
        ) {
            (Some(ok), _) => Ok(Ok(ok)),
            (None, Some(err)) => Ok(Err(err)),
            _ => Err(format!(
                "{}> {line}: neither ok nor error: {answer}",
                self.node
            )),
        }
    }

    /// A verb that must succeed.
    fn ok(&mut self, cx: &mut Cx<'_>, line: &str) -> StepResult<Value> {
        self.call_within(cx, line, Duration::from_secs(120))?
            .map_err(|e| format!("{}> {line}: {}", self.node, e["message"]))
    }

    /// A verb asked again while it answers an error that says retry, for up to [`CONVERGE`].
    fn ok_when_ready(&mut self, cx: &mut Cx<'_>, line: &str) -> StepResult<Value> {
        let deadline = Instant::now() + CONVERGE;
        loop {
            match self.call_within(cx, line, Duration::from_secs(120))? {
                Ok(ok) => return Ok(ok),
                Err(e) if e["retry"] == true && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(200));
                }
                Err(e) => return Err(format!("{}> {line}: {}", self.node, e["message"])),
            }
        }
    }

    /// Take in what the device prints on its own until `done` holds of it, within `within`.
    fn until(
        &mut self,
        cx: &mut Cx<'_>,
        what: &str,
        within: Duration,
        done: impl Fn(&Dev) -> bool,
    ) -> StepResult<Duration> {
        let started = Instant::now();
        let deadline = started + within;
        while !done(self) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(format!(
                    "{}: {what}: not within {}s ({} events so far){}",
                    self.node,
                    within.as_secs(),
                    self.events.len(),
                    self.tail()
                ));
            }
            if let Some(Some(v)) = self.line(cx, what, left)? {
                return Err(format!("{}: an answer to no verb: {v}", self.node));
            }
        }
        Ok(started.elapsed())
    }

    /// The messages delivered here whose text starts with `prefix`: `(seq, text)`.
    fn gots(&self, prefix: &str) -> Vec<(u64, String)> {
        self.events
            .iter()
            .filter(|e| e["ev"] == "got")
            .filter_map(|e| {
                let text = e["text"].as_str()?;
                text.starts_with(prefix)
                    .then(|| (e["seq"].as_u64().unwrap_or_default(), text.to_owned()))
            })
            .collect()
    }

    /// The index of the first event of `kind` of `ev` (`notice`, `alert`) at or after `from`.
    fn event(&self, ev: &str, kind: &str) -> Option<(usize, &Value)> {
        self.events
            .iter()
            .enumerate()
            .find(|(_, e)| e["ev"] == ev && e["kind"] == kind)
    }

    /// Take in what the device prints on its own until it printed nothing for `quiet`.
    fn settle(&mut self, cx: &mut Cx<'_>, quiet: Duration) -> StepResult<()> {
        let deadline = Instant::now() + quiet * 10;
        while Instant::now() < deadline {
            match self.line(cx, "settle", quiet)? {
                None => return Ok(()),
                Some(Some(v)) => return Err(format!("{}: an answer to no verb: {v}", self.node)),
                Some(None) => {}
            }
        }
        Ok(())
    }

    fn side(&mut self, cx: &mut Cx<'_>) -> StepResult<Side> {
        let ok = self.ok(cx, "side")?;
        Side::parse(ok["text"].as_str().unwrap_or_default())
    }

    /// The `links` report: each link's side-path counters, and the faces of the forwarder.
    fn links(&mut self, cx: &mut Cx<'_>) -> StepResult<Value> {
        self.ok(cx, "links")
    }

    /// The id of the QUIC face of this forwarder whose remote is `ip`.
    fn face_to(&mut self, cx: &mut Cx<'_>, ip: Ipv4Addr) -> StepResult<u64> {
        let report = self.links(cx)?;
        report["faces"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|f| {
                f["kind"] == "Quic"
                    && f["remote"]
                        .as_str()
                        .is_some_and(|r| r.contains(&ip.to_string()))
            })
            .and_then(|f| f["id"].as_u64())
            .ok_or_else(|| format!("{} has no QUIC face to {ip}: {report}", self.node))
    }

    /// Channel frames this device's link to `device` carried, sent and received (both carriers).
    fn side_frames(&mut self, cx: &mut Cx<'_>, device: &str) -> StepResult<(u64, u64)> {
        let report = self.links(cx)?;
        let link = report["links"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|l| l["device"] == device)
            .ok_or_else(|| format!("{} has no link to {device}: {report}", self.node))?;
        let n = |k: &str| link["side"][k].as_u64().unwrap_or_default();
        Ok((
            n("datagram_tx_frames") + n("stream_tx_frames"),
            n("datagram_rx_frames") + n("stream_rx_frames"),
        ))
    }

    fn tail(&self) -> String {
        let text = std::fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        let from = lines.len().saturating_sub(30);
        format!(
            "\n    ── tail of {} chan-device log ──\n    | {}",
            self.node,
            lines[from..].join("\n    | ")
        )
    }
}

impl Drop for Dev {
    fn drop(&mut self) {
        let _ = writeln!(self.stdin, "quit");
        let _ = self.stdin.flush();
    }
}

// ── a forwarder's side table, as `side/list` writes it ────────────────────────────────────

/// One route of the table.
#[derive(Clone, Debug)]
struct SideRoute {
    id: String,
    source: u64,
    sinks: Vec<u64>,
    frames: u64,
}

/// `side/list`: the counters, the routes and the faces barred now.
#[derive(Clone, Debug, Default)]
struct Side {
    frames_out: u64,
    /// Frames dropped because their face was barred.
    quarantined_drops: u64,
    routes: Vec<SideRoute>,
    barred: Vec<u64>,
    text: String,
}

impl Side {
    fn parse(text: &str) -> StepResult<Side> {
        let mut side = Side {
            text: text.to_owned(),
            ..Side::default()
        };
        let field = |line: &str, key: &str| -> Option<u64> {
            line.split_whitespace()
                .find_map(|w| w.strip_prefix(key)?.strip_prefix('=')?.parse().ok())
        };
        for line in text.lines() {
            if line.starts_with("routes=") {
                side.frames_out = field(line, "frames_out")
                    .ok_or_else(|| format!("no frames_out in {line:?}"))?;
            } else if line.starts_with("drops:") {
                side.quarantined_drops = field(line, "quarantined")
                    .ok_or_else(|| format!("no quarantined in {line:?}"))?;
            } else if let Some(rest) = line.strip_prefix("route id=") {
                let id = rest
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                let source =
                    field(line, "source").ok_or_else(|| format!("no source in {line:?}"))?;
                let frames =
                    field(line, "frames").ok_or_else(|| format!("no frames in {line:?}"))?;
                let inner = line
                    .split_once("sinks=[")
                    .and_then(|(_, r)| r.split_once(']'))
                    .map(|(s, _)| s)
                    .ok_or_else(|| format!("no sinks in {line:?}"))?;
                let sinks = inner
                    .split_whitespace()
                    .filter_map(|s| s.split('(').next()?.parse().ok())
                    .collect();
                side.routes.push(SideRoute {
                    id,
                    source,
                    sinks,
                    frames,
                });
            } else if let Some(rest) = line.strip_prefix("quarantined face=") {
                side.barred.push(
                    rest.split_whitespace()
                        .next()
                        .and_then(|f| f.parse().ok())
                        .ok_or_else(|| format!("{line:?}"))?,
                );
            }
        }
        Ok(side)
    }

    /// The route of channel `id` (hex).
    fn route(&self, id: &str) -> Option<&SideRoute> {
        self.routes
            .iter()
            .find(|r| r.id.trim_start_matches('0') == id.trim_start_matches('0'))
    }
}

/// The relay daemon's `side/list`, over its management socket (a signed command, as `ndn-ctl`
/// signs: the module is an ndn-rs extension; `ndn-ctl` has no verb for it).
fn relay_side(cx: &mut Cx<'_>) -> StepResult<Side> {
    let sock = cx.w.node("relay").sock().display().to_string();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let (code, text) = rt.block_on(async move {
        let client = ndn_ipc::MgmtClient::connect(&sock)
            .await
            .map_err(|e| format!("connect to the relay's management socket: {e}"))?;
        let params = ndn_config::ControlParameters::default();
        client
            .send_cmd_raw("side", "list", Some(&params))
            .await
            .map(|(code, text, _)| (code, text))
            .map_err(|e| format!("side/list on the relay: {e}"))
    })?;
    cx.note(&format!("relay> side/list -> {code}\n{text}"));
    if code != 200 {
        return Err(format!("side/list on the relay answered {code}: {text}"));
    }
    Side::parse(&text)
}

/// The relay's QUIC face to the device at `ip` (`ndn-ctl face list`).
fn relay_face(cx: &mut Cx<'_>, ip: Ipv4Addr) -> StepResult<u64> {
    let sock = cx.w.node("relay").sock().display().to_string();
    let op = cx
        .tool("ndn-ctl")
        .args(["--socket", &sock, "face", "list", "--scheme", "quic4"]);
    let out = cx.exec(op);
    if !out.success() {
        return Err(format!("face list on the relay: {}", out.status_text()));
    }
    let mut face = None;
    for line in out.stdout.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("faceid=") {
            face = rest.split_whitespace().next().and_then(|f| f.parse().ok());
        } else if let Some(remote) = t.strip_prefix("remote: quic4://")
            && remote
                .split(':')
                .next()
                .and_then(|a| a.parse::<Ipv4Addr>().ok())
                == Some(ip)
        {
            return face.ok_or_else(|| "a remote line before any faceid".to_owned());
        }
    }
    Err(format!(
        "the relay has no QUIC face to {ip}:\n{}",
        out.stdout
    ))
}

/// The frames of the channel as each end of a hop counted them, read together until they agree
/// (frames in flight make a read ahead by one for an instant): the sender's link's frames sent
/// since `base`, the relay route's frames since, the relay's frames out since, and each receiver's
/// link's frames received since.
struct Hop {
    sent: u64,
    routed: u64,
    out: u64,
    received: Vec<u64>,
}

fn read_hop(
    cx: &mut Cx<'_>,
    channel: &str,
    sender: &mut Dev,
    receivers: &mut [&mut Dev],
    relay_device: &str,
    base: &(u64, u64, u64, Vec<u64>),
) -> StepResult<Hop> {
    let side = relay_side(cx)?;
    let route = side.route(channel).ok_or_else(|| {
        format!(
            "the relay has no route of channel {channel}:\n{}",
            side.text
        )
    })?;
    let (tx, _) = sender.side_frames(cx, relay_device)?;
    let mut received = Vec::new();
    for (i, r) in receivers.iter_mut().enumerate() {
        let (_, rx) = r.side_frames(cx, relay_device)?;
        received.push(rx - base.3[i]);
    }
    Ok(Hop {
        sent: tx - base.0,
        routed: route.frames - base.1,
        out: side.frames_out - base.2,
        received,
    })
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    if let Some(why) = Nat::missing() {
        sc.skip("build a network namespace for each device", &why);
        return Ok(());
    }
    sc.step(
        "build a network namespace for each of the sender's, carol's and dave's devices (a veth \
         each, 10.1.k.2, default route via the harness, where the relay's daemon listens on \
         10.200.0.3)",
        |cx| {
            let mut nat = Nat::new(cx.w.dir.join("nat"))?;
            for _ in 0..3 {
                nat.add_roamer()?;
            }
            for k in 1..=3 {
                let r = nat.roamer(k);
                cx.evidence(&format!("roamer {k}: device at {}", r.home));
            }
            cx.w.nat = Some(nat);
            Ok(())
        },
    )?;
    for (node, k) in [("sender", 1), ("carol", 2), ("dave", 3)] {
        sc.world.add_roaming(node, k, NodeCfg::default());
    }
    sc.world.add(
        "rroot",
        ROOT,
        NodeCfg {
            extra_toml: "[relays]\nnamespace = false\n".to_owned(),
            ..Default::default()
        },
    );
    sc.world.add(
        "relay",
        RELAY,
        NodeCfg {
            links: vec![link("rroot", ROOT)],
            routes: vec![route(NS_R, "rroot")],
            quic_listen: true,
            ..Default::default()
        },
    );

    let roots = sc.step(
        "each creates a namespace (ndn-fwd init): the relay /cr, the sender /cs, carol /cc, dave \
         /cd; each person adopts the trust contexts of the namespaces it must know (the sender \
         the receivers', each receiver the sender's, every device the relay's, and carol dave's: \
         her link goes to him) — the relay adopts none",
        |cx| {
            cx.concept("namespaces of three people and a relay");
            let mut roots = Vec::new();
            for (node, ns, device) in [
                ("rroot", NS_R, "desk"),
                ("sender", NS_S, "sender"),
                ("carol", NS_C, "carol"),
                ("dave", NS_D, "dave"),
            ] {
                if node == "rroot" {
                    cx.w.node_mut("rroot").cfg.ca = Some(CaCfg {
                        prefix: NS_R.into(),
                        identity: format!("{NS_R}/CA"),
                        member_days: None,
                    });
                }
                let (root, _) = init_root_with(cx, node, ns, device, node == "rroot")?;
                cx.evidence(&format!("{node}: init {ns}: device {}", root.identity));
                roots.push(root);
            }
            let by = |ns: &str| match ns {
                NS_R => &roots[0],
                NS_S => &roots[1],
                NS_C => &roots[2],
                _ => &roots[3],
            };
            for (node, adopts) in [
                ("sender", [NS_C, NS_D, NS_R].as_slice()),
                ("carol", &[NS_S, NS_D, NS_R]),
                ("dave", &[NS_S, NS_R]),
            ] {
                for ns in adopts {
                    adopt_offline(cx, node, ns, &by(ns).link_inline)?;
                }
            }
            for ns in [NS_S, NS_C, NS_D] {
                if let Some(v) = cx.version("rroot", ns) {
                    return Err(format!("/cr's root device holds {ns} v{v}"));
                }
            }
            Ok(roots)
        },
    )?;
    let (relay_root, sender_root, carol_root, dave_root) = (
        roots[0].clone(),
        roots[1].clone(),
        roots[2].clone(),
        roots[3].clone(),
    );

    let relay_key = sc.step(
        "/cr's root device starts with its CA; the relay's daemon starts listening for links, \
         adopts /cr and becomes a node device on the root's approval (a relay of /cr: the \
         link policy the people follow /cr by lets node devices relay), serving the three \
         people by their root fingerprints with no quotas ([relay_service] serve = \"listed\"): \
         no trust context of theirs, no route, no [[peer]] to them",
        |cx| {
            cx.concept("relay serving listed namespaces without quotas");
            cx.w.node_mut("rroot").cfg.identity = Some(relay_root.identity.clone());
            cx.start("rroot")?;
            let relay = cx.w.node_mut("relay");
            relay.cfg.extra_toml = format!(
                "[relays]\nnamespace = false\n\n[relay_service]\nserve = \"listed\"\nroots = \
                 [\"{}\", \"{}\", \"{}\"]\n\n{FAST_LINKS}",
                sender_root.fp, carol_root.fp, dave_root.fp
            );
            cx.start("relay")?;
            let op = cx
                .tool("ndn-fwd")
                .arg("adopt")
                .arg(&relay_root.link_fp)
                .arg("-c")
                .arg(cx.w.node("relay").cfg_arg());
            cx.ok(op, "adopt")?;
            cx.expect_version("relay", NS_R, 1)?;
            let before_key = link_list(cx, "relay")?
                .key
                .ok_or_else(|| "the relay's link list shows no key".to_owned())?;
            enroll_by_approval_at(cx, NS_R, &relay_root.link_fp, "rroot", "relay")?;
            for ns in [NS_S, NS_C, NS_D] {
                if let Some(v) = cx.version("relay", ns) {
                    return Err(format!("the relay holds {ns} v{v}"));
                }
            }
            // The daemon's link key is its enrolled node key once the enrollment ends: until
            // then it is the ephemeral key it started with, which no device may pin.
            let mut key = String::new();
            wait_for(
                cx,
                "the relay's link key is its enrolled key",
                SHORT,
                |cx| {
                    key = link_list(cx, "relay")?
                        .key
                        .ok_or_else(|| "the relay's link list shows no key".to_owned())?;
                    Ok(key != before_key)
                },
            )?;
            cx.evidence(&format!(
                "relay: node device {NS_R}/node/relay, link key {key}; holds {NS_R} only"
            ));
            Ok(key)
        },
    )?;

    let relay_args = |key: &str, device: &str, endpoint: &str| {
        vec![
            "--relay-key".to_owned(),
            key.to_owned(),
            "--relay-device".to_owned(),
            device.to_owned(),
            "--relay-endpoint".to_owned(),
            endpoint.to_owned(),
        ]
    };
    let relay_endpoint = format!("{}:{QUIC_PORT}", addr(RELAY));
    let relay_device = format!("{NS_R}/node/relay");
    let (mut sender, mut carol, mut dave) = sc.step(
        "each device starts (chan-device: its own forwarder, its links, its data layer, in its \
         own network namespace): the sender, carol and dave link to the relay, dave listening \
         too and serving carol's root, and each shows its relay link up",
        |cx| {
            cx.concept("channel devices on forwarders of their own");
            let to_relay = relay_args(&relay_key, &relay_device, &relay_endpoint);
            let sender = Dev::start(cx, "sender", &sender_root.identity, 0, &to_relay)?;
            let carol = Dev::start(cx, "carol", &carol_root.identity, 0, &to_relay)?;
            let mut dave_args = to_relay.clone();
            dave_args.extend([
                "--listen".to_owned(),
                "--serve-root".to_owned(),
                carol_root.fp.clone(),
            ]);
            let dave = Dev::start(cx, "dave", &dave_root.identity, QUIC_PORT, &dave_args)?;
            let mut all = [sender, carol, dave];
            for dev in &mut all {
                let node = dev.node.clone();
                wait_for(
                    cx,
                    &format!("{node}'s link to the relay is up"),
                    SHORT,
                    |cx| linked_to(cx, dev, &relay_device),
                )?;
                cx.evidence(&format!(
                    "{node} ({}): link key {}, linked to the relay {relay_device}",
                    dev.device, dev.link_key
                ));
            }
            let [sender, carol, dave] = all;
            Ok((sender, carol, dave))
        },
    )?;

    sc.step(
        "the sender creates the space /cs/32=data/chan for carol and dave (readers /cc and /cd) \
         and each opens it (asked again until its record has reached them over the links)",
        |cx| {
            sender.ok(cx, &format!("create {SPACE} readers={NS_C},{NS_D}"))?;
            for dev in [&mut carol, &mut dave] {
                dev.ok_when_ready(cx, &format!("open {SPACE}"))?;
                cx.evidence(&format!("{} holds {SPACE}", dev.node));
            }
            Ok(())
        },
    )?;

    let channel = sc.step(
        "carol and dave each take the sender's channel (an Items, then the signed ask over the \
         links through the relay) and watch the space for alerts: one channel, with checkpoints",
        |cx| {
            cx.concept("channel: the signed ask through a relay");
            let line = format!("get {SPACE} {}", sender.device);
            let mut ids = Vec::new();
            for dev in [&mut carol, &mut dave] {
                dev.ok(cx, &format!("watch {SPACE}"))?;
                let got = dev.ok(cx, &line)?;
                if got["checkpoint_ms"].as_u64().is_none() {
                    return Err(format!(
                        "{}'s channel announces no checkpoints: {got}",
                        dev.node
                    ));
                }
                cx.evidence(&format!(
                    "{} took channel {} ({}, checkpoints every {} ms)",
                    dev.node, got["channel"], got["mode"], got["checkpoint_ms"]
                ));
                ids.push(got["channel"].as_str().unwrap_or_default().to_owned());
            }
            if ids[0] != ids[1] || ids[0].is_empty() {
                return Err(format!("carol and dave hold channels {ids:?}, not one"));
            }
            Ok(ids.remove(0))
        },
    )?;

    let (sender_face, carol_face, dave_face) = sc.step(
        "the sender emits 20 messages: carol and dave get all 20, in order, from the sender's \
         device; the relay's side table (side/list over its management socket) has one route \
         for the channel, sourced at the sender's link, with the two receivers' links as its \
         sinks; the sender's link carried one copy of each frame (its counter equals the route's \
         frames at the relay), the relay sent each to both sinks (frames out are twice the \
         route's), and each receiver's link counted exactly the route's frames",
        |cx| {
            cx.concept("one copy per link, fan-out at the relay");
            let base = hop_base(cx, &channel, &mut sender, &mut [&mut carol, &mut dave], &relay_device)?;
            sender.ok(cx, &format!("emit {SPACE} {POS} 20 100 a"))?;
            for dev in [&mut carol, &mut dave] {
                dev.until(cx, "all 20 messages of the burst", BURST, |d| {
                    d.gots("a-").len() == 20
                })?;
                let got = dev.gots("a-");
                let want: Vec<String> = (0..20).map(|i| format!("a-{i}")).collect();
                let texts: Vec<String> = got.iter().map(|(_, t)| t.clone()).collect();
                if texts != want {
                    return Err(format!("{} got {texts:?}, not {want:?} in order", dev.node));
                }
                if got.windows(2).any(|w| w[0].0 >= w[1].0) {
                    return Err(format!("{}'s sequences do not rise: {got:?}", dev.node));
                }
                let writers: Vec<&str> = dev
                    .events
                    .iter()
                    .filter(|e| e["ev"] == "got")
                    .filter_map(|e| e["writer"].as_str())
                    .collect();
                if writers.iter().any(|w| *w != sender.device) {
                    return Err(format!("{} got messages written by {writers:?}", dev.node));
                }
                cx.evidence(&format!(
                    "{} got a-0..a-19 in order (seqs {}..={}), all from {}",
                    dev.node,
                    got[0].0,
                    got[19].0,
                    sender.device
                ));
            }
            let faces = (
                relay_face(cx, sender.ip)?,
                relay_face(cx, carol.ip)?,
                relay_face(cx, dave.ip)?,
            );
            let side = relay_side(cx)?;
            if side.routes.len() != 1 {
                return Err(format!("the relay's table holds {} routes:\n{}", side.routes.len(), side.text));
            }
            let route = side
                .route(&channel)
                .ok_or_else(|| format!("the relay has no route of channel {channel}:\n{}", side.text))?;
            let mut sinks = route.sinks.clone();
            sinks.sort_unstable();
            let mut want = vec![faces.1, faces.2];
            want.sort_unstable();
            if route.source != faces.0 || sinks != want {
                return Err(format!(
                    "the relay's route of {channel} is source {} sinks {:?}, expected source {} \
                     (the sender's link) and sinks {want:?} (carol's and dave's):\n{}",
                    route.source, route.sinks, faces.0, side.text
                ));
            }
            cx.evidence(&format!(
                "relay side/list: route {channel}: source face {} (the sender's link), sinks {:?} \
                 (carol's face {}, dave's face {})",
                route.source, route.sinks, faces.1, faces.2
            ));
            let mut hop = None;
            wait_for(cx, "the counters of the hop agree", SHORT, |cx| {
                let h = read_hop(cx, &channel, &mut sender, &mut [&mut carol, &mut dave], &relay_device, &base)?;
                let agree = h.routed >= 1
                    && h.sent == h.routed
                    && h.out == 2 * h.routed
                    && h.received.iter().all(|r| *r == h.routed);
                hop = Some(h);
                Ok(agree)
            })?;
            let h = hop.expect("read at least once");
            cx.evidence(&format!(
                "frames of the channel since before the burst: the sender's link sent {}, the \
                 relay's route took {} and sent {} (two sinks), carol's link received {}, dave's {}",
                h.sent, h.routed, h.out, h.received[0], h.received[1]
            ));
            Ok(faces)
        },
    )?;

    sc.step(
        "carol drops her get: the relay's route is left with one sink, dave's; the sender emits \
         10 more, dave gets all 10 and carol none, and the relay sends each frame to one sink",
        |cx| {
            cx.concept("a receiver leaves");
            carol.ok(cx, "leave")?;
            wait_for(
                cx,
                "the relay's route has dave's link as its only sink",
                SHORT,
                |cx| {
                    let side = relay_side(cx)?;
                    Ok(side.route(&channel).is_some_and(|r| r.sinks == [dave_face]))
                },
            )?;
            let side = relay_side(cx)?;
            let route = side.route(&channel).ok_or("the route went with its sink")?;
            if route.source != sender_face {
                return Err(format!(
                    "the route's source is {}, not the sender's {sender_face}",
                    route.source
                ));
            }
            cx.evidence(&format!(
                "relay side/list: route {channel}: source face {sender_face}, sinks {:?} (dave's \
                 face {dave_face}); carol's face {carol_face} is no sink",
                route.sinks
            ));
            let base = hop_base(cx, &channel, &mut sender, &mut [&mut dave], &relay_device)?;
            sender.ok(cx, &format!("emit {SPACE} {POS} 10 100 b"))?;
            dave.until(cx, "all 10 messages of the burst", BURST, |d| {
                d.gots("b-").len() == 10
            })?;
            let texts: Vec<String> = dave.gots("b-").into_iter().map(|(_, t)| t).collect();
            let want: Vec<String> = (0..10).map(|i| format!("b-{i}")).collect();
            if texts != want {
                return Err(format!("dave got {texts:?}, not {want:?}"));
            }
            carol.settle(cx, Duration::from_millis(500))?;
            if !carol.gots("b-").is_empty() {
                return Err(format!("carol, who left, got {:?}", carol.gots("b-")));
            }
            let mut hop = None;
            wait_for(cx, "the counters of the hop agree", SHORT, |cx| {
                let h = read_hop(
                    cx,
                    &channel,
                    &mut sender,
                    &mut [&mut dave],
                    &relay_device,
                    &base,
                )?;
                let agree = h.routed >= 1
                    && h.sent == h.routed
                    && h.out == h.routed
                    && h.received == [h.routed];
                hop = Some(h);
                Ok(agree)
            })?;
            let h = hop.expect("read at least once");
            cx.evidence(&format!(
                "dave got b-0..b-9 in order, carol none; since the burst the sender's link sent \
                 {}, the route took {} and sent {} (one sink), dave's link received {}",
                h.sent, h.routed, h.out, h.received[0]
            ));
            Ok(())
        },
    )?;

    let carol_ip = carol.ip;
    sc.step(
        "carol's device starts again with dave as its relay (its link goes to dave's address, \
         not the relay's; dave serves her by her root fingerprint, no quotas): carol opens the \
         space, takes the channel and gets 5 messages through two forwarders; the relay's route \
         still has one sink, dave's, and dave's own route has two, his own device and carol's link",
        |cx| {
            cx.concept("a member's forwarder as another's relay");
            cx.stop("carol");
            let to_dave = relay_args(&dave.link_key, &dave.device, &format!("{}:{QUIC_PORT}", dave.ip));
            carol = Dev::start(cx, "carol", &carol_root.identity, 0, &to_dave)?;
            let dave_device = dave.device.clone();
            wait_for(cx, "carol's link to dave is up", SHORT, |cx| linked_to(cx, &mut carol, &dave_device))?;
            let carol_device = carol.device.clone();
            wait_for(cx, "dave's link to carol is up", SHORT, |cx| linked_to(cx, &mut dave, &carol_device))?;
            carol.ok_when_ready(cx, &format!("open {SPACE}"))?;
            carol.ok(cx, &format!("watch {SPACE}"))?;
            let got = carol.ok(cx, &format!("get {SPACE} {}", sender.device))?;
            if got["channel"] != channel.as_str() {
                return Err(format!("carol's channel is {}, not {channel}", got["channel"]));
            }
            let dave_to_relay = dave.face_to(cx, addr(RELAY))?;
            let dave_to_carol = dave.face_to(cx, carol_ip)?;
            let side = dave.side(cx)?;
            let route = side
                .route(&channel)
                .ok_or_else(|| format!("dave's table has no route of {channel}:\n{}", side.text))?;
            if route.source != dave_to_relay || route.sinks.len() != 2 || !route.sinks.contains(&dave_to_carol) {
                return Err(format!(
                    "dave's route of {channel}: source {} sinks {:?}, expected source {dave_to_relay} \
                     (the relay's link) and two sinks including carol's link {dave_to_carol}:\n{}",
                    route.source, route.sinks, side.text
                ));
            }
            let relay = relay_side(cx)?;
            let upstream = relay.route(&channel).ok_or("the relay lost the route")?;
            if upstream.sinks != [dave_face] {
                return Err(format!("the relay's sinks are {:?}, expected dave's {dave_face} alone", upstream.sinks));
            }
            cx.evidence(&format!(
                "dave side: route {channel}: source face {dave_to_relay} (the relay's link), sinks \
                 {:?} (his device and carol's link, face {dave_to_carol}); the relay's sinks: {:?}",
                route.sinks, upstream.sinks
            ));
            sender.ok(cx, &format!("emit {SPACE} {POS} 5 100 c"))?;
            for dev in [&mut carol, &mut dave] {
                dev.until(cx, "all 5 messages of the burst", BURST, |d| d.gots("c-").len() == 5)?;
            }
            let texts: Vec<String> = carol.gots("c-").into_iter().map(|(_, t)| t).collect();
            if texts != ["c-0", "c-1", "c-2", "c-3", "c-4"] {
                return Err(format!("carol got {texts:?}"));
            }
            cx.evidence(&format!(
                "carol got c-0..c-4 in order through dave (seqs {:?})",
                carol.gots("c-").iter().map(|g| g.0).collect::<Vec<_>>()
            ));
            Ok(())
        },
    )?;

    let forged = sc.step(
        "dave, a key holder and carol's forwarder, seals a frame under the channel key at a \
         sequence the sender has not reached and sends it to carol over his link; the sender \
         emits 40 more: carol's get delivers the forged frame as the sender's, then the sender's \
         checkpoint does not list it — carol raises Alert::ChannelForgery for that sequence and \
         that link, her evidence holds a Mismatch for the frame from that link, her get yields \
         Retracted over it, her forwarder's side/list shows that link barred, and neither \
         dave's nor the relay's shows a bar",
        |cx| {
            cx.concept("a forged frame exposed by the next checkpoint");
            let seen = dave
                .gots("c-")
                .last()
                .map(|g| g.0)
                .ok_or("dave saw no message of the sender's")?;
            let seq = seen + AHEAD;
            let dave_to_carol = dave.face_to(cx, carol_ip)?;
            let carol_to_dave = carol.face_to(cx, dave.ip)?;
            dave.ok(
                cx,
                &format!("forge {channel} {seq} {FORGED_NAME_ID} {POS} {dave_to_carol} FORGED"),
            )?;
            cx.evidence(&format!(
                "dave sealed a frame at seq {seq} (he last saw {seen}: the sender has not reached \
                 it) under the channel key and sent it to carol over his face {dave_to_carol}; it \
                 arrives at carol over her face {carol_to_dave}"
            ));
            sender.ok(cx, &format!("emit {SPACE} {POS} 40 25 d"))?;
            carol.until(cx, "the forgery alert and the retraction", BURST, |d| {
                d.event("alert", "channel-forgery").is_some() && d.event("notice", "retracted").is_some()
            })?;
            let (_, alert) = carol.event("alert", "channel-forgery").expect("waited for it");
            if alert["seq"] != seq || alert["via"] != carol_to_dave || alert["channel"] != channel.as_str() {
                return Err(format!(
                    "carol's alert is {alert}, expected channel {channel}, seq {seq}, via {carol_to_dave}"
                ));
            }
            let alert_at = carol.event("alert", "channel-forgery").map(|(i, _)| i).expect("kept");
            let (retracted_at, retracted) = carol.event("notice", "retracted").expect("waited for it");
            let (from, to) = (retracted["from"].as_u64().unwrap_or(u64::MAX), retracted["to"].as_u64().unwrap_or(0));
            if !(from <= seq && seq <= to) {
                return Err(format!("carol's get retracted {from}..={to}, which does not cover {seq}"));
            }
            let delivered_at = carol
                .events
                .iter()
                .position(|e| e["ev"] == "got" && e["text"] == "FORGED")
                .ok_or("carol's get never delivered the forged frame (it was to be delivered, then retracted)")?;
            if carol.events[delivered_at]["seq"] != seq || delivered_at > retracted_at {
                return Err(format!(
                    "the forged message was delivered as {} (event {delivered_at}), the retraction came as event {retracted_at}",
                    carol.events[delivered_at]
                ));
            }
            let evidence = carol.ok(cx, "evidence")?;
            let mismatch = evidence["evidence"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|e| e["kind"] == "Mismatch" && e["seq0"] == seq)
                .ok_or_else(|| format!("carol's evidence holds no Mismatch at {seq}: {evidence}"))?;
            if mismatch["ingress"] != carol_to_dave || mismatch["channel"] != channel.as_str() {
                return Err(format!(
                    "carol's evidence names {mismatch}, expected channel {channel}, ingress {carol_to_dave}"
                ));
            }
            let carol_side = carol.side(cx)?;
            if carol_side.barred != [carol_to_dave] {
                return Err(format!(
                    "carol's side/list bars {:?}, expected exactly her link to dave {carol_to_dave}:\n{}",
                    carol_side.barred, carol_side.text
                ));
            }
            let dave_side = dave.side(cx)?;
            let relay_side = relay_side(cx)?;
            if !dave_side.barred.is_empty() || !relay_side.barred.is_empty() {
                return Err(format!(
                    "a bar where there should be none: dave {:?}, relay {:?}",
                    dave_side.barred, relay_side.barred
                ));
            }
            if dave.gots("").iter().any(|(_, t)| t == "FORGED") {
                return Err("the forged message reached dave's get".to_owned());
            }
            cx.evidence(&format!(
                "carol: the forged message (seq {seq}) was delivered (event {delivered_at}), then \
                 the alert ChannelForgery (event {alert_at}: channel {channel}, seq {seq}, via face \
                 {carol_to_dave}) and Retracted {from}..={to} (event {retracted_at}); evidence: \
                 Mismatch at {seq} from ingress {carol_to_dave}; carol's side/list: face \
                 {carol_to_dave} barred; dave's and the relay's: none"
            ));
            Ok((seq, carol_to_dave))
        },
    )?;

    sc.step(
        "the bar is on channel frames only: the sender puts an entry in the space and it reaches \
         carol over the barred link (NDN traffic goes on); the sender emits 5 more and dave gets \
         all 5 while carol gets none, her side table counting the frames it dropped from the \
         barred link",
        |cx| {
            cx.concept("a barred link still carries NDN traffic");
            let (_, carol_to_dave) = forged;
            let drops0 = carol.side(cx)?.quarantined_drops;
            sender.ok(cx, &format!("put {SPACE} note after the bar"))?;
            wait_for(
                cx,
                "carol reads the entry the sender put",
                CONVERGE,
                |cx| match carol.call_within(
                    cx,
                    &format!("item {SPACE} /note"),
                    Duration::from_secs(30),
                )? {
                    Ok(ok) => Ok(ok["item"]["text"] == "after the bar"),
                    Err(e) if e["retry"] == true => Ok(false),
                    Err(e) => Err(format!("carol> item: {}", e["message"])),
                },
            )?;
            sender.ok(cx, &format!("emit {SPACE} {POS} 5 100 e"))?;
            dave.until(cx, "all 5 messages of the burst", BURST, |d| {
                d.gots("e-").len() == 5
            })?;
            let mut dropped = 0;
            wait_for(
                cx,
                "carol's side table counts frames dropped from the barred link",
                SHORT,
                |cx| {
                    dropped = carol.side(cx)?.quarantined_drops - drops0;
                    Ok(dropped > 0)
                },
            )?;
            carol.settle(cx, Duration::from_millis(500))?;
            if !carol.gots("e-").is_empty() {
                return Err(format!(
                    "carol got {:?} over the barred link",
                    carol.gots("e-")
                ));
            }
            let side = carol.side(cx)?;
            if !side.barred.contains(&carol_to_dave) {
                return Err(format!(
                    "carol's bar on {carol_to_dave} is gone:\n{}",
                    side.text
                ));
            }
            cx.evidence(&format!(
                "carol read the entry the sender put over face {carol_to_dave}, still barred; \
                 she dropped {dropped} channel frames from it and got no message of the burst; \
                 dave got e-0..e-4"
            ));
            Ok(())
        },
    )?;
    Ok(())
}

/// Whether `dev`'s link to `device` is up.
fn linked_to(cx: &mut Cx<'_>, dev: &mut Dev, device: &str) -> StepResult<bool> {
    let report = dev.links(cx)?;
    Ok(report["links"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|l| l["device"] == device && l["linked"] == true))
}

/// The counters a burst is measured from: the sender's link's frames sent, the relay route's
/// frames, the relay's frames out, and each receiver's link's frames received.
fn hop_base(
    cx: &mut Cx<'_>,
    channel: &str,
    sender: &mut Dev,
    receivers: &mut [&mut Dev],
    relay_device: &str,
) -> StepResult<(u64, u64, u64, Vec<u64>)> {
    let side = relay_side(cx)?;
    let route = side.route(channel).ok_or_else(|| {
        format!(
            "the relay has no route of channel {channel}:\n{}",
            side.text
        )
    })?;
    let (tx, _) = sender.side_frames(cx, relay_device)?;
    let mut rx = Vec::new();
    for r in receivers.iter_mut() {
        rx.push(r.side_frames(cx, relay_device)?.1);
    }
    Ok((tx, route.frames, side.frames_out, rx))
}
