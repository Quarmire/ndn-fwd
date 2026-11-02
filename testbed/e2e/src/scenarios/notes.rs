//! notes: one person's note, written on two devices apart, merged when they
//! meet again — the data layer (`ndn_data::Device`) on real daemons.
//!
//! Topology, on the harness's `lo`: laptop (10.200.0.1, the root device of
//! /nt with its CA) ↔ phone (.2, a member enrolled by invite), one UDP link.
//! Routes: the laptop sends `/nt/member/phone` to the phone, the phone sends
//! `/nt` (the laptop's device prefix, its CA) to the laptop, and each sends
//! the namespace's sync group `/nt/32=sync` over the link with the
//! `multicast` strategy: the data layer registers the group on its own sync
//! connection, which would otherwise shadow any shorter route, and a sync
//! Interest must reach every other member.
//!
//! Each device runs `ndn-data` (ndn-tools) on its daemon's socket: the
//! device's data layer with the key `ndn-fwd init`/`enroll` put in the PIB,
//! verifying with the PIB's trust context, driven line by line over stdin
//! and answering one JSON object per line — standing in for the host an app
//! runs in, not for anything the person does.
//!
//! Proves: the laptop shares a note collection and writes `text=day 1`; the
//! phone reads that version. With UDP between the two cut (nftables), the
//! laptop writes `text=on the plane` while the phone writes `tags=trip` and
//! then `text=in the taxi`, each seeing only its own (neither daemon gets
//! the other's new entry); once the link is back
//! both reach the same state (same frontier, same value) holding all four
//! versions, with no step by the person. Every version is named
//! `<its device>/32=log/<collection>/seq=<n>`, the two devices write with
//! different keys (each the key its PIB certifies), each offline version's
//! parents include `day 1` and neither side's offline versions name the
//! other's (they are concurrent); the phone's watch delivered the laptop's
//! versions; and each daemon fetches the other device's log entries,
//! validating them against /nt's trust context, with the writer device's
//! key as KeyLocator.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::run::Proc;
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{CaCfg, NodeCfg, addr};

const NS: &str = "/nt";
/// The note collection, in the person's namespace.
const NOTES: &str = "/nt/notes/trip";
const PHONE: &str = "/nt/member/phone";
/// The nftables table that cuts laptop–phone.
const CUT_TABLE: &str = "ndn_e2e_notes_cut";
/// SVS's periodic interval for the hosts (default 30 s): how soon two
/// devices that were apart notice; performance only.
const SYNC_INTERVAL_MS: u64 = 1000;
/// One verb's answer (a `get` may wait out a fetch's lifetime first).
const ANSWER: Duration = Duration::from_secs(30);
const CONVERGE: Duration = Duration::from_secs(60);

fn n(s: &str) -> String {
    format!("{NS}{s}")
}

fn name(s: &str) -> StepResult<ndn_packet::Name> {
    s.parse().map_err(|e| format!("{s:?} is no name: {e:?}"))
}

/// One device's `ndn-data` host: its stdin, its answers, the changes its
/// watches delivered.
struct Host {
    node: String,
    device: String,
    writer: String,
    stdin: ChildStdin,
    lines: Receiver<String>,
    watched: Vec<Value>,
    log: PathBuf,
}

impl Host {
    /// Start `ndn-data` for `device` on `node`'s daemon; ready once it says
    /// so. The process is the node's producer: stopped with it, its log
    /// shown when a step fails.
    fn start(cx: &mut Cx<'_>, node: &str, device: &str) -> StepResult<Host> {
        let (sock, pib, log) = {
            let nd = cx.w.node(node);
            (nd.sock(), nd.pib(), nd.dir.join("ndn-data.log"))
        };
        let program = cx.w.bins.dir.join("ndn-data");
        let args = [
            "--device".to_owned(),
            device.to_owned(),
            "--pib".to_owned(),
            pib.display().to_string(),
            "--face-socket".to_owned(),
            sock.display().to_string(),
            "--sync-interval-ms".to_owned(),
            SYNC_INTERVAL_MS.to_string(),
        ];
        cx.note(&format!("$ ndn-data {} &", args.join(" ")));
        let stderr = fs::File::create(&log).map_err(|e| format!("{}: {e}", log.display()))?;
        let mut child = Command::new(&program)
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
        let stdin = child.stdin.take().ok_or("ndn-data: no stdin")?;
        let stdout = child.stdout.take().ok_or("ndn-data: no stdout")?;
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
                label: "ndn-data".into(),
                log: log.clone(),
            },
        ));
        let mut host = Host {
            node: node.to_owned(),
            device: device.to_owned(),
            writer: String::new(),
            stdin,
            lines,
            watched: Vec::new(),
            log,
        };
        let ready = host.next(cx, "start", Duration::from_secs(20))?;
        let ready = &ready["ready"];
        if ready["device"] != device {
            return Err(format!(
                "{node}: ndn-data did not start as {device}: {ready}"
            ));
        }
        host.writer = ready["writer"]
            .as_str()
            .ok_or_else(|| format!("{node}: no writer in {ready}"))?
            .to_owned();
        Ok(host)
    }

    /// The next line that is not a watched change, as JSON.
    fn next(&mut self, cx: &mut Cx<'_>, what: &str, within: Duration) -> StepResult<Value> {
        let deadline = Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = match self.lines.recv_timeout(left) {
                Ok(line) => line,
                Err(RecvTimeoutError::Timeout) => {
                    return Err(format!(
                        "{}> {what}: no answer within {}s{}",
                        self.node,
                        within.as_secs(),
                        self.tail()
                    ));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(format!(
                        "{}> {what}: ndn-data exited{}",
                        self.node,
                        self.tail()
                    ));
                }
            };
            cx.note(&format!("{}< {line}", self.node));
            let v: Value = serde_json::from_str(&line).map_err(|e| {
                format!("{}: not one JSON object per line ({e}): {line}", self.node)
            })?;
            if v.get("watch").is_some() {
                self.watched.push(v);
            } else {
                return Ok(v);
            }
        }
    }

    /// Send one verb line: its `ok` object, or its `error` object.
    fn call(&mut self, cx: &mut Cx<'_>, line: &str) -> StepResult<Result<Value, Value>> {
        cx.note(&format!("{}> {line}", self.node));
        writeln!(self.stdin, "{line}")
            .and_then(|()| self.stdin.flush())
            .map_err(|e| format!("{}: ndn-data stdin: {e}{}", self.node, self.tail()))?;
        let answer = self.next(cx, line, ANSWER)?;
        let Value::Object(mut fields) = answer else {
            return Err(format!(
                "{}> {line}: not a JSON object: {answer}",
                self.node
            ));
        };
        match (fields.remove("ok"), fields.remove("error")) {
            (Some(ok), _) => Ok(Ok(ok)),
            (None, Some(err)) => Ok(Err(err)),
            _ => Err(format!(
                "{}> {line}: neither ok nor error: {}",
                self.node,
                Value::Object(fields)
            )),
        }
    }

    /// A verb that must succeed.
    fn ok(&mut self, cx: &mut Cx<'_>, line: &str) -> StepResult<Value> {
        self.call(cx, line)?.map_err(|e| {
            format!(
                "{}> {line}: {} (next: {})",
                self.node, e["message"], e["next_step"]
            )
        })
    }

    /// `put` into the notes: the version, its name checked to be
    /// `<device>/32=log/<collection>/seq=<n>` and its writer this device's
    /// key.
    fn put(&mut self, cx: &mut Cx<'_>, fields: &str) -> StepResult<Put> {
        let ok = self.ok(cx, &format!("put {NOTES} {fields}"))?;
        let put = Put {
            writer: ok["writer"].as_str().unwrap_or_default().to_owned(),
            seq: ok["seq"]
                .as_u64()
                .ok_or_else(|| format!("no seq in {ok}"))?,
            name: ok["name"].as_str().unwrap_or_default().to_owned(),
        };
        if put.writer != self.writer {
            return Err(format!(
                "{}'s put was written by {}, not its key {}",
                self.node, put.writer, self.writer
            ));
        }
        let expected = format!("{}/32=log{NOTES}/seq={}", self.device, put.seq);
        if name(&put.name)? != name(&expected)? {
            return Err(format!("{} is named {}, not {expected}", fields, put.name));
        }
        cx.evidence(&format!(
            "{} put {fields}: {} (writer {})",
            self.node, put.name, put.writer
        ));
        Ok(put)
    }

    /// The notes' merged state here (frontier, value); `None` while no path
    /// answered and nothing is held yet (an error that says retry).
    fn state(&mut self, cx: &mut Cx<'_>) -> StepResult<Option<(Value, Value)>> {
        match self.call(cx, &format!("get {NOTES}"))? {
            Ok(ok) => Ok(Some((
                ok["state"]["at"].clone(),
                ok["state"]["value"].clone(),
            ))),
            Err(e) if e["retry"] == true => Ok(None),
            Err(e) => Err(format!(
                "{}> get {NOTES}: {} (next: {})",
                self.node, e["message"], e["next_step"]
            )),
        }
    }

    /// Version `v` as this device reads it by its exact name.
    fn version(&mut self, cx: &mut Cx<'_>, v: &Put) -> StepResult<Value> {
        let mut ok = self.ok(cx, &format!("get {}", v.name))?;
        let got = ok["version"].take();
        if got["id"]["writer"] != v.writer.as_str()
            || got["id"]["seq"] != v.seq
            || got["collection"] != NOTES
            || name(got["name"].as_str().unwrap_or_default())? != name(&v.name)?
        {
            return Err(format!(
                "{} reads {} as {got}, not ({}, {})",
                self.node, v.name, v.writer, v.seq
            ));
        }
        Ok(got)
    }

    fn tail(&self) -> String {
        let text = fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        let from = lines.len().saturating_sub(30);
        format!(
            "\n    ── tail of {} ndn-data log ──\n    | {}",
            self.node,
            lines[from..].join("\n    | ")
        )
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = writeln!(self.stdin, "quit");
        let _ = self.stdin.flush();
    }
}

/// A version a host put.
#[derive(Clone, Debug)]
struct Put {
    writer: String,
    seq: u64,
    name: String,
}

/// Whether frontier `at` (`[{writer, seq}]`) includes version `v`.
fn includes(at: &Value, v: &Put) -> bool {
    at.as_array().is_some_and(|a| {
        a.iter().any(|e| {
            e["writer"] == v.writer.as_str() && e["seq"].as_u64().is_some_and(|s| s >= v.seq)
        })
    })
}

/// The KeyLocator `ndn-peek -m` prints for `name` fetched through `node`'s
/// daemon, which validates it (a non-local face) against the trust context
/// before delivering it.
fn key_locator(cx: &mut Cx<'_>, node: &str, name: &str) -> StepResult<String> {
    let sock = cx.w.node(node).sock().display().to_string();
    let op = cx
        .tool("ndn-peek")
        .args(["--face-socket", &sock, "-m", name])
        .timeout(Duration::from_secs(15));
    let out = cx.exec(op);
    if !out.success() {
        return Err(format!(
            "ndn-peek of {name} at {node}: {}: {}",
            out.status_text(),
            out.stderr.trim()
        ));
    }
    out.stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("key:").map(|k| k.trim().to_owned()))
        .ok_or_else(|| format!("ndn-peek -m of {name} shows no KeyLocator: {}", out.stdout))
}

/// `name` fetched through `node`'s daemon gets no Data (a short lifetime:
/// nothing answers across a cut).
fn unanswered(cx: &mut Cx<'_>, node: &str, name: &str) -> StepResult<()> {
    let sock = cx.w.node(node).sock().display().to_string();
    let op = cx
        .tool("ndn-peek")
        .args(["--face-socket", &sock, "--lifetime", "1500", "-m", name])
        .timeout(Duration::from_secs(10));
    let out = cx.exec(op);
    if out.timed_out {
        return Err(format!("ndn-peek of {name} at {node} hung"));
    }
    if out.success() {
        return Err(format!("{name} was delivered at {node} across the cut"));
    }
    Ok(())
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    let group = n("/32=sync");
    let multicast = format!("[[strategy]]\nprefix = \"{group}\"\nstrategy = \"multicast\"\n");
    sc.world.add(
        "laptop",
        1,
        NodeCfg {
            links: vec![link("phone", 2)],
            routes: vec![route(PHONE, "phone"), route(&group, "phone")],
            extra_toml: multicast.clone(),
            ..Default::default()
        },
    );
    sc.world.add(
        "phone",
        2,
        NodeCfg {
            links: vec![link("laptop", 1)],
            routes: vec![route(NS, "laptop"), route(&group, "laptop")],
            extra_toml: multicast,
            ..Default::default()
        },
    );

    let root = sc.step("init the laptop as the root device of /nt", |cx| {
        init_root(cx, "laptop", NS, "laptop")
    })?;
    sc.step("start the laptop's daemon with its CA", |cx| {
        cx.w.node_mut("laptop").cfg.identity = Some(root.identity.clone());
        cx.w.node_mut("laptop").cfg.ca = Some(CaCfg {
            prefix: NS.into(),
            identity: n("/CA"),
            member_days: None,
        });
        cx.start("laptop")
    })?;
    let invites = sc.step("make a member invite at the laptop's CA", |cx| {
        mint(cx, "laptop", NS, &root.fp, 1, Some("1h"))
    })?;
    let phone_cert = sc.step(
        "start the phone's daemon; the phone enrolls as /nt/member/phone over its link",
        |cx| {
            cx.start("phone")?;
            let c = enroll(cx, "phone", &invites[0], "phone", false, None)?;
            if !c.starts_with(&format!("{PHONE}/KEY/")) {
                return Err(format!("unexpected certificate {c}"));
            }
            Ok(c)
        },
    )?;

    let (mut laptop, mut phone) = sc.step(
        "start the data layer on each device (ndn-data on its daemon, signing with its own key)",
        |cx| {
            cx.concept("data layer host (ndn-data)");
            let laptop = Host::start(cx, "laptop", &root.identity)?;
            let phone = Host::start(cx, "phone", PHONE)?;
            let laptop_keys = cx.w.keys("laptop");
            if !laptop
                .writer
                .starts_with(&format!("{}/KEY/", root.identity))
                || !laptop_keys.contains(&laptop.writer)
            {
                return Err(format!(
                    "the laptop writes as {}, not a key of {} in its PIB ({laptop_keys:?})",
                    laptop.writer, root.identity
                ));
            }
            if !phone_cert.starts_with(&format!("{}/", phone.writer)) {
                return Err(format!(
                    "the phone writes as {}, not the key its certificate {phone_cert} certifies",
                    phone.writer
                ));
            }
            if laptop.writer == phone.writer {
                return Err("both devices write with one key".into());
            }
            cx.evidence(&format!("laptop writes as {}", laptop.writer));
            cx.evidence(&format!("phone writes as {}", phone.writer));
            Ok((laptop, phone))
        },
    )?;

    let day1 = sc.step(
        "the laptop shares the note collection (owner-signed members record) and writes text=day 1",
        |cx| {
            laptop.ok(cx, &format!("share {NOTES}"))?;
            laptop.put(cx, "text=\"day 1\"")
        },
    )?;
    sc.step(
        "the phone watches the notes and reads them until it holds day 1",
        |cx| {
            phone.ok(cx, &format!("watch {NOTES}"))?;
            wait_for(cx, "the phone holds day 1", SHORT, |cx| {
                Ok(phone
                    .state(cx)?
                    .is_some_and(|(at, value)| includes(&at, &day1) && value["text"] == "day 1"))
            })?;
            cx.evidence("the phone's state includes day 1, text = \"day 1\"");
            Ok(())
        },
    )?;

    if !crate::works(Command::new("nft").arg("--version")) {
        sc.skip(
            "cut the link (nftables), write on both devices apart, restore it, converge",
            "nft (nftables) not on PATH; run inside `nix-shell -p util-linux iproute2 nftables`",
        );
        return Ok(());
    }
    let cut = sc.step(
        "cut the link: nftables drops UDP between the laptop and the phone",
        |cx| {
            let cut = cut_udp(cx, CUT_TABLE, addr(1), addr(2))?;
            cx.evidence(&format!(
                "dropping UDP between {} (laptop) and {} (phone), both ways",
                addr(1),
                addr(2)
            ));
            Ok(cut)
        },
    )?;
    let (plane, trip, taxi) = sc.step(
        "apart: the laptop writes text=on the plane; the phone writes tags=trip, then text=in \
         the taxi; each holds only its own",
        |cx| {
            let plane = laptop.put(cx, "text=\"on the plane\"")?;
            let trip = phone.put(cx, "tags=trip")?;
            let taxi = phone.put(cx, "text=\"in the taxi\"")?;
            let (at, value) = laptop
                .state(cx)?
                .ok_or("the laptop holds no state of its own notes")?;
            if !includes(&at, &plane) || includes(&at, &trip) || includes(&at, &taxi) {
                return Err(format!("the laptop's state while apart is at {at}"));
            }
            cx.evidence(&format!("laptop apart: at {at}, value {value}"));
            let (at, value) = phone
                .state(cx)?
                .ok_or("the phone holds no state of the notes")?;
            if !includes(&at, &trip) || !includes(&at, &taxi) || includes(&at, &plane) {
                return Err(format!("the phone's state while apart is at {at}"));
            }
            cx.evidence(&format!("phone apart: at {at}, value {value}"));
            // The cut holds: each daemon asks for the other's new entry, which
            // its writer holds and serves, and gets nothing.
            unanswered(cx, "laptop", &trip.name)?;
            unanswered(cx, "phone", &plane.name)?;
            cx.evidence(&format!(
                "neither daemon gets the other's new entry ({}, {})",
                trip.name, plane.name
            ));
            Ok((plane, trip, taxi))
        },
    )?;
    sc.step("restore the link (the nftables table goes)", |cx| {
        drop(cut);
        cx.evidence("UDP between the laptop and the phone flows again");
        Ok(())
    })?;
    sc.step(
        "both devices reach one state holding all four versions, with no step by the person",
        |cx| {
            let all = [&day1, &plane, &trip, &taxi];
            let mut last = (Value::Null, Value::Null);
            wait_for(cx, "laptop and phone at one state", CONVERGE, |cx| {
                let (Some(l), Some(p)) = (laptop.state(cx)?, phone.state(cx)?) else {
                    return Ok(false);
                };
                let done = all.iter().all(|v| includes(&l.0, v)) && l == p;
                last = l;
                Ok(done)
            })?;
            let (at, value) = last;
            let text = value["text"].as_str().unwrap_or_default();
            if value["tags"] != "trip" || !["on the plane", "in the taxi"].contains(&text) {
                return Err(format!(
                    "the merged value {value} lacks tags=trip or one offline text"
                ));
            }
            cx.evidence(&format!("both at {at}"));
            cx.evidence(&format!("both hold {value}"));
            Ok(())
        },
    )?;
    sc.step(
        "each device reads the other's versions by name: right writer and name; the offline \
         versions' parents include day 1 and not each other",
        |cx| {
            // The parents' entry for `writer`, if any.
            let parent = |v: &Value, writer: &str| {
                v["parents"]
                    .as_array()
                    .and_then(|a| a.iter().find(|e| e["writer"] == writer))
                    .and_then(|e| e["seq"].as_u64())
            };
            let read_day1 = phone.version(cx, &day1)?;
            let read_plane = phone.version(cx, &plane)?;
            let read_trip = laptop.version(cx, &trip)?;
            let read_taxi = laptop.version(cx, &taxi)?;
            cx.evidence(&format!("phone reads {}: {read_day1}", day1.name));
            for (label, v) in [
                ("on the plane", &read_plane),
                ("tags=trip", &read_trip),
                ("in the taxi", &read_taxi),
            ] {
                if parent(v, &day1.writer).is_none_or(|s| s < day1.seq) {
                    return Err(format!("{label}'s parents do not include day 1: {v}"));
                }
                cx.evidence(&format!("{label}: parents {}", v["parents"]));
            }
            if parent(&read_plane, &trip.writer).is_some()
                || parent(&read_trip, &plane.writer).is_some_and(|s| s >= plane.seq)
                || parent(&read_taxi, &plane.writer).is_some_and(|s| s >= plane.seq)
            {
                return Err("the offline versions name each other as parents".into());
            }
            if parent(&read_taxi, &trip.writer).is_none_or(|s| s < trip.seq) {
                return Err(format!(
                    "in the taxi's parents do not include tags=trip: {read_taxi}"
                ));
            }
            Ok(())
        },
    )?;
    sc.step("the phone's watch delivered the laptop's versions", |cx| {
        // Draining what arrived since the last answer.
        phone.ok(cx, &format!("get {}", day1.name))?;
        let delivered: Vec<String> = phone
            .watched
            .iter()
            .filter_map(|w| w["change"]["version"]["name"].as_str().map(str::to_owned))
            .collect();
        for v in [&day1, &plane] {
            if !delivered.iter().any(|d| name(d).ok() == name(&v.name).ok()) {
                return Err(format!("{} was not delivered: {delivered:?}", v.name));
            }
        }
        cx.evidence(&format!("watch delivered {delivered:?}"));
        Ok(())
    })?;
    sc.step(
        "each daemon fetches the other device's log entries and validates them: the \
         KeyLocator is the writer device's key",
        |cx| {
            for (node, v, device) in [
                ("laptop", &taxi, PHONE),
                ("laptop", &trip, PHONE),
                ("phone", &plane, root.identity.as_str()),
            ] {
                let key = key_locator(cx, node, &v.name)?;
                if key != v.writer || !key.starts_with(&format!("{device}/KEY/")) {
                    return Err(format!(
                        "{} fetched at {node} is signed by {key}, not {device}'s key {}",
                        v.name, v.writer
                    ));
                }
                cx.evidence(&format!("{node} fetched {}: KeyLocator {key}", v.name));
            }
            Ok(())
        },
    )?;
    Ok(())
}
