//! The data layer on real daemons, as the scenarios drive it: `ndn-data`
//! (ndn-tools) hosting one device's `ndn_data::Device` on its daemon's
//! socket, with the key `ndn-fwd init`/`enroll` put in the PIB, verifying
//! with the PIB's trust contexts, driven line by line over stdin and
//! answering one JSON object per line — standing in for the host an app
//! runs in, not for anything the person does. Beside it, the harness's
//! inspection of what the daemons route and fetch for it.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::run::Proc;
use crate::step::{Cx, StepResult};

/// SVS's periodic interval for the hosts (default 30 s): how soon two
/// devices that were apart notice; performance only.
pub const SYNC_INTERVAL_MS: u64 = 1000;
/// One verb's answer (a `get` may wait out a fetch's lifetime first).
pub const ANSWER: Duration = Duration::from_secs(30);
/// Devices that were apart reaching one state again.
pub const CONVERGE: Duration = Duration::from_secs(60);

pub fn name(s: &str) -> StepResult<ndn_packet::Name> {
    s.parse().map_err(|e| format!("{s:?} is no name: {e:?}"))
}

/// One device's `ndn-data` host: its stdin, its answers, the changes its
/// watches delivered.
pub struct Host {
    pub node: String,
    pub device: String,
    pub writer: String,
    stdin: ChildStdin,
    lines: Receiver<String>,
    pub watched: Vec<Value>,
    log: PathBuf,
}

impl Host {
    /// Start `ndn-data` for `device` on `node`'s daemon; ready once it says
    /// so. The process is the node's producer: stopped with it, its log
    /// shown when a step fails.
    pub fn start(cx: &mut Cx<'_>, node: &str, device: &str) -> StepResult<Host> {
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

    /// The next line within `within`, as JSON; `None` when none came.
    fn line(&mut self, cx: &mut Cx<'_>, what: &str, within: Duration) -> StepResult<Option<Value>> {
        let line = match self.lines.recv_timeout(within) {
            Ok(line) => line,
            Err(RecvTimeoutError::Timeout) => return Ok(None),
            Err(RecvTimeoutError::Disconnected) => {
                return Err(format!(
                    "{}> {what}: ndn-data exited{}",
                    self.node,
                    self.tail()
                ));
            }
        };
        cx.note(&format!("{}< {line}", self.node));
        serde_json::from_str(&line)
            .map(Some)
            .map_err(|e| format!("{}: not one JSON object per line ({e}): {line}", self.node))
    }

    /// The next line that is not a watched change, as JSON.
    fn next(&mut self, cx: &mut Cx<'_>, what: &str, within: Duration) -> StepResult<Value> {
        let deadline = Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let Some(v) = self.line(cx, what, left)? else {
                return Err(format!(
                    "{}> {what}: no answer within {}s{}",
                    self.node,
                    within.as_secs(),
                    self.tail()
                ));
            };
            if v.get("watch").is_some() {
                self.watched.push(v);
            } else {
                return Ok(v);
            }
        }
    }

    /// Wait until a watched change matches `matches`, within `within`: the
    /// first that does (one delivered before counts).
    pub fn watched_until(
        &mut self,
        cx: &mut Cx<'_>,
        what: &str,
        within: Duration,
        matches: impl Fn(&Value) -> bool,
    ) -> StepResult<Value> {
        let deadline = Instant::now() + within;
        let mut seen = 0;
        loop {
            if let Some(w) = self.watched[seen..].iter().find(|w| matches(w)) {
                return Ok(w.clone());
            }
            seen = self.watched.len();
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(format!(
                    "{}: {what}: not delivered within {}s{}",
                    self.node,
                    within.as_secs(),
                    self.tail()
                ));
            }
            match self.line(cx, what, left)? {
                Some(v) if v.get("watch").is_some() => self.watched.push(v),
                Some(v) => return Err(format!("{}: an answer to no verb: {v}", self.node)),
                None => {}
            }
        }
    }

    /// Send one verb line: its `ok` object, or its `error` object.
    pub fn call(&mut self, cx: &mut Cx<'_>, line: &str) -> StepResult<Result<Value, Value>> {
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
    pub fn ok(&mut self, cx: &mut Cx<'_>, line: &str) -> StepResult<Value> {
        self.call(cx, line)?.map_err(|e| {
            format!(
                "{}> {line}: {} (next: {})",
                self.node, e["message"], e["next_step"]
            )
        })
    }

    /// `put` into `collection`: the version, its name checked to be
    /// `<device>/32=log/<collection>/seq=<n>` and its writer this device's
    /// key.
    pub fn put(&mut self, cx: &mut Cx<'_>, collection: &str, fields: &str) -> StepResult<Put> {
        let ok = self.ok(cx, &format!("put {collection} {fields}"))?;
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
        let expected = format!("{}/32=log{collection}/seq={}", self.device, put.seq);
        if name(&put.name)? != name(&expected)? {
            return Err(format!("{} is named {}, not {expected}", fields, put.name));
        }
        cx.evidence(&format!(
            "{} put {fields}: {} (writer {})",
            self.node, put.name, put.writer
        ));
        Ok(put)
    }

    /// `collection`'s merged state here (frontier, value); `None` while no
    /// path answered and nothing is held yet (an error that says retry).
    pub fn state(
        &mut self,
        cx: &mut Cx<'_>,
        collection: &str,
    ) -> StepResult<Option<(Value, Value)>> {
        match self.call(cx, &format!("get {collection}"))? {
            Ok(ok) => Ok(Some((
                ok["state"]["at"].clone(),
                ok["state"]["value"].clone(),
            ))),
            Err(e) if e["retry"] == true => Ok(None),
            Err(e) => Err(format!(
                "{}> get {collection}: {} (next: {})",
                self.node, e["message"], e["next_step"]
            )),
        }
    }

    /// Version `v` of `collection` as this device reads it by its exact
    /// name.
    pub fn version(&mut self, cx: &mut Cx<'_>, collection: &str, v: &Put) -> StepResult<Value> {
        let mut ok = self.ok(cx, &format!("get {}", v.name))?;
        let got = ok["version"].take();
        if got["id"]["writer"] != v.writer.as_str()
            || got["id"]["seq"] != v.seq
            || name(got["collection"].as_str().unwrap_or_default())? != name(collection)?
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
pub struct Put {
    pub writer: String,
    pub seq: u64,
    pub name: String,
}

/// Whether frontier `at` (`[{writer, seq}]`) includes version `v`.
pub fn includes(at: &Value, v: &Put) -> bool {
    at.as_array().is_some_and(|a| {
        a.iter().any(|e| {
            e["writer"] == v.writer.as_str() && e["seq"].as_u64().is_some_and(|s| s >= v.seq)
        })
    })
}

/// The KeyLocator `ndn-peek -m` prints for `name` fetched through `node`'s
/// daemon, which validates it (a non-local face) against the trust context
/// before delivering it.
pub fn key_locator(cx: &mut Cx<'_>, node: &str, name: &str) -> StepResult<String> {
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
pub fn unanswered(cx: &mut Cx<'_>, node: &str, name: &str) -> StepResult<()> {
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

/// The faces `node`'s RIB routes exactly `prefix` to, with each route's
/// origin (harness inspection: `ndn-ctl route rib-list`).
pub fn rib(cx: &mut Cx<'_>, node: &str, prefix: &str) -> StepResult<Vec<(u64, String)>> {
    let want = name(prefix)?;
    let sock = cx.w.node(node).sock().display().to_string();
    let op = cx
        .tool("ndn-ctl")
        .args(["--socket", &sock, "route", "rib-list"]);
    let out = cx.exec(op);
    if !out.success() {
        return Err(format!("route rib-list on {node}: {}", out.status_text()));
    }
    // `<prefix>  <face>  <origin>  <cost>  <flags>[  expiry=…]`
    Ok(out
        .stdout
        .lines()
        .filter_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            match w.as_slice() {
                [p, face, origin, ..] if name(p).ok().as_ref() == Some(&want) => {
                    Some((face.parse().ok()?, (*origin).to_owned()))
                }
                _ => None,
            }
        })
        .collect())
}

/// The strategy `node` runs at exactly `prefix`, if one is set there
/// (harness inspection: `ndn-ctl strategy list`).
pub fn strategy_at(cx: &mut Cx<'_>, node: &str, prefix: &str) -> StepResult<Option<String>> {
    let want = name(prefix)?;
    let sock = cx.w.node(node).sock().display().to_string();
    let op = cx
        .tool("ndn-ctl")
        .args(["--socket", &sock, "strategy", "list"]);
    let out = cx.exec(op);
    if !out.success() {
        return Err(format!("strategy list on {node}: {}", out.status_text()));
    }
    // `<prefix>  <strategy>`
    Ok(out.stdout.lines().find_map(|l| {
        let w: Vec<&str> = l.split_whitespace().collect();
        match w.as_slice() {
            [p, s] if name(p).ok().as_ref() == Some(&want) => Some((*s).to_owned()),
            _ => None,
        }
    }))
}

/// The multicast strategy `node` runs `group` with, if it does.
pub fn multicast_at(cx: &mut Cx<'_>, node: &str, group: &str) -> StepResult<Option<String>> {
    Ok(strategy_at(cx, node, group)?.filter(|s| s.contains("multicast")))
}

/// `node` routes `group` over the face it routes `peer` (the other device's
/// name) to, as the link library installs both for the link to it, and
/// runs `group` with the multicast strategy. The face's routes, as found.
pub fn carries_group(
    cx: &mut Cx<'_>,
    node: &str,
    peer: &str,
    group: &str,
) -> StepResult<Option<String>> {
    let to_peer = rib(cx, node, peer)?;
    let routed = rib(cx, node, group)?;
    let linked = to_peer
        .iter()
        .find(|(face, origin)| routed.contains(&(*face, origin.clone())));
    let strategy = multicast_at(cx, node, group)?;
    Ok(match (linked, strategy) {
        (Some((face, origin)), Some(s)) => Some(format!(
            "{node}: {peer} and {group} → face {face} ({origin}); {group} runs {s}"
        )),
        _ => None,
    })
}
