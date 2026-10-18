//! Steps, their outcome, and the touchpoints (human inputs and concepts)
//! each one needed — derived from the commands a step runs and the config
//! settings it starts daemons with, never written by hand.

use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::run::{Op, Out, tail};
use crate::world::World;

pub type StepResult<T> = Result<T, String>;

/// The inputs that are secrets a person must keep and type.
pub const SECRET_INPUTS: &[&str] = &["root passphrase", "kit passphrase", "24 recovery words"];

/// A failed step ends its scenario (later steps depend on it).
#[derive(Debug)]
pub struct Abort;

#[derive(Clone, Debug)]
pub enum Status {
    Pass,
    Fail(String),
    Skip(String),
}

#[derive(Clone, Debug)]
pub struct StepRecord {
    pub name: String,
    pub status: Status,
    pub dur: Duration,
    pub inputs: Vec<String>,
    pub concepts: Vec<String>,
}

pub struct Scenario {
    pub name: &'static str,
    pub world: World,
    pub steps: Vec<StepRecord>,
}

impl Scenario {
    pub fn new(name: &'static str, world: World) -> Self {
        Scenario {
            name,
            world,
            steps: Vec::new(),
        }
    }

    pub fn step<T>(
        &mut self,
        name: &str,
        f: impl FnOnce(&mut Cx<'_>) -> StepResult<T>,
    ) -> Result<T, Abort> {
        let start = Instant::now();
        let mut cx = Cx {
            w: &mut self.world,
            inputs: Vec::new(),
            concepts: Vec::new(),
            transcript: String::new(),
        };
        let r = f(&mut cx);
        let (inputs, concepts, transcript) = (cx.inputs, cx.concepts, cx.transcript);
        let dur = start.elapsed();
        let n = self.steps.len() + 1;
        match r {
            Ok(v) => {
                println!(
                    "[{}] PASS {:>7.2}s  {n:>2}. {name}",
                    self.name,
                    dur.as_secs_f64()
                );
                self.steps.push(StepRecord {
                    name: name.to_owned(),
                    status: Status::Pass,
                    dur,
                    inputs,
                    concepts,
                });
                Ok(v)
            }
            Err(e) => {
                println!(
                    "[{}] FAIL {:>7.2}s  {n:>2}. {name}\n    reason: {e}",
                    self.name,
                    dur.as_secs_f64()
                );
                println!("    ── commands of this step ──");
                for l in transcript.lines() {
                    println!("    | {l}");
                }
                for (label, path) in self.world.logs() {
                    println!("    ── tail of {label} log ({}) ──", path.display());
                    for l in tail(&path, 30).lines() {
                        println!("    | {l}");
                    }
                }
                self.steps.push(StepRecord {
                    name: name.to_owned(),
                    status: Status::Fail(e),
                    dur,
                    inputs,
                    concepts,
                });
                Err(Abort)
            }
        }
    }

    pub fn skip(&mut self, name: &str, reason: &str) {
        let n = self.steps.len() + 1;
        println!("[{}] SKIP           {n:>2}. {name}\n    reason: {reason}", self.name);
        self.steps.push(StepRecord {
            name: name.to_owned(),
            status: Status::Skip(reason.to_owned()),
            dur: Duration::ZERO,
            inputs: Vec::new(),
            concepts: Vec::new(),
        });
    }

    pub fn passed(&self) -> bool {
        !self.steps.iter().any(|s| matches!(s.status, Status::Fail(_)))
    }

    pub fn to_json(&self, total: Duration, aborted: bool) -> Value {
        let steps: Vec<Value> = self
            .steps
            .iter()
            .map(|s| {
                let (status, reason) = match &s.status {
                    Status::Pass => ("PASS", None),
                    Status::Fail(r) => ("FAIL", Some(r.clone())),
                    Status::Skip(r) => ("SKIP", Some(r.clone())),
                };
                json!({
                    "step": s.name,
                    "status": status,
                    "reason": reason,
                    "duration_ms": s.dur.as_millis() as u64,
                    "human_inputs": s.inputs,
                    "concepts": s.concepts,
                })
            })
            .collect();
        json!({
            "scenario": self.name,
            "passed": self.passed() && !aborted,
            "aborted": aborted,
            "duration_ms": total.as_millis() as u64,
            "steps": steps,
        })
    }
}

/// What a step body works with.
pub struct Cx<'a> {
    pub w: &'a mut World,
    inputs: Vec<String>,
    concepts: Vec<String>,
    transcript: String,
}

fn push_unique(v: &mut Vec<String>, s: String) {
    if !v.contains(&s) {
        v.push(s);
    }
}

impl Cx<'_> {
    /// A tool invocation; `.run()` it through [`Cx::op`] or [`Cx::exec`].
    pub fn tool(&self, tool: &str) -> Op {
        self.w.bins.op(tool)
    }

    pub fn input(&mut self, s: impl Into<String>) {
        push_unique(&mut self.inputs, s.into());
    }

    pub fn concept(&mut self, s: impl Into<String>) {
        push_unique(&mut self.concepts, s.into());
    }

    fn touch(&mut self, op: &Op) {
        let (i, c) = classify(op);
        for s in i {
            self.input(s);
        }
        for s in c {
            self.concept(s);
        }
    }

    /// An operator's command: its inputs are recorded as touchpoints.
    pub fn op(&mut self, op: Op) -> Out {
        self.touch(&op);
        self.exec(op)
    }

    /// A harness-internal command (inspection), not an operator input.
    pub fn exec(&mut self, op: Op) -> Out {
        let out = op.run();
        self.transcript
            .push_str(&format!("$ {}\n  -> {}\n", op.display(), out.status_text()));
        for l in out.stdout.lines().chain(out.stderr.lines()) {
            self.transcript.push_str(&format!("  {l}\n"));
        }
        out
    }

    pub fn note(&mut self, s: &str) {
        self.transcript.push_str(&format!("# {s}\n"));
    }

    pub fn ok(&mut self, op: Op, what: &str) -> StepResult<Out> {
        let out = self.op(op);
        if out.success() {
            Ok(out)
        } else {
            Err(format!("{what}: expected success, got {}", out.status_text()))
        }
    }

    /// The command must end with a failure status (not hang).
    pub fn refused(&mut self, op: Op, what: &str) -> StepResult<Out> {
        let out = self.op(op);
        if out.timed_out {
            Err(format!("{what}: expected a refusal, but it hung ({})", out.status_text()))
        } else if out.success() {
            Err(format!("{what}: expected a refusal, but it succeeded"))
        } else {
            Ok(out)
        }
    }

    /// Start a node's daemon; the config settings that changed since its last
    /// start are the operator's inputs.
    pub fn start(&mut self, node: &str) -> StepResult<()> {
        let settings = self.w.node(node).settings();
        let last = self.w.node(node).last_settings.clone();
        for s in &settings {
            if !last.contains(s) {
                self.input(format!("{node} {s}"));
            }
        }
        self.concept("daemon (ndn-fwd)");
        self.w.start(node)?;
        self.w.node_mut(node).last_settings = settings;
        Ok(())
    }

    pub fn stop(&mut self, node: &str) {
        self.w.stop(node);
    }

    pub fn version(&self, node: &str, ns: &str) -> Option<u64> {
        self.w.held_version(node, ns)
    }

    pub fn expect_version(&self, node: &str, ns: &str, want: u64) -> StepResult<()> {
        match self.version(node, ns) {
            Some(v) if v == want => Ok(()),
            other => Err(format!("{node}: holds {ns} at {other:?}, expected v{want}")),
        }
    }

    /// Wait until `node` holds `ns` at `want` or newer; the time it took.
    pub fn wait_version(
        &mut self,
        node: &str,
        ns: &str,
        want: u64,
        within: Duration,
    ) -> StepResult<Duration> {
        let start = Instant::now();
        loop {
            if self.version(node, ns).is_some_and(|v| v >= want) {
                let took = start.elapsed();
                self.note(&format!("{node} holds {ns} v{want} after {:.2}s", took.as_secs_f64()));
                return Ok(took);
            }
            if start.elapsed() > within {
                return Err(format!(
                    "{node}: still holds {ns} at {:?} after {}s, expected v{want}",
                    self.version(node, ns),
                    within.as_secs()
                ));
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn certs(&self, node: &str) -> Vec<String> {
        self.w.certs(node)
    }

    /// Start `ndn-put` on `node`'s daemon serving `content` under `name`,
    /// signed by `identity` from `pib` (default: the node's PIB and its
    /// default identity). Ready once a local fetch returns it.
    pub fn publish(
        &mut self,
        node: &str,
        name: &str,
        content: &[u8],
        pib: Option<PathBuf>,
        identity: Option<&str>,
    ) -> StepResult<()> {
        let seq = self.w.next_seq();
        let (dir, sock, node_pib) = {
            let n = self.w.node(node);
            (n.dir.clone(), n.sock(), n.pib())
        };
        let file = dir.join(format!("pub-{seq}.bin"));
        fs::write(&file, content).map_err(|e| e.to_string())?;
        let mut op = self
            .tool("ndn-put")
            .arg("--face-socket")
            .arg(sock.display().to_string())
            .arg("--pib")
            .arg(pib.unwrap_or(node_pib).display().to_string());
        if let Some(id) = identity {
            op = op.arg("--identity").arg(id);
        }
        let op = op.arg(name).arg(file.display().to_string());
        self.touch(&op);
        self.transcript.push_str(&format!("$ {} &\n", op.display()));
        let log = dir.join(format!("put-{seq}.log"));
        let mut proc = op.spawn_logged(&log, &format!("put-{seq}"))?;
        // A local fetch is answered within milliseconds once ndn-put has
        // registered; before that the probe goes upstream and waits out its
        // lifetime (plus ndn-peek's 500 ms grace), so keep it short.
        let probe = self
            .tool("ndn-peek")
            .arg("--face-socket")
            .arg(sock.display().to_string())
            .arg("--can-be-prefix")
            .arg("--lifetime")
            .arg("100")
            .arg(name)
            .timeout(Duration::from_secs(5));
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if !proc.alive() {
                return Err(format!(
                    "ndn-put for {name} exited early:\n{}",
                    tail(&log, 20)
                ));
            }
            if probe.run().success() {
                break;
            }
            if Instant::now() > deadline {
                return Err(format!("{name}: not served on {node} within 15 s"));
            }
            thread::sleep(Duration::from_millis(100));
        }
        self.w.producers.push((node.to_owned(), proc));
        Ok(())
    }

    fn peek(&self, node: &str, name: &str, out: &Path, segmented: bool, lifetime_ms: u32) -> Op {
        let sock = self.w.node(node).sock();
        let mut op = self
            .tool("ndn-peek")
            .arg("--face-socket")
            .arg(sock.display().to_string())
            .arg("--can-be-prefix")
            .arg("--lifetime")
            .arg(lifetime_ms.to_string());
        if segmented {
            op = op.arg("-p").arg("4");
        }
        op.arg("-o")
            .arg(out.display().to_string())
            .arg(name)
            .timeout(Duration::from_secs(30))
    }

    /// Fetch `name` through `node`'s daemon: the bytes must equal `expect`.
    pub fn fetch_ok(&mut self, node: &str, name: &str, expect: &[u8]) -> StepResult<()> {
        let seq = self.w.next_seq();
        let file = self.w.node(node).dir.join(format!("fetch-{seq}.bin"));
        let op = self.peek(node, name, &file, true, 4000);
        let out = self.op(op);
        let got = fs::read(&file).unwrap_or_default();
        if out.success() && got == expect {
            return Ok(());
        }
        Err(format!(
            "fetch of {name} at {node} failed: {}; {} bytes fetched, {} expected{}",
            out.status_text(),
            got.len(),
            expect.len(),
            if got.is_empty() || got == expect { "" } else { " (bytes differ)" }
        ))
    }

    /// Fetch `name` through `node`'s daemon: the daemon must refuse the
    /// answering Data for `reason` — `ndn-peek` exits 3 with
    /// `refused: <reason>` (the forwarder's local refusal Nack), well
    /// before the Interest lifetime; nothing is written.
    pub fn fetch_refused(&mut self, node: &str, name: &str, reason: &str) -> StepResult<()> {
        const EXIT_REFUSED: i32 = 3;
        let seq = self.w.next_seq();
        let file = self.w.node(node).dir.join(format!("fetch-{seq}.bin"));
        let op = self
            .peek(node, name, &file, false, 3000)
            .timeout(Duration::from_secs(10));
        let out = self.op(op);
        if out.timed_out {
            return Err(format!("ndn-peek of {name} hung"));
        }
        if out.success() || file.exists() {
            return Err(format!(
                "{name} was delivered at {node} ({}), expected it refused",
                out.status_text()
            ));
        }
        let token = format!("refused: {reason}");
        if out.code != Some(EXIT_REFUSED) || !out.stderr.lines().any(|l| l.trim() == token) {
            return Err(format!(
                "{name} at {node}: expected `{token}` (exit {EXIT_REFUSED}), got {}: {}",
                out.status_text(),
                out.stderr.trim()
            ));
        }
        Ok(())
    }
}

/// Flags that take a value, across the tools.
const VALUE_FLAGS: &[&str] = &[
    "-c", "--config", "--pib", "--namespace", "--device", "--root-store", "--old-root",
    "--format", "--out", "--kit", "--keep-kit", "--anchor-fp", "--role", "--ttl", "--ca",
    "--count", "--identity", "--face-socket", "--lifetime", "-p", "-o", "--socket", "--face",
    "--words-file", "--kit-passphrase-file", "--passphrase-file", "--chunk-size",
    "--freshness", "--timeout", "--bytes", "--reason",
];

/// Human inputs and concepts of one command, from its tool, subcommand,
/// flags, positional arguments and secret environment.
pub fn classify(op: &Op) -> (Vec<String>, Vec<String>) {
    let mut inputs = Vec::new();
    let mut concepts = Vec::new();
    let add = push_unique;

    for (k, _) in &op.env {
        match k.as_str() {
            "NDN_ROOT_PASSPHRASE" => {
                add(&mut inputs, "root passphrase".into());
                add(&mut concepts, "root store (sealed-file)".into());
            }
            "NDN_KIT_PASSPHRASE" => {
                add(&mut inputs, "kit passphrase".into());
                add(&mut concepts, "recovery kit (file)".into());
            }
            "NDN_KIT_WORDS" => {
                add(&mut inputs, "24 recovery words".into());
                add(&mut concepts, "recovery kit (words)".into());
            }
            _ => {}
        }
    }
    if op.foreign_user {
        add(&mut concepts, "another local user (not the daemon's user or groups)".into());
    }

    let mut positionals = Vec::new();
    let mut flags: Vec<(String, Option<String>)> = Vec::new();
    let mut it = op.args.iter();
    while let Some(a) = it.next() {
        if a.starts_with('-') && a.len() > 1 {
            if VALUE_FLAGS.contains(&a.as_str()) {
                flags.push((a.clone(), it.next().cloned()));
            } else {
                flags.push((a.clone(), None));
            }
        } else {
            positionals.push(a.clone());
        }
    }

    let sub: Vec<&str> = positionals.iter().map(String::as_str).collect();
    let mut targets_from = 0;
    match (op.tool.as_str(), sub.first().copied()) {
        ("ndn-fwd", Some("init")) => {
            for c in ["namespace", "root device", "root store"] {
                add(&mut concepts, c.into());
            }
            targets_from = 1;
        }
        ("ndn-fwd", Some("adopt")) => {
            add(&mut concepts, "adopt a namespace (trust context)".into());
            targets_from = 1;
        }
        ("ndn-fwd", Some("enroll")) => {
            add(&mut concepts, "enroll".into());
            if flags.iter().any(|(f, _)| f == "--status") {
                add(&mut concepts, "enrollment request status".into());
            }
            targets_from = 1;
        }
        ("ndn-fwd", Some("approvals")) => {
            let verb = sub.get(1).copied().unwrap_or("");
            add(&mut concepts, format!("admin's approval ({verb})"));
            if let Some(t) = sub.get(2) {
                let digits: String = t.chars().filter(|c| !matches!(c, ' ' | '-')).collect();
                if digits.len() == 6 && digits.bytes().all(|b| b.is_ascii_digit()) {
                    add(
                        &mut inputs,
                        "verification code (compared with the requesting device's)".into(),
                    );
                } else {
                    add(&mut inputs, format!("request id ({t})"));
                }
            }
            targets_from = usize::MAX;
        }
        ("ndn-fwd", Some("schema")) => {
            let verb = sub.get(1).copied().unwrap_or("");
            add(&mut concepts, format!("trust schema ({verb})"));
            if verb == "update" {
                add(&mut concepts, "trust context version".into());
            }
            targets_from = usize::MAX;
        }
        ("ndn-fwd", Some("revoke")) => {
            add(&mut concepts, "revoke".into());
            add(&mut concepts, "trust context version".into());
            if let Some(t) = sub.get(1) {
                add(&mut inputs, format!("device identity to revoke ({t})"));
            }
            targets_from = usize::MAX;
        }
        ("ndn-fwd", Some("renew")) => {
            add(&mut concepts, "certificate renewal".into());
        }
        ("ndn-fwd", Some("context")) => {
            add(&mut concepts, "trust context version (refresh)".into());
            targets_from = usize::MAX;
        }
        ("ndn-fwd", Some("recovery-kit")) => {
            let verb = sub.get(1).copied().unwrap_or("");
            add(&mut concepts, format!("recovery kit ({verb})"));
            match (verb, sub.get(2)) {
                ("revoke", Some(k)) => add(&mut inputs, format!("recovery key name ({k})")),
                ("check", Some(k)) if *k != "words" => add(&mut inputs, "kit file".into()),
                _ => {}
            }
            targets_from = usize::MAX;
        }
        ("ndn-fwd", Some("recover")) => {
            add(&mut concepts, "recovery".into());
            add(&mut concepts, "root device".into());
        }
        ("ndn-fwd-tokens", _) => {
            add(&mut concepts, "invite".into());
        }
        ("ndn-put", _) => {
            add(&mut concepts, "publish signed Data".into());
            if let Some(n) = sub.first() {
                add(&mut inputs, format!("Data name ({n})"));
            }
            add(&mut inputs, "file to publish".into());
            targets_from = usize::MAX;
        }
        ("ndn-peek", _) => {
            add(&mut concepts, "fetch".into());
            if let Some(n) = sub.first() {
                add(&mut inputs, format!("Data name ({n})"));
            }
            targets_from = usize::MAX;
        }
        ("ndn-ctl", _) => {
            add(&mut concepts, "management command".into());
            add(&mut inputs, format!("command ({})", sub.join(" ")));
            targets_from = usize::MAX;
        }
        _ => {}
    }
    for p in positionals.iter().skip(targets_from) {
        if p.starts_with("ndn-trust://invite/") {
            add(&mut inputs, "invite link".into());
        } else if p.starts_with("ndn-trust://anchor/") {
            if p.len() < 400 {
                add(&mut inputs, "anchor link (namespace + expected fingerprint)".into());
            } else {
                add(&mut inputs, "anchor link (inline trust context)".into());
            }
        }
    }
    for (f, v) in &flags {
        let v = v.clone().unwrap_or_default();
        match f.as_str() {
            "--namespace" => add(&mut inputs, format!("namespace name ({v})")),
            "--device" => add(&mut inputs, format!("device name ({v})")),
            "--root-store" => add(&mut inputs, format!("root store choice ({v})")),
            "--old-root" => add(
                &mut inputs,
                format!("--old-root destroyed|compromised choice ({v})"),
            ),
            "--format" => add(&mut inputs, format!("kit format choice ({v})")),
            "--out" => add(&mut inputs, "kit file location".into()),
            "--kit" if v != "words" => add(&mut inputs, "kit file".into()),
            "--keep-kit" => add(&mut inputs, format!("kit to keep ({v})")),
            "--anchor-fp" => add(
                &mut inputs,
                "expected fingerprint (anchor_fp from init/recover)".into(),
            ),
            "--role" if op.tool == "ndn-fwd" => add(&mut inputs, format!("requested role ({v})")),
            "--role" => add(&mut inputs, format!("invite role ({v})")),
            "--reason" => add(&mut inputs, "reason for the denial".into()),
            "--accept-narrowing" => add(
                &mut inputs,
                "--accept-narrowing (a schema that allows less)".into(),
            ),
            "--ttl" => add(&mut inputs, format!("invite lifetime ({v})")),
            "--identity" if op.tool == "ndn-put" => {
                add(&mut inputs, format!("signing identity ({v})"))
            }
            "--from-held" => add(
                &mut inputs,
                "--from-held (vouch that no newer version exists)".into(),
            ),
            "--force" => add(&mut inputs, "--force (enroll another key)".into()),
            _ => {}
        }
    }
    (inputs, concepts)
}
