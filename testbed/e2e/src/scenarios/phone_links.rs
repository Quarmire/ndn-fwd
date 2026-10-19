//! phone-links: an app hosts links through ndn-boltffi.
//!
//! The phone is the `phone_host` example of ndn-boltffi (ndn-mobile): the
//! FFI an Android or iOS app calls (`NdnEngine`), driven line by line over
//! stdin. Everything else is real daemons.
//!
//! Topology: root (10.200.0.1, root device + CA) ← UDP ← relay (.2, a
//! `node` device listening for QUIC links, holding Interests for sleeping
//! devices and running a wake command); desk (.3, a member) links to the
//! relay over QUIC only and enrolls by invite; the phone binds .4 and later
//! moves to .6.
//!
//! Proves, at the app's API: the app links to its namespace's relay with a
//! key of its own, enrolls by invite over that enrollment link and is then
//! linked in full without doing anything; it reaches the desk and the desk
//! reaches it through the relay, then over a direct path by membership (no
//! peer entry names the desk); a link turned off is closed until the app
//! asks for it; an on-demand link closes idle in the background and links
//! again for an outgoing Interest; a network change moves the links to the
//! new address, the direct path to the desk is made again from there at
//! once (whichever side dialled it), and the desk still reaches the phone;
//! the relay runs its
//! wake command with the app's token for the sleeping phone (and never for
//! the awake one), holds the Interest, and the app answers it once
//! foregrounded.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::thread;
use std::time::{Duration, Instant};

use super::direct_paths::{link_list, quic_faces};
use crate::run::Op;
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{CaCfg, NodeCfg, PeerCfg, QUIC_PORT, addr};

const NS: &str = "/pl";
const WAKE_TOKEN: &str = "70757368746f6b656e"; // "pushtoken"

fn n(s: &str) -> String {
    format!("{NS}{s}")
}

/// `bytes` as phone_host prints fetched content.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The app: `phone_host` with its stdin and its answers.
struct Phone {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    log: std::path::PathBuf,
}

impl Phone {
    fn start(program: &std::path::Path, log: std::path::PathBuf) -> StepResult<Phone> {
        let stderr = fs::File::create(&log).map_err(|e| format!("{}: {e}", log.display()))?;
        let mut child = Command::new(program)
            .env(
                "RUST_LOG",
                std::env::var("NDN_E2E_LOG").unwrap_or_else(|_| "info".into()),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn()
            .map_err(|e| format!("{}: {e}", program.display()))?;
        let stdin = child.stdin.take().ok_or("phone_host: no stdin")?;
        let stdout = child.stdout.take().ok_or("phone_host: no stdout")?;
        let (tx, lines) = channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Phone {
            child,
            stdin,
            lines,
            log,
        })
    }

    /// Run `command`; the lines after `ok`, or why it failed.
    fn call(
        &mut self,
        cx: &mut Cx<'_>,
        command: &str,
        within: Duration,
    ) -> StepResult<Vec<String>> {
        cx.note(&format!("phone> {command}"));
        writeln!(self.stdin, "{command}")
            .and_then(|()| self.stdin.flush())
            .map_err(|e| format!("phone_host: {e}{}", self.tail()))?;
        let deadline = Instant::now() + within;
        let mut answer = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) if line == "." => break,
                Ok(line) => answer.push(line),
                Err(RecvTimeoutError::Timeout) => {
                    return Err(format!(
                        "phone> {command}: no answer within {}s{}",
                        within.as_secs(),
                        self.tail()
                    ));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(format!(
                        "phone> {command}: phone_host exited{}",
                        self.tail()
                    ));
                }
            }
        }
        for l in &answer {
            cx.note(&format!("phone< {l}"));
        }
        match answer.split_first() {
            Some((first, rest)) if first == "ok" => Ok(rest.to_vec()),
            Some((first, _)) => Err(format!("phone> {command}: {first}")),
            None => Err(format!("phone> {command}: empty answer")),
        }
    }

    /// `status`, as lines.
    fn status(&mut self, cx: &mut Cx<'_>) -> StepResult<Vec<String>> {
        self.call(cx, "status", Duration::from_secs(10))
    }

    /// The `status` block of the link called `label` (its indented lines).
    fn link(&mut self, cx: &mut Cx<'_>, label: &str) -> StepResult<Vec<String>> {
        let lines = self.status(cx)?;
        let start = lines
            .iter()
            .position(|l| l == &format!("link {label}"))
            .ok_or_else(|| format!("the phone's status shows no link {label}: {lines:?}"))?;
        Ok(lines[start + 1..]
            .iter()
            .take_while(|l| l.starts_with(' '))
            .map(|l| l.trim().to_owned())
            .collect())
    }

    /// Whether the phone's link to its relay is up (a `path link` line).
    fn relay_linked(&mut self, cx: &mut Cx<'_>) -> StepResult<bool> {
        Ok(self
            .link(cx, "home")?
            .iter()
            .any(|l| l.starts_with("path link")))
    }

    fn tail(&self) -> String {
        let text = fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        let from = lines.len().saturating_sub(30);
        format!(
            "\n    ── tail of phone_host log ──\n    | {}",
            lines[from..].join("\n    | ")
        )
    }
}

impl Drop for Phone {
    fn drop(&mut self) {
        let _ = writeln!(self.stdin, "quit");
        let _ = self.stdin.flush();
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Whether the relay has a link face to an address of `ip`.
fn relay_links_from(cx: &mut Cx<'_>, ip: Ipv4Addr) -> StepResult<bool> {
    Ok(quic_faces(cx, "relay")?.iter().any(|(r, _)| *r.ip() == ip))
}

/// Whether the relay's link list shows a path to an address of `ip`: the
/// connection's address now, which follows a QUIC migration.
fn relay_reaches_at(cx: &mut Cx<'_>, ip: Ipv4Addr) -> StepResult<bool> {
    Ok(link_list(cx, "relay")?.links.iter().any(|l| {
        l.paths
            .iter()
            .any(|p| p.remote.is_some_and(|r| *r.ip() == ip))
    }))
}

/// The wake requests the relay's wake command recorded: `<token> <device>`.
fn wakes(cx: &Cx<'_>) -> Vec<String> {
    fs::read_to_string(cx.w.dir.join("wakes"))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The versioned name RDR metadata announces: its content starts with that
/// Name TLV.
fn metadata_version(content: &[u8]) -> Result<String, String> {
    let bad = || format!("not RDR metadata ({} bytes)", content.len());
    let (len, value) = match content {
        [0x07, 253, hi, lo, rest @ ..] => (usize::from(u16::from_be_bytes([*hi, *lo])), rest),
        [0x07, len, rest @ ..] if *len < 253 => (usize::from(*len), rest),
        _ => return Err(bad()),
    };
    let value = value.get(..len).ok_or_else(bad)?;
    let name =
        ndn_packet::Name::decode(value.to_vec().into()).map_err(|e| format!("{}: {e}", bad()))?;
    Ok(name.to_string())
}

/// Fetch what the app published at `name` (`publish_object`: RDR) through the
/// daemon at `sock`, as an app's `fetch_object` does: `<name>/keyword=metadata`
/// (Interest lifetime `lifetime_ms`) names the version, whose segments
/// ndn-peek then fetches. ndn-peek alone discovers ndn-put's segments by
/// `CanBePrefix`, which an RDR producer does not answer. The answers are
/// written beside `files`.
fn fetch_object(
    peek: &Op,
    sock: &str,
    name: &str,
    lifetime_ms: u32,
    files: &Path,
) -> Result<Vec<u8>, String> {
    let meta = files.with_extension("meta");
    let asked = peek
        .clone()
        .args(["--face-socket", sock, "--can-be-prefix", "--lifetime"])
        .arg(lifetime_ms.to_string())
        .arg("-o")
        .arg(meta.display().to_string())
        .arg(format!("{name}/keyword=metadata"))
        .timeout(Duration::from_secs(30))
        .run();
    if !asked.success() {
        return Err(format!("its metadata: {}", asked.status_text()));
    }
    let version = metadata_version(&fs::read(&meta).unwrap_or_default())?;
    let object = files.with_extension("bin");
    let got = peek
        .clone()
        .args([
            "--face-socket",
            sock,
            "--can-be-prefix",
            "--lifetime",
            "4000",
            "-p",
            "4",
            "-o",
        ])
        .arg(object.display().to_string())
        .arg(format!("{version}/seg=0"))
        .timeout(Duration::from_secs(30))
        .run();
    if !got.success() {
        return Err(format!("{version}: {}", got.status_text()));
    }
    fs::read(&object).map_err(|e| format!("{}: {e}", object.display()))
}

/// Fetch the app's object `name` at `node` until it is delivered, within
/// `within`.
fn fetch_object_within(
    cx: &mut Cx<'_>,
    node: &str,
    name: &str,
    expect: &[u8],
    within: Duration,
) -> StepResult<()> {
    cx.concept("fetch");
    cx.input(format!("Data name ({name})"));
    let peek = cx.tool("ndn-peek");
    let sock = cx.w.node(node).sock().display().to_string();
    let start = Instant::now();
    loop {
        let seq = cx.w.next_seq();
        let files = cx.w.node(node).dir.join(format!("object-{seq}"));
        let why = match fetch_object(&peek, &sock, name, 4000, &files) {
            Ok(got) if got == expect => {
                cx.note(&format!(
                    "{node} fetched {name} after {:.2}s",
                    start.elapsed().as_secs_f64()
                ));
                return Ok(());
            }
            Ok(got) => format!(
                "{} bytes fetched, {} expected (bytes differ)",
                got.len(),
                expect.len()
            ),
            Err(e) => e,
        };
        if start.elapsed() > within {
            return Err(format!(
                "after {}s: fetch of {name} at {node} failed: {why}",
                within.as_secs()
            ));
        }
        thread::sleep(Duration::from_millis(250));
    }
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    let wakes_file = sc.world.dir.join("wakes");
    let base = NodeCfg {
        refresh_secs: 600,
        ..Default::default()
    };
    sc.world.add("root", 1, base.clone());
    sc.world.add(
        "relay",
        2,
        NodeCfg {
            links: vec![link("root", 1)],
            routes: vec![route(NS, "root")],
            quic_listen: true,
            extra_toml: format!(
                "[relay_service]\nhold = true\nwake_command = [\"/bin/sh\", \"-c\", \"echo \\\"$NDN_WAKE_TOKEN \
                 $NDN_WAKE_DEVICE\\\" >> {}\"]\n",
                wakes_file.display()
            ),
            ..base.clone()
        },
    );
    sc.world.add(
        "desk",
        3,
        NodeCfg {
            peers: vec![PeerCfg {
                device: Some(n("/node/relay")),
                endpoint: Some(addr(2)),
                ..Default::default()
            }],
            quic_dial_only: true,
            ..base.clone()
        },
    );

    let root = sc.step("init the root device", |cx| {
        init_root(cx, "root", NS, "home")
    })?;
    let invites = sc.step("mint two member invites (desk, phone)", |cx| {
        mint(cx, NS, &root.fp, 2, Some("2h"))
    })?;
    sc.step("start the root device's daemon with its CA", |cx| {
        cx.w.node_mut("root").cfg.identity = Some(root.identity.clone());
        cx.w.node_mut("root").cfg.ca = Some(CaCfg {
            prefix: NS.into(),
            identity: n("/CA"),
            tokens: invites.iter().map(|i| i.token.clone()).collect(),
            member_days: None,
        });
        cx.start("root")
    })?;
    sc.step(
        "start the relay (listening, holding, waking), adopt, and become a node device on approval",
        |cx| {
            cx.start("relay")?;
            let op = cx
                .tool("ndn-fwd")
                .arg("adopt")
                .arg(&root.link_fp)
                .arg("-c")
                .arg(cx.w.node("relay").cfg_arg());
            cx.ok(op, "adopt")?;
            cx.expect_version("relay", NS, 1)?;
            enroll_by_approval(cx, NS, &root.link_fp, "relay")
        },
    )?;
    let relay_hello = content(1_500, 41);
    sc.step("the relay serves a greeting under its device name", |cx| {
        cx.publish("relay", &n("/node/relay/hello"), &relay_hello, None, None)
    })?;
    sc.step(
        "desk links to the relay over QUIC and enrolls by invite over its enrollment link",
        |cx| {
            cx.start("desk")?;
            wait_for(cx, "the relay links to desk", SHORT, |cx| {
                relay_links_from(cx, addr(3))
            })?;
            enroll(cx, "desk", &invites[0], "desk", false, None)?;
            fetch_within(cx, "desk", &n("/node/relay/hello"), &relay_hello, SHORT)
        },
    )?;
    // One segment, as the relay's greeting: the app gets `<name>/seg=0` by
    // its exact name (the FFI's `get`; ndn-put serves no RDR metadata for
    // the app's `fetch_object`).
    let desk_notes = content(1_500, 42);
    sc.step("desk publishes its notes", |cx| {
        cx.publish("desk", &n("/member/desk/notes"), &desk_notes, None, None)
    })?;

    let program = sc.world.bins.dir.join("examples/phone_host");
    let log = sc.world.dir.join("phone_host.log");
    let mut phone = sc.step("the app starts (phone_host over ndn-boltffi)", |cx| {
        cx.concept("app (ndn-boltffi NdnEngine)");
        Phone::start(&program, log.clone())
    })?;

    sc.step("the app makes a key of its own, starts links on 10.200.0.4 and adds its relay: an enrollment link", |cx| {
        cx.input("app: relay device /pl/node/relay");
        cx.input(format!("app: relay endpoint {}:{QUIC_PORT}", addr(2)));
        phone.call(cx, "generate /e2e/phone-before-enrollment", SHORT)?;
        let key = phone.call(cx, &format!("links {}:0", addr(4)), SHORT)?;
        phone.call(
            cx,
            &format!("relay home {} - {}:{QUIC_PORT} always", n("/node/relay"), addr(2)),
            SHORT,
        )?;
        wait_for(cx, "the relay links to the phone", SHORT, |cx| relay_links_from(cx, addr(4)))?;
        cx.evidence(&format!("the phone links with key {} from {}", key.join(""), addr(4)));
        Ok(())
    })?;
    sc.step(
        "the app enrolls by invite over the enrollment link; the link becomes a full one by itself",
        |cx| {
            cx.input("app: invite link (QR)");
            let cert = phone.call(
                cx,
                &format!("enroll {} phone", invites[1].link),
                Duration::from_secs(60),
            )?;
            cx.evidence(&format!("issued {}", cert.join("")));
            let took = wait_for(cx, "the phone's relay link is a full link", SHORT, |cx| {
                let lines = phone.link(cx, "home")?;
                Ok(lines.iter().any(|l| l.starts_with("relay linked"))
                    && lines.iter().any(|l| l.starts_with("path link")))
            })?;
            cx.evidence(&format!(
                "relay link up as an enrolled member {:.2}s after enrolling",
                took.as_secs_f64()
            ));
            Ok(())
        },
    )?;
    sc.step("the app reaches the desk through the relay", |cx| {
        let start = Instant::now();
        loop {
            match phone.call(cx, &format!("get {}/seg=0", n("/member/desk/notes")), SHORT) {
                Ok(got) if got.concat() == hex(&desk_notes) => break,
                Ok(_) => {
                    return Err("the phone fetched the desk's notes, but the bytes differ".into());
                }
                Err(e) if start.elapsed() > SHORT => return Err(e),
                Err(_) => thread::sleep(Duration::from_millis(500)),
            }
        }
        cx.evidence(&format!("{} bytes from the desk", desk_notes.len()));
        Ok(())
    })?;
    let photo = "a photo taken on the phone";
    sc.step(
        "the desk reaches the app: the app publishes, the desk fetches",
        |cx| {
            phone.call(
                cx,
                &format!("publish {} {photo}", n("/member/phone/photo")),
                SHORT,
            )?;
            fetch_object_within(
                cx,
                "desk",
                &n("/member/phone/photo"),
                photo.as_bytes(),
                SHORT,
            )
        },
    )?;
    sc.step(
        "the app and the desk get a direct path by membership (no peer entry names either)",
        |cx| {
            let took = wait_for(
                cx,
                "a direct path between the phone and the desk",
                Duration::from_secs(45),
                |cx| {
                    let desk_side = link_list(cx, "desk")?.links.iter().any(|l| {
                        l.device.as_deref() == Some(n("/member/phone").as_str())
                            && l.paths.iter().any(|p| p.kind == "direct")
                    });
                    let phone_side = phone
                        .status(cx)?
                        .iter()
                        .any(|l| l.trim().starts_with("path direct"));
                    Ok(desk_side && phone_side)
                },
            )?;
            cx.evidence(&format!("direct path up after {:.2}s", took.as_secs_f64()));
            Ok(())
        },
    )?;
    sc.step(
        "a link turned off closes and stays closed until the app asks for it",
        |cx| {
            cx.input("app: link mode off");
            phone.call(cx, "mode home off", SHORT)?;
            wait_for(cx, "the relay's link to the phone is gone", SHORT, |cx| {
                Ok(!relay_links_from(cx, addr(4))?)
            })?;
            // A link that dialled again by itself would be up within the first
            // backoff (0.5 s) and a dial (0.25 s here, as the connect below
            // shows): 1.5 s covers it twice.
            thread::sleep(Duration::from_millis(1500));
            if relay_links_from(cx, addr(4))? || phone.relay_linked(cx)? {
                return Err("the off link linked again by itself".into());
            }
            phone.call(cx, "connect home", SHORT)?;
            let took = wait_for(cx, "the app's connect links it again", SHORT, |cx| {
                relay_links_from(cx, addr(4))
            })?;
            cx.evidence(&format!(
                "off: closed and stayed closed; linked {:.2}s after the app asked",
                took.as_secs_f64()
            ));
            phone.call(cx, "disconnect home", SHORT)?;
            wait_for(cx, "the app's disconnect closes it", SHORT, |cx| {
                Ok(!relay_links_from(cx, addr(4))?)
            })?;
            Ok(())
        },
    )?;
    sc.step(
        "an on-demand link closes idle in the background and links again for an outgoing Interest",
        |cx| {
            cx.input("app: link mode on-demand (idle 3 s)");
            phone.call(cx, "mode home on-demand:3", SHORT)?;
            wait_for(
                cx,
                "the on-demand link links while the app is active",
                SHORT,
                |cx| relay_links_from(cx, addr(4)),
            )?;
            phone.call(cx, "active false", SHORT)?;
            let idle = wait_for(
                cx,
                "the on-demand link closes idle in the background",
                SHORT,
                |cx| Ok(!relay_links_from(cx, addr(4))?),
            )?;
            // Only the relay serves this name: the Interest needs the relay link.
            let got = phone.call(cx, &format!("get {}/seg=0", n("/node/relay/hello")), SHORT)?;
            if got.concat() != hex(&relay_hello) {
                return Err("the relay's greeting came back different".into());
            }
            if !relay_links_from(cx, addr(4))? {
                return Err(
                    "the fetch succeeded but the relay shows no link from the phone".into(),
                );
            }
            cx.evidence(&format!(
                "closed {:.2}s after going to the background; linked again for the fetch",
                idle.as_secs_f64()
            ));
            if !wakes(cx).is_empty() {
                return Err(format!("the relay woke an awake phone: {:?}", wakes(cx)));
            }
            Ok(())
        },
    )?;
    sc.step("a network change moves the links to the new address", |cx| {
        phone.call(cx, "active true", SHORT)?;
        phone.call(cx, "mode home always", SHORT)?;
        wait_for(cx, "linked again", SHORT, |cx| relay_links_from(cx, addr(4)))?;
        let phone_name = n("/member/phone");
        let desk_direct_at = |cx: &mut Cx<'_>, ip: Ipv4Addr| -> StepResult<bool> {
            Ok(link_list(cx, "desk")?
                .to(&phone_name, None)
                .and_then(|l| l.direct_path())
                .and_then(|p| p.remote)
                .is_some_and(|r| *r.ip() == ip))
        };
        wait_for(cx, "the desk's direct path to the phone", SHORT, |cx| desk_direct_at(cx, addr(4)))?;
        // Direct paths are dialled by the smaller key fingerprint (hex, so
        // the strings order as the keys): a phone with the larger one
        // accepted the path, and a QUIC server cannot migrate.
        let desk = link_list(cx, "desk")?;
        let accepted = desk.to(&phone_name, None).and_then(|l| l.key.clone()) > desk.key;
        let moved_at = Instant::now();
        phone.call(cx, &format!("net {}:0", addr(6)), SHORT)?;
        // The link migrates to the new socket: the relay's link list and
        // its link face (`ndn-ctl face list`) show the phone's new address.
        let took = wait_for(cx, "the relay sees the phone at its new address", SHORT, |cx| {
            Ok(relay_reaches_at(cx, addr(6))? && relay_links_from(cx, addr(6))?)
        })?;
        if relay_links_from(cx, addr(4))? {
            return Err(format!("the relay's face list still shows the phone at {} after the move", addr(4)));
        }
        // The phone punches again from its new address at once, whichever
        // side dialled the old direct path: well within the 8 s idle
        // timeout it took when the phone had accepted it.
        wait_for(cx, "the desk's direct path to the phone at its new address", Duration::from_secs(4), |cx| {
            desk_direct_at(cx, addr(6))
        })?;
        let again = moved_at.elapsed();
        let moved = "taken after the move";
        phone.call(cx, &format!("publish {} {moved}", n("/member/phone/moved")), SHORT)?;
        fetch_object_within(cx, "desk", &n("/member/phone/moved"), moved.as_bytes(), SHORT)?;
        cx.evidence(&format!(
            "the relay links to the phone at {} {:.2}s after the change; the direct path is back at that \
             address {:.2}s after it (the phone had {} the old one); the desk reaches it there",
            addr(6),
            took.as_secs_f64(),
            again.as_secs_f64(),
            if accepted { "accepted" } else { "dialled" },
        ));
        Ok(())
    })?;
    sc.step("the relay wakes the sleeping app with its token, holds the Interest, and the app answers it", |cx| {
        cx.input("app: wake token (platform push token)");
        phone.call(cx, "unrelay home", SHORT)?;
        phone.call(
            cx,
            &format!("relay home {} - {}:{QUIC_PORT} on-demand:2 hold", n("/node/relay"), addr(2)),
            SHORT,
        )?;
        phone.call(cx, &format!("wake home {WAKE_TOKEN}"), SHORT)?;
        wait_for(cx, "linked", SHORT, |cx| relay_links_from(cx, addr(6)))?;
        let late = "answered after waking";
        phone.call(cx, &format!("publish {} {late}", n("/member/phone/late")), SHORT)?;
        phone.call(cx, "active false", SHORT)?;
        wait_for(cx, "the phone sleeps", SHORT, |cx| Ok(!relay_links_from(cx, addr(6))?))?;
        if !wakes(cx).is_empty() {
            return Err(format!("the relay woke the phone while it was awake: {:?}", wakes(cx)));
        }
        // Asked at the relay: only the relay link reaches the phone from
        // there. The metadata Interest is the one held.
        let files = cx.w.node("relay").dir.join("late");
        let sock = cx.w.node("relay").sock().display().to_string();
        let peek = cx.tool("ndn-peek");
        let name = n("/member/phone/late");
        let asker = thread::spawn(move || fetch_object(&peek, &sock, &name, 8000, &files));
        let woke = wait_for(cx, "the relay runs its wake command", SHORT, |cx| Ok(!wakes(cx).is_empty()))?;
        let recorded = wakes(cx);
        let expected = format!("{WAKE_TOKEN} {}", n("/member/phone"));
        if recorded.first().map(|l| l.trim()) != Some(expected.as_str()) {
            return Err(format!("the wake command got {recorded:?}, expected {expected:?}"));
        }
        phone.call(cx, "active true", SHORT)?;
        match asker.join().map_err(|_| "the asking ndn-peek panicked")? {
            Ok(got) if got == late.as_bytes() => {}
            Ok(got) => return Err(format!("the held Interest was answered with {} other bytes", got.len())),
            Err(why) => return Err(format!("the held Interest was not answered: {why}")),
        }
        cx.evidence(&format!(
            "wake command ran {:.2}s after the Interest with `{expected}`; the held Interest was answered after the app woke",
            woke.as_secs_f64()
        ));
        Ok(())
    })?;
    drop(phone);
    Ok(())
}
