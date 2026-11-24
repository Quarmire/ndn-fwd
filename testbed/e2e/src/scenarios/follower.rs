//! follower: a repo carries a space for its owner; the owner goes away and a
//! new reader gets the space from the repo — `ndn-repo follow` (a carrier,
//! `ndn_heap::Node::follow`) on real daemons, the heap-level case h10 of the
//! conformance suite over real processes.
//!
//! Topology and gestures as in [`super::shared`]: ann (/oa) and bob (/ob),
//! each the root device of their namespace and pointing at each other,
//! linked through an open community relay (/or) their trust contexts
//! advertise; no config holds a route, a UDP link, a `[[peer]]` or a
//! `[[relay]]`. A fourth daemon, the repo's (10.200.0.4), is the root device of
//! its operator's namespace (/op), which advertises the same relay, so it
//! links to it by itself; its operator adopts ann's trust context (`ndn-fwd
//! adopt`: a follower verifies what it stores, and with no context of the
//! owner holds every entry pending) and bob adopts the operator's, as a person
//! does who chooses to read through that repo.
//!
//! The gestures: the operator starts `ndn-repo follow --device
//! /op/admin/repo --space /oa/32=data/guide` on the repo's daemon (the space
//! need not exist yet). Ann's device creates the space public (`readers=anyone`:
//! a carrier reads nothing sealed, and a reader asking a carrier for a key that
//! only an owner device grants gets none) and writes its title and a
//! chapter. The repo logs what it carries.
//!
//! Proves: once the repo holds the space's three entries (its creation and the
//! two writes) ann goes away: her host and her daemon stop, and bob's daemon
//! gets none of her entries by name. A new host on bob's device, with an empty
//! store, opens the space (naming the repo's device as a holder, `--holder`: a
//! reader asks only the members it heard and the holders its person names) and
//! reads the title and the chapter as ann wrote them (right ids, right text,
//! ann's person as owner and writer), the only holder the repo.

use std::fs;
use std::io::{BufRead, BufReader};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

use super::data_host::{CONVERGE, Host, name, quic_face_to, rib, unanswered};
use super::direct_paths::link_list;
use super::shared::{FAST_LINKS, NO_DIRECT, People, RELAY, adopt_offline, people_through_relay};
use crate::run::Proc;
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{NodeCfg, QUIC_PORT, addr};

const NAMESPACES: People = People {
    a: "/oa",
    b: "/ob",
    relay: "/or",
};
/// The repo's operator: its namespace, device and host address.
const OPERATOR: &str = "/op";
const REPO_DEVICE: &str = "/op/admin/repo";
const REPO: u8 = 4;
/// Ann's public space and its two paths.
const SPACE: &str = "/oa/32=data/guide";
const TITLE: &str = "title";
const CHAPTER: &str = "chapter/1";
/// The entries of the space: its creation and the two writes.
const ENTRIES: u64 = 3;
/// How long the repo may take to hold them (its report comes every 10 s).
const CARRIED: Duration = Duration::from_secs(90);

/// `ndn-repo follow` on a node's daemon: its stdin (held open: the carrier
/// stops at its end) and its log.
struct Carrier {
    _stdin: ChildStdin,
    log: std::path::PathBuf,
}

impl Carrier {
    /// Start `ndn-repo follow --device <device>` for `space` on `node`'s
    /// daemon; ready once it prints its `ready` line. The node's producer:
    /// stopped with it, its log shown when a step fails.
    fn start(cx: &mut Cx<'_>, node: &str, device: &str, space: &str) -> StepResult<Carrier> {
        let (sock, pib, dir) = {
            let n = cx.w.node(node);
            (n.sock(), n.pib(), n.dir.clone())
        };
        let store = dir.join("follow-store");
        let log = dir.join("ndn-repo.log");
        let program = cx.w.bins.dir.join("ndn-repo");
        let args = [
            "follow".to_owned(),
            "--device".to_owned(),
            device.to_owned(),
            "--pib".to_owned(),
            pib.display().to_string(),
            "--socket".to_owned(),
            sock.display().to_string(),
            "--store".to_owned(),
            store.display().to_string(),
            "--space".to_owned(),
            space.to_owned(),
            "--sync-interval-ms".to_owned(),
            super::data_host::SYNC_INTERVAL_MS.to_string(),
        ];
        cx.note(&format!("$ ndn-repo {} &", args.join(" ")));
        let stderr = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .map_err(|e| format!("{}: {e}", log.display()))?;
        let mut child = Command::new(&program)
            .args(&args)
            .env(
                "RUST_LOG",
                std::env::var("NDN_E2E_LOG").unwrap_or_else(|_| "info".into()),
            )
            .env("NO_COLOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn()
            .map_err(|e| format!("{}: {e}", program.display()))?;
        let stdin = child.stdin.take().ok_or("ndn-repo: no stdin")?;
        let stdout = child.stdout.take().ok_or("ndn-repo: no stdout")?;
        let (tx, ready) = channel();
        thread::spawn(move || {
            if let Some(Ok(line)) = BufReader::new(stdout).lines().next() {
                let _ = tx.send(line);
            }
        });
        cx.w.producers.push((
            node.to_owned(),
            Proc {
                child,
                label: "ndn-repo".into(),
                log: log.clone(),
            },
        ));
        let carrier = Carrier { _stdin: stdin, log };
        let line = ready.recv_timeout(Duration::from_secs(20)).map_err(|_| {
            format!(
                "{node}: ndn-repo follow printed no ready line{}",
                carrier.tail()
            )
        })?;
        let ready: serde_json::Value =
            serde_json::from_str(&line).map_err(|e| format!("{node}: {line}: {e}"))?;
        if ready["ready"]["device"] != device {
            return Err(format!(
                "{node}: ndn-repo follow did not start as {device}: {line}"
            ));
        }
        cx.note(&format!("{node}< {line}"));
        Ok(carrier)
    }

    /// What the carrier's last periodic report says it holds of the space.
    fn held(&self) -> u64 {
        fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .rev()
            .filter(|l| l.contains("carrying"))
            .find_map(|l| {
                let (_, rest) = l.split_once("held=")?;
                rest.split(|c: char| !c.is_ascii_digit())
                    .next()?
                    .parse()
                    .ok()
            })
            .unwrap_or(0)
    }

    fn tail(&self) -> String {
        let text = fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        let from = lines.len().saturating_sub(30);
        format!(
            "\n    ── tail of the ndn-repo log ──\n    | {}",
            lines[from..].join("\n    | ")
        )
    }
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    let (ann_root, bob_root) = people_through_relay(sc, NAMESPACES)?;
    sc.world.add(
        "repo",
        REPO,
        NodeCfg {
            quic_dial_only: true,
            ..Default::default()
        },
    );

    let repo_root = sc.step(
        "the repo's operator makes /op (init, advertising the relay) and adopts ann's trust \
         context, the owner's; its daemon links to the relay by itself",
        |cx| {
            cx.concept("a follower's operator holds the owner's trust context");
            let relay_key = link_list(cx, "relay")?
                .key
                .ok_or_else(|| "the relay's link list shows no key".to_owned())?;
            cx.w.node_mut("repo").cfg.extra_toml = format!(
                "[ca]\nprefix = \"{OPERATOR}\"\n\n[[ca.relay]]\ndevice = \"{}/admin/relay\"\nkey \
                 = \"{relay_key}\"\nendpoint = \"{}:{QUIC_PORT}\"\n",
                NAMESPACES.relay,
                addr(RELAY)
            );
            let (root, _) = init_root_with(cx, "repo", OPERATOR, "repo", true)?;
            if root.identity != REPO_DEVICE {
                return Err(format!(
                    "the repo is {}, expected {REPO_DEVICE}",
                    root.identity
                ));
            }
            let n = cx.w.node_mut("repo");
            n.cfg.identity = Some(root.identity.clone());
            n.cfg.extra_toml = format!("{NO_DIRECT}\n{FAST_LINKS}");
            adopt_offline(cx, "repo", NAMESPACES.a, &ann_root.link_inline)?;
            cx.start("repo")?;
            wait_for(cx, "the repo links to the relay", SHORT, |cx| {
                Ok(quic_face_to(cx, "relay", REPO)?.is_some())
            })?;
            cx.evidence(&format!(
                "the repo holds {OPERATOR} and {}; its daemon is linked to the relay",
                NAMESPACES.a
            ));
            Ok(root)
        },
    )?;
    sc.step(
        "bob adopts the operator's trust context (he reads through that repo): his daemon \
         routes the repo's device over the relay link",
        |cx| {
            let op = cx
                .tool("ndn-fwd")
                .arg("adopt")
                .arg(&repo_root.link_inline)
                .arg("-c")
                .arg(cx.w.node("bob").cfg_arg());
            cx.ok(op, "adopt")?;
            cx.expect_version("bob", OPERATOR, 1)?;
            wait_for(cx, "bob routes the repo over the relay link", SHORT, |cx| {
                let Some(face) = quic_face_to(cx, "bob", RELAY)? else {
                    return Ok(false);
                };
                Ok(rib(cx, "bob", OPERATOR)?.iter().any(|(f, _)| *f == face))
            })?;
            Ok(())
        },
    )?;

    let ann_store = sc.world.node("alice").dir.join("data-store");
    let mut ann = sc.step(
        "start ann's data layer (her entries kept in a store directory) and, on the repo, the \
         operator's `ndn-repo follow --space /oa/32=data/guide`",
        |cx| {
            cx.concept("data layer host (ndn-heap)");
            let ann = Host::start_with(
                cx,
                "alice",
                &ann_root.identity,
                &["--store".to_owned(), ann_store.display().to_string()],
            )?;
            cx.evidence(&format!("ann writes as {}", ann.writer));
            Ok(ann)
        },
    )?;
    let carrier = sc.step(
        "the operator starts `ndn-repo follow` on the repo's daemon: it carries the space, \
         verifying with the owner's context it holds",
        |cx| {
            let carrier = Carrier::start(cx, "repo", REPO_DEVICE, SPACE)?;
            cx.evidence(&format!("repo: carrying {SPACE} as {REPO_DEVICE}"));
            Ok(carrier)
        },
    )?;

    let (title, chapter) = sc.step(
        "ann creates the space public and writes its title and a chapter; the repo carries \
         the three entries",
        |cx| {
            ann.ok(cx, &format!("create {SPACE} readers=anyone"))?;
            let title = ann.put(cx, SPACE, TITLE, "A guide to the coast")?;
            let chapter = ann.put(cx, SPACE, CHAPTER, "Start at the harbour.")?;
            wait_for(
                cx,
                &format!("the repo holds the space's {ENTRIES} entries"),
                CARRIED,
                |_| Ok(carrier.held() >= ENTRIES),
            )
            .map_err(|e| format!("{e}{}", carrier.tail()))?;
            cx.evidence(&format!(
                "ann put {} and {}; the repo holds {} entries of {SPACE}",
                title.name,
                chapter.name,
                carrier.held()
            ));
            Ok((title, chapter))
        },
    )?;

    sc.step(
        "ann goes away: her host and her daemon stop; bob's daemon gets none of her entries",
        |cx| {
            cx.stop("alice");
            for put in [&title, &chapter] {
                unanswered(cx, "bob", &put.name)?;
            }
            cx.evidence(&format!(
                "ann's daemon is down: nothing answers {} or {}",
                title.name, chapter.name
            ));
            Ok(())
        },
    )?;

    sc.step(
        "a new host on bob's device, with an empty store, opens the space and reads the title \
         and the chapter as ann wrote them, from the repo alone",
        |cx| {
            cx.concept("reading a space through a repo");
            let mut bob = Host::start_with(
                cx,
                "bob",
                &bob_root.identity,
                &["--holder".to_owned(), REPO_DEVICE.to_owned()],
            )?;
            bob.watch_when_ready(cx, SPACE)?;
            for (put, text) in [
                (&title, "A guide to the coast"),
                (&chapter, "Start at the harbour."),
            ] {
                let path = put.path.clone();
                wait_for(
                    cx,
                    &format!("bob reads {path} through the repo"),
                    CONVERGE,
                    |cx| {
                        Ok(bob
                            .item(cx, SPACE, &path)?
                            .is_some_and(|item| put.is(&item["id"]) && item["text"] == text))
                    },
                )
                .map_err(|e| format!("{e}{}", carrier.tail()))?;
                let item = bob.item(cx, SPACE, &path)?.ok_or("bob lost a path")?;
                if name(item["by"].as_str().unwrap_or_default())? != name(NAMESPACES.a)? {
                    return Err(format!(
                        "bob reads {path} as written by {}, not /oa",
                        item["by"]
                    ));
                }
                cx.evidence(&format!("bob reads {path}: {item}"));
            }
            let members = bob.members(cx, SPACE)?;
            if members["owner"] != NAMESPACES.a || members["readers"] != "anyone" {
                return Err(format!("bob reads the space's members as {members}"));
            }
            cx.evidence(&format!(
                "bob's members of {SPACE}: owner {}, readers {}; ann's device {} is gone: the \
                 repo carried them",
                members["owner"], members["readers"], ann_root.identity
            ));
            Ok(())
        },
    )?;
    Ok(())
}
