//! quic-links: devices linked over QUIC, identified by their keys.
//!
//! Topology: root (10.200.0.1, root device + CA) ← UDP ← relay (.2, a
//! `node` device listening for QUIC links). phone (.3, dialling only, from
//! its own address: `listen = false`) and tab (.4) reach the relay over QUIC
//! only (`[[peer]] device = "/ql/node/relay"`), from before they are
//! enrolled: each enrolls over its enrollment link (phone by invite, tab on
//! the root device's approval), which then becomes a full link by itself.
//! Every byte between them crosses the relay (relay-first). stranger (.5)
//! holds the namespace but is not enrolled.
//!
//! Proves: an unenrolled device reachable only over QUIC enrolls by invite
//! and by approval; its enrollment link carries nothing but its enrollment;
//! once enrolled it has a full link; validated Data both ways between phone
//! and tab through the relay, a large segmented object included; a dial
//! expecting another key than the relay's links nothing; links come back
//! after the relay, then a device, restart; a revocation the relay adopts
//! closes the revoked device's link and keeps it closed. Link state is read
//! from `ndn-ctl face list` (a `quic4://` face per linked device).

use std::net::Ipv4Addr;
use std::thread;
use std::time::{Duration, Instant};

use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{CaCfg, NodeCfg, PeerCfg, addr};

const NS: &str = "/ql";

fn n(s: &str) -> String {
    format!("{NS}{s}")
}

/// The relay as phone and tab name it.
fn relay_peer(key: Option<String>) -> PeerCfg {
    PeerCfg {
        device: Some(n("/node/relay")),
        key,
        endpoint: Some(addr(2)),
        ..Default::default()
    }
}

/// The addresses `node` has a QUIC link face to (harness inspection).
fn linked(cx: &mut Cx<'_>, node: &str) -> StepResult<Vec<Ipv4Addr>> {
    let sock = cx.w.node(node).sock().display().to_string();
    let op = cx
        .tool("ndn-ctl")
        .args(["--socket", &sock, "face", "list", "--scheme", "quic4"]);
    let out = cx.exec(op);
    if !out.success() {
        return Err(format!("face list on {node}: {}", out.status_text()));
    }
    Ok(out
        .stdout
        .lines()
        .filter_map(|l| l.trim().strip_prefix("remote: quic4://"))
        .filter_map(|a| a.rsplit_once(':').and_then(|(ip, _)| ip.parse().ok()))
        .collect())
}

/// Wait until `node` is linked to (`want`) or not linked to (`!want`) the
/// node at `ip`.
fn wait_link(
    cx: &mut Cx<'_>,
    node: &str,
    ip: Ipv4Addr,
    want: bool,
    within: Duration,
) -> StepResult<()> {
    let start = Instant::now();
    loop {
        if linked(cx, node)?.contains(&ip) == want {
            cx.note(&format!(
                "{node} {} {ip} after {:.2}s",
                if want { "linked to" } else { "not linked to" },
                start.elapsed().as_secs_f64()
            ));
            return Ok(());
        }
        if start.elapsed() > within {
            return Err(format!(
                "{node}: {} {ip} after {}s",
                if want {
                    "still no link to"
                } else {
                    "still linked to"
                },
                within.as_secs()
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// `node` stays unlinked from `ip` for `span` (it keeps refusing).
fn stays_unlinked(cx: &mut Cx<'_>, node: &str, ip: Ipv4Addr, span: Duration) -> StepResult<()> {
    let start = Instant::now();
    while start.elapsed() < span {
        if linked(cx, node)?.contains(&ip) {
            return Err(format!(
                "{node}: linked to {ip} after {:.2}s",
                start.elapsed().as_secs_f64()
            ));
        }
        thread::sleep(Duration::from_millis(200));
    }
    Ok(())
}

/// A fetch at `node` that must not deliver `name` (nothing reaches it).
pub(super) fn fetch_fails(cx: &mut Cx<'_>, node: &str, name: &str) -> StepResult<()> {
    let seq = cx.w.next_seq();
    let file = cx.w.node(node).dir.join(format!("fetch-{seq}.bin"));
    let sock = cx.w.node(node).sock().display().to_string();
    let op = cx
        .tool("ndn-peek")
        .args([
            "--face-socket",
            &sock,
            "--can-be-prefix",
            "--lifetime",
            "1500",
            "-o",
        ])
        .arg(file.display().to_string())
        .arg(name)
        .timeout(Duration::from_secs(10));
    let out = cx.op(op);
    if out.timed_out {
        return Err(format!("ndn-peek of {name} at {node} hung"));
    }
    if out.success() || file.exists() {
        return Err(format!(
            "{name} was delivered at {node}, expected no route to it"
        ));
    }
    Ok(())
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    let base = NodeCfg {
        refresh_secs: 1,
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
            ..base.clone()
        },
    );
    // QUIC only, from the start: no UDP face, no route; links dial from
    // each node's own address on the shared `lo`, so the relay sees a
    // device at its address.
    sc.world.add(
        "phone",
        3,
        NodeCfg {
            peers: vec![relay_peer(None)],
            quic_dial_only: true,
            ..base.clone()
        },
    );
    let quic_only = NodeCfg {
        peers: vec![relay_peer(None)],
        quic_listen: true,
        ..base.clone()
    };
    sc.world.add("tab", 4, quic_only.clone());
    sc.world.add("stranger", 5, quic_only);

    let root = sc.step("init the root device", |cx| {
        init_root(cx, "root", NS, "desk")
    })?;
    sc.step("start the root device's daemon with its CA", |cx| {
        cx.w.node_mut("root").cfg.identity = Some(root.identity.clone());
        cx.w.node_mut("root").cfg.ca = Some(CaCfg {
            prefix: NS.into(),
            identity: n("/CA"),
            member_days: None,
        });
        cx.start("root")
    })?;
    let invites = sc.step("make a member invite at the running CA", |cx| {
        mint(cx, "root", NS, &root.fp, 1, Some("2h"))
    })?;
    sc.step(
        "start the relay (listening for QUIC links) and adopt the namespace",
        |cx| {
            cx.start("relay")?;
            let op = cx
                .tool("ndn-fwd")
                .arg("adopt")
                .arg(&root.link_fp)
                .arg("-c")
                .arg(cx.w.node("relay").cfg_arg());
            cx.ok(op, "adopt")?;
            cx.expect_version("relay", NS, 1)
        },
    )?;
    sc.step(
        "the relay becomes a node device on the root device's approval",
        |cx| {
            let before = cx.certs("relay");
            let op = cx
                .tool("ndn-fwd")
                .arg("enroll")
                .arg(&root.link_fp)
                .args(["--role", "node", "--device", "relay", "-c"])
                .arg(cx.w.node("relay").cfg_arg());
            let out = cx.ok(op, "enroll --role node")?;
            let code = out.kv("code").ok_or("no code in the enroll output")?;
            let approve = cx
                .tool("ndn-fwd")
                .args(["approvals", "approve"])
                .args(code.split_whitespace())
                .arg("-c")
                .arg(cx.w.node("root").cfg_arg());
            cx.ok(approve, "approve the relay")?;
            let start = Instant::now();
            loop {
                if let Ok(cert) = new_cert(cx, "relay", &before)
                    && cert.starts_with(&n("/node/relay/KEY/"))
                {
                    return Ok(());
                }
                if start.elapsed() > SHORT {
                    return Err(format!(
                        "the relay holds no {} certificate {}s after the approval",
                        n("/node/relay"),
                        SHORT.as_secs()
                    ));
                }
                thread::sleep(Duration::from_millis(100));
            }
        },
    )?;
    let hello = content(2_000, 20);
    sc.step(
        "the relay publishes Data no enrollment link carries",
        |cx| cx.publish("relay", &n("/node/relay/hello"), &hello, None, None),
    )?;

    sc.step("phone, unenrolled and reachable only over QUIC, gets an enrollment link that carries nothing else", |cx| {
        cx.start("phone")?;
        wait_link(cx, "relay", addr(3), true, SHORT)?;
        wait_link(cx, "phone", addr(2), true, SHORT)?;
        fetch_fails(cx, "phone", &n("/node/relay/hello"))
    })?;
    sc.step(
        "phone enrolls by invite over its enrollment link, which becomes a full link by itself",
        |cx| {
            enroll(cx, "phone", &invites[0], "phone", false, None)?;
            fetch_within(cx, "phone", &n("/node/relay/hello"), &hello, SHORT)
        },
    )?;

    sc.step("tab, unenrolled and reachable only over QUIC, gets an enrollment link that carries nothing else", |cx| {
        cx.start("tab")?;
        wait_link(cx, "relay", addr(4), true, SHORT)?;
        fetch_fails(cx, "tab", &n("/node/relay/hello"))
    })?;
    sc.step(
        "tab enrolls on the root device's approval over its enrollment link, then links fully",
        |cx| {
            let before = cx.certs("tab");
            let op = cx
                .tool("ndn-fwd")
                .arg("enroll")
                .arg(&root.link_fp)
                .args(["--role", "node", "--device", "tab", "-c"])
                .arg(cx.w.node("tab").cfg_arg());
            let out = cx.ok(op, "enroll --role node (by approval)")?;
            let code = out.kv("code").ok_or("no code in the enroll output")?;
            let approve = cx
                .tool("ndn-fwd")
                .args(["approvals", "approve"])
                .args(code.split_whitespace())
                .arg("-c")
                .arg(cx.w.node("root").cfg_arg());
            cx.ok(approve, "approve tab")?;
            let start = Instant::now();
            loop {
                if let Ok(cert) = new_cert(cx, "tab", &before)
                    && cert.starts_with(&n("/node/tab/KEY/"))
                {
                    break;
                }
                if start.elapsed() > SHORT {
                    return Err(format!(
                        "tab holds no {} certificate {}s after the approval",
                        n("/node/tab"),
                        SHORT.as_secs()
                    ));
                }
                thread::sleep(Duration::from_millis(100));
            }
            fetch_within(cx, "tab", &n("/node/relay/hello"), &hello, SHORT)
        },
    )?;

    let album = content(400_000, 21);
    sc.step(
        "tab fetches and validates a large segmented object phone publishes (relay-first)",
        |cx| {
            cx.publish("phone", &n("/member/phone/album"), &album, None, None)?;
            cx.fetch_ok("tab", &n("/member/phone/album"), &album)
        },
    )?;
    let note = content(3_000, 22);
    sc.step(
        "phone fetches and validates tab's Data (the other way)",
        |cx| {
            cx.publish("tab", &n("/node/tab/note"), &note, None, None)?;
            cx.fetch_ok("phone", &n("/node/tab/note"), &note)
        },
    )?;
    sc.step("the relay validates phone's object too", |cx| {
        cx.fetch_ok("relay", &n("/member/phone/album"), &album)
    })?;

    sc.step(
        "an unenrolled device gets only an enrollment link: it carries nothing else",
        |cx| {
            // It holds the namespace before its daemon first dials, so it links
            // to the relay as to a relay it can confirm; the relay knows no
            // certificate of its key and admits it on an enrollment link.
            {
                let s = cx.w.node("stranger");
                std::fs::write(s.config(), s.render()).map_err(|e| e.to_string())?;
            }
            let op = cx
                .tool("ndn-fwd")
                .arg("adopt")
                .arg(&root.link_inline)
                .arg("-c")
                .arg(cx.w.node("stranger").cfg_arg());
            cx.ok(op, "stranger adopts the namespace (inline anchor link)")?;
            cx.start("stranger")?;
            wait_link(cx, "relay", addr(5), true, SHORT)?;
            fetch_fails(cx, "stranger", &n("/member/phone/album"))?;
            fetch_fails(cx, "stranger", &n("/node/relay/hello"))?;
            cx.stop("stranger");
            Ok(())
        },
    )?;

    sc.step(
        "tab expecting another key at the relay's endpoint links nothing",
        |cx| {
            cx.stop("tab");
            wait_link(cx, "relay", addr(4), false, SHORT)?;
            cx.w.node_mut("tab").cfg.peers = vec![relay_peer(Some("ab".repeat(32)))];
            cx.start("tab")?;
            fetch_fails(cx, "tab", &n("/member/phone/album"))?;
            stays_unlinked(cx, "tab", addr(2), Duration::from_secs(1))?;
            stays_unlinked(cx, "relay", addr(4), Duration::from_millis(200))
        },
    )?;
    sc.step(
        "control: tab naming the relay by device links again after its restart",
        |cx| {
            cx.stop("tab");
            cx.w.node_mut("tab").cfg.peers = vec![relay_peer(None)];
            cx.start("tab")?;
            wait_link(cx, "tab", addr(2), true, SHORT)?;
            cx.fetch_ok("tab", &n("/member/phone/album"), &album)
        },
    )?;

    sc.step(
        "the relay restarts: phone and tab link again on their own",
        |cx| {
            cx.stop("relay");
            cx.start("relay")?;
            wait_link(cx, "relay", addr(3), true, SHORT)?;
            wait_link(cx, "relay", addr(4), true, SHORT)?;
            cx.fetch_ok("tab", &n("/member/phone/album"), &album)
        },
    )?;
    let doc = content(20_000, 23);
    sc.step(
        "phone restarts: its link comes back and its new Data reaches tab",
        |cx| {
            cx.stop("phone");
            cx.start("phone")?;
            wait_link(cx, "relay", addr(3), true, SHORT)?;
            cx.publish("phone", &n("/member/phone/doc"), &doc, None, None)?;
            cx.fetch_ok("tab", &n("/member/phone/doc"), &doc)
        },
    )?;

    let v0 = sc.world.held_version("root", NS).unwrap_or(0);
    sc.step(
        "revoke phone: the relay adopts it and closes phone's link, and keeps it closed",
        |cx| {
            let op = cx
                .tool("ndn-fwd")
                .arg("revoke")
                .arg(n("/member/phone"))
                .arg("-c")
                .arg(cx.w.node("root").cfg_arg())
                .env("NDN_ROOT_PASSPHRASE", ROOT_PASS);
            cx.ok(op, "revoke")?;
            cx.wait_version("relay", NS, v0 + 1, SHORT)?;
            wait_link(cx, "relay", addr(3), false, Duration::from_secs(5))?;
            stays_unlinked(cx, "relay", addr(3), Duration::from_secs(3))?;
            // Control: tab, not revoked, keeps its link.
            if !linked(cx, "relay")?.contains(&addr(4)) {
                return Err("the relay closed tab's link too".into());
            }
            Ok(())
        },
    )?;
    Ok(())
}
