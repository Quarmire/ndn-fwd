//! on-demand: link modes and reachability while asleep, configured in
//! `ndn-fwd.toml` and driven with `ndn-ctl link connect|disconnect`.
//!
//! Topology, all on the harness's `lo`: root (.1, root device + CA) ← UDP ←
//! relay (.2, a `node` device listening for QUIC links; `[relay_service]
//! hold = true`, `hold_per_device = 2`, and a `wake_command`: a notifier
//! script that appends `$NDN_WAKE_TOKEN $NDN_WAKE_DEVICE` to `wakes` in the
//! relay's directory). desk (.3), phone (.4) and tab (.5) are members that
//! link to the relay over QUIC only and enroll by invite; none makes direct
//! paths by membership, so whatever reaches the phone comes through the
//! relay. phone then uses the relay as a `[[relay]]` with `mode =
//! "on-demand"`, `idle_secs = 10`, `hold = true` and a `wake_token`; tab
//! with `mode = "off"`.
//!
//! Proves: the on-demand link closes after its idle time (the phone's link
//! list says why, the relay counts the phone asleep) and an outgoing fetch
//! links it again and is answered; an off link stays closed — a fetch over
//! it fails — until `ndn-ctl link connect`; the relay runs its wake command
//! never while the phone is linked (a fetch for the phone then leaves the
//! notifier's file empty) and exactly once, with the phone's token, when
//! Interests for the sleeping phone arrive; it holds up to
//! `hold_per_device` of them and Nacks the next at once; `ndn-ctl link
//! connect` on the phone (standing in for the push waking the app) delivers
//! the held Interests, answered within their lifetime.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::thread;
use std::time::{Duration, Instant};

use super::direct_paths::{Link, link_list, quic_faces};
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{CaCfg, NodeCfg, PeerCfg, QUIC_PORT, addr};

const NS: &str = "/od";
const WAKE_TOKEN: &str = "od-push-token";
const HOLD_PER_DEVICE: usize = 2;
const IDLE_SECS: u64 = 10;
const PHONE: u8 = 4;
const TAB: u8 = 5;

fn n(s: &str) -> String {
    format!("{NS}{s}")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// No direct paths by membership: traffic for a device goes through the
/// relay.
const NO_DIRECT: &str = "[direct]\nmembership = false\n";

/// The relay as a `[[relay]]` in `mode`, with `more` keys.
fn relay_entry(mode: &str, more: &str) -> String {
    format!(
        "{NO_DIRECT}\n[[relay]]\ndevice = \"{}\"\nendpoint = \"{}:{QUIC_PORT}\"\nmode = \"{mode}\"\n{more}",
        n("/node/relay"),
        addr(2)
    )
}

/// Whether the relay has a link face to `host`'s address.
fn relay_links(cx: &mut Cx<'_>, host: u8) -> StepResult<bool> {
    Ok(quic_faces(cx, "relay")?
        .iter()
        .any(|(r, _)| *r.ip() == addr(host)))
}

/// `node`'s link to the relay (its `[[relay]]` or `[[peer]]` entry).
fn to_relay(cx: &mut Cx<'_>, node: &str) -> StepResult<Link> {
    link_list(cx, node)?
        .links
        .into_iter()
        .find(|l| l.label == n("/node/relay"))
        .ok_or_else(|| format!("{node}'s link list shows no link to the relay"))
}

fn shown(l: &Link) -> String {
    format!(
        "mode {}; relay {}; {} path(s); down {}",
        l.mode.as_deref().unwrap_or("-"),
        l.relay.as_deref().unwrap_or("-"),
        l.paths.len(),
        l.down.as_deref().unwrap_or("-")
    )
}

/// The relay's `asleep` line for the phone, if the phone is asleep there.
fn phone_asleep(cx: &mut Cx<'_>) -> StepResult<Option<String>> {
    Ok(link_list(cx, "relay")?
        .links
        .into_iter()
        .find(|l| l.device.as_deref() == Some(n("/member/phone").as_str()))
        .and_then(|l| l.asleep))
}

/// `ndn-ctl link <verb> <relay>` on `node`.
fn link_cmd(cx: &mut Cx<'_>, node: &str, verb: &str) -> StepResult<()> {
    let sock = cx.w.node(node).sock().display().to_string();
    let op = cx
        .tool("ndn-ctl")
        .args(["--socket", &sock, "link", verb])
        .arg(n("/node/relay"));
    cx.ok(op, &format!("ndn-ctl link {verb}")).map(|_| ())
}

/// The lines the relay's wake command wrote.
fn wakes(cx: &Cx<'_>) -> Vec<String> {
    fs::read_to_string(cx.w.node("relay").dir.join("wakes"))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// `node` links to the relay over QUIC only and enrolls by invite over its
/// enrollment link; `hello` then reaches it over the full link.
fn link_and_enroll(
    cx: &mut Cx<'_>,
    node: &str,
    host: u8,
    invite: &Invite,
    hello: &[u8],
) -> StepResult<()> {
    cx.start(node)?;
    wait_for(cx, &format!("the relay links to {node}"), SHORT, |cx| {
        relay_links(cx, host)
    })?;
    enroll(cx, node, invite, node, false, None)?;
    fetch_within(cx, node, &n("/node/relay/hello"), hello, SHORT)
}

/// An `ndn-peek` of one Data packet `name` at the desk with `lifetime_ms`,
/// written to `file`.
fn desk_peek(cx: &Cx<'_>, name: &str, file: &std::path::Path, lifetime_ms: u32) -> crate::run::Op {
    let sock = cx.w.node("desk").sock().display().to_string();
    cx.tool("ndn-peek")
        .args([
            "--face-socket",
            &sock,
            "--can-be-prefix",
            "--lifetime",
            &lifetime_ms.to_string(),
            "-o",
        ])
        .arg(file.display().to_string())
        .arg(name)
        .timeout(Duration::from_millis(u64::from(lifetime_ms) + 10_000))
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    let base = NodeCfg {
        refresh_secs: 600,
        ..Default::default()
    };
    sc.world.add("root", 1, base.clone());
    let relay_dir = sc.world.dir.join("relay");
    let notifier = relay_dir.join("notify");
    sc.world.add(
        "relay",
        2,
        NodeCfg {
            links: vec![link("root", 1)],
            routes: vec![route(NS, "root")],
            quic_listen: true,
            extra_toml: format!(
                "[relay_service]\nhold = true\nhold_per_device = {HOLD_PER_DEVICE}\nwake_command = [\"{}\"]\n",
                notifier.display()
            ),
            ..base.clone()
        },
    );
    let member = NodeCfg {
        peers: vec![PeerCfg {
            device: Some(n("/node/relay")),
            endpoint: Some(addr(2)),
            ..Default::default()
        }],
        quic_dial_only: true,
        extra_toml: NO_DIRECT.into(),
        ..base.clone()
    };
    sc.world.add("desk", 3, member.clone());
    sc.world.add("phone", PHONE, member.clone());
    sc.world.add("tab", TAB, member);

    sc.step("write the relay's wake notifier: a script appending $NDN_WAKE_TOKEN $NDN_WAKE_DEVICE to `wakes`", |_cx| {
        let script = format!(
            "#!/bin/sh\necho \"$NDN_WAKE_TOKEN $NDN_WAKE_DEVICE\" >> \"{}\"\n",
            relay_dir.join("wakes").display()
        );
        fs::write(&notifier, script).map_err(|e| format!("{}: {e}", notifier.display()))?;
        fs::set_permissions(&notifier, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())
    })?;
    let root = sc.step("init the root device", |cx| {
        init_root(cx, "root", NS, "home")
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
    let invites = sc.step(
        "make three member invites at the running CA (desk, phone, tab)",
        |cx| mint(cx, "root", NS, &root.fp, 3, Some("2h")),
    )?;
    let hello = content(1_500, 71);
    sc.step("start the relay (holding, waking), adopt, become a node device on approval, serve a greeting", |cx| {
        cx.start("relay")?;
        let op = cx
            .tool("ndn-fwd")
            .arg("adopt")
            .arg(&root.link_fp)
            .arg("-c")
            .arg(cx.w.node("relay").cfg_arg());
        cx.ok(op, "adopt")?;
        cx.expect_version("relay", NS, 1)?;
        enroll_by_approval(cx, NS, &root.link_fp, "relay")?;
        cx.publish("relay", &n("/node/relay/hello"), &hello, None, None)
    })?;
    let notes = content(20_000, 72);
    sc.step("desk, phone and tab link to the relay over QUIC and enroll by invite; desk publishes its notes", |cx| {
        link_and_enroll(cx, "desk", 3, &invites[0], &hello)?;
        link_and_enroll(cx, "phone", PHONE, &invites[1], &hello)?;
        link_and_enroll(cx, "tab", TAB, &invites[2], &hello)?;
        cx.publish("desk", &n("/member/desk/notes"), &notes, None, None)
    })?;

    sc.step(
        "phone's relay link is on-demand (idle 10 s, hold, wake token): a fetch links it, it closes when idle, the next fetch links it again",
        |cx| {
            let phone = cx.w.node_mut("phone");
            phone.cfg.peers.clear();
            phone.cfg.extra_toml = relay_entry(
                "on-demand",
                &format!("idle_secs = {IDLE_SECS}\nhold = true\nwake_token = \"{WAKE_TOKEN}\"\n"),
            );
            cx.stop("phone");
            cx.start("phone")?;
            fetch_within(cx, "phone", &n("/member/desk/notes"), &notes, SHORT)?;
            if !relay_links(cx, PHONE)? {
                return Err("the phone fetched through the relay, but the relay shows no link from it".into());
            }
            let fetched = Instant::now();
            wait_for(cx, "the phone's on-demand link closes idle", Duration::from_secs(IDLE_SECS + 30), |cx| {
                Ok(!relay_links(cx, PHONE)? && to_relay(cx, "phone")?.paths.is_empty())
            })?;
            let idle = fetched.elapsed();
            let l = to_relay(cx, "phone")?;
            cx.evidence(&format!("closed {:.2}s after the fetch; phone → relay: {}", idle.as_secs_f64(), shown(&l)));
            if idle < Duration::from_secs(IDLE_SECS - 1) {
                return Err(format!("closed {:.2}s after its last traffic, before its idle time ({IDLE_SECS} s)", idle.as_secs_f64()));
            }
            if l.down.is_none() {
                return Err(format!("the phone's link list says nothing of why its relay link is down: {}", shown(&l)));
            }
            let asleep = wait_for(cx, "the relay counts the phone asleep", SHORT, |cx| Ok(phone_asleep(cx)?.is_some()))
                .and_then(|_| phone_asleep(cx))?;
            cx.evidence(&format!("relay: phone asleep {}", asleep.unwrap_or_default()));
            let start = Instant::now();
            fetch_within(cx, "phone", &n("/node/relay/hello"), &hello, SHORT)?;
            if !relay_links(cx, PHONE)? {
                return Err("the phone fetched the relay's greeting, but the relay shows no link from it".into());
            }
            cx.evidence(&format!("linked again for an outgoing fetch, answered {:.2}s after asking", start.elapsed().as_secs_f64()));
            Ok(())
        },
    )?;

    sc.step("tab's relay link is off: it stays closed and a fetch over it fails until `ndn-ctl link connect`", |cx| {
        let tab = cx.w.node_mut("tab");
        tab.cfg.peers.clear();
        tab.cfg.extra_toml = relay_entry("off", "");
        cx.stop("tab");
        cx.start("tab")?;
        // The daemon has taken the entry (its link list says off and why);
        // a link that dialled anyway is up within a dial (0.25 s here, as
        // the connect below shows), so a second covers it.
        wait_for(cx, "tab's link list shows its relay link off, saying why", SHORT, |cx| {
            let list = link_list(cx, "tab")?;
            Ok(list.links.iter().any(|l| {
                l.label == n("/node/relay") && l.mode.as_deref().is_some_and(|m| m.starts_with("off")) && l.down.is_some()
            }))
        })?;
        thread::sleep(Duration::from_secs(1));
        let l = to_relay(cx, "tab")?;
        cx.evidence(&format!("after starting: tab → relay: {}", shown(&l)));
        if relay_links(cx, TAB)? || !l.paths.is_empty() {
            return Err(format!("the off link is up: {}", shown(&l)));
        }
        if cx.fetch_ok("tab", &n("/node/relay/hello"), &hello).is_ok() {
            return Err("a fetch over the off link was answered".into());
        }
        if relay_links(cx, TAB)? {
            return Err("a fetch linked the off link".into());
        }
        link_cmd(cx, "tab", "connect")?;
        let took = wait_for(cx, "tab's off link links when asked", SHORT, |cx| relay_links(cx, TAB))?;
        fetch_within(cx, "tab", &n("/node/relay/hello"), &hello, SHORT)?;
        cx.evidence(&format!("linked {:.2}s after `ndn-ctl link connect`; the fetch is answered", took.as_secs_f64()));
        link_cmd(cx, "tab", "disconnect")?;
        let took = wait_for(cx, "tab's off link closes on disconnect", SHORT, |cx| Ok(!relay_links(cx, TAB)?))?;
        cx.evidence(&format!("closed {:.2}s after `ndn-ctl link disconnect`", took.as_secs_f64()));
        Ok(())
    })?;

    let photo = content(3_000, 73);
    sc.step(
        "while the phone is linked, the desk's fetch of its photo wakes nobody",
        |cx| {
            cx.publish("phone", &n("/member/phone/photo"), &photo, None, None)?;
            link_cmd(cx, "phone", "connect")?;
            wait_for(cx, "the phone is linked", SHORT, |cx| {
                relay_links(cx, PHONE)
            })?;
            fetch_within(cx, "desk", &n("/member/phone/photo"), &photo, SHORT)?;
            let w = wakes(cx);
            let sent = link_list(cx, "relay")?.wakes_sent;
            cx.evidence(&format!(
                "wake command lines {}; relay wakes-sent {sent:?}",
                w.len()
            ));
            if !w.is_empty() || sent != Some(0) {
                return Err(format!(
                    "the relay woke the linked phone: {w:?}; wakes-sent {sent:?}"
                ));
            }
            Ok(())
        },
    )?;

    let late: Vec<Vec<u8>> = (0..=HOLD_PER_DEVICE as u64)
        .map(|i| content(1_000, 80 + i))
        .collect();
    sc.step(
        "the phone publishes three items and sleeps: its link closes idle, the relay counts it asleep and wakes nobody yet",
        |cx| {
            for (i, data) in late.iter().enumerate() {
                cx.publish("phone", &n(&format!("/member/phone/late{i}")), data, None, None)?;
            }
            link_cmd(cx, "phone", "disconnect")?;
            wait_for(cx, "the phone's link closes idle and it is asleep at the relay", Duration::from_secs(IDLE_SECS + 30), |cx| {
                Ok(!relay_links(cx, PHONE)? && phone_asleep(cx)?.is_some())
            })?;
            if !wakes(cx).is_empty() {
                return Err(format!("the relay woke the phone before any Interest for it: {:?}", wakes(cx)));
            }
            Ok(())
        },
    )?;
    // The held fetches outlive the step that asks; their answers are
    // checked by the next.
    let mut askers = Vec::new();
    sc.step("the desk asks the sleeping phone twice: both held, one wake with the token; a third is Nacked at once", |cx| {
        let start = Instant::now();
        for (i, _) in late.iter().enumerate().take(HOLD_PER_DEVICE) {
            let file = cx.w.node("desk").dir.join(format!("late{i}.bin"));
            let peek = desk_peek(cx, &n(&format!("/member/phone/late{i}")), &file, 30_000);
            cx.note(&format!("$ {} &", peek.display()));
            askers.push((file, thread::spawn(move || peek.run())));
        }
        let held = wait_for(cx, "the relay holds both Interests", SHORT, |cx| {
            Ok(phone_asleep(cx)?.is_some_and(|a| a.split_whitespace().any(|w| w == format!("held={HOLD_PER_DEVICE}"))))
        })?;
        wait_for(cx, "the relay runs its wake command", SHORT, |cx| Ok(!wakes(cx).is_empty()))?;
        let expected = format!("{} {}", hex(WAKE_TOKEN.as_bytes()), n("/member/phone"));
        let w = wakes(cx);
        if w.len() != 1 || w[0].trim() != expected {
            return Err(format!("the wake command wrote {w:?}, expected one line {expected:?}"));
        }
        cx.evidence(&format!(
            "held {HOLD_PER_DEVICE} after {:.2}s; wake command wrote {:?}",
            held.as_secs_f64(),
            w[0]
        ));
        let file = cx.w.node("desk").dir.join(format!("late{HOLD_PER_DEVICE}.bin"));
        let excess = desk_peek(cx, &n(&format!("/member/phone/late{HOLD_PER_DEVICE}")), &file, 30_000);
        let out = cx.exec(excess);
        cx.evidence(&format!(
            "Interest {} beyond hold_per_device = {HOLD_PER_DEVICE}: {} ({})",
            HOLD_PER_DEVICE + 1,
            out.status_text(),
            out.stderr.trim()
        ));
        if out.success() || file.exists() {
            return Err("the Interest beyond hold_per_device was answered".into());
        }
        if out.elapsed > Duration::from_secs(5) {
            return Err(format!("the Interest beyond hold_per_device waited {:.1}s, not Nacked at once", out.elapsed.as_secs_f64()));
        }
        let asleep = phone_asleep(cx)?.unwrap_or_default();
        cx.evidence(&format!("relay: phone asleep {asleep}; {:.2}s since the first Interest", start.elapsed().as_secs_f64()));
        if wakes(cx).len() != 1 {
            return Err(format!("the wake command ran again: {:?}", wakes(cx)));
        }
        Ok(())
    })?;
    sc.step("`ndn-ctl link connect` on the phone (the push waking the app): the held Interests are answered", |cx| {
        let start = Instant::now();
        link_cmd(cx, "phone", "connect")?;
        for (i, (file, asker)) in askers.drain(..).enumerate() {
            let out = asker.join().map_err(|_| "a held ndn-peek panicked")?;
            let got = fs::read(&file).unwrap_or_default();
            if !out.success() || got != late[i] {
                return Err(format!(
                    "held Interest {i} not answered: {} ({}); {} bytes",
                    out.status_text(),
                    out.stderr.trim(),
                    got.len()
                ));
            }
        }
        cx.evidence(&format!(
            "both held Interests answered {:.2}s after the phone linked again, within their 30 s lifetime",
            start.elapsed().as_secs_f64()
        ));
        let sent = link_list(cx, "relay")?.wakes_sent;
        if wakes(cx).len() != 1 || sent != Some(1) {
            return Err(format!("wake command lines {:?}; relay wakes-sent {sent:?} (expected one)", wakes(cx)));
        }
        Ok(())
    })?;
    Ok(())
}
