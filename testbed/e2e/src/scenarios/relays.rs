//! relays: which relays a device uses, and whom a relay serves.
//!
//! Topology, all on the harness's `lo`: /ra's root device (.1, CA) advertises
//! two relays in its trust context, r1 (.2, preference 0) and r2 (.3,
//! preference 1), both `node` devices listening for QUIC links and serving
//! their own namespace only (the default). m1 (.4) and m2 (.5) are members
//! of /ra; they enroll over a UDP link to the root device and then run with
//! no `[[relay]]` and no `[[peer]]` (and no direct paths by membership, so
//! that their traffic shows on the relays). /rb's root device (.6) enrolls b1
//! (.7) and b2 (.8). club (.9) is the root device of /rc, a community relay.
//!
//! Proves: a relay serving only its namespace refuses a device of another
//! namespace, saying who it took the device for; an open relay admits one
//! device of a foreign namespace and refuses the next by its per-namespace
//! quota; newly enrolled devices use the relay their namespace advertises
//! with no local configuration; losing the preferred relay moves the links
//! and the traffic to the next one, and its return moves them back,
//! releasing the stand-in (which does not count them as asleep, although
//! they asked it to hold their Interests); a community relay of another
//! namespace added with its expected fingerprint carries a fetch between
//! two devices of /ra. Relay state is read from `ndn-ctl link list`,
//! relay traffic from the relays' `ndn-ctl face list` packet counters.

use std::fs;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use super::direct_paths::{Link, LinkList, link_list, quic_faces};
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{CaCfg, NodeCfg, QUIC_PORT, addr};

const NS: &str = "/ra";
const NS_B: &str = "/rb";
const NS_C: &str = "/rc";
/// ndn-put's default segment size.
const SEGMENT: usize = 8192;

const R1: u8 = 2;
const R2: u8 = 3;
const M1: u8 = 4;
const M2: u8 = 5;
const CLUB: u8 = 9;

/// Link timing that notices a lost relay within seconds.
const FAST_LINKS: &str = "[links]\nkeep_alive_secs = 2\nidle_timeout_secs = 6\n";

fn n(s: &str) -> String {
    format!("{NS}{s}")
}

fn endpoint(host: u8) -> String {
    format!("{}:{QUIC_PORT}", addr(host))
}

/// A member of /ra: namespace relays (asked to hold its Interests while it
/// is away, so that a release is told apart from a sleep), no direct paths
/// by membership, plus `more`.
fn member_toml(more: &str) -> String {
    format!("[relays]\nhold = true\n\n[direct]\nmembership = false\n\n{FAST_LINKS}\n{more}")
}

/// A `[[relay]]` the user adds: the relay's expected fingerprint and
/// endpoint.
fn user_relay(key: &str, host: u8) -> String {
    format!(
        "[[relay]]\nkey = \"{key}\"\nendpoint = \"{}\"\n",
        endpoint(host)
    )
}

/// The link in `list` labelled `label` (a device name or a key).
fn labelled<'a>(list: &'a LinkList, label: &str) -> Option<&'a Link> {
    list.links.iter().find(|l| l.label == label)
}

/// The first word of a link's `relay` line: linked, trying, down, standby, off.
fn relay_state(l: &Link) -> &str {
    l.relay
        .as_deref()
        .and_then(|r| r.split_whitespace().next())
        .unwrap_or("")
}

fn shown(l: Option<&Link>) -> String {
    match l {
        None => "no link entry".to_owned(),
        Some(l) => format!(
            "relay {}; {} path(s){}",
            l.relay.as_deref().unwrap_or("-"),
            l.paths.len(),
            l.down
                .as_deref()
                .map(|d| format!("; down {d}"))
                .unwrap_or_default()
        ),
    }
}

/// Wait until `node`'s link `label` is a relay in `state`; its `relay` line.
fn wait_relay(
    cx: &mut Cx<'_>,
    node: &str,
    label: &str,
    state: &str,
    within: Duration,
) -> StepResult<(Duration, String)> {
    let start = Instant::now();
    loop {
        let list = link_list(cx, node)?;
        let l = labelled(&list, label);
        if let Some(l) = l
            && relay_state(l) == state
            && (state != "linked" || !l.paths.is_empty())
        {
            let line = l.relay.clone().unwrap_or_default();
            return Ok((start.elapsed(), line));
        }
        if start.elapsed() > within {
            return Err(format!(
                "{node} → {label}: {} after {}s, expected relay {state}",
                shown(l),
                within.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Packets (Interests, Data, Nacks) `relay` exchanged on its links with
/// the devices bound to `hosts`.
fn relay_packets(cx: &mut Cx<'_>, relay: &str, hosts: &[u8]) -> StepResult<u64> {
    let ips: Vec<Ipv4Addr> = hosts.iter().map(|h| addr(*h)).collect();
    Ok(quic_faces(cx, relay)?
        .into_iter()
        .filter(|(r, _)| ips.contains(r.ip()))
        .map(|(_, p)| p)
        .sum())
}

/// m2 fetches `data` (published by m1 under `name`) within `within`; the
/// packets `relay` carried for m1 and m2 meanwhile must cover every segment.
fn fetch_through(
    cx: &mut Cx<'_>,
    relay: &str,
    name: &str,
    data: &[u8],
    within: Duration,
) -> StepResult<()> {
    let before = relay_packets(cx, relay, &[M1, M2])?;
    fetch_within(cx, "m2", name, data, within)?;
    let after = relay_packets(cx, relay, &[M1, M2])?;
    let segments = data.len().div_ceil(SEGMENT) as u64;
    let delta = after.saturating_sub(before);
    cx.evidence(&format!(
        "{name}: {segments} segments; {relay}'s packets on m1's and m2's links {before} → {after} (+{delta})"
    ));
    if delta < segments {
        return Err(format!(
            "{relay} carried {delta} packets for {segments} segments: the fetch did not go through it"
        ));
    }
    Ok(())
}

/// `node` enrolls by invite over its UDP link to its root device.
fn enroll_member(cx: &mut Cx<'_>, node: &str, invite: &Invite) -> StepResult<()> {
    cx.start(node)?;
    enroll(cx, node, invite, node, false, None)?;
    Ok(())
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    let base = NodeCfg {
        refresh_secs: 600,
        ..Default::default()
    };
    sc.world.add(
        "root",
        1,
        NodeCfg {
            extra_toml: format!(
                "[relays]\nnamespace = false\n\n\
                 [[ca.relay]]\ndevice = \"{}\"\nendpoint = \"{}\"\npreference = 0\n\n\
                 [[ca.relay]]\ndevice = \"{}\"\nendpoint = \"{}\"\npreference = 1\n",
                n("/node/r1"),
                endpoint(R1),
                n("/node/r2"),
                endpoint(R2)
            ),
            ..base.clone()
        },
    );
    let relay = NodeCfg {
        links: vec![link("root", 1)],
        routes: vec![route(NS, "root")],
        quic_listen: true,
        extra_toml: format!(
            "[relays]\nnamespace = false\n\n[relay_service]\nhold = true\n\n{FAST_LINKS}"
        ),
        ..base.clone()
    };
    sc.world.add("r1", R1, relay.clone());
    sc.world.add("r2", R2, relay);
    let member = NodeCfg {
        links: vec![link("root", 1)],
        routes: vec![route(NS, "root")],
        quic_dial_only: true,
        extra_toml: member_toml(""),
        ..base.clone()
    };
    sc.world.add("m1", M1, member.clone());
    sc.world.add("m2", M2, member);
    sc.world.add("broot", 6, base.clone());
    let foreign = NodeCfg {
        links: vec![link("broot", 6)],
        routes: vec![route(NS_B, "broot")],
        quic_dial_only: true,
        ..base.clone()
    };
    sc.world.add("b1", 7, foreign.clone());
    sc.world.add("b2", 8, foreign);
    sc.world.add(
        "club",
        CLUB,
        NodeCfg {
            quic_listen: true,
            ..base.clone()
        },
    );

    let root = sc.step("init /ra's root device; its [[ca.relay]] advertise r1 (preference 0) and r2 (preference 1)", |cx| {
        cx.w.node_mut("root").cfg.ca = Some(CaCfg {
            prefix: NS.into(),
            identity: n("/CA"),
            tokens: Vec::new(),
            member_days: None,
        });
        let (info, out) = init_root_with(cx, "root", NS, "desk", true)?;
        let relays = out.kv_all("relay");
        for r in &relays {
            cx.evidence(&format!("init: relay = {r}"));
        }
        if relays.len() != 2 {
            return Err(format!("init states {} advertised relays, expected 2: {relays:?}", relays.len()));
        }
        Ok(info)
    })?;
    let invites = sc.step("mint two member invites (m1, m2)", |cx| {
        mint(cx, NS, &root.fp, 2, Some("2h"))
    })?;
    sc.step("start the root device's daemon with its CA", |cx| {
        let root_node = cx.w.node_mut("root");
        root_node.cfg.identity = Some(root.identity.clone());
        if let Some(ca) = root_node.cfg.ca.as_mut() {
            ca.tokens = invites.iter().map(|i| i.token.clone()).collect();
        }
        cx.start("root")
    })?;
    let r1_key = sc.step(
        "r1 and r2 start (listening for QUIC links), adopt, and become node devices on approval",
        |cx| {
            for r in ["r1", "r2"] {
                cx.start(r)?;
                let op = cx
                    .tool("ndn-fwd")
                    .arg("adopt")
                    .arg(&root.link_fp)
                    .arg("-c")
                    .arg(cx.w.node(r).cfg_arg());
                cx.ok(op, "adopt")?;
                cx.expect_version(r, NS, 1)?;
                enroll_by_approval(cx, NS, &root.link_fp, r)?;
            }
            link_list(cx, "r1")?
                .key
                .ok_or_else(|| "r1's link list shows no key".to_owned())
        },
    )?;

    sc.step(
        "m1 and m2 enroll by invite and, with no [[relay]] or [[peer]], link to r1, the relay /ra advertises first",
        |cx| {
            for (m, invite) in [("m1", &invites[0]), ("m2", &invites[1])] {
                enroll_member(cx, m, invite)?;
                let (took, line) = wait_relay(cx, m, &n("/node/r1"), "linked", SHORT)?;
                cx.note(&format!("{m}: r1 linked {:.2}s after enrolling: relay {line}", took.as_secs_f64()));
                // Its config names no relay and no peer; the UDP link it
                // enrolled over goes too.
                let node = cx.w.node_mut(m);
                node.cfg.links.clear();
                node.cfg.routes.clear();
                cx.stop(m);
                cx.start(m)?;
                let (took, line) = wait_relay(cx, m, &n("/node/r1"), "linked", SHORT)?;
                if !line.contains(&format!("source=namespace:{NS}")) || !line.contains("preference=0") {
                    return Err(format!("{m} → r1: relay {line} (expected source=namespace:{NS} preference=0)"));
                }
                let (_, standby) = wait_relay(cx, m, &n("/node/r2"), "standby", SHORT)?;
                cx.evidence(&format!(
                    "{m} restarted with no [[relay]], [[peer]] or UDP link: r1 linked after {:.2}s: relay {line}",
                    took.as_secs_f64()
                ));
                cx.evidence(&format!("{m} → r2: relay {standby}"));
            }
            Ok(())
        },
    )?;
    let first = content(100_000, 61);
    sc.step("m2 fetches m1's object through r1", |cx| {
        cx.publish("m1", &n("/member/m1/first"), &first, None, None)?;
        fetch_through(cx, "r1", &n("/member/m1/first"), &first, SHORT)
    })?;

    let moved = content(100_000, 62);
    sc.step(
        "r1 stops: m1 and m2 move to r2 (preference 1), and m2's fetch of m1's Data with them",
        |cx| {
            cx.publish("m1", &n("/member/m1/moved"), &moved, None, None)?;
            cx.stop("r1");
            let start = Instant::now();
            for m in ["m1", "m2"] {
                let (_, line) =
                    wait_relay(cx, m, &n("/node/r2"), "linked", Duration::from_secs(60))?;
                let list = link_list(cx, m)?;
                let r1 = labelled(&list, &n("/node/r1"));
                cx.evidence(&format!(
                    "{m} linked to r2 {:.2}s after r1 stopped: relay {line}; r1: {}",
                    start.elapsed().as_secs_f64(),
                    shown(r1)
                ));
                // r1 said it shuts down: r2 stands in at once, not after a redial
                // of r1 fails.
                if !shown(r1).contains("shutting down") {
                    return Err(format!("{m}'s r1 does not say it shut down: {}", shown(r1)));
                }
            }
            fetch_through(cx, "r2", &n("/member/m1/moved"), &moved, SHORT)?;
            cx.evidence(&format!(
                "m2 fetched through r2 {:.2}s after r1 stopped",
                start.elapsed().as_secs_f64()
            ));
            Ok(())
        },
    )?;

    let back = content(100_000, 63);
    sc.step(
        "r1 is back: m1 and m2 link to it again and release r2, which does not count them asleep",
        |cx| {
            cx.publish("m1", &n("/member/m1/back"), &back, None, None)?;
            cx.start("r1")?;
            let start = Instant::now();
            for m in ["m1", "m2"] {
                let (_, line) =
                    wait_relay(cx, m, &n("/node/r1"), "linked", Duration::from_secs(90))?;
                cx.evidence(&format!(
                    "{m} linked to r1 again {:.2}s after it restarted: relay {line}",
                    start.elapsed().as_secs_f64()
                ));
            }
            // Released, r2 forgets them: no path, and not asleep there,
            // although both asked their relays to hold their Interests.
            wait_for(
                cx,
                "r2 has neither m1 nor m2 linked or asleep",
                SHORT,
                |cx| {
                    let list = link_list(cx, "r2")?;
                    Ok(["m1", "m2"].iter().all(|m| {
                        list.links
                            .iter()
                            .filter(|l| {
                                l.device.as_deref() == Some(n(&format!("/member/{m}")).as_str())
                            })
                            .all(|l| l.paths.is_empty() && l.asleep.is_none())
                    }))
                },
            )?;
            for m in ["m1", "m2"] {
                let (_, line) = wait_relay(cx, m, &n("/node/r2"), "standby", SHORT)?;
                cx.evidence(&format!("{m} → r2: relay {line}"));
            }
            let log = fs::read_to_string(cx.w.node("r2").log()).unwrap_or_default();
            if let Some(l) = log
                .lines()
                .filter(|l| l.contains("link down") && l.contains(&n("/member/m1")))
                .last()
            {
                cx.evidence(&format!("r2's log: {}", l.trim()));
            }
            fetch_through(cx, "r1", &n("/member/m1/back"), &back, SHORT)
        },
    )?;

    sc.step(
        "init /rb's root device, mint two member invites, start its CA; b1 and b2 enroll",
        |cx| {
            let info = init_root(cx, "broot", NS_B, "home")?;
            let invites = mint(cx, NS_B, &info.fp, 2, Some("2h"))?;
            let broot = cx.w.node_mut("broot");
            broot.cfg.identity = Some(info.identity.clone());
            broot.cfg.ca = Some(CaCfg {
                prefix: NS_B.into(),
                identity: format!("{NS_B}/CA"),
                tokens: invites.iter().map(|i| i.token.clone()).collect(),
                member_days: None,
            });
            cx.start("broot")?;
            enroll_member(cx, "b1", &invites[0])?;
            enroll_member(cx, "b2", &invites[1])
        },
    )?;
    sc.step("b1 adds r1 as its relay by r1's expected fingerprint: r1 serves only /ra and refuses it, saying why", |cx| {
        cx.w.node_mut("b1").cfg.extra_toml = user_relay(&r1_key, R1);
        cx.stop("b1");
        cx.start("b1")?;
        let b1_key = link_list(cx, "b1")?.key.ok_or("b1's link list shows no key")?;
        let device = format!("{NS_B}/member/b1");
        let mut seen = String::new();
        wait_for(cx, "b1's relay r1 is down with r1's reason", SHORT, |cx| {
            let list = link_list(cx, "b1")?;
            let Some(l) = labelled(&list, &r1_key) else { return Ok(false) };
            seen = shown(Some(l));
            // The refusal names the device and the namespace r1 took it for.
            Ok(relay_state(l) == "down"
                && l.paths.is_empty()
                && l.relay.as_deref().is_some_and(|r| r.contains(&device) && r.contains(NS)))
        })
        .map_err(|e| format!("{e}; b1 → r1: {seen}"))?;
        cx.evidence(&format!("b1 → r1: {seen}"));
        let r1 = link_list(cx, "r1")?;
        if let Some(l) = r1.links.iter().find(|l| l.key.as_deref() == Some(b1_key.as_str()) && !l.paths.is_empty()) {
            return Err(format!("r1 links with b1: {}", shown(Some(l))));
        }
        cx.evidence(&format!("r1: serve {}; no link with b1", r1.serve.as_deref().unwrap_or("-")));
        Ok(())
    })?;

    let club_key = sc.step("club, the root device of /rc, runs an open relay (one link per namespace)", |cx| {
        let info = init_root(cx, "club", NS_C, "club")?;
        let club = cx.w.node_mut("club");
        club.cfg.identity = Some(info.identity);
        club.cfg.extra_toml = "[relays]\nnamespace = false\n\n[relay_service]\nserve = \"open\"\nlinks_per_namespace = 1\n".into();
        cx.start("club")?;
        let list = link_list(cx, "club")?;
        cx.evidence(&format!("club: serve {}", list.serve.as_deref().unwrap_or("-")));
        list.key.ok_or_else(|| "club's link list shows no key".to_owned())
    })?;
    sc.step(
        "the open relay admits b1 of /rb and refuses b2, its namespace's quota being used",
        |cx| {
            cx.w.node_mut("b1").cfg.extra_toml = user_relay(&club_key, CLUB);
            cx.stop("b1");
            cx.start("b1")?;
            let (took, line) = wait_relay(cx, "b1", &club_key, "linked", SHORT)?;
            cx.evidence(&format!(
                "b1 → club after {:.2}s: relay {line}",
                took.as_secs_f64()
            ));
            cx.w.node_mut("b2").cfg.extra_toml = user_relay(&club_key, CLUB);
            cx.stop("b2");
            cx.start("b2")?;
            let mut seen = String::new();
            wait_for(
                cx,
                "b2's relay club is down with the quota reason",
                SHORT,
                |cx| {
                    let list = link_list(cx, "b2")?;
                    let Some(l) = labelled(&list, &club_key) else {
                        return Ok(false);
                    };
                    seen = shown(Some(l));
                    Ok(relay_state(l) == "down"
                        && l.paths.is_empty()
                        && l.relay.as_deref().is_some_and(|r| r.contains(NS_B)))
                },
            )
            .map_err(|e| format!("{e}; b2 → club: {seen}"))?;
            cx.evidence(&format!("b2 → club: {seen}"));
            let club = link_list(cx, "club")?;
            let served: Vec<&str> = club
                .links
                .iter()
                .filter(|l| !l.paths.is_empty())
                .filter_map(|l| l.device.as_deref())
                .filter(|d| d.starts_with(&format!("{NS_B}/")))
                .collect();
            cx.evidence(&format!("club links with /rb devices {served:?}"));
            if served != [format!("{NS_B}/member/b1").as_str()] {
                return Err(format!(
                    "club links with /rb devices {served:?}, expected b1 only"
                ));
            }
            Ok(())
        },
    )?;

    let community = content(100_000, 64);
    sc.step(
        "club serves /ra by its root fingerprint; m1 and m2 add it with its expected fingerprint, and it carries their fetch",
        |cx| {
            cx.stop("b1");
            cx.stop("b2");
            cx.w.node_mut("club").cfg.extra_toml = format!(
                "[relays]\nnamespace = false\n\n[relay_service]\nserve = \"listed\"\nroots = [\"{}\"]\n",
                root.fp
            );
            cx.stop("club");
            cx.start("club")?;
            for m in ["m1", "m2"] {
                cx.w.node_mut(m).cfg.extra_toml = member_toml(&user_relay(&club_key, CLUB));
                cx.stop(m);
                cx.start(m)?;
                let (took, line) = wait_relay(cx, m, &club_key, "linked", SHORT)?;
                if !line.contains("source=user") {
                    return Err(format!("{m} → club: relay {line} (expected source=user)"));
                }
                let (_, r1) = wait_relay(cx, m, &n("/node/r1"), "standby", SHORT)?;
                cx.evidence(&format!("{m} → club after {:.2}s: relay {line}; → r1: relay {r1}", took.as_secs_f64()));
            }
            cx.publish("m1", &n("/member/m1/community"), &community, None, None)?;
            fetch_through(cx, "club", &n("/member/m1/community"), &community, SHORT)
        },
    )?;
    Ok(())
}
