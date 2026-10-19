//! membership: direct paths by membership, under the namespace's role
//! matrix, with no peer entry naming the other device.
//!
//! Topology: root (10.200.0.1, root device + CA) ← UDP ← relay (.2, a
//! `node` device listening for QUIC links) on the harness's `lo`. Three
//! port-restricted cone NAT boxes (`nat.rs`): m1 behind A (dialling only)
//! and m2 behind B (listening on its LAN address), members, and visitor
//! behind C (dialling only), a guest (`/mb/guest/visitor`) by a guest invite. Each names only
//! the relay (`[[peer]]` with its endpoint) and enrolls by invite over its
//! enrollment link. The trust context states no `direct_pairs`: the default
//! matrix (admin, member and node pairs; guests none).
//!
//! Proves: the two members get a direct path at the other box's public
//! address, and a fetch between them then costs the relay no packet; the
//! guest gets no direct path and learns of no member — its link list shows
//! no member, so no member's address, and no member's lists the guest —
//! while it still reaches a member's Data through the relay; once the
//! guest names a member as reached through the relay, its status says the
//! role matrix allows no direct path between guest and member devices.

use std::net::Ipv4Addr;
use std::thread;
use std::time::{Duration, Instant};

use super::direct_paths::{LinkList, PathLine, link_list, quic_faces};
use crate::nat::{Nat, NatKind};
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{CaCfg, NodeCfg, PeerCfg, addr};

const NS: &str = "/mb";
const SEGMENT: usize = 8192;
const BOX_A: u8 = 1;
const BOX_B: u8 = 2;
const BOX_C: u8 = 3;

fn n(s: &str) -> String {
    format!("{NS}{s}")
}

/// The direct path in `list` to `device`.
fn direct_to<'a>(list: &'a LinkList, device: &str) -> Option<&'a PathLine> {
    list.to(device, None).and_then(|l| l.direct_path())
}

/// Packets the relay exchanged on its links with the boxes `publics`.
fn relay_packets(cx: &mut Cx<'_>, publics: &[Ipv4Addr]) -> StepResult<u64> {
    Ok(quic_faces(cx, "relay")?
        .into_iter()
        .filter(|(r, _)| publics.contains(r.ip()))
        .map(|(_, p)| p)
        .sum())
}

/// `node` behind the box with address `public` links to the relay, seen at
/// that address, and enrolls by `invite` as `device`; `hello` (the relay's
/// Data) then reaches it over the full link.
fn link_and_enroll(cx: &mut Cx<'_>, node: &str, public: Ipv4Addr, invite: &Invite, hello: &[u8]) -> StepResult<()> {
    cx.start(node)?;
    wait_for(cx, &format!("the relay links to {node} at {public}"), SHORT, |cx| {
        Ok(quic_faces(cx, "relay")?.iter().any(|(r, _)| *r.ip() == public))
    })?;
    enroll(cx, node, invite, node, false, None)?;
    fetch_within(cx, node, &n("/node/relay/hello"), hello, SHORT)
}

/// Every `remote=` address in `list`.
fn remotes(list: &LinkList) -> Vec<String> {
    list.links
        .iter()
        .flat_map(|l| l.paths.iter())
        .filter_map(|p| p.remote.map(|r| r.to_string()))
        .collect()
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    if let Some(why) = Nat::missing() {
        sc.skip("build NAT boxes (nested network namespaces with nftables)", &why);
        return Ok(());
    }
    sc.step("build NAT boxes A, B and C (port-restricted cone)", |cx| {
        let mut nat = Nat::new(cx.w.dir.join("nat"))?;
        for _ in 0..3 {
            let k = nat.add_box(NatKind::Cone)?;
            let b = nat.nat_box(k);
            cx.evidence(&format!("box {k}: public {}, device {} on its LAN", b.public, b.device_ip));
        }
        cx.w.nat = Some(nat);
        Ok(())
    })?;
    let public = |sc: &Scenario, k: u8| sc.world.nat.as_ref().expect("NAT boxes").nat_box(k).public;
    let (pub_a, pub_b, pub_c) = (public(sc, BOX_A), public(sc, BOX_B), public(sc, BOX_C));

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
            ..base.clone()
        },
    );
    let relay_peer = PeerCfg {
        device: Some(n("/node/relay")),
        endpoint: Some(addr(2)),
        ..Default::default()
    };
    let dialling = NodeCfg {
        peers: vec![relay_peer.clone()],
        quic_dial_only: true,
        ..base.clone()
    };
    sc.world.add_behind("m1", BOX_A, dialling.clone());
    sc.world.add_behind(
        "m2",
        BOX_B,
        NodeCfg {
            peers: vec![relay_peer],
            quic_listen: true,
            ..base.clone()
        },
    );
    sc.world.add_behind("visitor", BOX_C, dialling);

    let root = sc.step("init the root device (default direct-path role matrix)", |cx| init_root(cx, "root", NS, "home"))?;
    let (members, guests) = sc.step("mint two member invites and one guest invite", |cx| {
        Ok((
            mint(cx, NS, &root.fp, 2, Some("2h"))?,
            mint_as(cx, NS, &root.fp, "guest", 1, Some("2h"))?,
        ))
    })?;
    sc.step("start the root device's daemon with its CA", |cx| {
        cx.w.node_mut("root").cfg.identity = Some(root.identity.clone());
        cx.w.node_mut("root").cfg.ca = Some(CaCfg {
            prefix: NS.into(),
            identity: n("/CA"),
            tokens: members.iter().chain(&guests).map(|i| i.token.clone()).collect(),
            member_days: None,
        });
        cx.start("root")
    })?;
    let hello = content(2_000, 90);
    sc.step("start the relay (listening for QUIC links), adopt, become a node device on approval, serve a greeting", |cx| {
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
    // When each side had what it needs to punch: m2 enrolled (both
    // members linked to the relay as members), and the guest enrolled.
    let (members_ready, guest_ready) = sc.step("m1 (box A) and m2 (box B), members, and visitor (box C), a guest, link to the relay and enroll by invite", |cx| {
        link_and_enroll(cx, "m1", pub_a, &members[0], &hello)?;
        link_and_enroll(cx, "m2", pub_b, &members[1], &hello)?;
        let members_ready = Instant::now();
        link_and_enroll(cx, "visitor", pub_c, &guests[0], &hello)?;
        let guest_ready = Instant::now();
        let certs = cx.certs("visitor");
        if !certs.iter().any(|c| c.starts_with(&n("/guest/visitor/KEY/"))) {
            return Err(format!("visitor holds no {} certificate: {certs:?}", n("/guest/visitor")));
        }
        Ok((members_ready, guest_ready))
    })?;

    let members_took = sc.step("m1 and m2, with no [[peer]] for each other, get a direct path at the other box's public address", |cx| {
        let (d1, d2) = (n("/member/m1"), n("/member/m2"));
        let took = wait_for(cx, "a direct path between m1 and m2 by membership", Duration::from_secs(45), |cx| {
            let l1 = link_list(cx, "m1")?;
            let l2 = link_list(cx, "m2")?;
            let at = |p: Option<&PathLine>, ip: Ipv4Addr| p.and_then(|p| p.remote).is_some_and(|r| *r.ip() == ip);
            Ok(at(direct_to(&l1, &d2), pub_b) && at(direct_to(&l2, &d1), pub_a))
        })?;
        // At most this long after both enrolled (seen by now, so an upper
        // bound).
        let since_ready = members_ready.elapsed();
        for (from, to) in [("m1", &d2), ("m2", &d1)] {
            let list = link_list(cx, from)?;
            let l = list.to(to, None).ok_or_else(|| format!("{from} shows no link to {to}"))?;
            let path = l.direct_path().map(|p| p.text.clone()).unwrap_or_default();
            cx.evidence(&format!("after {:.2}s: {from} → {to}: path {path}; direct {}", took.as_secs_f64(), l.direct));
        }
        cx.evidence(&format!("up at most {:.2}s after m2 enrolled", since_ready.as_secs_f64()));
        Ok(since_ready)
    })?;

    let warm = content(2_000, 91);
    let album = content(400_000, 92);
    sc.step("m2 fetches m1's 400 KB object over the direct path: the relay carries none of it", |cx| {
        // The first fetch brings m1's certificate to m2; the counted one
        // needs nothing else.
        cx.publish("m1", &n("/member/m1/warm"), &warm, None, None)?;
        fetch_within(cx, "m2", &n("/member/m1/warm"), &warm, SHORT)?;
        cx.publish("m1", &n("/member/m1/album"), &album, None, None)?;
        let before = relay_packets(cx, &[pub_a, pub_b])?;
        fetch_within(cx, "m2", &n("/member/m1/album"), &album, SHORT)?;
        let after = relay_packets(cx, &[pub_a, pub_b])?;
        cx.evidence(&format!(
            "{} segments; relay packets on m1's and m2's links {before} → {after} (+{})",
            album.len().div_ceil(SEGMENT),
            after.saturating_sub(before)
        ));
        if after != before {
            return Err(format!("the relay carried {} packets of the fetch", after.saturating_sub(before)));
        }
        Ok(())
    })?;

    let note = content(30_000, 93);
    sc.step("the guest gets no direct path and learns of no member; it reaches m1's Data through the relay", |cx| {
        // As long again since the guest enrolled as the members took, and
        // more (at least 2 s).
        let window = (members_took * 2).max(Duration::from_secs(2));
        if let Some(left) = window.checked_sub(guest_ready.elapsed()) {
            thread::sleep(left);
        }
        cx.evidence(&format!(
            "looked {:.2}s after the guest enrolled (the members had their direct path within {:.2}s)",
            guest_ready.elapsed().as_secs_f64(),
            members_took.as_secs_f64()
        ));
        let guest = link_list(cx, "visitor")?;
        let members_seen: Vec<String> = guest
            .links
            .iter()
            .filter(|l| l.label.starts_with(&n("/member/")) || l.device.as_deref().is_some_and(|d| d.starts_with(&n("/member/"))))
            .map(|l| l.label.clone())
            .collect();
        let relay = format!("{}:{}", addr(2), crate::world::QUIC_PORT);
        let addresses: Vec<String> = remotes(&guest).into_iter().filter(|r| *r != relay).collect();
        cx.evidence(&format!(
            "guest's link list: links {:?}; remote addresses {:?}",
            guest.links.iter().map(|l| l.label.as_str()).collect::<Vec<_>>(),
            remotes(&guest)
        ));
        if !members_seen.is_empty() || !addresses.is_empty() {
            return Err(format!("the guest learned of members {members_seen:?} / addresses {addresses:?}"));
        }
        for m in ["m1", "m2"] {
            let list = link_list(cx, m)?;
            if let Some(l) = list.to(&n("/guest/visitor"), guest.key.as_deref()) {
                return Err(format!("{m} lists the guest: direct {}; {} path(s)", l.direct, l.paths.len()));
            }
        }
        cx.evidence("neither m1 nor m2 lists the guest");
        cx.publish("m1", &n("/member/m1/note"), &note, None, None)?;
        let before = relay_packets(cx, &[pub_c])?;
        fetch_within(cx, "visitor", &n("/member/m1/note"), &note, SHORT)?;
        let after = relay_packets(cx, &[pub_c])?;
        cx.evidence(&format!("guest fetched m1's note; relay packets on the guest's link {before} → {after}"));
        if after == before {
            return Err("the guest's fetch did not go through the relay".into());
        }
        Ok(())
    })?;

    sc.step("the guest names m1, reached through the relay: its status says the role matrix allows none", |cx| {
        cx.w.node_mut("visitor").cfg.peers.push(PeerCfg {
            device: Some(n("/member/m1")),
            relay: Some(n("/node/relay")),
            ..Default::default()
        });
        cx.stop("visitor");
        cx.start("visitor")?;
        let start = Instant::now();
        let mut seen = String::new();
        wait_for(cx, "the guest's direct state toward m1 is off with a reason", SHORT, |cx| {
            let list = link_list(cx, "visitor")?;
            let Some(l) = list.to(&n("/member/m1"), None) else { return Ok(false) };
            if let Some(p) = l.direct_path() {
                return Err(format!("the guest has a direct path to m1: path {}", p.text));
            }
            seen = l.direct.clone();
            let (state, text) = l.direct_state();
            Ok(state == "off" && text.contains("guest") && text.contains("member"))
        })
        .map_err(|e| format!("{e}; guest → m1: direct {seen}"))?;
        cx.evidence(&format!("after {:.2}s: guest → m1: direct {seen}", start.elapsed().as_secs_f64()));
        let list = link_list(cx, "visitor")?;
        let addresses: Vec<String> = remotes(&list)
            .into_iter()
            .filter(|r| !r.starts_with(&format!("{}:", addr(2))))
            .collect();
        if !addresses.is_empty() {
            return Err(format!("the guest learned addresses {addresses:?}"));
        }
        Ok(())
    })?;
    Ok(())
}
