//! notes: one person's note, written on two devices apart, merged when they
//! meet again — the data layer (`ndn_heap::Node`) on real daemons.
//!
//! Topology, on the harness's `lo`: laptop (10.200.0.1, the root device of
//! /nt as /nt/admin/laptop, with its CA) ↔ phone (.2, a member enrolled by
//! invite). The phone enrolls over a UDP face that routes `/nt` (the CA,
//! the namespace's certificates) to the laptop, and names the laptop as its
//! QUIC peer (`[[peer]] device = "/nt/admin/laptop"`): once enrolled it
//! links to it by itself. The link library routes each device's name to
//! the other and the namespace's sync group `/nt/32=sync` over that link
//! while it is up, and the trust-context library runs the group with the
//! multicast strategy on each daemon, since each holds /nt: nothing in
//! either config names the group or its strategy (data-layer spec §12).
//!
//! Each device runs `ndn-heap` (ndn-tools) on its daemon's socket: the
//! device's data layer with the key `ndn-fwd init`/`enroll` put in the PIB,
//! verifying with the PIB's trust context, driven line by line over stdin
//! and answering one JSON object per line — standing in for the host an app
//! runs in, not for anything the person does.
//!
//! Proves: the laptop creates a notes space (owner alone, sealed) and writes
//! "day 1" at `trip` (a path of the space: one newest-wins register); the
//! phone reads that entry. With UDP between the two cut (nftables), the
//! laptop writes "on the plane" while the phone writes "trip" and then "in
//! the taxi", each seeing only its own (neither daemon gets the other's new
//! entry); once the link is back both read the same value with no step by
//! the person, the value being the head with the highest signed digest (the
//! register's newest of the two heads, the offline entries). Every entry is
//! named `<its device>/32=log/<space>/seq=<n>`, the two devices write with
//! different keys (each the key its PIB certifies), each offline entry
//! supersedes `day 1` and neither side's offline entries name the other's
//! (they are concurrent; read from the entries' `after` as a daemon fetches
//! them); the laptop's next write supersedes both heads, which it therefore
//! holds; the watches delivered the other device's entries; and each daemon
//! fetches the other device's log entries, validating them against /nt's
//! trust context, with the writer device's key as KeyLocator.

use std::process::Command;

use super::data_host::{
    CONVERGE, Host, Put, carries_group, entry_at, highest, key_locator, name, stored, supersedes,
    unanswered,
};
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario};
use crate::world::{CaCfg, NodeCfg, PeerCfg, addr};

const NS: &str = "/nt";
/// The notes space, in the person's namespace: `<ns>/32=data/<c1>`
/// (heap spec §2), and the register path in it.
const SPACE: &str = "/nt/32=data/notes";
const TRIP: &str = "trip";
const PHONE: &str = "/nt/member/phone";
/// The laptop's device name: `ndn-fwd init --device laptop` on /nt.
const LAPTOP: &str = "/nt/admin/laptop";
/// The namespace's sync group (data-layer spec §12).
const GROUP: &str = "/nt/32=sync";
/// The nftables table that cuts laptop–phone.
const CUT_TABLE: &str = "ndn_e2e_notes_cut";

fn n(s: &str) -> String {
    format!("{NS}{s}")
}

/// `ndn-heap` options of a device's host: its entries kept in a store
/// directory of its node, which the steps read to see what it holds.
fn store(cx: &Cx<'_>, node: &str) -> Vec<String> {
    vec![
        "--store".to_owned(),
        cx.w.node(node).dir.join("data-store").display().to_string(),
    ]
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    sc.world.add(
        "laptop",
        1,
        NodeCfg {
            links: vec![link("phone", 2)],
            quic_listen: true,
            ..Default::default()
        },
    );
    sc.world.add(
        "phone",
        2,
        NodeCfg {
            links: vec![link("laptop", 1)],
            routes: vec![route(NS, "laptop")],
            peers: vec![PeerCfg {
                device: Some(LAPTOP.into()),
                endpoint: Some(addr(1)),
                ..Default::default()
            }],
            quic_dial_only: true,
            ..Default::default()
        },
    );

    let root = sc.step("init the laptop as the root device of /nt", |cx| {
        let root = init_root(cx, "laptop", NS, "laptop")?;
        if root.identity != LAPTOP {
            return Err(format!(
                "the laptop is {}, not {LAPTOP} (the phone's peer entry)",
                root.identity
            ));
        }
        Ok(root)
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
        "start the phone's daemon; the phone enrolls as /nt/member/phone over its UDP face",
        |cx| {
            cx.start("phone")?;
            let c = enroll(cx, "phone", &invites[0], "phone", false, None)?;
            if !c.starts_with(&format!("{PHONE}/KEY/")) {
                return Err(format!("unexpected certificate {c}"));
            }
            Ok(c)
        },
    )?;
    sc.step(
        "enrolled, the phone links to the laptop over QUIC: each daemon routes the other \
         device and /nt/32=sync over the link and runs the group with multicast, none of it \
         configured",
        |cx| {
            cx.concept("sync group carried by the trust-context and link libraries");
            for (node, peer) in [("laptop", PHONE), ("phone", LAPTOP)] {
                let mut found = None;
                wait_for(
                    cx,
                    &format!("{node} carries {GROUP} over its link to {peer}"),
                    SHORT,
                    |cx| {
                        found = carries_group(cx, node, peer, GROUP)?;
                        Ok(found.is_some())
                    },
                )?;
                cx.evidence(&found.unwrap_or_default());
            }
            Ok(())
        },
    )?;

    let (mut laptop, mut phone) = sc.step(
        "start the data layer on each device (ndn-heap on its daemon, signing with its own key)",
        |cx| {
            cx.concept("data layer host (ndn-heap)");
            let laptop = Host::start_with(cx, "laptop", &root.identity, &store(cx, "laptop"))?;
            let phone = Host::start_with(cx, "phone", PHONE, &store(cx, "phone"))?;
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
        "the laptop creates the notes space (owner alone) and writes \"day 1\" at trip",
        |cx| {
            laptop.ok(cx, &format!("create {SPACE}"))?;
            laptop.ok(cx, &format!("watch {SPACE}"))?;
            laptop.put(cx, SPACE, TRIP, "day 1")
        },
    )?;
    sc.step(
        "the phone watches the notes and reads them until it holds day 1",
        |cx| {
            phone.ok(cx, &format!("watch {SPACE}"))?;
            wait_for(cx, "the phone holds day 1", SHORT, |cx| {
                Ok(phone
                    .item(cx, SPACE, TRIP)?
                    .is_some_and(|item| day1.is(&item["id"]) && item["text"] == "day 1"))
            })?;
            cx.evidence("the phone's value at trip is day 1's entry, \"day 1\"");
            Ok(())
        },
    )?;
    sc.step(
        "each device reads an entry of the other's (at `sync/<device>`), so both hold the key of \
         the epoch in force before the link is cut",
        |cx| {
            let from_laptop = laptop.put(cx, SPACE, "sync/laptop", "ready")?;
            wait_for(cx, "the phone reads the laptop's entry", SHORT, |cx| {
                phone.holds(cx, SPACE, "sync/laptop", &from_laptop)
            })?;
            let from_phone = phone.put(cx, SPACE, "sync/phone", "ready")?;
            wait_for(cx, "the laptop reads the phone's entry", SHORT, |cx| {
                laptop.holds(cx, SPACE, "sync/phone", &from_phone)
            })?;
            cx.evidence("each device read the other's sealed entry: both hold the epoch's key");
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
        "apart: the laptop writes \"on the plane\"; the phone writes \"trip\", then \"in the \
         taxi\"; each holds only its own",
        |cx| {
            let plane = laptop.put(cx, SPACE, TRIP, "on the plane")?;
            let trip = phone.put(cx, SPACE, TRIP, "trip")?;
            let taxi = phone.put(cx, SPACE, TRIP, "in the taxi")?;
            let item = laptop
                .item(cx, SPACE, TRIP)?
                .ok_or("the laptop holds no value of its own notes")?;
            if !plane.is(&item["id"]) || item["text"] != "on the plane" {
                return Err(format!("the laptop's value while apart is {item}"));
            }
            cx.evidence(&format!("laptop apart: {item}"));
            let item = phone
                .item(cx, SPACE, TRIP)?
                .ok_or("the phone holds no value of the notes")?;
            if !taxi.is(&item["id"]) || item["text"] != "in the taxi" {
                return Err(format!("the phone's value while apart is {item}"));
            }
            cx.evidence(&format!("phone apart: {item}"));
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
        "both devices read one value, with no step by the person: the head with the highest \
         digest",
        |cx| {
            // The heads are the two offline entries that end each side's line
            // (day 1 and the trip tag are superseded); the register's value is
            // the one with the highest signed digest.
            let want = highest(&[&plane, &taxi]);
            wait_for(cx, "laptop and phone read one value", CONVERGE, |cx| {
                Ok(laptop.holds(cx, SPACE, TRIP, want)? && phone.holds(cx, SPACE, TRIP, want)?)
            })?;
            // The winner alone says nothing of the loser: a device that holds
            // the winner may not yet have taken the other head, and its next
            // entry would supersede only what it holds. Each device holds
            // both heads' entries before anyone writes again.
            for (node, head) in [("laptop", &taxi), ("phone", &plane)] {
                let dir = cx.w.node(node).dir.join("data-store");
                let wanted = name(&head.name)?;
                wait_for(cx, &format!("{node} holds {}", head.name), CONVERGE, |_| {
                    Ok(stored(&dir)?.iter().any(|(n, _)| *n == wanted))
                })?;
            }
            let item = laptop
                .item(cx, SPACE, TRIP)?
                .ok_or("the laptop lost its value")?;
            cx.evidence(&format!(
                "both read {item}: the head with the highest digest ({})",
                want.digest
            ));
            Ok(())
        },
    )?;
    let merged = sc.step(
        "the laptop writes \"home\": its entry supersedes both heads, so the laptop holds the \
         plane's and the taxi's entries",
        |cx| {
            let merged = laptop.put(cx, SPACE, TRIP, "home")?;
            let entry = entry_at(cx, "laptop", &merged)?;
            if !supersedes(&entry, &plane) || !supersedes(&entry, &taxi) {
                return Err(format!(
                    "the laptop's next entry supersedes {:?}, not both heads ({}, {})",
                    entry.after, plane.name, taxi.name
                ));
            }
            wait_for(cx, "the phone reads home", CONVERGE, |cx| {
                phone.holds(cx, SPACE, TRIP, &merged)
            })?;
            cx.evidence(&format!(
                "{} supersedes {} and {}; the phone reads \"home\"",
                merged.name, plane.name, taxi.name
            ));
            Ok(merged)
        },
    )?;
    sc.step(
        "each device's entries are named by their writer and the offline entries' parents \
         include day 1 and not each other",
        |cx| {
            let read_day1 = entry_at(cx, "phone", &day1)?;
            let read_plane = entry_at(cx, "phone", &plane)?;
            let read_trip = entry_at(cx, "laptop", &trip)?;
            let read_taxi = entry_at(cx, "laptop", &taxi)?;
            cx.evidence(&format!(
                "phone reads {}: after {:?}",
                day1.name, read_day1.after
            ));
            // `after` of `plane` and `trip` is what each superseded: day 1;
            // `taxi` supersedes `trip` (the phone wrote it after reading it).
            for (label, entry) in [("on the plane", &read_plane), ("trip", &read_trip)] {
                if !supersedes(entry, &day1) {
                    return Err(format!(
                        "{label}'s entry does not supersede day 1: {:?}",
                        entry.after
                    ));
                }
                cx.evidence(&format!("{label}: after {:?}", entry.after));
            }
            if supersedes(&read_plane, &trip)
                || supersedes(&read_plane, &taxi)
                || supersedes(&read_trip, &plane)
                || supersedes(&read_taxi, &plane)
            {
                return Err("the offline entries name each other as parents".into());
            }
            if !supersedes(&read_taxi, &trip) {
                return Err(format!(
                    "in the taxi's entry does not supersede \"trip\": {:?}",
                    read_taxi.after
                ));
            }
            Ok(())
        },
    )?;
    sc.step("the watches delivered the other device's entries", |cx| {
        // Draining what arrived since the last answer.
        phone.ok(cx, &format!("members {SPACE}"))?;
        laptop.ok(cx, &format!("members {SPACE}"))?;
        let delivered = |host: &Host, put: &Put| {
            host.watched
                .iter()
                .any(|w| put.is(&w["change"]["put"]["id"]))
        };
        // The phone's watch was told of day 1 (the laptop's) and, since "home"
        // decided the path last, of "home"; the laptop's watch of "home" too.
        for (host, put) in [(&phone, &day1), (&phone, &merged), (&laptop, &merged)] {
            if !delivered(host, put) {
                return Err(format!(
                    "{}'s watch was not told of {}: {:?}",
                    host.node, put.name, host.watched
                ));
            }
        }
        cx.evidence("the phone's watch delivered day 1 and home; the laptop's, home");
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
