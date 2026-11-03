//! notes: one person's note, written on two devices apart, merged when they
//! meet again — the data layer (`ndn_data::Device`) on real daemons.
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

use std::process::Command;

use serde_json::Value;

use super::data_host::{CONVERGE, Host, carries_group, includes, key_locator, name, unanswered};
use crate::scenarios::*;
use crate::step::{Abort, Scenario};
use crate::world::{CaCfg, NodeCfg, PeerCfg, addr};

const NS: &str = "/nt";
/// The note collection, in the person's namespace: `<ns>/32=data/<path>`
/// (data-layer spec §3).
const NOTES: &str = "/nt/32=data/notes/trip";
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
            laptop.put(cx, NOTES, "text=\"day 1\"")
        },
    )?;
    sc.step(
        "the phone watches the notes and reads them until it holds day 1",
        |cx| {
            phone.ok(cx, &format!("watch {NOTES}"))?;
            wait_for(cx, "the phone holds day 1", SHORT, |cx| {
                Ok(phone
                    .state(cx, NOTES)?
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
            let plane = laptop.put(cx, NOTES, "text=\"on the plane\"")?;
            let trip = phone.put(cx, NOTES, "tags=trip")?;
            let taxi = phone.put(cx, NOTES, "text=\"in the taxi\"")?;
            let (at, value) = laptop
                .state(cx, NOTES)?
                .ok_or("the laptop holds no state of its own notes")?;
            if !includes(&at, &plane) || includes(&at, &trip) || includes(&at, &taxi) {
                return Err(format!("the laptop's state while apart is at {at}"));
            }
            cx.evidence(&format!("laptop apart: at {at}, value {value}"));
            let (at, value) = phone
                .state(cx, NOTES)?
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
                let (Some(l), Some(p)) = (laptop.state(cx, NOTES)?, phone.state(cx, NOTES)?) else {
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
            let read_day1 = phone.version(cx, NOTES, &day1)?;
            let read_plane = phone.version(cx, NOTES, &plane)?;
            let read_trip = laptop.version(cx, NOTES, &trip)?;
            let read_taxi = laptop.version(cx, NOTES, &taxi)?;
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
