//! folder: two people share a space of registers; one writes while the
//! other is away and pastes a long text; the other catches up — the data
//! layer's spaces and newest-wins registers (heap spec §1, §10) on real
//! daemons.
//!
//! Topology and gestures as in [`super::shared`]: alice (/fa) and bob
//! (/fb), each the root device of their namespace, pointing at each other,
//! linked through an open community relay (/fr) their trust contexts
//! advertise; no config holds a route, a UDP link, a `[[peer]]` or a
//! `[[relay]]`. Each person's device hosts its data layer with `ndn-heap`
//! (see [`super::data_host`]); alice's keeps its entries in a store
//! directory (`--store`).
//!
//! The register: every path of a space is one, built into the data layer —
//! its value is the head with the highest signed digest of the entries
//! nothing supersedes, `put` writes it.
//!
//! Proves: alice creates the space `/fa/32=data/notebook` (writers /fb,
//! readers /fb) and writes the cover. Bob reads the cover and writes a page;
//! alice reads it — both paths governed by the space's members alone. With
//! bob cut from the relay (nftables), alice writes the cover's title again
//! and page 1's body and then pastes 20 KiB into the body (the page's new
//! text, from a file; its entry carries it in pieces, its packet far smaller
//! than the paste): Bob's watch delivers none of them while he is away. Once
//! he is back he reads the cover and page 1 as alice does, the paste by its
//! length and SHA-256, and his watch delivers the cover's entry and the
//! paste's only now, each naming its path.

use std::fs;
use std::time::Duration;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::data_host::{CONVERGE, Host, Put, content_at, name};
use super::shared::{BOB, People, RELAY, people_through_relay};
use crate::scenarios::*;
use crate::step::{Abort, Scenario};
use crate::world::addr;

const NAMESPACES: People = People {
    a: "/fa",
    b: "/fb",
    relay: "/fr",
};
/// Alice's space and three of its paths.
const SPACE: &str = "/fa/32=data/notebook";
const COVER: &str = "cover";
const PAGE1: &str = "page1";
const PAGE2: &str = "page2";
/// Both people write and read.
const BOTH: &str = "writers=/fb readers=/fb";
/// The nftables table that cuts bob–relay.
const CUT_TABLE: &str = "ndn_e2e_folder_cut";
/// The paste: 20 KiB of text.
const PASTE_LEN: usize = 20 * 1024;
/// Page 1's text, and where the paste goes into it.
const DAY2: &str = "Day 2: the museum, then dinner by the river.";
const PASTE_AT: usize = 7;
/// How long bob's host prints nothing before every change it delivered so
/// far is taken in (the log checks; no verdict depends on it).
const QUIET: Duration = Duration::from_secs(2);

/// The watched change delivers one of `members`: the change.
fn counts_member(w: &Value, members: &[Put]) -> Option<String> {
    let change = &w["change"]["put"];
    members
        .iter()
        .find(|m| m.is(&change["id"]))
        .map(|m| format!("{}: {change}", m.name))
}

/// The watched change names its space and the path of entry `put`.
fn tagged(w: &Value, put: &Put) -> bool {
    let path = format!("/{}", put.path.trim_start_matches('/'));
    name(w["watch"].as_str().unwrap_or_default()).ok() == name(SPACE).ok()
        && name(w["change"]["put"]["path"].as_str().unwrap_or_default()).ok() == name(&path).ok()
}

/// The 20 KiB the paste puts: numbered lines of text.
fn paste_text() -> String {
    let mut text = String::with_capacity(PASTE_LEN + 64);
    let mut i = 0;
    while text.len() < PASTE_LEN {
        text.push_str(&format!(
            "{i:05}: train times, tickets and the hotel address\n"
        ));
        i += 1;
    }
    text.truncate(PASTE_LEN);
    text
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    let (alice_root, bob_root) = people_through_relay(sc, NAMESPACES)?;
    let store = sc.world.node("alice").dir.join("data-store");
    let alice_options = vec!["--store".to_owned(), store.display().to_string()];

    let (mut alice, mut bob) = sc.step(
        "start the data layer on alice's device (its entries kept in a store directory) and on \
         bob's",
        |cx| {
            cx.concept("data layer host (ndn-heap)");
            let alice = Host::start_with(cx, "alice", &alice_root.identity, &alice_options)?;
            let bob = Host::start(cx, "bob", &bob_root.identity)?;
            cx.evidence(&format!(
                "alice writes as {}, bob as {}",
                alice.writer, bob.writer
            ));
            Ok((alice, bob))
        },
    )?;
    let first = sc.step(
        "alice creates the space /fa/32=data/notebook (writers /fb, readers /fb) and writes the \
         cover: \"Trip notes\"",
        |cx| {
            cx.concept("space members");
            alice.ok(cx, &format!("create {SPACE} {BOTH}"))?;
            alice.ok(cx, &format!("watch {SPACE}"))?;
            bob.watch_when_ready(cx, SPACE)?;
            let first = alice.put(cx, SPACE, COVER, "Trip notes")?;
            let item = alice
                .item(cx, SPACE, COVER)?
                .ok_or("alice holds no value of her cover")?;
            if item["text"] != "Trip notes" {
                return Err(format!("alice's cover is {item}"));
            }
            cx.evidence(&format!(
                "alice created {SPACE}: {BOTH}; put {COVER}: {}; her cover: {item}",
                first.name
            ));
            Ok(first)
        },
    )?;
    sc.step(
        "bob reads the cover and writes page 2 (\"from bob\"); alice reads his page: both \
         paths governed by the space's members alone",
        |cx| {
            wait_for(cx, "bob reads the cover", CONVERGE, |cx| {
                Ok(bob
                    .item(cx, SPACE, COVER)?
                    .is_some_and(|item| first.is(&item["id"]) && item["text"] == "Trip notes"))
            })?;
            cx.evidence("bob's cover is alice's first entry: \"Trip notes\"");
            let caption = bob.put(cx, SPACE, PAGE2, "from bob")?;
            wait_for(cx, "alice reads bob's page", CONVERGE, |cx| {
                alice.holds(cx, SPACE, PAGE2, &caption)
            })?;
            let item = alice
                .item(cx, SPACE, PAGE2)?
                .ok_or("alice lost bob's page")?;
            if item["text"] != "from bob" {
                return Err(format!("alice's page 2 is {item}"));
            }
            cx.evidence(&format!("alice's page 2: {item}"));
            Ok(())
        },
    )?;

    if !crate::works(std::process::Command::new("nft").arg("--version")) {
        sc.skip(
            "writes and a paste while bob is away; bob catches up",
            "nft (nftables) not on PATH; run inside `nix-shell -p util-linux iproute2 nftables`",
        );
        return Ok(());
    }
    let cut = sc.step(
        "bob goes offline: nftables drops UDP between bob and the relay",
        |cx| {
            let cut = cut_udp(cx, CUT_TABLE, addr(BOB), addr(RELAY))?;
            cx.evidence(&format!(
                "dropping UDP between {} (bob) and {} (relay), both ways",
                addr(BOB),
                addr(RELAY)
            ));
            Ok(cut)
        },
    )?;
    let written = sc.step(
        "alice writes the cover's day-2 title and page 1's body while bob is away",
        |cx| {
            let cover = alice.put(cx, SPACE, COVER, "Trip notes, day 2")?;
            let body = alice.put(cx, SPACE, PAGE1, DAY2)?;
            cx.evidence(&format!("put: {}, {}", cover.name, body.name));
            Ok([cover, body])
        },
    )?;
    let (paste, pasted) = sc.step(
        "alice pastes 20 KiB into page 1 (the page's new text, from a file): one entry, \
         carried in pieces, its value the newest",
        |cx| {
            let file = cx.w.node("alice").dir.join("paste.txt");
            let text = paste_text();
            let mut body = DAY2.to_owned();
            body.insert_str(PASTE_AT, &text);
            fs::write(&file, &body).map_err(|e| format!("{}: {e}", file.display()))?;
            let paste = alice.put(cx, SPACE, PAGE1, &format!("@{}", file.display()))?;
            let item = alice
                .item(cx, SPACE, PAGE1)?
                .ok_or("alice holds no value of page 1")?;
            let expected = (
                body.len(),
                Sha256::digest(body.as_bytes())
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
            );
            if !paste.is(&item["id"])
                || item["len"] != expected.0
                || item["sha256"] != expected.1.as_str()
            {
                return Err(format!("alice's page 1 after the paste is {item}"));
            }
            let packet = content_at(cx, "alice", &paste.name)?;
            if packet.len() >= PASTE_LEN {
                return Err(format!(
                    "{} carries {} octets in its own packet: not in pieces",
                    paste.name,
                    packet.len()
                ));
            }
            cx.evidence(&format!(
                "put {PAGE1}: {} ({} octets in its packet, the text {} octets); alice's page 1: \
                 {} octets, sha256 {}",
                paste.name,
                packet.len(),
                body.len(),
                item["len"],
                item["sha256"]
            ));
            Ok((paste, expected))
        },
    )?;
    let members = [written[0].clone(), written[1].clone(), paste.clone()];
    let before = sc.step(
        "bob is still away: his watch has delivered none of the three entries; the nftables \
         table goes",
        |cx| {
            bob.drain(cx, QUIET)?;
            if let Some(early) = bob.watched.iter().find_map(|w| counts_member(w, &members)) {
                return Err(format!(
                    "bob's watch delivered an entry while he was away: {early}"
                ));
            }
            cx.evidence("bob's watch delivered none of alice's entries while he was away");
            drop(cut);
            cx.evidence("UDP between bob and the relay flows again");
            Ok(bob.watched.len())
        },
    )?;
    sc.step(
        "bob catches up: on the cover and page 1 he reads what alice reads (the paste's length \
         and SHA-256 equal; each the newest of alice's writes), the cover's entry and the \
         paste's delivered to his watch only now",
        |cx| {
            for (path, newest) in [(COVER, &members[0]), (PAGE1, &paste)] {
                let converged = wait_for(
                    cx,
                    &format!("bob reads {path} as alice does"),
                    CONVERGE,
                    |cx| {
                        Ok(bob.holds(cx, SPACE, path, newest)?
                            && alice.holds(cx, SPACE, path, newest)?)
                    },
                );
                if let Err(e) = converged {
                    // What bob makes of each path.
                    let seen = [COVER, PAGE1]
                        .iter()
                        .map(|p| {
                            Ok(format!(
                                "{p}: {:?}",
                                bob.call(cx, &format!("kept {SPACE} {p}"))?
                            ))
                        })
                        .collect::<Result<Vec<_>, String>>()?;
                    return Err(format!("{e}; bob reads {}", seen.join("; ")));
                }
                let item = alice.item(cx, SPACE, path)?.ok_or("alice lost a path")?;
                cx.evidence(&format!("{path}: alice and bob read {}", item["id"]));
            }
            let page1 = bob
                .item(cx, SPACE, PAGE1)?
                .ok_or("bob holds no value of page 1")?;
            if page1["len"] != pasted.0 || page1["sha256"] != pasted.1.as_str() {
                return Err(format!(
                    "bob's page 1 is {page1}, not the paste ({} octets, {})",
                    pasted.0, pasted.1
                ));
            }
            for m in [&members[0], &paste] {
                let w =
                    bob.watched_until(cx, &format!("{} in bob's watch", m.name), CONVERGE, |w| {
                        counts_member(w, std::slice::from_ref(m)).is_some()
                    })?;
                if !bob.watched[before..].contains(&w) {
                    return Err(format!(
                        "bob's watch delivered {} while he was away",
                        m.name
                    ));
                }
                if !tagged(&w, m) {
                    return Err(format!(
                        "bob's space watch did not name {}'s path: {w}",
                        m.name
                    ));
                }
                cx.evidence(&format!("bob's watch, of {}: {}", w["watch"], w["change"]));
            }
            Ok(())
        },
    )?;
    Ok(())
}
