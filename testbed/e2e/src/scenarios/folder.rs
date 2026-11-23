//! folder: two people share a folder of registers under the built-in merge
//! rule; one writes while the other is away and pastes a long text; the
//! other catches up — the data layer's folder records and rules by name
//! (data-layer spec §6.1, §13) on real daemons.
//!
//! Topology and gestures as in [`super::shared`]: alice (/fa) and bob
//! (/fb), each the root device of their namespace, pointing at each other,
//! linked through an open community relay (/fr) their trust contexts
//! advertise; no config holds a route, a UDP link, a `[[peer]]` or a
//! `[[relay]]`. Each person's device hosts its data layer with `ndn-data`
//! (see [`super::data_host`]); alice's keeps its entries in a store
//! directory (`--store`).
//!
//! The rule: `/ndf/merge/newest/v=1`, built into the data layer — a
//! register holds the bytes of its newest version (the head with the
//! highest digest of the versions nothing supersedes), `put_op` writes it.
//!
//! Proves: alice shares the folder `/fa/32=data/notebook` (the newest
//! register, writers /fa and /fb, readers both people) with `share_folder`,
//! and writes the cover. A collection under it that names a rule no device
//! knows is held unreadable: `get` answers RuleUnknown naming the rule
//! (next: update the program). Bob reads the cover and writes a page; alice
//! reads it — both collections governed by the folder record alone. With
//! bob cut from the relay (nftables), alice writes the cover's title again
//! and page 1's body (`put_op`) and then pastes 20 KiB into the body (the
//! page's new text, from a file; its version carries it in pieces, its
//! packet far smaller than the paste): Bob's watch delivers none of them while
//! he is away. Once he is back he reads all three: on the cover and page 1
//! the same frontier and value as alice, every version delivered to his
//! watch only now, each named with its collection.

use std::fs;
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::data_host::{CONVERGE, Host, Put, includes, name};
use super::shared::{BOB, People, RELAY, content_at, people_through_relay};
use crate::scenarios::*;
use crate::step::{Abort, Scenario};
use crate::world::addr;

const NAMESPACES: People = People {
    a: "/fa",
    b: "/fb",
    relay: "/fr",
};
/// Alice's folder and three of its elements.
const FOLDER: &str = "/fa/32=data/notebook";
const COVER: &str = "/fa/32=data/notebook/cover";
const PAGE1: &str = "/fa/32=data/notebook/page1";
const PAGE2: &str = "/fa/32=data/notebook/page2";
const APPENDIX: &str = "/fa/32=data/notebook/appendix";
/// A merge rule by a name no program here implements.
const OTHER: &str = "/ndn-tools/merge/element/v=1";
/// Both people write and read.
const BOTH: &str = "writers=/fa,/fb readers=person:/fa,person:/fb";
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

/// A frontier entry or id (`{writer, seq}`) is version `v`.
fn is(id: &Value, v: &Put) -> bool {
    id["writer"] == v.writer.as_str() && id["seq"] == v.seq
}

/// The watched change delivers one of `members`.
fn counts_member(w: &Value, members: &[Put]) -> Option<String> {
    let change = &w["change"];
    members
        .iter()
        .find(|m| is(&change["version"]["id"], m))
        .map(|m| format!("{}: {change}", m.name))
}

/// The watched change names its collection: one under the folder, and for
/// a version the version's own.
fn tagged(w: &Value) -> bool {
    let tag = w["collection"].as_str().unwrap_or_default();
    let under = match (name(tag), name(FOLDER)) {
        (Ok(t), Ok(f)) => t.has_prefix(&f) && t != f,
        _ => false,
    };
    let version = &w["change"]["version"];
    under && (!version.is_object() || version["collection"] == tag)
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
            cx.concept("data layer host (ndn-data)");
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
        "alice shares the folder /fa/32=data/notebook (the newest register, writers /fa,/fb, \
         readers person:/fa,person:/fb) and writes the cover: \"Trip notes\"",
        |cx| {
            cx.concept("folder members record");
            alice.ok(cx, &format!("share_folder {FOLDER} rule=merge {BOTH}"))?;
            alice.ok(cx, &format!("watch {FOLDER}"))?;
            bob.ok(cx, &format!("watch {FOLDER}"))?;
            let first = alice.put_op(cx, COVER, "Trip notes")?;
            let (_, value) = alice
                .state(cx, COVER)?
                .ok_or("alice holds no state of her cover")?;
            if value["bytes"] != "Trip notes" {
                return Err(format!("alice's cover value is {value}"));
            }
            cx.evidence(&format!(
                "alice shared {FOLDER}: {BOTH}; put_op {COVER}: {}; her cover: {value}",
                first.name
            ));
            Ok(first)
        },
    )?;
    sc.step(
        "alice shares the appendix under a rule no device knows (/ndn-tools/merge/element/v=1, \
         which no program here implements): get answers RuleUnknown naming the rule (next: \
         update the program) at alice's device and at bob's",
        |cx| {
            cx.concept("merge rules by name");
            alice.ok(cx, &format!("share {APPENDIX} rule=merge:{OTHER} {BOTH}"))?;
            for host in [&mut alice, &mut bob] {
                let mut last = Value::Null;
                wait_for(
                    cx,
                    &format!("{}'s get of the appendix answers RuleUnknown", host.node),
                    CONVERGE,
                    |cx| match host.call(cx, &format!("get {APPENDIX}"))? {
                        // Nothing held yet: the appendix's own record has not
                        // reached this device, the folder's applies meanwhile.
                        Ok(ok) if ok["state"]["at"] == json!([]) => Ok(false),
                        Ok(ok) => Err(format!(
                            "{} reads the appendix under no rule: {ok}",
                            host.node
                        )),
                        Err(e) => {
                            let unknown = e["next"] == "update-program";
                            last = e;
                            Ok(unknown)
                        }
                    },
                )?;
                if name(last["rule_unknown"]["rule"].as_str().unwrap_or_default())? != name(OTHER)?
                    || last["retry"] != false
                {
                    return Err(format!("{}'s RuleUnknown answer is {last}", host.node));
                }
                cx.evidence(&format!(
                    "{}> get {APPENDIX}: {} (next: {}; rule {})",
                    host.node, last["message"], last["next"], last["rule_unknown"]["rule"]
                ));
            }
            Ok(())
        },
    )?;
    sc.step(
        "bob reads the cover and writes page 2 (\"from bob\"); alice reads his page: both \
         elements governed by the folder record alone",
        |cx| {
            wait_for(cx, "bob reads the cover", CONVERGE, |cx| {
                Ok(bob
                    .state(cx, COVER)?
                    .is_some_and(|(at, v)| includes(&at, &first) && v["bytes"] == "Trip notes"))
            })?;
            cx.evidence("bob's cover state includes alice's first version: \"Trip notes\"");
            let caption = bob.put_op(cx, PAGE2, "from bob")?;
            let mut value = Value::Null;
            wait_for(cx, "alice reads bob's page", CONVERGE, |cx| {
                Ok(alice.state(cx, PAGE2)?.is_some_and(|(at, v)| {
                    value = v;
                    includes(&at, &caption)
                }))
            })?;
            if value["bytes"] != "from bob" {
                return Err(format!("alice's page 2 value is {value}"));
            }
            cx.evidence(&format!("alice's page 2: {value}"));
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
        "alice writes the cover's day-2 title and page 1's body (put_op) while bob is away",
        |cx| {
            let cover = alice.put_op(cx, COVER, "Trip notes, day 2")?;
            let body = alice.put_op(cx, PAGE1, DAY2)?;
            cx.evidence(&format!("put_op: {}, {}", cover.name, body.name));
            Ok([cover, body])
        },
    )?;
    let (paste, pasted) = sc.step(
        "alice pastes 20 KiB into page 1 (put_op: the page's new text, from a file): one \
         version, carried in pieces, its value the newest",
        |cx| {
            let file = cx.w.node("alice").dir.join("paste.txt");
            let text = paste_text();
            let mut body = DAY2.to_owned();
            body.insert_str(PASTE_AT, &text);
            fs::write(&file, &body).map_err(|e| format!("{}: {e}", file.display()))?;
            let paste = alice.put_op(cx, PAGE1, &format!("@{}", file.display()))?;
            let (_, value) = alice
                .state(cx, PAGE1)?
                .ok_or("alice holds no state of page 1")?;
            let expected = json!({
                "len": body.len(),
                "sha256": Sha256::digest(body.as_bytes()).iter().map(|b| format!("{b:02x}")).collect::<String>(),
            });
            if value["bytes"] != expected {
                return Err(format!("alice's page 1 after the paste is {value}"));
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
                "put_op {PAGE1}: {} ({} octets in its packet, the text {} octets); alice's page 1: {}",
                paste.name,
                packet.len(),
                body.len(),
                value["bytes"]
            ));
            Ok((paste, expected))
        },
    )?;
    let members = [written[0].clone(), written[1].clone(), paste.clone()];
    let before = sc.step(
        "bob is still away: his watch has delivered none of the three versions; the nftables \
         table goes",
        |cx| {
            bob.drain(cx, QUIET)?;
            if let Some(early) = bob.watched.iter().find_map(|w| counts_member(w, &members)) {
                return Err(format!(
                    "bob's watch delivered a version while he was away: {early}"
                ));
            }
            cx.evidence("bob's watch delivered none of alice's versions while he was away");
            drop(cut);
            cx.evidence("UDP between bob and the relay flows again");
            Ok(bob.watched.len())
        },
    )?;
    sc.step(
        "bob catches up: on the cover and page 1 the same frontier and value as alice (the \
         paste's length and SHA-256 equal; each the newest of alice's writes), every version \
         delivered to his watch only now",
        |cx| {
            for (c, own) in [
                (COVER, vec![&members[0]]),
                (PAGE1, vec![&members[1], &paste]),
            ] {
                let mut last = (Value::Null, Value::Null);
                let converged = wait_for(
                    cx,
                    &format!("bob and alice hold one state of {c}"),
                    CONVERGE,
                    |cx| {
                        let (Some(a), Some(b)) = (alice.merged(cx, c)?, bob.merged(cx, c)?) else {
                            return Ok(false);
                        };
                        let done = a["at"] == b["at"]
                            && a["value"] == b["value"]
                            && own.iter().all(|m| includes(&b["at"], m));
                        last = (a, b);
                        Ok(done)
                    },
                );
                if let Err(e) = converged {
                    // What bob makes of each of this element's versions.
                    let mut seen = Vec::new();
                    for m in &own {
                        seen.push(format!(
                            "{}: {:?}",
                            m.name,
                            bob.call(cx, &format!("get {}", m.name))?
                        ));
                    }
                    return Err(format!("{e}; bob reads {}", seen.join("; ")));
                }
                cx.evidence(&format!(
                    "{c}: alice and bob at {}, value {}",
                    last.1["at"], last.1["value"]
                ));
            }
            let (_, page1) = bob
                .state(cx, PAGE1)?
                .ok_or("bob holds no state of page 1")?;
            if page1["bytes"] != pasted {
                return Err(format!("bob's page 1 is {page1}, not the paste {pasted}"));
            }
            for m in &members {
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
                if !tagged(&w) {
                    return Err(format!(
                        "bob's folder watch did not name {}'s collection: {w}",
                        m.name
                    ));
                }
                cx.evidence(&format!(
                    "bob's watch, of {}: {}",
                    w["collection"], w["change"]
                ));
            }
            Ok(())
        },
    )?;
    Ok(())
}
