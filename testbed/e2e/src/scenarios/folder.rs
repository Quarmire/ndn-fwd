//! folder: two people share a folder of elements under an app's own merge
//! rule; one saves several elements as one group and pastes a long text;
//! the other counts the group whole or not at all — the data layer's
//! folder records, rules by name, app-built operations in pieces and groups
//! (data-layer spec §5.1, §5.2, §5.5, §6.1, §13) on real daemons.
//!
//! Topology and gestures as in [`super::shared`]: alice (/fa) and bob
//! (/fb), each the root device of their namespace, pointing at each other,
//! linked through an open community relay (/fr) their trust contexts
//! advertise; no config holds a route, a UDP link, a `[[peer]]` or a
//! `[[relay]]`. Each person's device hosts its data layer with `ndn-data`
//! (see [`super::data_host`]); alice's keeps its entries in a store
//! directory (`--store`).
//!
//! The rule: `/ndn-tools/merge/element/v=1`, which `ndn-data` ships and
//! registers with `--merge-rule` — an element of named text settings, each
//! operation made over a basis it names by implicit digest (`set:` writes a
//! setting, `change:` splices the text its basis wrote), concurrent writes
//! kept as ordered variants.
//!
//! Proves: alice shares the folder `/fa/32=data/notebook` (rule
//! `/ndn-tools/merge/element/v=1`, writers /fa and /fb, readers both
//! people) with `share_folder`, and writes the cover; bob's device, running
//! a program that does not know the rule, holds the cover unreadable: its
//! `get` answers RuleUnknown naming the rule (next: update the program).
//! Started again knowing the rule, bob reads the cover and writes a page;
//! alice reads it — both collections governed by the folder record alone.
//! With bob cut from the relay (nftables), alice saves the cover and two
//! pages as one group (`put_group`: three versions, consecutive seqs, each
//! carrying the group `{id: first seq, count: 3}`) and then pastes 20 KiB
//! into a page (`put_op` with a change over the group's page version, by
//! its digest): one operation whose version carries it in pieces (its
//! packet is far smaller than the paste). Alice's device then serves only
//! part of the group: stopped, the page member's entries moved out of its
//! store, every cached copy erased, started again. Once bob is back he
//! holds the other two members and counts neither — each not counted
//! ("group incomplete"), the states' frontiers holding no member and no
//! paste, the values without the group's text, his watch delivering no
//! member — while no device answers the withheld member: a verdict from
//! the group's signed versions alone, not timing. Alice's store whole
//! again, bob counts the whole group and the paste: on every element the
//! same frontier and value as alice, nothing not counted, every member
//! delivered to his watch only now.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::data_host::{CONVERGE, Host, Put, delivered, erase_cs, includes, name, unanswered};
use super::shared::{BOB, People, RELAY, content_at, people_through_relay};
use crate::scenarios::*;
use crate::step::{Abort, Scenario, StepResult};
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
/// The app's rule, by its full name.
const RULE: &str = "/ndn-tools/merge/element/v=1";
/// Both people write and read.
const BOTH: &str = "writers=/fa,/fb readers=person:/fa,person:/fb";
/// The nftables table that cuts bob–relay.
const CUT_TABLE: &str = "ndn_e2e_folder_cut";
/// The paste: 20 KiB of text.
const PASTE_LEN: usize = 20 * 1024;
/// Page 1's text the group saves, and where the paste goes into it.
const DAY2: &str = "Day 2: the museum, then dinner by the river.";
const PASTE_AT: usize = 7;
/// How long bob's host prints nothing before every change it delivered so
/// far is taken in (the log checks; no verdict depends on it).
const QUIET: Duration = Duration::from_secs(2);

/// `ndn-data` options that make the device know the rule.
fn knows_rule() -> Vec<String> {
    vec!["--merge-rule".to_owned(), RULE.to_owned()]
}

/// The text of setting `setting` in an element value, when it has exactly
/// one variant.
fn text<'a>(value: &'a Value, setting: &str) -> Option<&'a Value> {
    match value["element"][setting].as_array().map(Vec::as_slice) {
        Some([one]) => Some(&one["text"]),
        _ => None,
    }
}

/// A frontier entry or id (`{writer, seq}`) is version `v`.
fn is(id: &Value, v: &Put) -> bool {
    id["writer"] == v.writer.as_str() && id["seq"] == v.seq
}

/// The watched change delivers or counts one of `members`.
fn counts_member(w: &Value, members: &[Put]) -> Option<String> {
    let change = &w["change"];
    let id = if change["version"].is_object() {
        &change["version"]["id"]
    } else {
        &change["counted"]["id"]
    };
    members
        .iter()
        .find(|m| is(id, m))
        .map(|m| format!("{}: {change}", m.name))
}

/// The files of the `--store` directory `store` holding entries under the
/// name `prefix` (each file: the name's TLV length, 4 octets big-endian,
/// the name's TLV, the stored wire).
fn entries_under(store: &Path, prefix: &str) -> StepResult<Vec<PathBuf>> {
    let prefix = name(prefix)?;
    let mut found = Vec::new();
    for entry in fs::read_dir(store).map_err(|e| format!("{}: {e}", store.display()))? {
        let path = entry
            .map_err(|e| format!("{}: {e}", store.display()))?
            .path();
        if path.extension().is_none_or(|x| x != "entry") {
            continue;
        }
        let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let len = bytes
            .get(..4)
            .map(|l| u32::from_be_bytes([l[0], l[1], l[2], l[3]]) as usize)
            .ok_or_else(|| format!("{} is no store entry", path.display()))?;
        let tlv = bytes
            .get(4..4 + len)
            .ok_or_else(|| format!("{} is no store entry", path.display()))?;
        let stored = ndn_packet::Name::decode_from_tlv(bytes::Bytes::copy_from_slice(tlv))
            .map_err(|e| format!("{}: {e:?}", path.display()))?;
        if stored.has_prefix(&prefix) {
            found.push(path);
        }
    }
    Ok(found)
}

/// Move every file of `files` into `to`.
fn move_all(files: &[PathBuf], to: &Path) -> StepResult<Vec<PathBuf>> {
    files
        .iter()
        .map(|f| {
            let dest = to.join(
                f.file_name()
                    .ok_or_else(|| format!("{}: no file name", f.display()))?,
            );
            fs::rename(f, &dest)
                .map_err(|e| format!("move {} to {}: {e}", f.display(), dest.display()))?;
            Ok(dest)
        })
        .collect()
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
    let alice_options = {
        let mut o = vec!["--store".to_owned(), store.display().to_string()];
        o.extend(knows_rule());
        o
    };

    let (mut alice, bob) = sc.step(
        "start the data layer on alice's device (ndn-data knowing the rule \
         /ndn-tools/merge/element/v=1, its entries kept in a store directory) and on bob's \
         (a program that does not know it)",
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
        "alice shares the folder /fa/32=data/notebook (rule /ndn-tools/merge/element/v=1, writers \
         /fa,/fb, readers person:/fa,person:/fb) and writes the cover: set title",
        |cx| {
            cx.concept("folder members record");
            alice.ok(
                cx,
                &format!("share_folder {FOLDER} rule=merge:{RULE} {BOTH}"),
            )?;
            alice.ok(cx, &format!("watch {FOLDER}"))?;
            let ok = alice.ok(cx, &format!("put_op {COVER} set:title=\"Trip notes\""))?;
            let first = alice.put_of(COVER, &ok)?;
            let (_, value) = alice
                .state(cx, COVER)?
                .ok_or("alice holds no state of her cover")?;
            if text(&value, "title") != Some(&json!("Trip notes")) {
                return Err(format!("alice's cover value is {value}"));
            }
            cx.evidence(&format!(
                "alice shared {FOLDER}: rule {RULE}, {BOTH}; put_op {COVER}: {} ({}); her cover: \
                 {value}",
                first.name, ok["op"]
            ));
            Ok(first)
        },
    )?;
    let mut bob = sc.step(
        "bob's device, whose program does not know the rule, holds the cover unreadable: get \
         answers RuleUnknown naming the rule (next: update the program); started again knowing \
         it, bob watches the folder",
        |cx| {
            cx.concept("merge rules by name");
            let mut bob = bob;
            let mut last = Value::Null;
            wait_for(
                cx,
                "bob's get of the cover answers RuleUnknown",
                CONVERGE,
                |cx| match bob.call(cx, &format!("get {COVER}"))? {
                    Ok(ok) => Err(format!("bob reads the cover under no known rule: {ok}")),
                    Err(e) => {
                        let unknown = e["next"] == "update-program";
                        last = e;
                        Ok(unknown)
                    }
                },
            )?;
            if name(last["rule_unknown"]["rule"].as_str().unwrap_or_default())? != name(RULE)?
                || last["retry"] != false
            {
                return Err(format!("bob's RuleUnknown answer is {last}"));
            }
            cx.evidence(&format!(
                "bob> get {COVER}: {} (next: {}; rule {})",
                last["message"], last["next"], last["rule_unknown"]["rule"]
            ));
            bob.stop(cx);
            let mut bob = Host::start_with(cx, "bob", &bob_root.identity, &knows_rule())?;
            bob.ok(cx, &format!("watch {FOLDER}"))?;
            Ok(bob)
        },
    )?;
    sc.step(
        "bob reads the cover and writes page 2 (set caption); alice reads his page: both \
         elements governed by the folder record alone",
        |cx| {
            wait_for(cx, "bob reads the cover", CONVERGE, |cx| {
                Ok(bob.state(cx, COVER)?.is_some_and(|(at, v)| {
                    includes(&at, &first) && text(&v, "title") == Some(&json!("Trip notes"))
                }))
            })?;
            cx.evidence("bob's cover state includes alice's first version: title \"Trip notes\"");
            let ok = bob.ok(cx, &format!("put_op {PAGE2} set:caption=\"from bob\""))?;
            let caption = bob.put_of(PAGE2, &ok)?;
            let mut value = Value::Null;
            wait_for(cx, "alice reads bob's page", CONVERGE, |cx| {
                Ok(alice.state(cx, PAGE2)?.is_some_and(|(at, v)| {
                    value = v;
                    includes(&at, &caption)
                }))
            })?;
            let variants = &value["element"]["caption"];
            if variants[0]["writer"] != bob.writer.as_str() || variants[0]["text"] != "from bob" {
                return Err(format!("alice's page 2 value is {value}"));
            }
            cx.evidence(&format!("alice's page 2: {value}"));
            Ok(())
        },
    )?;

    if !crate::works(std::process::Command::new("nft").arg("--version")) {
        sc.skip(
            "group save and paste while bob is away; alice serves part of the group; bob counts \
             it whole or not at all",
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
    let members = sc.step(
        "alice saves the cover and two pages as one group (put_group): three versions, \
         consecutive seqs, each carrying the group {id: first seq, count: 3}",
        |cx| {
            cx.concept("groups of versions");
            let ok = alice.ok(
                cx,
                &format!(
                    "put_group {COVER} op set:title=\"Trip notes, day 2\" ; {PAGE1} op \
                     set:body=\"{DAY2}\" ; {PAGE2} op set:caption=\"the river at night\""
                ),
            )?;
            let versions = ok["versions"]
                .as_array()
                .ok_or_else(|| format!("put_group answered {ok}"))?;
            let members = [COVER, PAGE1, PAGE2]
                .iter()
                .zip(versions)
                .map(|(c, v)| alice.put_of(c, v))
                .collect::<StepResult<Vec<_>>>()?;
            if members.len() != 3 || members.windows(2).any(|w| w[1].seq != w[0].seq + 1) {
                return Err(format!("put_group answered {ok}"));
            }
            let group = json!({"id": members[0].seq, "count": 3});
            for (c, m) in [COVER, PAGE1, PAGE2].iter().zip(&members) {
                let v = alice.version(cx, c, m)?;
                if v["group"] != group {
                    return Err(format!(
                        "{} carries the group {}, not {group}",
                        m.name, v["group"]
                    ));
                }
            }
            cx.evidence(&format!(
                "put_group: {} ; each carries group {group}",
                members
                    .iter()
                    .map(|m| m.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            Ok(members)
        },
    )?;
    let page1_member = members[1].clone();
    let (paste, pasted) = sc.step(
        "alice pastes 20 KiB into page 1 (put_op: a change over the group's page version, its \
         basis by digest): one operation, carried in pieces",
        |cx| {
            cx.concept("app-built operations in pieces");
            let file = cx.w.node("alice").dir.join("paste.txt");
            let text = paste_text();
            fs::write(&file, &text).map_err(|e| format!("{}: {e}", file.display()))?;
            let ok = alice.ok(
                cx,
                &format!("put_op {PAGE1} change:body={PASTE_AT},0,@{}", file.display()),
            )?;
            let paste = alice.put_of(PAGE1, &ok)?;
            let (_, value) = alice
                .state(cx, PAGE1)?
                .ok_or("alice holds no state of page 1")?;
            let variant = &value["element"]["body"][0];
            let variants = value["element"]["body"].as_array().map_or(0, Vec::len);
            let mut body = DAY2.to_owned();
            body.insert_str(PASTE_AT, &text);
            let expected = json!({
                "len": body.len(),
                "sha256": Sha256::digest(body.as_bytes()).iter().map(|b| format!("{b:02x}")).collect::<String>(),
            });
            if variants != 1 || !is(variant, &paste) || variant["text"] != expected {
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
                "put_op {PAGE1}: {} (op {}); its packet {} octets, the paste {PASTE_LEN}; alice's \
                 page 1 body: {}",
                paste.name,
                ok["op"],
                packet.len(),
                variant["text"]
            ));
            Ok((paste, expected))
        },
    )?;
    let withheld = store.with_file_name("withheld");
    let moved = sc.step(
        "alice's device serves only part of the group: stopped, page 1's member moved out of its \
         store, every cached copy erased, started again",
        |cx| {
            alice.stop(cx);
            let files = entries_under(&store, &page1_member.name)?;
            if files.is_empty() {
                return Err(format!(
                    "alice's store {} holds no entry of {}",
                    store.display(),
                    page1_member.name
                ));
            }
            fs::create_dir_all(&withheld).map_err(|e| format!("{}: {e}", withheld.display()))?;
            let moved = move_all(&files, &withheld)?;
            for node in ["alice", "relay", "bob"] {
                erase_cs(cx, node, &page1_member.name)?;
            }
            alice = Host::start_with(cx, "alice", &alice_root.identity, &alice_options)?;
            cx.evidence(&format!(
                "{} entr(ies) of {} moved to {}; caches erased at alice, relay and bob",
                moved.len(),
                page1_member.name,
                withheld.display()
            ));
            Ok(moved)
        },
    )?;
    sc.step("bob is back: the nftables table goes", |cx| {
        drop(cut);
        cx.evidence("UDP between bob and the relay flows again");
        Ok(())
    })?;
    sc.step(
        "bob holds the cover's and page 2's members and counts neither (group incomplete): no \
         member and no paste in his frontiers, none of the group's text in his values, no member \
         delivered to his watch; no device answers page 1's member",
        |cx| {
            // The path is back: bob's daemon fetches the cover's member from
            // alice's device.
            wait_for(
                cx,
                "bob's daemon fetches the cover's member",
                CONVERGE,
                |cx| Ok(delivered(cx, "bob", &members[0].name).is_ok()),
            )?;
            cx.evidence(&format!("bob's daemon fetches {}", members[0].name));
            let held = [(COVER, &members[0]), (PAGE2, &members[2])];
            let mut shown = Vec::new();
            wait_for(
                cx,
                "bob reports both held members not counted",
                CONVERGE,
                |cx| {
                    shown.clear();
                    for (c, m) in held {
                        let Some(state) = bob.merged(cx, c)? else {
                            return Ok(false);
                        };
                        let Some(n) = state["not_counted"]
                            .as_array()
                            .and_then(|n| n.iter().find(|n| is(&n["id"], m)))
                        else {
                            return Ok(false);
                        };
                        if !n["why"]
                            .as_str()
                            .is_some_and(|w| w.contains("group incomplete"))
                        {
                            return Err(format!(
                                "bob does not count {} because {}",
                                m.name, n["why"]
                            ));
                        }
                        shown.push(format!("{c}: {} not counted: {}", m.name, n["why"]));
                    }
                    Ok(true)
                },
            )?;
            for line in &shown {
                cx.evidence(line);
            }
            for (c, expect) in [
                (COVER, Some(json!("Trip notes"))),
                (PAGE1, None),
                (PAGE2, Some(json!("from bob"))),
            ] {
                let (at, value) = bob
                    .state(cx, c)?
                    .ok_or_else(|| format!("bob holds no state of {c}"))?;
                if let Some(m) = members.iter().chain([&paste]).find(|m| includes(&at, m)) {
                    return Err(format!("bob's state of {c} includes {}: at {at}", m.name));
                }
                let setting = match c {
                    COVER => "title",
                    PAGE1 => "body",
                    _ => "caption",
                };
                if text(&value, setting) != expect.as_ref() {
                    return Err(format!("bob's {c} value is {value}"));
                }
                cx.evidence(&format!("bob's {c}: at {at}, value {value}"));
            }
            bob.drain(cx, QUIET)?;
            if let Some(early) = bob.watched.iter().find_map(|w| counts_member(w, &members)) {
                return Err(format!(
                    "bob's watch counted a member of an incomplete group: {early}"
                ));
            }
            cx.evidence("bob's watch delivered no member of the group");
            unanswered(cx, "bob", &page1_member.name)?;
            cx.evidence(&format!("no device answers {} at bob", page1_member.name));
            Ok(())
        },
    )?;
    sc.step(
        "alice's store whole again (stopped, the member put back, started): bob counts the whole \
         group and the paste — on every element the same frontier and value as alice, nothing \
         not counted, every member delivered to his watch only now",
        |cx| {
            // Everything bob's watch delivered while the group was
            // incomplete (none of it a member, checked above).
            bob.drain(cx, QUIET)?;
            let before = bob.watched.len();
            if let Some(early) = bob.watched.iter().find_map(|w| counts_member(w, &members)) {
                return Err(format!(
                    "bob's watch counted a member of an incomplete group: {early}"
                ));
            }
            alice.stop(cx);
            for from in &moved {
                let to = store.join(from.file_name().expect("a file name"));
                fs::rename(from, &to).map_err(|e| format!("move {} back: {e}", from.display()))?;
            }
            alice = Host::start_with(cx, "alice", &alice_root.identity, &alice_options)?;
            for (c, own) in [
                (COVER, vec![&members[0]]),
                (PAGE1, vec![&members[1], &paste]),
                (PAGE2, vec![&members[2]]),
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
                            && own.iter().all(|m| includes(&b["at"], m))
                            && b["not_counted"].as_array().is_some_and(Vec::is_empty);
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
            if text(&page1, "body") != Some(&pasted) {
                return Err(format!("bob's page 1 is {page1}, not the paste {pasted}"));
            }
            for m in &members {
                let w =
                    bob.watched_until(cx, &format!("{} in bob's watch", m.name), CONVERGE, |w| {
                        counts_member(w, std::slice::from_ref(m)).is_some()
                    })?;
                if !bob.watched[before..].contains(&w) {
                    return Err(format!(
                        "bob's watch delivered {} before the group was whole",
                        m.name
                    ));
                }
                cx.evidence(&format!("bob's watch: {}", w["change"]));
            }
            Ok(())
        },
    )?;
    Ok(())
}
