//! invite: a stranger joins a folder by a code alone — the data layer's
//! introduction exchange (data-layer spec §19) on real daemons, reached
//! through a relay with no route anyone set.
//!
//! Topology as in [`super::shared`]: alice (/ia) and bob (/ib), each the
//! root device of their namespace, linked through an open community relay
//! (/ir) their trust contexts advertise; no config holds a route, a UDP
//! link, a `[[peer]]` or a `[[relay]]`. Unlike there, they are strangers:
//! neither adopts the other's trust context, so neither daemon routes
//! anything of the other's namespace. Each daemon routes the relay's own
//! device name over its relay link, and each forwarder's producer region
//! is its own device names (ndn-link spec §15.5 "Reaching a device not
//! followed yet"). Each person's device hosts its data layer with
//! `ndn-data` (see [`super::data_host`]).
//!
//! The gestures: alice shares her folder `/ia/32=data/trip` with herself
//! alone and offers it (`offer`: writer, an hour, three wrong tries); bob's
//! device is given the code's link and nothing else (`join`). His device
//! fetches the offer and asks alice's device with a ForwardingHint naming
//! the relay the code carries: bob's daemon sends it to the relay, the
//! relay (the hint is its own name) strips it and forwards by name over
//! alice's link. Alice's device checks the ask, adopts bob's anchor
//! through her daemon and adds /ib to the folder as writer; bob's device
//! checks the answer and adopts alice's anchor through his. Each daemon
//! then routes the other's namespace over its relay link at once (no
//! relink).
//!
//! Proves: bob joins with the code alone and the answer names the folder,
//! writer, and /ia; each daemon now holds the other's trust context and
//! routes the other's namespace over the relay link, with no route, peer
//! or relay in any config; bob writes into the folder and alice reads it;
//! alice writes and bob reads it.
//!
//! Then the short code. Alice shares a second folder `/ia/32=data/trip2`
//! and offers it: the offer carries a `short` code, one line of at most
//! 3×98 characters made of her device name, a contact (the community relay
//! /ir her context advertises) and 20 or 36 BIP39 words. Bob's device,
//! already a member of her first folder, joins the second by those tokens
//! alone: no ForwardingHint set by hand and no route anyone set (the
//! relay's name in the code is the hint of the first fetches). The same
//! code with one word changed is refused by his host with the checksum
//! message and nothing is joined.
//!
//! Proves, for the short code: the offer's `short` is one line of at most
//! 294 characters, `<device> <relay> <20 or 36 words>`; bob joins by it
//! alone and the answer names the second folder, writer and /ia; bob writes
//! into it and alice reads it, alice writes and bob reads it; a code with
//! one word changed is refused with the message that names a mistyped word,
//! address or device name, and bob holds nothing of the folder.

use super::data_host::{CONVERGE, Host, includes, name, quic_face_to, rib};
use super::shared::{People, RELAY, strangers_through_relay};
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::now_unix;
use bip39::Language;
use ndn_data::intro::{ShortCode, ShortError};
use serde_json::Value;

const NAMESPACES: People = People {
    a: "/ia",
    b: "/ib",
    relay: "/ir",
};
/// Alice's folder, and a collection under it.
const FOLDER: &str = "/ia/32=data/trip";
const NOTES: &str = "/ia/32=data/trip/notes";
/// Alice's second folder, shared by a short code, and a collection under it.
const FOLDER2: &str = "/ia/32=data/trip2";
const NOTES2: &str = "/ia/32=data/trip2/notes";
/// The most columns a short code may take (three lines of 98).
const SHORT_COLUMNS: usize = 3 * 98;
/// The community relay's device name, as its trust context advertises it
/// (the root device of /ir): the contact of alice's short code.
const RELAY_DEVICE: &str = "/ir/admin/relay";
/// The folder before anyone joins: alice alone.
const ALICE_ONLY: &str = "writers=/ia readers=person:/ia";
/// How long the offer stands, in ms.
const OFFER_FOR_MS: i64 = 3_600_000;

/// `node` routes `other` over its link face to the relay: the face and
/// the route's origin.
fn routes_over_relay(cx: &mut Cx<'_>, node: &str, other: &str) -> StepResult<Option<String>> {
    let Some(face) = quic_face_to(cx, node, RELAY)? else {
        return Ok(None);
    };
    Ok(rib(cx, node, other)?
        .into_iter()
        .find(|(f, _)| *f == face)
        .map(|(_, origin)| format!("{node}: {other} → face {face} (the relay link, {origin})")))
}

/// A verb's error that says to ask again unchanged (no path answered).
fn retry(e: &Value) -> bool {
    e["retry"] == true
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    let (alice_root, bob_root) = strangers_through_relay(sc, NAMESPACES)?;

    let (mut alice, mut bob) = sc.step(
        "start the data layer on alice's and bob's devices (ndn-data, each signing with its \
         root device's key)",
        |cx| {
            cx.concept("data layer host (ndn-data)");
            let alice = Host::start(cx, "alice", &alice_root.identity)?;
            let bob = Host::start(cx, "bob", &bob_root.identity)?;
            cx.evidence(&format!(
                "alice writes as {}, bob as {}",
                alice.writer, bob.writer
            ));
            Ok((alice, bob))
        },
    )?;

    let first = sc.step(
        "alice shares the folder /ia/32=data/trip with herself alone (writers /ia, readers \
         person:/ia) and writes its notes text=packing list",
        |cx| {
            alice.ok(
                cx,
                &format!("share_folder {FOLDER} rule=merge {ALICE_ONLY}"),
            )?;
            let first = alice.put_op(cx, NOTES, "packing list")?;
            cx.evidence(&format!("alice shared {FOLDER}: {ALICE_ONLY}"));
            Ok(first)
        },
    )?;

    let link = sc.step(
        "alice offers the folder: writer, for an hour, three wrong tries; she gets a code (a \
         link of one QR and the same as words)",
        |cx| {
            cx.concept("introduction code");
            let until = (now_unix() * 1000 + OFFER_FOR_MS).to_string();
            let ok = alice.ok(
                cx,
                &format!("offer {FOLDER} role=writer until={until} tries=3"),
            )?;
            let link = ok["link"].as_str().unwrap_or_default().to_owned();
            let words = ok["words"].as_str().unwrap_or_default();
            let offer = ok["offer"].as_str().unwrap_or_default();
            if !link.starts_with("ndn-trust://intro/") {
                return Err(format!("alice's offer printed no intro link: {ok}"));
            }
            if !name(offer)?.has_prefix(&name(&alice_root.identity)?)
                || !words.starts_with(offer)
                || words[offer.len()..].split_whitespace().count() != 24
            {
                return Err(format!(
                    "alice's code is not her log's offer and 24 words: {ok}"
                ));
            }
            cx.evidence(&format!(
                "alice's offer {offer}: link {} characters, words {words:?}",
                link.len()
            ));
            Ok(link)
        },
    )?;

    sc.step(
        "bob's device joins with the code's link alone: the answer names the folder, writer and \
         /ia; each daemon now holds the other's trust context and routes the other's namespace \
         over its relay link, with no route, peer or relay set anywhere",
        |cx| {
            cx.concept("joining a folder by a code");
            let mut joined = Value::Null;
            wait_for(cx, "bob's join is answered", CONVERGE, |cx| {
                match bob.call(cx, &format!("join {link}"))? {
                    Ok(ok) => {
                        joined = ok;
                        Ok(true)
                    }
                    Err(e) if retry(&e) => Ok(false),
                    Err(e) => Err(format!(
                        "bob's join was refused: {} (next: {}) {e}",
                        e["message"], e["next_step"]
                    )),
                }
            })?;
            if name(joined["folder"].as_str().unwrap_or_default())? != name(FOLDER)?
                || joined["role"] != "writer"
                || joined["inviter"] != NAMESPACES.a
            {
                return Err(format!(
                    "bob joined {joined}, not {FOLDER} as writer of /ia"
                ));
            }
            cx.evidence(&format!("bob joined: {joined}"));
            for (node, other) in [("bob", NAMESPACES.a), ("alice", NAMESPACES.b)] {
                let v = cx
                    .version(node, other)
                    .ok_or_else(|| format!("{node}'s daemon holds no trust context of {other}"))?;
                cx.evidence(&format!("{node}'s daemon holds {other} v{v}"));
                let mut found = None;
                wait_for(
                    cx,
                    &format!("{node} routes {other} over its relay link"),
                    SHORT,
                    |cx| {
                        found = routes_over_relay(cx, node, other)?;
                        Ok(found.is_some())
                    },
                )?;
                cx.evidence(&found.unwrap_or_default());
            }
            for node in ["alice", "bob", "relay"] {
                let n = cx.w.node(node);
                let config = n.render();
                if !n.cfg.routes.is_empty()
                    || !n.cfg.links.is_empty()
                    || config.contains("[[route]]")
                    || config.contains("routes =")
                    || config.contains("[[peer]]")
                    || config.contains("[[relay]]")
                {
                    return Err(format!(
                        "{node}'s config holds a route, a UDP link, a peer or a relay:\n{config}"
                    ));
                }
            }
            cx.evidence(
                "no config holds a [[route]], `routes`, a UDP link, a [[peer]] or a [[relay]]",
            );
            Ok(())
        },
    )?;

    let bobs = sc.step(
        "bob writes into the folder: notes \"hotel booked\", over alice's first; alice reads it",
        |cx| {
            wait_for(cx, "bob holds alice's first notes", CONVERGE, |cx| {
                Ok(bob
                    .state(cx, NOTES)?
                    .is_some_and(|(at, _)| includes(&at, &first)))
            })?;
            let bobs = bob.put_op(cx, NOTES, "hotel booked")?;
            wait_for(cx, "alice holds bob's notes", CONVERGE, |cx| {
                Ok(alice.state(cx, NOTES)?.is_some_and(|(at, v)| {
                    includes(&at, &bobs) && includes(&at, &first) && v["bytes"] == "hotel booked"
                }))
            })?;
            cx.evidence("alice's notes state includes bob's version: \"hotel booked\"");
            Ok(bobs)
        },
    )?;

    sc.step(
        "alice writes the notes \"packing list v2\"; bob reads it",
        |cx| {
            let second = alice.put_op(cx, NOTES, "packing list v2")?;
            wait_for(cx, "bob holds alice's v2", CONVERGE, |cx| {
                Ok(bob.state(cx, NOTES)?.is_some_and(|(at, v)| {
                    includes(&at, &second)
                        && includes(&at, &bobs)
                        && v["bytes"] == "packing list v2"
                }))
            })?;
            cx.evidence("bob's notes state includes alice's v2: \"packing list v2\"");
            Ok(())
        },
    )?;
    short_code(sc, &mut alice, &mut bob, &alice_root.identity)
}

/// The same exchange by the short code: alice offers a second folder, the
/// code is one short line (device, her community relay, words); bob's
/// device, already a member of her first folder, joins by the code alone,
/// with no hint and no route anyone set; a code with one word changed is
/// refused by his host, and nothing is adopted or joined.
fn short_code(
    sc: &mut Scenario,
    alice: &mut Host,
    bob: &mut Host,
    alice_device: &str,
) -> Result<(), Abort> {
    let first = sc.step(
        "alice shares a second folder /ia/32=data/trip2 with herself alone and writes its notes \
         text=packing list",
        |cx| {
            alice.ok(
                cx,
                &format!("share_folder {FOLDER2} rule=merge {ALICE_ONLY}"),
            )?;
            let first = alice.put_op(cx, NOTES2, "packing list")?;
            cx.evidence(&format!("alice shared {FOLDER2}: {ALICE_ONLY}"));
            Ok(first)
        },
    )?;

    let short = sc.step(
        "alice offers the second folder: the offer carries a short code, one line of at most \
         3×98 characters: her device, the relay of her context as first contact, 20 or 36 words",
        |cx| {
            cx.concept("short introduction code");
            let until = (now_unix() * 1000 + OFFER_FOR_MS).to_string();
            let ok = alice.ok(
                cx,
                &format!("offer {FOLDER2} role=writer until={until} tries=3"),
            )?;
            let Some(short) = ok["short"].as_str() else {
                return Err(format!(
                    "alice's offer carries no short code (why: {}): {ok}",
                    ok["short_why"]
                ));
            };
            if ok["share"] != short {
                return Err(format!("alice's share is not the short code: {ok}"));
            }
            if short.contains(['\n', '\r']) || short.chars().count() > SHORT_COLUMNS {
                return Err(format!(
                    "the short code is not one line of at most {SHORT_COLUMNS} characters ({}): \
                     {short:?}",
                    short.chars().count()
                ));
            }
            let tokens: Vec<&str> = short.split_whitespace().collect();
            let words = tokens.len().saturating_sub(2);
            if tokens.len() < 3
                || name(tokens[0])? != name(alice_device)?
                || name(tokens[1])? != name(RELAY_DEVICE)?
                || tokens[2..]
                    .iter()
                    .any(|w| !w.chars().all(|c| c.is_ascii_lowercase()))
                || (words != 20 && words != 36)
            {
                return Err(format!(
                    "the short code is not `<device> <relay> <20 or 36 words>`: {short:?}"
                ));
            }
            cx.evidence(&format!(
                "alice's short code ({} characters, device {}, contact {}, {words} words): \
                 {short:?}",
                short.chars().count(),
                tokens[0],
                tokens[1],
            ));
            Ok(short.to_owned())
        },
    )?;

    sc.step(
        "a short code with one word changed is refused by bob's host with the checksum message; \
         nothing is joined",
        |cx| {
            let tokens: Vec<&str> = short.split_whitespace().collect();
            // The code reads as it was made.
            ShortCode::parse(&short, false)
                .map_err(|e| format!("the offered short code does not parse: {e}"))?;
            // Change the first word to the first word of the list, in list order,
            // that makes the code fail with the checksum error (a changed word
            // passes the 12-bit checksum once in 4096 times: not left to chance).
            let mut typo = tokens.clone();
            let changed = Language::English
                .word_list()
                .iter()
                .find(|w| {
                    **w != tokens[2] && {
                        typo[2] = **w;
                        matches!(
                            ShortCode::parse(&typo.join(" "), false),
                            Err(ShortError::Checksum)
                        )
                    }
                })
                .ok_or("no word of the list makes the code fail its checksum")?;
            typo[2] = *changed;
            let typo = typo.join(" ");
            let refused = match bob.call(cx, &format!("join {typo}"))? {
                Ok(ok) => return Err(format!("bob joined with a mistyped code {typo:?}: {ok}")),
                Err(e) => e,
            };
            let message = refused["message"].as_str().unwrap_or_default();
            if !message.contains("mistyped") || refused["retry"] == true {
                return Err(format!(
                    "bob's refusal does not name a mistyped word, address or device name: \
                     {refused}"
                ));
            }
            cx.evidence(&format!(
                "bob's host refused the mistyped code (word {:?} changed): {message}",
                tokens[2]
            ));
            match bob.call(cx, &format!("get {NOTES2}"))? {
                Ok(ok) => Err(format!("bob holds {NOTES2} after a refused code: {ok}")),
                Err(e) => {
                    cx.evidence(&format!(
                        "bob holds nothing of {FOLDER2} after the refusal: {}",
                        e["message"]
                    ));
                    Ok(())
                }
            }
        },
    )?;

    sc.step(
        "bob's device, a member of the first folder, joins the second by the short code alone: \
         no ForwardingHint set by hand, no route anyone set; the answer names the folder, \
         writer and /ia",
        |cx| {
            cx.concept("joining a folder by a short code");
            let mut joined = Value::Null;
            wait_for(
                cx,
                "bob's join by the short code is answered",
                CONVERGE,
                |cx| match bob.call(cx, &format!("join {short}"))? {
                    Ok(ok) => {
                        joined = ok;
                        Ok(true)
                    }
                    Err(e) if retry(&e) => Ok(false),
                    Err(e) => Err(format!(
                        "bob's join by the short code was refused: {} (next: {}) {e}",
                        e["message"], e["next_step"]
                    )),
                },
            )?;
            if name(joined["folder"].as_str().unwrap_or_default())? != name(FOLDER2)?
                || joined["role"] != "writer"
                || joined["inviter"] != NAMESPACES.a
            {
                return Err(format!(
                    "bob joined {joined}, not {FOLDER2} as writer of /ia"
                ));
            }
            cx.evidence(&format!("bob joined by the short code: {joined}"));
            for node in ["alice", "bob", "relay"] {
                let n = cx.w.node(node);
                let config = n.render();
                if !n.cfg.routes.is_empty()
                    || !n.cfg.links.is_empty()
                    || config.contains("[[route]]")
                    || config.contains("[[peer]]")
                    || config.contains("[[relay]]")
                {
                    return Err(format!(
                        "{node}'s config holds a route, a UDP link, a peer or a relay"
                    ));
                }
            }
            cx.evidence("no config holds a route, a link, a peer or a relay; no hint set by hand");
            Ok(())
        },
    )?;

    let bobs = sc.step(
        "bob writes into the second folder: notes \"hotel booked\" (over her first); alice reads it",
        |cx| {
            wait_for(cx, "bob holds alice's first trip2 notes", CONVERGE, |cx| {
                Ok(bob
                    .state(cx, NOTES2)?
                    .is_some_and(|(at, _)| includes(&at, &first)))
            })?;
            let bobs = bob.put_op(cx, NOTES2, "hotel booked")?;
            wait_for(cx, "alice holds bob's notes of trip2", CONVERGE, |cx| {
                Ok(alice.state(cx, NOTES2)?.is_some_and(|(at, v)| {
                    includes(&at, &bobs) && includes(&at, &first) && v["bytes"] == "hotel booked"
                }))
            })?;
            cx.evidence("alice's trip2 notes state includes bob's version: \"hotel booked\"");
            Ok(bobs)
        },
    )?;

    sc.step(
        "alice writes the second folder's notes \"packing list v2\"; bob reads it",
        |cx| {
            let second = alice.put_op(cx, NOTES2, "packing list v2")?;
            wait_for(cx, "bob holds alice's trip2 v2", CONVERGE, |cx| {
                Ok(bob.state(cx, NOTES2)?.is_some_and(|(at, v)| {
                    includes(&at, &second)
                        && includes(&at, &bobs)
                        && v["bytes"] == "packing list v2"
                }))
            })?;
            cx.evidence("bob's trip2 notes state includes alice's v2: \"packing list v2\"");
            Ok(())
        },
    )?;
    Ok(())
}
