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

use super::data_host::{CONVERGE, Host, includes, name, quic_face_to, rib};
use super::shared::{People, RELAY, strangers_through_relay};
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::now_unix;
use serde_json::Value;

const NAMESPACES: People = People {
    a: "/ia",
    b: "/ib",
    relay: "/ir",
};
/// Alice's folder, and a collection under it.
const FOLDER: &str = "/ia/32=data/trip";
const NOTES: &str = "/ia/32=data/trip/notes";
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
            let first = alice.put(cx, NOTES, "text=\"packing list\"")?;
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
        "bob writes into the folder: notes bob=hotel booked; alice reads it, beside her own",
        |cx| {
            let bobs = bob.put(cx, NOTES, "bob=\"hotel booked\"")?;
            wait_for(cx, "alice holds bob's notes", CONVERGE, |cx| {
                Ok(alice.state(cx, NOTES)?.is_some_and(|(at, v)| {
                    includes(&at, &bobs)
                        && includes(&at, &first)
                        && v["bob"] == "hotel booked"
                        && v["text"] == "packing list"
                }))
            })?;
            cx.evidence("alice's notes state includes bob's version: bob = \"hotel booked\"");
            Ok(bobs)
        },
    )?;

    sc.step(
        "alice writes the notes text=packing list v2; bob reads it",
        |cx| {
            let second = alice.put(cx, NOTES, "text=\"packing list v2\"")?;
            wait_for(cx, "bob holds alice's v2", CONVERGE, |cx| {
                Ok(bob.state(cx, NOTES)?.is_some_and(|(at, v)| {
                    includes(&at, &second)
                        && includes(&at, &bobs)
                        && v["text"] == "packing list v2"
                        && v["bob"] == "hotel booked"
                }))
            })?;
            cx.evidence("bob's notes state includes alice's v2: text = \"packing list v2\"");
            Ok(())
        },
    )?;
    Ok(())
}
