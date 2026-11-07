//! shared: two people share a document and a chat across their trusted
//! prefixes through a community relay that carries them and cannot read
//! them — the data layer (`ndn_data::Device`) on real daemons.
//!
//! Topology, on the harness's `lo`: alice (10.200.0.1), bob (.2) and a
//! relay (.3). The relay is the root device of /sr, listening for QUIC
//! links, and an open community relay (`[relay_service] serve = "open"`:
//! its operator's standing policy, nothing per person). It holds no trust
//! context of /sa or /sb and lists no root.
//!
//! The people's gestures, and nothing else:
//! 1. each creates their namespace (`ndn-fwd init`): alice /sa, bob /sb,
//!    the init config advertising the relay in the namespace's trust
//!    context (`[[ca.relay]]`: its device name, link key and endpoint);
//! 2. each points at the other: adopts the other's inline anchor link;
//! 3. alice shares the document and the chat with bob (and later shares
//!    them again without him);
//! 4. put, get and watch.
//!
//! No config holds a route, a UDP link, a `[[peer]]` or a `[[relay]]`.
//! Each device links to the relay its namespace advertises, and over it
//! the link library routes the device's own namespace and each one it
//! follows: alice's daemon routes /sb (bob's device and, beneath it,
//! /sb/32=sync) to the relay, bob's /sa. The relay serves each device
//! offline against the root its hello carries; their Data crosses it in
//! transit, unvalidated (the devices validate it end to end). Over each
//! device's link it routes the device's name, the key name of each issuer
//! its hello showed (so the other person fetches the chain from the
//! device) and the sync group of the device's namespace, and runs that
//! group with the multicast strategy while the namespace is in transit; on
//! alice's and bob's daemons the trust-context library runs each held
//! namespace's group with multicast.
//! The data layer publishes each change about a collection into the group
//! of its namespace and of every namespace its members record names (and,
//! for a members record, its previous record's), so alice reaches bob in
//! /sb's group and bob alice in /sa's.
//!
//! Each person's device hosts its data layer with `ndn-data` (see
//! [`super::data_host`]).
//!
//! Proves: alice shares a document (merge rule) and a chat (log rule) with
//! bob as writer and reader; each reads what the other wrote, the chat by
//! watch, every version named `<its device>/32=log/<collection>/seq=<n>`.
//! The relay fetches the versions (in transit: it holds no context of /sa)
//! and their Content is a sealed record (an epoch and a ciphertext, no
//! fields) that holds neither plaintext. With UDP between bob and the relay
//! cut, bob edits the document; alice removes bob as writer and reader.
//! Once the link is back, alice's state never takes bob's offline edit
//! (refused outside the cut: ask the owner) and keeps his earlier one;
//! bob's watch reports his offline version withdrawn by the cut, and
//! outside the audience his get of the document is sealed; alice's next
//! version is sealed in a new epoch, which bob cannot open.

use bytes::Bytes;
use ndn_data::wire::{Record, decode_record};
use serde_json::Value;

use super::data_host::{
    CONVERGE, Host, Put, includes, key_locator, multicast_at, name, quic_face_to, rib, unanswered,
};
use super::direct_paths::link_list;
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{NodeCfg, QUIC_PORT, addr};

const NS_A: &str = "/sa";
const NS_B: &str = "/sb";
const NS_R: &str = "/sr";
/// Alice's, bob's and the relay's namespaces.
const NAMESPACES: People = People {
    a: NS_A,
    b: NS_B,
    relay: NS_R,
};
/// Alice's document and chat, in her namespace.
const DOC: &str = "/sa/32=data/docs/plan";
const CHAT: &str = "/sa/32=data/chat/ab";
/// Bob writes and reads beside alice; then alice alone.
const BOTH: &str = "writers=/sa,/sb readers=person:/sa,person:/sb";
const ALICE_ONLY: &str = "writers=/sa readers=person:/sa";
/// The nftables table that cuts bob–relay.
const CUT_TABLE: &str = "ndn_e2e_shared_cut";

/// The hosts of alice's, bob's and the relay's daemons.
pub const ALICE: u8 = 1;
pub const BOB: u8 = 2;
pub const RELAY: u8 = 3;

/// Link timing that notices a lost link within seconds.
const FAST_LINKS: &str = "[links]\nkeep_alive_secs = 2\nidle_timeout_secs = 6\n";
/// Whatever reaches the other person goes through the relay.
const NO_DIRECT: &str = "[direct]\nmembership = false\n";

/// The namespaces of two people (alice `a`, bob `b`) and of the community
/// relay between them.
#[derive(Clone, Copy)]
pub struct People {
    pub a: &'static str,
    pub b: &'static str,
    pub relay: &'static str,
}

/// A namespace's sync group (data-layer spec §12).
fn group(ns: &str) -> String {
    format!("{ns}/32=sync")
}

/// Alice or bob: its link face to the relay carries `other` (the other
/// person's namespace), and it runs both groups with multicast.
fn routes_over_relay(
    cx: &mut Cx<'_>,
    ns: People,
    node: &str,
    other: &str,
) -> StepResult<Option<String>> {
    let Some(face) = quic_face_to(cx, node, RELAY)? else {
        return Ok(None);
    };
    let Some((_, origin)) = rib(cx, node, other)?.into_iter().find(|(f, _)| *f == face) else {
        return Ok(None);
    };
    let (group_a, group_b) = (group(ns.a), group(ns.b));
    let (Some(a), Some(b)) = (
        multicast_at(cx, node, &group_a)?,
        multicast_at(cx, node, &group_b)?,
    ) else {
        return Ok(None);
    };
    Ok(Some(format!(
        "{node}: {other} → face {face} (the relay link, {origin}); {group_a} runs {a}, {group_b} \
         runs {b}"
    )))
}

/// The relay: each person's device name, the key name of the person's CA
/// (the issuer their hello showed) and the group of that person's
/// namespace over the person's link, both groups run with multicast while
/// their namespace is in transit (the relay holds neither). (Alice reaches
/// bob through bob's group, a member namespace of her collections, and bob
/// alice through alice's; each fetches the other's CA certificate through
/// the issuer route.)
fn relay_routes(cx: &mut Cx<'_>, ns: People, alice: &str, bob: &str) -> StepResult<Option<String>> {
    let (Some(fa), Some(fb)) = (
        quic_face_to(cx, "relay", ALICE)?,
        quic_face_to(cx, "relay", BOB)?,
    ) else {
        return Ok(None);
    };
    let (group_a, group_b) = (group(ns.a), group(ns.b));
    let on = |routes: &[(u64, String)], face: u64| routes.iter().any(|(f, _)| *f == face);
    let routed = on(&rib(cx, "relay", alice)?, fa)
        && on(&rib(cx, "relay", &group_a)?, fa)
        && on(&rib(cx, "relay", bob)?, fb)
        && on(&rib(cx, "relay", &group_b)?, fb);
    let (Some(ca_a), Some(ca_b)) = (issuer_route(cx, ns.a, fa)?, issuer_route(cx, ns.b, fb)?)
    else {
        return Ok(None);
    };
    let (Some(a), Some(b)) = (
        multicast_at(cx, "relay", &group_a)?,
        multicast_at(cx, "relay", &group_b)?,
    ) else {
        return Ok(None);
    };
    Ok(routed.then(|| {
        format!(
            "relay: {alice}, {ca_a} and {group_a} → face {fa}; {bob}, {ca_b} and {group_b} → face \
             {fb}; {group_a} runs {a}, {group_b} runs {b}"
        )
    }))
}

/// The relay's route of `<ns>/CA/KEY/<key-id>` (the issuer of the root
/// device of `ns`) to `face`, as found.
fn issuer_route(cx: &mut Cx<'_>, ns: &str, face: u64) -> StepResult<Option<String>> {
    let ca = name(&format!("{ns}/CA/KEY"))?;
    let sock = cx.w.node("relay").sock().display().to_string();
    let op = cx
        .tool("ndn-ctl")
        .args(["--socket", &sock, "route", "rib-list"]);
    let out = cx.exec(op);
    if !out.success() {
        return Err(format!("route rib-list on relay: {}", out.status_text()));
    }
    // `<prefix>  <face>  <origin>  <cost>  <flags>[  expiry=…]`
    Ok(out.stdout.lines().find_map(|l| {
        let w: Vec<&str> = l.split_whitespace().collect();
        match w.as_slice() {
            [p, f, ..] if f.parse() == Ok(face) && name(p).is_ok_and(|p| p.has_prefix(&ca)) => {
                Some((*p).to_owned())
            }
            _ => None,
        }
    }))
}

/// `name` fetched through `node`'s daemon (which validates it against the
/// trust context before delivering it, or forwards it unvalidated when its
/// namespace is in transit there): its Content's octets.
pub fn content_at(cx: &mut Cx<'_>, node: &str, name: &str) -> StepResult<Vec<u8>> {
    let sock = cx.w.node(node).sock().display().to_string();
    let op = cx
        .tool("ndn-peek")
        .args(["--face-socket", &sock, "--hex", name])
        .timeout(std::time::Duration::from_secs(15));
    let out = cx.exec(op);
    if !out.success() {
        return Err(format!(
            "ndn-peek of {name} at {node}: {}: {}",
            out.status_text(),
            out.stderr.trim()
        ));
    }
    let hex = out
        .stdout
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty() && l.len() % 2 == 0 && l.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| format!("ndn-peek --hex of {name} shows no content: {}", out.stdout))?;
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| format!("{hex}: {e}")))
        .collect()
}

/// The relay fetches version `v` and cannot read it: its Content holds
/// none of `plain`, and it is a version record whose payload is sealed (an
/// epoch and a ciphertext, no fields). The relay holds no context of /sa,
/// so its daemon carried the version in transit, unvalidated. The epoch,
/// as `<creator>/seq`.
fn relay_sees_sealed(cx: &mut Cx<'_>, v: &Put, plain: &[&str]) -> StepResult<String> {
    if let Some(version) = cx.version("relay", NS_A) {
        return Err(format!("the relay holds {NS_A} v{version}"));
    }
    let key = key_locator(cx, "relay", &v.name)?;
    let bytes = content_at(cx, "relay", &v.name)?;
    if let Some(p) = plain
        .iter()
        .find(|p| bytes.windows(p.len()).any(|w| w == p.as_bytes()))
    {
        return Err(format!(
            "{} as the relay fetched it holds the plaintext {p:?}",
            v.name
        ));
    }
    let record = decode_record(Bytes::from(bytes.clone()))
        .map_err(|e| format!("{} at the relay: {e}", v.name))?;
    let Record::Version(body) = record else {
        return Err(format!("{} at the relay is no version record", v.name));
    };
    let Some(sealed) = &body.sealed else {
        return Err(format!("{} travels unsealed: {body:?}", v.name));
    };
    if body.fields.fields().next().is_some() || !body.op.is_empty() {
        return Err(format!("{} carries its fields beside its seal", v.name));
    }
    let epoch = format!("{}/seq={}", sealed.epoch.creator, sealed.epoch.seq.0);
    cx.evidence(&format!(
        "relay fetched {} (KeyLocator {key}; in transit, unvalidated: the relay holds no context \
         of {NS_A}): {} octets, a version record sealed in epoch {epoch}, {}-octet ciphertext, no \
         fields; none of {plain:?} in it",
        v.name,
        bytes.len(),
        sealed.ciphertext.len()
    ));
    Ok(epoch)
}

/// `get <what>` at `host` until it answers an error that does not say
/// retry (a fetch that found no path yet does). The error.
fn refused(cx: &mut Cx<'_>, host: &mut Host, what: &str) -> StepResult<Value> {
    let mut last = Value::Null;
    wait_for(
        cx,
        &format!("{} answers get {what} with a final error", host.node),
        CONVERGE,
        |cx| match host.call(cx, &format!("get {what}"))? {
            Ok(ok) => Err(format!("{} reads {what}: {ok}", host.node)),
            Err(e) if e["retry"] == true => Ok(false),
            Err(e) => {
                last = e;
                Ok(true)
            }
        },
    )?;
    Ok(last)
}

/// A verb's error saying the name is sealed to an audience this device is
/// not in: ask the owner for a reading key.
fn sealed_to(e: &Value) -> bool {
    e["next"] == "ask-owner" && e["message"].as_str().is_some_and(|m| m.contains("sealed"))
}

/// The watched change in `collection` that is a version holding `text` in
/// field `field`.
fn delivers(w: &Value, collection: &str, v: &Put, field: &str, text: &str) -> bool {
    let version = &w["change"]["version"];
    name(w["watch"].as_str().unwrap_or_default()).ok() == name(collection).ok()
        && name(version["name"].as_str().unwrap_or_default()).ok() == name(&v.name).ok()
        && version["payload"]["entry"][field] == text
}

/// Write `node`'s config and adopt `link` (an inline anchor link) with no
/// daemon running.
fn adopt_offline(cx: &mut Cx<'_>, node: &str, ns: &str, link: &str) -> StepResult<()> {
    let n = cx.w.node(node);
    std::fs::write(n.config(), n.render()).map_err(|e| format!("{}: {e}", n.config().display()))?;
    let op = cx
        .tool("ndn-fwd")
        .arg("adopt")
        .arg(link)
        .arg("-c")
        .arg(cx.w.node(node).cfg_arg());
    let out = cx.ok(op, "adopt")?;
    if !out.stdout.contains("offline") {
        return Err(format!(
            "{node}'s adopt of {ns} was not offline: {}",
            out.stdout
        ));
    }
    cx.expect_version(node, ns, 1)?;
    cx.evidence(&format!(
        "{node} adopted {ns} offline from its inline anchor link"
    ));
    Ok(())
}

/// Two people, alice (namespace `ns.a`) and bob (`ns.b`), each the root
/// device of their namespace, pointing at each other, their daemons linked
/// through an open community relay (the root device of `ns.relay`) that
/// their namespaces' trust contexts advertise — no config holding a route,
/// a UDP link, a `[[peer]]` or a `[[relay]]` — and each routing the other
/// namespace and both sync groups over the relay link. Alice's and bob's
/// roots.
pub fn people_through_relay(sc: &mut Scenario, ns: People) -> Result<(RootInfo, RootInfo), Abort> {
    let person = NodeCfg {
        quic_dial_only: true,
        ..Default::default()
    };
    sc.world.add("alice", ALICE, person.clone());
    sc.world.add("bob", BOB, person);
    sc.world.add(
        "relay",
        RELAY,
        NodeCfg {
            quic_listen: true,
            ..Default::default()
        },
    );

    let (relay_root, relay_key) = sc.step(
        &format!(
            "the relay, the root device of {}, starts as an open community relay: serve = open, \
             no roots listed, no namespace of anyone else adopted",
            ns.relay
        ),
        |cx| {
            cx.concept("open community relay");
            let relay_root = init_root(cx, "relay", ns.relay, "relay")?;
            let relay = cx.w.node_mut("relay");
            relay.cfg.identity = Some(relay_root.identity.clone());
            relay.cfg.extra_toml = format!(
                "[relays]\nnamespace = false\n\n[relay_service]\nserve = \"open\"\n\n{FAST_LINKS}"
            );
            cx.start("relay")?;
            let list = link_list(cx, "relay")?;
            cx.evidence(&format!(
                "relay: serve {}",
                list.serve.as_deref().unwrap_or("-")
            ));
            let key = list
                .key
                .ok_or_else(|| "the relay's link list shows no key".to_owned())?;
            Ok((relay_root, key))
        },
    )?;
    let (alice_root, bob_root) = sc.step(
        &format!(
            "alice creates {} and bob {} (init); each init config advertises the relay in the \
             namespace's trust context ([[ca.relay]]: its device name, link key and endpoint)",
            ns.a, ns.b
        ),
        |cx| {
            let advertised = format!(
                "[[ca.relay]]\ndevice = \"{}\"\nkey = \"{relay_key}\"\nendpoint = \
                 \"{}:{QUIC_PORT}\"\n",
                relay_root.identity,
                addr(RELAY)
            );
            let mut roots = Vec::new();
            for (node, ns) in [("alice", ns.a), ("bob", ns.b)] {
                cx.w.node_mut(node).cfg.extra_toml =
                    format!("[ca]\nprefix = \"{ns}\"\n\n{advertised}");
                let (root, out) = init_root_with(cx, node, ns, node, true)?;
                let relays = out.kv_all("relay");
                if relays.len() != 1 || !relays[0].contains(&relay_root.identity) {
                    return Err(format!(
                        "{node}'s init of {ns} advertises {relays:?}, expected the relay {}",
                        relay_root.identity
                    ));
                }
                cx.evidence(&format!("{node}: init {ns}: relay = {}", relays[0]));
                roots.push(root);
            }
            let bob_root = roots.pop().expect("two roots");
            let alice_root = roots.pop().expect("two roots");
            Ok((alice_root, bob_root))
        },
    )?;
    sc.step(
        "each person points at the other (adopts the other's inline anchor link) and starts",
        |cx| {
            for (node, root, other_ns, other) in [
                ("alice", &alice_root, ns.b, &bob_root),
                ("bob", &bob_root, ns.a, &alice_root),
            ] {
                let n = cx.w.node_mut(node);
                n.cfg.identity = Some(root.identity.clone());
                n.cfg.extra_toml = format!("{NO_DIRECT}\n{FAST_LINKS}");
                adopt_offline(cx, node, other_ns, &other.link_inline)?;
                cx.start(node)?;
            }
            Ok(())
        },
    )?;
    sc.step(
        &format!(
            "each person's daemon links to the relay its namespace advertises, routes the other \
             namespace over it and runs both groups with multicast; the relay, holding no context \
             of {} or {}, routes each device, its issuer's key name and its namespace's group \
             over its link and runs both groups with multicast; no config holds a route, a UDP \
             link, a [[peer]] or a [[relay]]",
            ns.a, ns.b
        ),
        |cx| {
            cx.concept("sync groups of two namespaces carried through a relay");
            for node in ["alice", "bob", "relay"] {
                let n = cx.w.node(node);
                let config = n.render();
                if !n.cfg.routes.is_empty()
                    || !n.cfg.links.is_empty()
                    || config.contains("[[route]]")
                    || config.contains("routes =")
                    || config.contains("[[peer]]")
                    || config.contains("[[relay]]")
                    || config.contains("roots =")
                {
                    return Err(format!(
                        "{node}'s config holds a route, a UDP link, a peer, a relay or a roots \
                         list:\n{config}"
                    ));
                }
                cx.evidence(&format!(
                    "{node}'s config: no [[route]], no `routes`, no UDP [[face]] link, no \
                     [[peer]], no [[relay]], no `roots`"
                ));
            }
            for person in [ns.a, ns.b] {
                if let Some(v) = cx.version("relay", person) {
                    return Err(format!("the relay holds {person} v{v}"));
                }
            }
            cx.expect_version("relay", ns.relay, 1)?;
            cx.evidence(&format!(
                "relay holds {} only: no trust context of {} or {}",
                ns.relay, ns.a, ns.b
            ));
            for (node, own, other) in [("alice", ns.a, ns.b), ("bob", ns.b, ns.a)] {
                let mut line = None;
                wait_for(
                    cx,
                    &format!("{node} links to the relay {own} advertises"),
                    SHORT,
                    |cx| {
                        let list = link_list(cx, node)?;
                        line = list
                            .links
                            .iter()
                            .find(|l| l.label == relay_root.identity && !l.paths.is_empty())
                            .and_then(|l| l.relay.clone())
                            .filter(|r| {
                                r.starts_with("linked")
                                    && r.contains(&format!("source=namespace:{own}"))
                            });
                        Ok(line.is_some())
                    },
                )?;
                cx.evidence(&format!(
                    "{node} → {}: relay {}",
                    relay_root.identity,
                    line.unwrap_or_default()
                ));
                let mut found = None;
                wait_for(
                    cx,
                    &format!("{node} routes {other} over its relay link"),
                    SHORT,
                    |cx| {
                        found = routes_over_relay(cx, ns, node, other)?;
                        Ok(found.is_some())
                    },
                )?;
                cx.evidence(&found.unwrap_or_default());
            }
            let mut found = None;
            wait_for(
                cx,
                "the relay routes each device, its issuer and its namespace's group over its link",
                SHORT,
                |cx| {
                    found = relay_routes(cx, ns, &alice_root.identity, &bob_root.identity)?;
                    Ok(found.is_some())
                },
            )?;
            cx.evidence(&found.unwrap_or_default());
            Ok(())
        },
    )?;
    Ok((alice_root, bob_root))
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    let (alice_root, bob_root) = people_through_relay(sc, NAMESPACES)?;

    let (mut alice, mut bob) = sc.step(
        "start the data layer on alice's and bob's devices (ndn-data, each signing with its \
         root device's key)",
        |cx| {
            cx.concept("data layer host (ndn-data)");
            let alice = Host::start(cx, "alice", &alice_root.identity)?;
            let bob = Host::start(cx, "bob", &bob_root.identity)?;
            for (h, root) in [(&alice, &alice_root), (&bob, &bob_root)] {
                let keys = cx.w.keys(&h.node);
                if !h.writer.starts_with(&format!("{}/KEY/", root.identity))
                    || !keys.contains(&h.writer)
                {
                    return Err(format!(
                        "{} writes as {}, not a key of {} in its PIB ({keys:?})",
                        h.node, h.writer, root.identity
                    ));
                }
                cx.evidence(&format!("{} writes as {}", h.node, h.writer));
            }
            Ok((alice, bob))
        },
    )?;

    sc.step(
        "bob watches alice's document and chat; alice shares the document (merge) and the chat \
         (log) with writers /sa,/sb and readers person:/sa,person:/sb, and watches the chat",
        |cx| {
            bob.ok(cx, &format!("watch {DOC}"))?;
            bob.ok(cx, &format!("watch {CHAT}"))?;
            alice.ok(cx, &format!("share {DOC} rule=merge {BOTH}"))?;
            alice.ok(cx, &format!("share {CHAT} rule=log {BOTH}"))?;
            alice.ok(cx, &format!("watch {CHAT}"))?;
            cx.evidence(&format!(
                "alice shared {DOC} (merge) and {CHAT} (log): {BOTH}"
            ));
            Ok(())
        },
    )?;
    let (draft1, hi_bob) = sc.step(
        "alice writes the document text=draft 1 and the chat text=hi bob",
        |cx| {
            Ok((
                alice.put(cx, DOC, "text=\"draft 1\"")?,
                alice.put(cx, CHAT, "text=\"hi bob\"")?,
            ))
        },
    )?;
    sc.step(
        "bob reads the document until it holds draft 1; his chat watch delivers hi bob, the \
         chat's newest",
        |cx| {
            wait_for(cx, "bob holds draft 1", CONVERGE, |cx| {
                Ok(bob
                    .state(cx, DOC)?
                    .is_some_and(|(at, v)| includes(&at, &draft1) && v["text"] == "draft 1"))
            })?;
            cx.evidence("bob's document state includes draft 1, text = \"draft 1\"");
            let w = bob.watched_until(cx, "hi bob in bob's chat watch", CONVERGE, |w| {
                delivers(w, CHAT, &hi_bob, "text", "hi bob")
            })?;
            cx.evidence(&format!(
                "bob's chat watch delivered {}",
                w["change"]["version"]["name"]
            ));
            let newest = bob.ok(cx, &format!("get {CHAT}"))?;
            if newest["version"]["payload"]["entry"]["text"] != "hi bob" {
                return Err(format!("bob's chat's newest is {newest}, not hi bob"));
            }
            cx.evidence(&format!(
                "bob's get of the chat (log rule): the newest version {}",
                newest["version"]["name"]
            ));
            Ok(())
        },
    )?;
    let looks_good = sc.step(
        "bob writes the document bob=looks good and the chat text=hi alice; alice holds both",
        |cx| {
            let looks_good = bob.put(cx, DOC, "bob=\"looks good\"")?;
            let hi_alice = bob.put(cx, CHAT, "text=\"hi alice\"")?;
            let mut last = Value::Null;
            wait_for(cx, "alice holds looks good", CONVERGE, |cx| {
                Ok(alice.state(cx, DOC)?.is_some_and(|(at, v)| {
                    let done = includes(&at, &looks_good) && includes(&at, &draft1);
                    last = v;
                    done
                }))
            })?;
            if last["bob"] != "looks good" || last["text"] != "draft 1" {
                return Err(format!("alice's document value is {last}"));
            }
            cx.evidence(&format!(
                "alice's document state includes bob's edit: {last}"
            ));
            let w = alice.watched_until(cx, "hi alice in alice's chat watch", CONVERGE, |w| {
                delivers(w, CHAT, &hi_alice, "text", "hi alice")
            })?;
            cx.evidence(&format!(
                "alice's chat watch delivered {}",
                w["change"]["version"]["name"]
            ));
            Ok(looks_good)
        },
    )?;
    let epoch1 = sc.step(
        "the relay fetches alice's versions through its own daemon, which carries them in transit \
         (unvalidated: it holds no context of /sa), and cannot read them: each is a sealed record \
         without its plaintext",
        |cx| {
            cx.concept("sealed collections: relays carry ciphertext only");
            let plain = ["draft 1", "hi bob"];
            let epoch = relay_sees_sealed(cx, &draft1, &plain)?;
            relay_sees_sealed(cx, &hi_bob, &plain)?;
            Ok(epoch)
        },
    )?;

    if !crate::works(std::process::Command::new("nft").arg("--version")) {
        sc.skip(
            "cut bob from the relay, remove bob, restore, refuse his offline edit",
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
    let offline = sc.step(
        "offline, bob writes the document bob=offline edit; his own state holds it",
        |cx| {
            let offline = bob.put(cx, DOC, "bob=\"offline edit\"")?;
            let (at, value) = bob
                .state(cx, DOC)?
                .ok_or("bob holds no state of the document")?;
            if !includes(&at, &offline) || value["bob"] != "offline edit" {
                return Err(format!("bob's state offline is at {at}, value {value}"));
            }
            cx.evidence(&format!("bob offline: at {at}, value {value}"));
            unanswered(cx, "alice", &offline.name)?;
            cx.evidence(&format!("alice's daemon gets no {}", offline.name));
            Ok(offline)
        },
    )?;
    sc.step(
        "alice removes bob from the document and the chat: writers /sa, readers person:/sa",
        |cx| {
            cx.concept("removal cuts and reseal");
            alice.ok(cx, &format!("share {DOC} rule=merge {ALICE_ONLY}"))?;
            alice.ok(cx, &format!("share {CHAT} rule=log {ALICE_ONLY}"))?;
            cx.evidence(&format!(
                "alice shared {DOC} and {CHAT} again: {ALICE_ONLY}"
            ));
            Ok(())
        },
    )?;
    sc.step("bob is back: the nftables table goes", |cx| {
        drop(cut);
        cx.evidence("UDP between bob and the relay flows again");
        Ok(())
    })?;
    sc.step(
        "alice refuses bob's offline edit (outside the cut: ask the owner) and keeps looks good",
        |cx| {
            let e = refused(cx, &mut alice, &offline.name)?;
            if e["next"] != "ask-owner" {
                return Err(format!("alice's get of {} answers {e}", offline.name));
            }
            cx.evidence(&format!(
                "alice> get {}: {} (next: {})",
                offline.name, e["message"], e["next"]
            ));
            let (at, value) = alice
                .state(cx, DOC)?
                .ok_or("alice holds no state of her document")?;
            if includes(&at, &offline)
                || !includes(&at, &looks_good)
                || value["bob"] != "looks good"
            {
                return Err(format!("alice's document state is at {at}, value {value}"));
            }
            cx.evidence(&format!("alice's document state: at {at}, value {value}"));
            Ok(())
        },
    )?;
    sc.step(
        "bob's watch reports his offline version withdrawn by alice's cut of /sb; outside the \
         audience now, his get of the document is sealed (ask the owner)",
        |cx| {
            let w = bob.watched_until(cx, "the offline edit withdrawn", CONVERGE, |w| {
                let withdrawn = &w["change"]["withdrawn"];
                name(w["watch"].as_str().unwrap_or_default()).ok() == name(DOC).ok()
                    && withdrawn["id"]["writer"] == offline.writer.as_str()
                    && withdrawn["id"]["seq"] == offline.seq
                    && name(withdrawn["cut_of"].as_str().unwrap_or_default()).ok()
                        == name(NS_B).ok()
            })?;
            cx.evidence(&format!("bob's document watch: {}", w["change"]));
            match bob.call(cx, &format!("get {DOC}"))? {
                Err(e) if sealed_to(&e) => cx.evidence(&format!(
                    "bob> get {DOC}: {} (next: {})",
                    e["message"], e["next"]
                )),
                other => return Err(format!("bob's get of the document answers {other:?}")),
            }
            Ok(())
        },
    )?;
    sc.step(
        "alice writes the document text=draft 2 in a new epoch; bob cannot read it (sealed: ask \
         the owner)",
        |cx| {
            let draft2 = alice.put(cx, DOC, "text=\"draft 2\"")?;
            let (_, value) = alice
                .state(cx, DOC)?
                .ok_or("alice holds no state of her document")?;
            if value["text"] != "draft 2" {
                return Err(format!("alice's document value is {value}"));
            }
            let epoch2 = relay_sees_sealed(cx, &draft2, &["draft 2"])?;
            if epoch2 == epoch1 {
                return Err(format!("draft 2 is sealed in draft 1's epoch {epoch1}"));
            }
            cx.evidence(&format!("draft 2's epoch {epoch2}, draft 1's {epoch1}"));
            let e = refused(cx, &mut bob, &draft2.name)?;
            if !sealed_to(&e) {
                return Err(format!("bob's get of {} answers {e}", draft2.name));
            }
            let message = &e["message"];
            cx.evidence(&format!(
                "bob> get {}: {message} (next: {})",
                draft2.name, e["next"]
            ));
            match bob.call(cx, &format!("get {DOC}"))? {
                Err(e) if sealed_to(&e) => cx.evidence(&format!(
                    "bob> get {DOC}: {} (next: {})",
                    e["message"], e["next"]
                )),
                other => return Err(format!("bob's get of the document answers {other:?}")),
            }
            Ok(())
        },
    )?;
    Ok(())
}
