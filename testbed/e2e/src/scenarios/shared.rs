//! shared: two people share a document and a chat across their trusted
//! prefixes through a relay that carries them and cannot read them — the
//! data layer (`ndn_data::Device`) on real daemons.
//!
//! Topology, on the harness's `lo`: alice (10.200.0.1, the root device of
//! /sa), bob (.2, the root device of /sb) and a relay (.3, the root device
//! of /sr, listening for QUIC links and serving the devices of /sa and /sb
//! by their root fingerprints: `[relay_service] serve = "listed"`). Each
//! person follows the other's namespace (adopts its inline anchor link
//! before the daemon first starts) and adds the relay as a `[[relay]]` by
//! its link-key fingerprint; the relay follows both. No config holds a
//! route or a UDP link: over a link to a relay the person added, the link
//! library routes each namespace the device follows as well as its own, so
//! alice's daemon routes /sb (bob's device and, beneath it, /sb/32=sync) to
//! the relay; the relay routes each linked device's name and the sync group
//! of the device's namespace over that device's link; the trust-context
//! library runs each held namespace's group with the multicast strategy.
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
//! The relay fetches and validates the versions (it holds /sa) and their
//! Content is a sealed record (an epoch and a ciphertext, no fields) that
//! holds neither plaintext. With UDP between bob and the relay cut, bob
//! edits the document; alice removes bob as writer and reader. Once the
//! link is back, alice's state never takes bob's offline edit (refused
//! outside the cut: ask the owner) and keeps his earlier one; bob's watch
//! reports his offline version withdrawn by the cut, and outside the
//! audience his get of the document is sealed; alice's next version is
//! sealed in a new epoch, which bob cannot open.

use std::net::Ipv4Addr;

use bytes::Bytes;
use ndn_data::wire::{Record, decode_record};
use serde_json::Value;

use super::data_host::{
    CONVERGE, Host, Put, includes, key_locator, multicast_at, name, rib, unanswered,
};
use super::direct_paths::link_list;
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{NodeCfg, QUIC_PORT, addr};

const NS_A: &str = "/sa";
const NS_B: &str = "/sb";
const NS_R: &str = "/sr";
/// Alice's document and chat, in her namespace.
const DOC: &str = "/sa/32=data/docs/plan";
const CHAT: &str = "/sa/32=data/chat/ab";
/// The namespaces' sync groups (data-layer spec §12).
const GROUP_A: &str = "/sa/32=sync";
const GROUP_B: &str = "/sb/32=sync";
/// Bob writes and reads beside alice; then alice alone.
const BOTH: &str = "writers=/sa,/sb readers=person:/sa,person:/sb";
const ALICE_ONLY: &str = "writers=/sa readers=person:/sa";
/// The nftables table that cuts bob–relay.
const CUT_TABLE: &str = "ndn_e2e_shared_cut";

const ALICE: u8 = 1;
const BOB: u8 = 2;
const RELAY: u8 = 3;

/// Link timing that notices a lost link within seconds.
const FAST_LINKS: &str = "[links]\nkeep_alive_secs = 2\nidle_timeout_secs = 6\n";
/// Whatever reaches the other person goes through the relay.
const NO_DIRECT: &str = "[direct]\nmembership = false\n";

/// `node`'s QUIC link face to the daemon bound to `host`'s address.
fn quic_face_to(cx: &mut Cx<'_>, node: &str, host: u8) -> StepResult<Option<u64>> {
    let sock = cx.w.node(node).sock().display().to_string();
    let op = cx
        .tool("ndn-ctl")
        .args(["--socket", &sock, "face", "list", "--scheme", "quic4"]);
    let out = cx.exec(op);
    if !out.success() {
        return Err(format!("face list on {node}: {}", out.status_text()));
    }
    let mut face = None;
    for line in out.stdout.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("faceid=") {
            face = rest.split_whitespace().next().and_then(|f| f.parse().ok());
        } else if let Some(remote) = t.strip_prefix("remote: quic4://")
            && remote
                .split(':')
                .next()
                .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
                == Some(addr(host))
        {
            return Ok(face);
        }
    }
    Ok(None)
}

/// Alice or bob: its link face to the relay carries `other` (the other
/// person's namespace), and it runs both groups with multicast.
fn routes_over_relay(cx: &mut Cx<'_>, node: &str, other: &str) -> StepResult<Option<String>> {
    let Some(face) = quic_face_to(cx, node, RELAY)? else {
        return Ok(None);
    };
    let Some((_, origin)) = rib(cx, node, other)?.into_iter().find(|(f, _)| *f == face) else {
        return Ok(None);
    };
    let (Some(a), Some(b)) = (
        multicast_at(cx, node, GROUP_A)?,
        multicast_at(cx, node, GROUP_B)?,
    ) else {
        return Ok(None);
    };
    Ok(Some(format!(
        "{node}: {other} → face {face} (the relay link, {origin}); {GROUP_A} runs {a}, {GROUP_B} \
         runs {b}"
    )))
}

/// The relay: each person's device name and the group of that person's
/// namespace over the person's link, both groups run with multicast.
/// (Alice reaches bob through /sb's group, a member namespace of her
/// collections, and bob alice through /sa's.)
fn relay_routes(cx: &mut Cx<'_>, alice: &str, bob: &str) -> StepResult<Option<String>> {
    let (Some(fa), Some(fb)) = (
        quic_face_to(cx, "relay", ALICE)?,
        quic_face_to(cx, "relay", BOB)?,
    ) else {
        return Ok(None);
    };
    let on = |routes: &[(u64, String)], face: u64| routes.iter().any(|(f, _)| *f == face);
    let routed = on(&rib(cx, "relay", alice)?, fa)
        && on(&rib(cx, "relay", GROUP_A)?, fa)
        && on(&rib(cx, "relay", bob)?, fb)
        && on(&rib(cx, "relay", GROUP_B)?, fb);
    let (Some(a), Some(b)) = (
        multicast_at(cx, "relay", GROUP_A)?,
        multicast_at(cx, "relay", GROUP_B)?,
    ) else {
        return Ok(None);
    };
    Ok(routed.then(|| {
        format!(
            "relay: {alice} and {GROUP_A} → face {fa}; {bob} and {GROUP_B} → face {fb}; \
             {GROUP_A} runs {a}, {GROUP_B} runs {b}"
        )
    }))
}

/// `name` fetched through `node`'s daemon (which validates it against the
/// trust context before delivering it): its Content's octets.
fn content_at(cx: &mut Cx<'_>, node: &str, name: &str) -> StepResult<Vec<u8>> {
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
/// epoch and a ciphertext, no fields). The epoch, as `<creator>/seq`.
fn relay_sees_sealed(cx: &mut Cx<'_>, v: &Put, plain: &[&str]) -> StepResult<String> {
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
        "relay fetched {} (KeyLocator {key}, validated with /sa held): {} octets, a version \
         record sealed in epoch {epoch}, {}-octet ciphertext, no fields; none of {plain:?} in it",
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

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
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

    let (alice_root, bob_root, relay_root) = sc.step(
        "init alice as the root device of /sa, bob of /sb, the relay of /sr",
        |cx| {
            Ok((
                init_root(cx, "alice", NS_A, "alice")?,
                init_root(cx, "bob", NS_B, "bob")?,
                init_root(cx, "relay", NS_R, "relay")?,
            ))
        },
    )?;
    let relay_key = sc.step(
        "the relay follows /sa and /sb (inline anchor links, offline) and starts, serving the \
         devices of both by their root fingerprints",
        |cx| {
            cx.concept("relay serving listed namespaces");
            let relay = cx.w.node_mut("relay");
            relay.cfg.identity = Some(relay_root.identity.clone());
            relay.cfg.extra_toml = format!(
                "[relays]\nnamespace = false\n\n[relay_service]\nserve = \"listed\"\nroots = \
                 [\"{}\", \"{}\"]\n\n{FAST_LINKS}",
                alice_root.fp, bob_root.fp
            );
            adopt_offline(cx, "relay", NS_A, &alice_root.link_inline)?;
            adopt_offline(cx, "relay", NS_B, &bob_root.link_inline)?;
            cx.start("relay")?;
            let list = link_list(cx, "relay")?;
            cx.evidence(&format!(
                "relay: serve {}",
                list.serve.as_deref().unwrap_or("-")
            ));
            list.key
                .ok_or_else(|| "the relay's link list shows no key".to_owned())
        },
    )?;
    sc.step(
        "each person follows the other's namespace (inline anchor link, offline), adds the relay \
         as a [[relay]] by its link-key fingerprint, and starts",
        |cx| {
            for (node, root, other_ns, other) in [
                ("alice", &alice_root, NS_B, &bob_root),
                ("bob", &bob_root, NS_A, &alice_root),
            ] {
                let n = cx.w.node_mut(node);
                n.cfg.identity = Some(root.identity.clone());
                n.cfg.extra_toml = format!(
                    "{NO_DIRECT}\n{FAST_LINKS}\n[[relay]]\nkey = \"{relay_key}\"\nendpoint = \
                     \"{}:{QUIC_PORT}\"\n",
                    addr(RELAY)
                );
                adopt_offline(cx, node, other_ns, &other.link_inline)?;
                cx.start(node)?;
            }
            Ok(())
        },
    )?;
    sc.step(
        "each person's daemon routes the other namespace over its relay link and runs both \
         groups with multicast; the relay routes each device and its namespace's group over its \
         link; no config holds a route or a UDP link",
        |cx| {
            cx.concept("sync groups of two namespaces carried through a relay");
            for node in ["alice", "bob", "relay"] {
                let n = cx.w.node(node);
                let config = n.render();
                if !n.cfg.routes.is_empty()
                    || !n.cfg.links.is_empty()
                    || config.contains("[[route]]")
                    || config.contains("routes =")
                {
                    return Err(format!(
                        "{node}'s config holds a route or a UDP link:\n{config}"
                    ));
                }
                cx.evidence(&format!(
                    "{node}'s config: no [[route]], no `routes`, no UDP [[face]] link"
                ));
            }
            for (node, other) in [("alice", NS_B), ("bob", NS_A)] {
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
            let mut found = None;
            wait_for(
                cx,
                "the relay routes each device and its namespace's group over its link",
                SHORT,
                |cx| {
                    found = relay_routes(cx, &alice_root.identity, &bob_root.identity)?;
                    Ok(found.is_some())
                },
            )?;
            cx.evidence(&found.unwrap_or_default());
            Ok(())
        },
    )?;

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
        "the relay fetches alice's versions through its own daemon, validating them, and cannot \
         read them: each is a sealed record without its plaintext",
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
