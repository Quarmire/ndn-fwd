//! self-certifying: people named by their keys — `/user/<0xA1: SHA-256 of
//! the genesis root>` — followed by name alone, through a recovery after
//! compromise that keeps the name, and introduced to each other by a code
//! through the data layer on their daemons.
//!
//! Topology, on the harness's `lo`: alice (10.200.0.1, the root device of
//! alice's namespace, later the attacker's) ↔ spare (.3, another device of
//! alice's, which recovers her namespace) ↔ bob (.2, the root device of
//! bob's namespace); carol (.4, the root device of carol's) ↔ spare. Each
//! daemon routes the other namespaces it reaches over its UDP links: spare
//! routes alice's namespace to alice, bob's to bob and carol's to carol; bob
//! and carol route alice's to spare. The routes name namespaces only `init`
//! printed: nothing is known of them before.
//!
//! The gestures:
//! 1. `ndn-fwd init --self-certifying` on alice, bob and carol: each
//!    namespace is named from its new root key, init signs its genesis (v1,
//!    the root alone) and v2 (the CA, schema and policies), and prints its
//!    name-only anchor link (`anchor_uri_name`), a namespace and nothing else;
//! 2. spare and bob adopt alice's namespace from that link: each daemon
//!    fetches version 1 by name and checks it is signed by the key the name
//!    hashes — no fingerprint is given anywhere — then reaches v2 from it;
//! 3. alice makes a file recovery kit (v3), which spare and bob follow;
//!    alice's root device is then held by someone else: spare recovers with
//!    the kit (`--old-root compromised`: v4 by the kit, v5 by spare's new
//!    root) and becomes the root device; bob follows to v5 by refresh, under
//!    the same name;
//! 4. alice's device (spare, `ndn-data`, signing as its new identity) shares
//!    a folder with herself and offers it; bob's device joins with the
//!    code's link alone (see [`super::data_host`] and [`super::invite`]);
//! 5. alice, recovered, shares another folder with herself and offers it;
//!    carol's device — a stranger, holding nothing of alice's namespace —
//!    joins with that code's link alone. (Another folder: bob's versions in
//!    the first are parents of alice's there, and carol trusts nothing of
//!    bob's namespace, so she cannot verify them.)
//!
//! Proves: the namespaces are `/user/<0xA1 component>`; the name-only link
//! carries no fingerprint and no context; spare and bob hold alice's v2
//! adopted by name; after the recovery bob holds v5 of the very same name;
//! the introduction is admitted on both sides — alice's daemon and her data
//! host adopt bob's namespace from his genesis (his credentials carry v2,
//! and alice's host vouches for it from what her daemon stored), bob's host
//! finds alice's recovered context already held under the same anchor —
//! and each reads what the other writes in the folder. Carol, given alice's
//! recovered v5 in the answer, reaches it from alice's genesis (by name,
//! through her daemon) and is admitted; carol and alice read each other's
//! writes in the second folder.

use std::time::Duration;

use ndn_security::self_certifying::self_certifying_digest;
use ndn_trust_envelope::TrustEnvelope;
use serde_json::Value;

use super::data_host::{CONVERGE, Host, includes, name};
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{NodeCfg, now_unix};

/// How long the offer stands, in ms.
const OFFER_FOR_MS: i64 = 3_600_000;

/// A namespace `ndn-fwd init --self-certifying` made: what it printed.
struct Named {
    /// The namespace, `/user/<0xA1: …>`.
    ns: String,
    root: RootInfo,
    /// `anchor_uri_name`: the namespace alone.
    by_name: String,
}

/// `ndn-fwd init --self-certifying` with a sealed-file root on `node`'s
/// PIB: the namespace is named from the new root key, a `/user/<0xA1>`
/// name, init signs its genesis (v1) and v2, and the name-only link
/// carries nothing else.
fn init_named(cx: &mut Cx<'_>, node: &str, device: &str) -> StepResult<Named> {
    let pib = cx.w.node(node).pib();
    let op = cx
        .tool("ndn-fwd")
        .args(["init", "--self-certifying", "--device", device, "--pib"])
        .arg(pib.display().to_string())
        .args(["--root-store", "sealed-file"])
        .env("NDN_ROOT_PASSPHRASE", ROOT_PASS);
    let out = cx.ok(op, "init --self-certifying")?;
    let ns = first(out.kv("namespace")).ok_or("init printed no namespace")?;
    if !matches!(self_certifying_digest(&name(&ns)?), Ok(Some(_))) {
        return Err(format!(
            "{node}: init --self-certifying named {ns}, not /user/<0xA1: 32 bytes>"
        ));
    }
    if first(out.kv("genesis")).is_none() {
        return Err(format!("{node}: init printed no genesis (version 1)"));
    }
    cx.expect_version(node, &ns, 2)?;
    let by_name = first(out.kv("anchor_uri_name")).ok_or("init printed no anchor_uri_name")?;
    match TrustEnvelope::from_uri(&by_name) {
        Ok(TrustEnvelope::Anchor {
            namespace: Some(named),
            fingerprint: None,
            version: None,
            context_data: None,
            context_content: None,
        }) if named == ns => {}
        other => {
            return Err(format!(
                "{node}: anchor_uri_name {by_name} is not {ns} alone: {other:?}"
            ));
        }
    }
    cx.evidence(&format!(
        "{node}: init --self-certifying named {ns}; anchor_uri_name carries the namespace alone \
         (no fingerprint, no context)"
    ));
    Ok(Named {
        ns,
        root: root_info(&out)?,
        by_name,
    })
}

/// `node`'s daemon adopts `link`, a link naming the namespace alone
/// (`ndn-fwd adopt`): it fetches the context by name.
fn adopt_by_name(cx: &mut Cx<'_>, node: &str, link: &str) -> StepResult<()> {
    let op = cx
        .tool("ndn-fwd")
        .arg("adopt")
        .arg(link)
        .arg("-c")
        .arg(cx.w.node(node).cfg_arg());
    let out = cx.ok(op, "adopt")?;
    match out.kv("source") {
        Some(source) if source.starts_with("fetched") => Ok(()),
        other => Err(format!(
            "{node}'s daemon adopted a name-only link from {other:?}, not fetched by name"
        )),
    }
}

/// A verb's error that says to ask again unchanged (no path answered).
fn retry(e: &Value) -> bool {
    e["retry"] == true
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    sc.world.add(
        "alice",
        1,
        NodeCfg {
            links: vec![link("spare", 3)],
            ..Default::default()
        },
    );
    sc.world.add(
        "bob",
        2,
        NodeCfg {
            links: vec![link("spare", 3)],
            refresh_secs: 1,
            ..Default::default()
        },
    );
    sc.world.add(
        "spare",
        3,
        NodeCfg {
            links: vec![link("alice", 1), link("bob", 2), link("carol", 4)],
            refresh_secs: 1,
            ..Default::default()
        },
    );
    sc.world.add(
        "carol",
        4,
        NodeCfg {
            links: vec![link("spare", 3)],
            ..Default::default()
        },
    );

    let (alice, bob, carol) = sc.step(
        "alice, bob and carol each create a namespace named from its new root key (init \
         --self-certifying): /user/<0xA1: SHA-256 of the key>, and a link naming it alone",
        |cx| {
            cx.concept("self-certifying namespace /user/<hash>");
            let alice = init_named(cx, "alice", "desk")?;
            let bob = init_named(cx, "bob", "phone")?;
            let carol = init_named(cx, "carol", "tablet")?;
            if alice.ns == bob.ns || alice.ns == carol.ns || bob.ns == carol.ns {
                return Err("two new roots named one namespace".into());
            }
            Ok((alice, bob, carol))
        },
    )?;

    sc.step(
        "the daemons start, routing the namespaces init named: spare routes alice's to alice, \
         bob's to bob and carol's to carol; bob and carol route alice's to spare; carol holds \
         nothing of alice's namespace",
        |cx| {
            cx.w.node_mut("alice").cfg.identity = Some(alice.root.identity.clone());
            cx.w.node_mut("spare").cfg.routes = vec![
                route(alice.ns.clone(), "alice"),
                route(bob.ns.clone(), "bob"),
                route(carol.ns.clone(), "carol"),
            ];
            let b = cx.w.node_mut("bob");
            b.cfg.identity = Some(bob.root.identity.clone());
            b.cfg.routes = vec![route(alice.ns.clone(), "spare")];
            let c = cx.w.node_mut("carol");
            c.cfg.identity = Some(carol.root.identity.clone());
            c.cfg.routes = vec![route(alice.ns.clone(), "spare")];
            for node in ["alice", "spare", "bob", "carol"] {
                cx.start(node)?;
            }
            if let Some(v) = cx.version("carol", &alice.ns) {
                return Err(format!("carol holds {} v{v}: not a stranger", alice.ns));
            }
            Ok(())
        },
    )?;

    sc.step(
        "spare and bob adopt alice's namespace from its name alone: each daemon fetches version \
         1, checks it is signed by the key the name hashes, and reaches v2 from it",
        |cx| {
            cx.concept("adoption by name alone (no fingerprint)");
            cx.input(format!("anchor_uri_name: {}", alice.by_name));
            for node in ["spare", "bob"] {
                adopt_by_name(cx, node, &alice.by_name)?;
                cx.expect_version(node, &alice.ns, 2)?;
                cx.evidence(&format!("{node} holds {} v2, adopted by name", alice.ns));
            }
            Ok(())
        },
    )?;

    let kit = sc.world.dir.join("self-certifying.kit");
    sc.step(
        "alice makes a file recovery kit (v3); spare and bob follow it by refresh",
        |cx| {
            let op = cx
                .tool("ndn-fwd")
                .args(["recovery-kit", "create", "--format", "file", "--out"])
                .arg(kit.display().to_string())
                .arg("-c")
                .arg(cx.w.node("alice").cfg_arg())
                .env("NDN_ROOT_PASSPHRASE", ROOT_PASS)
                .env("NDN_KIT_PASSPHRASE", KIT_PASS);
            cx.ok(op, "recovery-kit create file")?;
            cx.expect_version("alice", &alice.ns, 3)?;
            cx.wait_version("spare", &alice.ns, 3, SHORT)?;
            cx.wait_version("bob", &alice.ns, 3, SHORT).map(|_| ())
        },
    )?;

    let recovered = sc.step(
        "alice's root device is held by someone else: spare recovers her namespace with the kit \
         (--old-root compromised; the old root keeps running) and becomes its root device",
        |cx| {
            cx.concept("root device compromised (keeps running)");
            let op = cx
                .tool("ndn-fwd")
                .arg("recover")
                .arg("--kit")
                .arg(kit.display().to_string())
                .args(["--old-root", "compromised", "--namespace"])
                .arg(&alice.ns)
                .args(["--root-store", "sealed-file", "--device", "laptop", "-c"])
                .arg(cx.w.node("spare").cfg_arg())
                .env("NDN_KIT_PASSPHRASE", KIT_PASS)
                .env("NDN_ROOT_PASSPHRASE", NEW_ROOT_PASS)
                .timeout(Duration::from_secs(180));
            let out = cx.ok(op, "recover")?;
            cx.expect_version("spare", &alice.ns, 5)?;
            if cx
                .w
                .node_mut("alice")
                .daemon
                .as_mut()
                .is_none_or(|d| !d.alive())
            {
                return Err("the old root's daemon is not running".into());
            }
            let recovered = root_info(&out)?;
            cx.stop("spare");
            cx.w.node_mut("spare").cfg.identity = Some(recovered.identity.clone());
            cx.start("spare")?;
            Ok(recovered)
        },
    )?;

    sc.step(
        "bob follows alice's namespace to v5 by refresh: the same name, now rooted in spare's \
         new key",
        |cx| {
            cx.wait_version("bob", &alice.ns, 5, SHORT)?;
            cx.evidence(&format!(
                "bob holds {} v5: the name init printed, kept through the recovery",
                alice.ns
            ));
            Ok(())
        },
    )?;

    let (mut alice_host, mut bob_host) = sc.step(
        "start the data layer on alice's device (spare, signing as its recovered identity) and \
         on bob's",
        |cx| {
            cx.concept("data layer host (ndn-data)");
            let a = Host::start(cx, "spare", &recovered.identity)?;
            let b = Host::start(cx, "bob", &bob.root.identity)?;
            cx.evidence(&format!(
                "alice writes as {}, bob as {}",
                a.writer, b.writer
            ));
            Ok((a, b))
        },
    )?;

    let folder = format!("{}/32=data/trip", alice.ns);
    let notes = format!("{folder}/notes");
    let first_put = sc.step(
        "alice shares her folder with herself alone and writes its notes",
        |cx| {
            alice_host.ok(
                cx,
                &format!(
                    "share_folder {folder} rule=merge writers={ns} readers=person:{ns}",
                    ns = alice.ns
                ),
            )?;
            alice_host.put(cx, &notes, "text=\"packing list\"")
        },
    )?;

    let code = sc.step(
        "alice offers the folder: writer, for an hour, three wrong tries",
        |cx| offer_writer(cx, &mut alice_host, &folder),
    )?;

    sc.step(
        "bob's device joins with the code's link alone: admitted as writer of alice's folder; \
         alice's daemon now holds bob's namespace from his genesis",
        |cx| {
            cx.concept("an introduction between two people named by their keys");
            let joined = joins(cx, &mut bob_host, &code, "bob")?;
            if name(joined["folder"].as_str().unwrap_or_default())? != name(&folder)?
                || joined["role"] != "writer"
                || name(joined["inviter"].as_str().unwrap_or_default())? != name(&alice.ns)?
            {
                return Err(format!(
                    "bob joined {joined}, not {folder} as writer of {}",
                    alice.ns
                ));
            }
            cx.evidence(&format!("bob joined: {joined}"));
            cx.expect_version("spare", &bob.ns, 2)?;
            cx.expect_version("bob", &alice.ns, 5)?;
            cx.evidence(&format!(
                "spare holds {} v2 (from bob's genesis); bob still holds {} v5",
                bob.ns, alice.ns
            ));
            Ok(())
        },
    )?;

    let bobs = sc.step(
        "bob writes into the folder; alice reads it beside her own",
        |cx| {
            let bobs = bob_host.put(cx, &notes, "bob=\"hotel booked\"")?;
            wait_for(cx, "alice holds bob's notes", CONVERGE, |cx| {
                Ok(alice_host.state(cx, &notes)?.is_some_and(|(at, v)| {
                    includes(&at, &bobs)
                        && includes(&at, &first_put)
                        && v["bob"] == "hotel booked"
                        && v["text"] == "packing list"
                }))
            })?;
            cx.evidence("alice's notes state includes bob's version: bob = \"hotel booked\"");
            Ok(bobs)
        },
    )?;

    sc.step("alice writes the notes again; bob reads it", |cx| {
        let second = alice_host.put(cx, &notes, "text=\"packing list v2\"")?;
        wait_for(cx, "bob holds alice's v2", CONVERGE, |cx| {
            Ok(bob_host.state(cx, &notes)?.is_some_and(|(at, v)| {
                includes(&at, &second)
                    && includes(&at, &bobs)
                    && v["text"] == "packing list v2"
                    && v["bob"] == "hotel booked"
            }))
        })?;
        cx.evidence("bob's notes state includes alice's v2: text = \"packing list v2\"");
        Ok(())
    })?;

    let mut carol_host = sc.step(
        "start the data layer on carol's device; carol's daemon still holds nothing of alice's \
         namespace",
        |cx| {
            if let Some(v) = cx.version("carol", &alice.ns) {
                return Err(format!("carol holds {} v{v}: not a stranger", alice.ns));
            }
            let c = Host::start(cx, "carol", &carol.root.identity)?;
            cx.evidence(&format!("carol writes as {}", c.writer));
            Ok(c)
        },
    )?;

    let plans = format!("{}/32=data/plans", alice.ns);
    let agenda = format!("{plans}/agenda");
    let (code, first_plan) = sc.step(
        "alice, recovered (v5, rooted on spare), shares another folder with herself alone, \
         writes its agenda and offers it: writer",
        |cx| {
            alice_host.ok(
                cx,
                &format!(
                    "share_folder {plans} rule=merge writers={ns} readers=person:{ns}",
                    ns = alice.ns
                ),
            )?;
            let first_plan = alice_host.put(cx, &agenda, "text=\"day one: museum\"")?;
            Ok((offer_writer(cx, &mut alice_host, &plans)?, first_plan))
        },
    )?;

    sc.step(
        "carol's device, a stranger to alice's namespace, joins with the code's link alone: \
         carol's daemon reaches alice's v5 from her genesis, and spare's holds carol's v2",
        |cx| {
            cx.concept("a stranger joins a recovered self-certifying namespace");
            let joined = joins(cx, &mut carol_host, &code, "carol")?;
            if name(joined["folder"].as_str().unwrap_or_default())? != name(&plans)?
                || joined["role"] != "writer"
                || name(joined["inviter"].as_str().unwrap_or_default())? != name(&alice.ns)?
            {
                return Err(format!(
                    "carol joined {joined}, not {plans} as writer of {}",
                    alice.ns
                ));
            }
            cx.evidence(&format!("carol joined: {joined}"));
            cx.expect_version("carol", &alice.ns, 5)?;
            cx.expect_version("spare", &carol.ns, 2)?;
            cx.evidence(&format!(
                "carol holds {} v5 (from its genesis, under the name init printed); spare holds \
                 {} v2 (from carol's genesis)",
                alice.ns, carol.ns
            ));
            Ok(())
        },
    )?;

    let carols = sc.step(
        "carol reads alice's agenda and writes into it; alice reads carol's",
        |cx| {
            wait_for(cx, "carol holds alice's agenda", CONVERGE, |cx| {
                Ok(carol_host.state(cx, &agenda)?.is_some_and(|(at, v)| {
                    includes(&at, &first_plan) && v["text"] == "day one: museum"
                }))
            })?;
            let carols = carol_host.put(cx, &agenda, "carol=\"tickets bought\"")?;
            wait_for(cx, "alice holds carol's agenda", CONVERGE, |cx| {
                Ok(alice_host.state(cx, &agenda)?.is_some_and(|(at, v)| {
                    includes(&at, &carols)
                        && includes(&at, &first_plan)
                        && v["carol"] == "tickets bought"
                }))
            })?;
            cx.evidence(
                "alice's agenda state includes carol's version: carol = \"tickets bought\"",
            );
            Ok(carols)
        },
    )?;

    sc.step("alice writes the agenda again; carol reads it", |cx| {
        let again = alice_host.put(cx, &agenda, "text=\"day one: museum, then the park\"")?;
        wait_for(cx, "carol holds alice's second agenda", CONVERGE, |cx| {
            Ok(carol_host.state(cx, &agenda)?.is_some_and(|(at, v)| {
                includes(&at, &again)
                    && includes(&at, &carols)
                    && v["text"] == "day one: museum, then the park"
                    && v["carol"] == "tickets bought"
            }))
        })?;
        cx.evidence(
            "carol's agenda state includes alice's second version: text = \"day one: museum, \
             then the park\"",
        );
        Ok(())
    })?;
    Ok(())
}

/// `host` offers `folder`: writer, for an hour, three wrong tries. The code's
/// link.
fn offer_writer(cx: &mut Cx<'_>, host: &mut Host, folder: &str) -> StepResult<String> {
    cx.concept("introduction code");
    let until = (now_unix() * 1000 + OFFER_FOR_MS).to_string();
    let ok = host.ok(
        cx,
        &format!("offer {folder} role=writer until={until} tries=3"),
    )?;
    let link = ok["link"].as_str().unwrap_or_default().to_owned();
    if !link.starts_with("ndn-trust://intro/") {
        return Err(format!("the offer printed no intro link: {ok}"));
    }
    Ok(link)
}

/// `host` joins with `code`, asking again while no path answers: the answer.
fn joins(cx: &mut Cx<'_>, host: &mut Host, code: &str, who: &str) -> StepResult<Value> {
    let mut joined = Value::Null;
    wait_for(
        cx,
        &format!("{who}'s join is answered"),
        CONVERGE,
        |cx| match host.call(cx, &format!("join {code}"))? {
            Ok(ok) => {
                joined = ok;
                Ok(true)
            }
            Err(e) if retry(&e) => Ok(false),
            Err(e) => Err(format!(
                "{who}'s join was refused: {} (next: {}) {e}",
                e["message"], e["next_step"]
            )),
        },
    )?;
    Ok(joined)
}
