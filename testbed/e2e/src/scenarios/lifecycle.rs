//! lifecycle / lifecycle-push: a namespace from `init` to a revocation.
//!
//! Topology: root (10.200.0.1, root device + CA) ← relay (.2) ← phone (.3)
//! and tab (.4); tab also links straight to phone, so tab validates phone's
//! Data itself rather than trusting the relay's check.
//!
//! The push variant runs the same steps with `context_sync = true` and
//! `context_refresh_secs = 0` (no periodic refresh) everywhere: the
//! revocation can then only arrive over the namespace's sync group.

use std::time::Instant;

use crate::run::snapshot;
use crate::scenarios::*;
use crate::step::{Abort, Scenario};
use crate::world::NodeCfg;

pub fn run(sc: &mut Scenario, push: bool) -> Result<(), Abort> {
    let ns = if push { "/lp" } else { "/lc" };
    let refresh = if push { 0 } else { 1 };
    let n = |s: &str| format!("{ns}{s}");
    let base = NodeCfg {
        refresh_secs: refresh,
        context_sync: push,
        ..Default::default()
    };
    sc.world.add("root", 1, base.clone());
    sc.world.add(
        "relay",
        2,
        NodeCfg {
            links: vec![link("root", 1), link("phone", 3), link("tab", 4)],
            routes: vec![
                route(ns, "root"),
                route(n("/member/phone"), "phone"),
                route(n("/member/tab"), "tab"),
            ],
            ..base.clone()
        },
    );
    sc.world.add(
        "phone",
        3,
        NodeCfg {
            links: vec![link("relay", 2)],
            routes: vec![route(ns, "relay")],
            ..base.clone()
        },
    );
    sc.world.add(
        "tab",
        4,
        NodeCfg {
            links: vec![link("relay", 2), link("phone", 3)],
            routes: vec![route(ns, "relay"), route(n("/member/phone"), "phone")],
            ..base.clone()
        },
    );

    let root = sc.step("init the root device (sealed-file root, passphrase via env)", |cx| {
        init_root(cx, "root", ns, "desk")
    })?;
    let invites = sc.step("mint two member invites for the root's fingerprint", |cx| {
        mint(cx, ns, &root.fp, 2, Some("2h"))
    })?;
    sc.step("start the root device's daemon with its CA (member lifetime 1 day)", |cx| {
        cx.w.node_mut("root").cfg.identity = Some(root.identity.clone());
        cx.w.node_mut("root").cfg.ca = Some(crate::world::CaCfg {
            prefix: ns.into(),
            identity: n("/CA"),
            tokens: invites.iter().map(|i| i.token.clone()).collect(),
            member_days: Some(1),
        });
        cx.start("root")
    })?;
    sc.step("start the relay", |cx| cx.start("relay"))?;
    sc.step("relay adopts the namespace from a fingerprint-only link", |cx| {
        let op = cx
            .tool("ndn-fwd")
            .arg("adopt")
            .arg(&root.link_fp)
            .arg("-c")
            .arg(cx.w.node("relay").cfg_arg());
        cx.ok(op, "adopt")?;
        cx.expect_version("relay", ns, 1)
    })?;
    sc.step("start phone and tab", |cx| {
        cx.start("phone")?;
        cx.start("tab")
    })?;
    let phone_cert = sc.step("phone enrolls with an invite, through the relay", |cx| {
        let c = enroll(cx, "phone", &invites[0], "phone", false, Some(1))?;
        cx.expect_version("phone", ns, 1)?;
        if !c.starts_with(&n("/member/phone/KEY/")) {
            return Err(format!("unexpected certificate {c}"));
        }
        Ok(c)
    })?;
    sc.step("tab enrolls with the second invite", |cx| {
        enroll(cx, "tab", &invites[1], "tab", false, Some(1)).map(|_| ())
    })?;

    let doc1 = content(20_000, 1);
    sc.step("phone publishes signed Data", |cx| {
        cx.publish("phone", &n("/member/phone/doc1"), &doc1, None, None)
    })?;
    sc.step("tab fetches and validates it (cold caches, direct link)", |cx| {
        cx.fetch_ok("tab", &n("/member/phone/doc1"), &doc1)
    })?;
    sc.step("relay fetches and validates it (cold cache)", |cx| {
        cx.fetch_ok("relay", &n("/member/phone/doc1"), &doc1)
    })?;

    sc.step("restart every daemon; trust state persists", |cx| {
        let nodes = ["root", "relay", "phone", "tab"];
        let before: Vec<_> = nodes
            .iter()
            .map(|x| (cx.version(x, ns), cx.certs(x)))
            .collect();
        for x in nodes {
            cx.stop(x);
        }
        for x in nodes {
            cx.start(x)?;
        }
        let after: Vec<_> = nodes
            .iter()
            .map(|x| (cx.version(x, ns), cx.certs(x)))
            .collect();
        if before != after {
            return Err(format!("trust state changed across the restart: {before:?} -> {after:?}"));
        }
        cx.publish("phone", &n("/member/phone/doc1"), &doc1, None, None)
    })?;
    sc.step("after the restart: tab and relay fetch and validate again", |cx| {
        fetch_all(cx, &["tab", "relay"], &n("/member/phone/doc1"), &doc1)
    })?;

    sc.step("phone renews: same key, a new certificate name, 1-day lifetime", |cx| {
        let before = cx.certs("phone");
        let op = cx
            .tool("ndn-fwd")
            .arg("renew")
            .arg("-c")
            .arg(cx.w.node("phone").cfg_arg());
        let out = cx.ok(op, "renew")?;
        let renewed = new_cert(cx, "phone", &before)?;
        let key = |c: &str| c.split("/NDNCERT/").next().unwrap_or("").to_owned();
        if renewed == phone_cert || key(&renewed) != key(&phone_cert) {
            return Err(format!("renewal gave {renewed}, was {phone_cert}: expected the same key, a new name"));
        }
        check_lifetime(&out, 1)
    })?;
    let doc2 = content(9_000, 2);
    sc.step("Data signed after the renewal validates where the old certificate is cached", |cx| {
        cx.publish("phone", &n("/member/phone/doc2"), &doc2, None, None)?;
        fetch_all(cx, &["tab", "relay"], &n("/member/phone/doc2"), &doc2)
    })?;

    let v0 = sc.world.held_version("root", ns).unwrap_or(0);
    sc.step("revoke with a wrong passphrase changes nothing", |cx| {
        let pib = cx.w.node("root").pib();
        let before = (snapshot(&pib.join("contexts")), snapshot(&pib.join("ca")));
        let op = cx
            .tool("ndn-fwd")
            .arg("revoke")
            .arg(n("/member/phone"))
            .arg("-c")
            .arg(cx.w.node("root").cfg_arg())
            .env("NDN_ROOT_PASSPHRASE", WRONG_PASS);
        cx.refused(op, "revoke with a wrong passphrase")?;
        let after = (snapshot(&pib.join("contexts")), snapshot(&pib.join("ca")));
        if before != after {
            return Err("the root device's contexts/ or ca/ changed".into());
        }
        cx.expect_version("root", ns, v0)
    })?;
    sc.step("revoke phone with the right passphrase: a new trust-context version", |cx| {
        let op = cx
            .tool("ndn-fwd")
            .arg("revoke")
            .arg(n("/member/phone"))
            .arg("-c")
            .arg(cx.w.node("root").cfg_arg())
            .env("NDN_ROOT_PASSPHRASE", ROOT_PASS);
        cx.ok(op, "revoke")?;
        cx.expect_version("root", ns, v0 + 1)?;
        let revoked = cx.w.node("root").pib().join("ca").join("revoked");
        if snapshot(&revoked).is_empty() {
            return Err("the CA records no revoked certificate".into());
        }
        Ok(())
    })?;
    let how = if push { "by push (context_sync; no periodic refresh)" } else { "by pull (refresh every 1 s)" };
    sc.step(&format!("relay and tab adopt the revocation {how}"), |cx| {
        let start = Instant::now();
        cx.wait_version("relay", ns, v0 + 1, SHORT)?;
        cx.wait_version("tab", ns, v0 + 1, SHORT.saturating_sub(start.elapsed()))?;
        Ok(())
    })?;
    let doc3 = content(5_000, 3);
    sc.step("phone publishes after its revocation", |cx| {
        cx.publish("phone", &n("/member/phone/doc3"), &doc3, None, None)
    })?;
    sc.step("the revoked member's Data is refused at the relay", |cx| {
        cx.fetch_refused("relay", &n("/member/phone/doc3"), "revoked")
    })?;
    sc.step("the revoked member's Data is refused at tab (its own validation)", |cx| {
        cx.fetch_refused("tab", &n("/member/phone/doc3"), "revoked")
    })?;
    let note = content(3_000, 4);
    sc.step("control: tab's Data still validates at the relay", |cx| {
        cx.publish("tab", &n("/member/tab/note"), &note, None, None)?;
        cx.fetch_ok("relay", &n("/member/tab/note"), &note)
    })?;
    Ok(())
}
