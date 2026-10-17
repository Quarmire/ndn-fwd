//! recovery-compromised: someone else holds the old root device, which keeps
//! running. A replacement recovers with a file kit and cuts the old root, its
//! CA and every kit not kept out of the namespace.
//!
//! Topology: root (.1, the old root, then the attacker's) ← relay (.2,
//! becomes the root device) ← phone (.3); witness (.4) links only to the old
//! root, so the old root is the only source it can refresh from.

use std::time::Duration;

use crate::run::snapshot;
use crate::scenarios::*;
use crate::step::{Abort, Scenario};
use crate::world::{CaCfg, NodeCfg};

const NS: &str = "/rc";

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    let n = |s: &str| format!("{NS}{s}");
    sc.world.add("root", 1, NodeCfg::default());
    sc.world.add(
        "relay",
        2,
        NodeCfg {
            links: vec![link("root", 1), link("phone", 3)],
            routes: vec![route(NS, "root"), route(n("/member/phone"), "phone")],
            refresh_secs: 1,
            ..Default::default()
        },
    );
    sc.world.add(
        "phone",
        3,
        NodeCfg {
            links: vec![link("relay", 2)],
            routes: vec![route(NS, "relay")],
            refresh_secs: 1,
            ..Default::default()
        },
    );
    sc.world.add(
        "witness",
        4,
        NodeCfg {
            links: vec![link("root", 1)],
            routes: vec![route(NS, "root")],
            refresh_secs: 0,
            ..Default::default()
        },
    );

    let root = sc.step("init the root device", |cx| init_root(cx, "root", NS, "desk"))?;
    let invites = sc.step("mint a member invite", |cx| mint(cx, NS, &root.fp, 1, Some("2h")))?;
    sc.step("start the root device (CA) and the relay; relay adopts by fingerprint link", |cx| {
        cx.w.node_mut("root").cfg.identity = Some(root.identity.clone());
        cx.w.node_mut("root").cfg.ca = Some(CaCfg {
            prefix: NS.into(),
            identity: n("/CA"),
            tokens: invites.iter().map(|i| i.token.clone()).collect(),
            member_days: None,
        });
        cx.start("root")?;
        cx.start("relay")?;
        let op = cx
            .tool("ndn-fwd")
            .arg("adopt")
            .arg(&root.link_fp)
            .arg("-c")
            .arg(cx.w.node("relay").cfg_arg());
        cx.ok(op, "adopt")?;
        cx.expect_version("relay", NS, 1)
    })?;
    let old_cert = sc.step("phone enrolls with the invite through the relay", |cx| {
        cx.start("phone")?;
        enroll(cx, "phone", &invites[0], "phone", false, None)
    })?;
    let doc1 = content(10_000, 21);
    sc.step("phone publishes; the relay validates it", |cx| {
        cx.publish("phone", &n("/member/phone/doc1"), &doc1, None, None)?;
        cx.fetch_ok("relay", &n("/member/phone/doc1"), &doc1)
    })?;

    let kit_a = sc.world.dir.join("rc-kept.kit");
    let kit_b = sc.world.dir.join("rc-not-kept.kit");
    let mut kit_b_key = String::new();
    for (i, (kit, pass)) in [(&kit_a, KIT_PASS), (&kit_b, KIT2_PASS)].into_iter().enumerate() {
        let key = sc.step(&format!("create file recovery kit {} of 2", i + 1), |cx| {
            let op = cx
                .tool("ndn-fwd")
                .args(["recovery-kit", "create", "--format", "file", "--out"])
                .arg(kit.display().to_string())
                .arg("-c")
                .arg(cx.w.node("root").cfg_arg())
                .env("NDN_ROOT_PASSPHRASE", ROOT_PASS)
                .env("NDN_KIT_PASSPHRASE", pass);
            let out = cx.ok(op, "recovery-kit create file")?;
            cx.expect_version("root", NS, 2 + i as u64)?;
            first(out.kv("recovery_key")).ok_or_else(|| "no recovery_key in the output".to_owned())
        })?;
        kit_b_key = key;
    }
    sc.step("relay and phone adopt the kits' version by periodic refresh", |cx| {
        cx.wait_version("relay", NS, 3, SHORT)?;
        cx.wait_version("phone", NS, 3, SHORT).map(|_| ())
    })?;

    let new_root = sc.step(
        "the relay recovers with kit 1: --old-root compromised (the old root still answers)",
        |cx| {
            cx.concept("root device compromised (keeps running)");
            let op = cx
                .tool("ndn-fwd")
                .arg("recover")
                .arg("--kit")
                .arg(kit_a.display().to_string())
                .args([
                    "--old-root", "compromised", "--namespace", NS, "--root-store", "sealed-file",
                    "--device", "relay", "-c",
                ])
                .arg(cx.w.node("relay").cfg_arg())
                .env("NDN_KIT_PASSPHRASE", KIT_PASS)
                .env("NDN_ROOT_PASSPHRASE", NEW_ROOT_PASS)
                .timeout(Duration::from_secs(180));
            let out = cx.ok(op, "recover")?;
            cx.expect_version("relay", NS, 5)?;
            if cx.w.node_mut("root").daemon.as_mut().is_none_or(|d| !d.alive()) {
                return Err("the old root's daemon is not running".into());
            }
            root_info(&out)
        },
    )?;
    let new_invites = sc.step("mint an invite for the new root's fingerprint", |cx| {
        mint(cx, NS, &new_root.fp, 1, Some("2h"))
    })?;
    sc.step("restart the relay as the root device with the printed [security]/[ca] lines", |cx| {
        cx.stop("relay");
        let relay = cx.w.node_mut("relay");
        relay.cfg.identity = Some(new_root.identity.clone());
        relay.cfg.ca = Some(CaCfg {
            prefix: NS.into(),
            identity: n("/CA"),
            tokens: new_invites.iter().map(|i| i.token.clone()).collect(),
            member_days: None,
        });
        cx.start("relay")
    })?;
    sc.step("phone adopts the recovered version by periodic refresh", |cx| {
        cx.wait_version("phone", NS, 5, SHORT).map(|_| ())
    })?;
    let doc2 = content(6_000, 22);
    sc.step("the member's Data under its old certificate is refused at the relay", |cx| {
        cx.publish("phone", &n("/member/phone/doc2"), &doc2, None, None)?;
        // The recovered version revokes the old CA that certified it.
        cx.fetch_refused("relay", &n("/member/phone/doc2"), "revoked")
    })?;
    sc.step("phone enrolls again with the new invite (--force)", |cx| {
        let c = enroll(cx, "phone", &new_invites[0], "phone", true, None)?;
        let key = |c: &str| c.split("/NDNCERT/").next().unwrap_or("").to_owned();
        if key(&c) == key(&old_cert) {
            return Err(format!("re-enrollment certified the old key: {c}"));
        }
        Ok(())
    })?;
    let doc3 = content(6_000, 23);
    sc.step("Data under the new certificate validates at the relay", |cx| {
        cx.w.stop_producers("phone");
        cx.publish("phone", &n("/member/phone/doc3"), &doc3, None, None)?;
        cx.fetch_ok("relay", &n("/member/phone/doc3"), &doc3)
    })?;
    sc.step("the kit not kept was revoked; the kit used still checks out", |cx| {
        cx.input(format!("kit not kept: {kit_b_key}"));
        let cfg = cx.w.node("relay").cfg_arg();
        let op = cx
            .tool("ndn-fwd")
            .args(["recovery-kit", "check"])
            .arg(kit_b.display().to_string())
            .args(["--namespace", NS, "-c"])
            .arg(&cfg)
            .env("NDN_KIT_PASSPHRASE", KIT2_PASS);
        cx.refused(op, "check the kit not kept")?;
        let op = cx
            .tool("ndn-fwd")
            .args(["recovery-kit", "check"])
            .arg(kit_a.display().to_string())
            .args(["--namespace", NS, "-c"])
            .arg(&cfg)
            .env("NDN_KIT_PASSPHRASE", KIT_PASS);
        cx.ok(op, "check the kit used").map(|_| ())
    })?;
    sc.step("a witness linked only to the old root adopts the recovered version inline", |cx| {
        cx.start("witness")?;
        let op = cx
            .tool("ndn-fwd")
            .arg("adopt")
            .arg(&new_root.link_inline)
            .arg("-c")
            .arg(cx.w.node("witness").cfg_arg());
        cx.ok(op, "adopt")?;
        cx.expect_version("witness", NS, 5)
    })?;
    sc.step("the old root signs three more versions (as its holder can)", |cx| {
        cx.concept("attacker holds the old root");
        for i in 0..3 {
            old_root_signs(cx, i)?;
        }
        cx.expect_version("root", NS, 6)
    })?;
    sc.step("holders refuse the old root's versions", |cx| {
        let pib = cx.w.node("witness").pib();
        let before = snapshot(&pib.join("contexts"));
        let op = cx
            .tool("ndn-fwd")
            .args(["context", "refresh", NS, "-c"])
            .arg(cx.w.node("witness").cfg_arg());
        // The refresh reports a refusal; what counts is the state it leaves.
        let _ = cx.op(op);
        if snapshot(&pib.join("contexts")) != before {
            return Err("the witness's held contexts changed".into());
        }
        cx.expect_version("witness", NS, 5)?;
        cx.expect_version("phone", NS, 5)?;
        cx.expect_version("relay", NS, 5)
    })?;
    Ok(())
}

/// One `recovery-kit create` on the old root device (the attacker's
/// signatures: each is a version signed by the old root).
fn old_root_signs(cx: &mut crate::step::Cx<'_>, i: u32) -> crate::step::StepResult<()> {
    let out = cx.w.dir.join(format!("attacker-{i}.kit"));
    let op = cx
        .tool("ndn-fwd")
        .args(["recovery-kit", "create", "--format", "file", "--out"])
        .arg(out.display().to_string())
        .arg("-c")
        .arg(cx.w.node("root").cfg_arg())
        .env("NDN_ROOT_PASSPHRASE", ROOT_PASS)
        .env("NDN_KIT_PASSPHRASE", KIT_PASS);
    cx.ok(op, "old root signs a version").map(|_| ())
}
