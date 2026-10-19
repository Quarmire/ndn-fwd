//! recovery-destroyed: the root device is lost for good; a replacement takes
//! the namespace over with a recovery kit and nothing else.
//!
//! Topology: root (.1) ← relay (.2, becomes the root device) ← phone (.3)
//! and fresh (.4, a device that joins after the recovery).

use std::fs;
use std::time::Duration;

use crate::scenarios::*;
use crate::step::{Abort, Scenario};
use crate::world::{CaCfg, NodeCfg, cert_issuers};

const NS: &str = "/rd";

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    let n = |s: &str| format!("{NS}{s}");
    sc.world.add("root", 1, NodeCfg::default());
    sc.world.add(
        "relay",
        2,
        NodeCfg {
            links: vec![link("root", 1), link("phone", 3), link("fresh", 4)],
            routes: vec![
                route(NS, "root"),
                route(n("/member/phone"), "phone"),
                route(n("/member/tablet"), "fresh"),
            ],
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
        "fresh",
        4,
        NodeCfg {
            links: vec![link("relay", 2)],
            routes: vec![route(NS, "relay")],
            refresh_secs: 1,
            ..Default::default()
        },
    );

    let root = sc.step("init the root device", |cx| {
        init_root(cx, "root", NS, "desk")
    })?;
    sc.step(
        "start the root device (CA) and the relay; relay adopts by fingerprint link",
        |cx| {
            cx.w.node_mut("root").cfg.identity = Some(root.identity.clone());
            cx.w.node_mut("root").cfg.ca = Some(CaCfg {
                prefix: NS.into(),
                identity: n("/CA"),
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
        },
    )?;
    let invites = sc.step("make a member invite at the running CA", |cx| {
        mint(cx, "root", NS, &root.fp, 1, Some("2h"))
    })?;
    let old_cert = sc.step("phone enrolls with the invite through the relay", |cx| {
        cx.start("phone")?;
        enroll(cx, "phone", &invites[0], "phone", false, None)
    })?;
    let doc1 = content(12_000, 11);
    sc.step("phone publishes; the relay validates it", |cx| {
        cx.publish("phone", &n("/member/phone/doc1"), &doc1, None, None)?;
        cx.fetch_ok("relay", &n("/member/phone/doc1"), &doc1)
    })?;

    let words = sc.step("create a words recovery kit (root passphrase)", |cx| {
        let op = cx
            .tool("ndn-fwd")
            .args(["recovery-kit", "create", "--format", "words", "-c"])
            .arg(cx.w.node("root").cfg_arg())
            .env("NDN_ROOT_PASSPHRASE", ROOT_PASS);
        let out = cx.ok(op, "recovery-kit create words")?;
        cx.expect_version("root", NS, 2)?;
        words(&out)
    })?;
    let kit = sc.world.dir.join("rd-file.kit");
    sc.step(
        "create a file recovery kit (root passphrase, kit passphrase)",
        |cx| {
            let op = cx
                .tool("ndn-fwd")
                .args(["recovery-kit", "create", "--format", "file", "--out"])
                .arg(kit.display().to_string())
                .arg("-c")
                .arg(cx.w.node("root").cfg_arg())
                .env("NDN_ROOT_PASSPHRASE", ROOT_PASS)
                .env("NDN_KIT_PASSPHRASE", KIT_PASS);
            cx.ok(op, "recovery-kit create file")?;
            cx.expect_version("root", NS, 3)?;
            if !kit.exists() {
                return Err("no kit file written".into());
            }
            Ok(())
        },
    )?;
    sc.step(
        "relay and phone adopt the kits' version by periodic refresh",
        |cx| {
            cx.wait_version("relay", NS, 3, SHORT)?;
            cx.wait_version("phone", NS, 3, SHORT).map(|_| ())
        },
    )?;
    sc.step("both kits check out on the relay (nothing signed)", |cx| {
        let cfg = cx.w.node("relay").cfg_arg();
        let op = cx
            .tool("ndn-fwd")
            .args(["recovery-kit", "check", "words", "--namespace", NS, "-c"])
            .arg(&cfg)
            .env("NDN_KIT_WORDS", words.join(" "));
        cx.ok(op, "check words")?;
        let op = cx
            .tool("ndn-fwd")
            .args(["recovery-kit", "check"])
            .arg(kit.display().to_string())
            .args(["--namespace", NS, "-c"])
            .arg(&cfg)
            .env("NDN_KIT_PASSPHRASE", KIT_PASS);
        cx.ok(op, "check file kit")?;
        cx.expect_version("relay", NS, 3)
    })?;

    sc.step("phone goes offline", |cx| {
        cx.stop("phone");
        Ok(())
    })?;
    sc.step(
        "the root device is destroyed (daemon stopped, PIB deleted)",
        |cx| {
            cx.concept("root device lost");
            cx.stop("root");
            let pib = cx.w.node("root").pib();
            fs::remove_dir_all(&pib).map_err(|e| e.to_string())?;
            if pib.exists() {
                return Err("root PIB still present".into());
            }
            // The relay's content store may still hold the root's last answers
            // (the trust-context metadata is fresh for 1 s), which would answer
            // the next step's "is v3 the newest?" as a live node would. A device
            // recovering minutes after the loss sees no such copy; erase them.
            let sock = cx.w.node("relay").sock().display().to_string();
            let erase = cx
                .tool("ndn-ctl")
                .args(["--socket", &sock, "cs", "erase", NS]);
            cx.ok(erase, "erase the relay's cached copies")?;
            Ok(())
        },
    )?;
    let recover_op = |cx: &crate::step::Cx<'_>, from_held: bool| {
        let mut op = cx
            .tool("ndn-fwd")
            .args([
                "recover",
                "--kit",
                "words",
                "--old-root",
                "destroyed",
                "--namespace",
                NS,
                "--root-store",
                "sealed-file",
                "--device",
                "relay",
                "-c",
            ])
            .arg(cx.w.node("relay").cfg_arg())
            .env("NDN_KIT_WORDS", words.join(" "))
            .env("NDN_ROOT_PASSPHRASE", NEW_ROOT_PASS)
            .timeout(Duration::from_secs(180));
        if from_held {
            op = op.arg("--from-held");
        }
        op
    };
    sc.step(
        "recover without --from-held stops: nothing answers for the namespace",
        |cx| {
            let op = recover_op(cx, false);
            cx.refused(op, "recover")?;
            cx.expect_version("relay", NS, 3)?;
            if cx.w.node("relay").pib().join("root").exists() {
                return Err("a root store was written on the relay".into());
            }
            Ok(())
        },
    )?;
    let new_root = sc.step(
        "the relay recovers with the words: --old-root destroyed --from-held",
        |cx| {
            let op = recover_op(cx, true);
            let out = cx.ok(op, "recover")?;
            cx.expect_version("relay", NS, 5)?;
            let info = root_info(&out)?;
            if info.fp == root.fp {
                return Err("the namespace's fingerprint did not change".into());
            }
            Ok(info)
        },
    )?;
    sc.step(
        "restart the relay as the root device with the printed [security]/[ca] lines",
        |cx| {
            cx.stop("relay");
            let relay = cx.w.node_mut("relay");
            relay.cfg.identity = Some(new_root.identity.clone());
            relay.cfg.ca = Some(CaCfg {
                prefix: NS.into(),
                identity: n("/CA"),
                member_days: None,
            });
            cx.start("relay")
        },
    )?;
    let new_invites = sc.step(
        "make invites at the new root's CA: they carry the new root's fingerprint",
        |cx| mint(cx, "relay", NS, &new_root.fp, 2, Some("2h")),
    )?;
    sc.step(
        "the offline member comes back and catches up v3 -> v5 by itself",
        |cx| {
            cx.start("phone")?;
            cx.wait_version("phone", NS, 5, SHORT).map(|_| ())
        },
    )?;
    sc.step(
        "its Data (old CA's certificate) still validates at the relay, cold cache",
        |cx| {
            cx.publish("phone", &n("/member/phone/doc1"), &doc1, None, None)?;
            cx.fetch_ok("relay", &n("/member/phone/doc1"), &doc1)
        },
    )?;
    sc.step("phone renews at the new CA", |cx| {
        let pib = cx.w.node("phone").pib();
        let before = cx.certs("phone");
        let issuers_before = cert_issuers(&pib);
        if issuers_before.contains(&new_root.ca_key) {
            return Err("phone already holds a certificate of the new CA".into());
        }
        let op = cx
            .tool("ndn-fwd")
            .arg("renew")
            .arg("-c")
            .arg(cx.w.node("phone").cfg_arg());
        cx.ok(op, "renew")?;
        let renewed = new_cert(cx, "phone", &before)?;
        if renewed == old_cert {
            return Err("renewal returned the old certificate".into());
        }
        let issuers = cert_issuers(&pib);
        if !issuers.contains(&new_root.ca_key) {
            return Err(format!(
                "no certificate in phone's PIB issued by the new CA key {}: issuers {issuers:?}",
                new_root.ca_key
            ));
        }
        Ok(())
    })?;
    let doc2 = content(7_000, 12);
    sc.step(
        "Data signed after the renewal validates at the relay",
        |cx| {
            cx.publish("phone", &n("/member/phone/doc2"), &doc2, None, None)?;
            cx.fetch_ok("relay", &n("/member/phone/doc2"), &doc2)
        },
    )?;
    sc.step("a fresh device is refused the old root's link", |cx| {
        cx.start("fresh")?;
        let op = cx
            .tool("ndn-fwd")
            .arg("adopt")
            .arg(&root.link_fp)
            .arg("-c")
            .arg(cx.w.node("fresh").cfg_arg());
        cx.refused(op, "adopt with the old link")?;
        match cx.version("fresh", NS) {
            None => Ok(()),
            Some(v) => Err(format!("fresh holds v{v} after a refused adopt")),
        }
    })?;
    sc.step("the fresh device adopts with the new root's link", |cx| {
        let op = cx
            .tool("ndn-fwd")
            .arg("adopt")
            .arg(&new_root.link_fp)
            .arg("-c")
            .arg(cx.w.node("fresh").cfg_arg());
        cx.ok(op, "adopt")?;
        cx.expect_version("fresh", NS, 5)
    })?;
    let doc3 = content(4_000, 13);
    sc.step(
        "the fresh device enrolls with a new invite; its Data validates",
        |cx| {
            enroll(cx, "fresh", &new_invites[0], "tablet", false, None)?;
            cx.publish("fresh", &n("/member/tablet/doc"), &doc3, None, None)?;
            cx.fetch_ok("relay", &n("/member/tablet/doc"), &doc3)
        },
    )?;
    Ok(())
}
