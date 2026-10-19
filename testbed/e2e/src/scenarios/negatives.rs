//! negatives: what must be refused, and must change nothing when refused.
//! Each refusal sits next to a control that succeeds under the same setup,
//! so a refusal cannot pass because something else is broken.
//!
//! Topology: root (.1, root device + CA of /ng) — phone (.3) directly, and
//! through a tampering shim (.5); fresh (.4) links to root; other (.6) is
//! the root device of another namespace /ot (its PIB only).

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use bip39::{Language, Mnemonic};

use crate::run::snapshot;
use crate::scenarios::*;
use crate::shim::Shim;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{CaCfg, NodeCfg, PORT, addr};

const NS: &str = "/ng";
const OTHER: &str = "/ot";

/// The words with one word replaced by another valid word, the checksum
/// failing.
fn mistyped(words: &[String]) -> Vec<String> {
    let list = Language::English.word_list();
    for i in [5usize, 11, 17, 0] {
        for cand in list.iter() {
            if *cand == words[i] {
                continue;
            }
            let mut w = words.to_vec();
            w[i] = (*cand).to_owned();
            if Mnemonic::parse_in_normalized(Language::English, &w.join(" ")).is_err() {
                return w;
            }
        }
    }
    unreachable!("every single-word change passing the checksum")
}

/// The words with two neighbours swapped, the checksum failing.
fn swapped(words: &[String]) -> Vec<String> {
    for i in 0..words.len() - 1 {
        if words[i] == words[i + 1] {
            continue;
        }
        let mut w = words.to_vec();
        w.swap(i, i + 1);
        if Mnemonic::parse_in_normalized(Language::English, &w.join(" ")).is_err() {
            return w;
        }
    }
    unreachable!("every neighbour swap passing the checksum")
}

/// `recover` on phone, which must be refused with nothing written: no root
/// store in phone's PIB, its contexts unchanged.
fn recover_refused(cx: &mut Cx<'_>, kit: &str, env: (&str, String)) -> StepResult<()> {
    let pib = cx.w.node("phone").pib();
    let before = snapshot(&pib.join("contexts"));
    let op = cx
        .tool("ndn-fwd")
        .args([
            "recover",
            "--kit",
            kit,
            "--old-root",
            "destroyed",
            "--namespace",
            NS,
        ])
        .args(["--root-store", "sealed-file", "--device", "phone", "-c"])
        .arg(cx.w.node("phone").cfg_arg())
        .env(env.0, env.1)
        .env("NDN_ROOT_PASSPHRASE", NEW_ROOT_PASS)
        .timeout(Duration::from_secs(120));
    cx.refused(op, "recover")?;
    if pib.join("root").exists() {
        return Err("a root store was written on phone".into());
    }
    if snapshot(&pib.join("contexts")) != before {
        return Err("phone's held contexts changed".into());
    }
    Ok(())
}

fn check_kit(cx: &mut Cx<'_>, node: &str, kit: &str, env: (&str, String)) -> crate::run::Op {
    cx.tool("ndn-fwd")
        .args(["recovery-kit", "check", kit, "--namespace", NS, "-c"])
        .arg(cx.w.node(node).cfg_arg())
        .env(env.0, env.1)
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    let n = |s: &str| format!("{NS}{s}");
    sc.world.add(
        "root",
        1,
        NodeCfg {
            links: vec![link("phone", 3), link("shim", 5)],
            routes: vec![
                route(n("/member/phone"), "phone"),
                route(n("/member/phone/viashim"), "shim"),
            ],
            ..Default::default()
        },
    );
    sc.world.add(
        "phone",
        3,
        NodeCfg {
            links: vec![link("root", 1)],
            routes: vec![route(NS, "root")],
            ..Default::default()
        },
    );
    sc.world.add(
        "fresh",
        4,
        NodeCfg {
            links: vec![link("root", 1)],
            routes: vec![route(NS, "root")],
            ..Default::default()
        },
    );
    sc.world.add("other", 6, NodeCfg::default());

    let root = sc.step("init the root device of /ng", |cx| {
        init_root(cx, "root", NS, "desk")
    })?;
    let other = sc.step("init the root device of another namespace /ot", |cx| {
        init_root(cx, "other", OTHER, "desk")
    })?;
    let (invites, foreign, expiring) = sc.step(
        "mint invites: two for /ng, one carrying /ot's fingerprint, one expiring in 1 s",
        |cx| {
            let ok = mint(cx, NS, &root.fp, 2, Some("2h"))?;
            let foreign = mint(cx, NS, &other.fp, 1, Some("2h"))?.remove(0);
            let expiring = mint(cx, NS, &root.fp, 1, Some("1"))?.remove(0);
            Ok((ok, foreign, expiring))
        },
    )?;
    let minted = Instant::now();
    sc.step("start the root device with every token in its CA", |cx| {
        cx.w.node_mut("root").cfg.identity = Some(root.identity.clone());
        let mut tokens: Vec<String> = invites.iter().map(|i| i.token.clone()).collect();
        tokens.push(foreign.token.clone());
        tokens.push(expiring.token.clone());
        cx.w.node_mut("root").cfg.ca = Some(CaCfg {
            prefix: NS.into(),
            identity: n("/CA"),
            tokens,
            member_days: None,
        });
        cx.start("root")
    })?;
    let (words, file_key) = sc.step("create a words kit and a file kit", |cx| {
        let cfg = cx.w.node("root").cfg_arg();
        let op = cx
            .tool("ndn-fwd")
            .args(["recovery-kit", "create", "--format", "words", "-c"])
            .arg(&cfg)
            .env("NDN_ROOT_PASSPHRASE", ROOT_PASS);
        let out = cx.ok(op, "create words kit")?;
        let w = words(&out)?;
        let kit = cx.w.dir.join("ng.kit");
        let op = cx
            .tool("ndn-fwd")
            .args(["recovery-kit", "create", "--format", "file", "--out"])
            .arg(kit.display().to_string())
            .arg("-c")
            .arg(&cfg)
            .env("NDN_ROOT_PASSPHRASE", ROOT_PASS)
            .env("NDN_KIT_PASSPHRASE", KIT_PASS);
        let out = cx.ok(op, "create file kit")?;
        cx.expect_version("root", NS, 3)?;
        let key = first(out.kv("recovery_key")).ok_or("no recovery_key in the output")?;
        Ok((w, key))
    })?;
    let kit = sc.world.dir.join("ng.kit").display().to_string();
    sc.step(
        "phone enrolls with an invite and refreshes to the kits' version",
        |cx| {
            cx.start("phone")?;
            enroll(cx, "phone", &invites[0], "phone", false, None)?;
            let op = cx
                .tool("ndn-fwd")
                .args(["context", "refresh", NS, "-c"])
                .arg(cx.w.node("phone").cfg_arg());
            cx.ok(op, "context refresh")?;
            cx.expect_version("phone", NS, 3)
        },
    )?;

    sc.step("control: the right words check out on phone", |cx| {
        let op = check_kit(cx, "phone", "words", ("NDN_KIT_WORDS", words.join(" ")));
        cx.ok(op, "check words").map(|_| ())
    })?;
    sc.step("mistyped words are refused; nothing signed", |cx| {
        let bad = mistyped(&words).join(" ");
        let op = check_kit(cx, "phone", "words", ("NDN_KIT_WORDS", bad.clone()));
        cx.refused(op, "check mistyped words")?;
        recover_refused(cx, "words", ("NDN_KIT_WORDS", bad))
    })?;
    sc.step("swapped words are refused; nothing signed", |cx| {
        let bad = swapped(&words).join(" ");
        let op = check_kit(cx, "phone", "words", ("NDN_KIT_WORDS", bad.clone()));
        cx.refused(op, "check swapped words")?;
        recover_refused(cx, "words", ("NDN_KIT_WORDS", bad))
    })?;
    sc.step(
        "control: the file kit checks out with its passphrase",
        |cx| {
            let op = check_kit(cx, "phone", &kit, ("NDN_KIT_PASSPHRASE", KIT_PASS.into()));
            cx.ok(op, "check file kit").map(|_| ())
        },
    )?;
    sc.step("a wrong kit passphrase is refused; nothing signed", |cx| {
        let op = check_kit(cx, "phone", &kit, ("NDN_KIT_PASSPHRASE", WRONG_PASS.into()));
        cx.refused(op, "check with a wrong passphrase")?;
        recover_refused(cx, &kit, ("NDN_KIT_PASSPHRASE", WRONG_PASS.into()))
    })?;
    sc.step(
        "revoke the file kit on the root device; phone refreshes",
        |cx| {
            let cfg = cx.w.node("root").cfg_arg();
            let op = cx
                .tool("ndn-fwd")
                .args(["recovery-kit", "revoke", &file_key, "-c"])
                .arg(&cfg)
                .env("NDN_ROOT_PASSPHRASE", ROOT_PASS);
            cx.ok(op, "recovery-kit revoke")?;
            cx.expect_version("root", NS, 4)?;
            // A relay or cache between phone and root may still answer with the
            // previous metadata briefly (`current`/`behind`): refresh again until
            // phone holds v4, under a deadline.
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let op = cx
                    .tool("ndn-fwd")
                    .args(["context", "refresh", NS, "-c"])
                    .arg(cx.w.node("phone").cfg_arg());
                cx.ok(op, "context refresh")?;
                if cx.version("phone", NS).is_some_and(|v| v >= 4) || Instant::now() > deadline {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
            cx.expect_version("phone", NS, 4)
        },
    )?;
    sc.step(
        "the revoked kit cannot recover (right passphrase); nothing signed",
        |cx| {
            let op = check_kit(cx, "phone", &kit, ("NDN_KIT_PASSPHRASE", KIT_PASS.into()));
            cx.refused(op, "check the revoked kit")?;
            recover_refused(cx, &kit, ("NDN_KIT_PASSPHRASE", KIT_PASS.into()))
        },
    )?;

    sc.step(
        "an invite carrying another namespace's fingerprint is refused",
        |cx| {
            cx.start("fresh")?;
            let op = cx
                .tool("ndn-fwd")
                .arg("enroll")
                .arg(&foreign.link)
                .args(["--device", "laptop", "-c"])
                .arg(cx.w.node("fresh").cfg_arg());
            cx.refused(op, "enroll")?;
            if let Some(v) = cx.version("fresh", NS) {
                return Err(format!(
                    "fresh adopted {NS} v{v} under a foreign fingerprint"
                ));
            }
            if !cx.certs("fresh").is_empty() {
                return Err("fresh holds a certificate".into());
            }
            Ok(())
        },
    )?;
    sc.step("a used invite is refused", |cx| {
        let op = cx
            .tool("ndn-fwd")
            .arg("enroll")
            .arg(&invites[0].link)
            .args(["--device", "laptop", "-c"])
            .arg(cx.w.node("fresh").cfg_arg());
        cx.refused(op, "enroll with a used invite")?;
        if !cx.certs("fresh").is_empty() {
            return Err("fresh holds a certificate".into());
        }
        Ok(())
    })?;
    sc.step("an expired invite is refused", |cx| {
        let wait = Duration::from_secs(2).saturating_sub(minted.elapsed());
        thread::sleep(wait);
        let op = cx
            .tool("ndn-fwd")
            .arg("enroll")
            .arg(&expiring.link)
            .args(["--device", "laptop", "-c"])
            .arg(cx.w.node("fresh").cfg_arg());
        cx.refused(op, "enroll with an expired invite")?;
        if !cx.certs("fresh").is_empty() {
            return Err("fresh holds a certificate".into());
        }
        Ok(())
    })?;
    sc.step(
        "control: an unused, current invite enrolls the same device",
        |cx| enroll(cx, "fresh", &invites[1], "laptop", false, None).map(|_| ()),
    )?;

    let doc = content(3_000, 31);
    sc.step("control: phone's Data validates at the root", |cx| {
        cx.publish("phone", &n("/member/phone/doc"), &doc, None, None)?;
        cx.fetch_ok("root", &n("/member/phone/doc"), &doc)
    })?;
    sc.step(
        "Data signed by an unenrolled key under phone's name is refused",
        |cx| {
            let rogue = cx.w.dir.join("rogue-pib");
            let op = cx
                .tool("ndn-sec")
                .arg("--pib")
                .arg(rogue.display().to_string())
                .args(["keygen", &n("/member/phone")]);
            let out = cx.exec(op);
            if !out.success() {
                return Err(format!("ndn-sec keygen: {}", out.status_text()));
            }
            cx.publish(
                "phone",
                &n("/member/phone/rogue"),
                &doc,
                Some(rogue),
                Some(&n("/member/phone")),
            )?;
            // The key has no certificate anywhere: root's certificate fetch is
            // answered NoRoute (phone has none, and routes back only to root), a
            // definite absence, so the Data is refused as unverifiable at once —
            // refused for now, not final (`fetch_refused` checks ndn-peek says so).
            cx.fetch_refused("root", &n("/member/phone/rogue"), "unverifiable")
        },
    )?;
    let clean = content(1_000, 32);
    sc.step(
        "control: Data through the shim (not tampering) validates",
        |cx| {
            let shim = Shim::start(
                SocketAddr::new(addr(5).into(), PORT),
                SocketAddr::new(addr(1).into(), PORT),
                SocketAddr::new(addr(3).into(), PORT),
            )
            .map_err(|e| format!("shim: {e}"))?;
            cx.w.shims.push(shim);
            cx.publish(
                "phone",
                &n("/member/phone/viashim/clean"),
                &clean,
                None,
                None,
            )?;
            cx.fetch_ok("root", &n("/member/phone/viashim/clean"), &clean)
        },
    )?;
    sc.step("Data with one byte flipped in transit is refused", |cx| {
        cx.publish(
            "phone",
            &n("/member/phone/viashim/flipped"),
            &clean,
            None,
            None,
        )?;
        let flip = cx.w.shims[0].flip.clone();
        flip.store(true, Ordering::Relaxed);
        cx.fetch_refused("root", &n("/member/phone/viashim/flipped"), "bad-signature")?;
        flip.store(false, Ordering::Relaxed);
        if cx.w.shims[0].flipped.load(Ordering::Relaxed) == 0 {
            return Err("the shim tampered with nothing: the refusal proves nothing".into());
        }
        Ok(())
    })?;

    let foreign_ok = sc.world.bins.foreign_uid;
    let why = "no second uid in the user namespace (newuidmap/subuid unavailable): \
               every process in the namespace is the daemons' own user";
    if !foreign_ok {
        sc.skip("another local user is refused a management command", why);
        sc.skip(
            "another local user is refused a trust-changing command",
            why,
        );
        return Ok(());
    }
    sc.step(
        "another local user is refused a management command; the operator is not",
        |cx| {
            let sock = cx.w.node("root").sock().display().to_string();
            let cmd = |cx: &Cx<'_>, prefix: &str| {
                cx.tool("ndn-ctl")
                    .args(["--socket", &sock, "route", "add", prefix, "--face", "1"])
            };
            let op = cmd(cx, "/ng/intruder").by_foreign_user();
            cx.refused(op, "route add by uid 1")?;
            let op = cmd(cx, "/ng/operator");
            cx.ok(op, "route add by the operator").map(|_| ())
        },
    )?;
    sc.step(
        "another local user is refused a trust-changing command; the operator is not",
        |cx| {
            let cfg = cx.w.node("phone").cfg_arg();
            let op = cx
                .tool("ndn-fwd")
                .arg("adopt")
                .arg(&other.link_inline)
                .arg("-c")
                .arg(&cfg)
                .by_foreign_user();
            cx.refused(op, "adopt by uid 1")?;
            if cx.version("phone", OTHER).is_some() {
                return Err("phone adopted /ot for uid 1".into());
            }
            let op = cx
                .tool("ndn-fwd")
                .arg("adopt")
                .arg(&other.link_inline)
                .arg("-c")
                .arg(&cfg);
            cx.ok(op, "adopt by the operator")?;
            cx.expect_version("phone", OTHER, 1)
        },
    )?;
    Ok(())
}
