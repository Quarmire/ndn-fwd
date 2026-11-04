//! stolen: a device's key is stolen; the owner ends it with a revocation
//! cut, re-admits the honest note the cut left out, and nothing the thief
//! wrote stays anywhere — the data layer (`ndn_data::Device`) and the root
//! flow on real daemons (data-layer slice 5, "keys over time").
//!
//! Topology, on the harness's `lo`: laptop (10.200.0.1, the root device of
//! /st as /st/admin/laptop, with its CA, listening for QUIC links), tab (.2,
//! a member listening for QUIC links, naming the laptop as its peer), phone
//! (.3, a member dialling the laptop and the tab) and thief (.4). tab and
//! phone enroll by invite over a UDP face that routes `/st` to the laptop
//! (the only `[[route]]` any config holds; it also carries their trust
//! context refreshes, every second); every device's links notice a lost
//! peer within seconds. Each device hosts its data layer with `ndn-data`
//! (see [`super::data_host`]); the phone's keeps its entries in a store
//! directory too (`--store`), as a phone keeps its data on its disk.
//!
//! The thief: the phone was out of its owner's hands for a while (a repair
//! shop) and its storage was imaged — its PIB (the phone's key and
//! certificate) and its data store, copied into the thief's daemon and
//! host. The thief's path to the namespace is the one that copy gives it: a
//! QUIC link dialled as the phone, with the phone's key and certificate,
//! which every device of the namespace admits until the key is revoked.
//! It reaches the tab (listening for links where the thief's network
//! reaches it); the laptop is closed at home meanwhile, and the phone is on
//! a flight. Its host runs a week behind (`--clock-offset-ms`), so what it
//! writes claims to predate the revocation; it continues the phone's log
//! from the image (the seqs after the phone's last one), outside the cut.
//!
//! Proves: the phone's notes reach every device; apart, the phone writes a
//! note nobody sees, and the thief's backdated notes reach the tab, which
//! takes them (the key is not revoked yet). On the laptop, still apart, the
//! owner takes the cut from what the laptop holds verified (`ndn-data` `cut
//! <phone key> <file>`: runs of the phone's seqs that cover its notes and
//! none of the thief's or the offline note) and revokes the phone with it
//! (`ndn-fwd revoke /st/member/phone --cut <file>`; a cut of another key is
//! refused and signs nothing). The thief writes once more after the
//! revocation, dated before it; the tab, which has not heard of the
//! revocation yet, takes that too. Once the laptop is back and the tab
//! holds the new version, the tab withdraws every thief note (each reported
//! to its watch as withdrawn by the cut of the phone's key; a `get` of each
//! is refused outside the cut, ask the owner) while the phone's notes stay
//! at every honest device, and the thief, no longer linked, reaches no one
//! with a further write. The phone, back, adopts the revocation and reports
//! its own offline note as refused, with its full name and digest; it
//! enrolls again (a new key) and the owner re-admits that exact version
//! (`ndn-fwd readmit <phone key> <full name>`; a name without its digest is
//! refused): every daemon delivers that exact version by its full name (the
//! phone's host serves it; the laptop's and the tab's daemons validate it,
//! signed by the revoked key, as in the cut now), and it appears at the
//! laptop and the tab, while no honest device answers any thief note (not
//! even at the offline note's name, where the thief wrote other bytes).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

use super::data_host::{
    CONVERGE, Host, Put, carries_group, delivered, includes, name, quic_face_to, rib, unanswered,
};
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{CaCfg, NodeCfg, PeerCfg, addr};

const NS: &str = "/st";
/// The note collection, in the person's namespace (data-layer spec §3).
const NOTES: &str = "/st/32=data/notes/trip";
/// The laptop's device name: `ndn-fwd init --device laptop` on /st.
const LAPTOP: &str = "/st/admin/laptop";
const TAB: &str = "/st/member/tab";
const PHONE: &str = "/st/member/phone";
/// The namespace's sync group (data-layer spec §12).
const GROUP: &str = "/st/32=sync";
/// How far behind the thief's clock runs.
const WEEK_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// The implicit SHA-256 digest component's TLV-TYPE.
const IMPLICIT_SHA256: u64 = 0x01;

/// The nftables tables that keep the owner's devices apart.
const CUT_LAPTOP_TAB: &str = "ndn_e2e_stolen_laptop_tab";
const CUT_LAPTOP_PHONE: &str = "ndn_e2e_stolen_laptop_phone";
const CUT_TAB_PHONE: &str = "ndn_e2e_stolen_tab_phone";

const LAPTOP_HOST: u8 = 1;
const TAB_HOST: u8 = 2;
const PHONE_HOST: u8 = 3;
const THIEF_HOST: u8 = 4;

/// Link timing that notices a lost link within seconds.
const FAST_LINKS: &str = "[links]\nkeep_alive_secs = 2\nidle_timeout_secs = 6\n";

/// What the phone wrote offline, and what the thief writes.
const OFFLINE_TEXT: &str = "written on the plane";
const THIEF_TEXTS: [&str; 4] = [
    "thief: wire the deposit",
    "thief: new bank details",
    "thief: written after the revocation",
    "thief: written once unlinked",
];

/// `node` routes `device` (a device name) over its QUIC link with the
/// daemon at `host`'s address: that face and the route's origin.
fn routes_over_link(
    cx: &mut Cx<'_>,
    node: &str,
    device: &str,
    host: u8,
) -> StepResult<Option<String>> {
    let Some(face) = quic_face_to(cx, node, host)? else {
        return Ok(None);
    };
    Ok(rib(cx, node, device)?
        .into_iter()
        .find(|(f, _)| *f == face)
        .map(|(f, origin)| format!("{node}: {device} → face {f} ({origin}) to {}", addr(host))))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

fn peer(device: &str, host: u8) -> PeerCfg {
    PeerCfg {
        device: Some(device.into()),
        endpoint: Some(addr(host)),
        ..Default::default()
    }
}

/// The `text` field of version `v` as `host` reads it by name: `Ok(text)`
/// when it answers a version, `Err(error)` when it answers an error.
fn text_at(cx: &mut Cx<'_>, host: &mut Host, v: &Put) -> StepResult<Result<String, Value>> {
    Ok(host.call(cx, &format!("get {}", v.name))?.map(|ok| {
        ok["version"]["payload"]["entry"]["text"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }))
}

/// `host` answers `get` of thief version `v` with no thief text: an error,
/// or (at a name the thief shares with an honest version) the honest one.
fn never_answers(cx: &mut Cx<'_>, host: &mut Host, v: &Put) -> StepResult<String> {
    match text_at(cx, host, v)? {
        Ok(text) if THIEF_TEXTS.contains(&text.as_str()) => Err(format!(
            "{} answers the thief's {} with {text:?}; expected a refusal (or the honest \
             version at that name)",
            host.node, v.name
        )),
        Ok(text) => Ok(format!("answers the honest {text:?}")),
        Err(e) => Ok(format!("error, next {}", e["next"])),
    }
}

/// The full names (each ending in an implicit digest) `host` reports as
/// refused by the revocation of `key`.
fn refused_names(cx: &mut Cx<'_>, host: &mut Host, key: &str) -> StepResult<Vec<String>> {
    let ok = host.ok(cx, &format!("refused {key}"))?;
    Ok(ok["names"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|n| n.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default())
}

/// Whether `full` is version `v`'s name followed by a 32-octet implicit
/// SHA-256 digest component.
fn is_full_name_of(full: &str, v: &Put) -> StepResult<bool> {
    let full = name(full)?;
    let Some((last, prefix)) = full.components().split_last() else {
        return Ok(false);
    };
    Ok(last.typ == IMPLICIT_SHA256
        && last.value.len() == 32
        && prefix == name(&v.name)?.components())
}

/// Whether the cut's answer (`ranges`: `[{prefix, runs: [[first, last]]}]`)
/// accepts `seq` of the phone's entries in `NOTES`.
fn cut_covers(cut: &Value, seq: u64) -> StepResult<bool> {
    let prefix = name(&format!("{PHONE}/32=log{NOTES}"))?;
    let mut covered = false;
    for r in cut["ranges"].as_array().into_iter().flatten() {
        if name(r["prefix"].as_str().unwrap_or_default())? != prefix {
            continue;
        }
        covered |= r["runs"].as_array().into_iter().flatten().any(|run| {
            matches!((run[0].as_u64(), run[1].as_u64()), (Some(a), Some(b)) if (a..=b).contains(&seq))
        });
    }
    Ok(covered)
}

/// Copy `from` (a directory) to `to` as it is, modes kept: what imaging a
/// device's storage copies.
fn copy_tree(cx: &mut Cx<'_>, from: &Path, to: &Path) -> StepResult<()> {
    match std::fs::remove_dir_all(to) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(format!("{}: {e}", to.display()));
        }
        _ => {}
    }
    let op = Op::new("cp", PathBuf::from("cp")).args([
        "-a".to_owned(),
        from.display().to_string(),
        to.display().to_string(),
    ]);
    let out = cx.exec(op);
    if !out.success() {
        return Err(format!(
            "copy {} to {}: expected success, got {}",
            from.display(),
            to.display(),
            out.status_text()
        ));
    }
    Ok(())
}

/// `ndn-fwd <args> -c <laptop config>` with the root passphrase.
fn root_op(cx: &Cx<'_>, args: &[&str]) -> Op {
    cx.tool("ndn-fwd")
        .args(args.iter().copied())
        .arg("-c")
        .arg(cx.w.node("laptop").cfg_arg())
        .env("NDN_ROOT_PASSPHRASE", ROOT_PASS)
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    let member = |peers: Vec<PeerCfg>, listen: bool| NodeCfg {
        links: vec![link("laptop", LAPTOP_HOST)],
        routes: vec![route(NS, "laptop")],
        peers,
        quic_listen: listen,
        quic_dial_only: !listen,
        refresh_secs: 1,
        extra_toml: FAST_LINKS.into(),
        ..Default::default()
    };
    sc.world.add(
        "laptop",
        LAPTOP_HOST,
        NodeCfg {
            quic_listen: true,
            refresh_secs: 1,
            extra_toml: FAST_LINKS.into(),
            ..Default::default()
        },
    );
    sc.world.add(
        "tab",
        TAB_HOST,
        member(vec![peer(LAPTOP, LAPTOP_HOST)], true),
    );
    sc.world.add(
        "phone",
        PHONE_HOST,
        member(vec![peer(LAPTOP, LAPTOP_HOST), peer(TAB, TAB_HOST)], false),
    );
    // The thief's daemon: the phone's PIB once imaged, dialling the one
    // device of the namespace its network reaches.
    sc.world.add(
        "thief",
        THIEF_HOST,
        NodeCfg {
            peers: vec![peer(TAB, TAB_HOST)],
            quic_dial_only: true,
            refresh_secs: 1,
            extra_toml: FAST_LINKS.into(),
            ..Default::default()
        },
    );

    let root = sc.step("init the laptop as the root device of /st", |cx| {
        let root = init_root(cx, "laptop", NS, "laptop")?;
        if root.identity != LAPTOP {
            return Err(format!(
                "the laptop is {}, expected {LAPTOP} (the members' peer entries)",
                root.identity
            ));
        }
        Ok(root)
    })?;
    sc.step("start the laptop's daemon with its CA", |cx| {
        cx.w.node_mut("laptop").cfg.identity = Some(root.identity.clone());
        cx.w.node_mut("laptop").cfg.ca = Some(CaCfg {
            prefix: NS.into(),
            identity: format!("{NS}/CA"),
            member_days: None,
        });
        cx.start("laptop")
    })?;
    let invites = sc.step("make two member invites at the laptop's CA", |cx| {
        mint(cx, "laptop", NS, &root.fp, 2, Some("1h"))
    })?;
    sc.step(
        "start the tab's and the phone's daemons; each enrolls by invite over its UDP face",
        |cx| {
            for (node, device, invite) in [("tab", TAB, &invites[0]), ("phone", PHONE, &invites[1])]
            {
                cx.start(node)?;
                let short = device.rsplit('/').next().unwrap_or(device);
                let c = enroll(cx, node, invite, short, false, None)?;
                if !c.starts_with(&format!("{device}/KEY/")) {
                    return Err(format!(
                        "{node} was certified as {c}, expected a certificate of {device}"
                    ));
                }
                cx.evidence(&format!("{node} enrolled: {c}"));
            }
            Ok(())
        },
    )?;
    sc.step(
        "the devices link over QUIC and carry /st/32=sync over each link",
        |cx| {
            for (node, peer) in [
                ("laptop", TAB),
                ("laptop", PHONE),
                ("tab", PHONE),
                ("phone", LAPTOP),
            ] {
                let mut found = None;
                wait_for(
                    cx,
                    &format!("{node} carries {GROUP} over its link to {peer}"),
                    SHORT,
                    |cx| {
                        found = carries_group(cx, node, peer, GROUP)?;
                        Ok(found.is_some())
                    },
                )?;
                cx.evidence(&format!("{node} → {peer}: {}", found.unwrap_or_default()));
            }
            Ok(())
        },
    )?;

    let phone_store = sc.world.node("phone").dir.join("data-store");
    let (mut laptop, mut tab, mut phone) = sc.step(
        "start the data layer on each device; the phone's keeps its entries on its disk too",
        |cx| {
            cx.concept("data layer host (ndn-data)");
            let laptop = Host::start(cx, "laptop", &root.identity)?;
            let tab = Host::start(cx, "tab", TAB)?;
            let phone = Host::start_with(
                cx,
                "phone",
                PHONE,
                &["--store".to_owned(), phone_store.display().to_string()],
            )?;
            if !phone.writer.starts_with(&format!("{PHONE}/KEY/")) {
                return Err(format!(
                    "the phone writes as {}, expected a key of {PHONE}",
                    phone.writer
                ));
            }
            if [&laptop.writer, &tab.writer].contains(&&phone.writer) || laptop.writer == tab.writer
            {
                return Err("two devices write with one key; expected one key each".into());
            }
            cx.evidence(&format!("the phone writes as {}", phone.writer));
            Ok((laptop, tab, phone))
        },
    )?;
    let phone_key = phone.writer.clone();

    let day1 = sc.step(
        "the laptop shares the notes and writes text=day 1; the tab and the phone watch them",
        |cx| {
            laptop.ok(cx, &format!("share {NOTES}"))?;
            let day1 = laptop.put(cx, NOTES, "text=\"day 1\"")?;
            tab.ok(cx, &format!("watch {NOTES}"))?;
            phone.ok(cx, &format!("watch {NOTES}"))?;
            Ok(day1)
        },
    )?;
    let (n1, n2) = sc.step(
        "the phone writes two notes; the laptop and the tab hold them",
        |cx| {
            wait_for(cx, "the phone holds day 1", SHORT, |cx| {
                Ok(phone
                    .state(cx, NOTES)?
                    .is_some_and(|(at, _)| includes(&at, &day1)))
            })?;
            let n1 = phone.put(cx, NOTES, "text=\"flight at nine\"")?;
            let n2 = phone.put(cx, NOTES, "tags=trip")?;
            for host in [&mut laptop, &mut tab] {
                wait_for(
                    cx,
                    &format!("{} holds the phone's two notes", host.node),
                    CONVERGE,
                    |cx| {
                        Ok(host
                            .state(cx, NOTES)?
                            .is_some_and(|(at, _)| includes(&at, &n1) && includes(&at, &n2)))
                    },
                )?;
                cx.evidence(&format!("{} holds {} and {}", host.node, n1.name, n2.name));
            }
            Ok((n1, n2))
        },
    )?;

    if !crate::works(Command::new("nft").arg("--version")) {
        sc.skip(
            "take the devices apart, steal the phone's key, revoke with a cut, re-admit",
            "nft (nftables) not on PATH; run inside `nix-shell -p util-linux iproute2 nftables`",
        );
        return Ok(());
    }
    let (laptop_tab, laptop_phone, tab_phone) = sc.step(
        "apart: the laptop is closed at home and the phone is on a flight (nftables drops UDP \
         between each two of laptop, tab and phone)",
        |cx| {
            let a = cut_udp(cx, CUT_LAPTOP_TAB, addr(LAPTOP_HOST), addr(TAB_HOST))?;
            let b = cut_udp(cx, CUT_LAPTOP_PHONE, addr(LAPTOP_HOST), addr(PHONE_HOST))?;
            let c = cut_udp(cx, CUT_TAB_PHONE, addr(TAB_HOST), addr(PHONE_HOST))?;
            cx.evidence("laptop, tab and phone hear none of each other");
            Ok((a, b, c))
        },
    )?;
    sc.step(
        "the phone's storage is imaged: its PIB (key and certificate) and its data store, \
         copied into the thief's daemon and host",
        |cx| {
            let (phone_pib, thief_pib, thief_dir) = {
                let w = &cx.w;
                (
                    w.node("phone").pib(),
                    w.node("thief").pib(),
                    w.node("thief").dir.clone(),
                )
            };
            copy_tree(cx, &phone_pib, &thief_pib)?;
            copy_tree(cx, &phone_store, &thief_dir.join("data-store"))?;
            let keys = cx.w.keys("thief");
            if !keys.contains(&phone_key) {
                return Err(format!(
                    "the thief's PIB holds {keys:?}, expected the phone's key {phone_key}"
                ));
            }
            cx.evidence(&format!(
                "the thief's PIB holds the phone's key {phone_key}"
            ));
            Ok(())
        },
    )?;
    let n3 = sc.step(
        "on the flight, the phone writes a note that nobody sees",
        |cx| {
            let n3 = phone.put(cx, NOTES, &format!("text=\"{OFFLINE_TEXT}\""))?;
            unanswered(cx, "laptop", &n3.name)?;
            unanswered(cx, "tab", &n3.name)?;
            cx.evidence(&format!(
                "{} reaches neither the laptop nor the tab",
                n3.name
            ));
            Ok(n3)
        },
    )?;

    let mut thief = sc.step(
        "the thief starts the image: its daemon dials the tab as the phone, its host runs a \
         week behind",
        |cx| {
            cx.start("thief")?;
            let thief_store = cx.w.node("thief").dir.join("data-store");
            let thief = Host::start_with(
                cx,
                "thief",
                PHONE,
                &[
                    "--store".to_owned(),
                    thief_store.display().to_string(),
                    "--clock-offset-ms".to_owned(),
                    (-WEEK_MS).to_string(),
                ],
            )?;
            if thief.writer != phone_key {
                return Err(format!(
                    "the thief writes as {}, expected the phone's key {phone_key}",
                    thief.writer
                ));
            }
            let mut found = None;
            wait_for(
                cx,
                &format!(
                    "the tab routes {PHONE} over a QUIC link with the thief's daemon ({})",
                    addr(THIEF_HOST)
                ),
                CONVERGE,
                |cx| {
                    found = routes_over_link(cx, "tab", PHONE, THIEF_HOST)?;
                    Ok(found.is_some())
                },
            )?;
            cx.evidence(&format!(
                "the tab admits the thief's link as {PHONE}: {}",
                found.unwrap_or_default()
            ));
            Ok(thief)
        },
    )?;
    let (t1, t2) = sc.step(
        "the thief writes two notes as the phone, continuing its log from the image; the tab \
         takes them (the key is not revoked yet), the laptop hears nothing",
        |cx| {
            let t1 = thief.put(cx, NOTES, &format!("text=\"{}\"", THIEF_TEXTS[0]))?;
            let t2 = thief.put(cx, NOTES, &format!("text=\"{}\"", THIEF_TEXTS[1]))?;
            if t1.seq <= n2.seq {
                return Err(format!(
                    "the thief wrote seq {}, expected it past the phone's seq {} (the log \
                     continues from the image)",
                    t1.seq, n2.seq
                ));
            }
            if name(&t1.name)? == name(&n3.name)? {
                cx.evidence(&format!(
                    "the thief's first note and the phone's offline note share the name {} \
                     (other bytes)",
                    t1.name
                ));
            }
            for (v, text) in [(&t1, THIEF_TEXTS[0]), (&t2, THIEF_TEXTS[1])] {
                wait_for(
                    cx,
                    &format!("the tab reads {} as the thief wrote it", v.name),
                    CONVERGE,
                    |cx| Ok(text_at(cx, &mut tab, v)?.is_ok_and(|t| t == text)),
                )?;
            }
            let read = tab.version(cx, NOTES, &t1)?;
            cx.evidence(&format!(
                "the tab took {} (dated_ms {}, the thief's clock a week behind)",
                t1.name, read["dated_ms"]
            ));
            unanswered(cx, "laptop", &t2.name)?;
            cx.evidence("the laptop gets none of the thief's notes");
            Ok((t1, t2))
        },
    )?;

    let cut_file = sc.world.node("laptop").dir.join("phone.cut");
    sc.step(
        "on the laptop, the owner takes the cut of the phone's key from what the laptop holds \
         verified: the phone's notes, none of the thief's, not the offline note",
        |cx| {
            cx.concept("revocation cut");
            let cut = laptop.ok(cx, &format!("cut {phone_key} {}", cut_file.display()))?;
            if name(cut["key"].as_str().unwrap_or_default())? != name(&phone_key)? {
                return Err(format!(
                    "the cut is of {}, expected {phone_key}",
                    cut["key"]
                ));
            }
            for v in [&n1, &n2] {
                if !cut_covers(&cut, v.seq)? {
                    return Err(format!(
                        "the cut {cut} leaves out the phone's {}; expected it accepted",
                        v.name
                    ));
                }
            }
            for v in [&n3, &t1, &t2] {
                if cut_covers(&cut, v.seq)? {
                    return Err(format!(
                        "the cut {cut} accepts seq {} ({}), which the laptop never held; \
                         expected it outside",
                        v.seq, v.name
                    ));
                }
            }
            let len = std::fs::metadata(&cut_file).map(|m| m.len()).unwrap_or(0);
            if len == 0 {
                return Err(format!(
                    "{} is empty or missing; expected the cut's TLV",
                    cut_file.display()
                ));
            }
            cx.evidence(&format!("cut: {}", cut["ranges"]));
            Ok(())
        },
    )?;
    let v0 = sc.world.held_version("laptop", NS).unwrap_or(0);
    sc.step(
        "a revocation of the phone with a cut of another key (the tab's) is refused and signs \
         nothing",
        |cx| {
            let other = cx.w.node("tab").dir.join("tab.cut");
            laptop.ok(cx, &format!("cut {} {}", tab.writer, other.display()))?;
            let other = other.display().to_string();
            let op = root_op(cx, &["revoke", PHONE, "--cut", other.as_str()]);
            cx.refused(op, "revoke the phone with the tab's cut")?;
            cx.expect_version("laptop", NS, v0)
        },
    )?;
    let revoked_ms = sc.step(
        "the owner revokes the phone with its cut: a new trust-context version",
        |cx| {
            let file = cut_file.display().to_string();
            let op = root_op(cx, &["revoke", PHONE, "--cut", file.as_str()]);
            cx.ok(op, "revoke the phone with its cut")?;
            cx.expect_version("laptop", NS, v0 + 1)?;
            Ok(now_ms())
        },
    )?;
    let t3 = sc.step(
        "after the revocation, the thief writes a note dated before it; the tab, which has not \
         heard of the revocation, takes it",
        |cx| {
            let t3 = thief.put(cx, NOTES, &format!("text=\"{}\"", THIEF_TEXTS[2]))?;
            wait_for(
                cx,
                &format!("the tab reads {} as the thief wrote it", t3.name),
                CONVERGE,
                |cx| Ok(text_at(cx, &mut tab, &t3)?.is_ok_and(|t| t == THIEF_TEXTS[2])),
            )?;
            let read = tab.version(cx, NOTES, &t3)?;
            let dated = read["dated_ms"].as_u64().unwrap_or(u64::MAX);
            if dated >= revoked_ms {
                return Err(format!(
                    "the thief's note is dated {dated} ms, expected before the revocation at \
                     {revoked_ms} ms (its clock runs a week behind)"
                ));
            }
            cx.evidence(&format!(
                "{} dated {dated} ms, before the revocation at {revoked_ms} ms",
                t3.name
            ));
            Ok(t3)
        },
    )?;

    sc.step("the laptop is back: the tab adopts the revocation", |cx| {
        drop(laptop_tab);
        cx.wait_version("tab", NS, v0 + 1, CONVERGE).map(|_| ())
    })?;
    sc.step(
        "the tab withdraws every thief note, each reported to its watch as withdrawn by the \
         cut of the phone's key, and refuses each outside the cut (ask the owner)",
        |cx| {
            for v in [&t1, &t2, &t3] {
                let w = tab.watched_until(cx, &format!("{} withdrawn", v.name), CONVERGE, |w| {
                    let d = &w["change"]["withdrawn"];
                    d["id"]["writer"] == v.writer.as_str()
                        && d["id"]["seq"] == v.seq
                        && name(d["cut_of"].as_str().unwrap_or_default()).ok()
                            == name(&phone_key).ok()
                })?;
                cx.evidence(&format!("tab watch: {}", w["change"]));
                let mut last = Value::Null;
                wait_for(
                    cx,
                    &format!("the tab refuses {} outside the cut", v.name),
                    CONVERGE,
                    |cx| {
                        Ok(match text_at(cx, &mut tab, v)? {
                            Err(e) => {
                                let done = e["next"] == "ask-owner"
                                    && name(e["outside_cut"]["of"].as_str().unwrap_or_default())
                                        .ok()
                                        == name(&phone_key).ok();
                                last = e;
                                done
                            }
                            Ok(_) => false,
                        })
                    },
                )?;
                cx.evidence(&format!("tab get {}: {}", v.name, last["outside_cut"]));
            }
            let refused = refused_names(cx, &mut tab, &phone_key)?;
            for v in [&t1, &t2, &t3] {
                let mut listed = false;
                for f in &refused {
                    listed |= is_full_name_of(f, v)?;
                }
                if !listed {
                    return Err(format!(
                        "the tab's refused names {refused:?} lack {} with its digest",
                        v.name
                    ));
                }
            }
            cx.evidence(&format!("tab refused: {refused:?}"));
            Ok(())
        },
    )?;
    sc.step(
        "the phone's notes stay at the laptop and the tab; neither answers a thief note",
        |cx| {
            for host in [&mut laptop, &mut tab] {
                let (at, value) = host
                    .state(cx, NOTES)?
                    .ok_or_else(|| format!("{} holds no state of the notes", host.node))?;
                if !includes(&at, &n1) || !includes(&at, &n2) || includes(&at, &n3) {
                    return Err(format!(
                        "{}'s state is at {at}; expected the phone's notes up to seq {} and \
                         nothing of its key past them",
                        host.node, n2.seq
                    ));
                }
                if THIEF_TEXTS.iter().any(|t| value["text"] == *t) {
                    return Err(format!(
                        "{}'s notes read {value}, a thief's text",
                        host.node
                    ));
                }
                for v in [&n1, &n2] {
                    host.version(cx, NOTES, v)?;
                }
                for v in [&t1, &t2, &t3] {
                    let how = never_answers(cx, host, v)?;
                    cx.evidence(&format!("{} get {}: {how}", host.node, v.name));
                }
                cx.evidence(&format!("{}: at {at}, value {value}", host.node));
            }
            Ok(())
        },
    )?;
    let t4 = sc.step(
        "the tab no longer routes the phone's name to the thief (its key is revoked); the \
         thief writes again: no honest device gets it",
        |cx| {
            wait_for(
                cx,
                &format!(
                    "the tab routes {PHONE} over no link with the thief's daemon ({})",
                    addr(THIEF_HOST)
                ),
                CONVERGE,
                |cx| Ok(routes_over_link(cx, "tab", PHONE, THIEF_HOST)?.is_none()),
            )?;
            cx.evidence(&format!("the tab routes {PHONE} to no link with the thief"));
            let t4 = thief.put(cx, NOTES, &format!("text=\"{}\"", THIEF_TEXTS[3]))?;
            for host in [&mut laptop, &mut tab] {
                let how = never_answers(cx, host, &t4)?;
                cx.evidence(&format!("{} get {}: {how}", host.node, t4.name));
            }
            Ok(t4)
        },
    )?;

    let n3_full = sc.step(
        "the phone is back: it adopts the revocation and reports its offline note refused, \
         with its full name and digest; its earlier notes stay",
        |cx| {
            drop(laptop_phone);
            drop(tab_phone);
            cx.wait_version("phone", NS, v0 + 1, CONVERGE)?;
            let mut full = None;
            wait_for(
                cx,
                &format!("the phone reports {} refused by the cut", n3.name),
                CONVERGE,
                |cx| {
                    for f in refused_names(cx, &mut phone, &phone_key)? {
                        if is_full_name_of(&f, &n3)? {
                            full = Some(f);
                        }
                    }
                    Ok(full.is_some())
                },
            )?;
            for v in [&n1, &n2] {
                phone.version(cx, NOTES, v)?;
            }
            let full = full.unwrap_or_default();
            cx.evidence(&format!("the phone's offline note: {full}"));
            Ok(full)
        },
    )?;
    sc.step(
        "the owner enrolls the phone again (a new key): it links to the laptop and the tab",
        |cx| {
            let invite = mint(cx, "laptop", NS, &root.fp, 1, Some("1h"))?;
            let c = enroll(cx, "phone", &invite[0], "phone", true, None)?;
            if c.starts_with(&format!("{phone_key}/")) || !c.starts_with(&format!("{PHONE}/KEY/")) {
                return Err(format!(
                    "the phone was certified as {c}; expected a new key of {PHONE}, not \
                     {phone_key}"
                ));
            }
            cx.evidence(&format!("the phone's new certificate: {c}"));
            for node in ["laptop", "tab"] {
                let mut found = None;
                wait_for(
                    cx,
                    &format!(
                        "{node} routes {PHONE} over a QUIC link with the phone's daemon ({})",
                        addr(PHONE_HOST)
                    ),
                    CONVERGE,
                    |cx| {
                        found = routes_over_link(cx, node, PHONE, PHONE_HOST)?;
                        Ok(found.is_some())
                    },
                )?;
                cx.evidence(&format!("{node} → {PHONE}: {}", found.unwrap_or_default()));
            }
            Ok(())
        },
    )?;
    sc.step(
        "a re-admission without the version's digest is refused and signs nothing",
        |cx| {
            let op = root_op(cx, &["readmit", phone_key.as_str(), n3.name.as_str()]);
            cx.refused(op, "readmit a name without its digest")?;
            cx.expect_version("laptop", NS, v0 + 1)
        },
    )?;
    sc.step(
        "the owner re-admits the offline note by its full name: a new trust-context version",
        |cx| {
            let op = root_op(cx, &["readmit", phone_key.as_str(), n3_full.as_str()]);
            cx.ok(op, "readmit the phone's offline note")?;
            cx.expect_version("laptop", NS, v0 + 2)?;
            cx.wait_version("tab", NS, v0 + 2, CONVERGE).map(|_| ())
        },
    )?;
    sc.step(
        "the re-admitted version is delivered by its full name: the phone serves it, and the \
         laptop's and the tab's daemons, validating it, forward it (in the cut now)",
        |cx| {
            for node in ["phone", "laptop", "tab"] {
                let mut got = Err(String::new());
                wait_for(
                    cx,
                    &format!("{node}'s daemon delivers {n3_full}"),
                    CONVERGE,
                    |cx| {
                        got = delivered(cx, node, &n3_full);
                        Ok(got.is_ok())
                    },
                )
                .map_err(|e| {
                    let last = got.as_ref().err().cloned().unwrap_or_default();
                    format!("{e}; the last fetch: {last}")
                })?;
                let key = got
                    .unwrap_or_default()
                    .lines()
                    .find_map(|l| l.trim().strip_prefix("key:").map(|k| k.trim().to_owned()))
                    .unwrap_or_default();
                if key != phone_key {
                    return Err(format!(
                        "{n3_full} at {node} is signed by {key:?}, expected the revoked key \
                         {phone_key} (re-admitted exactly)"
                    ));
                }
                cx.evidence(&format!("{node} delivers {n3_full}, signed by {key}"));
            }
            Ok(())
        },
    )?;
    sc.step(
        "the offline note appears at the laptop and the tab; the thief's notes stay out",
        |cx| {
            for host in [&mut laptop, &mut tab] {
                let mut last = (Value::Null, Value::Null);
                wait_for(
                    cx,
                    &format!("{} holds {} with text {OFFLINE_TEXT:?}", host.node, n3.name),
                    CONVERGE,
                    |cx| {
                        let Some(s) = host.state(cx, NOTES)? else {
                            return Ok(false);
                        };
                        let done = includes(&s.0, &n3) && s.1["text"] == OFFLINE_TEXT;
                        last = s;
                        Ok(done)
                    },
                )?;
                let read = host.version(cx, NOTES, &n3)?;
                if read["payload"]["entry"]["text"] != OFFLINE_TEXT {
                    return Err(format!(
                        "{} reads {} as {read}, expected the phone's text {OFFLINE_TEXT:?}",
                        host.node, n3.name
                    ));
                }
                cx.evidence(&format!("{}: at {}, value {}", host.node, last.0, last.1));
                for v in [&t1, &t2, &t3, &t4] {
                    let how = never_answers(cx, host, v)?;
                    cx.evidence(&format!("{} get {}: {how}", host.node, v.name));
                }
                if refused_names(cx, host, &phone_key)?.contains(&n3_full) {
                    return Err(format!(
                        "{} still reports {n3_full} refused; expected it re-admitted",
                        host.node
                    ));
                }
            }
            let delivered = tab.watched_until(
                cx,
                &format!("the tab's watch delivers {}", n3.name),
                CONVERGE,
                |w| {
                    let v = &w["change"]["version"];
                    name(v["name"].as_str().unwrap_or_default()).ok() == name(&n3.name).ok()
                        && v["payload"]["entry"]["text"] == OFFLINE_TEXT
                },
            )?;
            cx.evidence(&format!(
                "tab watch delivered {}",
                delivered["change"]["version"]["name"]
            ));
            Ok(())
        },
    )?;
    Ok(())
}
