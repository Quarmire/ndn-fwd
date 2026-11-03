//! photos: a phone's large photo kept safely by two holders the person
//! runs — the data layer's custody (`hold`, audits, repair, `release`,
//! `prune`) on real daemons.
//!
//! Topology, on the harness's `lo`: home (10.200.0.1, the root device of
//! /ph as /ph/admin/home, with its CA, listening for QUIC links), phone
//! (.2), repo (.3) and vault (.4), each a member enrolled by invite over a
//! UDP face that routes `/ph` to home (the enrollment route notes uses, and
//! no other), naming home as its QUIC peer: once enrolled each links to it
//! by itself, and the link library routes each device's name and the sync
//! group `/ph/32=sync` over its link (data-layer spec §12). No config
//! routes a collection, a device or the group.
//!
//! home and phone host their data layer with `ndn-data` (see
//! [`super::data_host`]); repo and vault each run `ndn-repo hold
//! --hold-for /ph --in-namespace`, a device of /ph that holds the
//! namespace's data for custody (holding for its own namespace, so the
//! operator accepts that it reads what /ph's readers read and is an owner
//! device), keeping what it holds for others as erasure stripes
//! (`<store>/held/<i>`, 2 of 3 by default) beside its own log
//! (`<store>/own`).
//!
//! Proves: the phone shares a log collection sealed to /ph and puts a
//! 1.5 MB photo, which travels in pieces (home's watch sees it as large,
//! by its size), and a caption. Asked to hold the collection (two copies,
//! 30 days, holders the repo and the vault, named in the hold record), the
//! repo and the vault each sign a lease covering both, and the phone's
//! audit of each (random pieces, fresh nonces) finds it kept; nothing is
//! unkept. The phone releases the photo's pieces — release asks each named
//! holder for a fresh proof over every piece of the photo while the phone
//! serves none of them, and drops them once both prove — and, with every
//! forwarder's cached copies erased, still reads the photo (length and
//! SHA-256 equal the file's) from the holders. The repo loses one stripe
//! (stopped, one stripe deleted, started): the next audit still finds its
//! lease kept. Then the phone releases the pieces its read fetched back
//! (both holders again prove every piece), every cache under /ph is
//! erased, the vault goes offline (stopped, its stripes kept) and the repo
//! loses everything it held (every stripe): no device in reach has the
//! photo, so the phone's next `hold` reports the repo's lease broken
//! (signed missing, or unanswered) and the vault's unanswered (no
//! evidence, no verdict), no lease audited kept holds the photo, and the
//! custody names it unkept. The vault comes back: asked again, the repo
//! fetches the photo back from the vault, the only copy left, both leases
//! are audited kept, nothing is unkept, and the phone reads the photo. The
//! phone prunes the photo: the phone and home answer `get` of it with a
//! final error naming the prune (home's watch reports it pruned), the
//! caption still reads, and the phone's audit of both leases, which no
//! longer count the photo, finds nothing broken.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::data_host::{
    CONVERGE, Holder, Host, Put, carries_group, delete, includes, name, octets,
};
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{CaCfg, NodeCfg, PeerCfg, addr};

const NS: &str = "/ph";
const HOME: &str = "/ph/admin/home";
const PHONE: &str = "/ph/member/phone";
const REPO: &str = "/ph/member/repo";
const VAULT: &str = "/ph/member/vault";
/// The photo collection: a log, so the photo may travel in pieces.
const PHOTOS: &str = "/ph/32=data/photos";
/// The namespace's sync group (data-layer spec §12).
const GROUP: &str = "/ph/32=sync";
/// The photo's octets: hundreds of pieces.
const PHOTO_LEN: usize = 1_500_000;
/// The data layer's piece size (spec §4.1).
const CHUNK: u64 = 4096;
/// How many holders the phone asks to keep the photos.
const COPIES: u32 = 2;
/// How long the phone asks the holders to keep the photos.
const HOLD_DAYS: u64 = 30;

fn n(s: &str) -> String {
    format!("{NS}{s}")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `hold` of the photos at `host` (two copies, until `until`, held by the
/// repo and the vault): the custody, or the error.
fn hold(cx: &mut Cx<'_>, host: &mut Host, until: u64) -> StepResult<Result<Value, Value>> {
    Ok(host
        .call_within(
            cx,
            &format!("hold {PHOTOS} copies={COPIES} until={until} holders={REPO},{VAULT}"),
            CONVERGE,
        )?
        .map(|mut ok| ok["custody"].take()))
}

/// The lease of `holder` (a key name) in `list` (`leases` or `broken`).
fn lease_of<'a>(list: &'a Value, holder: &str) -> Option<&'a Value> {
    list.as_array()?.iter().find(|l| l["holder"] == holder)
}

/// Whether `lease` is audited kept and holds `v`.
fn keeps(lease: &Value, v: &Put) -> bool {
    lease["audit"].get("kept").is_some() && includes(&lease["holds"], v)
}

/// Whether the custody's `unkept` is empty.
fn nothing_unkept(custody: &Value) -> bool {
    custody["unkept"].as_array().is_some_and(Vec::is_empty)
}

/// Whether the custody's `unkept` names `v`.
fn unkept(custody: &Value, v: &Put) -> StepResult<bool> {
    let want = name(&v.name)?;
    Ok(custody["unkept"].as_array().is_some_and(|u| {
        u.iter()
            .any(|x| x.as_str().and_then(|s| name(s).ok()).as_ref() == Some(&want))
    }))
}

/// A lease as evidence: holder, name, what it holds, until, audit.
fn shown(l: &Value) -> String {
    format!(
        "lease {} by {}: holds {}, until {} ms, audit {}",
        l["name"].as_str().unwrap_or_default(),
        l["holder"].as_str().unwrap_or_default(),
        l["holds"],
        l["until_ms"],
        l["audit"]
    )
}

/// Erase every copy `node`'s content store caches under `prefix`.
fn erase_cs(cx: &mut Cx<'_>, node: &str, prefix: &str) -> StepResult<String> {
    let sock = cx.w.node(node).sock().display().to_string();
    let op = cx
        .tool("ndn-ctl")
        .args(["--socket", &sock, "cs", "erase", prefix]);
    let out = cx.ok(op, "cs erase")?;
    Ok(out.stdout.trim().to_owned())
}

/// The phone's `release` of `v`: once both named holders prove every piece,
/// it must drop at least the photo's chunks.
fn released(cx: &mut Cx<'_>, phone: &mut Host, v: &Put, len: usize) -> StepResult<()> {
    let r = phone.ok(cx, &format!("release {}", v.name))?;
    let least = (len as u64).div_ceil(CHUNK);
    if r["versions"].as_u64().is_none_or(|n| n < 1)
        || r["pieces"].as_u64().is_none_or(|p| p < least)
        || r["bytes"].as_u64().is_none_or(|b| b < len as u64)
    {
        return Err(format!(
            "the phone's release of {} dropped {r}, not the photo's {least}+ pieces",
            v.name
        ));
    }
    cx.evidence(&format!(
        "phone released {} version(s), {} pieces, {} octets; kept {}",
        r["versions"], r["pieces"], r["bytes"], r["kept"]
    ));
    Ok(())
}

/// The stopped `holder` started again on its own store: it must sign with
/// the key it had.
fn restarted(cx: &mut Cx<'_>, holder: &Holder) -> StepResult<Holder> {
    let again = Holder::start(cx, &holder.node, &holder.device, &[NS], true)?;
    if again.writer != holder.writer {
        return Err(format!(
            "{} restarted as {}, not {}",
            holder.node, again.writer, holder.writer
        ));
    }
    Ok(again)
}

/// What `holder` stores for others, as evidence.
fn stored(cx: &mut Cx<'_>, holder: &Holder) -> StepResult<usize> {
    let stripes = holder.stripes()?;
    cx.evidence(&format!(
        "{} holds {} octets in {} stripes under {}",
        holder.node,
        octets(&holder.store.join("held")),
        stripes.len(),
        holder.store.join("held").display()
    ));
    Ok(stripes.len())
}

/// The photo as `host` reads it by the version's exact name: its length
/// and SHA-256 must be the file's.
fn reads_photo(
    cx: &mut Cx<'_>,
    host: &mut Host,
    v: &Put,
    len: usize,
    sha256: &str,
) -> StepResult<()> {
    let got = host.version(cx, PHOTOS, v)?;
    let photo = &got["payload"]["entry"]["photo"];
    if photo["len"] != len || photo["sha256"] != sha256 {
        return Err(format!(
            "{} reads {} as {photo}, not {len} octets with SHA-256 {sha256}",
            host.node, v.name
        ));
    }
    cx.evidence(&format!(
        "{} reads {}: {len} octets, SHA-256 {sha256} (the file's)",
        host.node, v.name
    ));
    Ok(())
}

/// `get` of `v` at `host` answers a final error naming a prune that covers
/// it: `v`'s writer, up to at least its seq.
fn pruned_at(cx: &mut Cx<'_>, host: &mut Host, v: &Put) -> StepResult<()> {
    let e = match host.call(cx, &format!("get {}", v.name))? {
        Ok(ok) => return Err(format!("{} still reads {}: {ok}", host.node, v.name)),
        Err(e) => e,
    };
    if e["retry"] != false || e["next"] != "none" || !includes(&e["pruned_by"]["upto"], v) {
        return Err(format!(
            "{}'s get of {} is not a final error naming its prune: {e}",
            host.node, v.name
        ));
    }
    cx.evidence(&format!(
        "{} answers get {} with next {}: pruned by {}",
        host.node, v.name, e["next"], e["pruned_by"]["name"]
    ));
    Ok(())
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    sc.world.add(
        "home",
        1,
        NodeCfg {
            links: vec![link("phone", 2), link("repo", 3), link("vault", 4)],
            quic_listen: true,
            ..Default::default()
        },
    );
    for (node, host) in [("phone", 2), ("repo", 3), ("vault", 4)] {
        sc.world.add(
            node,
            host,
            NodeCfg {
                links: vec![link("home", 1)],
                routes: vec![route(NS, "home")],
                peers: vec![PeerCfg {
                    device: Some(HOME.into()),
                    endpoint: Some(addr(1)),
                    ..Default::default()
                }],
                quic_dial_only: true,
                ..Default::default()
            },
        );
    }

    let root = sc.step("init home as the root device of /ph", |cx| {
        let root = init_root(cx, "home", NS, "home")?;
        if root.identity != HOME {
            return Err(format!(
                "home is {}, not {HOME} (the members' peer entry)",
                root.identity
            ));
        }
        Ok(root)
    })?;
    sc.step("start home's daemon with its CA", |cx| {
        cx.w.node_mut("home").cfg.identity = Some(root.identity.clone());
        cx.w.node_mut("home").cfg.ca = Some(CaCfg {
            prefix: NS.into(),
            identity: n("/CA"),
            member_days: None,
        });
        cx.start("home")
    })?;
    let invites = sc.step("make three member invites at home's CA", |cx| {
        mint(cx, "home", NS, &root.fp, 3, Some("1h"))
    })?;
    sc.step(
        "start the phone's, the repo's and the vault's daemons; each enrolls as a member over \
         its UDP face",
        |cx| {
            for (i, (node, device)) in [("phone", PHONE), ("repo", REPO), ("vault", VAULT)]
                .into_iter()
                .enumerate()
            {
                cx.start(node)?;
                let c = enroll(cx, node, &invites[i], node, false, None)?;
                if !c.starts_with(&format!("{device}/KEY/")) {
                    return Err(format!("{node}: unexpected certificate {c}"));
                }
                cx.evidence(&format!("{node} enrolled: {c}"));
            }
            Ok(())
        },
    )?;
    sc.step(
        "enrolled, the phone, the repo and the vault link to home over QUIC: each link carries \
         the other device and /ph/32=sync, none of it configured (the configs route only /ph, \
         for enrollment)",
        |cx| {
            cx.concept("sync group carried by the trust-context and link libraries");
            for (node, peer) in [
                ("home", PHONE),
                ("home", REPO),
                ("home", VAULT),
                ("phone", HOME),
                ("repo", HOME),
                ("vault", HOME),
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
                cx.evidence(&found.unwrap_or_default());
            }
            for node in ["home", "phone", "repo", "vault"] {
                let config = cx.w.node(node).config();
                let text = std::fs::read_to_string(&config)
                    .map_err(|e| format!("{}: {e}", config.display()))?;
                // Only `[[route]]` tables are routes (`[ca] prefix` is not).
                let mut section = "";
                let mut routes: Vec<&str> = Vec::new();
                for l in text.lines().map(str::trim) {
                    if l.starts_with('[') {
                        section = l;
                    } else if section == "[[route]]"
                        && let Some(p) = l.strip_prefix("prefix = ")
                    {
                        routes.push(p);
                    }
                }
                let enrollment = if node == "home" {
                    vec![]
                } else {
                    vec!["\"/ph\""]
                };
                if routes != enrollment {
                    return Err(format!("{node}'s config routes {routes:?}"));
                }
                cx.evidence(&format!("{node}'s config routes {routes:?}"));
            }
            Ok(())
        },
    )?;

    let (mut home, mut phone) = sc.step(
        "start the data layer on home and the phone (ndn-data on its daemon, signing with its \
         own key); home watches the photos",
        |cx| {
            cx.concept("data layer host (ndn-data)");
            let mut home = Host::start(cx, "home", HOME)?;
            let phone = Host::start(cx, "phone", PHONE)?;
            if home.writer == phone.writer {
                return Err("both devices write with one key".into());
            }
            home.ok(cx, &format!("watch {PHOTOS}"))?;
            cx.evidence(&format!("home writes as {}", home.writer));
            cx.evidence(&format!("phone writes as {}", phone.writer));
            Ok((home, phone))
        },
    )?;

    let (photo, caption, len, sha256) = sc.step(
        "the phone shares the photos (log rule, sealed to /ph) and puts a 1.5 MB photo and a \
         caption: the photo travels in pieces (home's watch sees it by its size)",
        |cx| {
            let bytes = content(PHOTO_LEN, 0x0094_0705);
            let sha256 = hex(&Sha256::digest(&bytes));
            let file = cx.w.node("phone").dir.join("photo.jpg");
            std::fs::write(&file, &bytes).map_err(|e| format!("{}: {e}", file.display()))?;
            phone.ok(cx, &format!("share {PHOTOS} rule=log readers=person:{NS}"))?;
            let photo = phone.put(
                cx,
                PHOTOS,
                &format!("photo=@{} title=beach", file.display()),
            )?;
            let caption = phone.put(cx, PHOTOS, "caption=\"the beach at noon\"")?;
            reads_photo(cx, &mut phone, &photo, PHOTO_LEN, &sha256)?;
            let seen = home.watched_until(cx, "the photo", CONVERGE, |w| {
                name(w["change"]["version"]["name"].as_str().unwrap_or_default()).ok()
                    == name(&photo.name).ok()
            })?;
            let size = &seen["change"]["version"]["payload"]["large"];
            if size.as_u64().is_none_or(|s| s < PHOTO_LEN as u64) {
                return Err(format!(
                    "home's watch delivers {} as {}, not large",
                    photo.name, seen["change"]["version"]["payload"]
                ));
            }
            cx.evidence(&format!(
                "home's watch: {} is large, {size} octets carried in pieces",
                photo.name
            ));
            Ok((photo, caption, PHOTO_LEN, sha256))
        },
    )?;

    let until = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
        + HOLD_DAYS * 24 * 3600 * 1000;
    let (mut repo, mut vault) = sc.step(
        "start the holders (ndn-repo hold for /ph, in its namespace) on the repo and the vault; \
         the phone asks them by name for two copies for 30 days: a lease from each covering \
         both versions, each audited kept, nothing unkept",
        |cx| {
            cx.concept("holder (ndn-repo hold)");
            cx.concept("custody: hold, lease, audit");
            let repo = Holder::start(cx, "repo", REPO, &[NS], true)?;
            let vault = Holder::start(cx, "vault", VAULT, &[NS], true)?;
            for (h, device) in [(&repo, REPO), (&vault, VAULT)] {
                if !h.writer.starts_with(&format!("{device}/KEY/")) {
                    return Err(format!(
                        "{} holds as {}, not a key of {device}",
                        h.node, h.writer
                    ));
                }
            }
            let mut last = Value::Null;
            wait_for(cx, "a kept lease from each holder", CONVERGE, |cx| {
                let custody = match hold(cx, &mut phone, until)? {
                    Ok(c) => c,
                    Err(e) if e["retry"] == true => return Ok(false),
                    Err(e) => return Err(format!("phone> hold: {e}")),
                };
                let mut done = nothing_unkept(&custody);
                for h in [&repo, &vault] {
                    let Some(lease) = lease_of(&custody["leases"], &h.writer) else {
                        done = false;
                        continue;
                    };
                    if lease["audit"].get("broken").is_some() {
                        return Err(format!(
                            "{}'s first lease is audited broken: {lease}",
                            h.node
                        ));
                    }
                    done &= keeps(lease, &photo) && includes(&lease["holds"], &caption);
                }
                last = custody;
                Ok(done)
            })?;
            for h in [&repo, &vault] {
                let lease = lease_of(&last["leases"], &h.writer)
                    .ok_or_else(|| format!("no lease of {} in {last}", h.node))?;
                if lease["until_ms"].as_u64().is_none_or(|u| u > until) {
                    return Err(format!(
                        "{}'s lease outlives the hold asked for: {lease}",
                        h.node
                    ));
                }
                cx.evidence(&shown(lease));
            }
            cx.evidence(&format!("unkept: {}", last["unkept"]));
            for h in [&repo, &vault] {
                if stored(cx, h)? < 2 {
                    return Err(format!(
                        "{} does not hold erasure-coded across several stripes",
                        h.node
                    ));
                }
            }
            Ok((repo, vault))
        },
    )?;

    sc.step(
        "the phone releases the photo's pieces once both named holders prove, to a fresh audit \
         over every piece while the phone serves none, that they keep them; with every \
         forwarder's cached copies erased it still reads the photo from the holders, length \
         and SHA-256 the file's",
        |cx| {
            released(cx, &mut phone, &photo, len)?;
            for node in ["phone", "home", "repo", "vault"] {
                let out = erase_cs(cx, node, &photo.name)?;
                cx.evidence(&format!("{node}: cs erase {}: {out}", photo.name));
            }
            reads_photo(cx, &mut phone, &photo, len, &sha256)
        },
    )?;

    repo = sc.step(
        "the repo loses a disk: stopped, one stripe deleted, started again; the phone's next \
         hold audits its lease kept",
        |cx| {
            let stripes = repo.stripes()?;
            let lost = stripes
                .first()
                .ok_or_else(|| format!("the repo holds no stripe under {}", repo.store.display()))?
                .clone();
            repo.stop(cx);
            delete(&lost)?;
            cx.evidence(&format!(
                "deleted stripe {} of {}",
                lost.display(),
                stripes.len()
            ));
            let repo = restarted(cx, &repo)?;
            let custody = hold(cx, &mut phone, until)?.map_err(|e| format!("phone> hold: {e}"))?;
            if let Some(b) = lease_of(&custody["broken"], &repo.writer) {
                return Err(format!("one lost stripe broke the repo's lease: {b}"));
            }
            let lease = lease_of(&custody["leases"], &repo.writer)
                .ok_or_else(|| format!("no lease of the repo in {custody}"))?;
            if !keeps(lease, &photo) {
                return Err(format!("after one lost stripe the repo's lease is {lease}"));
            }
            cx.evidence(&shown(lease));
            Ok(repo)
        },
    )?;

    (repo, vault) = sc.step(
        "the phone releases the pieces its read fetched back (both holders again prove every \
         piece) and every cache under /ph is erased; the vault goes offline (stopped, its \
         stripes kept) and the repo loses what it held (stopped, every stripe deleted, \
         started): the phone's hold reports the repo's lease broken by the audit and the \
         vault's unanswered, no lease audited kept holds the photo, and the custody names it \
         unkept",
        |cx| {
            released(cx, &mut phone, &photo, len)?;
            vault.stop(cx);
            let stripes = repo.stripes()?;
            repo.stop(cx);
            for s in &stripes {
                delete(s)?;
            }
            cx.evidence(&format!(
                "deleted all {} stripes of the repo",
                stripes.len()
            ));
            for node in ["phone", "home", "repo", "vault"] {
                let out = erase_cs(cx, node, NS)?;
                cx.evidence(&format!("{node}: cs erase {NS}: {out}"));
            }
            let repo = restarted(cx, &repo)?;
            let custody = hold(cx, &mut phone, until)?.map_err(|e| format!("phone> hold: {e}"))?;
            let caught = lease_of(&custody["broken"], &repo.writer)
                .ok_or_else(|| format!("the audit did not catch the repo's loss: {custody}"))?;
            let audit = &caught["audit"];
            if audit["broken"]["breach"] != "missing" && audit.get("unanswered").is_none() {
                return Err(format!("the repo's lost lease is audited {audit}"));
            }
            cx.evidence(&format!("caught: {}", shown(caught)));
            let away = lease_of(&custody["broken"], &vault.writer)
                .ok_or_else(|| format!("the offline vault's lease is not reported: {custody}"))?;
            if away["audit"].get("unanswered").is_none() {
                return Err(format!(
                    "the offline vault's lease is audited {}, not unanswered",
                    away["audit"]
                ));
            }
            cx.evidence(&format!("no answer, no verdict: {}", shown(away)));
            let claimed: Vec<&Value> = custody["leases"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|l| keeps(l, &photo))
                .collect();
            if !claimed.is_empty() {
                return Err(format!(
                    "no device in reach has the photo, yet leases audited kept hold it: \
                     {claimed:?}"
                ));
            }
            if !unkept(&custody, &photo)? {
                return Err(format!(
                    "the photo is kept nowhere in reach, and the custody does not name it \
                     unkept: {custody}"
                ));
            }
            cx.evidence(&format!("unkept: {}", custody["unkept"]));
            Ok((repo, vault))
        },
    )?;

    vault = sc.step(
        "the vault comes back with its stripes: the phone's hold asks the repo again, which \
         fetches the photo back from the vault (the only copy left); both leases are audited \
         kept, nothing is unkept, and the phone reads the photo",
        |cx| {
            let vault = restarted(cx, &vault)?;
            let mut last = Value::Null;
            wait_for(cx, "both leases kept again", CONVERGE, |cx| {
                let custody =
                    hold(cx, &mut phone, until)?.map_err(|e| format!("phone> hold: {e}"))?;
                let done = nothing_unkept(&custody)
                    && [&repo, &vault].into_iter().all(|h| {
                        lease_of(&custody["leases"], &h.writer).is_some_and(|l| keeps(l, &photo))
                    });
                last = custody;
                Ok(done)
            })?;
            for h in [&repo, &vault] {
                let lease = lease_of(&last["leases"], &h.writer)
                    .ok_or_else(|| format!("no lease of {} in {last}", h.node))?;
                cx.evidence(&format!("kept: {}", shown(lease)));
            }
            cx.evidence(&format!("unkept: {}", last["unkept"]));
            stored(cx, &repo)?;
            reads_photo(cx, &mut phone, &photo, len, &sha256)?;
            Ok(vault)
        },
    )?;

    sc.step(
        "the phone prunes the photo: the phone and home answer get of it with a final error \
         naming the prune, the caption still reads, and the phone's audit of both leases finds \
         nothing broken",
        |cx| {
            cx.concept("prune");
            let ok = phone.ok(
                cx,
                &format!("prune {} upto={}:{}", photo.name, photo.writer, photo.seq),
            )?;
            cx.evidence(&format!("phone pruned {}: upto {}", photo.name, ok["upto"]));
            pruned_at(cx, &mut phone, &photo)?;
            home.watched_until(cx, "the photo pruned", CONVERGE, |w| {
                let p = &w["change"]["pruned"]["id"];
                p["writer"] == photo.writer.as_str() && p["seq"] == photo.seq
            })?;
            cx.evidence(&format!("home's watch: {} pruned", photo.name));
            pruned_at(cx, &mut home, &photo)?;
            let got = home.version(cx, PHOTOS, &caption)?;
            if got["payload"]["entry"]["caption"] != "the beach at noon" {
                return Err(format!("home reads the caption as {got}"));
            }
            cx.evidence(&format!("home reads {}: {}", caption.name, got["payload"]));
            let custody = hold(cx, &mut phone, until)?.map_err(|e| format!("phone> hold: {e}"))?;
            if custody["broken"].as_array().is_none_or(|b| !b.is_empty()) {
                return Err(format!("after the prune the audit finds {custody}"));
            }
            for h in [&repo, &vault] {
                let lease = lease_of(&custody["leases"], &h.writer)
                    .ok_or_else(|| format!("no lease of {} in {custody}", h.node))?;
                if lease["audit"].get("kept").is_none() {
                    return Err(format!("after the prune {}'s lease is {lease}", h.node));
                }
                cx.evidence(&shown(lease));
                stored(cx, h)?;
            }
            Ok(())
        },
    )?;
    Ok(())
}
