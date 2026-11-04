//! sensor: a small, constant stream — a sensor's readings signed in blocks
//! under the one-key rule, held by a repo, read by name and by time, and
//! dropped everywhere once their keep passes — the data layer's streams
//! (data-layer spec §4.1 blocks, §5.3 one key, §5.4 range reads, §14.1
//! retention by expiry) on real daemons.
//!
//! Topology, on the harness's `lo`: home (10.200.0.1, the root device of
//! /hm as /hm/admin/home, with its CA, listening for QUIC links), sensor
//! (.2), repo (.3) and phone (.4), each a member enrolled by invite over a
//! UDP face that routes `/hm` to home (the enrollment route, and no other),
//! naming home as its QUIC peer: once enrolled each links to it by itself,
//! and the link library routes each device's name and the sync group
//! `/hm/32=sync` over its link (spec §12). No config routes a collection, a
//! device or the group.
//!
//! The sensor and the phone host their data layer with `ndn-data` (see
//! [`super::data_host`]); the repo runs `ndn-repo hold --hold-for /hm
//! --in-namespace`, a device of /hm holding the namespace's data for
//! custody.
//!
//! Proves: the sensor shares a one-key collection naming itself (its key
//! the one writer, sealed to /hm) and publishes 20 readings a second for
//! 20 s, each kept 90 s from its write, accepting a 1 s batch delay: every
//! put answers the block that carries it, and the blocks are far fewer than
//! the readings (one signature per block). The sensor's own range read by
//! seq over every block returns exactly the readings it put, each in the
//! block its put named, in order, dates non-decreasing, each named
//! `<block>/32=entry/seg=<index>`. Asked by name, the repo signs a lease
//! holding the stream, audited kept, and serves the oldest block under its
//! own name (`32=held`). The phone reads the newest block through the
//! signed head (newest, with how long it may be unconfirmed), a range by
//! time and one by seq — each exactly the sensor's entries in that range,
//! none missing — and one entry by its name, exact; its own put into the
//! stream is refused (one key writes). Once the keep passes, the phone's
//! watch reports every block expired with the latest keep of its entries,
//! and the phone and the sensor answer `get` of an old block with a final
//! `Expired` naming it and its keep. The sensor goes on (readings kept an
//! hour): the phone's range read by seq over the whole stream returns
//! exactly the new readings and lists every old block as expired, none
//! missing, and a range by time over the old window returns no entry; the
//! sensor's next hold finds the repo's lease kept with nothing broken or
//! unkept, and the repo no longer serves the old blocks (`32=held`
//! unanswered with its cache erased) while it serves the new ones.

use std::collections::{BTreeMap, BTreeSet};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::Value;

use super::data_host::{
    ANSWER, CONVERGE, Holder, Host, Put, carries_group, delivered, erase_cs, includes, name,
    unanswered,
};
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{CaCfg, NodeCfg, PeerCfg, addr};

const NS: &str = "/hm";
const HOME: &str = "/hm/admin/home";
const SENSOR: &str = "/hm/member/sensor";
const REPO: &str = "/hm/member/repo";
const PHONE: &str = "/hm/member/phone";
/// The sensor's stream: a one-key collection, its key the one writer.
const STREAM: &str = "/hm/32=data/temperature";
/// The namespace's sync group (data-layer spec §12).
const GROUP: &str = "/hm/32=sync";
/// How often the sensor reads: 20 readings a second.
const EVERY: Duration = Duration::from_millis(50);
/// The readings of the first 20 s.
const READINGS: u64 = 400;
/// The delay the sensor accepts so that readings share a signature.
const BATCH_MS: u64 = 1000;
/// How long each of the first readings is kept, from its write.
const KEEP_MS: u64 = 90_000;
/// The readings after the first ones expired, each kept an hour.
const LATER: u64 = 40;
const LATER_KEEP_MS: u64 = 3_600_000;
/// How long the sensor asks the repo to hold the stream.
const HOLD_DAYS: u64 = 1;

fn n(s: &str) -> String {
    format!("{NS}{s}")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Reading `i`'s value.
fn celsius(i: u64) -> String {
    format!("{}.{}", 18 + (i / 20) % 6, i % 10)
}

/// One reading the sensor put: its number, value, keep, and the block its
/// put answered.
#[derive(Clone, Debug)]
struct Reading {
    i: u64,
    celsius: String,
    keep: u64,
    block: Put,
}

/// One entry of a range read.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    name: String,
    seq: u64,
    index: u64,
    dated: u64,
    i: u64,
    celsius: String,
}

/// `<block>/32=entry/seg=<index>`, canonical.
fn entry_name(block: &str, index: u64) -> StepResult<String> {
    Ok(name(&format!("{block}/32=entry/seg={index}"))?.to_string())
}

/// The sensor puts readings `from..from + count`, one every [`EVERY`],
/// batched, each kept until `keep()` at its put; the readings by number,
/// each with the block its put answered.
fn stream(
    cx: &mut Cx<'_>,
    sensor: &mut Host,
    from: u64,
    count: u64,
    keep: impl Fn() -> u64,
) -> StepResult<Vec<Reading>> {
    let start = Instant::now();
    let mut keeps = BTreeMap::new();
    for (k, i) in (from..from + count).enumerate() {
        let at = start + EVERY * k as u32;
        thread::sleep(at.saturating_duration_since(Instant::now()));
        let until = keep();
        keeps.insert(i, until);
        sensor.send(
            cx,
            &format!(
                "put {STREAM} --batch {BATCH_MS} --keep until={until} i={i} celsius={}",
                celsius(i)
            ),
        )?;
    }
    let answers = sensor.answers(cx, "the readings' puts", count as usize, ANSWER)?;
    let mut readings = BTreeMap::new();
    for a in answers {
        let ok =
            a.map_err(|e| format!("sensor> put: {} (next: {})", e["message"], e["next_step"]))?;
        let block = sensor.put_of(STREAM, &ok)?;
        let i: u64 = ok["fields"]["i"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("a put answer names no reading: {ok}"))?;
        let keep = *keeps
            .get(&i)
            .ok_or_else(|| format!("a put answers reading {i}, which was not put: {ok}"))?;
        if ok["fields"]["celsius"] != celsius(i).as_str() {
            return Err(format!("reading {i} answered as {ok}"));
        }
        if readings
            .insert(
                i,
                Reading {
                    i,
                    celsius: celsius(i),
                    keep,
                    block,
                },
            )
            .is_some()
        {
            return Err(format!("reading {i} answered twice"));
        }
    }
    Ok(readings.into_values().collect())
}

/// The blocks carrying `readings`, by seq: each block and the latest keep
/// of its readings.
fn blocks(readings: &[Reading]) -> BTreeMap<u64, (Put, u64)> {
    let mut blocks: BTreeMap<u64, (Put, u64)> = BTreeMap::new();
    for r in readings {
        let b = blocks
            .entry(r.block.seq)
            .or_insert_with(|| (r.block.clone(), r.keep));
        b.1 = b.1.max(r.keep);
    }
    blocks
}

/// `range <stream> <bounds>` at `host`: its answer, which must succeed.
fn range_ok(cx: &mut Cx<'_>, host: &mut Host, bounds: &str) -> StepResult<Value> {
    host.call(cx, &format!("range {STREAM} {bounds}"))?
        .map_err(|e| {
            format!(
                "{}> range {STREAM} {bounds}: {} (next: {})",
                host.node, e["message"], e["next_step"]
            )
        })
}

/// The entries of a range or entry answer, every one by `writer`.
fn entries_of(ok: &Value, writer: &str) -> StepResult<Vec<Entry>> {
    let e = &ok["entries"];
    if e["writer"] != writer {
        return Err(format!("entries of {}, not {writer}: {ok}", e["writer"]));
    }
    e["entries"]
        .as_array()
        .ok_or_else(|| format!("no entries in {ok}"))?
        .iter()
        .map(|x| {
            let bad = || format!("not an entry of the stream: {x}");
            if x["id"]["writer"] != writer {
                return Err(format!("an entry by {}: {x}", x["id"]["writer"]));
            }
            Ok(Entry {
                name: name(x["name"].as_str().ok_or_else(bad)?)?.to_string(),
                seq: x["id"]["seq"].as_u64().ok_or_else(bad)?,
                index: x["index"].as_u64().ok_or_else(bad)?,
                dated: x["dated_ms"].as_u64().ok_or_else(bad)?,
                i: x["fields"]["i"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(bad)?,
                celsius: x["fields"]["celsius"].as_str().ok_or_else(bad)?.to_owned(),
            })
        })
        .collect()
}

/// The seqs of `writer`'s blocks a range answer lists under `list`
/// (`missing`, `expired`, `large`).
fn listed(ok: &Value, list: &str, writer: &str) -> StepResult<BTreeSet<u64>> {
    ok["entries"][list]
        .as_array()
        .ok_or_else(|| format!("no {list} in {ok}"))?
        .iter()
        .map(|id| {
            if id["writer"] != writer {
                return Err(format!("{list} names a block of {}: {ok}", id["writer"]));
            }
            id["seq"]
                .as_u64()
                .ok_or_else(|| format!("{list} lists no seq: {ok}"))
        })
        .collect()
}

/// A range answer at `host` is exactly `want`, none missing.
fn exactly(host: &str, what: &str, ok: &Value, writer: &str, want: &[Entry]) -> StepResult<()> {
    let got = entries_of(ok, writer)?;
    let missing = listed(ok, "missing", writer)?;
    if !missing.is_empty() {
        return Err(format!("{host}'s {what} misses blocks {missing:?}: {ok}"));
    }
    if got != want {
        let have: Vec<u64> = got.iter().map(|e| e.i).collect();
        let need: Vec<u64> = want.iter().map(|e| e.i).collect();
        return Err(format!(
            "{host}'s {what} returns readings {have:?}, not exactly {need:?}: {ok}"
        ));
    }
    Ok(())
}

/// The `get` error of `block` at `host`: a final `Expired` naming it.
fn expired_at(cx: &mut Cx<'_>, host: &mut Host, block: &Put, keep: u64) -> StepResult<()> {
    let e = match host.call(cx, &format!("get {}", block.name))? {
        Ok(ok) => return Err(format!("{} still reads {}: {ok}", host.node, block.name)),
        Err(e) => e,
    };
    let named = e["expired"]["name"]
        .as_str()
        .and_then(|s| name(s).ok())
        .is_some_and(|n| Some(n) == name(&block.name).ok());
    if e["retry"] != false || e["next"] != "none" || !named {
        return Err(format!(
            "{}'s get of {} is not a final Expired naming it: {e}",
            host.node, block.name
        ));
    }
    if e["expired"]["keep"]["until_ms"] != keep {
        return Err(format!(
            "{} answers {} expired with keep {}, not until {keep} (its latest entry's)",
            host.node, block.name, e["expired"]["keep"]
        ));
    }
    cx.evidence(&format!(
        "{} answers get {} with next {}: expired, keep {}",
        host.node, block.name, e["next"], e["expired"]["keep"]
    ));
    Ok(())
}

/// `hold` of the stream at the sensor (one copy, held by the repo): the
/// custody, or the error.
fn hold(cx: &mut Cx<'_>, sensor: &mut Host, until: u64) -> StepResult<Result<Value, Value>> {
    Ok(sensor
        .call_within(
            cx,
            &format!("hold {STREAM} copies=1 until={until} holders={REPO}"),
            CONVERGE,
        )?
        .map(|mut ok| ok["custody"].take()))
}

/// The sensor's hold until the repo's lease is audited kept and holds
/// `newest`, nothing unkept and no lease broken: the lease.
fn kept_lease(
    cx: &mut Cx<'_>,
    sensor: &mut Host,
    repo: &Holder,
    newest: &Put,
    until: u64,
) -> StepResult<Value> {
    let mut last = Value::Null;
    wait_for(
        cx,
        "the repo's lease kept, holding the newest block",
        CONVERGE,
        |cx| {
            let custody = match hold(cx, sensor, until)? {
                Ok(c) => c,
                Err(e) if e["retry"] == true => return Ok(false),
                Err(e) => return Err(format!("sensor> hold: {e}")),
            };
            if custody["broken"].as_array().is_some_and(|b| !b.is_empty()) {
                return Err(format!("the sensor's hold finds leases broken: {custody}"));
            }
            let done = custody["unkept"].as_array().is_some_and(Vec::is_empty)
                && custody["leases"].as_array().is_some_and(|ls| {
                    ls.iter().any(|l| {
                        l["holder"] == repo.writer.as_str()
                            && l["audit"].get("kept").is_some()
                            && includes(&l["holds"], newest)
                    })
                });
            last = custody;
            Ok(done)
        },
    )?;
    let lease = last["leases"]
        .as_array()
        .and_then(|ls| ls.iter().find(|l| l["holder"] == repo.writer.as_str()))
        .cloned()
        .ok_or_else(|| format!("no lease of the repo in {last}"))?;
    cx.evidence(&format!(
        "lease {} by {}: holds {}, until {} ms, audit {}; unkept {}",
        lease["name"].as_str().unwrap_or_default(),
        lease["holder"].as_str().unwrap_or_default(),
        lease["holds"],
        lease["until_ms"],
        lease["audit"],
        last["unkept"]
    ));
    Ok(lease)
}

/// `block` as the repo serves it under its own name (`32=held`).
fn held(block: &Put) -> StepResult<String> {
    Ok(ndn_data::wire::held_name(&name(REPO)?, &name(&block.name)?).to_string())
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    sc.world.add(
        "home",
        1,
        NodeCfg {
            links: vec![link("sensor", 2), link("repo", 3), link("phone", 4)],
            quic_listen: true,
            ..Default::default()
        },
    );
    for (node, host) in [("sensor", 2), ("repo", 3), ("phone", 4)] {
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

    let root = sc.step("init home as the root device of /hm", |cx| {
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
        "start the sensor's, the repo's and the phone's daemons; each enrolls as a member over \
         its UDP face",
        |cx| {
            for (i, (node, device)) in [("sensor", SENSOR), ("repo", REPO), ("phone", PHONE)]
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
        "enrolled, the sensor, the repo and the phone link to home over QUIC: each link carries \
         the other device and /hm/32=sync, none of it configured (the configs route only /hm, \
         for enrollment)",
        |cx| {
            cx.concept("sync group carried by the trust-context and link libraries");
            for (node, peer) in [
                ("home", SENSOR),
                ("home", REPO),
                ("home", PHONE),
                ("sensor", HOME),
                ("repo", HOME),
                ("phone", HOME),
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
            for node in ["home", "sensor", "repo", "phone"] {
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
                    vec!["\"/hm\""]
                };
                if routes != enrollment {
                    return Err(format!("{node}'s config routes {routes:?}"));
                }
                cx.evidence(&format!("{node}'s config routes {routes:?}"));
            }
            Ok(())
        },
    )?;

    let (mut sensor, mut phone, repo) = sc.step(
        "start the data layer on the sensor and the phone (ndn-data, each signing with its own \
         key) and the holder on the repo (ndn-repo hold for /hm, in its namespace); the sensor \
         shares its stream as a one-key collection naming itself, sealed to /hm; the phone \
         watches it",
        |cx| {
            cx.concept("data layer host (ndn-data)");
            cx.concept("holder (ndn-repo hold)");
            cx.concept("one-key collection");
            let mut sensor = Host::start(cx, "sensor", SENSOR)?;
            let mut phone = Host::start(cx, "phone", PHONE)?;
            let repo = Holder::start(cx, "repo", REPO, &[NS], true)?;
            if !sensor.writer.starts_with(&format!("{SENSOR}/KEY/"))
                || !repo.writer.starts_with(&format!("{REPO}/KEY/"))
            {
                return Err(format!(
                    "the sensor writes as {} and the repo holds as {}: not their keys",
                    sensor.writer, repo.writer
                ));
            }
            sensor.ok(
                cx,
                &format!("share {STREAM} rule=one-key writers={SENSOR} readers=person:{NS}"),
            )?;
            phone.ok(cx, &format!("watch {STREAM}"))?;
            cx.evidence(&format!("the sensor writes as {}", sensor.writer));
            cx.evidence(&format!("the phone writes as {}", phone.writer));
            cx.evidence(&format!("the repo holds as {}", repo.writer));
            Ok((sensor, phone, repo))
        },
    )?;

    let (first, all, oldest, newest) = sc.step(
        "the sensor publishes 20 readings a second for 20 s, each kept 90 s from its write, \
         accepting a 1 s batch delay: each put answers the block carrying it, far fewer blocks \
         than readings; its own range read by seq over every block returns exactly what it \
         put, in order, each entry named in its block",
        |cx| {
            cx.concept("signed blocks (batching)");
            let readings = stream(cx, &mut sensor, 0, READINGS, || now_ms() + KEEP_MS)?;
            let first = blocks(&readings);
            let per = first.len() as f64 / readings.len() as f64;
            cx.evidence(&format!(
                "{} readings in {} blocks: {per:.3} signatures per reading",
                readings.len(),
                first.len()
            ));
            if first.len() * 5 > readings.len() {
                return Err(format!(
                    "{} readings put with a 1 s batch at 20/s took {} blocks: the batch does \
                     not share signatures",
                    readings.len(),
                    first.len()
                ));
            }
            let (lo, hi) = (
                *first.keys().next().ok_or("no block")?,
                *first.keys().next_back().ok_or("no block")?,
            );
            let ok = range_ok(cx, &mut sensor, &format!("seq={lo}..{hi}"))?;
            let all = entries_of(&ok, &sensor.writer)?;
            for list in ["missing", "expired", "large"] {
                let l = listed(&ok, list, &sensor.writer)?;
                if !l.is_empty() {
                    return Err(format!("the sensor's own stream lists {list} {l:?}: {ok}"));
                }
            }
            if all.len() != readings.len() {
                return Err(format!(
                    "the sensor's range read returns {} entries for {} readings: {ok}",
                    all.len(),
                    readings.len()
                ));
            }
            let mut seen = BTreeSet::new();
            for (k, e) in all.iter().enumerate() {
                let r = readings
                    .get(e.i as usize)
                    .filter(|r| r.i == e.i)
                    .ok_or_else(|| format!("an entry of no reading: {e:?}"))?;
                if !seen.insert(e.i) || e.seq != r.block.seq || e.celsius != r.celsius {
                    return Err(format!(
                        "entry {e:?} is not reading {} as put (block {})",
                        r.i, r.block.seq
                    ));
                }
                if e.name != entry_name(&r.block.name, e.index)? {
                    return Err(format!(
                        "entry {e:?} is not named in block {}",
                        r.block.name
                    ));
                }
                if let Some(p) = k.checked_sub(1).map(|p| &all[p]) {
                    let next_in_block = p.seq == e.seq && e.index == p.index + 1;
                    let next_block = p.seq < e.seq && e.index == 0;
                    if !(next_in_block || next_block) || e.dated < p.dated {
                        return Err(format!(
                            "entries out of (seq, index, date) order: {p:?}, {e:?}"
                        ));
                    }
                } else if e.index != 0 {
                    return Err(format!("the first entry is {e:?}"));
                }
            }
            cx.evidence(&format!(
                "the sensor reads blocks {lo}..{hi}: {} entries, exactly the readings it put, \
                 dated {}..{} ms",
                all.len(),
                all[0].dated,
                all[all.len() - 1].dated
            ));
            let (oldest, newest) = (first[&lo].0.clone(), first[&hi].0.clone());
            Ok((first, all, oldest, newest))
        },
    )?;
    let earliest_keep = first.values().map(|b| b.1).min().unwrap_or(0);

    let until = now_ms() + HOLD_DAYS * 24 * 3600 * 1000;
    sc.step(
        "the sensor asks the repo by name to hold the stream: a lease holding every block, \
         audited kept, nothing unkept; the repo serves the oldest block under its own name",
        |cx| {
            cx.concept("custody: hold, lease, audit");
            kept_lease(cx, &mut sensor, &repo, &newest, until)?;
            delivered(cx, "repo", &held(&oldest)?)?;
            cx.evidence(&format!(
                "the repo serves {} as {}",
                oldest.name,
                held(&oldest)?
            ));
            Ok(())
        },
    )?;

    sc.step(
        "the phone reads the stream: the newest block through the sensor's signed head, a \
         range by time and one by seq, each exactly the sensor's entries in it, none missing, \
         and one entry by its name; its own put into the stream is refused (one key writes)",
        |cx| {
            cx.concept("one-key head and freshness bound");
            cx.concept("range reads by seq and by time");
            if now_ms() + 10_000 >= earliest_keep {
                return Err(format!(
                    "the run reached the reads {} ms before the first keep: too slow for the \
                     keep this scenario sets",
                    earliest_keep.saturating_sub(now_ms())
                ));
            }
            let mut got = Value::Null;
            wait_for(
                cx,
                "the phone reads the newest block",
                CONVERGE,
                |cx| match phone.call(cx, &format!("get {STREAM}"))? {
                    Ok(ok) => {
                        let done = ok["version"]["id"]["seq"] == newest.seq;
                        got = ok;
                        Ok(done)
                    }
                    Err(e) if e["retry"] == true => Ok(false),
                    Err(e) => Err(format!("phone> get {STREAM}: {e}")),
                },
            )?;
            if got["version"]["id"]["writer"] != sensor.writer.as_str()
                || got["age"]["unconfirmed_for_ms"].as_u64().is_none()
            {
                return Err(format!(
                    "the phone's get of the stream answers {got}, not the sensor's newest with \
                     how long it may be unconfirmed"
                ));
            }
            cx.evidence(&format!(
                "the phone reads {} (newest), unconfirmed for at most {} ms",
                got["version"]["name"].as_str().unwrap_or_default(),
                got["age"]["unconfirmed_for_ms"]
            ));

            let (from, to) = (all[all.len() / 4].dated, all[3 * all.len() / 4].dated);
            if from >= to {
                return Err(format!(
                    "the sensor dated a quarter of its readings {from}..{to}"
                ));
            }
            let want: Vec<Entry> = all
                .iter()
                .filter(|e| from <= e.dated && e.dated < to)
                .cloned()
                .collect();
            let ok = range_ok(cx, &mut phone, &format!("time={from}..{to}"))?;
            exactly("phone", "range by time", &ok, &sensor.writer, &want)?;
            cx.evidence(&format!(
                "the phone's range {from}..{to} ms: readings {}..{} ({} entries), exactly the \
                 sensor's dated in it",
                want[0].i,
                want[want.len() - 1].i,
                want.len()
            ));

            let seqs: Vec<u64> = first.keys().copied().collect();
            let (lo, hi) = (seqs[1], seqs[seqs.len() / 2]);
            let want: Vec<Entry> = all
                .iter()
                .filter(|e| (lo..=hi).contains(&e.seq))
                .cloned()
                .collect();
            let ok = range_ok(cx, &mut phone, &format!("seq={lo}..{hi}"))?;
            exactly("phone", "range by seq", &ok, &sensor.writer, &want)?;
            cx.evidence(&format!(
                "the phone's blocks {lo}..{hi}: {} entries, exactly the sensor's in them",
                want.len()
            ));

            let one = &all[all.len() / 2];
            let ok = phone.ok(cx, &format!("get {}", one.name))?;
            exactly(
                "phone",
                "entry",
                &ok,
                &sensor.writer,
                std::slice::from_ref(one),
            )?;
            if ok["age"] != "exact" {
                return Err(format!(
                    "the phone's entry {} is aged {}",
                    one.name, ok["age"]
                ));
            }
            cx.evidence(&format!(
                "the phone reads {}: reading {}, {} °C (exact)",
                one.name, one.i, one.celsius
            ));

            match phone.call(cx, &format!("put {STREAM} i=0 celsius=99.9"))? {
                Ok(ok) => return Err(format!("the phone wrote into the sensor's stream: {ok}")),
                Err(e) if e["retry"] == false => cx.evidence(&format!(
                    "the phone's put into {STREAM} is refused: {} (next: {})",
                    e["message"], e["next"]
                )),
                Err(e) => return Err(format!("the phone's put is refused as retryable: {e}")),
            }
            Ok(())
        },
    )?;

    sc.step(
        "the keep passes: the phone's watch reports every block expired with the latest keep \
         of its entries, and the phone and the sensor answer get of an old block with a final \
         Expired naming it and its keep",
        |cx| {
            cx.concept("retention by expiry");
            for (seq, (block, keep)) in &first {
                let within = Duration::from_millis(keep.saturating_sub(now_ms())) + CONVERGE;
                let w = phone.watched_until(cx, &format!("block {seq} expired"), within, |w| {
                    let x = &w["change"]["expired"];
                    x["id"]["writer"] == sensor.writer.as_str() && x["id"]["seq"] == *seq
                })?;
                let k = &w["change"]["expired"]["keep"];
                if k["until_ms"] != *keep {
                    return Err(format!(
                        "block {seq} expired with keep {k}, not until {keep} (its latest \
                         entry's)"
                    ));
                }
                if now_ms() < *keep {
                    return Err(format!(
                        "the phone reported block {seq} expired before its keep {keep}"
                    ));
                }
                cx.note(&format!("phone's watch: {} expired, keep {k}", block.name));
            }
            cx.evidence(&format!(
                "the phone's watch: all {} blocks expired, each at its latest entry's keep",
                first.len()
            ));
            for (block, keep) in [&first[&oldest.seq], &first[&newest.seq]] {
                expired_at(cx, &mut phone, block, *keep)?;
                expired_at(cx, &mut sensor, block, *keep)?;
            }
            Ok(())
        },
    )?;

    sc.step(
        "the sensor goes on (readings kept an hour): the phone's range read by seq over the \
         whole stream returns exactly the new readings and lists every old block expired, none \
         missing; a range by time over the old window returns no entry; the sensor's next hold \
         finds the repo's lease kept, nothing broken or unkept, and the repo serves the new \
         blocks but none of the old",
        |cx| {
            let keep = now_ms() + LATER_KEEP_MS;
            let later = stream(cx, &mut sensor, READINGS, LATER, || keep)?;
            let next = blocks(&later);
            let (lo, hi) = (
                *next.keys().next().ok_or("no block")?,
                *next.keys().next_back().ok_or("no block")?,
            );
            let ok = range_ok(cx, &mut sensor, &format!("seq={lo}..{hi}"))?;
            let want = entries_of(&ok, &sensor.writer)?;
            let put: Vec<u64> = later.iter().map(|r| r.i).collect();
            if want.iter().map(|e| e.i).collect::<Vec<_>>() != put {
                return Err(format!(
                    "the sensor's new blocks hold {ok}, not readings {put:?}"
                ));
            }

            let bounds = format!("seq={}..{hi}", oldest.seq);
            let mut got = Value::Null;
            wait_for(cx, "the phone reads the new readings", CONVERGE, |cx| {
                let ok = range_ok(cx, &mut phone, &bounds)?;
                let done = entries_of(&ok, &sensor.writer)? == want;
                got = ok;
                Ok(done)
            })?;
            exactly(
                "phone",
                "range over the whole stream",
                &got,
                &sensor.writer,
                &want,
            )?;
            let (from, to) = (all[0].dated, all[all.len() - 1].dated + 1);
            let ok = range_ok(cx, &mut phone, &format!("time={from}..{to}"))?;
            exactly(
                "phone",
                "range over the old window",
                &ok,
                &sensor.writer,
                &[],
            )?;
            cx.evidence(&format!(
                "the phone's range {from}..{to} ms (the old readings): no entry; expired {:?}",
                listed(&ok, "expired", &sensor.writer)?
            ));

            let latest = next
                .values()
                .next_back()
                .map(|b| b.0.clone())
                .ok_or("no block")?;
            kept_lease(cx, &mut sensor, &repo, &latest, until)?;
            let out = erase_cs(cx, "repo", &n("/member/repo/32=held"))?;
            cx.note(&format!("repo: cs erase {REPO}/32=held: {out}"));
            delivered(cx, "repo", &held(&latest)?)?;
            for block in [&oldest, &newest] {
                unanswered(cx, "repo", &held(block)?)?;
                cx.evidence(&format!(
                    "the repo no longer serves {} ({} unanswered)",
                    block.name,
                    held(block)?
                ));
            }
            cx.evidence(&format!(
                "the repo serves {} as {}",
                latest.name,
                held(&latest)?
            ));
            let expired = listed(&got, "expired", &sensor.writer)?;
            let old: BTreeSet<u64> = first.keys().copied().collect();
            if !old.is_subset(&expired) {
                return Err(format!(
                    "the phone's range lists expired {expired:?}, not every old block {old:?}"
                ));
            }
            cx.evidence(&format!(
                "the phone's blocks {}..{hi}: readings {}..{} ({} entries, exactly the new \
                 ones); expired: blocks {:?}",
                oldest.seq,
                want[0].i,
                want[want.len() - 1].i,
                want.len(),
                expired
            ));

            Ok(())
        },
    )?;
    Ok(())
}
