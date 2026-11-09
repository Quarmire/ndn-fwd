//! signals: two people's live cursors and a live edit through a community
//! relay that forwards them and cannot read them — ephemeral signals
//! (`ndn_surface::signal`, the signals spec; data-layer §20 for the gate)
//! on real daemons: never a version, never stored, never cached.
//!
//! Topology and gestures as in [`super::shared`]: alice (/ga) and bob
//! (/gb), each the root device of their namespace, pointing at each other,
//! linked through an open community relay (/gr) their trust contexts
//! advertise; no config holds a route, a UDP link, a `[[peer]]` or a
//! `[[relay]]`. Each person's device hosts its data layer and its signals
//! with `ndn-data` (see [`super::data_host`]), its entries in a store
//! directory (`--store`). Its signal runs open no local ring
//! (`--no-signal-ring`): the harness runs every daemon on one host, where a
//! ring would carry a run past the relay, as it would between two apps on
//! one real host. The relay's operator is curious: on the relay a capture
//! (`ndn-data` with no device, `signal-capture`) registers both people's
//! sync groups on the relay's daemon and prints every signal Interest the
//! daemon gives it.
//!
//! The pushes ride the sync groups the relay already carries: alice's
//! signals reach bob as Interests `/gb/32=sync/32=signal/<digest>`, bob's
//! reach alice in `/ga/32=sync`; nothing answers them.
//!
//! Proves: alice shares the sealed folder `/ga/32=data/sketch` (writers
//! /ga,/gb, readers both people) and writes its board; bob reads it. Both
//! subscribe to the folder's signals. Alice streams 120 cursor signals at
//! 60 Hz while bob streams 120 of his: each person's signals deliver the
//! other's through the relay (none off a local ring), at most 5 % lost by
//! their counters, and the subscriber reads the last of each stream (a
//! signal superseded before the reader took it is not read: the newest per
//! address, never a backlog); latency p50/p99 (send to read, one host's
//! clock) and octets per packet (each person's stats, and the relay's
//! capture) are reported. Every signal Interest the relay's capture saw —
//! in each group at least as many as its member delivered — decodes as
//! SignalSealed (a key id, a nonce, a ciphertext) and holds no folder
//! name, device or key name, address or payload text. No content store —
//! the relay's, alice's, bob's daemons — holds anything under the pushes'
//! or the run headers' names (an erase of each prefix erases nothing), and
//! neither person's store holds an entry with a `32=signal` component.
//! Alice's live text, three drafts sent as signals, reaches bob as the
//! newest draft, and no version came of any signal (bob's watch of the
//! folder delivered none while they flowed); alice commits the text with
//! one put, her next sequence, and bob's watch delivers exactly one new
//! version, his board the committed text.

use std::time::Duration;

use bytes::Bytes;
use ndn_packet::NameComponent;
use serde_json::Value;

use super::data_host::{CONVERGE, Host, Put, erase_cs, includes, name, stored};
use super::shared::{People, people_through_relay};
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};

const NAMESPACES: People = People {
    a: "/ga",
    b: "/gb",
    relay: "/gr",
};
/// The people's sync groups, which carry the pushes.
const GROUPS: [&str; 2] = ["/ga/32=sync", "/gb/32=sync"];
/// Alice's folder, the scope of the signals, and its board.
const FOLDER: &str = "/ga/32=data/sketch";
const BOARD: &str = "/ga/32=data/sketch/board";
/// Both people write and read: the folder is sealed to them.
const BOTH: &str = "writers=/ga,/gb readers=person:/ga,person:/gb";
/// The cursors: how many each person streams, how often.
const CURSOR: &str = "cursor";
const COUNT: u64 = 120;
const HZ: u64 = 60;
/// At most this many of a stream's signals may be lost (5 %): a push is
/// never sent again.
const MAX_LOST: u64 = 6;
/// The live edit: alice's drafts as signals, the last one committed.
const TEXT: &str = "text";
const DRAFTS: [&str; 3] = ["Plan", "Plan: museum", "Plan: museum at ten"];
/// How long a stream may take to be sent and its last signal received.
const STREAMED: Duration = Duration::from_secs(30);
/// How long a host prints nothing before what it delivered so far is taken
/// in (the counts check; no verdict depends on it).
const QUIET: Duration = Duration::from_secs(2);

/// `ndn-data` options of a person's host: its store directory, no ring.
fn options(cx: &Cx<'_>, node: &str) -> Vec<String> {
    vec![
        "--store".to_owned(),
        cx.w.node(node).dir.join("data-store").display().to_string(),
        "--no-signal-ring".to_owned(),
    ]
}

/// The keyword component `32=signal`.
fn signal_keyword() -> NameComponent {
    NameComponent::keyword(Bytes::from_static(b"signal"))
}

/// The signals `host` received since `from` from `sender` (a key name) for
/// `address`.
fn received<'a>(
    host: &'a Host,
    from: usize,
    sender: &'a str,
    address: &'a str,
) -> impl Iterator<Item = &'a Value> + 'a {
    host.signals[from..]
        .iter()
        .map(|s| &s["signal"])
        .filter(move |s| s["sender"] == sender && s["address"] == address)
}

/// The versions `host`'s watches delivered since `from`.
fn versions_since(host: &Host, from: usize) -> Vec<&Value> {
    host.watched[from..]
        .iter()
        .filter_map(|w| w["change"].get("version"))
        .collect()
}

/// The `q`-th percentile of `sorted`.
fn percentile(sorted: &[u64], q: usize) -> u64 {
    sorted[(sorted.len() - 1) * q / 100]
}

/// `host`'s signal counters.
fn stats(cx: &mut Cx<'_>, host: &mut Host) -> StepResult<Value> {
    let mut ok = host.ok(cx, "signal-stats")?;
    if ok["started"] != true {
        return Err(format!("{}'s signals never started: {ok}", host.node));
    }
    Ok(ok["stats"].take())
}

/// The captured Interests of `group` (the capture shows its group as the
/// daemon names it: compared as names).
fn captured<'a>(capture: &'a Host, group: &'a str) -> impl Iterator<Item = &'a Value> + 'a {
    let group = name(group).ok();
    capture
        .captured
        .iter()
        .filter(move |c| name(c["capture"].as_str().unwrap_or_default()).ok() == group)
        .map(|c| &c["interest"])
}

fn unhex(s: &str) -> StepResult<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| {
            s.get(i..i + 2)
                .and_then(|b| u8::from_str_radix(b, 16).ok())
                .ok_or_else(|| format!("{s} is no hex"))
        })
        .collect()
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    let (alice_root, bob_root) = people_through_relay(sc, NAMESPACES)?;

    let (mut alice, mut bob, mut capture) = sc.step(
        "start each person's data layer and signals (ndn-data, entries in a store directory, no \
         local ring) and, on the relay, its operator's capture of both people's sync groups \
         (ndn-data with no device: signal-capture /ga/32=sync and /gb/32=sync)",
        |cx| {
            cx.concept("signals: live data that is never a version");
            let alice_options = options(cx, "alice");
            let alice = Host::start_with(cx, "alice", &alice_root.identity, &alice_options)?;
            let bob_options = options(cx, "bob");
            let bob = Host::start_with(cx, "bob", &bob_root.identity, &bob_options)?;
            let mut capture = Host::capture(cx, "relay")?;
            for group in GROUPS {
                capture.ok(cx, &format!("signal-capture {group}"))?;
            }
            cx.evidence(&format!(
                "alice writes as {}, bob as {}; the relay's capture registered {GROUPS:?} on the \
                 relay's daemon",
                alice.writer, bob.writer
            ));
            Ok((alice, bob, capture))
        },
    )?;

    let first = sc.step(
        "alice shares the folder /ga/32=data/sketch (writers /ga,/gb, readers person:/ga, \
         person:/gb: sealed to both) and writes its board; both watch the folder; bob reads the \
         board",
        |cx| {
            alice.ok(cx, &format!("share_folder {FOLDER} {BOTH}"))?;
            alice.ok(cx, &format!("watch {FOLDER}"))?;
            bob.ok(cx, &format!("watch {FOLDER}"))?;
            let first = alice.put(cx, BOARD, "text=\"(empty board)\"")?;
            wait_for(cx, "bob reads the board", CONVERGE, |cx| {
                Ok(bob
                    .state(cx, BOARD)?
                    .is_some_and(|(at, v)| includes(&at, &first) && v["text"] == "(empty board)"))
            })?;
            cx.evidence(&format!(
                "alice shared {FOLDER}: {BOTH}; bob's board state includes {}",
                first.name
            ));
            Ok(first)
        },
    )?;

    let (alice_from, bob_from, bob_watch_from) = sc.step(
        "each subscribes to the folder's signals (asked again while NotReady: the record or the \
         sealed epoch's key not held yet)",
        |cx| {
            let line = format!("signal-subscribe {FOLDER}");
            for host in [&mut alice, &mut bob] {
                let mut refusals = Vec::new();
                wait_for(
                    cx,
                    &format!("{} subscribes to {FOLDER}", host.node),
                    CONVERGE,
                    |cx| match host.call(cx, &line)? {
                        Ok(_) => Ok(true),
                        Err(e) if e["retry"] == true => {
                            refusals.push(format!("{} (next: {})", e["message"], e["next"]));
                            Ok(false)
                        }
                        Err(e) => Err(format!(
                            "{}> {line}: {} (next: {})",
                            host.node, e["message"], e["next_step"]
                        )),
                    },
                )?;
                cx.evidence(&format!(
                    "{} subscribed to {FOLDER}{}",
                    host.node,
                    refusals
                        .last()
                        .map(|r| format!(" after {} NotReady, the last: {r}", refusals.len()))
                        .unwrap_or_default()
                ));
            }
            Ok((alice.signals.len(), bob.signals.len(), bob.watched.len()))
        },
    )?;

    let delivered = sc.step(
        "alice streams 120 cursor signals at 60 Hz while bob streams 120 of his: each person's \
         signals deliver the other's through the relay, none off a local ring, at most 5 % lost, \
         and the subscriber reads the last of each stream; latency p50/p99 and octets per \
         packet reported",
        |cx| {
            cx.concept("signal push through a relay");
            // Each person's counters before the streams: what they count
            // of the streams is the difference.
            let mut before = Vec::new();
            for host in [&mut alice, &mut bob] {
                before.push(stats(cx, host)?);
            }
            let line = format!("signal-stream {FOLDER} {CURSOR} {COUNT} {HZ}");
            alice.send(cx, &line)?;
            bob.send(cx, &line)?;
            let mut sent = Vec::new();
            for host in [&mut alice, &mut bob] {
                let answer = host
                    .answers(cx, &line, 1, STREAMED)?
                    .remove(0)
                    .map_err(|e| {
                        format!(
                            "{}> {line}: {} (next: {})",
                            host.node, e["message"], e["next_step"]
                        )
                    })?;
                let (Some(first), Some(last)) =
                    (answer["first_seq"].as_u64(), answer["last_seq"].as_u64())
                else {
                    return Err(format!("{}'s stream answered {answer}", host.node));
                };
                if answer["sent"] != COUNT || last - first + 1 != COUNT {
                    return Err(format!(
                        "{}'s stream sent {answer}, not {COUNT} signals in sequence",
                        host.node
                    ));
                }
                cx.evidence(&format!(
                    "{} streamed {COUNT} at {HZ} Hz: run {}, seqs {first}..={last}, {} ms",
                    host.node, answer["run"], answer["elapsed_ms"]
                ));
                sent.push((host.writer.clone(), first, last));
            }
            let (alice_writer, a_first, a_last) = sent[0].clone();
            let (bob_writer, b_first, b_last) = sent[1].clone();
            let mut latencies = Vec::new();
            // What each subscriber's reader read of the other's stream:
            // bob's of alice's, then alice's of bob's.
            let mut read = Vec::new();
            for (host, from, sender, first, last) in [
                (&mut bob, bob_from, &alice_writer, a_first, a_last),
                (&mut alice, alice_from, &bob_writer, b_first, b_last),
            ] {
                let took = host.until(
                    cx,
                    &format!("the last of {sender}'s cursor stream"),
                    STREAMED,
                    |h| received(h, from, sender, CURSOR).any(|s| s["seq"] == last),
                )?;
                let mut seqs = Vec::new();
                for s in received(host, from, sender, CURSOR) {
                    if name(s["scope"].as_str().unwrap_or_default())? != name(FOLDER)?
                        || s["local"] != false
                    {
                        return Err(format!("{} received {s}", host.node));
                    }
                    let seq = s["seq"].as_u64().ok_or_else(|| format!("no seq in {s}"))?;
                    if !(first..=last).contains(&seq) {
                        return Err(format!(
                            "{} received a seq outside the stream: {s}",
                            host.node
                        ));
                    }
                    seqs.push(seq);
                    latencies.push(
                        s["latency_us"]
                            .as_u64()
                            .ok_or_else(|| format!("no latency in {s}"))?,
                    );
                }
                seqs.sort_unstable();
                seqs.dedup();
                let unread: Vec<u64> = (first..=last)
                    .filter(|s| seqs.binary_search(s).is_err())
                    .map(|s| s - first)
                    .collect();
                cx.evidence(&format!(
                    "{}'s reader read {} of {sender}'s {COUNT} cursor signals, the last (seq \
                     {last}) {:.1} s after its stream was answered, none local; not read: n = \
                     {unread:?}",
                    host.node,
                    seqs.len(),
                    took.as_secs_f64()
                ));
                read.push(seqs.len() as u64);
            }
            latencies.sort_unstable();
            cx.evidence(&format!(
                "latency through the relay over the {} signals read (send to read, one host's \
                 clock): p50 {} µs, p99 {} µs, max {} µs",
                latencies.len(),
                percentile(&latencies, 50),
                percentile(&latencies, 99),
                latencies.last().copied().unwrap_or_default()
            ));
            let mut over = Vec::new();
            let mut delivered_to = Vec::new();
            for (host, before, read, sender) in [
                (&mut alice, &before[0], read[1], &bob_writer),
                (&mut bob, &before[1], read[0], &alice_writer),
            ] {
                let s = stats(cx, host)?;
                let delta = |k: &str| {
                    s[k].as_u64()
                        .unwrap_or_default()
                        .saturating_sub(before[k].as_u64().unwrap_or_default())
                };
                let (packets, octets, delivered) = (
                    delta("sent_packets"),
                    delta("sent_bytes"),
                    delta("delivered"),
                );
                if packets < COUNT || delivered > COUNT {
                    return Err(format!(
                        "{}'s stats over the streams: {packets} packets sent, {delivered} \
                         delivered: {s} (before: {before})",
                        host.node
                    ));
                }
                let lost = COUNT - delivered;
                delivered_to.push(delivered);
                cx.evidence(&format!(
                    "{}'s stats over the streams: {packets} packets sent (one signal each), \
                     {octets} octets of push Interests ({} per packet: one Interest into each \
                     of the {} groups, {} octets each); {delivered} of {sender}'s {COUNT} \
                     delivered to its subscriber ({lost} lost: unknown_run +{}, stale +{}, \
                     replayed +{}, expired +{}, flood +{}); its reader read {read} of them, {} \
                     superseded unread (the newest per address, never a backlog)",
                    host.node,
                    octets / packets,
                    GROUPS.len(),
                    octets / packets / GROUPS.len() as u64,
                    delta("unknown_run"),
                    delta("stale"),
                    delta("replayed"),
                    delta("expired"),
                    delta("flood"),
                    delivered.saturating_sub(read),
                ));
                if lost > MAX_LOST {
                    over.push(format!(
                        "{}'s signals delivered {delivered} of {sender}'s {COUNT} cursor \
                         signals: {lost} lost, over {MAX_LOST}",
                        host.node
                    ));
                }
            }
            if !over.is_empty() {
                return Err(over.join("; "));
            }
            Ok(delivered_to)
        },
    )?;

    sc.step(
        "the relay's capture: every signal Interest its daemon gave it — in each group at least \
         as many as that group's member delivered of the other's stream — decodes as \
         SignalSealed and holds no folder name, device or key name, address or payload text",
        |cx| {
            cx.concept("sealed signals in transit");
            // Alice's counters came first, then bob's: alice's group
            // carries bob's stream to her, bob's group alice's to him.
            for (group, member, need) in [
                (GROUPS[0], "alice", delivered[0]),
                (GROUPS[1], "bob", delivered[1]),
            ] {
                let took = capture.until(
                    cx,
                    &format!("{need} signal Interests captured in {group}"),
                    STREAMED,
                    |c| captured(c, group).count() as u64 >= need,
                )?;
                cx.evidence(&format!(
                    "{group} ({member}'s group): {} Interests captured on the relay, at least \
                     the {need} signals {member} delivered ({:.1} s)",
                    captured(&capture, group).count(),
                    took.as_secs_f64()
                ));
            }
            capture.drain(cx, QUIET)?;
            let plain: Vec<(String, Vec<u8>)> = [
                (FOLDER, true),
                (alice_root.identity.as_str(), true),
                (bob_root.identity.as_str(), true),
                (alice.writer.as_str(), true),
                (bob.writer.as_str(), true),
                (CURSOR, false),
                ("sent_us=", false),
                (DRAFTS[0], false),
            ]
            .into_iter()
            .map(|(p, is_name)| {
                Ok((
                    p.to_owned(),
                    if is_name {
                        name(p)?.encode_to_tlv().to_vec()
                    } else {
                        p.as_bytes().to_vec()
                    },
                ))
            })
            .collect::<StepResult<_>>()?;
            let mut octets = Vec::new();
            for c in captured(&capture, GROUPS[0]).chain(captured(&capture, GROUPS[1])) {
                if c["decodes_as"] != "SignalSealed" || c["digest_ok"] != true {
                    return Err(format!("the relay captured {c}"));
                }
                let params = unhex(c["params_hex"].as_str().unwrap_or_default())?;
                if let Some((p, _)) = plain
                    .iter()
                    .find(|(_, b)| params.windows(b.len()).any(|w| w == b.as_slice()))
                {
                    return Err(format!(
                        "{} as the relay captured it holds {p:?}",
                        c["name"]
                    ));
                }
                octets.push(params.len() as u64);
            }
            let total: u64 = octets.iter().sum();
            cx.evidence(&format!(
                "the relay captured {} signal Interests ({} in {}, {} in {}), every one \
                 SignalSealed (a key id, e.g. {}, a nonce, a ciphertext) with its digest; \
                 {} octets of parameters each on average ({}..={}); none holds any of {:?}",
                octets.len(),
                captured(&capture, GROUPS[0]).count(),
                GROUPS[0],
                captured(&capture, GROUPS[1]).count(),
                GROUPS[1],
                captured(&capture, GROUPS[1])
                    .next()
                    .map(|c| c["key_id"].clone())
                    .unwrap_or_default(),
                total / octets.len().max(1) as u64,
                octets.iter().min().copied().unwrap_or_default(),
                octets.iter().max().copied().unwrap_or_default(),
                plain.iter().map(|(p, _)| p).collect::<Vec<_>>()
            ));
            Ok(())
        },
    )?;

    sc.step(
        "no content store holds a signal: on the relay's, alice's and bob's daemons an erase of \
         the pushes' prefixes and of the folder's run headers' erases nothing; neither person's \
         store holds an entry with a 32=signal component",
        |cx| {
            cx.concept("signals are never cached or stored");
            let prefixes = [
                format!("{}/32=signal", GROUPS[0]),
                format!("{}/32=signal", GROUPS[1]),
                format!("{FOLDER}/32=signal"),
            ];
            for node in ["relay", "alice", "bob"] {
                for prefix in &prefixes {
                    let out = erase_cs(cx, node, prefix)?;
                    let count = out
                        .lines()
                        .find_map(|l| l.trim().strip_prefix("count:"))
                        .map(str::trim);
                    if count != Some("0") {
                        return Err(format!("{node}: cs erase {prefix}: {out}"));
                    }
                }
                cx.evidence(&format!("{node}: cs erase of {prefixes:?}: count 0 each"));
            }
            let keyword = signal_keyword();
            for node in ["alice", "bob"] {
                let dir = cx.w.node(node).dir.join("data-store");
                let entries = stored(&dir)?;
                if let Some((n, path)) = entries
                    .iter()
                    .find(|(n, _)| n.components().contains(&keyword))
                {
                    return Err(format!("{node}'s store holds {n} ({})", path.display()));
                }
                if entries.is_empty() {
                    return Err(format!("{node}'s store {} holds nothing", dir.display()));
                }
                cx.evidence(&format!(
                    "{node}'s store {}: {} entries, none named with 32=signal",
                    dir.display(),
                    entries.len()
                ));
            }
            Ok(())
        },
    )?;

    sc.step(
        "alice's live text — three drafts as signals — reaches bob as the newest; no version \
         came of any signal; alice commits the text with one put (her next sequence) and bob's \
         watch delivers exactly one new version, his board the committed text",
        |cx| {
            cx.concept("commit: live work becomes a version through put");
            for draft in DRAFTS {
                alice.ok(cx, &format!("signal-send {FOLDER} {TEXT} \"{draft}\""))?;
            }
            let newest = DRAFTS[DRAFTS.len() - 1];
            let alice_writer = alice.writer.clone();
            bob.until(cx, "bob receives alice's newest draft", STREAMED, |h| {
                received(h, bob_from, &alice_writer, TEXT).any(|s| s["payload"] == newest)
            })?;
            let drafts: Vec<String> = received(&bob, bob_from, &alice_writer, TEXT)
                .map(|s| s["payload"].as_str().unwrap_or_default().to_owned())
                .collect();
            bob.drain(cx, QUIET)?;
            let during = versions_since(&bob, bob_watch_from);
            if !during.is_empty() {
                return Err(format!(
                    "bob's watch delivered versions while signals flowed: {during:?}"
                ));
            }
            cx.evidence(&format!(
                "bob received alice's drafts {drafts:?} (the newest per address); his watch \
                 delivered no version since he subscribed"
            ));
            let mark = bob.watched.len();
            let commit = alice.put(cx, BOARD, &format!("{TEXT}=\"{newest}\""))?;
            if commit.seq != first.seq + 1 {
                return Err(format!(
                    "alice's commit is seq {}, not {} (her version after the board's first)",
                    commit.seq,
                    first.seq + 1
                ));
            }
            wait_for(cx, "bob reads the committed text", CONVERGE, |cx| {
                Ok(bob
                    .state(cx, BOARD)?
                    .is_some_and(|(at, v)| includes(&at, &commit) && v[TEXT] == newest))
            })?;
            bob.watched_until(cx, "the commit in bob's watch", CONVERGE, |w| {
                is_version(w, &commit)
            })?;
            bob.drain(cx, QUIET)?;
            let new = versions_since(&bob, mark);
            if new.len() != 1 {
                return Err(format!(
                    "bob's watch delivered {} versions after the commit: {new:?}",
                    new.len()
                ));
            }
            cx.evidence(&format!(
                "alice committed {} ({TEXT}={newest:?}); bob's watch delivered exactly that one \
                 version, his board state includes it with {TEXT} = {newest:?}",
                commit.name
            ));
            Ok(())
        },
    )?;
    Ok(())
}

/// The watched change is version `v`.
fn is_version(w: &Value, v: &Put) -> bool {
    name(w["change"]["version"]["name"].as_str().unwrap_or_default()).ok() == name(&v.name).ok()
}
