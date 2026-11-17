//! events: the device-wide events a device keeps whether or not anything
//! watches — a writer removed from a collection (a cut) and the version the
//! cut withdraws — delivered at least once, kept across a restart until
//! acknowledged (data-layer spec §21) on real daemons.
//!
//! Topology and enrollment as in [`super::trio`]: laptop (the owner of /ev),
//! tab and phone, each its own daemon and its own `ndn-data` host; the tab's
//! keeps its entries in a store directory too (`--store`), as a phone keeps
//! its data on its disk. Nobody watches anything: no `watch` is sent to any
//! host.
//!
//! Proves: the laptop shares the notes (writers the laptop, the tab and the
//! phone; no readers: unsealed), the phone writes a note both others hold;
//! no device has an event. Apart — nftables drops UDP between the laptop and
//! each of the tab and the phone, the tab and the phone still hear each other
//! — the phone writes a second note, which the tab holds, and the laptop,
//! which has not seen it, removes the phone as a writer (a cut bounded by what
//! it has seen: the first note). Once the links are back, the tab's `events`
//! lists, with nobody watching, a cut event (the key prefix removed, the
//! signer and the record it signed, the notes it concerns and how many
//! versions the cut keeps, with what to do and why in words) and a withdrawal
//! event for the second note (its full name and digest, withdrawn by the cut,
//! ask the owner); the phone, the removed writer, reports the same cut event
//! under the same id; the laptop, which signed the cut itself, reports none.
//! The tab's host stopped and started again on the same store, before any
//! acknowledgement, delivers the same events with the same ids and cursors;
//! `events <cursor>` shows only the later ones. `ack` of an unknown id is
//! refused with a reason, together with a known one it changes nothing (the
//! whole call is refused); `ack` of the known ones empties the list, accepts
//! the same ids again with no effect and, after another restart, nothing is
//! delivered again while the tab still holds the first note and not the
//! second.

use std::process::Command;

use serde_json::Value;

use super::data_host::{CONVERGE, Host, Put, includes, name, unanswered};
use super::trio::{self, LAPTOP_HOST, PHONE_HOST, TAB_HOST};
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::addr;

const NS: &str = "/ev";
const NOTES: &str = "/ev/32=data/notes/trip";
/// Who writes the notes before the phone is removed, and after.
const THREE: &str = "writers=/ev/admin,/ev/member/tab,/ev/member/phone readers=";
const TWO: &str = "writers=/ev/admin,/ev/member/tab readers=";
/// The key prefix the owner removes.
const PHONE_PREFIX: &str = "/ev/member/phone";

/// The nftables tables that keep the laptop from the tab and the phone.
const CUT_LAPTOP_TAB: &str = "ndn_e2e_events_laptop_tab";
const CUT_LAPTOP_PHONE: &str = "ndn_e2e_events_laptop_phone";

/// `host`'s unacknowledged events with a cursor above `after`, and the
/// highest cursor the answer shows (`after` when it shows none).
fn events(cx: &mut Cx<'_>, host: &mut Host, after: u64) -> StepResult<(Vec<Value>, u64)> {
    let line = if after == 0 {
        "events".to_owned()
    } else {
        format!("events {after}")
    };
    let ok = host.ok(cx, &line)?;
    let list = ok["events"]
        .as_array()
        .cloned()
        .ok_or_else(|| format!("{}: no events in {ok}", host.node))?;
    Ok((list, ok["cursor"].as_u64().unwrap_or(after)))
}

fn of_kind<'a>(events: &'a [Value], kind: &str) -> Vec<&'a Value> {
    events.iter().filter(|e| e["kind"] == kind).collect()
}

/// The `(id, cursor)` of each event.
fn identities(events: &[Value]) -> Vec<(String, u64)> {
    events
        .iter()
        .map(|e| {
            (
                e["id"].as_str().unwrap_or_default().to_owned(),
                e["cursor"].as_u64().unwrap_or_default(),
            )
        })
        .collect()
}

/// An event says what it is in words: what to do and why, and the class of
/// next step.
fn explained(e: &Value) -> StepResult<()> {
    for field in ["what_to_do", "why", "next_step"] {
        if e[field].as_str().is_none_or(str::is_empty) {
            return Err(format!("the event has no {field}: {e}"));
        }
    }
    if e["id"].as_str().is_none_or(|id| id.len() != 32) || e["count"].as_u64() < Some(1) {
        return Err(format!("the event has no 32-digit id or no count: {e}"));
    }
    Ok(())
}

/// `host`'s cut event for the removal of the phone by the laptop's key
/// `signer`, from `events`: the key prefix removed, the signer and the record
/// it signed, the notes it concerns.
fn cut_event<'a>(events: &'a [Value], signer: &str) -> StepResult<&'a Value> {
    let cuts = of_kind(events, "cut");
    let [cut] = cuts.as_slice() else {
        return Err(format!("expected one cut event, got {cuts:?}"));
    };
    let d = &cut["detail"];
    explained(cut)?;
    let record = name(d["record"].as_str().unwrap_or_default())?;
    let owned = [
        name(d["of"].as_str().unwrap_or_default())? == name(PHONE_PREFIX)?,
        cut["subject"]["writer"] == d["of"],
        name(d["subject"].as_str().unwrap_or_default())? == name(NOTES)?,
        d["folder"] == false,
        d["signer"] == signer,
        record.has_prefix(&name(&format!("{}/32=log{NOTES}", signer_device(signer)?))?),
        cut["evidence"].as_array().is_some_and(|names| {
            names
                .iter()
                .any(|n| n == d["record"].as_str().unwrap_or(""))
        }),
        cut["meaning"] == "writer-cut",
        cut["next"] == "none",
    ];
    if owned.iter().any(|ok| !ok) {
        return Err(format!(
            "the cut event is not the laptop's removal of {PHONE_PREFIX} from {NOTES} ({owned:?}): \
             {cut}"
        ));
    }
    Ok(cut)
}

/// The device a key name `<device>/KEY/<id>` belongs to.
fn signer_device(key: &str) -> StepResult<String> {
    key.split_once("/KEY/")
        .map(|(device, _)| device.to_owned())
        .ok_or_else(|| format!("{key} is no key name"))
}

/// The withdrawal event for `v` in `events`: its full name with digest,
/// withdrawn by the cut of the phone's prefix the laptop `signer` signed.
fn withdrawal_event<'a>(events: &'a [Value], v: &Put, signer: &str) -> StepResult<&'a Value> {
    let found = of_kind(events, "withdrawal");
    let [w] = found.as_slice() else {
        return Err(format!("expected one withdrawal event, got {found:?}"));
    };
    explained(w)?;
    let d = &w["detail"];
    let cut = &d["by"]["cut"];
    let digest = d["entry"]["digest"].as_str().unwrap_or_default();
    let owned = [
        name(d["entry"]["name"].as_str().unwrap_or_default())? == name(&v.name)?,
        digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
        d["writer"] == v.writer.as_str(),
        w["subject"]["writer"] == v.writer.as_str(),
        name(cut["of"].as_str().unwrap_or_default())?.has_prefix(&name(PHONE_PREFIX)?)
            || name(&v.writer)?.has_prefix(&name(cut["of"].as_str().unwrap_or_default())?),
        cut["signer"] == signer,
        w["meaning"] == "withdrawn",
        w["next"] == "ask-owner",
    ];
    if owned.iter().any(|ok| !ok) {
        return Err(format!(
            "the withdrawal event is not the cut's withdrawal of {} ({owned:?}): {w}",
            v.name
        ));
    }
    Ok(w)
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    let root = trio::start(sc, NS)?;
    let tab_device = trio::tab(NS);
    let phone_device = trio::phone(NS);
    let tab_store = sc.world.node("tab").dir.join("data-store");
    let tab_options = vec!["--store".to_owned(), tab_store.display().to_string()];

    let (mut laptop, mut tab, mut phone) = sc.step(
        "start the data layer on each device; the tab's keeps its entries on its disk too",
        |cx| {
            cx.concept("data layer host (ndn-data)");
            let laptop = Host::start(cx, "laptop", &root.identity)?;
            let tab = Host::start_with(cx, "tab", &tab_device, &tab_options)?;
            let phone = Host::start(cx, "phone", &phone_device)?;
            Ok((laptop, tab, phone))
        },
    )?;
    let laptop_key = laptop.writer.clone();

    let (n1, day1) = sc.step(
        "the laptop shares the notes with the three devices as writers and writes day 1; the \
         phone writes a note; every device holds both, and none has an event",
        |cx| {
            laptop.ok(cx, &format!("share {NOTES} {THREE}"))?;
            let day1 = laptop.put(cx, NOTES, "text=\"day 1\"")?;
            wait_for(cx, "the phone holds day 1", SHORT, |cx| {
                Ok(phone
                    .state(cx, NOTES)?
                    .is_some_and(|(at, _)| includes(&at, &day1)))
            })?;
            let n1 = phone.put(cx, NOTES, "text=\"flight at nine\"")?;
            for host in [&mut laptop, &mut tab, &mut phone] {
                wait_for(
                    cx,
                    &format!("{} holds day 1 and the phone's note", host.node),
                    CONVERGE,
                    |cx| {
                        Ok(host
                            .state(cx, NOTES)?
                            .is_some_and(|(at, _)| includes(&at, &day1) && includes(&at, &n1)))
                    },
                )?;
                let (list, _) = events(cx, host, 0)?;
                if !list.is_empty() {
                    return Err(format!("{} has events already: {list:?}", host.node));
                }
            }
            cx.evidence(&format!(
                "laptop, tab and phone hold {} and {}; none has an event",
                day1.name, n1.name
            ));
            Ok((n1, day1))
        },
    )?;

    if !crate::works(Command::new("nft").arg("--version")) {
        sc.skip(
            "take the laptop apart, remove the phone as a writer, read the events",
            "nft (nftables) not on PATH; run inside `nix-shell -p util-linux iproute2 nftables`",
        );
        return Ok(());
    }
    let cuts = sc.step(
        "apart: nftables drops UDP between the laptop and the tab and between the laptop and \
         the phone; the tab and the phone still hear each other",
        |cx| {
            let a = cut_udp(cx, CUT_LAPTOP_TAB, addr(LAPTOP_HOST), addr(TAB_HOST))?;
            let b = cut_udp(cx, CUT_LAPTOP_PHONE, addr(LAPTOP_HOST), addr(PHONE_HOST))?;
            Ok((a, b))
        },
    )?;
    let n2 = sc.step(
        "the phone writes a second note, which the tab holds and the laptop does not",
        |cx| {
            let n2 = phone.put(cx, NOTES, "text=\"written apart from the laptop\"")?;
            wait_for(cx, "the tab holds the second note", CONVERGE, |cx| {
                Ok(tab
                    .state(cx, NOTES)?
                    .is_some_and(|(at, _)| includes(&at, &n2)))
            })?;
            unanswered(cx, "laptop", &n2.name)?;
            cx.evidence(&format!(
                "the tab holds {}; the laptop's daemon fetches none of it",
                n2.name
            ));
            Ok(n2)
        },
    )?;
    sc.step(
        "the laptop removes the phone as a writer of the notes: a cut at what it has seen of \
         the phone's key; it reports no event of its own cut",
        |cx| {
            laptop.ok(cx, &format!("share {NOTES} {TWO}"))?;
            let members = laptop.ok(cx, &format!("members {NOTES}"))?;
            let writers = members["members"]["writers"].to_string();
            if writers.contains("phone") {
                return Err(format!(
                    "the laptop's record still lists the phone: {writers}"
                ));
            }
            let (list, _) = events(cx, &mut laptop, 0)?;
            if !of_kind(&list, "cut").is_empty() {
                return Err(format!(
                    "the laptop reports the cut it signed itself: {list:?}"
                ));
            }
            cx.evidence(&format!("laptop members: {}", members["members"]));
            Ok(())
        },
    )?;
    let cut_cursor = sc.step(
        "the links are back: with nobody watching, the tab's events list the cut (what to do, \
         why) and the second note's withdrawal; the phone reports the same cut under the same \
         id; the laptop reports none",
        |cx| {
            drop(cuts);
            let mut seen = Vec::new();
            wait_for(
                cx,
                "the tab lists a cut event and a withdrawal event",
                CONVERGE,
                |cx| {
                    seen = events(cx, &mut tab, 0)?.0;
                    Ok(!of_kind(&seen, "cut").is_empty()
                        && !of_kind(&seen, "withdrawal").is_empty())
                },
            )?;
            let cut = cut_event(&seen, &laptop_key)?;
            let withdrawal = withdrawal_event(&seen, &n2, &laptop_key)?;
            let kept = cut["detail"]["kept"].as_u64().unwrap_or_default();
            if kept != 1 {
                return Err(format!(
                    "the cut keeps {kept} of the phone's versions, expected 1 (the first note, \
                     which the laptop had seen): {cut}"
                ));
            }
            if seen.len() != 2 {
                return Err(format!("the tab lists more than the two events: {seen:?}"));
            }
            if !tab.watched.is_empty() {
                return Err(format!("the tab watched something: {:?}", tab.watched));
            }
            cx.evidence(&format!(
                "tab event cut: id {} cursor {} subject {} evidence {} kept {}; what to do: {}; \
                 why: {}",
                cut["id"],
                cut["cursor"],
                cut["subject"],
                cut["evidence"],
                kept,
                cut["what_to_do"],
                cut["why"]
            ));
            cx.evidence(&format!(
                "tab event withdrawal: id {} subject {} entry {} by {}; next {}; what to do: {}",
                withdrawal["id"],
                withdrawal["subject"],
                withdrawal["detail"]["entry"],
                withdrawal["detail"]["by"],
                withdrawal["next"],
                withdrawal["what_to_do"]
            ));
            // The phone, the removed writer, is a second device that receives
            // the record.
            let mut theirs = Vec::new();
            wait_for(cx, "the phone lists the cut event", CONVERGE, |cx| {
                theirs = events(cx, &mut phone, 0)?.0;
                Ok(!of_kind(&theirs, "cut").is_empty())
            })?;
            let phone_cut = cut_event(&theirs, &laptop_key)?;
            if phone_cut["id"] != cut["id"] {
                return Err(format!(
                    "the phone's cut event has id {}, the tab's {}: devices that derive the \
                     same evidence share its id\n  phone: {phone_cut}\n  tab: {cut}",
                    phone_cut["id"], cut["id"]
                ));
            }
            cx.evidence(&format!(
                "phone event cut: the same id {} (cursor {} there, {} at the tab)",
                phone_cut["id"], phone_cut["cursor"], cut["cursor"]
            ));
            let (own, _) = events(cx, &mut laptop, 0)?;
            if !of_kind(&own, "cut").is_empty() || !of_kind(&own, "withdrawal").is_empty() {
                return Err(format!("the laptop reports events of its own cut: {own:?}"));
            }
            cx.evidence(
                "the laptop, which signed the cut and never held the second note, has no event",
            );
            // What the events report was done before they were told.
            let refused = tab.call(cx, &format!("get {}", n2.name))?;
            match refused {
                Err(e) if e["next"] == "ask-owner" && e["outside_cut"].is_object() => {
                    cx.evidence(&format!(
                        "tab get {}: refused outside the cut ({})",
                        n2.name, e["outside_cut"]
                    ));
                }
                other => {
                    return Err(format!(
                        "the tab does not refuse the withdrawn {} outside the cut: {other:?}",
                        n2.name
                    ));
                }
            }
            Ok(cut["cursor"].as_u64().unwrap_or_default())
        },
    )?;

    let before = sc.step(
        "the tab's host stopped and started again on the same store, before any \
         acknowledgement, delivers the same events with the same ids and cursors; `events \
         <cursor>` shows only the later ones",
        |cx| {
            let (list, cursor) = events(cx, &mut tab, 0)?;
            let before = identities(&list);
            tab.stop(cx);
            tab = Host::start_with(cx, "tab", &tab_device, &tab_options)?;
            let mut again = Vec::new();
            wait_for(cx, "the restarted tab lists its events", SHORT, |cx| {
                again = identities(&events(cx, &mut tab, 0)?.0);
                Ok(!again.is_empty())
            })?;
            if again != before {
                return Err(format!(
                    "the restarted tab lists {again:?}, before the restart {before:?}"
                ));
            }
            if !tab.watched.is_empty() {
                return Err(format!("the tab watched something: {:?}", tab.watched));
            }
            let (later, ends) = events(cx, &mut tab, cut_cursor)?;
            let expected: Vec<_> = before.iter().filter(|(_, c)| *c > cut_cursor).collect();
            if identities(&later).iter().collect::<Vec<_>>() != expected || ends != cursor {
                return Err(format!(
                    "events after cursor {cut_cursor} are {later:?} (ending at {ends}); expected \
                     {expected:?} (ending at {cursor})"
                ));
            }
            cx.evidence(&format!(
                "after the restart the tab lists {again:?}, as before; events {cut_cursor} lists \
                 {} of them",
                later.len()
            ));
            Ok(before)
        },
    )?;

    sc.step(
        "`ack` of an unknown id is refused with a reason, and with a known id beside it changes \
         nothing; `ack` of the known ids empties the list and takes the same ids again",
        |cx| {
            let unknown = "00000000000000000000000000000000";
            let known: Vec<&str> = before.iter().map(|(id, _)| id.as_str()).collect();
            let refused = tab
                .call(cx, &format!("ack {unknown}"))?
                .err()
                .ok_or_else(|| format!("the tab acknowledged the unknown id {unknown}"))?;
            let message = refused["message"].as_str().unwrap_or_default();
            if !message.contains(unknown)
                || refused["next"] != "fix-request"
                || refused["retry"] != false
                || refused["next_step"].as_str().is_none_or(str::is_empty)
            {
                return Err(format!(
                    "the refusal of an unknown id names no id, or no way on: {refused}"
                ));
            }
            cx.evidence(&format!(
                "tab ack {unknown}: {} (next: {})",
                refused["message"], refused["next_step"]
            ));
            let mixed = format!("ack {} {unknown}", known[0]);
            if tab.call(cx, &mixed)?.is_ok() {
                return Err(format!("the tab took a call with an unknown id: {mixed}"));
            }
            let (still, _) = events(cx, &mut tab, 0)?;
            if identities(&still) != before {
                return Err(format!(
                    "a refused ack changed the events: {:?}, before {before:?}",
                    identities(&still)
                ));
            }
            let ok = tab.ok(cx, &format!("ack {}", known.join(" ")))?;
            let (none, _) = events(cx, &mut tab, 0)?;
            if !none.is_empty() {
                return Err(format!("events remain after the acknowledgement: {none:?}"));
            }
            tab.ok(cx, &format!("ack {}", known.join(" ")))?;
            cx.evidence(&format!(
                "tab ack {} → {ok}; no events remain; the same ids again are accepted",
                known.join(" ")
            ));
            Ok(())
        },
    )?;

    sc.step(
        "after another restart the acknowledged events are gone, while the tab holds the first \
         note and not the withdrawn one",
        |cx| {
            tab.stop(cx);
            tab = Host::start_with(cx, "tab", &tab_device, &tab_options)?;
            wait_for(
                cx,
                "the restarted tab reads the notes again, the first and not the second",
                CONVERGE,
                |cx| {
                    Ok(tab
                        .state(cx, NOTES)?
                        .is_some_and(|(at, _)| includes(&at, &day1) && includes(&at, &n1)))
                },
            )?;
            let (at, _) = tab
                .state(cx, NOTES)?
                .ok_or_else(|| "the tab reads no notes".to_owned())?;
            if includes(&at, &n2) {
                return Err(format!(
                    "the restarted tab counts the withdrawn {}",
                    n2.name
                ));
            }
            let (list, _) = events(cx, &mut tab, 0)?;
            if !list.is_empty() {
                return Err(format!(
                    "the restarted tab delivers acknowledged events again: {list:?}"
                ));
            }
            cx.evidence(&format!(
                "the restarted tab counts {} and {} and not {}; no event is delivered",
                day1.name, n1.name, n2.name
            ));
            Ok(())
        },
    )?;
    Ok(())
}
