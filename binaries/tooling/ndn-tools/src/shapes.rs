//! The JSON the host prints: ids, items, members, changes, alerts, the items and notices of a
//! `get`, channel evidence and errors (the shapes the module doc of `heap.rs` lists).

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use ndn_heap::{
    Alert, Change, ChannelEvidence, EmitError, EntryId, GetNotice, Got, HeapError, Item, Kind,
    LiveEnd, Members, NextStep, Readers, Refusal,
};
use ndn_invite::{IntroRefusal, InviteError, Role};
use ndn_security::RevocationCut;

/// Octets written as hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Values longer than this are shown by digest, not bytes.
const SHOWN_MAX: usize = 256;

/// An entry's id: `{"device","seq","digest"}`.
pub fn id(id: &EntryId) -> Value {
    json!({"device": id.device.to_string(), "seq": id.seq, "digest": hex(&id.digest)})
}

/// A value's octets as an item shows them: `len`, and `text` when they are
/// UTF-8 and at most [`SHOWN_MAX`] octets, `hex` when they are not, `sha256`
/// alone when they are longer.
pub fn value_fields(bytes: &[u8], into: &mut Map<String, Value>) {
    into.insert("len".into(), json!(bytes.len()));
    if bytes.len() > SHOWN_MAX {
        into.insert("sha256".into(), json!(hex(&Sha256::digest(bytes))));
    } else {
        match std::str::from_utf8(bytes) {
            Ok(text) => into.insert("text".into(), json!(text)),
            Err(_) => into.insert("hex".into(), json!(hex(bytes))),
        };
    }
}

/// An item: `{"path","by","writer","id","len"}` and the value.
pub fn item(i: &Item) -> Value {
    let mut m = Map::new();
    m.insert("path".into(), json!(i.path.to_string()));
    m.insert("by".into(), json!(i.by.to_string()));
    m.insert("writer".into(), json!(i.writer.to_string()));
    m.insert("id".into(), id(&i.id));
    value_fields(&i.bytes, &mut m);
    Value::Object(m)
}

/// A space's members: `{"owner","writers","readers"}`, readers `"anyone"` or
/// the persons.
pub fn members(m: &Members) -> Value {
    json!({
        "owner": m.owner.to_string(),
        "writers": m.writers.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "readers": match &m.readers {
            Readers::Anyone => json!("anyone"),
            Readers::Persons(persons) => {
                json!(persons.iter().map(ToString::to_string).collect::<Vec<_>>())
            }
        },
    })
}

/// A role as the lines name it.
pub fn role_word(role: Role) -> &'static str {
    match role {
        Role::Reader => "reader",
        Role::Writer => "writer",
    }
}

/// What a watch tells of a change.
pub fn change(c: &Change) -> Value {
    match c {
        Change::Put(i) => json!({"put": item(i)}),
        Change::Removed(i) => json!({"removed": item(i)}),
        Change::Withdrawn { id: i, why } => json!({ "withdrawn": withdrawal(i, why) }),
        Change::Members(m) => json!({"members": members(m)}),
        Change::Alert(a) => json!({"alert": alert(a)}),
        Change::Lagged { missed } => json!({"lagged": {
            "missed": missed,
            "what_to_do": "changes were dropped while this watch was behind; it lists the \
                           heads again from the start"
        }}),
    }
}

/// An entry refused after the fact: `{"id","why"}` and, by cause, `cut_of` (the device cut) and
/// `keeps_to` (the seq its tip keeps) when a revocation's cut withdrew it, or `untrusted` when
/// the durable rule refused its issuer.
fn withdrawal(i: &EntryId, why: &Refusal) -> Value {
    let mut w = json!({"id": id(i), "why": why.to_string()});
    match why {
        Refusal::OutsideCut(cut) => {
            w["cut_of"] = json!(cut.device.to_string());
            w["keeps_to"] = json!(cut.keeps_to);
        }
        // An issuer refused by the durable rule: never re-admitted.
        Refusal::Untrusted { .. } => w["untrusted"] = json!(true),
        _ => {}
    }
    w
}

/// An item of a `get`: `{"path","by","writer","kind"}` and the value as an item shows it
/// (`len`, `text`/`hex`/`sha256`); a kept one adds `id`, `as_of_ms` and `removed`, an emitted one
/// `seq`, `stands_ms` and `verified` (whether a signed checkpoint of the sender listed the frame
/// before it was given: `false` for a `Prompt` get, `true` for `--verified`).
pub fn got(g: &Got) -> Value {
    let mut m = Map::new();
    m.insert("path".into(), json!(g.path.to_string()));
    m.insert("by".into(), json!(g.by.to_string()));
    m.insert("writer".into(), json!(g.writer.to_string()));
    match &g.kind {
        Kind::Kept(k) => {
            m.insert("kind".into(), json!("kept"));
            m.insert("id".into(), id(&k.id));
            m.insert("as_of_ms".into(), json!(k.as_of.map(millis)));
            m.insert("removed".into(), json!(k.removed));
        }
        Kind::Emitted(e) => {
            m.insert("kind".into(), json!("emitted"));
            m.insert("seq".into(), json!(e.seq));
            m.insert("stands_ms".into(), json!(e.stands.map(millis)));
            m.insert("verified".into(), json!(e.verified));
        }
        other => {
            m.insert("kind".into(), json!("other"));
            m.insert("debug".into(), json!(format!("{other:?}")));
        }
    }
    value_fields(&g.bytes, &mut m);
    Value::Object(m)
}

/// A duration as whole milliseconds.
fn millis(d: std::time::Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// What a `get` tells besides items: `{"kind","what_to_do",…}`.
pub fn notice(n: &GetNotice) -> Value {
    match n {
        GetNotice::Lagged { missed } => json!({
            "kind": "lagged",
            "missed": missed,
            "what_to_do": "the mode dropped this many emissions (or the sequence has a gap): they \
                           are gone; a slow reader of kept values is never told this, it is \
                           given the current values again",
        }),
        GetNotice::Withdrawn { id: i, why } => {
            let mut v = withdrawal(i, why);
            v["kind"] = json!("withdrawn");
            v["what_to_do"] = json!(
                "an entry this get delivered was refused after the fact: the value that stands \
                 is the one that follows, or none (a kept item with removed set) when the path \
                 has no head left"
            );
            v
        }
        GetNotice::LiveEnded(end) => {
            let (kind, why, who) = match end {
                LiveEnd::Ended { writer, reason } => {
                    ("ended", reason.to_string(), Some(writer.to_string()))
                }
                LiveEnd::NoPath { why } => ("no-path", why.clone(), None),
            };
            let mut v = json!({
                "kind": "live-ended",
                "end": kind,
                "why": why,
                "next": next_token(end.next()),
                "what_to_do": "the live part of this get ended and its kept part goes on; get \
                               again when the live part is wanted",
            });
            if let Some(writer) = who {
                v["writer"] = json!(writer);
            }
            v
        }
        GetNotice::KeptEnded { why } => json!({
            "kind": "kept-ended",
            "why": why,
            "what_to_do": "the kept part of this get ended and gives nothing more, while its live \
                           part goes on: get again; it either goes on or is refused with the \
                           same reason, which says what to do",
        }),
        GetNotice::Retracted { writer, from, to } => json!({
            "kind": "retracted",
            "writer": writer.to_string(),
            "from": from,
            "to": to,
            "what_to_do": "a signed checkpoint contradicts these emissions: discard what this get \
                           delivered from this writer with an emitted seq from `from` to `to`",
        }),
    }
}

/// One piece of channel evidence: `{"kind","channel","sender","key_epoch","seq0","ingress",
/// "when_ms"}`, the channel id in hex and the face the frame came over.
pub fn evidence(e: &ChannelEvidence) -> Value {
    json!({
        "kind": format!("{:?}", e.kind),
        "channel": format!("{:016x}", e.channel),
        "sender": e.sender.to_string(),
        "key_epoch": e.key_epoch,
        "seq0": e.seq0,
        "ingress": e.ingress.0,
        "when_ms": e.when.0,
    })
}

/// What the host should know of a space.
fn alert(a: &Alert) -> Value {
    match a {
        Alert::Equivocation { device, seq } => {
            json!({"kind": "equivocation", "device": device.to_string(), "seq": seq})
        }
        Alert::OutsideCut { id: i } => json!({"kind": "outside-cut", "id": id(i)}),
        Alert::Refused { id: i, why, next } => json!({
            "kind": "refused",
            "id": id(i),
            "why": why.to_string(),
            "next": next_token(*next),
        }),
        Alert::RolledBack { reserved, seen } => {
            json!({"kind": "rolled-back", "reserved": reserved, "seen": seen})
        }
        Alert::GapSigned { after, resumed } => {
            json!({"kind": "gap-signed", "after": after, "resumed": resumed})
        }
        Alert::UnbackedCounter { device, seen } => {
            json!({"kind": "unbacked-counter", "device": device.to_string(), "seen": seen})
        }
        Alert::StoreFailed { why } => json!({"kind": "store-failed", "why": why}),
        Alert::ChannelForgery {
            writer,
            channel,
            key_epoch,
            seq,
            via,
        } => json!({
            "kind": "channel-forgery",
            "writer": writer.to_string(),
            "channel": format!("{channel:016x}"),
            "key_epoch": key_epoch,
            "seq": seq,
            "via": via.0,
            "what_to_do": "a frame of this channel is not the one its sender sent (the sender's \
                           signed checkpoint contradicts it): a holder of the channel key made \
                           it. The node asked its forwarder to bar the face it came over \
                           (`via`) from channel frames, but this alert does not say it did: \
                           the forwarder refuses the node's own face and a face it does not \
                           hold, and a node with no IngressBar attached asks nothing (the \
                           node's log says which: `barred for N s`, `could not be barred`, or \
                           `NOT barred`). Look at that link, bar it at the forwarder if it is \
                           not barred, and remove the member that holds the key if it is not \
                           expected",
        }),
        Alert::ChannelCheckpoint {
            writer,
            channel,
            key_epoch,
            via,
        } => json!({
            "kind": "channel-checkpoint",
            "writer": writer.to_string(),
            "channel": format!("{channel:016x}"),
            "key_epoch": key_epoch,
            "via": via.0,
            "what_to_do": "a checkpoint of this channel opened under the channel key and was \
                           not signed by the sender: a holder of the key made it, and the \
                           session was dropped. The node asked its forwarder to bar the face \
                           it came over (`via`) from channel frames, but this alert does not \
                           say it did (see the node's log: `barred for N s`, `could not be \
                           barred`, or `NOT barred` with no IngressBar attached); bar that \
                           link at the forwarder if it is not barred, and ask the sender \
                           again once that link is dealt with",
        }),
    }
}

/// The error answer of a line this tool cannot read.
pub fn usage_error(verb: &str, why: &str) -> Value {
    json!({"verb": verb, "error": {
        "message": why,
        "retry": false,
        "next": "fix-command",
        "next_step": "correct the line and send it again",
    }})
}

fn error(message: String, retry: bool, next: NextStep) -> Value {
    json!({
        "message": message,
        "retry": retry,
        "next": next_token(next),
        "next_step": next_step(next),
    })
}

/// A data-layer error as an error answer: why, whether to ask again, what to
/// do next, and by cause `outside_cut`, `suspected` or `untrusted`.
pub fn heap_error(e: &HeapError) -> Value {
    let mut v = error(e.to_string(), e.retry(), e.next());
    if let HeapError::Refused { why, .. } = e {
        refusal(&mut v, why);
    }
    v
}

/// What an `emit` answer says of delivery, as `{"confirmed":false,"note":…}`. `Heap::emit` is
/// fire-and-forget: it returns `()` when the message is handed to the channel, and a sender with
/// no receiver sends nothing and returns at once (docs/specs/channel.md §17). The node has no
/// count of receivers or acknowledgement to report, so the answer says that nothing here
/// confirms a receiver got it, rather than let an `ok` read as "delivered".
pub fn emit_delivery(stand: Option<std::time::Duration>) -> Value {
    let kept = match stand {
        Some(lifetime) => format!(
            "; it also stands for {} s, so a receiver that joins within that time is given it",
            lifetime.as_secs()
        ),
        None => "; it does not stand, so a receiver that joins later never gets it (--stand \
                 keeps it for one)"
            .into(),
    };
    json!({
        "confirmed": false,
        "note": format!(
            "emit is not acknowledged: the message went to the receivers this device's channel \
             holds now, and to none if no receiver has asked yet. Start the receivers' `get` \
             first, then emit{kept}"
        ),
    })
}

/// An emit's refusal as an error answer: why, whether to ask again, what to do next, and
/// `retry_after_ms` when the queue was full.
pub fn emit_error(e: &EmitError) -> Value {
    let mut v = error(
        e.to_string(),
        matches!(e.next(), NextStep::RetryLater),
        e.next(),
    );
    if let EmitError::Congested { retry_after } = e {
        v["retry_after_ms"] = json!(millis(*retry_after));
    }
    v
}

/// An introduction's error as an error answer: the data layer's as
/// [`heap_error`], a refused offer with `introduction`: `{"why","left"?}`.
pub fn invite_error(e: &InviteError) -> Value {
    if let InviteError::Heap(e) = e {
        return heap_error(e);
    }
    let mut v = error(e.to_string(), e.retry(), e.next());
    if let Some(why) = e.refusal() {
        let mut i = json!({"why": intro_refusal(why)});
        if let IntroRefusal::WrongProof { left } = why {
            i["left"] = json!(left);
        }
        v["introduction"] = i;
    }
    v
}

/// An introduction's refusal as the error answers name it.
fn intro_refusal(why: &IntroRefusal) -> &'static str {
    match why {
        IntroRefusal::Unknown => "unknown",
        IntroRefusal::Used => "used",
        IntroRefusal::Expired => "expired",
        IntroRefusal::Closed => "closed",
        IntroRefusal::WrongProof { .. } => "wrong-proof",
        IntroRefusal::Forged => "forged",
        IntroRefusal::Conflict => "conflict",
        IntroRefusal::InviterConflict { .. } => "inviter-conflict",
        IntroRefusal::Hint { .. } => "hint",
        IntroRefusal::HintMismatch { .. } => "hint-mismatch",
        IntroRefusal::GoneUnproven { .. } => "gone-unproven",
    }
}

/// The fields of a refusal an error answer carries beside its message:
/// `outside_cut` (the device cut and the seq its tip keeps), `suspected`
/// (the key this device marked suspected, and since when), `untrusted`
/// (why the durable rule refuses an issuer on its chain).
fn refusal(v: &mut Value, why: &Refusal) {
    match why {
        Refusal::OutsideCut(cut) => {
            v["outside_cut"] = json!({"device": cut.device.to_string(), "keeps_to": cut.keeps_to});
        }
        Refusal::Suspected { key, since } => {
            v["suspected"] = json!({"key": key.to_string(), "since_ms": since.0});
        }
        Refusal::Untrusted { why } => v["untrusted"] = json!(why),
        _ => {}
    }
}

pub fn next_token(n: NextStep) -> &'static str {
    match n {
        NextStep::None => "none",
        NextStep::RetryLater => "retry-later",
        NextStep::AskOwner => "ask-owner",
        NextStep::UseOwnerDevice => "use-owner-device",
        NextStep::FixLocal => "fix-local",
        NextStep::FixName => "fix-name",
        NextStep::FixRequest => "fix-request",
    }
}

pub fn next_step(n: NextStep) -> &'static str {
    match n {
        NextStep::None => "nothing: the answer is final",
        NextStep::RetryLater => "ask again later, unchanged: no path or holder answered",
        NextStep::AskOwner => "ask the space's owner for membership, a reading key or re-admission",
        NextStep::UseOwnerDevice => "do it on a device that holds the owner's key",
        NextStep::FixLocal => "fix this device: its storage or its keys",
        NextStep::FixName => "ask again with a well-formed name: the message says how",
        NextStep::FixRequest => {
            "ask again as the message says: the request, as given, asks for something no \
             device does"
        }
    }
}

/// A revocation cut: its key, its runs of seqs per prefix, its tips (per
/// log: the log prefix, the tip's seq and the hex SHA-256 of its signed
/// region; a cut in the tips form has no ranges and no manifest), its exact
/// (re-admitted) names, the SHA-256 of the key's public key it binds
/// (`key_digest`) and the full name of its manifest's root packet
/// (`manifest`), each `null` when the cut has none.
pub fn revocation_cut(c: &RevocationCut) -> Value {
    json!({
        "key": c.key().to_string(),
        "ranges": c.ranges().iter().map(|r| json!({
            "prefix": r.prefix.to_string(),
            "runs": r.runs.iter().map(|(first, last)| json!([first, last])).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "tips": c.tips().iter().map(|t| json!({
            "prefix": t.prefix.to_string(),
            "seq": t.seq,
            "digest": hex(&t.digest),
        })).collect::<Vec<_>>(),
        "exact": c.exact().iter().map(ToString::to_string).collect::<Vec<_>>(),
        "key_digest": c.key_digest().map(|d| hex(d.as_slice())),
        "manifest": c.manifest().map(ToString::to_string),
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;
    use ndn_heap::{Cut, Emitted, EndReason, EvidenceKind, Kept, Timestamp};
    use ndn_packet::Name;
    use ndn_transport::FaceId;

    use super::*;

    fn n(s: &str) -> Name {
        s.parse().expect("a name")
    }

    fn entry() -> EntryId {
        EntryId {
            device: n("/alice/member/phone"),
            seq: 7,
            digest: [0xab; 32],
        }
    }

    fn item_of(bytes: &[u8]) -> Item {
        Item {
            path: n("/trip/day1"),
            bytes: Bytes::copy_from_slice(bytes),
            by: n("/alice"),
            writer: n("/alice/member/phone"),
            id: entry(),
            as_of: None,
        }
    }

    /// An item carries its path, person, writer and id, and the value as
    /// text, as hex when it is no text, as its digest alone when long: the
    /// keys the e2e scenarios and an operator read.
    #[test]
    fn an_item_shows_its_value_by_size_and_kind() {
        let text = item(&item_of(b"on the plane"));
        assert_eq!(text["path"], "/trip/day1");
        assert_eq!(text["by"], "/alice");
        assert_eq!(text["writer"], "/alice/member/phone");
        assert_eq!(text["id"]["device"], "/alice/member/phone");
        assert_eq!(text["id"]["seq"], 7);
        assert_eq!(text["id"]["digest"], "ab".repeat(32));
        assert_eq!(text["len"], 12);
        assert_eq!(text["text"], "on the plane");

        let binary = item(&item_of(&[0xff, 0x00]));
        assert_eq!(binary["hex"], "ff00");
        assert!(binary.get("text").is_none());

        let long = item(&item_of(&[b'x'; 257]));
        assert_eq!(long["len"], 257);
        assert!(long.get("text").is_none() && long.get("hex").is_none());
        assert_eq!(long["sha256"], hex(&Sha256::digest([b'x'; 257])));
    }

    /// A removal and a withdrawal are told as their own change; a withdrawal
    /// by a revocation's cut names the device and the seq its tip keeps.
    #[test]
    fn a_watch_tells_removals_and_withdrawals_by_their_own_keys() {
        assert!(
            change(&Change::Removed(item_of(b"")))
                .get("removed")
                .is_some()
        );
        let withdrawn = change(&Change::Withdrawn {
            id: entry(),
            why: Refusal::OutsideCut(Cut {
                device: n("/alice/member/phone"),
                keeps_to: 3,
            }),
        });
        assert_eq!(withdrawn["withdrawn"]["cut_of"], "/alice/member/phone");
        assert_eq!(withdrawn["withdrawn"]["keeps_to"], 3);
        let alert = change(&Change::Alert(Alert::GapSigned {
            after: 4,
            resumed: 9,
        }));
        assert_eq!(alert["alert"]["kind"], "gap-signed");
        assert_eq!(change(&Change::Lagged { missed: 2 })["lagged"]["missed"], 2);
    }

    /// A public space says `anyone`, a private one lists its persons.
    #[test]
    fn members_say_anyone_or_list_the_persons() {
        let mut m = Members {
            owner: n("/alice"),
            writers: vec![n("/alice"), n("/bob")],
            readers: Readers::Anyone,
        };
        assert_eq!(members(&m)["readers"], "anyone");
        m.readers = Readers::Persons(vec![n("/alice")]);
        assert_eq!(members(&m)["readers"], json!(["/alice"]));
        assert_eq!(members(&m)["writers"], json!(["/alice", "/bob"]));
    }

    /// An error answer keeps `message`, `retry`, `next` and `next_step`, and
    /// the refusal's own fields: what a cut, a suspicion or an untrusted
    /// chain says.
    #[test]
    fn errors_keep_their_keys_and_the_refusals_fields() {
        let not_owner = heap_error(&HeapError::NotOwner {
            space: n("/bob/32=data/notes"),
        });
        assert_eq!(not_owner["next"], "use-owner-device");
        assert_eq!(not_owner["retry"], false);
        assert!(not_owner["message"].as_str().unwrap().contains("/bob"));
        assert!(not_owner["next_step"].is_string());

        let suspected = heap_error(&HeapError::Refused {
            name: n("/alice/member/phone/32=log/x/seq=3"),
            why: Refusal::Suspected {
                key: n("/alice/member/phone/KEY/1"),
                since: Timestamp(1_790_000_000_123),
            },
        });
        assert_eq!(suspected["suspected"]["since_ms"], 1_790_000_000_123u64);
        assert_eq!(suspected["next"], "ask-owner");

        let retry = heap_error(&HeapError::NotReady {
            name: n("/alice/32=data/notes"),
            why: "the epoch key is not held".into(),
        });
        assert_eq!(
            (retry["retry"].as_bool(), retry["next"].as_str()),
            (Some(true), Some("retry-later"))
        );
    }

    /// A refused offer answers `introduction` with why, and the wrong tries
    /// left of a mistyped secret; the data layer's own errors answer as its
    /// own.
    #[test]
    fn a_refused_offer_names_why_and_the_tries_left() {
        let wrong = invite_error(&InviteError::Refused(IntroRefusal::WrongProof { left: 2 }));
        assert_eq!(wrong["introduction"]["why"], "wrong-proof");
        assert_eq!(wrong["introduction"]["left"], 2);
        assert_eq!(wrong["next"], "fix-request");
        let used = invite_error(&InviteError::Refused(IntroRefusal::Used));
        assert_eq!(used["introduction"]["why"], "used");
        assert!(used["introduction"].get("left").is_none());
        let heap = invite_error(&InviteError::Heap(HeapError::BadRequest {
            why: "x".into(),
        }));
        assert!(heap.get("introduction").is_none());
        assert_eq!(heap["next"], "fix-request");
    }

    /// A cut in the tips form lists its tips (log prefix, seq, signed-region
    /// digest in hex) beside its empty ranges and has no manifest; a cut
    /// without tips lists none.
    #[test]
    fn a_cut_lists_its_tips_beside_its_ranges() {
        let mut cut = RevocationCut::new(n("/alice/member/phone/KEY/1"));
        assert_eq!(revocation_cut(&cut)["tips"], json!([]));
        cut.add_tip(&n("/alice/member/phone/32=log/notes"), 7, [0xcd; 32]);
        let shown = revocation_cut(&cut);
        assert_eq!(
            shown["tips"],
            json!([{
                "prefix": n("/alice/member/phone/32=log/notes").to_string(),
                "seq": 7,
                "digest": "cd".repeat(32),
            }])
        );
        assert_eq!(shown["ranges"], json!([]));
        assert!(shown["manifest"].is_null());
    }

    fn got_of(kind: Kind, bytes: &[u8]) -> Got {
        Got {
            path: n("/pos"),
            bytes: Bytes::copy_from_slice(bytes),
            by: n("/alice"),
            writer: n("/alice/member/phone"),
            kind,
        }
    }

    /// A `get` item says which it is: a kept one carries its entry's id, how old it is and
    /// whether it is a removal; an emitted one the channel's sequence and what is left of a
    /// stated lifetime; both the value as an item shows it.
    #[test]
    fn a_get_item_says_whether_it_is_kept_or_emitted() {
        let kept = got(&got_of(
            Kind::Kept(Kept {
                id: entry(),
                as_of: Some(Duration::from_millis(1500)),
                removed: false,
            }),
            b"on the plane",
        ));
        assert_eq!(kept["kind"], "kept");
        assert_eq!(kept["id"]["seq"], 7);
        assert_eq!(kept["as_of_ms"], 1500);
        assert_eq!(kept["removed"], false);
        assert_eq!(kept["text"], "on the plane");
        assert_eq!(kept["writer"], "/alice/member/phone");
        assert!(kept.get("seq").is_none());

        let removal = got(&got_of(
            Kind::Kept(Kept {
                id: entry(),
                as_of: None,
                removed: true,
            }),
            b"",
        ));
        assert_eq!(
            (&removal["removed"], &removal["as_of_ms"]),
            (&json!(true), &Value::Null)
        );
        assert_eq!(removal["len"], 0);

        let emitted = got(&got_of(
            Kind::Emitted(Emitted {
                seq: 42,
                stands: Some(Duration::from_secs(30)),
                verified: false,
            }),
            &[0xff],
        ));
        assert_eq!(emitted["kind"], "emitted");
        assert_eq!(emitted["seq"], 42);
        assert_eq!(emitted["stands_ms"], 30_000);
        assert_eq!(emitted["hex"], "ff");
        assert!(emitted.get("id").is_none());
        let live = got(&got_of(
            Kind::Emitted(Emitted {
                seq: 43,
                stands: None,
                verified: true,
            }),
            b"x",
        ));
        assert!(live["stands_ms"].is_null());
        // Whether a signed checkpoint listed the frame before it was given: a `Prompt` item says
        // `false` for good, a `Verified` one `true`.
        assert_eq!(emitted["verified"], false);
        assert_eq!(live["verified"], true);
        assert!(kept.get("verified").is_none());
    }

    /// Each notice says what to do; an end names the writer whose session ended, a missing path
    /// does not; a retraction gives the range to discard.
    #[test]
    fn a_get_notice_says_what_to_do() {
        let lagged = notice(&GetNotice::Lagged { missed: 3 });
        assert_eq!(
            (lagged["kind"].as_str(), lagged["missed"].as_u64()),
            (Some("lagged"), Some(3))
        );
        let ended = notice(&GetNotice::LiveEnded(LiveEnd::Ended {
            writer: n("/alice/member/phone"),
            reason: EndReason::Closed,
        }));
        assert_eq!(ended["kind"], "live-ended");
        assert_eq!(ended["end"], "ended");
        assert_eq!(ended["writer"], "/alice/member/phone");
        let no_path = notice(&GetNotice::LiveEnded(LiveEnd::NoPath {
            why: "no frame reached this device".into(),
        }));
        assert_eq!(no_path["end"], "no-path");
        assert_eq!(no_path["next"], "fix-local");
        assert!(no_path.get("writer").is_none());
        let retracted = notice(&GetNotice::Retracted {
            writer: n("/alice/member/phone"),
            from: 10,
            to: 12,
        });
        assert_eq!(
            (retracted["from"].as_u64(), retracted["to"].as_u64()),
            (Some(10), Some(12))
        );
        let withdrawn = notice(&GetNotice::Withdrawn {
            id: entry(),
            why: Refusal::OutsideCut(Cut {
                device: n("/alice/member/phone"),
                keeps_to: 3,
            }),
        });
        assert_eq!(withdrawn["kind"], "withdrawn");
        assert_eq!(withdrawn["id"]["seq"], 7);
        assert_eq!(withdrawn["cut_of"], "/alice/member/phone");
        assert_eq!(withdrawn["keeps_to"], 3);
        let kept_ended = notice(&GetNotice::KeptEnded {
            why: "this device's person is no reader of the space any more".into(),
        });
        assert_eq!(kept_ended["kind"], "kept-ended");
        assert_eq!(
            kept_ended["why"],
            "this device's person is no reader of the space any more"
        );
        for v in [
            &lagged,
            &withdrawn,
            &ended,
            &no_path,
            &retracted,
            &kept_ended,
        ] {
            assert!(v["what_to_do"].is_string(), "{v} says nothing to do");
        }
    }

    /// An `emit` that returned `ok` does not read as delivered: the answer says nothing confirms a
    /// receiver got it, that none got it if no receiver had asked, and how to make a late
    /// receiver get it.
    #[test]
    fn an_emit_says_that_delivery_is_not_confirmed() {
        let plain = emit_delivery(None);
        assert_eq!(plain["confirmed"], false);
        let note = plain["note"].as_str().unwrap();
        assert!(note.contains("not acknowledged"), "{note}");
        assert!(note.contains("none if no receiver has asked"), "{note}");
        assert!(note.contains("--stand"), "{note}");
        let standing = emit_delivery(Some(Duration::from_secs(30)))["note"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(standing.contains("stands for 30 s"), "{standing}");
    }

    /// An emit's refusal keeps `message`, `retry`, `next` and `next_step`, a full queue says when
    /// to try again, and what the caller can do about each cause is the heap's own word for it.
    #[test]
    fn an_emit_refusal_says_why_and_what_to_do() {
        let not_writer = emit_error(&EmitError::NotWriter {
            space: n("/bob/32=data/chat"),
            why: "ask the owner".into(),
        });
        assert_eq!(not_writer["next"], "ask-owner");
        assert_eq!(not_writer["retry"], false);
        assert!(not_writer["message"].as_str().unwrap().contains("/bob"));
        assert!(not_writer["next_step"].is_string());
        let congested = emit_error(&EmitError::Congested {
            retry_after: Duration::from_millis(5),
        });
        assert_eq!(congested["retry"], true);
        assert_eq!(congested["retry_after_ms"], 5);
        let too_large = emit_error(&EmitError::TooLarge {
            what: "message",
            size: 9,
            max: 8,
        });
        assert_eq!(too_large["next"], "fix-request");
        assert!(too_large.get("retry_after_ms").is_none());
    }

    /// Evidence names its kind, the channel in hex, the sender, the sequence and the face the
    /// frame came over.
    #[test]
    fn evidence_names_the_channel_the_sender_and_the_face() {
        let shown = evidence(&ChannelEvidence {
            kind: EvidenceKind::Mismatch,
            channel: 0x0102_0304_0506_0708,
            sender: n("/alice/member/phone"),
            key_epoch: 2,
            seq0: 77,
            frame: Bytes::from_static(b"frame"),
            frame_digest: None,
            ingress: FaceId(9),
            proof: Bytes::new(),
            proof_digest: None,
            when: Timestamp(1_700_000_000_123),
        });
        assert_eq!(shown["kind"], "Mismatch");
        assert_eq!(shown["channel"], "0102030405060708");
        assert_eq!(shown["sender"], "/alice/member/phone");
        assert_eq!(
            (shown["key_epoch"].as_u64(), shown["seq0"].as_u64()),
            (Some(2), Some(77))
        );
        assert_eq!(shown["ingress"], 9);
        assert_eq!(shown["when_ms"], 1_700_000_000_123u64);
    }
}
