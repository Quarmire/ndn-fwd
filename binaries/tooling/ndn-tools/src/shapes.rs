//! The JSON the host prints: ids, items, members, changes, alerts and
//! errors (the shapes the module doc of `heap.rs` lists).

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use ndn_heap::{Alert, Change, EntryId, HeapError, Item, Members, NextStep, Readers, Refusal};
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
        Change::Withdrawn { id: i, why } => {
            let mut w = json!({"id": id(i), "why": why.to_string()});
            match why {
                // A cut: the device cut, and the seq its tip keeps.
                Refusal::OutsideCut(cut) => {
                    w["cut_of"] = json!(cut.device.to_string());
                    w["keeps_to"] = json!(cut.keeps_to);
                }
                // An issuer refused by the durable rule: never re-admitted.
                Refusal::Untrusted { .. } => w["untrusted"] = json!(true),
                _ => {}
            }
            json!({ "withdrawn": w })
        }
        Change::Members(m) => json!({"members": members(m)}),
        Change::Alert(a) => json!({"alert": alert(a)}),
        Change::Lagged { missed } => json!({"lagged": {
            "missed": missed,
            "what_to_do": "changes were dropped while this watch was behind; it lists the \
                           heads again from the start"
        }}),
    }
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
    use bytes::Bytes;
    use ndn_heap::{Cut, Timestamp};
    use ndn_packet::Name;

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
}
