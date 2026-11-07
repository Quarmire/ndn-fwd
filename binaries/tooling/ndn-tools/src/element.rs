//! `/ndn-tools/merge/element/v=1`: the merge rule `ndn-data --merge-rule`
//! registers — an element of named text settings, shaped like an app's own
//! rule (ndf's elements): operations the app builds, each made over a basis
//! it names by content address, merged into a value only this crate
//! decodes.
//!
//! An **operation** is a basis and edits:
//! - the basis: the implicit digest (SHA-256 of the whole Data packet) of a
//!   version of the collection the operation was made over — optional, and
//!   required when it changes a setting;
//! - each edit names one setting (each at most once): `Set(setting, text)`
//!   writes the setting's text whole; `Change(setting, splice)` splices the
//!   text the basis wrote for that setting (from character `at`, `delete`
//!   characters removed, `insert` put there) and writes the result.
//!
//! **Check** (a function of the operation and its past only, so every
//! reader judges it alike): the octets decode; a basis lies inside the
//! operation's past and was applied; each change's setting was written by
//! the basis and its splice lies inside that text. Anything else is refused
//! for good.
//!
//! **Value**: per setting, its variants — the texts written by versions no
//! later version that wrote the setting was made over (concurrent writes
//! all stay, none is lost) — each with its version (writer key and seq) and
//! that version's digest (the basis a later change names), ordered by
//! version. Applying a write drops the variants inside its past, so the
//! value depends only on which versions are applied, never on their order.
//! Every applied version counts.
//!
//! Wire (all integers big-endian; a text is a u32 length and UTF-8; the
//! octets are consumed exactly). Operation: `basis` (u8 0, or u8 1 and 32
//! octets), u32 edit count, each edit u8 kind (1 set: setting, text; 2
//! change: setting, u32 at, u32 delete, insert). Value: u32 setting count,
//! each the setting and u32 variant count, each variant the writer key's
//! name (URI text), u64 seq, 32-octet digest, text.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use bytes::{BufMut, Bytes, BytesMut};
use ndn_data::{Counting, MergeError, MergeRule, MergeState, Op, OpKind, Value, VersionId, Writer};
use ndn_packet::Name;

/// The rule's name, matched exactly by every reader.
pub const FUNCTION: &str = "/ndn-tools/merge/element/v=1";

const SET: u8 = 1;
const CHANGE: u8 = 2;

/// The rule.
pub struct Element {
    function: Name,
}

impl Element {
    pub fn new() -> Self {
        Self {
            function: FUNCTION.parse().expect("a valid name"),
        }
    }
}

impl MergeRule for Element {
    fn function(&self) -> &Name {
        &self.function
    }

    fn start(&self, _local: &Writer) -> Box<dyn MergeState> {
        Box::new(ElementState::default())
    }
}

/// One edit of an operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Edit {
    /// Write the setting's text whole.
    Set { setting: String, text: String },
    /// Splice the text the basis wrote for the setting, in characters.
    Change {
        setting: String,
        at: u32,
        delete: u32,
        insert: String,
    },
}

impl Edit {
    pub fn setting(&self) -> &str {
        match self {
            Edit::Set { setting, .. } | Edit::Change { setting, .. } => setting,
        }
    }
}

/// An operation: its basis and its edits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElementOp {
    pub basis: Option<[u8; 32]>,
    pub edits: Vec<Edit>,
}

impl ElementOp {
    pub fn encode(&self) -> Bytes {
        let mut b = BytesMut::new();
        match &self.basis {
            None => b.put_u8(0),
            Some(d) => {
                b.put_u8(1);
                b.put_slice(d);
            }
        }
        put_len(&mut b, self.edits.len());
        for e in &self.edits {
            match e {
                Edit::Set { setting, text } => {
                    b.put_u8(SET);
                    put_text(&mut b, setting);
                    put_text(&mut b, text);
                }
                Edit::Change {
                    setting,
                    at,
                    delete,
                    insert,
                } => {
                    b.put_u8(CHANGE);
                    put_text(&mut b, setting);
                    b.put_u32(*at);
                    b.put_u32(*delete);
                    put_text(&mut b, insert);
                }
            }
        }
        b.freeze()
    }

    pub fn decode(octets: &[u8]) -> Result<Self, String> {
        let mut r = Reader(octets);
        let basis = match r.u8()? {
            0 => None,
            1 => Some(r.digest()?),
            f => return Err(format!("basis flag {f} is neither 0 nor 1")),
        };
        let count = r.u32()?;
        let mut edits = Vec::new();
        for _ in 0..count {
            let edit = match r.u8()? {
                SET => Edit::Set {
                    setting: r.text()?,
                    text: r.text()?,
                },
                CHANGE => Edit::Change {
                    setting: r.text()?,
                    at: r.u32()?,
                    delete: r.u32()?,
                    insert: r.text()?,
                },
                k => return Err(format!("edit kind {k} is neither set (1) nor change (2)")),
            };
            edits.push(edit);
        }
        r.end()?;
        let op = Self { basis, edits };
        op.well_formed()?;
        Ok(op)
    }

    /// Edits name each setting at most once, none empty; a change needs a
    /// basis.
    pub fn well_formed(&self) -> Result<(), String> {
        let mut seen = BTreeSet::new();
        for e in &self.edits {
            if e.setting().is_empty() {
                return Err("an edit names no setting".into());
            }
            if !seen.insert(e.setting()) {
                return Err(format!(
                    "setting {:?} is edited twice: an operation edits each setting at most once",
                    e.setting()
                ));
            }
            if matches!(e, Edit::Change { .. }) && self.basis.is_none() {
                return Err(format!(
                    "the change of {:?} names no basis: a change splices the text its basis \
                     wrote, so name the version it was made on",
                    e.setting()
                ));
            }
        }
        if self.edits.is_empty() {
            return Err("an operation with no edit changes nothing".into());
        }
        Ok(())
    }
}

/// One variant of a setting in a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Variant {
    /// The writer key's name, as URI text.
    pub writer: String,
    pub seq: u64,
    /// The digest of the version that wrote it.
    pub digest: [u8; 32],
    pub text: String,
}

/// A decoded value: the variants of each setting.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ElementValue {
    pub settings: BTreeMap<String, Vec<Variant>>,
}

impl ElementValue {
    pub fn encode(&self) -> Bytes {
        let mut b = BytesMut::new();
        put_len(&mut b, self.settings.len());
        for (setting, variants) in &self.settings {
            put_text(&mut b, setting);
            put_len(&mut b, variants.len());
            for v in variants {
                put_text(&mut b, &v.writer);
                b.put_u64(v.seq);
                b.put_slice(&v.digest);
                put_text(&mut b, &v.text);
            }
        }
        b.freeze()
    }

    pub fn decode(octets: &[u8]) -> Result<Self, String> {
        let mut r = Reader(octets);
        let mut settings = BTreeMap::new();
        for _ in 0..r.u32()? {
            let setting = r.text()?;
            let mut variants = Vec::new();
            for _ in 0..r.u32()? {
                variants.push(Variant {
                    writer: r.text()?,
                    seq: r.u64()?,
                    digest: r.digest()?,
                    text: r.text()?,
                });
            }
            settings.insert(setting, variants);
        }
        r.end()?;
        Ok(Self { settings })
    }
}

/// A variant as the state holds it.
#[derive(Clone, Debug)]
struct Held {
    id: VersionId,
    digest: [u8; 32],
    text: String,
}

#[derive(Default)]
struct ElementState {
    /// Each setting's variants, ordered by version.
    settings: BTreeMap<String, Vec<Held>>,
    /// The texts each applied version wrote: what a later change splices.
    written: HashMap<VersionId, BTreeMap<String, String>>,
}

impl ElementState {
    /// The texts `op` writes, each setting's whole result, once checked.
    fn resolve(&self, op: &Op<'_>) -> Result<BTreeMap<String, String>, MergeError> {
        let decoded = ElementOp::decode(op.bytes)
            .map_err(|e| MergeError(format!("not an element operation: {e}")))?;
        let basis = match &decoded.basis {
            None => None,
            Some(d) => {
                let id = op.past.by_digest(d).ok_or_else(|| {
                    MergeError(format!(
                        "its basis {} is no version this operation was made over: an operation \
                         names a basis inside its past",
                        hex(d)
                    ))
                })?;
                let texts = self.written.get(&id).ok_or_else(|| {
                    MergeError(format!(
                        "its basis ({}, {}) was refused, so nothing it wrote can be changed: \
                         change a version that applied",
                        id.writer.key(),
                        id.seq.0
                    ))
                })?;
                Some((id, texts))
            }
        };
        let mut out = BTreeMap::new();
        for e in decoded.edits {
            match e {
                Edit::Set { setting, text } => {
                    out.insert(setting, text);
                }
                Edit::Change {
                    setting,
                    at,
                    delete,
                    insert,
                } => {
                    let (id, texts) = basis.as_ref().expect("a change has a basis (checked)");
                    let text = texts.get(&setting).ok_or_else(|| {
                        MergeError(format!(
                            "its basis ({}, {}) did not write {setting:?}: a change splices the \
                             text its basis wrote; set the setting, or change the version that \
                             wrote it",
                            id.writer.key(),
                            id.seq.0
                        ))
                    })?;
                    out.insert(
                        setting.clone(),
                        splice(text, at, delete, &insert).map_err(|why| {
                            MergeError(format!("the change of {setting:?}: {why}"))
                        })?,
                    );
                }
            }
        }
        Ok(out)
    }
}

impl MergeState for ElementState {
    fn check(&self, op: &Op<'_>) -> Result<OpKind, MergeError> {
        self.resolve(op).map(|_| OpKind::Edit)
    }

    fn apply(&mut self, op: &Op<'_>) -> Result<Counting, MergeError> {
        if self.written.contains_key(op.id) {
            return Ok(Counting::Counted);
        }
        let texts = self.resolve(op)?;
        for (setting, text) in &texts {
            let variants = self.settings.entry(setting.clone()).or_default();
            variants.retain(|v| !op.past.contains(&v.id));
            variants.push(Held {
                id: op.id.clone(),
                digest: *op.digest,
                text: text.clone(),
            });
            variants.sort_by(|a, b| a.id.cmp(&b.id));
        }
        self.written.insert(op.id.clone(), texts);
        Ok(Counting::Counted)
    }

    fn value(&self) -> Value {
        let settings = self
            .settings
            .iter()
            .map(|(s, held)| {
                let variants = held
                    .iter()
                    .map(|h| Variant {
                        writer: h.id.writer.key().to_string(),
                        seq: h.id.seq.0,
                        digest: h.digest,
                        text: h.text.clone(),
                    })
                    .collect();
                (s.clone(), variants)
            })
            .collect();
        Value::Rule(ElementValue { settings }.encode())
    }
}

/// `text` with `delete` characters from character `at` replaced by
/// `insert`.
pub fn splice(text: &str, at: u32, delete: u32, insert: &str) -> Result<String, String> {
    let chars = text.chars().count();
    let (at, delete) = (at as usize, delete as usize);
    if at.checked_add(delete).is_none_or(|end| end > chars) {
        return Err(format!(
            "deleting {delete} characters from {at} reaches past the text's {chars}"
        ));
    }
    let byte = |n: usize| text.char_indices().nth(n).map_or(text.len(), |(i, _)| i);
    let (start, end) = (byte(at), byte(at + delete));
    let mut out = String::with_capacity(text.len() - (end - start) + insert.len());
    out.push_str(&text[..start]);
    out.push_str(insert);
    out.push_str(&text[end..]);
    Ok(out)
}

fn put_len(b: &mut BytesMut, n: usize) {
    b.put_u32(u32::try_from(n).expect("fewer than 2^32 items"));
}

fn put_text(b: &mut BytesMut, s: &str) {
    put_len(b, s.len());
    b.put_slice(s.as_bytes());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Reads the wire, every read checked against what is left.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], String> {
        if self.0.len() < n {
            return Err(format!(
                "cut short: {n} octets wanted, {} left",
                self.0.len()
            ));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 octets"),
        ))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("8 octets"),
        ))
    }

    fn digest(&mut self) -> Result<[u8; 32], String> {
        Ok(self.take(32)?.try_into().expect("32 octets"))
    }

    fn text(&mut self) -> Result<String, String> {
        let n = self.u32()? as usize;
        String::from_utf8(self.take(n)?.to_vec()).map_err(|e| format!("a text is not UTF-8: {e}"))
    }

    fn end(&self) -> Result<(), String> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(format!("{} octets after its end", self.0.len()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct PastOf(Vec<(VersionId, [u8; 32])>);

    impl ndn_data::Past for PastOf {
        fn contains(&self, id: &VersionId) -> bool {
            self.0.iter().any(|(i, _)| i == id)
        }
        fn by_digest(&self, digest: &[u8; 32]) -> Option<VersionId> {
            self.0
                .iter()
                .find(|(_, d)| d == digest)
                .map(|(i, _)| i.clone())
        }
    }

    fn vid(w: &str, seq: u64) -> VersionId {
        VersionId {
            writer: Writer::new(w.parse().expect("a name")),
            seq: ndn_data::Seq(seq),
        }
    }

    fn apply(
        s: &mut Box<dyn MergeState>,
        id: &VersionId,
        digest: [u8; 32],
        past: &PastOf,
        op: &ElementOp,
    ) -> Result<Counting, MergeError> {
        let bytes = op.encode();
        let parents = ndn_data::Frontier::new();
        let op = Op {
            id,
            digest: &digest,
            parents: &parents,
            past,
            bytes: &bytes,
        };
        s.check(&op)?;
        s.apply(&op)
    }

    fn set(setting: &str, text: &str) -> Edit {
        Edit::Set {
            setting: setting.into(),
            text: text.into(),
        }
    }

    /// Concurrent writes stay as variants in one order whatever the
    /// arrival order; a later write over both replaces them; a change
    /// splices its basis's text.
    #[test]
    fn variants_are_order_independent() {
        let rule = Element::new();
        let (a, b) = (vid("/a/KEY/1", 1), vid("/b/KEY/1", 1));
        let none = PastOf(Vec::new());
        let values: Vec<Value> = [[(&a, 1u8), (&b, 2u8)], [(&b, 2u8), (&a, 1u8)]]
            .iter()
            .map(|order| {
                let mut s = rule.start(&Writer::new("/a/KEY/1".parse().expect("a name")));
                for (id, d) in order {
                    let text = if *d == 1 { "from a" } else { "from b" };
                    apply(
                        &mut s,
                        id,
                        [*d; 32],
                        &none,
                        &ElementOp {
                            basis: None,
                            edits: vec![set("title", text)],
                        },
                    )
                    .expect("applies");
                }
                s.value()
            })
            .collect();
        assert_eq!(values[0], values[1]);
        let v = ElementValue::decode(values[0].bytes().expect("rule bytes")).expect("decodes");
        assert_eq!(v.settings["title"].len(), 2);

        let mut s = rule.start(&Writer::new("/a/KEY/1".parse().expect("a name")));
        let past = PastOf(vec![(a.clone(), [1; 32]), (b.clone(), [2; 32])]);
        for (id, d) in [(&a, 1u8), (&b, 2u8)] {
            apply(
                &mut s,
                id,
                [d; 32],
                &none,
                &ElementOp {
                    basis: None,
                    edits: vec![set("title", "x")],
                },
            )
            .expect("applies");
        }
        let c = vid("/a/KEY/1", 2);
        apply(
            &mut s,
            &c,
            [3; 32],
            &past,
            &ElementOp {
                basis: Some([2; 32]),
                edits: vec![Edit::Change {
                    setting: "title".into(),
                    at: 1,
                    delete: 0,
                    insert: "yz".into(),
                }],
            },
        )
        .expect("applies");
        let v = ElementValue::decode(s.value().bytes().expect("rule bytes")).expect("decodes");
        assert_eq!(v.settings["title"].len(), 1);
        assert_eq!(v.settings["title"][0].text, "xyz");
    }

    /// A basis outside the past, a change of a setting the basis did not
    /// write, and a splice past the text are refused.
    #[test]
    fn refuses_what_its_writer_cannot_have_made() {
        let rule = Element::new();
        let mut s = rule.start(&Writer::new("/a/KEY/1".parse().expect("a name")));
        let a = vid("/a/KEY/1", 1);
        let none = PastOf(Vec::new());
        apply(
            &mut s,
            &a,
            [1; 32],
            &none,
            &ElementOp {
                basis: None,
                edits: vec![set("title", "ab")],
            },
        )
        .expect("applies");
        let change = |setting: &str, at| ElementOp {
            basis: Some([1; 32]),
            edits: vec![Edit::Change {
                setting: setting.into(),
                at,
                delete: 0,
                insert: "z".into(),
            }],
        };
        let b = vid("/a/KEY/1", 2);
        assert!(apply(&mut s, &b, [2; 32], &none, &change("title", 0)).is_err());
        let past = PastOf(vec![(a, [1; 32])]);
        assert!(apply(&mut s, &b, [2; 32], &past, &change("body", 0)).is_err());
        assert!(apply(&mut s, &b, [2; 32], &past, &change("title", 3)).is_err());
        assert!(apply(&mut s, &b, [2; 32], &past, &change("title", 2)).is_ok());
    }

    #[test]
    fn wire_round_trips() {
        let op = ElementOp {
            basis: Some([7; 32]),
            edits: vec![
                set("a", "é"),
                Edit::Change {
                    setting: "b".into(),
                    at: 1,
                    delete: 2,
                    insert: "x".into(),
                },
            ],
        };
        assert_eq!(ElementOp::decode(&op.encode()), Ok(op.clone()));
        let mut long = op.encode().to_vec();
        long.push(0);
        assert!(ElementOp::decode(&long).is_err());
    }
}
