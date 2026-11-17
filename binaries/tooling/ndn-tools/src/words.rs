//! `/ndn-tools/eval/words/v=1`: the pure evaluator `ndn-data --evaluator`
//! registers — a deterministic count of words, shaped like an app's own
//! evaluator (ndf's readings): it reads its definition and the newest version
//! of each collection the definition names, and answers how many words their
//! notes hold.
//!
//! The **definition** is a version of a collection (log or one-key rule: a
//! plain version, not a merge state) of one entry with the fields `note`
//! (text; absent counts none) and `inputs` (collection names, comma
//! separated; absent or empty names none). The **plan** reads each named
//! collection's newest version this device holds as an exact read. The
//! **result** is the number of words — runs of non-whitespace characters — of
//! the definition's `note` and of every input's `note`, as decimal text. An
//! input that is not one entry refuses the definition, the same on every
//! device.

use bytes::Bytes;
use ndn_data::{
    Definition, EvalError, Evaluator, Got, Payload, PlanError, ReadView, Reads, Version,
};
use ndn_packet::Name;

/// The evaluator's name, matched exactly by every reader.
pub const FUNCTION: &str = "/ndn-tools/eval/words/v=1";

/// The evaluator.
pub struct Words {
    name: Name,
}

impl Words {
    pub fn new() -> Self {
        Self {
            name: FUNCTION.parse().expect("a valid name"),
        }
    }
}

/// The entry of a version read, or why this evaluator takes none.
fn entry<'a>(got: &'a Got, what: &str) -> Result<&'a Version, EvalError> {
    match got {
        Got::Version(v) if matches!(v.payload, Payload::Entry(_)) => Ok(v),
        _ => Err(EvalError::Refused(format!(
            "{what} is not one entry of a log or one-key collection: this evaluator counts the \
             words of the note of a version"
        ))),
    }
}

/// The collections the definition names.
fn inputs_of(def: &Definition) -> Result<Vec<Name>, EvalError> {
    let v = entry(&def.got, "the definition")?;
    let Payload::Entry(content) = &v.payload else {
        unreachable!("entry() takes entries only");
    };
    let Some(list) = content.get("inputs") else {
        return Ok(Vec::new());
    };
    let list = std::str::from_utf8(list)
        .map_err(|_| EvalError::Refused("the definition's inputs are not text".into()))?;
    list.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<Name>()
                .map_err(|e| EvalError::Refused(format!("the input {s:?} is no name: {e}")))
        })
        .collect()
}

/// The words of a version's `note`.
fn words_of(got: &Got, what: &str) -> Result<usize, EvalError> {
    let v = entry(got, what)?;
    let Payload::Entry(content) = &v.payload else {
        unreachable!("entry() takes entries only");
    };
    match content.get("note") {
        None => Ok(0),
        Some(note) => std::str::from_utf8(note)
            .map(|t| t.split_whitespace().count())
            .map_err(|_| EvalError::Refused(format!("the note of {what} is not text"))),
    }
}

#[async_trait::async_trait]
impl Evaluator for Words {
    fn evaluator(&self) -> &Name {
        &self.name
    }

    async fn plan(&self, definition: &Definition, reads: &mut dyn Reads) -> Result<(), PlanError> {
        for collection in inputs_of(definition)? {
            let (read, _) = reads.current(&collection).await?;
            reads.read(&read).await?;
        }
        Ok(())
    }

    fn evaluate(&self, definition: &Definition, view: &dyn ReadView) -> Result<Bytes, EvalError> {
        let mut total = words_of(&definition.got, "the definition")?;
        for collection in inputs_of(definition)? {
            let read = view.current(&collection)?;
            total += words_of(view.read(read)?, &format!("the input {collection}"))?;
        }
        Ok(Bytes::from(total.to_string()))
    }
}
