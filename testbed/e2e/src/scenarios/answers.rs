//! answers: named, checkable, sealed answers (data-layer answers spec) on
//! real daemons — a result computed by a named evaluator over exact signed
//! versions, published as one packet under its signer's name, readable
//! exactly by the devices that can read everything it read.
//!
//! Topology and enrollment as in [`super::trio`]: laptop (the owner of /an),
//! tab and phone, each its own daemon and `ndn-data` host; the tab's keeps
//! its entries in a store directory too (`--store`). The laptop shares the
//! folder `/an/32=data/proj` (rule `log`) to itself and the tab as readers
//! (`device:` audiences: the folder is sealed to those two devices) and the
//! two as writers; the phone, a device of the same namespace with a daemon of
//! its own, is outside the audience. The hosts know the pure evaluator
//! `/ndn-tools/eval/words/v=1` (`ndn-data --evaluator`: the words of the
//! definition's note and of the newest note of each collection the definition
//! names, a function of the signed versions alone) and the tab takes the
//! provider function `/ndn-tools/fn/tally/v=1` from the laptop
//! (`--provider`).
//!
//! Proves: the laptop writes a definition (`plan`, naming `chapter` as its
//! input) and the chapter and publishes the answer (`answer-put`: the layer
//! computes it and signs it under the laptop's name, `<laptop>/32=answer/<id>`,
//! with that id). The tab, which has computed nothing, asks the same question
//! and gets the same id and result, which it recomputed and found equal to
//! the laptop's published answer (`recomputed`, confirmed by the laptop's
//! key), and the same again by the answer's exact name and by a question that
//! states the reads. A new version of the chapter gives a new read set: a new
//! answer name and result (the old answer keeps its name and result), which
//! the tab gets too. The phone, outside the audience, cannot read the answer:
//! its question is refused exactly as its `get` of the definition is
//! (sealed: ask the owner), its exact-name `get` of the answer is refused as
//! sealed too, `answer-put` signs nothing for it, and the packet its daemon
//! fetches under the answer's name holds none of the words, collection names
//! or evaluator it was made of and is the very packet the tab fetches. A
//! provider function's answer — the laptop signs a result over the chapter's
//! newest version (`provide`) — is taken by a tab whose policy names the
//! laptop for the function (`provider`) and refused by one whose policy does
//! not (`NotProvider`, next: change the policy). The tab's host started
//! again knowing no evaluator takes the laptop's answer on trust for a question
//! that states its reads (`trusted`, the same id and result), cannot make an
//! answer itself (`CannotCheck`), and, trusting no signer for pure answers,
//! refuses it too (`CannotCheck`, next: update the program).

use serde_json::Value;

use super::data_host::{CONVERGE, Host, Put, name};
use super::shared::content_at;
use super::trio;
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};

const NS: &str = "/an";
const FOLDER: &str = "/an/32=data/proj";
const DEFINITION: &str = "/an/32=data/proj/plan";
const CHAPTER: &str = "/an/32=data/proj/chapter";
const EVALUATOR: &str = "/ndn-tools/eval/words/v=1";
const FUNCTION: &str = "/ndn-tools/fn/tally/v=1";
const LAPTOP: &str = "/an/admin/laptop";
/// The audience and the writers of the folder: the laptop and the tab, not
/// the phone.
const SHARING: &str = "rule=log writers=/an/admin,/an/member/tab \
                       readers=device:/an/admin/laptop,device:/an/member/tab";

/// The words of what the definition and the chapter say, then of the
/// chapter's next version.
const PLAN_NOTE: &str = "alpha beta";
const CHAPTER_NOTE: &str = "one two three";
const CHAPTER_NOTE_2: &str = "one two three four five six";

/// What the answers must not show a device outside the audience: pieces of
/// the notes, the collections and the evaluator; of a refusal of a question,
/// whatever the asker did not name itself: the notes and the evaluator.
const SECRETS: [&str; 7] = [
    "alpha", "beta", "one two", "proj", "plan", "chapter", "words",
];
const NOT_IN_A_REFUSAL: [&str; 4] = ["alpha", "beta", "one two", "words"];

fn opts(pairs: &[&str]) -> Vec<String> {
    pairs.iter().map(|s| (*s).to_owned()).collect()
}

/// `host`'s answer to `line` once it is ok and `done` holds of its `answer`;
/// an error that does not say retry is a failure.
fn answer_until(
    cx: &mut Cx<'_>,
    host: &mut Host,
    line: &str,
    done: impl Fn(&Value) -> bool,
) -> StepResult<Value> {
    let node = host.node.clone();
    let mut found = None;
    wait_for(cx, &format!("{node}> {line}"), CONVERGE, |cx| {
        match host.call(cx, line)? {
            Ok(ok) if done(&ok["answer"]) => {
                found = Some(ok["answer"].clone());
                Ok(true)
            }
            Ok(_) => Ok(false),
            Err(e) if e["retry"] == true => Ok(false),
            Err(e) => Err(format!(
                "{node}> {line}: {} (next: {})",
                e["message"], e["next_step"]
            )),
        }
    })?;
    found.ok_or_else(|| format!("{node}> {line}: no answer"))
}

/// `put` into `collection` once the folder's record covers it: a put that
/// says retry (the walk of the namespace's devices for a record of the
/// collection runs in the background) is asked again.
fn put_when_ready(
    cx: &mut Cx<'_>,
    host: &mut Host,
    collection: &str,
    fields: &str,
) -> StepResult<Put> {
    let node = host.node.clone();
    let mut put = None;
    wait_for(
        cx,
        &format!("{node} puts into {collection}"),
        CONVERGE,
        |cx| match host.call(cx, &format!("put {collection} {fields}"))? {
            Ok(ok) => {
                put = Some(host.put_of(collection, &ok)?);
                Ok(true)
            }
            Err(e) if e["retry"] == true => Ok(false),
            Err(e) => Err(format!(
                "{node}> put {collection}: {} (next: {})",
                e["message"], e["next_step"]
            )),
        },
    )?;
    put.ok_or_else(|| format!("{node}> put {collection}: no answer"))
}

/// `host` reads `v` as the newest version of `collection` (a log
/// collection's `get` answers its newest version).
fn reads_newest(cx: &mut Cx<'_>, host: &mut Host, collection: &str, v: &Put) -> StepResult<bool> {
    match host.call(cx, &format!("get {collection}"))? {
        Ok(ok) => Ok(ok["version"]["id"]["writer"] == v.writer.as_str()
            && ok["version"]["id"]["seq"] == v.seq),
        Err(e) if e["retry"] == true => Ok(false),
        Err(e) => Err(format!(
            "{}> get {collection}: {} (next: {})",
            host.node, e["message"], e["next_step"]
        )),
    }
}

/// `line` at `host` until it answers an error that does not say retry. The
/// error; an ok answer is a failure.
fn refused(cx: &mut Cx<'_>, host: &mut Host, line: &str) -> StepResult<Value> {
    let node = host.node.clone();
    let mut last = Value::Null;
    wait_for(
        cx,
        &format!("{node}> {line} is refused"),
        CONVERGE,
        |cx| match host.call(cx, line)? {
            Ok(ok) => Err(format!("{node}> {line} answered ok: {ok}")),
            Err(e) if e["retry"] == true => Ok(false),
            Err(e) => {
                last = e;
                Ok(true)
            }
        },
    )?;
    Ok(last)
}

/// A refusal saying the name is sealed to an audience this device is not in:
/// ask the owner.
fn sealed(e: &Value) -> bool {
    e["next"] == "ask-owner" && e["message"].as_str().is_some_and(|m| m.contains("sealed"))
}

/// The answer's own fields, as `answer-get` shows them.
fn got_id(a: &Value) -> &str {
    a["id"].as_str().unwrap_or_default()
}

fn text(a: &Value) -> &str {
    a["result"]["text"].as_str().unwrap_or_default()
}

/// Whether `a` was recomputed and found equal to an answer signed by `key`.
fn confirmed_by(a: &Value, key: &str) -> bool {
    a["how"]["recomputed"]["confirmed_by"]
        .as_array()
        .is_some_and(|signers| signers.iter().any(|s| s == key))
}

/// An answer's name is `<device>/32=answer/<id>` with `id` its id.
fn named_by(made: &Value, device: &str) -> StepResult<(String, String)> {
    let answer = made["answer"].as_str().unwrap_or_default();
    let id = made["id"].as_str().unwrap_or_default();
    let (signer, octets) = ndn_data::wire::parse_answer_name(&name(answer)?)
        .ok_or_else(|| format!("{answer} is no answer name: {made}"))?;
    let hex: String = octets.iter().map(|b| format!("{b:02x}")).collect();
    if signer != name(device)? || hex != id {
        return Err(format!(
            "{answer} is under {signer} with id {hex}; expected {device} and {id}"
        ));
    }
    Ok((answer.to_owned(), id.to_owned()))
}

/// None of `secrets` appears in `bytes` or in `shown`.
fn reveals_nothing(bytes: &[u8], shown: &str, secrets: &[&str]) -> StepResult<()> {
    for s in secrets {
        if bytes.windows(s.len()).any(|w| w == s.as_bytes()) || shown.contains(s) {
            return Err(format!(
                "{s:?} shows in what a device outside the audience sees"
            ));
        }
    }
    Ok(())
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    let root = trio::start(sc, NS)?;
    let tab_device = trio::tab(NS);
    let phone_device = trio::phone(NS);
    let tab_store = sc.world.node("tab").dir.join("data-store");
    let store = |extra: &[&str]| {
        let mut o = opts(&["--store", &tab_store.display().to_string()]);
        o.extend(opts(extra));
        o
    };
    let tab_options = store(&["--evaluator", EVALUATOR, "--provider", FUNCTION, LAPTOP]);

    let (mut laptop, mut tab, mut phone) = sc.step(
        "start the data layer on each device, each knowing the evaluator; the tab's keeps its \
         entries on its disk too and takes the function's answers from the laptop; the phone is \
         a device of the namespace outside the folder's audience",
        |cx| {
            cx.concept("data layer host (ndn-data)");
            cx.concept("answers: a named evaluator over signed versions");
            let laptop = Host::start_with(
                cx,
                "laptop",
                &root.identity,
                &opts(&["--evaluator", EVALUATOR]),
            )?;
            let tab = Host::start_with(cx, "tab", &tab_device, &tab_options)?;
            let phone = Host::start_with(
                cx,
                "phone",
                &phone_device,
                &opts(&["--evaluator", EVALUATOR]),
            )?;
            Ok((laptop, tab, phone))
        },
    )?;
    let laptop_key = laptop.writer.clone();

    let first = sc.step(
        "the laptop shares the folder with itself and the tab as readers and writers, writes the \
         definition (a note, naming the chapter as its input) and the chapter; the tab reads \
         both; the phone, outside the audience, is refused both: sealed, ask the owner",
        |cx| {
            laptop.ok(cx, &format!("share_folder {FOLDER} {SHARING}"))?;
            let chapter = put_when_ready(
                cx,
                &mut laptop,
                CHAPTER,
                &format!("note=\"{CHAPTER_NOTE}\""),
            )?;
            let plan = put_when_ready(
                cx,
                &mut laptop,
                DEFINITION,
                &format!("note=\"{PLAN_NOTE}\" inputs={CHAPTER}"),
            )?;
            wait_for(
                cx,
                "the tab reads the definition and the chapter",
                CONVERGE,
                |cx| {
                    Ok(reads_newest(cx, &mut tab, DEFINITION, &plan)?
                        && reads_newest(cx, &mut tab, CHAPTER, &chapter)?)
                },
            )?;
            for what in [DEFINITION, CHAPTER] {
                let e = refused(cx, &mut phone, &format!("get {what}"))?;
                if !sealed(&e) {
                    return Err(format!("the phone's get of {what} is not sealed: {e}"));
                }
                cx.evidence(&format!(
                    "phone get {what}: {} (next: {})",
                    e["message"], e["next"]
                ));
            }
            Ok((plan, chapter))
        },
    )?;

    let (answer_1, id_1) = sc.step(
        "the laptop publishes the answer to the question over the definition: it is signed \
         under the laptop's name with its id, and the laptop reads 5 words (2 + 3) recomputed \
         over the two exact versions",
        |cx| {
            let made = laptop.ok(cx, &format!("answer-put {DEFINITION}"))?;
            let (answer, id) = named_by(&made, LAPTOP)?;
            let got = laptop.ok(cx, &format!("answer-get {DEFINITION}"))?;
            let a = &got["answer"];
            if id != got_id(a)
                || text(a) != "5"
                || a["kind"] != "pure"
                || a["by"] != EVALUATOR
                || a["reads"] != 2
                || !a["how"]["recomputed"].is_object()
            {
                return Err(format!("the laptop's answer is not the published one: {a}"));
            }
            cx.evidence(&format!(
                "laptop answer-put {DEFINITION}: {answer}; answer-get: id {id}, result {} (len \
                 {}, sha256 {}), {} reads by {}, {}",
                text(a),
                a["result"]["len"],
                a["result"]["sha256"],
                a["reads"],
                a["by"],
                a["how"]
            ));
            Ok((answer, id))
        },
    )?;

    sc.step(
        "the tab, which has computed nothing, asks the same question: the same id and result; \
         it asks for the laptop's answer by its exact name (fetched, verified, recomputed and \
         found equal), and its question is then confirmed by the laptop's key; the same by a \
         question that states its reads",
        |cx| {
            let line = format!("answer-get {DEFINITION}");
            let a = answer_until(cx, &mut tab, &line, |a| got_id(a) == id_1)?;
            if text(&a) != "5" || !a["how"]["recomputed"].is_object() {
                return Err(format!(
                    "the tab's answer is not the laptop's result, recomputed: {a}"
                ));
            }
            cx.evidence(&format!(
                "tab {line} (no answer of anyone held yet): id {}, result {}, {}",
                got_id(&a),
                text(&a),
                a["how"]
            ));
            let exact = answer_until(cx, &mut tab, &format!("get {answer_1}"), |a| {
                confirmed_by(a, &laptop_key)
            })?;
            let confirmed = answer_until(cx, &mut tab, &line, |a| confirmed_by(a, &laptop_key))?;
            let stated = answer_until(
                cx,
                &mut tab,
                &format!("answer-get {DEFINITION} {CHAPTER}"),
                |a| confirmed_by(a, &laptop_key),
            )?;
            for (how, got) in [
                ("exact name", &exact),
                ("the question again", &confirmed),
                ("stated reads", &stated),
            ] {
                if got_id(got) != id_1 || got["result"] != a["result"] {
                    return Err(format!(
                        "the tab's answer by {how} differs from its first answer: {got}"
                    ));
                }
            }
            cx.evidence(&format!(
                "tab get {answer_1}: {}; the question again and the stated reads: id {}, {}",
                exact["how"],
                got_id(&confirmed),
                confirmed["how"]
            ));
            Ok(())
        },
    )?;

    let (answer_2, id_2) = sc.step(
        "the laptop writes the chapter again: the new read set gives a new answer name and \
         result (8 words), the old answer keeps its name and result; the tab gets the new one",
        |cx| {
            let (_, chapter) = &first;
            let c2 = put_when_ready(
                cx,
                &mut laptop,
                CHAPTER,
                &format!("note=\"{CHAPTER_NOTE_2}\""),
            )?;
            let made = laptop.ok(cx, &format!("answer-put {DEFINITION}"))?;
            let (answer, id) = named_by(&made, LAPTOP)?;
            if answer == answer_1 || id == id_1 {
                return Err(format!(
                    "an answer over a new version of the chapter ({} after {}) has the old name \
                     {answer}",
                    c2.name, chapter.name
                ));
            }
            let new = laptop.ok(cx, &format!("get {answer}"))?;
            let old = laptop.ok(cx, &format!("answer-get {DEFINITION}"))?;
            let old_by_name = laptop.ok(cx, &format!("get {answer_1}"))?;
            if text(&new["answer"]) != "8"
                || text(&old["answer"]) != "8"
                || got_id(&old_by_name["answer"]) != id_1
                || text(&old_by_name["answer"]) != "5"
            {
                return Err(format!(
                    "the laptop's answers: new {new}, current {old}, old by name {old_by_name}"
                ));
            }
            let line = format!("answer-get {DEFINITION}");
            let a = answer_until(cx, &mut tab, &line, |a| got_id(a) == id)?;
            if text(&a) != "8" {
                return Err(format!("the tab's new answer is not 8: {a}"));
            }
            let fetched = answer_until(cx, &mut tab, &format!("get {answer}"), |a| {
                confirmed_by(a, &laptop_key)
            })?;
            if got_id(&fetched) != id || fetched["result"] != a["result"] {
                return Err(format!(
                    "the tab's new answer by name differs from its answer to the question: \
                     {fetched}"
                ));
            }
            let old_at_tab = answer_until(cx, &mut tab, &format!("get {answer_1}"), |a| {
                got_id(a) == id_1
            })?;
            if text(&old_at_tab) != "5" {
                return Err(format!("the tab's old answer is not 5: {old_at_tab}"));
            }
            cx.evidence(&format!(
                "new chapter {}: answer {answer} (id {id}, result 8) beside the old {answer_1} \
                 (id {id_1}, result 5); the tab reads both",
                c2.name
            ));
            Ok((answer, id))
        },
    )?;

    sc.step(
        "the phone, outside the audience, cannot read the answer: its question is refused as \
         its get of the definition is, its get of the answer by name is refused as sealed, \
         answer-put signs nothing for it; the packet its daemon fetches shows none of the \
         words, collections or evaluator and is the packet the tab fetches",
        |cx| {
            let on_get = refused(cx, &mut phone, &format!("get {DEFINITION}"))?;
            for line in [
                format!("answer-get {DEFINITION}"),
                format!("answer-get {DEFINITION} {CHAPTER}"),
                format!("answer-put {DEFINITION}"),
            ] {
                let e = refused(cx, &mut phone, &line)?;
                if e["message"] != on_get["message"] || e["next"] != on_get["next"] {
                    return Err(format!(
                        "the phone's {line} is refused differently from its get of the \
                         definition:\n  {e}\n  {on_get}"
                    ));
                }
                reveals_nothing(&[], &e.to_string(), &NOT_IN_A_REFUSAL)?;
                cx.evidence(&format!(
                    "phone {line}: {} (next: {}), as get {DEFINITION}",
                    e["message"], e["next"]
                ));
            }
            let by_name = refused(cx, &mut phone, &format!("get {answer_2}"))?;
            if !sealed(&by_name) {
                return Err(format!(
                    "the phone's get of {answer_2} is not sealed: {by_name}"
                ));
            }
            reveals_nothing(&[], &by_name.to_string(), &SECRETS)?;
            cx.evidence(&format!(
                "phone get {answer_2}: {} (next: {})",
                by_name["message"], by_name["next"]
            ));
            let seen = content_at(cx, "phone", &answer_2)?;
            let members = content_at(cx, "tab", &answer_2)?;
            reveals_nothing(&seen, "", &SECRETS)?;
            if seen != members {
                return Err(format!(
                    "the phone's daemon fetches another packet under {answer_2} than the tab's \
                     ({} and {} octets)",
                    seen.len(),
                    members.len()
                ));
            }
            cx.evidence(&format!(
                "the phone's daemon fetches {answer_2}: {} octets, none of {SECRETS:?} in them, \
                 the packet the tab fetches",
                seen.len()
            ));
            Ok(())
        },
    )?;

    sc.step(
        "the laptop signs a provider answer over the chapter's newest version (provide); the \
         tab, whose policy names the laptop for the function, takes it (provider), the phone \
         cannot even name the input",
        |cx| {
            let made = laptop.ok(cx, &format!("provide {FUNCTION} tally:6 {CHAPTER}"))?;
            let (answer, id) = named_by(&made, LAPTOP)?;
            let line = format!("provider-get {LAPTOP} {FUNCTION} {CHAPTER}");
            let a = answer_until(cx, &mut tab, &line, |a| a["how"]["provider"].is_object())?;
            if a["kind"] != "provider"
                || a["by"] != FUNCTION
                || text(&a) != "tally:6"
                || got_id(&a) != id
                || a["how"]["provider"]["signer"] != laptop_key.as_str()
            {
                return Err(format!(
                    "the tab's provider answer is not the laptop's: {a}"
                ));
            }
            let e = refused(cx, &mut phone, &line)?;
            if !sealed(&e) {
                return Err(format!("the phone's {line} is not sealed: {e}"));
            }
            cx.evidence(&format!(
                "laptop provide: {answer}; tab {line}: result {}, {}; phone: {} (next: {})",
                text(&a),
                a["how"],
                e["message"],
                e["next"]
            ));
            Ok(())
        },
    )?;

    sc.step(
        "the tab's host started again knowing no evaluator and no provider: it takes the \
         laptop's answer on trust for a question that states its reads (trusted: the same id \
         and result), cannot make an answer itself (CannotCheck), and refuses the provider's \
         answer (NotProvider, next: set the policy)",
        |cx| {
            tab.stop(cx);
            tab = Host::start_with(cx, "tab", &tab_device, &store(&[]))?;
            let line = format!("answer-get {DEFINITION} {CHAPTER}");
            let a = answer_until(cx, &mut tab, &line, |a| a["how"]["trusted"].is_object())?;
            if got_id(&a) != id_2
                || text(&a) != "8"
                || a["how"]["trusted"]["signer"] != laptop_key.as_str()
            {
                return Err(format!(
                    "the tab's trusted answer is not the laptop's ({id_2}, 8, {laptop_key}): {a}"
                ));
            }
            cx.evidence(&format!(
                "tab (no evaluator) {line}: id {}, result {}, {}",
                got_id(&a),
                text(&a),
                a["how"]
            ));
            let put = format!("answer-put {DEFINITION} {CHAPTER}");
            let e = tab
                .call(cx, &put)?
                .err()
                .ok_or_else(|| format!("the tab signed an answer it cannot compute: {put}"))?;
            if e["cannot_check"]["evaluator"] != EVALUATOR || e["next"] != "update-program" {
                return Err(format!("the tab's {put} is not a CannotCheck: {e}"));
            }
            cx.evidence(&format!(
                "tab {put}: {} (next: {})",
                e["message"], e["next_step"]
            ));
            let provider = format!("provider-get {LAPTOP} {FUNCTION} {CHAPTER}");
            let e = refused(cx, &mut tab, &provider)?;
            if e["answer_refused"] != "not-provider" || e["next"] != "set-policy" {
                return Err(format!("the tab's {provider} is not a NotProvider: {e}"));
            }
            cx.evidence(&format!(
                "tab {provider}: {} (next: {})",
                e["message"], e["next_step"]
            ));
            Ok(())
        },
    )?;

    sc.step(
        "the tab's host started again knowing no evaluator and trusting no signer for pure \
         answers: the laptop's answer is a CannotCheck (the typed refusal: the evaluator, next: \
         update the program, no retry)",
        |cx| {
            tab.stop(cx);
            tab = Host::start_with(
                cx,
                "tab",
                &tab_device,
                &store(&["--answer-signers", "none"]),
            )?;
            let line = format!("answer-get {DEFINITION} {CHAPTER}");
            let e = refused(cx, &mut tab, &line)?;
            if e["cannot_check"]["evaluator"] != EVALUATOR
                || e["next"] != "update-program"
                || e["retry"] != false
            {
                return Err(format!("the tab's {line} is not a CannotCheck: {e}"));
            }
            cx.evidence(&format!(
                "tab {line}: {} (cannot_check {}; next: {})",
                e["message"], e["cannot_check"], e["next_step"]
            ));
            Ok(())
        },
    )?;
    Ok(())
}
