//! approval: enrollment on an admin's approval. A device asks with the
//! namespace's anchor link and `--role admin|node`, shows a verification
//! code, and its daemon finishes on its own once an admin decides — on the
//! CA host, or from a remote admin device that compared the code. The
//! request survives restarts of the CA and of the requester; a member
//! cannot decide; a denial reaches the requester with its reason and its
//! key is deleted. Last, a namespace whose trust context predates the
//! `#deny`/`#pending` rules: remote listing and denial are refused there
//! until `ndn-fwd schema update` on the root device signs a version that
//! carries them.
//!
//! Topology: root (.1, root device + CA of /ap) linked directly to laptop
//! (.2, becomes the remote admin device), tablet (.3, asks to become an
//! admin) and phone (.4, a member by invite, later asks for node
//! certificates).
//!
//! A requester's daemon keeps a held status Interest at the CA, which the
//! CA answers the moment a decision is recorded, so a decision reaches a
//! waiting device at once. A CA restart loses the Interests it held: a
//! device whose Interest was held there sends its next one when that one
//! expires, so a decision made after the restart reaches it within one
//! status lifetime (30 s). Every wait ends on what `ndn-fwd enroll
//! --status` shows.

use std::collections::BTreeMap;
use std::thread;
use std::time::{Duration, Instant};

use ndn_cert::roles::namespace_schema;
use ndn_cert::{RootSecret, RootStore, bump_context_schema, read_stored_context};
use ndn_packet::Name;
use ndn_security::{EnrollmentHint, FilePib, SchemaBlob, compile_lvs_to_binary};

use crate::run::{Op, Out, snapshot};
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{CaCfg, NodeCfg};

const NS: &str = "/ap";
const DENIAL: &str = "not a relay I set up";
const DENIAL_AGAIN: &str = "no hub here";

/// One `key = value` block of `ndn-fwd enroll --status` or
/// `ndn-fwd approvals list`: one request.
type Rec = BTreeMap<String, String>;

fn blocks(out: &Out) -> Vec<Rec> {
    let mut all = Vec::new();
    let mut cur = Rec::new();
    for l in out.stdout.lines().map(str::trim) {
        if l.starts_with('#') {
            continue;
        }
        if l.is_empty() {
            if !cur.is_empty() {
                all.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if let Some((k, v)) = l.split_once('=') {
            cur.insert(k.trim().to_owned(), v.trim().to_owned());
        }
    }
    if !cur.is_empty() {
        all.push(cur);
    }
    all
}

fn field<'a>(r: &'a Rec, k: &str) -> &'a str {
    r.get(k).map(String::as_str).unwrap_or("")
}

/// A code as typed: its digits.
fn digits(code: &str) -> String {
    code.chars().filter(char::is_ascii_digit).collect()
}

/// A request a device made: what its `ndn-fwd enroll` printed.
#[derive(Clone, Debug)]
struct Req {
    id: String,
    code: String,
}

/// `ndn-fwd enroll <anchor link> --role <role> --device <device>` on `node`:
/// pending, with a request id and a code, its status showing the same, and
/// no new certificate.
fn ask(
    cx: &mut Cx<'_>,
    node: &str,
    link: &str,
    role: &str,
    device: &str,
    force: bool,
) -> StepResult<Req> {
    let before = cx.certs(node);
    let mut op = cx
        .tool("ndn-fwd")
        .arg("enroll")
        .arg(link)
        .args(["--role", role, "--device", device, "-c"])
        .arg(cx.w.node(node).cfg_arg());
    if force {
        op = op.arg("--force");
    }
    let out = cx.ok(op, "enroll --role")?;
    if first(out.kv("state")).as_deref() != Some("pending") {
        return Err(format!(
            "enroll: expected state pending, got {:?}",
            out.kv("state")
        ));
    }
    let req = Req {
        id: out.kv("request").ok_or("no request id in the output")?,
        code: out.kv("code").ok_or("no code in the output")?,
    };
    if digits(&req.code).len() != 6 {
        return Err(format!("the code {:?} is not six digits", req.code));
    }
    let identity = format!("{NS}/{role}/{device}/KEY/");
    if !cx.w.keys(node).iter().any(|k| k.starts_with(&identity)) {
        return Err(format!("{node}'s PIB holds no key under {identity}"));
    }
    if cx.certs(node) != before {
        return Err(format!(
            "{node} holds a new certificate before any decision"
        ));
    }
    let shown = status_of(cx, node, &req.id, true)?;
    if field(&shown, "state") != "pending" || digits(field(&shown, "code")) != digits(&req.code) {
        return Err(format!(
            "enroll --status on {node} shows {shown:?}, expected pending {req:?}"
        ));
    }
    Ok(req)
}

/// `ndn-fwd enroll --status` on `node`: its record of request `id`. An
/// operator's look when `operator`, else the harness's own.
fn status_of(cx: &mut Cx<'_>, node: &str, id: &str, operator: bool) -> StepResult<Rec> {
    let op = cx
        .tool("ndn-fwd")
        .args(["enroll", "--status", "-c"])
        .arg(cx.w.node(node).cfg_arg());
    let out = if operator { cx.op(op) } else { cx.exec(op) };
    if !out.success() {
        return Err(format!("enroll --status on {node}: {}", out.status_text()));
    }
    blocks(&out)
        .into_iter()
        .find(|r| field(r, "request") == id)
        .ok_or_else(|| format!("enroll --status on {node} lists no request {id}"))
}

/// Wait until `node`'s request `id` is decided — its daemon's held status
/// Interest brings the decision — then read the record as its operator
/// would. Bounded by one status lifetime beyond [`SHORT`]: a CA restart
/// loses the status Interest it held, and the device sends the next one
/// when that one expires.
fn resolved(cx: &mut Cx<'_>, node: &str, id: &str) -> StepResult<Rec> {
    let start = Instant::now();
    loop {
        let r = status_of(cx, node, id, false)?;
        if field(&r, "state") != "pending" {
            cx.note(&format!(
                "{node}: request {id} {} after {:.2}s",
                field(&r, "state"),
                start.elapsed().as_secs_f64()
            ));
            return status_of(cx, node, id, true);
        }
        let bound = SHORT + ndn_cert::approval::STATUS_LIFETIME;
        if start.elapsed() > bound {
            return Err(format!(
                "{node}: request {id} still pending {}s after the decision",
                bound.as_secs()
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn list_op(cx: &Cx<'_>, node: &str) -> Op {
    cx.tool("ndn-fwd")
        .args(["approvals", "list", "-c"])
        .arg(cx.w.node(node).cfg_arg())
}

/// `ndn-fwd approvals list` on `node`: the record of request `id`. An
/// operator's look when `operator`, else the harness's own.
fn listed(cx: &mut Cx<'_>, node: &str, id: &str, operator: bool) -> StepResult<Rec> {
    let op = list_op(cx, node);
    let out = if operator { cx.op(op) } else { cx.exec(op) };
    if !out.success() {
        return Err(format!("approvals list on {node}: {}", out.status_text()));
    }
    blocks(&out)
        .into_iter()
        .find(|r| field(r, "request") == id)
        .ok_or_else(|| format!("approvals list on {node} shows no request {id}"))
}

/// `ndn-fwd approvals approve|deny <code> [--reason <why>]` on `node`, the
/// code pasted unquoted exactly as a screen shows it (`482 913`: two words),
/// so a list whose code the command refuses fails here.
fn decide(cx: &Cx<'_>, node: &str, verb: &str, shown: &str, reason: Option<&str>) -> Op {
    let mut op = cx
        .tool("ndn-fwd")
        .args(["approvals", verb])
        .args(shown.split_whitespace())
        .arg("-c")
        .arg(cx.w.node(node).cfg_arg());
    if let Some(r) = reason {
        op = op.arg("--reason").arg(r);
    }
    op
}

/// The command must be refused and say why.
fn refused_with_reason(cx: &mut Cx<'_>, op: Op, what: &str) -> StepResult<()> {
    let out = cx.refused(op, what)?;
    if out.stderr.trim().is_empty() {
        return Err(format!("{what}: refused without a reason"));
    }
    Ok(())
}

/// The CA host's durable approval records, byte for byte.
fn ca_records(cx: &Cx<'_>) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let ns: Name = NS.parse().expect("a namespace name");
    snapshot(&ndn_cert::ca_dir(&cx.w.node("root").pib(), &ns).join("approvals"))
}

/// A denial reached `node`: its request `req` is denied with `reason`, the
/// key it generated for `identity` is gone from its PIB, and it still holds
/// the certificates it held.
fn denial_reached(
    cx: &mut Cx<'_>,
    node: &str,
    req: &Req,
    identity: &str,
    reason: &str,
) -> StepResult<()> {
    let held = cx.certs(node);
    let r = resolved(cx, node, &req.id)?;
    if field(&r, "state") != "denied" || !field(&r, "reason").contains(reason) {
        return Err(format!(
            "{node}: expected request {} denied with {reason:?}: {r:?}",
            req.id
        ));
    }
    let prefix = format!("{identity}/KEY/");
    if let Some(k) = cx.w.keys(node).into_iter().find(|k| k.starts_with(&prefix)) {
        return Err(format!("{node}: the denied key {k} is still in its PIB"));
    }
    if cx.certs(node) != held {
        return Err(format!("{node}: its certificates changed with the denial"));
    }
    Ok(())
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// The fixture of an old namespace. On the root device's PIB, sign version
/// N+1 of the held context with the schema and enrollment hint `ndn-fwd
/// init` gave namespaces before the `#deny`/`#pending` rules existed (the
/// generated schema without those two rules; a hint naming no approval
/// roles), with the root store's passphrase, and hand it to the root's
/// daemon (`security/context-update`), as `ndn-fwd revoke` hands its
/// versions over. Returns N+1.
fn sign_old_namespace_version(cx: &mut Cx<'_>) -> StepResult<u64> {
    let (pib_dir, sock) = {
        let n = cx.w.node("root");
        (n.pib(), n.sock().display().to_string())
    };
    cx.note(
        "fixture (ndn-cert, not a CLI): sign v(N+1) with the schema before #deny/#pending \
         and hand it to the root's daemon with security/context-update",
    );
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(err)?;
    rt.block_on(async move {
        let ns: Name = NS.parse().map_err(err)?;
        let pib = FilePib::open(&pib_dir).map_err(err)?;
        let store = RootStore::open(&pib)
            .map_err(err)?
            .ok_or("the root's PIB holds no root store")?;
        let (_, held) = read_stored_context(&pib_dir, &ns)
            .map_err(err)?
            .ok_or("the root's PIB holds no trust context")?;
        let schema = namespace_schema(&ns).map_err(err)?;
        let old: String = schema
            .lvs_source
            .lines()
            .filter(|l| !l.starts_with("#deny:") && !l.starts_with("#pending:"))
            .map(|l| format!("{l}\n"))
            .collect();
        if old.lines().count() + 2 != schema.lvs_source.lines().count() {
            return Err("the generated schema has no #deny and #pending rule to leave out".into());
        }
        let blobs = [
            SchemaBlob::lvs(compile_lvs_to_binary(&old).map_err(err)?),
            SchemaBlob::native_text(schema.native_rules),
        ];
        let hint = EnrollmentHint {
            challenges: vec!["token".into(), "device-approval".into()],
            require_all: true,
            approval_roles: Vec::new(),
        };
        let secret = RootSecret::new(ROOT_PASS.as_bytes().to_vec());
        let root = store.signer(Some(&secret)).await.map_err(err)?;
        let signed = bump_context_schema(root.as_ref(), &held, &blobs, &hint, None, None, true)
            .await
            .map_err(err)?
            .ok_or("the held context carries that schema already")?;
        drop(root);
        let version = signed.bump.context.version();
        let client = ndn_ipc::MgmtClient::connect(&sock).await.map_err(err)?;
        let resp = client
            .security_context_update(signed.bump.data.raw().clone(), Duration::from_secs(30))
            .await
            .map_err(err)?;
        if !resp.is_ok() {
            return Err(format!(
                "the root's daemon did not take v{version} ({}): {}",
                resp.status_code, resp.status_text
            ));
        }
        Ok(version)
    })
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    let n = |s: &str| format!("{NS}{s}");
    let to_root = NodeCfg {
        links: vec![link("root", 1)],
        routes: vec![route(NS, "root")],
        refresh_secs: 1,
        ..Default::default()
    };
    sc.world.add(
        "root",
        1,
        NodeCfg {
            links: vec![link("laptop", 2), link("tablet", 3), link("phone", 4)],
            routes: vec![route(n("/admin/tablet"), "tablet")],
            refresh_secs: 1,
            ..Default::default()
        },
    );
    sc.world.add("laptop", 2, to_root.clone());
    sc.world.add("tablet", 3, to_root.clone());
    sc.world.add("phone", 4, to_root);

    let root = sc.step("init the root device of /ap", |cx| {
        init_root(cx, "root", NS, "desk")
    })?;
    let invite = sc.step("mint a member invite", |cx| {
        mint(cx, NS, &root.fp, 1, Some("2h")).map(|mut v| v.remove(0))
    })?;
    sc.step(
        "start the root device with its CA, and laptop, tablet and phone",
        |cx| {
            cx.w.node_mut("root").cfg.identity = Some(root.identity.clone());
            cx.w.node_mut("root").cfg.ca = Some(CaCfg {
                prefix: NS.into(),
                identity: n("/CA"),
                tokens: vec![invite.token.clone()],
                member_days: None,
            });
            for node in ["root", "laptop", "tablet", "phone"] {
                cx.start(node)?;
            }
            Ok(())
        },
    )?;
    sc.step("phone enrolls as a member with the invite", |cx| {
        enroll(cx, "phone", &invite, "phone", false, None).map(|_| ())
    })?;

    let laptop = sc.step(
        "laptop asks to be an admin device (anchor link): pending, with a code",
        |cx| ask(cx, "laptop", &root.link_fp, "admin", "laptop", false),
    )?;
    sc.step(
        "the root device's operator approves by code; laptop's certificate is issued with no further action",
        |cx| {
            let before = cx.certs("laptop");
            let r = listed(cx, "root", &laptop.id, true)?;
            let op = decide(cx, "root", "approve", field(&r, "code"), None);
            cx.ok(op, "approvals approve on the CA host")?;
            let r = resolved(cx, "laptop", &laptop.id)?;
            if field(&r, "state") != "issued" {
                return Err(format!("laptop: expected its request issued: {r:?}"));
            }
            let cert = new_cert(cx, "laptop", &before)?;
            if !cert.starts_with(&n("/admin/laptop/KEY/")) {
                return Err(format!("unexpected certificate {cert}"));
            }
            let at_ca = listed(cx, "root", &laptop.id, false)?;
            if field(&at_ca, "state") != "approved" || field(&at_ca, "decided_by").is_empty() {
                return Err(format!("the CA's record does not say who approved: {at_ca:?}"));
            }
            Ok(())
        },
    )?;

    let tablet = sc.step(
        "tablet asks to be an admin device: pending, with a code",
        |cx| ask(cx, "tablet", &root.link_fp, "admin", "tablet", false),
    )?;
    let relay = sc.step(
        "phone (a member) asks for a node certificate: pending, with a code",
        |cx| ask(cx, "phone", &root.link_fp, "node", "relay", true),
    )?;
    sc.step(
        "restart the CA's daemon and tablet's: the requests stay pending on both sides",
        |cx| {
            let before = ca_records(cx);
            for node in ["root", "tablet"] {
                cx.stop(node);
            }
            for node in ["root", "tablet"] {
                cx.start(node)?;
            }
            if ca_records(cx) != before {
                return Err("the CA's approval records changed across the restart".into());
            }
            let at_ca = listed(cx, "root", &tablet.id, false)?;
            if field(&at_ca, "state") != "pending"
                || digits(field(&at_ca, "code")) != digits(&tablet.code)
            {
                return Err(format!(
                    "the CA lists {at_ca:?}, expected pending {tablet:?}"
                ));
            }
            let shown = status_of(cx, "tablet", &tablet.id, false)?;
            if field(&shown, "state") != "pending"
                || digits(field(&shown, "code")) != digits(&tablet.code)
            {
                return Err(format!(
                    "tablet shows {shown:?}, expected pending {tablet:?}"
                ));
            }
            Ok(())
        },
    )?;
    sc.step(
        "laptop (remote admin) lists the request with tablet's code and approves it",
        |cx| {
            let r = listed(cx, "laptop", &tablet.id, true)?;
            if field(&r, "state") != "pending" || digits(field(&r, "code")) != digits(&tablet.code)
            {
                return Err(format!("laptop lists {r:?}; tablet shows {tablet:?}"));
            }
            let op = decide(cx, "laptop", "approve", field(&r, "code"), None);
            cx.ok(op, "approvals approve on the remote admin device")
                .map(|_| ())
        },
    )?;
    sc.step(
        "tablet's certificate is issued with no further action; the CA records laptop's key",
        |cx| {
            let before = cx.certs("tablet");
            let r = resolved(cx, "tablet", &tablet.id)?;
            if field(&r, "state") != "issued" {
                return Err(format!("tablet: expected its request issued: {r:?}"));
            }
            let cert = new_cert(cx, "tablet", &before)?;
            if !cert.starts_with(&n("/admin/tablet/KEY/")) {
                return Err(format!("unexpected certificate {cert}"));
            }
            let at_ca = listed(cx, "root", &tablet.id, false)?;
            if field(&at_ca, "state") != "approved"
                || !field(&at_ca, "decided_by").contains(&n("/admin/laptop/KEY/"))
            {
                return Err(format!(
                    "the CA's record does not name laptop's admin key: {at_ca:?}"
                ));
            }
            Ok(())
        },
    )?;
    let doc = content(4_000, 41);
    sc.step("tablet's Data validates at the root", |cx| {
        cx.publish("tablet", &n("/admin/tablet/doc"), &doc, None, None)?;
        cx.fetch_ok("root", &n("/admin/tablet/doc"), &doc)
    })?;

    sc.step(
        "phone, a member, cannot decide: its approve is refused and nothing changes",
        |cx| {
            let before = ca_records(cx);
            // A member cannot list: it types the code its requester shows.
            let op = decide(cx, "phone", "approve", &relay.code, None);
            refused_with_reason(cx, op, "approvals approve on a member device")?;
            if ca_records(cx) != before {
                return Err("the CA's approval records changed".into());
            }
            let at_ca = listed(cx, "root", &relay.id, false)?;
            if field(&at_ca, "state") != "pending" {
                return Err(format!("the CA lists {at_ca:?}, expected it still pending"));
            }
            let shown = status_of(cx, "phone", &relay.id, false)?;
            if field(&shown, "state") != "pending" {
                return Err(format!("phone shows {shown:?}, expected it still pending"));
            }
            Ok(())
        },
    )?;
    sc.step(
        "laptop denies it with a reason; phone learns why and its new key is deleted",
        |cx| {
            let r = listed(cx, "laptop", &relay.id, true)?;
            let op = decide(cx, "laptop", "deny", field(&r, "code"), Some(DENIAL));
            cx.ok(op, "approvals deny on the remote admin device")?;
            denial_reached(cx, "phone", &relay, &n("/node/relay"), DENIAL)
        },
    )?;

    // A namespace made before `#deny`/`#pending`: its context lacks them.
    let hub = sc.step(
        "phone asks for a node certificate again (hub): pending",
        |cx| ask(cx, "phone", &root.link_fp, "node", "hub", true),
    )?;
    let v = sc.world.held_version("root", NS).unwrap_or(0);
    sc.step(
        "fixture: the root device signs a version with the schema of a namespace made before \
         #deny/#pending; every node adopts it",
        |cx| {
            let signed = sign_old_namespace_version(cx)?;
            if signed != v + 1 {
                return Err(format!("signed v{signed}, expected v{}", v + 1));
            }
            cx.expect_version("root", NS, v + 1)?;
            let start = Instant::now();
            for node in ["laptop", "tablet", "phone"] {
                cx.wait_version(node, NS, v + 1, SHORT.saturating_sub(start.elapsed()))?;
            }
            Ok(())
        },
    )?;
    sc.step(
        "on that schema the remote admin's list and deny are refused; nothing changes",
        |cx| {
            let before = ca_records(cx);
            let op = list_op(cx, "laptop");
            refused_with_reason(cx, op, "approvals list on the remote admin device")?;
            let op = decide(cx, "laptop", "deny", &hub.code, Some(DENIAL_AGAIN));
            refused_with_reason(cx, op, "approvals deny on the remote admin device")?;
            if ca_records(cx) != before {
                return Err("the CA's approval records changed".into());
            }
            let at_ca = listed(cx, "root", &hub.id, false)?;
            if field(&at_ca, "state") != "pending" {
                return Err(format!("the CA lists {at_ca:?}, expected it still pending"));
            }
            Ok(())
        },
    )?;
    sc.step(
        "`ndn-fwd schema update` on the root device signs a version with the current schema",
        |cx| {
            let op = cx
                .tool("ndn-fwd")
                .args(["schema", "update", "-c"])
                .arg(cx.w.node("root").cfg_arg())
                .env("NDN_ROOT_PASSPHRASE", ROOT_PASS);
            cx.ok(op, "schema update")?;
            cx.expect_version("root", NS, v + 2)
        },
    )?;
    sc.step("laptop, tablet and phone adopt it", |cx| {
        let start = Instant::now();
        for node in ["laptop", "tablet", "phone"] {
            cx.wait_version(node, NS, v + 2, SHORT.saturating_sub(start.elapsed()))?;
        }
        Ok(())
    })?;
    sc.step(
        "the remote admin lists the request with phone's code and denies it; phone learns why",
        |cx| {
            let r = listed(cx, "laptop", &hub.id, true)?;
            if field(&r, "state") != "pending" || digits(field(&r, "code")) != digits(&hub.code) {
                return Err(format!("laptop lists {r:?}; phone shows {hub:?}"));
            }
            let op = decide(cx, "laptop", "deny", field(&r, "code"), Some(DENIAL_AGAIN));
            cx.ok(op, "approvals deny on the remote admin device")?;
            denial_reached(cx, "phone", &hub, &n("/node/hub"), DENIAL_AGAIN)
        },
    )?;
    let doc2 = content(4_000, 42);
    sc.step(
        "devices keep validating: tablet's new Data validates at the root and at laptop",
        |cx| {
            cx.publish("tablet", &n("/admin/tablet/doc2"), &doc2, None, None)?;
            fetch_all(cx, &["root", "laptop"], &n("/admin/tablet/doc2"), &doc2)
        },
    )?;
    Ok(())
}
