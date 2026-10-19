//! multi-prefix: one device takes part in several trusted prefixes at once.
//!
//! Topology, all on the harness's `lo`: owner (10.200.0.1) is the root
//! device of two trusted prefixes, /mpa and /mpc, from one PIB (two `ndn-fwd
//! init --namespace`, two `[[ca]]` tables in one config). rootb (.2) is the
//! root device of /mpb. dev (.3) links over UDP to owner and rootb; it
//! enrolls in /mpa, then in /mpc, and only adopts (follows) /mpb. relay (.4)
//! is a `node` device of /mpc only, listening for QUIC links with the default
//! serving policy (its own trusted prefix). cfan (.5) is a member of /mpc
//! that reaches /mpc only through the relay (dev and cfan take no direct
//! paths by membership, so their traffic shows on the relay). temp (.6) is
//! a throwaway member of /mpa and /mpc that owner revokes in each.
//!
//! Proves: a device that owns two trusted prefixes runs both CAs and acts as
//! the root of each on its own (a revocation or a recovery kit changes only
//! that prefix's trust context and CA), and refuses a root operation that
//! does not say which prefix; a member of /mpa that enrolls in /mpc keeps
//! /mpa's key for /mpa's Data and its node identity (management responses,
//! link key), signs /mpc's Data with /mpc's key, verifies /mpb's Data it
//! follows and is refused, with why, when publishing under /mpb; the
//! membership report shows owner / member (role) / following per prefix;
//! the relay serving only /mpc admits dev by its /mpc membership although
//! dev's link key is its /mpa key, names dev's /mpc device, and carries dev's
//! /mpc Data to cfan. Forged or replayed membership bindings on a link are
//! covered by the ndn-link tests, not here.

use std::path::Path;
use std::time::Duration;

use ndn_packet::Name;
use ndn_security::{FilePib, anchor_fingerprint};

use super::direct_paths::{link_list, quic_faces};
use crate::run::snapshot;
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{CaCfg, NodeCfg, PeerCfg, addr};

const A: &str = "/mpa";
const B: &str = "/mpb";
const C: &str = "/mpc";
/// ndn-put's default segment size.
const SEGMENT: usize = 8192;

const DEV: u8 = 3;
const RELAY: u8 = 4;
const CFAN: u8 = 5;

/// No direct paths by membership: dev's and cfan's /mpc traffic stays on
/// the relay, where it shows.
const NO_DIRECT: &str = "[direct]\nmembership = false\n";

/// One row of `ndn-ctl status`'s "trusted prefixes" table.
#[derive(Clone, Debug)]
struct Prefix {
    namespace: String,
    /// `following`, `member` or `owner`.
    relation: String,
    /// The device role (`member`, `node`, `admin`), "" when none.
    role: String,
    /// The identity this node signs the prefix's Data as; `None`: verify
    /// only.
    signs_as: Option<String>,
    node_identity: bool,
    line: String,
}

/// `ndn-ctl status`, the parts about signing: the `signing:` line's
/// `key=value` fields (the node identity, its key and why it was chosen,
/// every signing identity) and the trusted prefixes.
#[derive(Clone, Debug, Default)]
struct Signing {
    fields: Vec<(String, String)>,
    prefixes: Vec<Prefix>,
}

impl Signing {
    fn field(&self, k: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(f, _)| f == k)
            .map(|(_, v)| v.as_str())
    }

    fn all(&self, k: &str) -> Vec<&str> {
        self.fields
            .iter()
            .filter(|(f, _)| f == k)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    fn prefix(&self, ns: &str) -> Option<&Prefix> {
        self.prefixes.iter().find(|p| p.namespace == ns)
    }

    /// The node identity, its key and the rule that chose it.
    fn node(&self) -> String {
        format!(
            "node identity {} (key {}, source {})",
            self.field("identity").unwrap_or("-"),
            self.field("key").unwrap_or("-"),
            self.field("node_identity_source").unwrap_or("-")
        )
    }
}

fn signing(cx: &mut Cx<'_>, node: &str) -> StepResult<Signing> {
    let sock = cx.w.node(node).sock().display().to_string();
    let op = cx.tool("ndn-ctl").args(["--socket", &sock, "status"]);
    let out = cx.exec(op);
    if !out.success() {
        return Err(format!("status on {node}: {}", out.status_text()));
    }
    let mut s = Signing::default();
    let mut in_prefixes = false;
    for line in out.stdout.lines() {
        if let Some(rest) = line.strip_prefix("signing:") {
            s.fields = rest
                .split_whitespace()
                .filter_map(|w| w.split_once('='))
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect();
            continue;
        }
        if line.starts_with("trusted prefixes:") {
            in_prefixes = true;
            continue;
        }
        if !in_prefixes || !line.starts_with("  /") {
            continue;
        }
        // `  <ns> v<N>  <relation>[ (<role>)]  signs as <id> until <t>[, node identity]`
        // or `... verify only`.
        let t = line.trim();
        let cols: Vec<&str> = t.split("  ").map(str::trim).collect();
        let [head, part, signs] = cols.as_slice() else {
            return Err(format!("status on {node}: unreadable trusted prefix {t:?}"));
        };
        let namespace = head.split_whitespace().next().unwrap_or("").to_owned();
        let (relation, role) = match part.split_once(" (") {
            Some((r, role)) => (r.to_owned(), role.trim_end_matches(')').to_owned()),
            None => (part.to_string(), String::new()),
        };
        let signs_as = signs
            .strip_prefix("signs as ")
            .and_then(|r| r.split_whitespace().next())
            .map(str::to_owned);
        s.prefixes.push(Prefix {
            namespace,
            relation,
            role,
            signs_as,
            node_identity: signs.ends_with(", node identity"),
            line: t.to_owned(),
        });
    }
    if s.fields.is_empty() {
        return Err(format!("status on {node}: no `signing:` line"));
    }
    Ok(s)
}

/// `node`'s relation to each of `want` (`namespace`, `relation`, `role`,
/// node identity); every row is evidence.
fn expect_prefixes(
    cx: &mut Cx<'_>,
    node: &str,
    want: &[(&str, &str, &str, bool)],
) -> StepResult<Signing> {
    let s = signing(cx, node)?;
    for p in &s.prefixes {
        cx.evidence(&format!("{node}: {}", p.line));
    }
    for (ns, relation, role, node_identity) in want {
        let p = s
            .prefix(ns)
            .ok_or_else(|| format!("{node} reports no trusted prefix {ns}: {:?}", s.prefixes))?;
        if p.relation != *relation || p.role != *role || p.node_identity != *node_identity {
            return Err(format!(
                "{node} → {ns}: {:?}, expected {relation} (role {role:?}), node identity {node_identity}",
                p.line
            ));
        }
        let signs = p.signs_as.is_some();
        if signs == (*relation == "following") {
            return Err(format!(
                "{node} → {ns}: {:?}: a {relation} signs {}",
                p.line,
                if signs { "nothing" } else { "as its identity" }
            ));
        }
    }
    Ok(s)
}

/// The KeyLocator of the Data `name` fetched through `node` (`ndn-peek
/// -m`): the key (or certificate) that signed it.
fn key_locator(cx: &mut Cx<'_>, node: &str, name: &str) -> StepResult<String> {
    let sock = cx.w.node(node).sock().display().to_string();
    let op = cx
        .tool("ndn-peek")
        .args([
            "--face-socket",
            &sock,
            "--can-be-prefix",
            "--lifetime",
            "4000",
            "-m",
            name,
        ])
        .timeout(Duration::from_secs(30));
    let out = cx.op(op);
    if !out.success() {
        return Err(format!(
            "ndn-peek -m {name} at {node}: {}",
            out.status_text()
        ));
    }
    out.stdout
        .lines()
        .chain(out.stderr.lines())
        .find_map(|l| l.trim().strip_prefix("key:").map(|k| k.trim().to_owned()))
        .ok_or_else(|| format!("{name} at {node}: no KeyLocator in the Data"))
}

/// `name` (published by dev) fetched and validated at `node`, its bytes
/// `expect`, signed by a key of `identity`.
fn signed_by(
    cx: &mut Cx<'_>,
    node: &str,
    name: &str,
    expect: &[u8],
    identity: &str,
) -> StepResult<()> {
    fetch_within(cx, node, name, expect, SHORT)?;
    let key = key_locator(cx, node, name)?;
    cx.evidence(&format!("{name} validated at {node}; KeyLocator {key}"));
    if !key.contains(&format!("{identity}/KEY/")) {
        return Err(format!(
            "{name}: signed by {key}, expected a key of {identity}"
        ));
    }
    Ok(())
}

fn root_op(cx: &Cx<'_>, args: &[&str]) -> crate::run::Op {
    cx.tool("ndn-fwd")
        .args(args.iter().copied())
        .arg("-c")
        .arg(cx.w.node("owner").cfg_arg())
        .env("NDN_ROOT_PASSPHRASE", ROOT_PASS)
}

fn version(cx: &Cx<'_>, ns: &str) -> u64 {
    cx.version("owner", ns).unwrap_or(0)
}

/// Packets the relay exchanged on its links with dev and cfan.
fn relay_packets(cx: &mut Cx<'_>) -> StepResult<u64> {
    let ips = [addr(DEV), addr(CFAN)];
    Ok(quic_faces(cx, "relay")?
        .into_iter()
        .filter(|(r, _)| ips.contains(r.ip()))
        .map(|(_, p)| p)
        .sum())
}

fn parse_name(s: &str) -> StepResult<Name> {
    s.parse().map_err(|e| format!("{s}: {e:?}"))
}

/// The fingerprint of `key` in `pib` (SHA-256 of the public key its
/// certificate carries), as `ndn-ctl link list` shows link keys.
fn fingerprint(pib: &Path, key: &str) -> StepResult<String> {
    let pib = FilePib::open(pib).map_err(|e| format!("{}: {e}", pib.display()))?;
    let cert = pib
        .certs(&parse_name(key)?)
        .map_err(|e| format!("{key}: {e}"))?
        .into_iter()
        .next()
        .ok_or_else(|| format!("no certificate of {key}"))?;
    Ok(anchor_fingerprint(&cert)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// The key `identity` holds in `pib`.
fn identity_key(pib: &Path, identity: &str) -> StepResult<String> {
    let pib = FilePib::open(pib).map_err(|e| format!("{}: {e}", pib.display()))?;
    let keys = pib
        .identity_keys(&parse_name(identity)?)
        .map_err(|e| format!("{identity}: {e}"))?;
    match keys.as_slice() {
        [one] => Ok(one.to_string()),
        _ => Err(format!("{identity} holds keys {keys:?}, expected one")),
    }
}

fn relay_peer() -> PeerCfg {
    PeerCfg {
        device: Some(format!("{C}/node/relay")),
        endpoint: Some(addr(RELAY)),
        ..Default::default()
    }
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    let base = NodeCfg {
        refresh_secs: 2,
        ..Default::default()
    };
    sc.world.add(
        "owner",
        1,
        NodeCfg {
            links: vec![link("dev", DEV)],
            routes: vec![
                route(format!("{A}/member/dev"), "dev"),
                route(format!("{C}/member/dev"), "dev"),
            ],
            ..base.clone()
        },
    );
    sc.world.add("rootb", 2, base.clone());
    sc.world.add(
        "dev",
        DEV,
        NodeCfg {
            links: vec![link("owner", 1), link("rootb", 2)],
            routes: vec![route(A, "owner"), route(C, "owner"), route(B, "rootb")],
            ..base.clone()
        },
    );
    sc.world.add(
        "relay",
        RELAY,
        NodeCfg {
            links: vec![link("owner", 1)],
            routes: vec![route(C, "owner")],
            quic_listen: true,
            ..base.clone()
        },
    );
    let to_owner = NodeCfg {
        links: vec![link("owner", 1)],
        routes: vec![route(A, "owner"), route(C, "owner")],
        ..base.clone()
    };
    sc.world.add("cfan", CFAN, to_owner.clone());
    sc.world.add("temp", 6, to_owner);

    let (a, c) = sc.step(
        "owner: init the roots of trusted prefixes /mpa and /mpc in one PIB, each in its own root store",
        |cx| {
            let a = init_root(cx, "owner", A, "desk")?;
            let c = init_root(cx, "owner", C, "desk")?;
            let pib = cx.w.node("owner").pib().display().to_string();
            let op = cx.tool("ndn-fwd").args(["root-key", "status", "--pib", &pib]);
            let out = cx.ok(op, "root-key status")?;
            let held = out.kv_all("namespace");
            cx.evidence(&format!("root-key status lists the roots of {held:?}"));
            if held != [A, C] {
                return Err(format!("root-key status lists {held:?}, expected [{A}, {C}]"));
            }
            Ok((a, c))
        },
    )?;
    let b = sc.step("rootb: init the root of trusted prefix /mpb", |cx| {
        init_root(cx, "rootb", B, "home")
    })?;
    let (inv_a, inv_c) = sc.step(
        "mint invites: /mpa for dev and temp; /mpc for dev, temp and cfan",
        |cx| {
            Ok((
                mint(cx, A, &a.fp, 2, Some("2h"))?,
                mint(cx, C, &c.fp, 3, Some("2h"))?,
            ))
        },
    )?;
    sc.step(
        "owner runs the CAs of both trusted prefixes from one config (one [[ca]] each) and reports itself owner of both",
        |cx| {
            let owner = cx.w.node_mut("owner");
            owner.cfg.identity = Some(a.identity.clone());
            owner.cfg.cas = [(A, &inv_a), (C, &inv_c)]
                .into_iter()
                .map(|(ns, invites)| CaCfg {
                    prefix: ns.into(),
                    identity: format!("{ns}/CA"),
                    tokens: invites.iter().map(|i| i.token.clone()).collect(),
                    member_days: None,
                })
                .collect();
            cx.start("owner")?;
            expect_prefixes(
                cx,
                "owner",
                &[(A, "owner", "admin", true), (C, "owner", "admin", false)],
            )?;
            Ok(())
        },
    )?;
    sc.step(
        "rootb starts its daemon, serving /mpb's trust context",
        |cx| {
            cx.w.node_mut("rootb").cfg.identity = Some(b.identity.clone());
            cx.start("rootb")
        },
    )?;

    sc.step(
        "a root operation that does not name its trusted prefix is refused, naming both, and changes nothing",
        |cx| {
            let contexts = cx.w.node("owner").pib().join("contexts");
            let before = snapshot(&contexts);
            let op = root_op(cx, &["recovery-kit", "create", "--format", "words"]);
            let out = cx.refused(op, "recovery-kit create without --namespace")?;
            let said = format!("{}\n{}", out.stdout, out.stderr);
            let line = said
                .lines()
                .find(|l| l.contains(A) && l.contains(C))
                .ok_or_else(|| format!("the refusal does not name both {A} and {C}: {said}"))?;
            cx.evidence(&format!("refused: {}", line.trim()));
            if snapshot(&contexts) != before {
                return Err("the refused root operation changed a trust context".into());
            }
            Ok(())
        },
    )?;
    sc.step(
        "a recovery kit for /mpc (--namespace): a new /mpc trust-context version; /mpa's is unchanged",
        |cx| {
            let (va, vc) = (version(cx, A), version(cx, C));
            let op = root_op(
                cx,
                &["recovery-kit", "create", "--format", "words", "--namespace", C],
            );
            let out = cx.ok(op, "recovery-kit create --namespace /mpc")?;
            words(&out)?;
            cx.expect_version("owner", C, vc + 1)?;
            cx.expect_version("owner", A, va)?;
            cx.evidence(&format!("{C} v{vc} → v{}; {A} stays v{va}", vc + 1));
            Ok(())
        },
    )?;
    sc.step(
        "temp enrolls in /mpa and in /mpc; owner revokes it in /mpa, then in /mpc: each revocation changes only its own trusted prefix and CA",
        |cx| {
            cx.start("temp")?;
            enroll(cx, "temp", &inv_a[1], "temp", false, None)?;
            enroll(cx, "temp", &inv_c[1], "temp", false, None)?;
            let pib = cx.w.node("owner").pib();
            let revoked = |ns: &str| {
                let ns: Name = ns.parse().expect("a namespace name");
                snapshot(&ndn_cert::ca_dir(&pib, &ns).join("revoked")).len()
            };
            for (ns, other) in [(A, C), (C, A)] {
                let (v, vo) = (version(cx, ns), version(cx, other));
                let (r, ro) = (revoked(ns), revoked(other));
                let device = format!("{ns}/member/temp");
                let op = root_op(cx, &["revoke", &device]);
                cx.ok(op, &format!("revoke {device}"))?;
                cx.expect_version("owner", ns, v + 1)?;
                cx.expect_version("owner", other, vo)?;
                if revoked(ns) <= r || revoked(other) != ro {
                    return Err(format!(
                        "revoking {device}: {ns}'s CA records {} revoked (was {r}), {other}'s {} (was {ro})",
                        revoked(ns),
                        revoked(other)
                    ));
                }
                cx.evidence(&format!(
                    "revoke {device}: {ns} v{v} → v{}, its CA records the revocation; {other} stays v{vo}",
                    v + 1
                ));
            }
            cx.stop("temp");
            Ok(())
        },
    )?;

    let dev_a = format!("{A}/member/dev");
    let dev_c = format!("{C}/member/dev");
    let node_key = sc.step(
        "dev enrolls in /mpa by invite: its first identity becomes its node identity",
        |cx| {
            cx.start("dev")?;
            enroll(cx, "dev", &inv_a[0], "dev", false, None)?;
            let s = expect_prefixes(cx, "dev", &[(A, "member", "member", true)])?;
            cx.evidence(&format!("dev: {}", s.node()));
            if s.field("identity") != Some(dev_a.as_str()) {
                return Err(format!("dev's {}, expected {dev_a}", s.node()));
            }
            s.field("key")
                .map(str::to_owned)
                .ok_or_else(|| "dev's identity status names no key".to_owned())
        },
    )?;
    sc.step(
        "dev enrolls in /mpc by invite: the /mpc identity is added beside /mpa's, and dev signs Data as these two only; the node identity and key stay /mpa's",
        |cx| {
            enroll(cx, "dev", &inv_c[0], "dev", false, None)?;
            let s = expect_prefixes(
                cx,
                "dev",
                &[(A, "member", "member", true), (C, "member", "member", false)],
            )?;
            cx.evidence(&format!(
                "dev: {}; signs Data as {:?}",
                s.node(),
                s.all("signing_identity")
            ));
            if s.field("identity") != Some(dev_a.as_str()) || s.field("key") != Some(node_key.as_str()) {
                return Err(format!("dev's {}, expected {dev_a} with key {node_key}", s.node()));
            }
            // The key minted at startup left with the first enrolment.
            let mut signs = s.all("signing_identity");
            signs.sort_unstable();
            if signs != [dev_a.as_str(), dev_c.as_str()] {
                return Err(format!("dev signs Data as {signs:?}, expected {dev_a} and {dev_c} only"));
            }
            Ok(())
        },
    )?;
    sc.step(
        "dev adopts /mpb only: its trusted prefixes are /mpa member (node identity), /mpc member, /mpb following",
        |cx| {
            let op = cx
                .tool("ndn-fwd")
                .arg("adopt")
                .arg(&b.link_fp)
                .arg("-c")
                .arg(cx.w.node("dev").cfg_arg());
            cx.ok(op, "adopt /mpb")?;
            cx.expect_version("dev", B, 1)?;
            expect_prefixes(
                cx,
                "dev",
                &[
                    (A, "member", "member", true),
                    (B, "following", "", false),
                    (C, "member", "member", false),
                ],
            )?;
            Ok(())
        },
    )?;

    let doc_a = content(20_000, 101);
    let doc_c = content(20_000, 102);
    sc.step(
        "dev publishes under /mpa and /mpc with ndn-put and no --identity: owner validates /mpa's Data signed by dev's /mpa key and /mpc's by its /mpc key",
        |cx| {
            cx.publish("dev", &format!("{dev_a}/doc"), &doc_a, None, None)?;
            cx.publish("dev", &format!("{dev_c}/doc"), &doc_c, None, None)?;
            signed_by(cx, "owner", &format!("{dev_a}/doc"), &doc_a, &dev_a)?;
            signed_by(cx, "owner", &format!("{dev_c}/doc"), &doc_c, &dev_c)
        },
    )?;
    sc.step(
        "dev cannot publish under /mpb, which it only follows: ndn-put is refused, saying which trusted prefix",
        |cx| {
            let (dir, sock, pib) = {
                let n = cx.w.node("dev");
                (n.dir.clone(), n.sock(), n.pib())
            };
            let file = dir.join("mpb-note.bin");
            std::fs::write(&file, b"not dev's to sign").map_err(|e| e.to_string())?;
            let op = cx
                .tool("ndn-put")
                .arg("--face-socket")
                .arg(sock.display().to_string())
                .arg("--pib")
                .arg(pib.display().to_string())
                .arg(format!("{B}/notes/dev"))
                .arg(file.display().to_string())
                .timeout(Duration::from_secs(20));
            let out = cx.refused(op, "ndn-put under /mpb")?;
            // The refusal is the last thing it says.
            let why = out
                .stdout
                .lines()
                .chain(out.stderr.lines())
                .rfind(|l| l.contains(B))
                .ok_or_else(|| format!("the refusal does not name {B}: {}", out.stderr.trim()))?;
            cx.evidence(&format!("refused: {}", why.trim()));
            Ok(())
        },
    )?;
    let doc_b = content(12_000, 103);
    sc.step("dev verifies /mpb's Data, which it follows", |cx| {
        let name = format!("{}/notes", b.identity);
        cx.publish("rootb", &name, &doc_b, None, None)?;
        signed_by(cx, "dev", &name, &doc_b, &b.identity)
    })?;
    sc.step(
        "dev's management responses stay signed with its node key (/mpa's), not /mpc's",
        |cx| {
            let key = key_locator(cx, "dev", "/localhost/nfd/status/general")?;
            cx.evidence(&format!("dev's status dataset: KeyLocator {key}"));
            if !key.contains(&node_key) {
                return Err(format!(
                    "dev's management response is signed by {key}, expected its node key {node_key}"
                ));
            }
            Ok(())
        },
    )?;

    sc.step(
        "relay (listening for QUIC links) adopts /mpc and becomes a node device of /mpc only, on owner's approval",
        |cx| {
            cx.start("relay")?;
            let op = cx
                .tool("ndn-fwd")
                .arg("adopt")
                .arg(&c.link_fp)
                .arg("-c")
                .arg(cx.w.node("relay").cfg_arg());
            cx.ok(op, "adopt /mpc")?;
            cx.expect_version("relay", C, version(cx, C))?;
            enroll_by_approval_at(cx, C, &c.link_fp, "owner", "relay")?;
            let s = expect_prefixes(cx, "relay", &[(C, "member", "node", true)])?;
            if s.prefixes.len() != 1 {
                return Err(format!("relay takes part in {:?}, expected {C} only", s.prefixes));
            }
            Ok(())
        },
    )?;
    sc.step(
        "cfan enrolls in /mpc by invite, then reaches /mpc only over a QUIC link to the relay",
        |cx| {
            cx.start("cfan")?;
            enroll(cx, "cfan", &inv_c[2], "cfan", false, None)?;
            let cfan = cx.w.node_mut("cfan");
            cfan.cfg.links.clear();
            cfan.cfg.routes.clear();
            cfan.cfg.peers = vec![relay_peer()];
            cfan.cfg.quic_dial_only = true;
            cfan.cfg.extra_toml = NO_DIRECT.into();
            cx.stop("cfan");
            cx.start("cfan")?;
            let device = format!("{C}/member/cfan");
            wait_for(cx, "the relay links to cfan's /mpc device", SHORT, |cx| {
                let list = link_list(cx, "relay")?;
                Ok(list.to(&device, None).is_some_and(|l| !l.paths.is_empty()))
            })?;
            Ok(())
        },
    )?;
    sc.step(
        "dev names the relay ([[peer]]) and restarts: its node identity is still /mpa's; the relay, serving only /mpc, admits it by its /mpc membership on its /mpa link key and names its /mpc device",
        |cx| {
            let dev = cx.w.node_mut("dev");
            dev.cfg.peers = vec![relay_peer()];
            dev.cfg.quic_dial_only = true;
            dev.cfg.extra_toml = NO_DIRECT.into();
            cx.stop("dev");
            cx.start("dev")?;
            let s = signing(cx, "dev")?;
            cx.evidence(&format!(
                "dev after its restart: {}; signs Data as {:?}",
                s.node(),
                s.all("signing_identity")
            ));
            if s.field("identity") != Some(dev_a.as_str()) || s.field("key") != Some(node_key.as_str()) {
                return Err(format!("dev's {} after its restart, expected {dev_a} with key {node_key}", s.node()));
            }
            let dev_link_key = link_list(cx, "dev")?
                .key
                .ok_or("dev's link list shows no key of its own")?;
            // The link (TLS) key is the node key, /mpa's: its fingerprint is
            // the /mpa key's, not the /mpc key's.
            let pib = cx.w.node("dev").pib();
            let fp_a = fingerprint(&pib, &node_key)?;
            let key_c = identity_key(&pib, &dev_c)?;
            let fp_c = fingerprint(&pib, &key_c)?;
            cx.evidence(&format!(
                "dev's link key {dev_link_key}; {node_key}: {fp_a}; {key_c}: {fp_c}"
            ));
            if dev_link_key != fp_a || fp_a == fp_c {
                return Err(format!(
                    "dev's link key {dev_link_key} is not its /mpa key {node_key} ({fp_a}; /mpc key {fp_c})"
                ));
            }
            let mut seen = String::new();
            wait_for(cx, "the relay links to dev, named by its /mpc device", SHORT, |cx| {
                let list = link_list(cx, "relay")?;
                let Some(l) = list.links.iter().find(|l| l.key.as_deref() == Some(dev_link_key.as_str())) else {
                    return Ok(false);
                };
                seen = format!("label {}, device {:?}, {} path(s)", l.label, l.device, l.paths.len());
                Ok(l.device.as_deref() == Some(dev_c.as_str()) && !l.paths.is_empty())
            })
            .map_err(|e| format!("{e}; relay's link with dev's key: {seen}"))?;
            cx.evidence(&format!("relay → dev (link key {dev_link_key}): {seen}"));
            Ok(())
        },
    )?;
    let relayed = content(40_000, 104);
    sc.step(
        "dev's /mpc Data reaches cfan through the relay, signed by dev's /mpc key",
        |cx| {
            let name = format!("{dev_c}/relayed");
            cx.publish("dev", &name, &relayed, None, None)?;
            let before = relay_packets(cx)?;
            signed_by(cx, "cfan", &name, &relayed, &dev_c)?;
            let after = relay_packets(cx)?;
            let segments = relayed.len().div_ceil(SEGMENT) as u64;
            cx.evidence(&format!(
                "{segments} segments; relay packets on dev's and cfan's links {before} → {after}"
            ));
            if after.saturating_sub(before) < segments {
                return Err(format!(
                    "the relay carried {} packets for {segments} segments: the fetch did not go through it",
                    after.saturating_sub(before)
                ));
            }
            Ok(())
        },
    )?;
    Ok(())
}
