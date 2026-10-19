//! The scenarios, and the steps several of them share.

use std::net::Ipv4Addr;
use std::thread;
use std::time::{Duration, Instant};

use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{addr, now_unix, parse_utc};

mod approval;
mod compromised;
mod destroyed;
mod direct_paths;
mod lifecycle;
mod membership;
mod multi_prefix;
mod negatives;
mod on_demand;
mod phone_links;
mod quic_links;
mod relays;
mod tui;

pub const ALL: &[&str] = &[
    "lifecycle",
    "lifecycle-push",
    "recovery-destroyed",
    "recovery-compromised",
    "negatives",
    "approval",
    "quic-links",
    "direct-paths",
    "phone-links",
    "relays",
    "on-demand",
    "membership",
    "multi-prefix",
    "tui",
];

pub fn run(name: &str, sc: &mut Scenario) -> Result<(), Abort> {
    match name {
        "lifecycle" => lifecycle::run(sc, false),
        "lifecycle-push" => lifecycle::run(sc, true),
        "recovery-destroyed" => destroyed::run(sc),
        "recovery-compromised" => compromised::run(sc),
        "negatives" => negatives::run(sc),
        "approval" => approval::run(sc),
        "quic-links" => quic_links::run(sc),
        "direct-paths" => direct_paths::run(sc),
        "phone-links" => phone_links::run(sc),
        "relays" => relays::run(sc),
        "on-demand" => on_demand::run(sc),
        "membership" => membership::run(sc),
        "multi-prefix" => multi_prefix::run(sc),
        "tui" => tui::run(sc),
        other => unreachable!("unknown scenario {other}"),
    }
}

pub const ROOT_PASS: &str = "e2e root passphrase: correct horse";
pub const NEW_ROOT_PASS: &str = "e2e replacement root passphrase";
pub const KIT_PASS: &str = "e2e kit passphrase: battery staple";
pub const KIT2_PASS: &str = "e2e second kit passphrase";
pub const WRONG_PASS: &str = "not the passphrase";

pub fn link(name: &str, host: u8) -> (String, Ipv4Addr) {
    (name.to_owned(), addr(host))
}

pub fn route(prefix: impl Into<String>, link: &str) -> (String, String) {
    (prefix.into(), link.to_owned())
}

/// Random bytes (the content a member publishes).
pub fn content(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed
        ^ (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0));
    (0..len)
        .map(|_| {
            // xorshift64*
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            (x.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
        })
        .collect()
}

/// What `ndn-fwd init` (or `recover`) tells the operator about a root.
#[derive(Clone, Debug)]
pub struct RootInfo {
    pub fp: String,
    /// `anchor_uri_fp`: namespace + expected fingerprint (+ version).
    pub link_fp: String,
    /// `anchor_uri`: the whole trust context inline.
    pub link_inline: String,
    /// `[security] identity` to sign as.
    pub identity: String,
    pub ca_key: String,
}

/// The first whitespace-separated token of a `key = value` value.
pub fn first(v: Option<String>) -> Option<String> {
    v.and_then(|s| s.split_whitespace().next().map(str::to_owned))
}

pub fn root_info(out: &crate::run::Out) -> StepResult<RootInfo> {
    let need = |k: &str| first(out.kv(k)).ok_or_else(|| format!("no `{k}` in the output"));
    let identity = out
        .kv_all("identity")
        .first()
        .map(|s| s.trim_matches('"').to_owned())
        .ok_or("no [security] identity line in the output")?;
    Ok(RootInfo {
        fp: need("anchor_fp")?,
        link_fp: need("anchor_uri_fp")?,
        link_inline: need("anchor_uri")?,
        identity,
        ca_key: need("ca_key")?,
    })
}

/// `ndn-fwd init` with a sealed-file root on `node`'s PIB.
pub fn init_root(cx: &mut Cx<'_>, node: &str, ns: &str, device: &str) -> StepResult<RootInfo> {
    init_root_with(cx, node, ns, device, false).map(|(info, _)| info)
}

/// `ndn-fwd init` with a sealed-file root on `node`'s PIB; with `config`,
/// `-c` names `node`'s config, written first from its current settings
/// (its `[ca]` link keys and `[[ca.relay]]` go into the trust context).
/// The init output too.
pub fn init_root_with(
    cx: &mut Cx<'_>,
    node: &str,
    ns: &str,
    device: &str,
    config: bool,
) -> StepResult<(RootInfo, crate::run::Out)> {
    let pib = cx.w.node(node).pib();
    let mut op = cx
        .tool("ndn-fwd")
        .args(["init", "--namespace", ns, "--device", device, "--pib"])
        .arg(pib.display().to_string())
        .args(["--root-store", "sealed-file"])
        .env("NDN_ROOT_PASSPHRASE", ROOT_PASS);
    if config {
        let n = cx.w.node(node);
        std::fs::write(n.config(), n.render())
            .map_err(|e| format!("{}: {e}", n.config().display()))?;
        op = op.arg("-c").arg(n.cfg_arg());
    }
    let out = cx.ok(op, "init")?;
    cx.expect_version(node, ns, 1)?;
    // Each trusted prefix's root store sits in its own directory
    // (`<pib>/root/<hex of the prefix>/`), beside the others of the PIB.
    let ns_name: ndn_packet::Name = ns.parse().map_err(|e| format!("{ns}: {e:?}"))?;
    let sealed = ndn_cert::root_store_dir(&pib, &ns_name).join("root.safebag");
    if !sealed.exists() {
        return Err(format!(
            "init: no sealed root ({}) in the PIB",
            sealed.display()
        ));
    }
    let info = root_info(&out)?;
    // The root's private key is sealed, never a PIB key.
    let root_keys: Vec<String> = cx
        .certs(node)
        .into_iter()
        .filter(|c| c.starts_with(&format!("{ns}/KEY/")))
        .collect();
    if !root_keys.is_empty() {
        return Err(format!(
            "init: a root key sits in the PIB in plaintext: {root_keys:?}"
        ));
    }
    Ok((info, out))
}

/// An invite the CA made: its id (to withdraw it) and its link (to hand
/// on).
#[derive(Clone, Debug)]
pub struct Invite {
    pub id: String,
    pub link: String,
}

/// `ndn-fwd-tokens new` at the running CA of `ns` on `node`: member invites.
/// Each link must carry `fp`, the namespace's expected fingerprint.
pub fn mint(
    cx: &mut Cx<'_>,
    node: &str,
    ns: &str,
    fp: &str,
    count: u32,
    ttl: Option<&str>,
) -> StepResult<Vec<Invite>> {
    mint_as(cx, node, ns, fp, "member", count, ttl)
}

/// `ndn-fwd-tokens new` at the running CA of `ns` on `node` (its daemon
/// makes and records them): invites for `role` (`member` or `guest`), each
/// link carrying `fp`.
pub fn mint_as(
    cx: &mut Cx<'_>,
    node: &str,
    ns: &str,
    fp: &str,
    role: &str,
    count: u32,
    ttl: Option<&str>,
) -> StepResult<Vec<Invite>> {
    let mut op = cx
        .tool("ndn-fwd-tokens")
        .arg("-c")
        .arg(cx.w.node(node).cfg_arg())
        .args(["new", "--namespace", ns, "--role", role])
        .arg("--count")
        .arg(count.to_string());
    if let Some(t) = ttl {
        op = op.arg("--ttl").arg(t);
    }
    let out = cx.ok(op, "make invites")?;
    let ids = out.kv_all("id");
    let tokens: Vec<String> = out
        .kv_all("token")
        .iter()
        .filter_map(|v| v.split('"').nth(1).map(str::to_owned))
        .collect();
    let links = out.kv_all("invite");
    if ids.len() != count as usize
        || tokens.len() != count as usize
        || links.len() != count as usize
    {
        return Err(format!(
            "expected {count} invites, got ids {ids:?}, tokens {tokens:?}, links {links:?}"
        ));
    }
    for (link, token) in links.iter().zip(&tokens) {
        let read = ndn_cert::InviteLink::from_uri(link)
            .map_err(|e| format!("unreadable invite link {link}: {e}"))?;
        if &read.token != token {
            return Err(format!(
                "the link {link} carries another token than {token}"
            ));
        }
        let carried = read
            .expected_fingerprint
            .map(|f| f.iter().map(|b| format!("{b:02x}")).collect::<String>());
        if carried.as_deref() != Some(fp) {
            return Err(format!(
                "the invite carries the fingerprint {carried:?}, not the root's {fp}"
            ));
        }
    }
    Ok(ids
        .into_iter()
        .zip(links)
        .map(|(id, link)| Invite { id, link })
        .collect())
}

/// `ndn-fwd enroll <invite> --device <device>` on `node`; the new
/// certificate's name, checked to be in the PIB and issued for at most
/// `max_days`.
pub fn enroll(
    cx: &mut Cx<'_>,
    node: &str,
    invite: &Invite,
    device: &str,
    force: bool,
    max_days: Option<i64>,
) -> StepResult<String> {
    let before = cx.certs(node);
    let mut op = cx
        .tool("ndn-fwd")
        .arg("enroll")
        .arg(&invite.link)
        .args(["--device", device, "-c"])
        .arg(cx.w.node(node).cfg_arg());
    if force {
        op = op.arg("--force");
    }
    let out = cx.ok(op, "enroll")?;
    let new_cert = new_cert(cx, node, &before)?;
    if let Some(days) = max_days {
        check_lifetime(&out, days)?;
    }
    Ok(new_cert)
}

/// `node` becomes a `node` device of `ns` on the approval of the node
/// named `root` (the root device running `ns`'s CA).
pub fn enroll_by_approval(
    cx: &mut Cx<'_>,
    ns: &str,
    root_link: &str,
    node: &str,
) -> StepResult<()> {
    enroll_by_approval_at(cx, ns, root_link, "root", node)
}

/// `node` becomes a `node` device of `ns` on the approval of `root`, the
/// node running `ns`'s CA.
pub fn enroll_by_approval_at(
    cx: &mut Cx<'_>,
    ns: &str,
    root_link: &str,
    root: &str,
    node: &str,
) -> StepResult<()> {
    let before = cx.certs(node);
    let op = cx
        .tool("ndn-fwd")
        .arg("enroll")
        .arg(root_link)
        .args(["--role", "node", "--device", node, "-c"])
        .arg(cx.w.node(node).cfg_arg());
    let out = cx.ok(op, "enroll --role node")?;
    let code = out.kv("code").ok_or("no code in the enroll output")?;
    let approve = cx
        .tool("ndn-fwd")
        .args(["approvals", "approve"])
        .args(code.split_whitespace())
        .arg("-c")
        .arg(cx.w.node(root).cfg_arg());
    cx.ok(approve, "approve")?;
    let device = format!("{ns}/node/{node}");
    let start = Instant::now();
    loop {
        if let Ok(cert) = new_cert(cx, node, &before)
            && cert.starts_with(&format!("{device}/KEY/"))
        {
            return Ok(());
        }
        if start.elapsed() > SHORT {
            return Err(format!(
                "{node} holds no {device} certificate {}s after the approval",
                SHORT.as_secs()
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// The certificate in `node`'s PIB that `before` did not list.
pub fn new_cert(cx: &Cx<'_>, node: &str, before: &[String]) -> StepResult<String> {
    let after = cx.certs(node);
    let fresh: Vec<&String> = after.iter().filter(|c| !before.contains(c)).collect();
    match fresh.as_slice() {
        [one] => Ok((*one).clone()),
        _ => Err(format!(
            "expected exactly one new certificate in {node}'s PIB; before {before:?}, after {after:?}"
        )),
    }
}

/// `valid_until` (e.g. `20270115T172028Z`) at most `days` from now.
pub fn check_lifetime(out: &crate::run::Out, days: i64) -> StepResult<()> {
    let v = first(out.kv("valid_until")).ok_or("no valid_until in the output")?;
    let iso = if v.contains('-') {
        v.clone()
    } else if v.len() == 16 {
        format!(
            "{}-{}-{}T{}:{}:{}Z",
            &v[0..4],
            &v[4..6],
            &v[6..8],
            &v[9..11],
            &v[11..13],
            &v[13..15]
        )
    } else {
        return Err(format!("unreadable valid_until {v}"));
    };
    let until = parse_utc(&iso).ok_or_else(|| format!("unreadable valid_until {v}"))?;
    let left = until - now_unix();
    if left <= 0 || left > days * 86400 + 300 {
        return Err(format!(
            "certificate valid until {v}: {left} s from now, expected at most {days} day(s)"
        ));
    }
    Ok(())
}

/// The 24 numbered words `recovery-kit create --format words` prints.
pub fn words(out: &crate::run::Out) -> StepResult<Vec<String>> {
    let w: Vec<String> = out
        .stdout
        .lines()
        .filter_map(|l| {
            let (n, word) = l.trim().split_once(". ")?;
            n.parse::<u32>().ok()?;
            let word = word.trim();
            word.chars()
                .all(|c| c.is_ascii_lowercase())
                .then(|| word.to_owned())
        })
        .collect();
    if w.len() == 24 {
        Ok(w)
    } else {
        Err(format!("expected 24 recovery words, found {}", w.len()))
    }
}

/// Fetch through each of `nodes`; every one must return `expect`.
pub fn fetch_all(cx: &mut Cx<'_>, nodes: &[&str], name: &str, expect: &[u8]) -> StepResult<()> {
    for n in nodes {
        cx.fetch_ok(n, name, expect)?;
    }
    Ok(())
}

/// Fetch `name` at `node` until it is delivered, within `within`: the link
/// or path it needs comes up (or becomes a full link) on its own.
pub fn fetch_within(
    cx: &mut Cx<'_>,
    node: &str,
    name: &str,
    expect: &[u8],
    within: Duration,
) -> StepResult<()> {
    let start = Instant::now();
    loop {
        match cx.fetch_ok(node, name, expect) {
            Ok(()) => {
                cx.note(&format!(
                    "{node} fetched {name} after {:.2}s",
                    start.elapsed().as_secs_f64()
                ));
                return Ok(());
            }
            Err(e) if start.elapsed() > within => {
                return Err(format!("after {}s: {e}", within.as_secs()));
            }
            Err(_) => thread::sleep(Duration::from_millis(250)),
        }
    }
}

/// Wait until `done`, polling; how long it took.
pub fn wait_for(
    cx: &mut Cx<'_>,
    what: &str,
    within: Duration,
    mut done: impl FnMut(&mut Cx<'_>) -> StepResult<bool>,
) -> StepResult<Duration> {
    let start = Instant::now();
    loop {
        if done(cx)? {
            let took = start.elapsed();
            cx.note(&format!("{what} after {:.2}s", took.as_secs_f64()));
            return Ok(took);
        }
        if start.elapsed() > within {
            return Err(format!("not within {}s: {what}", within.as_secs()));
        }
        thread::sleep(Duration::from_millis(200));
    }
}

pub const SHORT: Duration = Duration::from_secs(30);
