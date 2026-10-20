//! dv: ndn-dv routing between daemons, multi-hop, withdrawal and a cost
//! change.
//!
//! Topology, all on the harness's `lo`: a (10.200.0.1) — b (.2) — c (.3) in
//! a line, each a DV router of /dvnet (`[routing.dv]`, `/dvnet/<node>`) with
//! a `[[routing.dv.neighbor]]` per neighbour (the daemon opens a UDP socket
//! to the neighbour's listener). No `[[face]]` links and no `[[route]]`:
//! every route between them is DV's. Adv sync runs every 1 s and a
//! neighbour silent for 3 s is dead (checked every 750 ms), so routes
//! between routers converge in seconds. Pfx Sync keeps its default 30 s
//! period: a prefix (or its withdrawal) reaching a in seconds was relayed
//! by b at once, not carried by b's periodic Pfx Sync.
//! DV's own trust is its default, `insecure` (Adv/Pfx Data signed
//! DigestSha256), so the daemons need no DV key exchange; the forwarders
//! still validate every Data. c is the root device of /dvapp and serves
//! under `/dvapp/admin/c/app` (not its device prefix itself, under which
//! its certificates answer a CanBePrefix fetch too); a and b adopt /dvapp
//! from the inline anchor link, so they validate c's Data.
//!
//! Proves: a prefix c's producer registers (rib/register, origin app) is
//! announced by DV and installed at b (origin dvr, cost 1, via its face to
//! c) and at a (cost 2, via its face to b: learned through b), and a fetches
//! c's bytes over those routes; once the producer stops, the route goes at a
//! and a fetch there gets nothing; it comes back when the producer does; a
//! direct a–c link (a and c restarted with each other as a further
//! neighbour) moves a's route to its face to c at cost 1, and cutting that
//! link (nftables) moves it back to its face to b at cost 2, the fetch
//! working on each path.
//!
//! Routes are read from `ndn-ctl route rib-list` (origin 127 shows as
//! `dvr`), faces from `ndn-ctl face list`. DV binds a neighbour to the face
//! its Sync Interests arrive on: the face a node's listener made for the
//! neighbour's DV socket, so a node's face to neighbour n is its UDP face
//! whose remote is the local address of n's DV face to that node. Content
//! stores keep Data after its producer has gone, so before each fetch at a
//! the harness erases c's prefix from every content store (`ndn-ctl cs
//! erase`): the bytes a gets come from c's producer over the route under
//! test.

use std::fs;
use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use super::quic_links::fetch_fails;
use crate::run::Op;
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{NodeCfg, PORT, addr};

const NS: &str = "/dvapp";
/// The DV network; router names are `/dvnet/<node>`.
const NET: &str = "/dvnet";
/// `adv_sync_secs`; `pfx_sync_secs` stays at its default (30).
const ADV_SYNC_SECS: u64 = 1;
/// `router_dead_secs`: a neighbour silent this long is dropped (checked
/// every quarter of it).
const DEAD_SECS: u64 = 3;
/// How long a route change may take to show: well under the 30 s Pfx Sync
/// period, so a prefix route that appears or goes within it got there by
/// relayed Pfx Sync, not a periodic one.
const CONVERGE: Duration = Duration::from_secs(10);
/// The nftables table that cuts a–c.
const CUT_TABLE: &str = "ndn_e2e_dv_cut";
/// What `ndn-ctl route rib-list` shows for origin 127 (DVR).
const DVR: &str = "dvr";

fn host(node: &str) -> u8 {
    match node {
        "a" => 1,
        "b" => 2,
        "c" => 3,
        other => unreachable!("no dv node {other}"),
    }
}

/// `[routing.dv]` of router `/dvnet/<node>` with a neighbour socket to each
/// of `neighbours`.
fn dv_toml(node: &str, neighbours: &[&str]) -> String {
    let mut s = format!(
        "[routing.dv]\nenabled = true\nnetwork = \"{NET}\"\nrouter = \"{NET}/{node}\"\n\
         adv_sync_secs = {ADV_SYNC_SECS}\nrouter_dead_secs = {DEAD_SECS}\n"
    );
    for n in neighbours {
        s.push_str(&format!(
            "\n[[routing.dv.neighbor]]\nname = \"{NET}/{n}\"\nface_uri = \"udp4://{}:{PORT}\"\n",
            addr(host(n))
        ));
    }
    s
}

/// One route of a RIB entry.
#[derive(Clone, Debug)]
struct Route {
    face: u64,
    origin: String,
    cost: u64,
}

/// `node`'s RIB routes for exactly `prefix` (harness inspection).
fn routes(cx: &mut Cx<'_>, node: &str, prefix: &str) -> StepResult<Vec<Route>> {
    let sock = cx.w.node(node).sock().display().to_string();
    let op = cx
        .tool("ndn-ctl")
        .args(["--socket", &sock, "route", "rib-list"]);
    let out = cx.exec(op);
    if !out.success() {
        return Err(format!("route rib-list on {node}: {}", out.status_text()));
    }
    // `<prefix>  <face>  <origin>  <cost>  <flags>[  expiry=…]`
    Ok(out
        .stdout
        .lines()
        .filter_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            match w.as_slice() {
                [p, face, origin, cost, ..] if *p == prefix => Some(Route {
                    face: face.parse().ok()?,
                    origin: (*origin).to_owned(),
                    cost: cost.parse().ok()?,
                }),
                _ => None,
            }
        })
        .collect())
}

/// The cheapest DV route of `routes`.
fn best(routes: &[Route]) -> Option<&Route> {
    routes
        .iter()
        .filter(|r| r.origin == DVR)
        .min_by_key(|r| r.cost)
}

fn show(routes: &[Route]) -> String {
    if routes.is_empty() {
        return "no route".to_owned();
    }
    routes
        .iter()
        .map(|r| format!("face {} origin {} cost {}", r.face, r.origin, r.cost))
        .collect::<Vec<_>>()
        .join("; ")
}

/// `node`'s UDP faces: id, remote and local address (harness inspection).
fn udp_faces(
    cx: &mut Cx<'_>,
    node: &str,
) -> StepResult<Vec<(u64, SocketAddrV4, Option<SocketAddrV4>)>> {
    let sock = cx.w.node(node).sock().display().to_string();
    let op = cx
        .tool("ndn-ctl")
        .args(["--socket", &sock, "face", "list", "--scheme", "udp4"]);
    let out = cx.exec(op);
    if !out.success() {
        return Err(format!("face list on {node}: {}", out.status_text()));
    }
    let udp = |s: &str| {
        s.trim()
            .strip_prefix("udp4://")?
            .parse::<SocketAddrV4>()
            .ok()
    };
    let mut rows: Vec<(Option<u64>, Option<SocketAddrV4>, Option<SocketAddrV4>)> = Vec::new();
    for line in out.stdout.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("faceid=") {
            let id = rest.split_whitespace().next().and_then(|s| s.parse().ok());
            rows.push((id, None, None));
            continue;
        }
        let Some(row) = rows.last_mut() else { continue };
        if let Some(r) = t.strip_prefix("remote:") {
            row.1 = udp(r);
        } else if let Some(l) = t.strip_prefix("local:") {
            row.2 = udp(l);
        }
    }
    Ok(rows
        .into_iter()
        .filter_map(|(id, remote, local)| Some((id?, remote?, local)))
        .collect())
}

/// The address of `node`'s DV socket to neighbour `peer`: the local
/// address of its UDP face to `peer`'s listener.
fn dv_socket(cx: &mut Cx<'_>, node: &str, peer: &str) -> StepResult<SocketAddrV4> {
    let listener = SocketAddrV4::new(addr(host(peer)), PORT);
    udp_faces(cx, node)?
        .into_iter()
        .find_map(|(_, remote, local)| local.filter(|_| remote == listener))
        .ok_or_else(|| format!("{node}: no DV socket to {peer}'s listener {listener}"))
}

/// The face `node` reaches DV neighbour `peer` over: the one its listener
/// made for `peer`'s DV socket to it. Its id, and that socket's address.
fn face_to(cx: &mut Cx<'_>, node: &str, peer: &str) -> StepResult<(u64, SocketAddrV4)> {
    let theirs = dv_socket(cx, peer, node)?;
    udp_faces(cx, node)?
        .into_iter()
        .find(|(_, remote, _)| *remote == theirs)
        .map(|(id, _, _)| (id, theirs))
        .ok_or_else(|| format!("{node}: no face for {peer}'s DV socket {theirs}"))
}

/// Wait until `node`'s cheapest DV route for `prefix` is via its face to
/// `via` at `cost` and none is via face `not_via`; evidence. The face's id.
fn wait_best(
    cx: &mut Cx<'_>,
    node: &str,
    prefix: &str,
    (via, cost): (&str, u64),
    not_via: Option<u64>,
) -> StepResult<u64> {
    let what = format!("{node} routes {prefix} via its face to {via} at cost {cost}");
    let mut seen = Vec::new();
    let mut face = None;
    let took = wait_for(cx, &what, CONVERGE, |cx| {
        face = face_to(cx, node, via).ok();
        seen = routes(cx, node, prefix)?;
        let Some((f, _)) = face else { return Ok(false) };
        Ok(best(&seen).is_some_and(|r| r.face == f && r.cost == cost)
            && not_via.is_none_or(|n| !seen.iter().any(|r| r.face == n)))
    })
    .map_err(|e| {
        let to = face.map_or("not found".to_owned(), |(f, _)| f.to_string());
        format!(
            "{e}; {node} routes {prefix}: {}; its face to {via}: {to}",
            show(&seen)
        )
    })?;
    let (f, theirs) = face.ok_or("no face after the wait")?;
    cx.evidence(&format!(
        "{node} routes {prefix}: {} (face {f}: {node}'s face to {via}, for {via}'s DV socket \
         {theirs}) after {:.2}s",
        show(&seen),
        took.as_secs_f64()
    ));
    Ok(f)
}

/// Wait until `node` holds no route for `prefix` of `origin`; evidence.
fn wait_gone(cx: &mut Cx<'_>, node: &str, prefix: &str, origin: &str) -> StepResult<()> {
    let what = format!("{node}'s {origin} route for {prefix} gone");
    let mut seen = Vec::new();
    let took = wait_for(cx, &what, CONVERGE, |cx| {
        seen = routes(cx, node, prefix)?;
        Ok(!seen.iter().any(|r| r.origin == origin))
    })
    .map_err(|e| format!("{e}; {node} routes {prefix}: {}", show(&seen)))?;
    cx.evidence(&format!(
        "{node} routes {prefix}: {} ({origin} route gone after {:.2}s)",
        show(&seen),
        took.as_secs_f64()
    ));
    Ok(())
}

/// Erase `prefix` from every content store (harness inspection), so the
/// next fetch at a is answered by c's producer, not a cached copy.
fn uncache(cx: &mut Cx<'_>, prefix: &str) -> StepResult<()> {
    for node in ["a", "b", "c"] {
        let sock = cx.w.node(node).sock().display().to_string();
        let op = cx
            .tool("ndn-ctl")
            .args(["--socket", &sock, "cs", "erase", prefix]);
        let out = cx.exec(op);
        if !out.success() {
            return Err(format!("cs erase on {node}: {}", out.status_text()));
        }
    }
    Ok(())
}

/// a fetches `prefix` from c's producer: the bytes must equal `expect`.
fn fetch_from_c(cx: &mut Cx<'_>, prefix: &str, expect: &[u8]) -> StepResult<()> {
    uncache(cx, prefix)?;
    fetch_within(cx, "a", prefix, expect, SHORT)?;
    cx.evidence(&format!(
        "a fetched {prefix}: {} bytes, equal to c's published bytes",
        expect.len()
    ));
    Ok(())
}

/// The nftables table dropping a–c's UDP; deleted on drop.
struct Cut;

impl Drop for Cut {
    fn drop(&mut self) {
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", CUT_TABLE])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Drop UDP between a's and c's addresses, both ways, as it leaves a socket
/// in the harness's namespace (on `lo` nothing is forwarded). Each DV socket
/// sends from its daemon's listener address and each listener answers from
/// it, so this cuts a–c and leaves a–b and b–c.
fn cut(cx: &mut Cx<'_>) -> StepResult<Cut> {
    let (a, c) = (addr(host("a")), addr(host("c")));
    let ruleset = format!(
        "table inet {CUT_TABLE} {{\n\
         \tchain output {{\n\
         \t\ttype filter hook output priority 0;\n\
         \t\tip saddr {a} ip daddr {c} meta l4proto udp drop;\n\
         \t\tip saddr {c} ip daddr {a} meta l4proto udp drop;\n\
         \t}}\n\
         }}\n"
    );
    let file = cx.w.dir.join("cut.nft");
    fs::write(&file, ruleset).map_err(|e| format!("{}: {e}", file.display()))?;
    let op = Op::new("nft", PathBuf::from("nft"))
        .arg("-f")
        .arg(file.display().to_string());
    let out = cx.exec(op);
    if !out.success() {
        return Err(format!("nft -f {}: {}", file.display(), out.status_text()));
    }
    Ok(Cut)
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    let node = |name: &str, neighbours: &[&str]| NodeCfg {
        extra_toml: dv_toml(name, neighbours),
        ..Default::default()
    };
    sc.world.add("a", host("a"), node("a", &["b"]));
    sc.world.add("b", host("b"), node("b", &["a", "c"]));
    sc.world.add("c", host("c"), node("c", &["b"]));

    let root = sc.step(
        "c makes /dvapp (init, sealed-file root): its producer's Data validates where /dvapp \
         is held",
        |cx| init_root(cx, "c", NS, "c"),
    )?;
    // Under c's device identity, so c may sign it.
    let prefix = format!("{}/app", root.identity);
    sc.step(
        &format!(
            "start a, b and c as DV routers of {NET} in a line (a–b, b–c; Adv sync every \
             {ADV_SYNC_SECS} s, Pfx Sync at its default 30 s, dead after {DEAD_SECS} s)"
        ),
        |cx| {
            cx.w.node_mut("c").cfg.identity = Some(root.identity.clone());
            for n in ["a", "b", "c"] {
                cx.start(n)?;
            }
            Ok(())
        },
    )?;
    sc.step("a and b adopt /dvapp from the inline anchor link", |cx| {
        for n in ["a", "b"] {
            let op = cx
                .tool("ndn-fwd")
                .arg("adopt")
                .arg(&root.link_inline)
                .arg("-c")
                .arg(cx.w.node(n).cfg_arg());
            cx.ok(op, "adopt")?;
            cx.expect_version(n, NS, 1)?;
        }
        Ok(())
    })?;

    let doc1 = content(20_000, 1);
    sc.step(
        &format!("c publishes under {prefix}; ndn-put registers it (c's RIB: origin app)"),
        |cx| {
            cx.publish("c", &prefix, &doc1, None, None)?;
            let rs = routes(cx, "c", &prefix)?;
            if !rs.iter().any(|r| r.origin == "app") {
                return Err(format!("c routes {prefix}: {}", show(&rs)));
            }
            cx.evidence(&format!("c routes {prefix}: {}", show(&rs)));
            Ok(())
        },
    )?;
    sc.step(
        "b, c's neighbour, routes the prefix to c: origin dvr (127), cost 1, its face to c",
        |cx| wait_best(cx, "b", &prefix, ("c", 1), None).map(drop),
    )?;
    sc.step(
        "a learns it through b: origin dvr (127), cost 2 (two hops), its face to b; a fetches \
         c's bytes",
        |cx| {
            wait_best(cx, "a", &prefix, ("b", 2), None)?;
            fetch_from_c(cx, &prefix, &doc1)
        },
    )?;

    sc.step(
        "c's producer stops: its route goes at c, then a's DV route goes, and a fetch at a gets \
         nothing",
        |cx| {
            cx.w.stop_producers("c");
            wait_gone(cx, "c", &prefix, "app")?;
            wait_gone(cx, "a", &prefix, DVR)?;
            uncache(cx, &prefix)?;
            fetch_fails(cx, "a", &prefix)?;
            cx.evidence(&format!("a's fetch of {prefix} delivered nothing"));
            Ok(())
        },
    )?;

    let doc2 = content(20_000, 2);
    sc.step(
        "the producer comes back with new content: a routes via b at cost 2 again and fetches \
         the new bytes",
        |cx| {
            cx.publish("c", &prefix, &doc2, None, None)?;
            wait_best(cx, "a", &prefix, ("b", 2), None)?;
            fetch_from_c(cx, &prefix, &doc2)
        },
    )?;

    let doc3 = content(20_000, 3);
    let a_to_c = sc.step(
        "a direct a–c link (a and c restart with each other as a further neighbour): a's route \
         moves to its face to c at cost 1",
        |cx| {
            cx.w.node_mut("a").cfg.extra_toml = dv_toml("a", &["b", "c"]);
            cx.w.node_mut("c").cfg.extra_toml = dv_toml("c", &["b", "a"]);
            cx.stop("c");
            cx.stop("a");
            cx.start("c")?;
            cx.start("a")?;
            cx.publish("c", &prefix, &doc3, None, None)?;
            let face = wait_best(cx, "a", &prefix, ("c", 1), None)?;
            fetch_from_c(cx, &prefix, &doc3)?;
            Ok(face)
        },
    )?;

    if !crate::works(Command::new("nft").arg("--version")) {
        sc.skip(
            "cut a–c (nftables): a falls back to its face to b at cost 2",
            "nft (nftables) not on PATH; run inside `nix-shell -p util-linux iproute2 nftables`",
        );
        return Ok(());
    }
    let _cut = sc.step(
        "cut a–c: nftables drops UDP between a's and c's addresses",
        |cx| {
            let cut = cut(cx)?;
            cx.evidence(&format!(
                "dropping UDP between {} (a) and {} (c), both ways",
                addr(host("a")),
                addr(host("c"))
            ));
            Ok(cut)
        },
    )?;
    sc.step(
        "a drops c as a neighbour and falls back to its face to b at cost 2; the fetch still \
         works",
        |cx| {
            wait_best(cx, "a", &prefix, ("b", 2), Some(a_to_c))?;
            cx.evidence(&format!(
                "a routes {prefix} via face {a_to_c} (to c) no more"
            ));
            fetch_from_c(cx, &prefix, &doc3)
        },
    )?;
    Ok(())
}
