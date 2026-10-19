//! direct-paths: devices behind NATs punch direct paths through the relay.
//!
//! Topology: root (10.200.0.1, root device + CA) ← UDP ← relay (.2, a
//! `node` device listening for QUIC links), both on the harness's `lo`,
//! which is "the internet". Four NAT boxes (`nat.rs`): A and B are
//! port-restricted cone NATs, C and D symmetric ones; box k's public
//! address is 10.0.k.2 and its device sits on 192.168.k.2. phone (A,
//! dialling only) and tab (B, listening on its LAN address) link to the
//! relay over QUIC only and enroll by invite; car (C) and tv (D) the same.
//! stranger (.5, public) is never enrolled and holds no trust context; the
//! relay accepts it by its key.
//!
//! Proves: the relay sees each device at its box's public address (the
//! NAT is real); phone naming tab as a peer reached through the relay gives
//! both a direct path, at the other box's public address; a large object
//! then flows over it with next to nothing through the relay; when the
//! boxes can no longer reach each other the direct path goes, traffic
//! falls back to the relay and phone's status says so; when they can again
//! the direct path comes back by itself; between symmetric NATs no direct
//! path forms, car's status says why, and traffic flows through the relay;
//! a punch from a key not allowed to link is refused and makes tab send
//! nothing toward it (no probe, no dial: box B forwards no UDP to it).
//! Path state is read from `ndn-ctl link list`, relay traffic from the
//! relay's `ndn-ctl face list` packet counters.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::thread;
use std::time::{Duration, Instant};

use crate::nat::{Nat, NatKind};
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{CaCfg, NodeCfg, PeerCfg, addr};

const NS: &str = "/dp";
/// ndn-put's default segment size.
const SEGMENT: usize = 8192;
/// NAT boxes, in the order they are built.
const BOX_A: u8 = 1;
const BOX_B: u8 = 2;
const BOX_C: u8 = 3;
const BOX_D: u8 = 4;

fn n(s: &str) -> String {
    format!("{NS}{s}")
}

fn relay_peer() -> PeerCfg {
    PeerCfg {
        device: Some(n("/node/relay")),
        endpoint: Some(addr(2)),
        ..Default::default()
    }
}

/// A member device reached through the relay (and punched to).
fn via_relay(device: &str) -> PeerCfg {
    PeerCfg {
        device: Some(n(&format!("/member/{device}"))),
        relay: Some(n("/node/relay")),
        ..Default::default()
    }
}

fn segments(len: usize) -> u64 {
    len.div_ceil(SEGMENT) as u64
}

/// `ndn-ctl link list`, parsed.
#[derive(Debug, Default)]
pub(super) struct LinkList {
    pub(super) key: Option<String>,
    probes_sent: Option<u64>,
    punches_refused: Option<u64>,
    /// The `serve` line: this device's relay serving policy.
    pub(super) serve: Option<String>,
    pub(super) held_total: Option<u64>,
    pub(super) wakes_sent: Option<u64>,
    pub(super) links: Vec<Link>,
}

#[derive(Debug, Default)]
pub(super) struct Link {
    /// The word after `link`.
    pub(super) label: String,
    pub(super) key: Option<String>,
    pub(super) device: Option<String>,
    /// The `mode`, `relay`, `asleep` and `down` lines after their word.
    pub(super) mode: Option<String>,
    pub(super) relay: Option<String>,
    pub(super) asleep: Option<String>,
    pub(super) down: Option<String>,
    pub(super) paths: Vec<PathLine>,
    /// The `direct` line after the word `direct`.
    pub(super) direct: String,
}

#[derive(Debug)]
pub(super) struct PathLine {
    pub(super) kind: String,
    pub(super) remote: Option<SocketAddrV4>,
    /// The line after the word `path`.
    pub(super) text: String,
}

impl LinkList {
    fn parse(out: &str) -> Result<LinkList, String> {
        let mut l = LinkList::default();
        for line in out.lines() {
            let t = line.trim();
            let (word, rest) = t.split_once(' ').unwrap_or((t, ""));
            let value = (rest != "-").then(|| rest.to_owned());
            let count = || {
                rest.parse::<u64>()
                    .map_err(|_| format!("unreadable line {t:?}"))
            };
            if line.starts_with(' ') {
                let Some(link) = l.links.last_mut() else {
                    return Err(format!("{t:?} before any `link` line"));
                };
                match word {
                    "key" => link.key = value,
                    "device" => link.device = value,
                    "mode" => link.mode = Some(rest.to_owned()),
                    "relay" => link.relay = Some(rest.to_owned()),
                    "asleep" => link.asleep = Some(rest.to_owned()),
                    "down" => link.down = Some(rest.to_owned()),
                    "path" => link.paths.push(PathLine {
                        kind: rest.split_whitespace().next().unwrap_or("").to_owned(),
                        remote: rest
                            .split_whitespace()
                            .find_map(|w| w.strip_prefix("remote="))
                            .and_then(|a| a.parse().ok()),
                        text: rest.to_owned(),
                    }),
                    "direct" => link.direct = rest.to_owned(),
                    _ => {}
                }
            } else {
                match word {
                    "key" => l.key = value,
                    "probes-sent" => l.probes_sent = Some(count()?),
                    "punches-refused" => l.punches_refused = Some(count()?),
                    "serve" => l.serve = Some(rest.to_owned()),
                    "held-total" => l.held_total = Some(count()?),
                    "wakes-sent" => l.wakes_sent = Some(count()?),
                    "link" => l.links.push(Link {
                        label: rest.to_owned(),
                        ..Link::default()
                    }),
                    _ => {}
                }
            }
        }
        Ok(l)
    }

    /// The link to the device named `device`, or holding `key`.
    pub(super) fn to(&self, device: &str, key: Option<&str>) -> Option<&Link> {
        self.links.iter().find(|l| {
            l.device.as_deref() == Some(device) || (key.is_some() && l.key.as_deref() == key)
        })
    }
}

impl Link {
    pub(super) fn direct_path(&self) -> Option<&PathLine> {
        self.paths.iter().find(|p| p.kind == "direct")
    }

    /// The `direct` state, and the text after it (and after any
    /// `retry-in-s=`).
    pub(super) fn direct_state(&self) -> (String, String) {
        let d = self.direct.trim();
        let (state, rest) = d.split_once(' ').unwrap_or((d, ""));
        let text = match rest.split_once(' ') {
            Some((w, t)) if w.starts_with("retry-in-s=") => t,
            _ if rest.starts_with("retry-in-s=") => "",
            _ => rest,
        };
        (state.to_owned(), text.trim().to_owned())
    }
}

pub(super) fn link_list(cx: &mut Cx<'_>, node: &str) -> StepResult<LinkList> {
    let sock = cx.w.node(node).sock().display().to_string();
    let op = cx.tool("ndn-ctl").args(["--socket", &sock, "link", "list"]);
    let out = cx.exec(op);
    if !out.success() {
        return Err(format!("link list on {node}: {}", out.status_text()));
    }
    LinkList::parse(&out.stdout).map_err(|e| format!("link list on {node}: {e}"))
}

/// This device's link key (the top `key` line).
fn own_key(cx: &mut Cx<'_>, node: &str) -> StepResult<String> {
    link_list(cx, node)?
        .key
        .ok_or_else(|| format!("{node}: link list shows no key of its own"))
}

/// The direct path of member `a`'s link to member `b` (`lb` is `b`'s list).
fn direct_path<'a>(la: &'a LinkList, lb: &LinkList, b: &str) -> Option<&'a PathLine> {
    la.to(&n(&format!("/member/{b}")), lb.key.as_deref())
        .and_then(Link::direct_path)
}

fn shown(p: Option<&PathLine>) -> String {
    p.map_or_else(|| "none".to_owned(), |p| format!("path {}", p.text))
}

/// Wait until `a` and `b` each have a direct path to the other, at the
/// other's box's public address.
fn wait_direct_up(
    cx: &mut Cx<'_>,
    (a, a_public): (&str, Ipv4Addr),
    (b, b_public): (&str, Ipv4Addr),
    within: Duration,
) -> StepResult<Duration> {
    let start = Instant::now();
    loop {
        let la = link_list(cx, a)?;
        let lb = link_list(cx, b)?;
        let (pa, pb) = (direct_path(&la, &lb, b), direct_path(&lb, &la, a));
        let at = |p: Option<&PathLine>, ip: Ipv4Addr| {
            p.and_then(|p| p.remote).is_some_and(|r| *r.ip() == ip)
        };
        if at(pa, b_public) && at(pb, a_public) {
            let took = start.elapsed();
            cx.evidence(&format!(
                "after {:.2}s: {a} → {b}: {}",
                took.as_secs_f64(),
                shown(pa)
            ));
            cx.evidence(&format!(
                "after {:.2}s: {b} → {a}: {}",
                took.as_secs_f64(),
                shown(pb)
            ));
            return Ok(took);
        }
        if start.elapsed() > within {
            return Err(format!(
                "no direct path at the other box's public address after {}s: {a} → {b} ({b_public} expected): {}; \
                 {b} → {a} ({a_public} expected): {}",
                within.as_secs(),
                shown(pa),
                shown(pb)
            ));
        }
        thread::sleep(Duration::from_millis(250));
    }
}

/// Wait until neither `a` nor `b` has a direct path to the other.
fn wait_direct_gone(cx: &mut Cx<'_>, a: &str, b: &str, within: Duration) -> StepResult<Duration> {
    let start = Instant::now();
    loop {
        let la = link_list(cx, a)?;
        let lb = link_list(cx, b)?;
        let (pa, pb) = (direct_path(&la, &lb, b), direct_path(&lb, &la, a));
        if pa.is_none() && pb.is_none() {
            let took = start.elapsed();
            cx.evidence(&format!(
                "after {:.2}s: no direct path between {a} and {b}",
                took.as_secs_f64()
            ));
            return Ok(took);
        }
        if start.elapsed() > within {
            return Err(format!(
                "direct path still there after {}s: {a} → {b}: {}; {b} → {a}: {}",
                within.as_secs(),
                shown(pa),
                shown(pb)
            ));
        }
        thread::sleep(Duration::from_millis(250));
    }
}

/// `node`'s QUIC link faces: remote address and packets in and out
/// (Interests, Data and Nacks).
pub(super) fn quic_faces(cx: &mut Cx<'_>, node: &str) -> StepResult<Vec<(SocketAddrV4, u64)>> {
    let sock = cx.w.node(node).sock().display().to_string();
    let op = cx
        .tool("ndn-ctl")
        .args(["--socket", &sock, "face", "list", "--scheme", "quic4"]);
    let out = cx.exec(op);
    if !out.success() {
        return Err(format!("face list on {node}: {}", out.status_text()));
    }
    let mut rows: Vec<(Option<SocketAddrV4>, u64)> = Vec::new();
    for line in out.stdout.lines() {
        let t = line.trim();
        if t.starts_with("faceid=") {
            rows.push((None, 0));
            continue;
        }
        let Some(row) = rows.last_mut() else { continue };
        if let Some(a) = t.strip_prefix("remote: quic4://") {
            row.0 = a.parse().ok();
        } else if let Some(counts) = t.strip_prefix("in:").or_else(|| t.strip_prefix("out:")) {
            for w in counts.split_whitespace() {
                let v = ["interests=", "data=", "nacks="]
                    .iter()
                    .find_map(|k| w.strip_prefix(k))
                    .map(|v| {
                        v.parse::<u64>()
                            .map_err(|_| format!("face list on {node}: unreadable {t:?}"))
                    });
                if let Some(v) = v {
                    row.1 += v?;
                }
            }
        }
    }
    Ok(rows
        .into_iter()
        .filter_map(|(r, p)| r.map(|r| (r, p)))
        .collect())
}

/// Packets the relay exchanged on its links with the boxes `publics`.
fn relay_packets(cx: &mut Cx<'_>, publics: &[Ipv4Addr]) -> StepResult<u64> {
    Ok(quic_faces(cx, "relay")?
        .into_iter()
        .filter(|(r, _)| publics.contains(r.ip()))
        .map(|(_, p)| p)
        .sum())
}

/// Wait until the relay has a link face to an address of `public`; that
/// address.
fn wait_relay_sees(
    cx: &mut Cx<'_>,
    public: Ipv4Addr,
    within: Duration,
) -> StepResult<SocketAddrV4> {
    let start = Instant::now();
    loop {
        if let Some((r, _)) = quic_faces(cx, "relay")?
            .into_iter()
            .find(|(r, _)| *r.ip() == public)
        {
            cx.note(&format!(
                "the relay links to {r} after {:.2}s",
                start.elapsed().as_secs_f64()
            ));
            return Ok(r);
        }
        if start.elapsed() > within {
            return Err(format!(
                "the relay has no link from {public} after {}s",
                within.as_secs()
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// `node`, behind box `public`, links to the relay over QUIC only and
/// enrolls by invite over its enrollment link; `hello` (the relay's Data)
/// then reaches it over the full link.
fn link_and_enroll(
    cx: &mut Cx<'_>,
    node: &str,
    public: Ipv4Addr,
    invite: &Invite,
    hello: &[u8],
) -> StepResult<()> {
    cx.start(node)?;
    let seen = wait_relay_sees(cx, public, SHORT)?;
    let lan = cx.w.node(node).ip;
    cx.evidence(&format!(
        "{node} binds {lan}; the relay sees it at {seen} (its box's public address)"
    ));
    enroll(cx, node, invite, node, false, None)?;
    fetch_within(cx, node, &n("/node/relay/hello"), hello, SHORT)
}

/// Publish `data` on `from`, fetch it at `to`: the relay's packet count on
/// the links of `publics` before and after.
fn fetch_counted(
    cx: &mut Cx<'_>,
    (from, to): (&str, &str),
    name: &str,
    data: &[u8],
    publics: &[Ipv4Addr],
) -> StepResult<u64> {
    cx.publish(from, name, data, None, None)?;
    let before = relay_packets(cx, publics)?;
    fetch_within(cx, to, name, data, SHORT)?;
    let after = relay_packets(cx, publics)?;
    let delta = after.saturating_sub(before);
    cx.evidence(&format!(
        "{name}: {} segments; relay packets on the links of {publics:?}: {before} before, {after} after (+{delta})",
        segments(data.len())
    ));
    Ok(delta)
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    if let Some(why) = Nat::missing() {
        sc.skip(
            "build NAT boxes (nested network namespaces with nftables)",
            &why,
        );
        return Ok(());
    }
    sc.step(
        "build NAT boxes A, B (port-restricted cone) and C, D (symmetric)",
        |cx| {
            let mut nat = Nat::new(cx.w.dir.join("nat"))?;
            for kind in [
                NatKind::Cone,
                NatKind::Cone,
                NatKind::Symmetric,
                NatKind::Symmetric,
            ] {
                let k = nat.add_box(kind)?;
                let b = nat.nat_box(k);
                cx.evidence(&format!(
                    "box {k} ({}): public {}, device {} on its LAN",
                    b.kind.label(),
                    b.public,
                    b.device_ip
                ));
            }
            cx.w.nat = Some(nat);
            Ok(())
        },
    )?;
    let public = |sc: &Scenario, k: u8| sc.world.nat.as_ref().expect("NAT boxes").nat_box(k).public;
    let (pub_a, pub_b, pub_c, pub_d) = (
        public(sc, BOX_A),
        public(sc, BOX_B),
        public(sc, BOX_C),
        public(sc, BOX_D),
    );

    // Few background packets on the relay: the trust context is pulled
    // rarely.
    let base = NodeCfg {
        refresh_secs: 600,
        ..Default::default()
    };
    sc.world.add("root", 1, base.clone());
    sc.world.add(
        "relay",
        2,
        NodeCfg {
            links: vec![link("root", 1)],
            routes: vec![route(NS, "root")],
            quic_listen: true,
            ..base.clone()
        },
    );
    sc.world.add(
        "stranger",
        5,
        NodeCfg {
            quic_listen: true,
            ..base.clone()
        },
    );
    let dialling = NodeCfg {
        peers: vec![relay_peer()],
        quic_dial_only: true,
        ..base.clone()
    };
    let listening = NodeCfg {
        peers: vec![relay_peer()],
        quic_listen: true,
        ..base.clone()
    };
    sc.world.add_behind("phone", BOX_A, dialling.clone());
    sc.world.add_behind("tab", BOX_B, listening.clone());
    sc.world.add_behind("car", BOX_C, dialling);
    sc.world.add_behind("tv", BOX_D, listening);

    let root = sc.step("init the root device", |cx| {
        init_root(cx, "root", NS, "desk")
    })?;
    let invites = sc.step("mint four member invites", |cx| {
        mint(cx, NS, &root.fp, 4, Some("2h"))
    })?;
    sc.step("start the root device's daemon with its CA", |cx| {
        cx.w.node_mut("root").cfg.identity = Some(root.identity.clone());
        cx.w.node_mut("root").cfg.ca = Some(CaCfg {
            prefix: NS.into(),
            identity: n("/CA"),
            tokens: invites.iter().map(|i| i.token.clone()).collect(),
            member_days: None,
        });
        cx.start("root")
    })?;
    let stranger_key = sc.step(
        "stranger (never enrolled, no trust context) makes a key of its own: its link key",
        |cx| {
            // A key in its PIB (not the daemon's ephemeral one), so the key the
            // relay is told to accept is the one it links with after a restart.
            let pib = cx.w.node("stranger").pib().display().to_string();
            let op = cx
                .tool("ndn-sec")
                .args(["--pib", &pib, "keygen", "/stranger"]);
            cx.ok(op, "ndn-sec keygen")?;
            cx.w.node_mut("stranger").cfg.identity = Some("/stranger".into());
            cx.start("stranger")?;
            let key = own_key(cx, "stranger")?;
            cx.stop("stranger");
            cx.evidence(&format!("stranger's link key {key}"));
            Ok(key)
        },
    )?;
    sc.step(
        "start the relay (listening for QUIC links), adopt, and become a node device on approval",
        |cx| {
            cx.start("relay")?;
            let op = cx
                .tool("ndn-fwd")
                .arg("adopt")
                .arg(&root.link_fp)
                .arg("-c")
                .arg(cx.w.node("relay").cfg_arg());
            cx.ok(op, "adopt")?;
            cx.expect_version("relay", NS, 1)?;
            enroll_by_approval(cx, NS, &root.link_fp, "relay")
        },
    )?;
    let hello = content(2_000, 30);
    let relay_key = sc.step(
        "the relay accepts stranger by its key and restarts: its link key",
        |cx| {
            cx.w.node_mut("relay").cfg.peers = vec![PeerCfg {
                key: Some(stranger_key.clone()),
                ..Default::default()
            }];
            cx.stop("relay");
            cx.start("relay")?;
            let key = own_key(cx, "relay")?;
            cx.evidence(&format!("the relay's link key {key}"));
            cx.publish("relay", &n("/node/relay/hello"), &hello, None, None)?;
            Ok(key)
        },
    )?;

    sc.step("phone behind cone box A links to the relay, seen at A's public address, and enrolls by invite", |cx| {
        link_and_enroll(cx, "phone", pub_a, &invites[0], &hello)
    })?;
    sc.step("tab behind cone box B links to the relay, seen at B's public address, and enrolls by invite", |cx| {
        link_and_enroll(cx, "tab", pub_b, &invites[1], &hello)
    })?;

    sc.step("phone names tab, reached through the relay: both get a direct path at the other box's public address", |cx| {
        cx.w.node_mut("phone").cfg.peers.push(via_relay("tab"));
        cx.stop("phone");
        cx.start("phone")?;
        wait_direct_up(cx, ("phone", pub_a), ("tab", pub_b), Duration::from_secs(20))?;
        Ok(())
    })?;

    let album = content(800_000, 31);
    sc.step("tab fetches an 800 KB object from phone over the direct path: the relay carries next to none of it", |cx| {
        let delta = fetch_counted(cx, ("phone", "tab"), &n("/member/phone/album"), &album, &[pub_a, pub_b])?;
        let segs = segments(album.len());
        // Relayed, every segment would cost the relay four packets.
        if delta * 2 >= segs {
            return Err(format!("the relay forwarded {delta} packets of phone's and tab's for {segs} segments"));
        }
        Ok(())
    })?;

    let cut = content(200_000, 32);
    sc.step("boxes A and B can no longer reach each other: the direct path goes, traffic falls back to the relay", |cx| {
        cx.w.nat.as_mut().expect("NAT boxes").cut(BOX_A, BOX_B)?;
        cx.evidence(&format!("the harness drops UDP between {pub_a} and {pub_b}"));
        wait_direct_gone(cx, "phone", "tab", Duration::from_secs(20))?;
        let start = Instant::now();
        loop {
            let lp = link_list(cx, "phone")?;
            let lt = link_list(cx, "tab")?;
            let link = lp
                .to(&n("/member/tab"), lt.key.as_deref())
                .ok_or("phone shows no link to tab")?;
            let (state, _) = link.direct_state();
            if state == "not-possible" || state == "trying" {
                cx.evidence(&format!("phone → tab: direct {}", link.direct));
                break;
            }
            if start.elapsed() > Duration::from_secs(15) {
                return Err(format!("phone → tab: direct {} (expected not-possible or trying)", link.direct));
            }
            thread::sleep(Duration::from_millis(250));
        }
        let delta = fetch_counted(cx, ("phone", "tab"), &n("/member/phone/cut"), &cut, &[pub_a, pub_b])?;
        let segs = segments(cut.len());
        if delta < segs {
            return Err(format!("the relay forwarded only {delta} packets for {segs} segments: not through the relay"));
        }
        Ok(())
    })?;

    let healed = content(200_000, 33);
    sc.step(
        "A and B reach each other again: the direct path comes back by itself",
        |cx| {
            cx.w.nat.as_mut().expect("NAT boxes").heal()?;
            wait_direct_up(
                cx,
                ("phone", pub_a),
                ("tab", pub_b),
                Duration::from_secs(75),
            )?;
            fetch_counted(
                cx,
                ("phone", "tab"),
                &n("/member/phone/healed"),
                &healed,
                &[pub_a, pub_b],
            )?;
            Ok(())
        },
    )?;

    sc.step("car behind symmetric box C links to the relay, seen at C's public address, and enrolls by invite", |cx| {
        link_and_enroll(cx, "car", pub_c, &invites[2], &hello)
    })?;
    sc.step("tv behind symmetric box D links to the relay, seen at D's public address, and enrolls by invite", |cx| {
        link_and_enroll(cx, "tv", pub_d, &invites[3], &hello)
    })?;
    sc.step("car names tv, reached through the relay: no direct path between symmetric NATs, and car says why", |cx| {
        cx.w.node_mut("car").cfg.peers.push(via_relay("tv"));
        cx.stop("car");
        cx.start("car")?;
        let start = Instant::now();
        // Until car's punch has failed and says why: its window (10 s) is
        // over, and it names the symmetric NATs as the cause.
        loop {
            let lc = link_list(cx, "car")?;
            let lt = link_list(cx, "tv")?;
            if let Some(p) = direct_path(&lc, &lt, "tv").or(direct_path(&lt, &lc, "car")) {
                return Err(format!("a direct path between symmetric NATs: path {}", p.text));
            }
            let direct = lc.to(&n("/member/tv"), lt.key.as_deref()).map(|l| (l.direct_state(), l.direct.clone()));
            if let Some(((state, text), line)) = &direct
                && state == "not-possible"
                && text.contains("symmetric NAT")
            {
                cx.evidence(&format!("after {:.1}s, no direct path; car → tv: direct {line}", start.elapsed().as_secs_f64()));
                return Ok(());
            }
            if start.elapsed() > Duration::from_secs(60) {
                return Err(format!(
                    "car → tv after 60s: {} (expected not-possible, naming symmetric NATs)",
                    direct.map_or_else(|| "no link".to_owned(), |(_, l)| format!("direct {l}"))
                ));
            }
            thread::sleep(Duration::from_millis(250));
        }
    })?;
    let note = content(100_000, 34);
    sc.step("tv's Data reaches car through the relay", |cx| {
        let delta = fetch_counted(cx, ("tv", "car"), &n("/member/tv/note"), &note, &[pub_c, pub_d])?;
        let segs = segments(note.len());
        if delta < segs {
            return Err(format!("the relay forwarded only {delta} packets for {segs} segments: not through the relay"));
        }
        Ok(())
    })?;

    sc.step("a punch from a key not allowed to link is refused; tab sends nothing toward it", |cx| {
        // No other punch reaches tab meanwhile, and tab's own (of phone, car
        // and tv, by membership) are over: its probe count stands still.
        for node in ["phone", "car", "tv"] {
            cx.stop(node);
        }
        let mut last = link_list(cx, "tab")?.probes_sent;
        wait_for(cx, "tab runs no punch: no link trying, probes-sent steady for 1 s", SHORT, |cx| {
            thread::sleep(Duration::from_secs(1));
            let list = link_list(cx, "tab")?;
            let steady = list.probes_sent == last;
            last = list.probes_sent;
            Ok(steady && list.links.iter().all(|l| l.direct_state().0 != "trying"))
        })?;
        let before = link_list(cx, "tab")?;
        let probes = before.probes_sent.ok_or("tab's link list shows no probes-sent")?;
        let refused = before.punches_refused.ok_or("tab's link list shows no punches-refused")?;
        let counter = "to_stranger";
        cx.w.nat.as_ref().expect("NAT boxes").count_udp_to(BOX_B, counter, addr(5))?;
        cx.w.node_mut("stranger").cfg.peers = vec![
            PeerCfg {
                key: Some(relay_key.clone()),
                endpoint: Some(addr(2)),
                routes: vec![NS.to_owned()],
                ..Default::default()
            },
            PeerCfg {
                device: Some(n("/member/tab")),
                relay: Some(relay_key.clone()),
                ..Default::default()
            },
        ];
        cx.start("stranger")?;
        let start = Instant::now();
        loop {
            let now = link_list(cx, "tab")?.punches_refused.ok_or("tab's link list shows no punches-refused")?;
            if now > refused {
                cx.evidence(&format!("tab: punches-refused {refused} → {now} after {:.2}s", start.elapsed().as_secs_f64()));
                break;
            }
            if start.elapsed() > SHORT {
                return Err(format!("tab refused no punch within {}s (punches-refused stays {refused})", SHORT.as_secs()));
            }
            thread::sleep(Duration::from_millis(250));
        }
        // A punch that went ahead probes from the moment its answer is sent,
        // every 200 ms: once stranger holds tab's answer (its punch says
        // refused), a probe would already be counted, or be within the
        // next second's five.
        wait_for(cx, "stranger's punch of tab ends refused, with a reason", SHORT, |cx| {
            let ls = link_list(cx, "stranger")?;
            Ok(ls.to(&n("/member/tab"), None).is_some_and(|l| {
                let (state, text) = l.direct_state();
                state == "refused" && !text.is_empty()
            }))
        })?;
        thread::sleep(Duration::from_secs(1));
        let after = link_list(cx, "tab")?;
        let probes_after = after.probes_sent.ok_or("tab's link list shows no probes-sent")?;
        let sent = cx.w.nat.as_ref().expect("NAT boxes").counter(BOX_B, counter)?;
        cx.evidence(&format!("tab: probes-sent {probes} → {probes_after}; box B forwarded {sent} UDP packets to {}", addr(5)));
        let ls = link_list(cx, "stranger")?;
        let l = ls.to(&n("/member/tab"), None).ok_or("stranger shows no link to tab")?;
        cx.evidence(&format!("stranger → tab: direct {}", l.direct));
        let (state, text) = l.direct_state();
        if state != "refused" || text.is_empty() {
            return Err(format!("stranger → tab: direct {} (expected refused with a reason)", l.direct));
        }
        if probes_after != probes {
            return Err(format!("tab sent probes after the refusal: probes-sent {probes} → {probes_after}"));
        }
        if sent != 0 {
            return Err(format!("box B forwarded {sent} UDP packets from tab's LAN to stranger ({})", addr(5)));
        }
        Ok(())
    })?;
    Ok(())
}
