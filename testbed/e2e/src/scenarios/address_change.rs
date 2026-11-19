//! address-change: a device whose address changes is linked again by itself.
//!
//! Topology: root (10.200.0.1, root device + CA) ← UDP ← relay (.2, a
//! `node` device listening for QUIC links), both on the harness's `lo`.
//! laptop runs in a network namespace of its own (`nat.rs`, a roamer: one
//! veth, no NAT) at 10.1.1.2 and listens for QUIC links on every address
//! (`[[face]] kind = "quic"` bound to `0.0.0.0`, so its link socket follows
//! its address). Each names the other in a `[[peer]]` with `mode = "off"`:
//! a link is made when `ndn-ctl link connect` asks for it, so who dials
//! whom is the harness's choice, not a race of keys. laptop dials the relay
//! once, to enroll by invite; then the relay dials laptop, so the link the
//! laptop has is one it accepted at 10.1.1.2 (a QUIC server cannot follow
//! its address: the relay keeps sending to 10.1.1.2).
//!
//! Proves: when the laptop's address changes (10.2.1.2 added, 10.1.1.2
//! deleted, the default route replaced, as `ip` does it) its daemon notices
//! (the link layer watches the device's own addresses; nothing in the config
//! asks for it), closes the link it accepted and dials the relay again from
//! where it is: the relay's link to it at 10.1.1.2 is replaced by one at
//! 10.2.1.2 (read from `ndn-ctl face list --scheme quic4`), and Interests and
//! Data cross both ways afterwards, within the time of a redial, measured
//! from the change. Both bounds are below the links' idle timeout (30 s), so
//! a device that only learns from the dead link going quiet cannot pass.
//! Data that crosses afterwards is new to both sides (not in either content
//! store).

use std::net::Ipv4Addr;
use std::thread;
use std::time::{Duration, Instant};

use crate::nat::Nat;
use crate::scenarios::direct_paths::quic_faces;
use crate::scenarios::*;
use crate::step::{Abort, Cx, Scenario, StepResult};
use crate::world::{CaCfg, NodeCfg, PeerCfg, addr};

const NS: &str = "/ac";
/// The time of a redial: the bound from the address change to the link at
/// the new address, and to Data crossing. Under `[links] idle_timeout_secs`
/// (30 by default), which is how long a link nobody can send on takes to be
/// noticed without the address watch.
const REDIAL: Duration = Duration::from_secs(15);
/// ndn-link's `DIAL_RACE_WINDOW`: a link of a key younger than this is the
/// other half of a simultaneous dial, and the link the device with the
/// smaller fingerprint dialled stays, whichever address the new one comes
/// from. A device that moves within it waits up to this long (or not, by the
/// keys' order); an older link is one the device lost and the new one
/// replaces it. The scenario moves the laptop after it.
const DIAL_RACE_WINDOW: Duration = Duration::from_secs(10);

fn n(s: &str) -> String {
    format!("{NS}{s}")
}

/// The addresses `node` has a QUIC link face to.
fn remotes(cx: &mut Cx<'_>, node: &str) -> StepResult<Vec<Ipv4Addr>> {
    Ok(quic_faces(cx, node)?
        .into_iter()
        .map(|(r, _)| *r.ip())
        .collect())
}

/// `ndn-ctl link <verb> <label>` on `node`.
fn link_cmd(cx: &mut Cx<'_>, node: &str, verb: &str, label: &str) -> StepResult<()> {
    let sock = cx.w.node(node).sock().display().to_string();
    let op = cx
        .tool("ndn-ctl")
        .args(["--socket", &sock, "link", verb])
        .arg(label);
    cx.ok(op, &format!("ndn-ctl link {verb}")).map(|_| ())
}

pub fn run(sc: &mut Scenario) -> Result<(), Abort> {
    if let Some(why) = Nat::missing() {
        sc.skip("build a device namespace that can change its address", &why);
        return Ok(());
    }
    let (home, away) = sc.step(
        "build a device namespace that can change its address (10.1.1.2 to 10.2.1.2)",
        |cx| {
            let mut nat = Nat::new(cx.w.dir.join("nat"))?;
            let k = nat.add_roamer()?;
            let r = nat.roamer(k);
            let addrs = (r.home, r.away);
            cx.evidence(&format!(
                "roamer {k}: device at {} (default route via the harness), moves to {}",
                r.home, r.away
            ));
            cx.w.nat = Some(nat);
            Ok(addrs)
        },
    )?;

    let base = NodeCfg {
        refresh_secs: 1,
        ..Default::default()
    };
    let laptop_device = n("/member/laptop");
    let relay_device = n("/node/relay");
    sc.world.add("root", 1, base.clone());
    sc.world.add(
        "relay",
        2,
        NodeCfg {
            links: vec![link("root", 1)],
            routes: vec![route(NS, "root")],
            quic_listen: true,
            peers: vec![PeerCfg {
                device: Some(laptop_device.clone()),
                endpoint: Some(home),
                mode: Some("off".into()),
                ..Default::default()
            }],
            ..base.clone()
        },
    );
    sc.world.add_roaming(
        "laptop",
        1,
        NodeCfg {
            peers: vec![PeerCfg {
                device: Some(relay_device.clone()),
                endpoint: Some(addr(2)),
                mode: Some("off".into()),
                ..Default::default()
            }],
            quic_listen_any: true,
            ..base
        },
    );

    let root = sc.step("init the root device", |cx| {
        init_root(cx, "root", NS, "desk")
    })?;
    sc.step("start the root device's daemon with its CA", |cx| {
        cx.w.node_mut("root").cfg.identity = Some(root.identity.clone());
        cx.w.node_mut("root").cfg.ca = Some(CaCfg {
            prefix: NS.into(),
            identity: n("/CA"),
            member_days: None,
        });
        cx.start("root")
    })?;
    let invites = sc.step("make a member invite at the running CA", |cx| {
        mint(cx, "root", NS, &root.fp, 1, Some("2h"))
    })?;
    sc.step(
        "start the relay (listening for QUIC links), adopt the namespace, become a node device",
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
    let hello = content(2_000, 40);
    sc.step("the relay publishes Data", |cx| {
        cx.publish("relay", &n("/node/relay/hello"), &hello, None, None)
    })?;

    sc.step(
        "laptop starts in its namespace and dials the relay once: the relay sees it at its home address",
        |cx| {
            cx.start("laptop")?;
            link_cmd(cx, "laptop", "connect", &relay_device)?;
            wait_for(
                cx,
                &format!("the relay is linked to the laptop at {home}"),
                SHORT,
                |cx| Ok(remotes(cx, "relay")?.contains(&home)),
            )
            .map(|_| ())
        },
    )?;
    sc.step("laptop enrolls by invite over its link", |cx| {
        enroll(cx, "laptop", &invites[0], "laptop", false, None)?;
        fetch_within(cx, "laptop", &n("/node/relay/hello"), &hello, SHORT)
    })?;
    let linked_at = sc.step(
        "laptop lets go and the relay dials it: the laptop's link is one it accepted",
        |cx| {
            link_cmd(cx, "laptop", "disconnect", &relay_device)?;
            wait_for(
                cx,
                &format!("the relay's link to the laptop at {home} is closed"),
                SHORT,
                |cx| Ok(!remotes(cx, "relay")?.contains(&home)),
            )?;
            link_cmd(cx, "relay", "connect", &laptop_device)?;
            wait_for(
                cx,
                &format!("the relay dialled the laptop at {home}"),
                SHORT,
                |cx| Ok(remotes(cx, "relay")?.contains(&home)),
            )?;
            let linked_at = Instant::now();
            // Asked for, the laptop keeps the link it accepted (an `off` link
            // nobody asked for closes); it dials nothing while it has it.
            link_cmd(cx, "laptop", "connect", &relay_device)?;
            Ok(linked_at)
        },
    )?;
    let note = content(3_000, 41);
    sc.step(
        "Data crosses the accepted link both ways before the move (control)",
        |cx| {
            cx.publish("relay", &n("/node/relay/before"), &hello, None, None)?;
            fetch_within(cx, "laptop", &n("/node/relay/before"), &hello, SHORT)?;
            cx.publish("laptop", &n("/member/laptop/before"), &note, None, None)?;
            fetch_within(cx, "relay", &n("/member/laptop/before"), &note, SHORT)?;
            if !remotes(cx, "relay")?.contains(&home) {
                return Err(format!("the relay's link to the laptop left {home}"));
            }
            Ok(())
        },
    )?;

    sc.step(
        "the accepted link ages past the window in which a second link of a key is the other half of a dial race",
        |cx| {
            let age = linked_at.elapsed();
            let wait = (DIAL_RACE_WINDOW + Duration::from_secs(1)).saturating_sub(age);
            cx.evidence(&format!(
                "the relay's link to the laptop is {:.1}s old; waiting {:.1}s",
                age.as_secs_f64(),
                wait.as_secs_f64()
            ));
            thread::sleep(wait);
            Ok(())
        },
    )?;

    let moved_at = sc.step(
        "laptop's address changes: the relay's link at the old address is replaced by one at the new",
        |cx| {
            let at = Instant::now();
            cx.w.nat.as_ref().expect("roamer").move_roamer(1)?;
            cx.evidence(&format!(
                "address changed: {home} deleted, {away} added, default route replaced"
            ));
            let took = wait_for(
                cx,
                &format!("the relay's link to the laptop moved from {home} to {away}"),
                REDIAL,
                |cx| {
                    let r = remotes(cx, "relay")?;
                    Ok(r.contains(&away) && !r.contains(&home))
                },
            )?;
            cx.evidence(&format!(
                "relay: link at {away}, none at {home}, {:.2}s after the change",
                took.as_secs_f64()
            ));
            Ok(at)
        },
    )?;

    let after_relay = content(2_500, 42);
    let after_laptop = content(2_600, 43);
    sc.step(
        "Interest and Data cross both ways at the new address, within the time of a redial",
        |cx| {
            cx.publish(
                "relay",
                &n("/node/relay/after-move"),
                &after_relay,
                None,
                None,
            )?;
            cx.publish(
                "laptop",
                &n("/member/laptop/after-move"),
                &after_laptop,
                None,
                None,
            )?;
            fetch_within(
                cx,
                "laptop",
                &n("/node/relay/after-move"),
                &after_relay,
                REDIAL,
            )?;
            cx.evidence(&format!(
                "laptop fetched the relay's new Data {:.2}s after the address change",
                moved_at.elapsed().as_secs_f64()
            ));
            fetch_within(
                cx,
                "relay",
                &n("/member/laptop/after-move"),
                &after_laptop,
                REDIAL,
            )?;
            let both = moved_at.elapsed();
            cx.evidence(&format!(
                "relay fetched the laptop's new Data {:.2}s after the address change",
                both.as_secs_f64()
            ));
            if both >= REDIAL {
                return Err(format!(
                    "Data crossed {:.2}s after the address change, not within {}s",
                    both.as_secs_f64(),
                    REDIAL.as_secs()
                ));
            }
            Ok(())
        },
    )?;
    Ok(())
}
