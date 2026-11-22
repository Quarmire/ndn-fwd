//! One namespace, three devices on three daemons: the setup `events` uses.
//!
//! Topology, on the harness's `lo`: laptop (10.200.0.1, the root device of
//! the namespace as `<ns>/admin/laptop`, with its CA, listening for QUIC
//! links), tab (.2, `<ns>/member/tab`, listening, naming the laptop as its
//! peer) and phone (.3, `<ns>/member/phone`, dialling the laptop and the tab).
//! tab and phone enroll by invite over a UDP face that routes the namespace to
//! the laptop (the only `[[route]]` any config holds; it also carries their
//! trust-context refreshes, every second); every device's links notice a lost
//! peer within seconds. Once enrolled, the devices link over QUIC and each
//! carries the namespace's sync group over its links.

use super::data_host::carries_group;
use crate::scenarios::*;
use crate::step::{Abort, Scenario};
use crate::world::{CaCfg, NodeCfg, PeerCfg, addr};

/// The harness hosts of the three daemons.
pub const LAPTOP_HOST: u8 = 1;
pub const TAB_HOST: u8 = 2;
pub const PHONE_HOST: u8 = 3;

/// Link timing that notices a lost link within seconds.
const FAST_LINKS: &str = "[links]\nkeep_alive_secs = 2\nidle_timeout_secs = 6\n";

/// The tab's and the phone's device names in `ns`.
pub fn tab(ns: &str) -> String {
    format!("{ns}/member/tab")
}

pub fn phone(ns: &str) -> String {
    format!("{ns}/member/phone")
}

fn peer(device: &str, host: u8) -> PeerCfg {
    PeerCfg {
        device: Some(device.into()),
        endpoint: Some(addr(host)),
        ..Default::default()
    }
}

/// Create `ns` on the laptop (its root device and CA), enroll the tab and the
/// phone by invite, and wait until each device carries `<ns>/32=sync` over
/// its links to the others. The root of `ns`.
pub fn start(sc: &mut Scenario, ns: &str) -> Result<RootInfo, Abort> {
    let (laptop, tab, phone) = (format!("{ns}/admin/laptop"), tab(ns), phone(ns));
    let group = format!("{ns}/32=sync");
    let member = |peers: Vec<PeerCfg>, listen: bool| NodeCfg {
        links: vec![link("laptop", LAPTOP_HOST)],
        routes: vec![route(ns, "laptop")],
        peers,
        quic_listen: listen,
        quic_dial_only: !listen,
        refresh_secs: 1,
        extra_toml: FAST_LINKS.into(),
        ..Default::default()
    };
    sc.world.add(
        "laptop",
        LAPTOP_HOST,
        NodeCfg {
            quic_listen: true,
            refresh_secs: 1,
            extra_toml: FAST_LINKS.into(),
            ..Default::default()
        },
    );
    sc.world.add(
        "tab",
        TAB_HOST,
        member(vec![peer(&laptop, LAPTOP_HOST)], true),
    );
    sc.world.add(
        "phone",
        PHONE_HOST,
        member(
            vec![peer(&laptop, LAPTOP_HOST), peer(&tab, TAB_HOST)],
            false,
        ),
    );

    let root = sc.step(
        &format!("init the laptop as the root device of {ns}"),
        |cx| {
            let root = init_root(cx, "laptop", ns, "laptop")?;
            if root.identity != laptop {
                return Err(format!(
                    "the laptop is {}, expected {laptop} (the members' peer entries)",
                    root.identity
                ));
            }
            Ok(root)
        },
    )?;
    sc.step("start the laptop's daemon with its CA", |cx| {
        cx.w.node_mut("laptop").cfg.identity = Some(root.identity.clone());
        cx.w.node_mut("laptop").cfg.ca = Some(CaCfg {
            prefix: ns.into(),
            identity: format!("{ns}/CA"),
            member_days: None,
        });
        cx.start("laptop")
    })?;
    let invites = sc.step("make two member invites at the laptop's CA", |cx| {
        mint(cx, "laptop", ns, &root.fp, 2, Some("1h"))
    })?;
    sc.step(
        "start the tab's and the phone's daemons; each enrolls by invite over its UDP face",
        |cx| {
            for (node, device, invite) in
                [("tab", &tab, &invites[0]), ("phone", &phone, &invites[1])]
            {
                cx.start(node)?;
                let short = device.rsplit('/').next().unwrap_or(device);
                let c = enroll(cx, node, invite, short, false, None)?;
                if !c.starts_with(&format!("{device}/KEY/")) {
                    return Err(format!(
                        "{node} was certified as {c}, expected a certificate of {device}"
                    ));
                }
                cx.evidence(&format!("{node} enrolled: {c}"));
            }
            Ok(())
        },
    )?;
    sc.step(
        &format!("the devices link over QUIC and carry {group} over each link"),
        |cx| {
            for (node, peer) in [
                ("laptop", &tab),
                ("laptop", &phone),
                ("tab", &phone),
                ("phone", &laptop),
            ] {
                let mut found = None;
                wait_for(
                    cx,
                    &format!("{node} carries {group} over its link to {peer}"),
                    SHORT,
                    |cx| {
                        found = carries_group(cx, node, peer, &group)?;
                        Ok(found.is_some())
                    },
                )?;
                cx.evidence(&format!("{node} → {peer}: {}", found.unwrap_or_default()));
            }
            Ok(())
        },
    )?;
    Ok(root)
}
