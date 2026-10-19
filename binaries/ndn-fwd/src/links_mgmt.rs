//! `/localhost/nfd/links/*`: `list` — this device's QUIC links, the paths
//! that reach each linked device, the state of its direct path, its mode,
//! relay and sleep state, from [`Links::report`] (`ndn-ctl link list` prints
//! it); `connect`, `disconnect` and `mode` — the link commands of
//! `ndn-ctl link`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ndn_link::{LinkMode, LinkReport, LinkStatus, Links, PathStatus, PeerId};
use ndn_mgmt::{MgmtContext, MgmtModule, MgmtResponse};
use ndn_mgmt_wire::control_response::status;
use ndn_mgmt_wire::nfd_command::{module, verb};
use ndn_mgmt_wire::{
    ControlParameters, ControlResponse, LinkAsleepEntry, LinkEntry, LinkListing, LinkModeArg,
    LinkPathEntry, LinkRelayEntry, parse_link_command,
};

/// Serves the links module. `links = None` when this daemon runs no QUIC
/// links.
pub(crate) struct LinksMgmtModule {
    links: Option<Arc<Links>>,
}

impl LinksMgmtModule {
    pub(crate) fn new(links: Option<Arc<Links>>) -> Self {
        Self { links }
    }
}

#[async_trait]
impl MgmtModule for LinksMgmtModule {
    fn name(&self) -> &'static [u8] {
        module::LINKS
    }

    async fn dispatch(
        &self,
        verb_name: &[u8],
        params: ControlParameters,
        _ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        let known = [verb::LIST, verb::CONNECT, verb::DISCONNECT, verb::MODE];
        if !known.contains(&verb_name) {
            return ControlResponse::error(
                status::NOT_FOUND,
                "unknown links verb; the links module answers `list`, `connect`, `disconnect` and `mode`",
            )
            .into();
        }
        let Some(links) = &self.links else {
            return ControlResponse::error(
                status::NOT_FOUND,
                "this daemon runs no QUIC links: it has no key ([security] profile = \"disabled\"); \
                 enable security to link",
            )
            .into();
        };
        if verb_name == verb::LIST {
            return MgmtResponse::Dataset(listing(links.report()).encode());
        }
        command(links, verb_name, &params).into()
    }
}

/// `connect`, `disconnect` or `mode` on the link the parameters label.
fn command(links: &Links, verb_name: &[u8], params: &ControlParameters) -> ControlResponse {
    let (label, mode) = match parse_link_command(params) {
        Ok(parsed) => parsed,
        Err(why) => return ControlResponse::error(status::BAD_PARAMS, why),
    };
    let report = links.report();
    let Some(link) = report.links.iter().find(|l| l.label == label) else {
        return ControlResponse::error(
            status::NOT_FOUND,
            format!("no link is labelled {label:?}; `ndn-ctl link list` shows the labels"),
        );
    };
    let Some(peer) = link.peer else {
        return ControlResponse::error(
            status::BAD_PARAMS,
            format!(
                "{label:?} linked in and is not configured, so it has no mode to set and is not \
                 dialled: add it as a [[peer]] (or [[relay]]) to control its link"
            ),
        );
    };
    match verb_name {
        v if v == verb::CONNECT => {
            links.connect(peer);
            ControlResponse::ok_empty(format!(
                "linking to {label}, whatever its mode, until it is disconnected"
            ))
        }
        v if v == verb::DISCONNECT => {
            links.disconnect(peer);
            ControlResponse::ok_empty(format!(
                "no longer asking for the link to {label}: an `off` link closes now, an `on-demand` one once \
                 idle; an `always` link stays up (set its mode to off to close it)"
            ))
        }
        _ => set_mode(links, peer, &label, link.mode, mode),
    }
}

/// Idle close of `on-demand` without seconds when the link is not on demand
/// already: the config's default.
const DEFAULT_IDLE: Duration = Duration::from_secs(60);
/// Bounds of the idle close, as the config takes it.
const IDLE_SECS: std::ops::RangeInclusive<u64> = 10..=86_400;

fn set_mode(
    links: &Links,
    peer: PeerId,
    label: &str,
    current: Option<LinkMode>,
    mode: Option<LinkModeArg>,
) -> ControlResponse {
    let Some(mode) = mode else {
        return ControlResponse::error(
            status::BAD_PARAMS,
            "name the mode in LocalUri: always, on-demand, on-demand:<idle seconds> or off",
        );
    };
    let mode = match mode {
        LinkModeArg::Always => LinkMode::Always,
        LinkModeArg::Off => LinkMode::Off,
        LinkModeArg::OnDemand {
            idle_secs: Some(secs),
        } if !IDLE_SECS.contains(&secs) => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                format!(
                    "idle close {secs} s is outside {}..={} s: below that an on-demand link closes \
                     between the packets of one exchange; pick a value in range",
                    IDLE_SECS.start(),
                    IDLE_SECS.end()
                ),
            );
        }
        LinkModeArg::OnDemand {
            idle_secs: Some(secs),
        } => LinkMode::OnDemand {
            idle: Duration::from_secs(secs),
        },
        LinkModeArg::OnDemand { idle_secs: None } => LinkMode::OnDemand {
            idle: match current {
                Some(LinkMode::OnDemand { idle }) => idle,
                _ => DEFAULT_IDLE,
            },
        },
    };
    links.set_mode(peer, mode);
    ControlResponse::ok_empty(format!(
        "{label} is now {} (until the daemon restarts)",
        mode_text(mode)
    ))
}

fn mode_text(mode: LinkMode) -> String {
    match mode {
        LinkMode::OnDemand { idle } => {
            format!("on-demand, closing after {} s idle", idle.as_secs())
        }
        other => other.as_str().to_owned(),
    }
}

fn listing(report: LinkReport) -> LinkListing {
    LinkListing {
        key: report.key.map(|k| k.0),
        probes_sent: report.probes_sent,
        punches_refused: report.punches_refused,
        links: report.links.into_iter().map(entry).collect(),
        serve: report.serve,
        held_total: report.held_total as u64,
        wakes_sent: report.wakes_sent,
    }
}

fn entry(link: LinkStatus) -> LinkEntry {
    LinkEntry {
        label: link.label,
        key: link.key.map(|k| k.0),
        device: link.device,
        paths: link.paths.into_iter().map(path).collect(),
        direct_state: link.direct.state.as_str().to_owned(),
        direct_text: link.direct.text,
        retry_in_secs: link.direct.retry_in.map(|d| d.as_secs()),
        mode: link.mode.map(|m| m.as_str().to_owned()),
        idle_secs: match link.mode {
            Some(LinkMode::OnDemand { idle }) => Some(idle.as_secs()),
            _ => None,
        },
        relay: link.relay.map(|r| LinkRelayEntry {
            source: r.source.describe(),
            preference: u64::from(r.preference),
            state: r.state.as_str().to_owned(),
            text: r.text,
        }),
        asleep: link.asleep.map(|a| LinkAsleepEntry {
            since_secs: a.since.as_secs(),
            held: a.held as u64,
            hold: a.hold,
            wake: a.wake,
            wakes: a.wakes,
        }),
        down: link.down,
    }
}

fn path(path: PathStatus) -> LinkPathEntry {
    LinkPathEntry {
        kind: path.kind.as_str().to_owned(),
        face_id: path.face.0,
        remote: path.remote.map(|a| a.to_string()),
        rtt_micros: path
            .rtt
            .map(|d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX)),
        age_secs: path.age.as_secs(),
        via: path.via,
    }
}
