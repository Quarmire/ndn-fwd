//! `/localhost/nfd/links/*`: `list` — this device's QUIC links, the paths
//! that reach each linked device, the state of its direct path, its mode,
//! relay and sleep state, from [`Links::report`] (`ndn-ctl link list` prints
//! it); `connect`, `disconnect` and `mode` — the link commands of
//! `ndn-ctl link`.
//!
//! A command answers a [`Detail`] as JSON in the status text (codes
//! `linking`, `link-released`, `link-mode-set`); a refusal is a
//! [`TrustRefusal`] (the `links` codes of `ndn_cert::report::code`). Their
//! sentences name no host command or configuration: clients word them.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ndn_cert::report::{Detail, TrustRefusal, code};
use ndn_link::{LinkMode, LinkReport, LinkStatus, Links, PathStatus, PeerId};
use ndn_mgmt::{MgmtContext, MgmtModule, MgmtResponse, refusal_response};
use ndn_mgmt_wire::control_response::status;
use ndn_mgmt_wire::nfd_command::{module, verb};
use ndn_mgmt_wire::{
    ControlParameters, ControlResponse, LinkAsleepEntry, LinkCommandError, LinkEntry, LinkListing,
    LinkModeArg, LinkPathEntry, LinkRelayEntry, link_code, parse_link_command,
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
        let links = match running(verb_name, self.links.as_ref()) {
            Ok(links) => links,
            Err(refusal) => return refusal_response(&refusal).into(),
        };
        if verb_name == verb::LIST {
            return MgmtResponse::Dataset(listing(links.report()).encode());
        }
        match command(links, verb_name, &params) {
            Ok(done) => answer(&done),
            Err(refusal) => refusal_response(&refusal),
        }
        .into()
    }
}

/// The links `verb_name` acts on: refused when the module has no such verb,
/// or when this daemon runs no links (`links = None`).
fn running<'a>(
    verb_name: &[u8],
    links: Option<&'a Arc<Links>>,
) -> Result<&'a Arc<Links>, TrustRefusal> {
    let known = [verb::LIST, verb::CONNECT, verb::DISCONNECT, verb::MODE];
    if !known.contains(&verb_name) {
        let asked = String::from_utf8_lossy(verb_name);
        return Err(TrustRefusal::new(
            code::LINKS_UNKNOWN_VERB,
            format!(
                "the links module has no verb {asked:?}; it answers list, connect, disconnect and \
                 mode"
            ),
        )
        .with("verb", asked));
    }
    links.ok_or_else(|| {
        TrustRefusal::new(
            code::LINKS_NOT_RUNNING,
            "this node runs no QUIC links: it has no key (security is disabled)",
        )
    })
}

/// A command's answer: `done` as JSON in the status text.
fn answer(done: &Detail) -> ControlResponse {
    match serde_json::to_string(done) {
        Ok(json) => ControlResponse::ok_empty(json),
        Err(e) => ControlResponse::error(status::SERVER_ERROR, format!("encode: {e}")),
    }
}

/// `connect`, `disconnect` or `mode` on the link the parameters label.
fn command(
    links: &Links,
    verb_name: &[u8],
    params: &ControlParameters,
) -> Result<Detail, TrustRefusal> {
    let (label, mode) = parse_link_command(params).map_err(|e| match e {
        LinkCommandError::NoLabel => TrustRefusal::new(
            code::LINK_LABEL_MISSING,
            "the command names no link: give its label, as the link listing shows it",
        ),
        LinkCommandError::BadMode(m) => TrustRefusal::new(
            code::LINK_MODE_INVALID,
            format!(
                "{m:?} is not a link mode: use always, on-demand, on-demand:<idle seconds> \
                 (e.g. on-demand:60) or off"
            ),
        )
        .with("mode", m),
    })?;
    let report = links.report();
    let Some(link) = report.links.iter().find(|l| l.label == label) else {
        return Err(TrustRefusal::new(
            code::LINK_NOT_FOUND,
            format!("no link is labelled {label:?}; the link listing shows the labels"),
        )
        .with("label", label));
    };
    let Some(peer) = link.peer else {
        return Err(TrustRefusal::new(
            code::LINK_NOT_CONFIGURED,
            format!(
                "{label:?} linked in and is not configured, so it has no mode to set and is not \
                 dialled: configure it as a device or relay to link with to control its link"
            ),
        )
        .with("label", label));
    };
    match verb_name {
        v if v == verb::CONNECT => {
            links.connect(peer);
            Ok(Detail::new(
                link_code::LINKING,
                format!("linking to {label}, whatever its mode, until it is disconnected"),
            )
            .with("label", label))
        }
        v if v == verb::DISCONNECT => {
            links.disconnect(peer);
            Ok(Detail::new(
                link_code::LINK_RELEASED,
                format!(
                    "no longer asking for the link to {label}: an `off` link closes now, an \
                     `on-demand` one once idle; an `always` link stays up (set its mode to off to \
                     close it)"
                ),
            )
            .with("label", label))
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
) -> Result<Detail, TrustRefusal> {
    let Some(mode) = mode else {
        return Err(TrustRefusal::new(
            code::LINK_MODE_MISSING,
            "the command names no mode: always, on-demand, on-demand:<idle seconds> or off",
        ));
    };
    let mode = match mode {
        LinkModeArg::Always => LinkMode::Always,
        LinkModeArg::Off => LinkMode::Off,
        LinkModeArg::OnDemand {
            idle_secs: Some(secs),
        } if !IDLE_SECS.contains(&secs) => {
            return Err(TrustRefusal::new(
                code::LINK_IDLE_OUT_OF_RANGE,
                format!(
                    "idle close {secs} s is outside {}..={} s: below that an on-demand link closes \
                     between the packets of one exchange; pick a value in range",
                    IDLE_SECS.start(),
                    IDLE_SECS.end()
                ),
            )
            .with("idle_secs", secs)
            .with("min", IDLE_SECS.start())
            .with("max", IDLE_SECS.end()));
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
    let done = Detail::new(
        link_code::LINK_MODE_SET,
        format!(
            "{label} is now {} (until the daemon restarts)",
            mode_text(mode)
        ),
    )
    .with("label", label)
    .with("mode", mode.as_str());
    Ok(match mode {
        LinkMode::OnDemand { idle } => done.with("idle_secs", idle.as_secs()),
        _ => done,
    })
}

fn mode_text(mode: LinkMode) -> String {
    match mode {
        LinkMode::OnDemand { idle } => {
            format!("on-demand, closing after {} s idle", idle.as_secs())
        }
        other => other.as_str().to_owned(),
    }
}

pub(crate) fn listing(report: LinkReport) -> LinkListing {
    LinkListing {
        key: report.key.map(|k| k.0),
        probes_sent: report.probes_sent,
        punches_refused: report.punches_refused,
        links: report.links.into_iter().map(entry).collect(),
        serve: Some(report.serve),
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
        direct: link.direct.detail,
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
            detail: Some(r.detail),
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_face_quic::{KeyFingerprint, LinkKey, LinkKeySource, LinkTransportConfig};
    use ndn_link::{ConfiguredEndpoints, FaceSink, LinkSetup, LinkTrust, PeerSpec, Route};
    use ndn_packet::Name;
    use ndn_security::{Certificate, Ed25519Signer, Keyring};
    use ndn_transport::{Face, FaceId};
    use tokio_util::sync::CancellationToken;

    struct NoTrust(Arc<Keyring>);

    impl LinkTrust for NoTrust {
        fn keyring(&self) -> &Arc<Keyring> {
            &self.0
        }
        fn own_chain(&self) -> Vec<Bytes> {
            Vec::new()
        }
        fn known_certificate(&self, _: &Name) -> Option<Certificate> {
            None
        }
        fn known_certificate_of_key(&self, _: &KeyFingerprint) -> Option<Certificate> {
            None
        }
    }

    struct NoFaces;

    impl FaceSink for NoFaces {
        fn alloc_face_id(&self) -> FaceId {
            FaceId(1)
        }
        fn add_face(&self, _: Face, _: CancellationToken) {}
        fn remove_face(&self, _: FaceId) {}
        fn add_routes(&self, _: FaceId, _: &[Route]) {}
        fn remove_routes(&self, _: FaceId, _: &[Name]) {}
        fn transit(&self, _: &Name, _: bool) {}
    }

    /// Links with one configured device, `vps`, that is never dialled.
    fn links(cancel: &CancellationToken) -> Arc<Links> {
        let key = LinkKey::from_signer(Arc::new(Ed25519Signer::from_seed(
            &[7; 32],
            "/ns/member/d/KEY/k".parse().unwrap(),
        )))
        .unwrap();
        let peer = PeerSpec {
            label: "vps".into(),
            key: Some(KeyFingerprint([9; 32])),
            mode: LinkMode::Off,
            persistent: false,
            ..PeerSpec::default()
        };
        Links::start(
            LinkSetup {
                peers: vec![peer],
                key: Arc::new(key) as Arc<dyn LinkKeySource>,
                trust: Arc::new(NoTrust(Arc::new(Keyring::new()))),
                faces: Arc::new(NoFaces),
                paths: Arc::new(ConfiguredEndpoints),
                candidates: Vec::new(),
                socket: None,
                transport: LinkTransportConfig::default(),
                relays: Default::default(),
                service: Default::default(),
                direct: Default::default(),
            },
            cancel.child_token(),
        )
    }

    /// Whether `text` names a host's command or configuration.
    fn names_the_host(text: &str) -> bool {
        ["ndn-fwd", "ndn-ctl", "[[", "[security]"]
            .iter()
            .any(|host| text.contains(host))
    }

    fn mode(label: &str, mode: Option<&str>) -> ControlParameters {
        ControlParameters {
            uri: Some(label.into()),
            local_uri: mode.map(Into::into),
            ..Default::default()
        }
    }

    /// Every links answer — a command done or refused, the listing's
    /// details — carries its code, and none names the host's commands or
    /// configuration.
    #[tokio::test]
    async fn link_answers_are_coded_and_name_no_host() {
        let cancel = CancellationToken::new();
        let links = links(&cancel);

        let mut refusals = vec![
            (
                running(b"rename", Some(&links)).err().unwrap(),
                code::LINKS_UNKNOWN_VERB,
            ),
            (
                running(verb::LIST, None).err().unwrap(),
                code::LINKS_NOT_RUNNING,
            ),
        ];
        for (verb_name, params, expected) in [
            (
                verb::CONNECT,
                ControlParameters::default(),
                code::LINK_LABEL_MISSING,
            ),
            (
                verb::MODE,
                mode("vps", Some("sometimes")),
                code::LINK_MODE_INVALID,
            ),
            (verb::CONNECT, mode("laptop", None), code::LINK_NOT_FOUND),
            (verb::MODE, mode("vps", None), code::LINK_MODE_MISSING),
            (
                verb::MODE,
                mode("vps", Some("on-demand:1")),
                code::LINK_IDLE_OUT_OF_RANGE,
            ),
        ] {
            refusals.push((command(&links, verb_name, &params).err().unwrap(), expected));
        }
        for (refusal, expected) in &refusals {
            assert!(refusal.is(*expected), "{refusal:?}");
            let json = serde_json::to_string(refusal).unwrap();
            assert!(!names_the_host(&json), "{json}");
        }

        for (verb_name, params, expected) in [
            (verb::CONNECT, mode("vps", None), link_code::LINKING),
            (
                verb::DISCONNECT,
                mode("vps", None),
                link_code::LINK_RELEASED,
            ),
            (
                verb::MODE,
                mode("vps", Some("on-demand:60")),
                link_code::LINK_MODE_SET,
            ),
            (
                verb::MODE,
                mode("vps", Some("off")),
                link_code::LINK_MODE_SET,
            ),
        ] {
            let done = command(&links, verb_name, &params).unwrap();
            assert_eq!(done.code, expected);
            assert_eq!(done.param("label"), Some("vps"));
            let json = serde_json::to_string(&done).unwrap();
            assert!(!names_the_host(&json), "{json}");
        }

        let listing = listing(links.report());
        let mut details: Vec<&ndn_mgmt_wire::LinkDetail> = listing.serve.iter().collect();
        for link in &listing.links {
            details.extend(link.direct.iter().chain(&link.down));
            details.extend(link.relay.iter().filter_map(|r| r.detail.as_ref()));
        }
        assert!(!details.is_empty());
        while let Some(detail) = details.pop() {
            assert!(link_code::ALL.contains(&detail.code.as_str()), "{detail:?}");
            assert!(!names_the_host(&detail.text), "{detail:?}");
            details.extend(&detail.causes);
        }
        cancel.cancel();
    }
}
