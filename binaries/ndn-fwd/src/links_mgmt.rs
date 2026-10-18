//! `/localhost/nfd/links/list`: this device's QUIC links, the paths that
//! reach each linked device and the state of its direct path, from
//! [`Links::report`] (`ndn-ctl link list` prints it).

use std::sync::Arc;

use async_trait::async_trait;
use ndn_link::{LinkReport, LinkStatus, Links, PathStatus};
use ndn_mgmt::{MgmtContext, MgmtModule, MgmtResponse};
use ndn_mgmt_wire::control_response::status;
use ndn_mgmt_wire::nfd_command::{module, verb};
use ndn_mgmt_wire::{ControlParameters, ControlResponse, LinkEntry, LinkListing, LinkPathEntry};

/// Serves `links/list`. `links = None` when this daemon runs no QUIC links.
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
        _params: ControlParameters,
        _ctx: &MgmtContext<'_>,
    ) -> MgmtResponse {
        if verb_name != verb::LIST {
            return ControlResponse::error(
                status::NOT_FOUND,
                "unknown links verb; the links module answers `list`",
            )
            .into();
        }
        let Some(links) = &self.links else {
            return ControlResponse::error(
                status::NOT_FOUND,
                "this daemon runs no QUIC links ([[peer]] or [[face]] kind = \"quic\")",
            )
            .into();
        };
        MgmtResponse::Dataset(listing(links.report()).encode())
    }
}

fn listing(report: LinkReport) -> LinkListing {
    LinkListing {
        key: report.key.map(|k| k.0),
        probes_sent: report.probes_sent,
        punches_refused: report.punches_refused,
        links: report.links.into_iter().map(entry).collect(),
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
