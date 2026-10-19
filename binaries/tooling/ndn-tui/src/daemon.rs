//! The running daemon, as the TUI asks it: every listing and command over
//! one management connection, answered as typed data or a [`Failure`].
//!
//! Nothing here words anything: refusals stay coded ([`TrustRefusal`]) for
//! [`crate::words`].

use std::path::Path;
use std::time::Duration;

use ndn_cert::OutgoingRequest;
use ndn_cert::report::{
    AdoptedContextInfo, ApprovalDecision, ContextRefreshInfo, DataInspection, Detail,
    EnrollOutcome, IdentityStatus, MembershipInfo, TrustRefusal,
};
use ndn_cert::{CaInviteListing, CaIssuedListing, CreatedInvite, InviteEntry, InviteRequest};
use ndn_ipc::{ForwarderError, MgmtClient, trust_refusal_in};
use ndn_mgmt_wire::{
    ApprovalListing, CsListing, FaceStatus, FibEntry, LinkListing, LinkModeArg, RibEntry,
};
use ndn_packet::Name;

use crate::model::{Anchor, Listing, RootFacts, Update};

/// How long a command that needs the network (adopting, enrolling, deciding
/// on an admin device, checking for a newer version) may take.
pub const NETWORK_TIMEOUT: Duration = Duration::from_secs(20);
/// How long a listing may take.
pub const LIST_TIMEOUT: Duration = Duration::from_secs(10);

/// Why something the TUI asked for did not happen.
#[derive(Debug, Clone, PartialEq)]
pub enum Failure {
    /// The daemon (or a root operation) refused, with a code.
    Refused(TrustRefusal),
    /// The daemon could not be asked, or answered something unreadable.
    Unreachable(String),
}

impl Failure {
    /// The refusal's code, if it is one.
    pub fn code(&self) -> Option<&str> {
        match self {
            Failure::Refused(r) => Some(&r.code),
            Failure::Unreachable(_) => None,
        }
    }

    /// The refusal, if it is one.
    pub fn refusal(&self) -> Option<&TrustRefusal> {
        match self {
            Failure::Refused(r) => Some(r),
            Failure::Unreachable(_) => None,
        }
    }

    /// What the person reads.
    pub fn words(&self) -> String {
        match self {
            Failure::Refused(r) => {
                let next = crate::words::next_step(r.next);
                let sentence = crate::words::refusal(r);
                if next.is_empty() {
                    sentence
                } else {
                    format!("{sentence} {next}")
                }
            }
            Failure::Unreachable(why) => format!("The daemon could not be asked: {why}"),
        }
    }
}

impl From<ForwarderError> for Failure {
    fn from(e: ForwarderError) -> Self {
        match trust_refusal_in(&e) {
            Some(refusal) => Failure::Refused(refusal),
            None => match e {
                ForwarderError::Command { code, text } => {
                    Failure::Unreachable(format!("refused ({code}): {text}"))
                }
                other => Failure::Unreachable(other.to_string()),
            },
        }
    }
}

impl From<ndn_namespace::root::RootError> for Failure {
    fn from(e: ndn_namespace::root::RootError) -> Self {
        Failure::Refused(e.into_parts().0)
    }
}

/// A command answer in the ControlResponse status text: its JSON, or the
/// refusal it carries.
fn answer<T: serde::de::DeserializeOwned>(
    resp: ndn_mgmt_wire::ControlResponse,
) -> Result<T, Failure> {
    if !resp.is_ok() {
        return Err(match ndn_ipc::trust_refusal(&resp) {
            Some(refusal) => Failure::Refused(refusal),
            None => Failure::Unreachable(format!(
                "refused ({}): {}",
                resp.status_code, resp.status_text
            )),
        });
    }
    serde_json::from_str(&resp.status_text)
        .map_err(|e| Failure::Unreachable(format!("an unreadable answer ({e})")))
}

/// The routes and faces of the forwarder: what is served here, and what
/// each link carries.
#[derive(Debug, Clone, Default)]
pub struct Routes {
    pub rib: Vec<RibEntry>,
    pub fib: Vec<FibEntry>,
    pub faces: Vec<FaceStatus>,
}

/// The daemon at one management socket.
pub struct Daemon {
    client: MgmtClient,
    socket: String,
}

impl Daemon {
    /// Connect to the daemon's management socket.
    pub async fn connect(socket: &str) -> Result<Self, Failure> {
        let client = MgmtClient::connect(socket).await?;
        Ok(Self {
            client,
            socket: socket.to_owned(),
        })
    }

    /// Where it is reached.
    pub fn socket(&self) -> &str {
        &self.socket
    }

    pub async fn identity(&self) -> Result<IdentityStatus, Failure> {
        Ok(self.client.security_identity_status().await?)
    }

    pub async fn memberships(&self) -> Result<Vec<MembershipInfo>, Failure> {
        answer(self.client.security_memberships().await?)
    }

    pub async fn approvals(&self) -> Result<ApprovalListing, Failure> {
        Ok(self.client.ca_list_approvals(NETWORK_TIMEOUT).await?)
    }

    pub async fn invites(&self) -> Result<Vec<CaInviteListing>, Failure> {
        Ok(self.client.ca_invite_list(None).await?)
    }

    pub async fn issued(&self) -> Result<Vec<CaIssuedListing>, Failure> {
        Ok(self.client.ca_issued_list(None).await?)
    }

    /// This device's own requests for an admin's approval.
    pub async fn requests(&self) -> Result<Vec<OutgoingRequest>, Failure> {
        answer(self.client.security_enroll_status(LIST_TIMEOUT).await?)
    }

    pub async fn links(&self) -> Result<LinkListing, Failure> {
        Ok(self.client.link_list(LIST_TIMEOUT).await?)
    }

    pub async fn routes(&self) -> Result<Routes, Failure> {
        Ok(Routes {
            rib: self.client.rib_list().await?,
            fib: self.client.route_list().await?,
            faces: self.client.face_list().await?,
        })
    }

    /// What the content store holds under `prefix`, at most `limit` names.
    pub async fn cached(&self, prefix: Option<&Name>, limit: u64) -> Result<CsListing, Failure> {
        Ok(self.client.cs_list(prefix, limit).await?)
    }

    /// Fetch the Data `name` names and check it.
    pub async fn inspect(&self, name: &Name) -> Result<DataInspection, Failure> {
        Ok(self
            .client
            .security_data_inspect(name, NETWORK_TIMEOUT)
            .await?)
    }

    /// Check for newer versions of `namespace`'s trust context (every held
    /// one when `None`).
    pub async fn refresh(
        &self,
        namespace: Option<&Name>,
    ) -> Result<Vec<ContextRefreshInfo>, Failure> {
        answer(
            self.client
                .security_context_refresh(namespace, NETWORK_TIMEOUT)
                .await?,
        )
    }

    pub async fn create_invite(
        &self,
        ca: &Name,
        request: &InviteRequest,
    ) -> Result<CreatedInvite, Failure> {
        Ok(self.client.ca_invite_create(Some(ca), request).await?)
    }

    pub async fn withdraw_invite(&self, ca: &Name, id: &str) -> Result<InviteEntry, Failure> {
        Ok(self.client.ca_invite_withdraw(Some(ca), id).await?)
    }

    /// Approve the request with id `request`.
    pub async fn approve(&self, request: &str) -> Result<ApprovalDecision, Failure> {
        Ok(self.client.ca_approve(request, NETWORK_TIMEOUT).await?)
    }

    /// Deny the request with id `request`, saying `reason` (may be empty).
    pub async fn deny(&self, request: &str, reason: &str) -> Result<ApprovalDecision, Failure> {
        Ok(self
            .client
            .ca_deny(request, reason, NETWORK_TIMEOUT)
            .await?)
    }

    /// Follow a trusted prefix: adopt the trust context an anchor link
    /// names.
    pub async fn follow(&self, link: &str) -> Result<AdoptedContextInfo, Failure> {
        answer(
            self.client
                .security_context_adopt(link, NETWORK_TIMEOUT)
                .await?,
        )
    }

    /// Join a trusted prefix as `identity` (`/<prefix>/<role>/<device>`):
    /// with an invite link, or an anchor link to ask for an admin's
    /// approval.
    pub async fn join(&self, link: &str, identity: &Name) -> Result<EnrollOutcome, Failure> {
        answer(
            self.client
                .security_enroll(link, identity, false, NETWORK_TIMEOUT)
                .await?,
        )
    }

    pub async fn set_link_mode(&self, label: &str, mode: LinkModeArg) -> Result<Detail, Failure> {
        Ok(self.client.link_mode(label, mode).await?)
    }

    pub async fn connect_link(&self, label: &str) -> Result<Detail, Failure> {
        Ok(self.client.link_connect(label).await?)
    }

    pub async fn disconnect_link(&self, label: &str) -> Result<Detail, Failure> {
        Ok(self.client.link_disconnect(label).await?)
    }

    /// Read `listing` again, as an update for the model. `pib` is the key
    /// storage of this device (the daemon's), where the root facts are read.
    pub async fn load(&self, listing: Listing, pib: Option<&Path>) -> Update {
        match listing {
            Listing::Identity => Update::Identity(self.identity().await),
            Listing::Memberships => Update::Memberships(self.memberships().await),
            Listing::Approvals => Update::Approvals(self.approvals().await),
            Listing::Invites => Update::Invites(self.invites().await),
            Listing::Issued => Update::Issued(self.issued().await),
            Listing::Requests => Update::Requests(self.requests().await),
            Listing::Links => Update::Links(self.links().await),
            Listing::Routes => Update::Routes(self.routes().await),
            Listing::Cached => Update::Cached(self.cached(None, CACHED_LIMIT).await),
            Listing::Refresh => Update::Refreshed(self.refresh(None).await),
            Listing::Roots => Update::Roots(match pib {
                Some(pib) => read_roots(pib),
                None => Ok(Vec::new()),
            }),
        }
    }
}

/// How many cached names the data screen lists.
pub const CACHED_LIMIT: u64 = 500;

/// The root keys this device's key storage at `pib` holds, with the
/// recovery kits of each prefix (empty on a device that is no main device).
pub fn read_roots(pib: &Path) -> Result<Vec<RootFacts>, Failure> {
    use ndn_namespace::root::{key, kit};
    let statuses = key::open(pib)?.status(None)?;
    if statuses.is_empty() {
        return Ok(Vec::new());
    }
    let kits = kit::list(pib, None)?;
    Ok(statuses
        .into_iter()
        .map(|status| {
            let held = kits
                .contexts
                .iter()
                .find(|c| c.namespace == status.namespace);
            RootFacts {
                namespace: status.namespace.to_string(),
                key: status.key.to_string(),
                store: status.store.kind.as_str().to_owned(),
                location: status.store.location.clone(),
                version: held.map(|c| c.version),
                anchors: held
                    .map(|c| {
                        c.anchors
                            .iter()
                            .map(|a| Anchor {
                                key: a.key.to_string(),
                                recovery_kit: a.recovery_kit,
                                fingerprint: hex(&a.fingerprint),
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            }
        })
        .collect())
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}
