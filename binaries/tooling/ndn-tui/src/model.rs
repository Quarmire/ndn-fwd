//! What the TUI knows about the device: the daemon's listings, the root
//! facts read from this device's own key storage, and the event log —
//! updated in place as listings arrive and events happen.
//!
//! Events carry identifiers and states only; each one says which listings
//! to read again ([`Model::apply`] returns them). This is the TUI's state
//! layer: the screens only read it, and a test can drive it without a
//! terminal.

use std::collections::{BTreeMap, VecDeque};

use ndn_cert::report::{
    ContextRefreshInfo, IdentityStatus, MembershipInfo, MembershipRelation, RefreshState,
    TrustEvent,
};
use ndn_cert::{CaInviteListing, CaIssuedListing, InviteEntry, InviteState, IssuedEntry};
use ndn_cert::{OutgoingRequest, OutgoingState};
use ndn_mgmt_wire::events::LinkEvent;
use ndn_mgmt_wire::{ApprovalListing, CsListing, LinkEntry, LinkListing, PendingApproval};
use ndn_packet::Name;

use crate::daemon::{Failure, Routes};

/// A listing the TUI reads from the daemon (or, for [`Listing::Roots`],
/// from this device's key storage).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Listing {
    Identity,
    Memberships,
    Approvals,
    Invites,
    Issued,
    Requests,
    Links,
    Routes,
    Cached,
    Refresh,
    Roots,
}

impl Listing {
    /// Every listing, in the order a first load reads them.
    pub const ALL: [Listing; 11] = [
        Listing::Identity,
        Listing::Memberships,
        Listing::Roots,
        Listing::Approvals,
        Listing::Invites,
        Listing::Issued,
        Listing::Requests,
        Listing::Links,
        Listing::Routes,
        Listing::Cached,
        Listing::Refresh,
    ];

    /// The listings a trust stream's resync reads again.
    pub const TRUST: [Listing; 7] = [
        Listing::Identity,
        Listing::Memberships,
        Listing::Roots,
        Listing::Approvals,
        Listing::Invites,
        Listing::Issued,
        Listing::Requests,
    ];
}

/// A recovery kit or root anchor of a prefix this device is the main
/// device of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub key: String,
    pub recovery_kit: bool,
    /// Hex fingerprint.
    pub fingerprint: String,
}

/// The root key of a prefix this device is the main device of, and its
/// recovery kits, as this device's key storage holds them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootFacts {
    pub namespace: String,
    pub key: String,
    /// `os-keyring`, `sealed-file`, `yubikey-piv`, `file`.
    pub store: String,
    pub location: String,
    /// The version the key storage holds, when it holds one.
    pub version: Option<u64>,
    pub anchors: Vec<Anchor>,
}

impl RootFacts {
    pub fn kits(&self) -> impl Iterator<Item = &Anchor> {
        self.anchors.iter().filter(|a| a.recovery_kit)
    }
}

/// A listing as last read: its value (kept when a later read fails) and
/// why the last read failed.
#[derive(Debug, Clone, PartialEq)]
pub struct Fact<T> {
    pub value: Option<T>,
    pub failure: Option<Failure>,
}

impl<T> Default for Fact<T> {
    fn default() -> Self {
        Self {
            value: None,
            failure: None,
        }
    }
}

impl<T> Fact<T> {
    fn set(&mut self, read: Result<T, Failure>) {
        match read {
            Ok(value) => {
                self.value = Some(value);
                self.failure = None;
            }
            Err(failure) => self.failure = Some(failure),
        }
    }

    pub fn get(&self) -> Option<&T> {
        self.value.as_ref()
    }
}

/// What arrived for the model.
#[derive(Debug, Clone)]
pub enum Update {
    Identity(Result<IdentityStatus, Failure>),
    Memberships(Result<Vec<MembershipInfo>, Failure>),
    Approvals(Result<ApprovalListing, Failure>),
    Invites(Result<Vec<CaInviteListing>, Failure>),
    Issued(Result<Vec<CaIssuedListing>, Failure>),
    Requests(Result<Vec<OutgoingRequest>, Failure>),
    Links(Result<LinkListing, Failure>),
    Routes(Result<Routes, Failure>),
    /// The first page of what the content store holds.
    Cached(Result<CsListing, Failure>),
    /// The page after the cached names listed so far.
    CachedPage(Result<CsListing, Failure>),
    Refreshed(Result<Vec<ContextRefreshInfo>, Failure>),
    Roots(Result<Vec<RootFacts>, Failure>),
    /// Event number `seq` of the trust stream.
    Trust {
        seq: u64,
        event: TrustEvent,
    },
    /// Event number `seq` of the links stream.
    Link {
        seq: u64,
        event: LinkEvent,
    },
    /// A stream does not hold what was asked: list again.
    Resync(Stream),
    /// A stream could not be followed (it is retried).
    StreamDown(Stream, Failure),
}

impl Update {
    /// The listing this update is a reading of, if it is one.
    pub fn listing(&self) -> Option<Listing> {
        Some(match self {
            Update::Identity(_) => Listing::Identity,
            Update::Memberships(_) => Listing::Memberships,
            Update::Approvals(_) => Listing::Approvals,
            Update::Invites(_) => Listing::Invites,
            Update::Issued(_) => Listing::Issued,
            Update::Requests(_) => Listing::Requests,
            Update::Links(_) => Listing::Links,
            Update::Routes(_) => Listing::Routes,
            Update::Cached(_) => Listing::Cached,
            Update::Refreshed(_) => Listing::Refresh,
            Update::Roots(_) => Listing::Roots,
            _ => return None,
        })
    }
}

/// The two change-notification streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Trust,
    Links,
}

/// One line of the event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// Seconds since the Unix epoch, when it arrived.
    pub at: u64,
    pub stream: Stream,
    pub seq: u64,
    /// The event's kind, as the stream names it.
    pub kind: String,
    /// The event in words.
    pub text: String,
}

/// How many events the log keeps.
pub const LOG_LINES: usize = 200;

/// Everything the screens show.
#[derive(Debug, Clone, Default)]
pub struct Model {
    pub identity: Fact<IdentityStatus>,
    pub memberships: Fact<Vec<MembershipInfo>>,
    pub approvals: Fact<ApprovalListing>,
    pub invites: Fact<Vec<CaInviteListing>>,
    pub issued: Fact<Vec<CaIssuedListing>>,
    pub requests: Fact<Vec<OutgoingRequest>>,
    pub links: Fact<LinkListing>,
    pub routes: Fact<Routes>,
    pub cached: Fact<CsListing>,
    pub roots: Fact<Vec<RootFacts>>,
    /// The last check for newer versions, by prefix.
    pub refreshed: BTreeMap<String, ContextRefreshInfo>,
    pub refresh_failure: Option<Failure>,
    pub log: VecDeque<LogLine>,
    /// Whether each stream is followed now (`None`: why not).
    pub trust_stream: Option<Failure>,
    pub links_stream: Option<Failure>,
}

/// One trusted prefix as the home screen lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixRow {
    pub namespace: String,
    pub relation: MembershipRelation,
    pub role: String,
    pub version: u64,
    /// The last check's state, if one ran.
    pub state: Option<RefreshState>,
    /// Requests waiting for this device's decision.
    pub pending: usize,
}

/// A safety warning of the home screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    /// This device is the main device of `namespace` and no recovery kit
    /// exists: losing it loses the prefix.
    NoRecoveryKit { namespace: String },
    /// The root key of `namespace` is a plain, unprotected file.
    PlainRootKey { namespace: String, location: String },
}

/// What this device may do in a prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Powers {
    /// A CA of this device makes invites for it.
    pub invite: bool,
    /// Requests for an admin's approval are decided here.
    pub approve: bool,
    /// The root key is here: remove devices, recovery kits, root key,
    /// schema.
    pub root: bool,
}

/// Unix seconds now.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether the name `name` is `prefix` or under it (both NDN URIs).
pub fn under(name: &str, prefix: &str) -> bool {
    match (name.parse::<Name>(), prefix.parse::<Name>()) {
        (Ok(name), Ok(prefix)) => name.has_prefix(&prefix),
        _ => false,
    }
}

impl Model {
    /// Where the next page of cached names starts (`None`: every name is
    /// listed, or none was read yet).
    pub fn cached_next(&self) -> Option<Name> {
        self.cached.get()?.next_after().cloned()
    }

    /// Append `page`, the names after those listed so far. A page read
    /// before the first page was read again adds only names past the
    /// last one listed (names come in canonical order).
    fn more_cached(&mut self, page: CsListing) {
        let Some(listed) = self.cached.value.as_mut() else {
            self.cached.value = Some(page);
            return;
        };
        let last = listed.entries.last().map(|e| e.name.clone());
        listed.entries.extend(
            page.entries
                .into_iter()
                .filter(|e| last.as_ref().is_none_or(|last| e.name > *last)),
        );
        listed.total = page.total;
        listed.more = page.more;
        self.cached.failure = None;
    }

    /// Take `update` in; returns the listings to read again because of it.
    pub fn apply(&mut self, update: Update) -> Vec<Listing> {
        match update {
            Update::Identity(r) => self.identity.set(r),
            Update::Memberships(r) => self.memberships.set(r),
            Update::Approvals(r) => self.approvals.set(r),
            Update::Invites(r) => self.invites.set(r),
            Update::Issued(r) => self.issued.set(r),
            Update::Requests(r) => self.requests.set(r),
            Update::Links(r) => self.links.set(r),
            Update::Routes(r) => self.routes.set(r),
            Update::Cached(r) => self.cached.set(r),
            Update::CachedPage(Ok(page)) => self.more_cached(page),
            Update::CachedPage(Err(failure)) => self.cached.failure = Some(failure),
            Update::Roots(r) => self.roots.set(r),
            Update::Refreshed(Ok(results)) => {
                self.refresh_failure = None;
                for info in results {
                    self.refreshed.insert(info.namespace.clone(), info);
                }
            }
            Update::Refreshed(Err(failure)) => self.refresh_failure = Some(failure),
            Update::Trust { seq, event } => {
                self.set_stream(Stream::Trust, None);
                let follow = follow_up_trust(&event);
                self.log(
                    Stream::Trust,
                    seq,
                    trust_kind(&event),
                    crate::words::trust_event(&event),
                );
                return follow;
            }
            Update::Link { seq, event } => {
                self.set_stream(Stream::Links, None);
                let kind = match &event {
                    LinkEvent::LinkChanged(_) => "link-changed",
                    LinkEvent::LinkGone { .. } => "link-gone",
                    LinkEvent::Unknown => "unknown",
                };
                self.log(Stream::Links, seq, kind, crate::words::link_event(&event));
                return match event {
                    LinkEvent::Unknown => Vec::new(),
                    _ => vec![Listing::Links, Listing::Routes],
                };
            }
            Update::Resync(stream) => {
                self.set_stream(stream, None);
                return match stream {
                    Stream::Trust => Listing::TRUST.to_vec(),
                    Stream::Links => vec![Listing::Links, Listing::Routes],
                };
            }
            Update::StreamDown(stream, failure) => self.set_stream(stream, Some(failure)),
        }
        Vec::new()
    }

    fn set_stream(&mut self, stream: Stream, failure: Option<Failure>) {
        match stream {
            Stream::Trust => self.trust_stream = failure,
            Stream::Links => self.links_stream = failure,
        }
    }

    fn log(&mut self, stream: Stream, seq: u64, kind: &str, text: Option<String>) {
        let Some(text) = text else { return };
        if self.log.len() == LOG_LINES {
            self.log.pop_front();
        }
        self.log.push_back(LogLine {
            at: now_secs(),
            stream,
            seq,
            kind: kind.to_owned(),
            text,
        });
    }

    /// The memberships, owned prefixes first, then by name.
    pub fn prefixes(&self) -> Vec<PrefixRow> {
        let Some(memberships) = self.memberships.get() else {
            return Vec::new();
        };
        let mut rows: Vec<PrefixRow> = memberships
            .iter()
            .map(|m| PrefixRow {
                namespace: m.namespace.clone(),
                relation: m.relation,
                role: m.role.clone(),
                version: m.version,
                state: self.refreshed.get(&m.namespace).map(|r| r.state),
                pending: self.pending_in(&m.namespace).len(),
            })
            .collect();
        rows.sort_by(|a, b| {
            rank(a.relation)
                .cmp(&rank(b.relation))
                .then_with(|| a.namespace.cmp(&b.namespace))
        });
        rows
    }

    /// This device's membership in `namespace`.
    pub fn membership(&self, namespace: &str) -> Option<&MembershipInfo> {
        self.memberships
            .get()?
            .iter()
            .find(|m| m.namespace == namespace)
    }

    /// The trusted prefix a name falls under, of those held (the longest).
    pub fn vouching(&self, name: &str) -> Option<&str> {
        self.memberships
            .get()?
            .iter()
            .filter(|m| under(name, &m.namespace))
            .max_by_key(|m| m.namespace.len())
            .map(|m| m.namespace.as_str())
    }

    /// Every request waiting for a decision.
    pub fn pending(&self) -> Vec<&PendingApproval> {
        self.approvals
            .get()
            .map(|l| l.rows.iter().filter(|r| r.state == "pending").collect())
            .unwrap_or_default()
    }

    /// The requests waiting for a decision in `namespace`.
    pub fn pending_in(&self, namespace: &str) -> Vec<&PendingApproval> {
        self.pending()
            .into_iter()
            .filter(|r| under(&r.namespace, namespace) || under(&r.key_name, namespace))
            .collect()
    }

    /// Every request of `namespace` as listed, decided ones too.
    pub fn approvals_in(&self, namespace: &str) -> Vec<&PendingApproval> {
        self.approvals
            .get()
            .map(|l| {
                l.rows
                    .iter()
                    .filter(|r| under(&r.namespace, namespace) || under(&r.key_name, namespace))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The CA of this device that makes invites for `namespace`.
    pub fn invite_ca(&self, namespace: &str) -> Option<&CaInviteListing> {
        self.invites
            .get()?
            .iter()
            .find(|l| l.namespace == namespace)
    }

    /// The invites of `namespace`, outstanding first, newest first.
    pub fn invites_in(&self, namespace: &str) -> Vec<&InviteEntry> {
        let Some(listing) = self.invite_ca(namespace) else {
            return Vec::new();
        };
        let mut invites: Vec<&InviteEntry> = listing.invites.iter().collect();
        invites.sort_by(|a, b| {
            (a.info.state != InviteState::Outstanding)
                .cmp(&(b.info.state != InviteState::Outstanding))
                .then_with(|| b.info.created_secs.cmp(&a.info.created_secs))
        });
        invites
    }

    /// The devices this device's CA certified in `namespace`: the members
    /// as the main device knows them, current ones first.
    pub fn members_in(&self, namespace: &str) -> Vec<&IssuedEntry> {
        let mut members: Vec<&IssuedEntry> = self
            .issued
            .get()
            .into_iter()
            .flatten()
            .filter(|l| l.namespace == namespace)
            .flat_map(|l| l.certificates.iter())
            .collect();
        members.sort_by(|a, b| {
            a.revoked
                .cmp(&b.revoked)
                .then_with(|| a.identity.cmp(&b.identity))
        });
        members
    }

    /// The root facts of `namespace`, when this is its main device.
    pub fn root_of(&self, namespace: &str) -> Option<&RootFacts> {
        self.roots.get()?.iter().find(|r| r.namespace == namespace)
    }

    /// What this device may do in `namespace`.
    pub fn powers(&self, namespace: &str) -> Powers {
        let membership = self.membership(namespace);
        let owner = membership.is_some_and(|m| m.relation == MembershipRelation::Owner);
        let admin = membership.is_some_and(|m| m.role == "admin");
        Powers {
            invite: self.invite_ca(namespace).is_some(),
            approve: owner || admin || !self.approvals_in(namespace).is_empty(),
            root: owner && self.root_of(namespace).is_some(),
        }
    }

    /// The safety warnings, by prefix.
    pub fn warnings(&self) -> Vec<Warning> {
        let mut out = Vec::new();
        for root in self.roots.get().into_iter().flatten() {
            if root.kits().next().is_none() {
                out.push(Warning::NoRecoveryKit {
                    namespace: root.namespace.clone(),
                });
            }
            if root.store == "file" {
                out.push(Warning::PlainRootKey {
                    namespace: root.namespace.clone(),
                    location: root.location.clone(),
                });
            }
        }
        out
    }

    /// This device's own request for an admin's approval `request` (id).
    pub fn request(&self, request: &str) -> Option<&OutgoingRequest> {
        self.requests
            .get()?
            .iter()
            .find(|r| r.request_id == request)
    }

    /// This device's requests still waiting for an admin.
    pub fn waiting_requests(&self) -> Vec<&OutgoingRequest> {
        self.requests
            .get()
            .map(|rs| {
                rs.iter()
                    .filter(|r| matches!(r.state, OutgoingState::Pending))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The trusted prefixes the link `entry` carries: those whose routes go
    /// over one of its paths' faces, and the prefix of the device it
    /// reaches.
    pub fn carried_by(&self, entry: &LinkEntry) -> Vec<String> {
        let faces: Vec<u64> = entry.paths.iter().map(|p| p.face_id).collect();
        let mut out: Vec<String> = Vec::new();
        let mut add = |ns: &str| {
            if !out.iter().any(|o| o == ns) {
                out.push(ns.to_owned());
            }
        };
        if let Some(device) = &entry.device
            && let Some(ns) = self.vouching(&device.to_string())
        {
            add(ns);
        }
        if let Some(routes) = self.routes.get() {
            for fib in &routes.fib {
                if !fib.nexthops.iter().any(|n| faces.contains(&n.face_id)) {
                    continue;
                }
                let route = fib.name.to_string();
                for m in self.memberships.get().into_iter().flatten() {
                    if under(&route, &m.namespace) || under(&m.namespace, &route) {
                        add(&m.namespace);
                    }
                }
            }
        }
        out.sort();
        out
    }

    /// The prefixes this node serves: routes to a producer on this device,
    /// with the trusted prefix that vouches for each.
    pub fn served(&self) -> Vec<(String, Option<String>)> {
        let Some(routes) = self.routes.get() else {
            return Vec::new();
        };
        let local: Vec<u64> = routes
            .faces
            .iter()
            .filter(|f| f.face_scope == 1)
            .map(|f| f.face_id)
            .collect();
        let mut out: Vec<(String, Option<String>)> = routes
            .rib
            .iter()
            .filter(|e| e.routes.iter().any(|r| local.contains(&r.face_id)))
            .map(|e| e.name.to_string())
            .filter(|n| !n.starts_with("/localhost") && !n.starts_with("/localhop"))
            .map(|n| {
                let vouch = self.vouching(&n).map(str::to_owned);
                (n, vouch)
            })
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

/// Owner first, then member, then following.
fn rank(relation: MembershipRelation) -> u8 {
    match relation {
        MembershipRelation::Owner => 0,
        MembershipRelation::Member => 1,
        MembershipRelation::Following => 2,
    }
}

/// The kind of a trust event, as the stream names it.
pub fn trust_kind(event: &TrustEvent) -> &'static str {
    match event {
        TrustEvent::ApprovalRequested { .. } => "approval-requested",
        TrustEvent::ApprovalDecided { .. } => "approval-decided",
        TrustEvent::InviteCreated { .. } => "invite-created",
        TrustEvent::InviteWithdrawn { .. } => "invite-withdrawn",
        TrustEvent::InviteRedeemed { .. } => "invite-redeemed",
        TrustEvent::CertificateIssued { .. } => "certificate-issued",
        TrustEvent::ContextUpdated { .. } => "context-updated",
        TrustEvent::MembershipChanged(_) => "membership-changed",
        TrustEvent::EnrollmentEnded { .. } => "enrollment-ended",
        TrustEvent::RenewalFailed { .. } => "renewal-failed",
        TrustEvent::Unknown => "unknown",
    }
}

/// The listings a trust event makes stale.
pub fn follow_up_trust(event: &TrustEvent) -> Vec<Listing> {
    match event {
        TrustEvent::ApprovalRequested { .. } => vec![Listing::Approvals],
        TrustEvent::ApprovalDecided { .. } => vec![Listing::Approvals, Listing::Issued],
        TrustEvent::InviteCreated { .. } | TrustEvent::InviteWithdrawn { .. } => {
            vec![Listing::Invites]
        }
        TrustEvent::InviteRedeemed { .. } => vec![Listing::Invites, Listing::Issued],
        TrustEvent::CertificateIssued { .. } => vec![Listing::Issued],
        TrustEvent::ContextUpdated { .. } => vec![
            Listing::Memberships,
            Listing::Roots,
            Listing::Issued,
            Listing::Refresh,
        ],
        TrustEvent::MembershipChanged(_) => vec![
            Listing::Memberships,
            Listing::Identity,
            Listing::Requests,
            Listing::Approvals,
            Listing::Invites,
        ],
        TrustEvent::EnrollmentEnded { .. } => vec![Listing::Requests],
        TrustEvent::RenewalFailed { .. } => vec![Listing::Memberships],
        TrustEvent::Unknown => Vec::new(),
    }
}
