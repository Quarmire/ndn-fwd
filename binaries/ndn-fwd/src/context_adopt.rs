//! The running daemon's trust-admin backend: `security/context-adopt`
//! (`ndn-fwd adopt`), `security/enroll` (`ndn-fwd enroll`),
//! `security/context-refresh` (`ndn-fwd context refresh`),
//! `security/context-update` (`ndn-fwd revoke`, `ndn-fwd recovery-kit`,
//! `ndn-fwd recover`: a version signed on this device), `security/renew`
//! (`ndn-fwd renew`) and the signing identity `security/identity-status`
//! reports.
//!
//! Every verb is the [`ndn_namespace`] operation of the same name over the
//! daemon's [`Participant`] — its engine, the keyring its validator uses,
//! the context store beside its PIB (`<pib>/contexts/`), its publisher,
//! certificate server, sync groups and CA — and its [`PibVault`]. Who may
//! ask is decided before a verb runs, by the management socket's peer
//! credentials.

use std::path::PathBuf;
use std::sync::Arc;

use ndn_cert::{AnchorLink, CaState};
use ndn_engine::ForwarderEngine;
use ndn_namespace::publish::{OwnCertificates, PublishedContexts};
use ndn_namespace::sync::ContextSync;
use ndn_namespace::{HostWords, Participant, ParticipantParts, PibContextStore, keep};
use ndn_security::Keyring;

use crate::active_identity::ActiveIdentity;
use crate::pib_vault::PibVault;

pub(crate) struct TrustAdmin {
    pub(crate) ns: Arc<Participant>,
    pub(crate) vault: Arc<PibVault>,
    pub(crate) pib_root: PathBuf,
    /// The key management responses and discovery records are signed with;
    /// `None` when the node runs unsigned.
    pub(crate) signing: Option<Arc<ActiveIdentity>>,
}

/// What the daemon builds its [`TrustAdmin`] from.
pub(crate) struct TrustAdminParts {
    pub(crate) engine: ForwarderEngine,
    /// The keyring the engine's validator dispatches against.
    pub(crate) keyring: Arc<Keyring>,
    pub(crate) pib_root: PathBuf,
    /// `None` when `[security] serve_contexts = false`.
    pub(crate) publisher: Option<PublishedContexts>,
    pub(crate) signing: Option<Arc<ActiveIdentity>>,
    /// Serves this node's certificates by name; a certificate enrolled at
    /// runtime is added to it. `None` only in tests.
    pub(crate) own_certs: Option<Arc<OwnCertificates>>,
    /// DV routing keeps the key the node started with (`static`/`lvs`
    /// trust), so an enrollment says so.
    pub(crate) dv_keeps_startup_key: bool,
    /// `[security] identity` from the config.
    pub(crate) configured_identity: Option<String>,
    /// This node's CA (`[ca]`); `None` when the node runs none.
    pub(crate) ca: Option<Arc<CaState>>,
    /// The namespaces' sync groups (`[security] context_sync`).
    pub(crate) context_sync: Option<ContextSync>,
}

/// How the person at this node does what a library refusal or log line
/// asks of them: the daemon's CLI and configuration, its PIB.
pub(crate) fn namespace_words() -> HostWords {
    HostWords {
        enroll_again: "`ndn-fwd enroll`".into(),
        enroll_first: "`ndn-fwd enroll <invite>`".into(),
        enroll_with_invite: "run `ndn-fwd enroll <invite link>`".into(),
        enroll_with_invite_as: "run `ndn-fwd enroll <invite link> --role {role}`".into(),
        enroll_as_admin: "`ndn-fwd enroll <anchor link> --role admin`".into(),
        invite_origin: "`ndn-fwd-tokens new` prints one".into(),
        role_invite: "`ndn-fwd-tokens new --role {role}`".into(),
        anchor_link_origin: "`ndn-fwd init` prints it as anchor_uri".into(),
        adopt: "`ndn-fwd adopt`".into(),
        adopt_anchor_link: "`ndn-fwd adopt <ndn-trust://anchor/…>`, the link `ndn-fwd init` printed"
            .into(),
        refresh_context: "`ndn-fwd context refresh {namespace}`".into(),
        list_approvals: "`ndn-fwd approvals list`".into(),
        decide_approvals: "Run `ndn-fwd approvals`".into(),
        root_key_status: "`ndn-fwd root-key status`".into(),
        key_storage: "the PIB".into(),
        key_storage_dir: "the PIB directory".into(),
        make_key_storage_readable: "Make the PIB readable by this daemon".into(),
        renew_before: "[security] renew_before".into(),
        contexts_not_served: "[security] serve_contexts = false".into(),
        enroll_another_key: "run again with --force and another --device name".into(),
        recover_from_held: "retry with --from-held".into(),
    }
}

/// The context store beside the PIB at `pib_root`, worded as the daemon's.
pub(crate) fn context_store(pib_root: &std::path::Path) -> PibContextStore {
    PibContextStore::new(pib_root).with_words(&namespace_words())
}

impl TrustAdmin {
    pub(crate) fn new(parts: TrustAdminParts) -> Self {
        let TrustAdminParts {
            engine,
            keyring,
            pib_root,
            publisher,
            signing,
            own_certs,
            dv_keeps_startup_key,
            configured_identity,
            ca,
            context_sync,
        } = parts;
        Self {
            ns: Arc::new(Participant::new(ParticipantParts {
                engine,
                keyring,
                store: Arc::new(context_store(&pib_root)),
                publisher,
                own_certs,
                sync: context_sync,
                ca,
                words: namespace_words(),
            })),
            vault: Arc::new(PibVault {
                pib_root: pib_root.clone(),
                signing: signing.clone(),
                dv_keeps_startup_key,
                configured_identity,
            }),
            pib_root,
            signing,
        }
    }
}

#[async_trait::async_trait]
impl ndn_mgmt::TrustAdminMgmtBackend for TrustAdmin {
    async fn adopt(
        &self,
        link_uri: String,
    ) -> Result<ndn_mgmt::AdoptedContextInfo, ndn_mgmt::TrustRefusal> {
        let link = AnchorLink::from_uri(&link_uri)
            .map_err(|e| ndn_namespace::refusal(keep::adopt_status(&e), e.to_string()))?;
        keep::adopt_link(&self.ns, &link).await
    }

    async fn enroll(
        &self,
        request: ndn_mgmt::EnrollRequest,
    ) -> Result<ndn_mgmt::EnrollOutcome, ndn_mgmt::TrustRefusal> {
        crate::enroll::enroll(self, request).await
    }

    async fn enroll_status(&self) -> Result<Vec<ndn_cert::OutgoingRequest>, ndn_mgmt::TrustRefusal> {
        crate::enroll::enroll_status(self)
    }

    async fn refresh_contexts(
        &self,
        namespace: Option<ndn_packet::Name>,
    ) -> Result<Vec<ndn_mgmt::ContextRefreshInfo>, ndn_mgmt::TrustRefusal> {
        crate::context_refresh::refresh_contexts(self, namespace).await
    }

    async fn update_context(
        &self,
        context_data: bytes::Bytes,
    ) -> Result<ndn_mgmt::ContextRefreshInfo, ndn_mgmt::TrustRefusal> {
        crate::context_refresh::apply_update(self, context_data).await
    }

    async fn renew(&self) -> Result<Vec<ndn_mgmt::RenewalInfo>, ndn_mgmt::TrustRefusal> {
        crate::renewal::renew_now(self).await
    }

    fn signing_identity(&self) -> Option<ndn_mgmt::SigningIdentityInfo> {
        self.signing.as_ref().map(|s| {
            let (key, ephemeral) = s.current();
            // A self-signed key certificate that never expires reports none.
            let valid_until = ndn_security::FilePib::open(&self.pib_root)
                .and_then(|pib| pib.get_cert(&key))
                .ok()
                .map(|cert| cert.valid_until)
                .filter(|&until| until != u64::MAX);
            ndn_mgmt::SigningIdentityInfo {
                key,
                ephemeral,
                valid_until,
            }
        })
    }

    fn root_store(&self) -> Option<ndn_mgmt::RootStoreInfo> {
        crate::root_key::status_info(&self.pib_root)
    }
}

#[cfg(test)]
mod tests {
    use ndn_namespace::admin::{NewestRefusal, newest_of};
    use ndn_namespace::{ContextRefreshInfo, ContextStore, RefreshState};
    use ndn_packet::Name;

    use super::*;

    /// The library's messages with the daemon's words read exactly as the
    /// daemon printed them before the library took its words from the host.
    #[test]
    fn the_daemon_words_reproduce_its_messages() {
        let w = namespace_words();
        let ns: Name = "/home/bob".parse().unwrap();
        let key: Name = "/home/bob/node/pi/KEY/k1".parse().unwrap();

        assert_eq!(
            w.context_check_timed_out(8, &ns),
            "no newer version was confirmed within 8s (following several versions takes \
             longer); `ndn-fwd context refresh /home/bob` completes the check"
        );
        assert_eq!(
            w.request_expired_unanswered(),
            "the CA never answered before the request expired; it ended here and its key was \
             deleted: ask again (`ndn-fwd enroll`)"
        );
        let e = ndn_cert::EnrollLink::parse("not a link").unwrap_err();
        assert_eq!(
            ndn_namespace::enroll::parse_link("not a link", &w).unwrap_err().reason,
            format!(
                "the link is neither an invite nor an anchor link ({e}): give an \
                 ndn-trust://invite link (`ndn-fwd-tokens new` prints one) or, for a role the \
                 namespace certifies on an admin's approval, its ndn-trust://anchor link \
                 (`ndn-fwd init` prints it as anchor_uri)"
            )
        );
        assert_eq!(
            w.invite_for_another_role(&ns, "member", "guest"),
            "the invite admits a member device, not a guest device; /home/bob certifies guest \
             devices by invite: ask for a guest invite (`ndn-fwd-tokens new --role guest`)"
        );
        assert_eq!(
            w.role_by_invite(&ns, "member", "admin, node by an admin's approval"),
            "/home/bob certifies member devices by invite, not on an admin's approval (admin, \
             node by an admin's approval): ask an admin for an invite (`ndn-fwd-tokens new \
             --role member` on the root device) and run `ndn-fwd enroll <invite link>`"
        );
        assert_eq!(
            w.role_by_invite_and_approval(&ns, "node"),
            "/home/bob certifies a node device only on an invite AND an admin's approval: ask \
             an admin for an invite and run `ndn-fwd enroll <invite link> --role node`"
        );
        assert_eq!(
            w.invite_spent(),
            "The token is spent: fix the PIB directory and ask for a new invite"
        );
        assert_eq!(
            w.approval_used(),
            "The approval is used: fix the PIB directory, ask again (`ndn-fwd enroll`) and have \
             an admin approve the new request"
        );
        assert_eq!(
            w.request_not_recorded("r1", "123456", "disk full", "the PIB at /var/lib/ndn/pib"),
            "the CA holds request r1 (code 123456), but this node could not record it (disk \
             full), so it would never finish it: the key was deleted. Fix the PIB directory (the \
             PIB at /var/lib/ndn/pib) and ask again; an admin can deny request r1"
        );
        assert_eq!(w.enrolled(), "enrolled; the PIB's default identity is now this one");
        assert_eq!(
            w.request_names_no_ca(),
            "the request record names no valid namespace or CA; ask again (`ndn-fwd enroll`)"
        );
        assert_eq!(
            w.request_names_no_key(),
            "the request record names no valid namespace, CA, identity or key; ask again \
             (`ndn-fwd enroll`)"
        );
        assert_eq!(
            w.request_key_gone(&key, "gone from the PIB"),
            "the key /home/bob/node/pi/KEY/k1 of this request is gone from the PIB; nothing can \
             be certified for it: ask again (`ndn-fwd enroll`)"
        );
        assert_eq!(
            w.no_pending_request("123456", "the CAs of the namespaces this node administers"),
            "no pending request shows \"123456\" at the CAs of the namespaces this node \
             administers: check the code on the new device against `ndn-fwd approvals list` (a \
             request that expired or was decided is not pending)"
        );
        assert_eq!(
            w.nothing_to_approve(),
            "this node neither runs a CA that takes approval requests nor holds a current admin \
             certificate of a namespace whose CA runs elsewhere: there is nothing to approve \
             here. Run `ndn-fwd approvals` on the namespace's root device (its CA host) or on \
             an admin device; a device becomes one with `ndn-fwd enroll <anchor link> --role \
             admin`, approved by an admin"
        );
        assert_eq!(
            w.no_context(&ns),
            "this node holds no trust context for /home/bob; adopt it first (`ndn-fwd adopt`)"
        );
        assert_eq!(
            w.renewal_unreadable("the PIB cannot be read"),
            "the PIB cannot be read: nothing was renewed. Make the PIB readable by this daemon, \
             then renew again"
        );
        assert_eq!(
            w.nothing_to_renew("/var/lib/ndn/pib"),
            "this node holds no certificate a namespace CA issued to it in /var/lib/ndn/pib: \
             nothing to renew. Enroll first (`ndn-fwd enroll <invite>`)"
        );
        assert_eq!(
            w.renewal_waits_for_storage(),
            "no certificate is renewed while the PIB cannot be read; they expire unless it \
             becomes readable"
        );
        assert_eq!(
            w.renew_before_too_long(),
            "[security] renew_before is at least the lifetime of the certificates this CA \
             issues; renewing them once a third of their lifetime is left instead"
        );
        assert_eq!(
            w.not_published(),
            "; not published: [security] serve_contexts = false, so no node fetches it from this \
             one"
        );

        let source = ContextRefreshInfo {
            namespace: ns.to_string(),
            state: RefreshState::Source,
            held_version: 3,
            version: 3,
            revoked: Vec::new(),
            detail: String::new(),
        };
        assert_eq!(
            newest_of(&ns, &source, false, &w).unwrap_err().to_string(),
            "this device holds the root of /home/bob (`ndn-fwd root-key status`): it is the \
             root device, nothing to recover"
        );
        let unreachable = ContextRefreshInfo {
            state: RefreshState::Unreachable,
            detail: "no answer".into(),
            ..source
        };
        assert_eq!(
            newest_of(&ns, &unreachable, false, &w).unwrap_err().to_string(),
            "no answer. Recovering from the held v3 without knowing it is the newest could fork \
             the namespace: give this device a face and a route toward a relay or member that \
             holds it, then retry. If no other node holding /home/bob exists or can be reached, \
             and you know no version newer than v3 was made, retry with --from-held"
        );
        assert_eq!(
            w.already_certified(
                &ns,
                "/home/bob/member/phone/KEY/k1 until 20270101T000000",
                " (judged against v2)"
            ),
            "this node already holds a certificate in /home/bob: /home/bob/member/phone/KEY/k1 \
             until 20270101T000000 (judged against v2). To enroll another key anyway, run again \
             with --force and another --device name (the CA certifies a new key for a device \
             name it already certified only once that certificate is revoked or an admin \
             approves the new key); the certificate this node holds stays valid until it \
             expires or is revoked"
        );
        let not_held = NewestRefusal::NotHeld {
            namespace: ns.clone(),
            adopt_anchor_link: w.adopt_anchor_link.clone(),
        };
        assert_eq!(
            not_held.to_string(),
            "this device's daemon holds no trust context for /home/bob. Adopt it first with the \
             namespace's anchor link (`ndn-fwd adopt <ndn-trust://anchor/…>`, the link `ndn-fwd \
             init` printed), so the version recovered from is authenticated, then retry"
        );
        assert_eq!(
            context_store(std::path::Path::new("/var/lib/ndn/pib")).location(),
            "the PIB directory (/var/lib/ndn/pib)"
        );
    }
}
