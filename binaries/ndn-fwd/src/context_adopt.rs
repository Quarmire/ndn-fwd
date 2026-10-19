//! The running daemon's trust-admin backend: `security/context-adopt`
//! (`ndn-fwd adopt`), `security/enroll` (`ndn-fwd enroll`),
//! `security/context-refresh` (`ndn-fwd context refresh`),
//! `security/context-update` (`ndn-fwd revoke`, `ndn-fwd recovery-kit`,
//! `ndn-fwd recover`: a version signed on this device), `security/renew`
//! (`ndn-fwd renew`), `security/memberships` (`ndn-ctl status`: the trusted
//! prefixes and how the daemon takes part in each, with their changes at
//! `/localhost/nfd/security/notifications`) and the identities
//! `security/identity-status` reports (the node identity, why, and every
//! signing identity).
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
use ndn_namespace::{
    Detail, HostWords, Participant, ParticipantParts, PibContextStore, TrustRefusal, code,
    detail_code, keep,
};
use ndn_security::Keyring;

use crate::active_identity::ActiveIdentity;
use crate::pib_vault::PibVault;

pub(crate) struct TrustAdmin {
    pub(crate) ns: Arc<Participant>,
    pub(crate) vault: Arc<PibVault>,
    pub(crate) pib_root: PathBuf,
    /// The daemon's identities (node signer, signing identities); `None`
    /// when the node runs unsigned.
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
    /// This node's CAs (`[ca]` / `[[ca]]`), one per namespace it runs one
    /// of; empty when it runs none.
    pub(crate) cas: Vec<Arc<CaState>>,
    /// The namespaces' sync groups (`[security] context_sync`).
    pub(crate) context_sync: Option<ContextSync>,
}

/// How the person at this node does what a library refusal, detail or log
/// line asks of them: the daemon's CLI and configuration, its PIB. The
/// daemon quotes them in its own log lines; the CLI renders the daemon's
/// refusals and details with them ([`render_refusal`], [`render_detail`]).
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
        add_route: "`ndn-ctl route add {namespace} --face <face-id>`".into(),
        list_routes: "`ndn-ctl route list`".into(),
        refresh_context: "`ndn-fwd context refresh {namespace}`".into(),
        list_approvals: "`ndn-fwd approvals list`".into(),
        decide_approvals: "Run `ndn-fwd approvals`".into(),
        key_storage: "the PIB".into(),
        key_storage_dir: "the PIB directory".into(),
        make_key_storage_readable: "Make the PIB readable by this daemon".into(),
        renew_before: "[security] renew_before".into(),
        contexts_not_served: "[security] serve_contexts = false".into(),
        enroll_another_key: "run again with --force and another --device name".into(),
    }
}

/// A refusal the daemon answered, in this CLI's words: the library's
/// sentences with [`namespace_words`], and the management layer's own
/// codes (a verb the daemon does not run, the trust-admin gate) naming the
/// CLI and its configuration; any other code as its neutral sentence.
pub(crate) fn render_refusal(refusal: &TrustRefusal) -> String {
    let get = |k: &str| refusal.param(k).unwrap_or_default();
    let configured = || match get("groups") {
        "" => "none configured".to_owned(),
        groups => format!("currently: {groups}"),
    };
    match refusal.code.as_str() {
        c if c == code::NOT_AT_RUNTIME.code => {
            let run = match get("operation") {
                "context-adopt" => {
                    return "this node does not adopt trust contexts at runtime; adopt offline \
                            with `ndn-fwd adopt <link> --pib <dir>` and restart it"
                        .to_owned();
                }
                "enroll" => "`ndn-fwd enroll`",
                "enroll-status" => "`ndn-fwd enroll --status`",
                "renew" => "`ndn-fwd renew`",
                "context-refresh" => "`ndn-fwd context refresh`",
                "context-update" => "it",
                _ => return refusal.reason.clone(),
            };
            format!("{}: run {run} against an ndn-fwd daemon", refusal.reason)
        }
        c if c == code::TRUST_CHANGE_UNIDENTIFIED.code => format!(
            "refused: changing this node's trust must be requested over the forwarder's local \
             management socket, where the kernel reports who is asking; this request arrived on \
             a face that carries no caller identity. Run the command on this node against the \
             daemon's Unix socket, as the daemon's user (uid {}), root, or a member of a group \
             in `[security] trust_admin_groups` ({}).",
            get("daemon_uid"),
            configured()
        ),
        c if c == code::TRUST_CHANGE_NOT_OPERATOR.code => format!(
            "refused: only the daemon's user (uid {}), root, or members of `[security] \
             trust_admin_groups` ({}) may change this node's trust; this request came from uid \
             {}. Run the command as the daemon's user or root, or add a group you belong to to \
             `[security] trust_admin_groups` in the daemon config and restart.",
            get("daemon_uid"),
            configured(),
            get("uid")
        ),
        c if c == code::TRUST_CHANGE_OVER_LOCALHOP.code => {
            "trust changes — adopting, enrolling, revoking, refreshing, and listing or deciding \
             approval requests — are accepted only on this node's local management socket; run \
             `ndn-fwd adopt` / `enroll` / `revoke` / `context refresh` / `approvals` on the node \
             itself (an admin device decides another node's requests with `ndn-fwd approvals` \
             on its own node)"
                .to_owned()
        }
        c if c == code::APPROVAL_TARGET_MISSING.code => {
            "give the request id or the six-digit code (`ndn-fwd approvals list` shows them) in \
             Uri; a denial may add `:<reason>`"
                .to_owned()
        }
        _ => namespace_words().render(refusal),
    }
}

/// A detail of the daemon's answer, in this CLI's words: the library's
/// sentences with [`namespace_words`], and the daemon's own (what changes
/// at the next start) naming its configuration.
pub(crate) fn render_detail(detail: &Detail) -> String {
    let get = |k: &str| detail.param(k).unwrap_or_default();
    match detail.code.as_str() {
        detail_code::NEXT_START_CONFIGURED_IDENTITY => format!(
            "the node identity stays {}: [security] identity in this node's config names it; \
             {} is recorded as the PIB's default identity, the node identity once that line is \
             removed",
            get("configured"),
            get("identity")
        ),
        detail_code::NEXT_START_ROUTING_KEY => format!(
            "DV routing: it keeps signing with the key this node started with (DV \
             `static`/`lvs` trust); it signs with {} after a restart, so add that key to every \
             DV neighbour's [routing.dv.trust] trusted_keys before restarting",
            get("key")
        ),
        _ => namespace_words().render_detail(detail),
    }
}

/// The status text of a refusing answer, in this CLI's words: a structured
/// refusal rendered from its code ([`render_refusal`]); any other text as it
/// stands.
pub(crate) fn refusal_text(status_code: u64, status_text: &str) -> String {
    match ndn_ipc::trust_refusal_of(status_code, status_text) {
        Some(refusal) => render_refusal(&refusal),
        None => status_text.to_owned(),
    }
}

/// The context store beside the PIB at `pib_root`.
pub(crate) fn context_store(pib_root: &std::path::Path) -> PibContextStore {
    PibContextStore::new(pib_root)
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
            cas,
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
                cas,
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
        let link = AnchorLink::from_uri(&link_uri).map_err(|e| keep::adopt_refusal(&e))?;
        keep::adopt_link(&self.ns, &link).await
    }

    async fn enroll(
        &self,
        request: ndn_mgmt::EnrollRequest,
    ) -> Result<ndn_mgmt::EnrollOutcome, ndn_mgmt::TrustRefusal> {
        crate::enroll::enroll(self, request).await
    }

    async fn enroll_status(
        &self,
    ) -> Result<Vec<ndn_cert::OutgoingRequest>, ndn_mgmt::TrustRefusal> {
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
                source: s.source(),
                signing: s
                    .signing_identities()
                    .into_iter()
                    .map(|i| (i.identity, i.key))
                    .collect(),
            }
        })
    }

    async fn memberships(&self) -> Result<Vec<ndn_mgmt::MembershipInfo>, ndn_mgmt::TrustRefusal> {
        Ok(ndn_namespace::membership::memberships(
            &self.ns,
            self.vault.as_ref(),
        ))
    }

    fn trust_events(&self) -> Option<tokio::sync::broadcast::Receiver<ndn_mgmt::TrustEvent>> {
        Some(self.ns.events())
    }

    fn root_stores(&self) -> Vec<ndn_mgmt::RootStoreInfo> {
        crate::root_key::status_info(&self.pib_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refusal as the daemon answers it: its code and params (the CLI
    /// words those codes from the params alone).
    fn refused(kind: ndn_cert::report::RefusalCode, params: &[(&str, &str)]) -> TrustRefusal {
        params
            .iter()
            .fold(TrustRefusal::new(kind, "neutral"), |r, (k, v)| r.with(k, v))
    }

    fn detail(code: &str, params: &[(&str, &str)]) -> Detail {
        params
            .iter()
            .fold(Detail::new(code, "neutral"), |d, (k, v)| d.with(k, v))
    }

    /// The CLI renders the daemon's coded refusals and details exactly as
    /// the daemon worded them before it answered codes: its output is
    /// unchanged.
    #[test]
    fn the_cli_renders_the_daemon_codes_as_before() {
        let w = namespace_words();
        assert_eq!(
            render_detail(&detail(
                detail_code::CONTEXT_CHECK_TIMED_OUT,
                &[("budget_secs", "8"), ("namespace", "/home/bob")]
            )),
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
            render_refusal(&ndn_namespace::enroll::parse_link("not a link").unwrap_err()),
            format!(
                "the link is neither an invite nor an anchor link ({e}): give an \
                 ndn-trust://invite link (`ndn-fwd-tokens new` prints one) or, for a role the \
                 namespace certifies on an admin's approval, its ndn-trust://anchor link \
                 (`ndn-fwd init` prints it as anchor_uri)"
            )
        );
        assert_eq!(
            render_refusal(&refused(
                code::INVITE_FOR_ANOTHER_ROLE,
                &[
                    ("namespace", "/home/bob"),
                    ("invite_role", "member"),
                    ("role", "guest")
                ]
            )),
            "the invite admits a member device, not a guest device; /home/bob certifies guest \
             devices by invite: ask for a guest invite (`ndn-fwd-tokens new --role guest`)"
        );
        assert_eq!(
            render_refusal(&refused(
                code::ROLE_BY_INVITE,
                &[
                    ("namespace", "/home/bob"),
                    ("role", "member"),
                    ("policy", "admin, node by an admin's approval")
                ]
            )),
            "/home/bob certifies member devices by invite, not on an admin's approval (admin, \
             node by an admin's approval): ask an admin for an invite (`ndn-fwd-tokens new \
             --role member` on the root device) and run `ndn-fwd enroll <invite link>`"
        );
        assert_eq!(
            render_refusal(&refused(
                code::ROLE_NEEDS_INVITE_AND_APPROVAL,
                &[("namespace", "/home/bob"), ("role", "node")]
            )),
            "/home/bob certifies a node device only on an invite AND an admin's approval: ask \
             an admin for an invite and run `ndn-fwd enroll <invite link> --role node`"
        );
        assert_eq!(
            render_refusal(&refused(
                code::CERTIFICATE_NOT_KEPT,
                &[
                    ("certificate", "/c"),
                    ("location", "/var/lib/ndn/pib"),
                    ("error", "disk full"),
                    ("spent", "invite")
                ]
            )),
            "the CA issued /c, but storing it in /var/lib/ndn/pib failed (disk full); nothing \
             was kept and nothing changed. The token is spent: fix the PIB directory and ask for \
             a new invite"
        );
        assert_eq!(
            render_refusal(&refused(
                code::CERTIFICATE_NOT_KEPT,
                &[
                    ("certificate", "/c"),
                    ("location", "/var/lib/ndn/pib"),
                    ("error", "disk full"),
                    ("spent", "approval")
                ]
            )),
            "the CA issued /c, but storing it in /var/lib/ndn/pib failed (disk full); nothing \
             was kept and nothing changed. The approval is used: fix the PIB directory, ask \
             again (`ndn-fwd enroll`) and have an admin approve the new request"
        );
        assert_eq!(
            render_refusal(&refused(
                code::REQUEST_NOT_RECORDED,
                &[
                    ("request", "r1"),
                    ("code", "123456"),
                    ("error", "disk full"),
                    ("location", "/var/lib/ndn/pib")
                ]
            )),
            "the CA holds request r1 (code 123456), but this node could not record it (disk \
             full), so it would never finish it: the key was deleted. Fix the PIB directory \
             (/var/lib/ndn/pib) and ask again; an admin can deny request r1"
        );
        assert_eq!(
            w.enrolled(true),
            "enrolled; the PIB's default identity is now this one, the node identity"
        );
        assert_eq!(
            render_detail(&detail(detail_code::REQUEST_NAMES_NO_CA, &[])),
            "the request record names no valid namespace or CA; ask again (`ndn-fwd enroll`)"
        );
        assert_eq!(
            render_detail(&detail(detail_code::REQUEST_NAMES_NO_KEY, &[])),
            "the request record names no valid namespace, CA, identity or key; ask again \
             (`ndn-fwd enroll`)"
        );
        assert_eq!(
            render_detail(&detail(
                detail_code::REQUEST_KEY_GONE,
                &[
                    ("key", "/home/bob/node/pi/KEY/k1"),
                    ("why", "gone from the PIB")
                ]
            )),
            "the key /home/bob/node/pi/KEY/k1 of this request is gone from the PIB; nothing can \
             be certified for it: ask again (`ndn-fwd enroll`)"
        );
        assert_eq!(
            render_refusal(&refused(
                code::APPROVAL_NOT_PENDING,
                &[("target", "123456"), ("scope", "administered")]
            )),
            "no pending request shows \"123456\" at the CAs of the namespaces this node \
             administers: check the code on the new device against `ndn-fwd approvals list` (a \
             request that expired or was decided is not pending)"
        );
        assert_eq!(
            render_refusal(&refused(code::NOTHING_TO_APPROVE, &[])),
            "this node neither runs a CA that takes approval requests nor holds a current admin \
             certificate of a namespace whose CA runs elsewhere: there is nothing to approve \
             here. Run `ndn-fwd approvals` on the namespace's root device (its CA host) or on \
             an admin device; a device becomes one with `ndn-fwd enroll <anchor link> --role \
             admin`, approved by an admin"
        );
        assert_eq!(
            render_refusal(&refused(
                code::CONTEXT_NOT_HELD,
                &[("namespace", "/home/bob")]
            )),
            "this node holds no trust context for /home/bob; adopt it first (`ndn-fwd adopt`)"
        );
        assert_eq!(
            render_refusal(&refused(
                code::RENEWAL_KEYS_UNREADABLE,
                &[("error", "the PIB cannot be read")]
            )),
            "the PIB cannot be read: nothing was renewed. Make the PIB readable by this daemon, \
             then renew again"
        );
        assert_eq!(
            render_refusal(&refused(
                code::NOTHING_TO_RENEW,
                &[("location", "/var/lib/ndn/pib")]
            )),
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
            render_refusal(&refused(
                code::CONTEXT_NOT_STORED,
                &[
                    ("namespace", "/home/bob"),
                    ("version", "3"),
                    ("error", "disk full"),
                    ("location", "/var/lib/ndn/pib")
                ]
            )),
            "adopted /home/bob v3 for this run, but storing it failed (disk full); it will be \
             gone after a restart — fix the PIB directory (/var/lib/ndn/pib)"
        );
        assert!(
            render_detail(&detail(
                detail_code::CONTEXT_UPDATED,
                &[
                    ("version", "4"),
                    ("signer", "/s"),
                    ("from", "3"),
                    ("stored", "/c"),
                    ("published", "false")
                ]
            ))
            .ends_with(
                "; not published: [security] serve_contexts = false, so no node fetches it from \
                 this one"
            )
        );
        assert_eq!(
            render_refusal(&refused(
                code::ALREADY_CERTIFIED,
                &[
                    ("namespace", "/home/bob"),
                    (
                        "still_valid",
                        "/home/bob/member/phone/KEY/k1 (valid until 20270101T000000Z)"
                    ),
                    ("judged_version", "2"),
                    ("cause", detail_code::CONTEXT_CHECK_TIMED_OUT),
                    ("budget_secs", "8"),
                ]
            )),
            "this node already holds a certificate in /home/bob: /home/bob/member/phone/KEY/k1 \
             (valid until 20270101T000000Z) (judged against the trust context v2 this node \
             holds; whether a newer version revokes it could not be checked: no newer version \
             was confirmed within 8s (following several versions takes longer); `ndn-fwd \
             context refresh /home/bob` completes the check). To enroll another key anyway, run \
             again with --force and another --device name (the CA certifies a new key for a \
             device name it already certified only once that certificate is revoked or an admin \
             approves the new key); the certificate this node holds stays valid until it \
             expires or is revoked"
        );
        assert_eq!(
            render_refusal(
                &TrustRefusal::new(code::NOT_AT_RUNTIME, "this node does not enroll at runtime")
                    .with("operation", "enroll")
            ),
            "this node does not enroll at runtime: run `ndn-fwd enroll` against an ndn-fwd \
             daemon"
        );
        assert_eq!(
            render_refusal(&refused(
                code::TRUST_CHANGE_NOT_OPERATOR,
                &[("uid", "1000"), ("daemon_uid", "0"), ("groups", "")]
            )),
            "refused: only the daemon's user (uid 0), root, or members of `[security] \
             trust_admin_groups` (none configured) may change this node's trust; this request \
             came from uid 1000. Run the command as the daemon's user or root, or add a group \
             you belong to to `[security] trust_admin_groups` in the daemon config and restart."
        );
    }
}
