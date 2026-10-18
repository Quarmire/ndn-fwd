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
use ndn_namespace::{Participant, ParticipantParts, PibContextStore, keep};
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
                store: Arc::new(PibContextStore::new(&pib_root)),
                publisher,
                own_certs,
                sync: context_sync,
                ca,
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
