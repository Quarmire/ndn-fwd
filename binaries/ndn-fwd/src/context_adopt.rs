//! The running daemon's trust-admin backend: `security/context-adopt`
//! (`ndn-fwd adopt`), `security/enroll` (`ndn-fwd enroll`, see
//! [`crate::enroll`]), `security/revoke` (`ndn-fwd revoke`, see
//! [`crate::revoke`]), `security/context-refresh` (`ndn-fwd context
//! refresh`, see [`crate::context_refresh`]), `security/context-update`
//! (`ndn-fwd recovery-kit`, `ndn-fwd recover`: a version signed on this
//! device, see [`crate::context_refresh::apply_update`]), `security/renew`
//! (`ndn-fwd renew`, see [`crate::renewal`]) and the signing identity
//! `security/identity-status` reports.
//!
//! Adopting: the daemon reads the `ndn-trust://anchor` link and adopts the
//! trust context it names with [`ndn_identity::adopt_anchor_link_via_engine`]
//! — inline context: verified against the link; fingerprint only: fetched by
//! name through this engine while its validator expects exactly that context
//! — into the keyring its validator uses, then stores the signed Data in
//! `<pib>/contexts/` (so it is loaded again after a restart) and publishes it
//! by name (so other devices can fetch it from this one). Who may ask is
//! decided before this runs, by the management socket's peer credentials.

use std::path::PathBuf;
use std::sync::Arc;

use ndn_cert::{AdoptError, AnchorLink, CaState, LinkAdoption};
use ndn_engine::ForwarderEngine;
use ndn_mgmt_wire::control_response::status;
use ndn_packet::Data;
use ndn_security::{Keyring, SignedTrustContext};

use crate::active_identity::ActiveIdentity;
use crate::context_publisher::PublishedContexts;
use crate::own_certs::OwnCertificates;

pub(crate) struct TrustAdmin {
    pub(crate) engine: ForwarderEngine,
    /// The keyring the engine's validator dispatches against.
    pub(crate) keyring: Arc<Keyring>,
    pub(crate) pib_root: PathBuf,
    /// `None` when `[security] serve_contexts = false`.
    pub(crate) publisher: Option<PublishedContexts>,
    /// The key management responses and discovery records are signed with;
    /// `None` when the node runs unsigned.
    pub(crate) signing: Option<Arc<ActiveIdentity>>,
    /// Serves this node's certificates by name; a certificate enrolled at
    /// runtime is added to it. `None` only in tests.
    pub(crate) own_certs: Option<Arc<OwnCertificates>>,
    /// DV routing runs with `static`/`lvs` trust: it keeps the key the node
    /// started with (see `installs::dv::prepare`), so an enrollment says so.
    pub(crate) dv_keeps_startup_key: bool,
    /// `[security] identity` from the config: it takes precedence over the
    /// PIB's default identity, so an enrollment does not change the signer.
    pub(crate) configured_identity: Option<String>,
    /// One enrollment at a time.
    pub(crate) enrolling: tokio::sync::Mutex<()>,
    /// Held while a context is stored and published, so of two concurrent
    /// adoptions of one namespace the disk and the publisher end up with the
    /// version the keyring holds, never an older one.
    pub(crate) keeping: std::sync::Mutex<()>,
    /// This node's CA (`[ca]`), which `security/revoke` revokes at; `None`
    /// when the node runs none.
    pub(crate) ca: Option<Arc<CaState>>,
    /// One context change at a time: a revocation (new version made here)
    /// or a refresh (newer version fetched), so neither works from a version
    /// the other is replacing.
    pub(crate) context_change: tokio::sync::Mutex<()>,
    /// One certificate renewal at a time (`security/renew` and the renewal
    /// timer).
    pub(crate) renewing: tokio::sync::Mutex<()>,
    /// Woken whenever this node's certificates change (an enrollment, a
    /// renewal), so the renewal timer reads them again.
    pub(crate) certificates_changed: tokio::sync::Notify,
}

pub(crate) fn refusal(status_code: u64, reason: impl Into<String>) -> ndn_mgmt::TrustRefusal {
    ndn_mgmt::TrustRefusal {
        status_code,
        reason: reason.into(),
    }
}

/// The status code an adoption refusal is reported with.
fn status_of(e: &AdoptError) -> u64 {
    match e {
        AdoptError::BadLink(_)
        | AdoptError::NotAnchor(_)
        | AdoptError::LinkMissing(_)
        | AdoptError::BadNamespace(_)
        | AdoptError::BadData(_)
        | AdoptError::UnsignedLegacyContext => status::BAD_PARAMS,
        AdoptError::Fetch { .. } => 504,
        AdoptError::InProgress(_) => 409,
        _ => status::UNAUTHORIZED,
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl TrustAdmin {
    /// Keep a context adopted into the keyring: store it in `<pib>/contexts/`
    /// and publish it by name. Refused (`409`) when the keyring meanwhile
    /// holds a newer version of the namespace: that one is what is kept.
    pub(crate) fn keep_adopted(
        &self,
        adopted: &LinkAdoption,
        expected_fingerprint: &[u8; 32],
    ) -> Result<ndn_mgmt::AdoptedContextInfo, ndn_mgmt::TrustRefusal> {
        let ctx = &adopted.context;
        let stored = self.keep(ctx, &adopted.data)?;
        tracing::info!(
            target: "security",
            namespace = %ctx.namespace(),
            version = ctx.version(),
            fetched = adopted.fetched,
            path = %stored.display(),
            "adopted trust context"
        );
        Ok(ndn_mgmt::AdoptedContextInfo {
            namespace: ctx.namespace().to_string(),
            version: ctx.version(),
            expected_fingerprint: hex(expected_fingerprint),
            anchors: ctx.anchors().len(),
            ca_endpoints: ctx.ca_endpoints().len(),
            fetched: adopted.fetched,
            stored: stored.display().to_string(),
            published: self.publisher.is_some(),
        })
    }

    /// Store `ctx` (signed Data `data`), already in the keyring, in
    /// `<pib>/contexts/` and publish it by name as the namespace's newest
    /// version (the versions before it stay stored and served). Refused
    /// (`409`) when the keyring meanwhile holds a newer version of the
    /// namespace: that one is what is kept.
    pub(crate) fn keep(
        &self,
        ctx: &SignedTrustContext,
        data: &Data,
    ) -> Result<PathBuf, ndn_mgmt::TrustRefusal> {
        let _keeping = self
            .keeping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(held) = self.keyring.version_of(ctx.namespace())
            && held > ctx.version()
        {
            return Err(refusal(
                409,
                format!(
                    "{} v{} was adopted, but v{held} was adopted meanwhile by another command; \
                     v{held} is the version this node holds, stores and publishes",
                    ctx.namespace(),
                    ctx.version()
                ),
            ));
        }
        self.store_and_publish(ctx, data)
    }

    /// Store and publish `ctx` (signed Data `data`), a version this node
    /// went through to reach the one its keyring holds
    /// (`ndn_cert::ContextUpdate::walked`): kept by its exact name for the
    /// nodes behind this one, which follow the namespace the same way. The
    /// stored and published newest version never moves back to it.
    pub(crate) fn keep_walked(
        &self,
        ctx: &SignedTrustContext,
        data: &Data,
    ) -> Result<PathBuf, ndn_mgmt::TrustRefusal> {
        let _keeping = self
            .keeping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.store_and_publish(ctx, data)
    }

    /// Under `keeping`.
    fn store_and_publish(
        &self,
        ctx: &SignedTrustContext,
        data: &Data,
    ) -> Result<PathBuf, ndn_mgmt::TrustRefusal> {
        let stored = ndn_cert::persist_context(&self.pib_root, ctx, data).map_err(|e| {
            refusal(
                status::SERVER_ERROR,
                format!(
                    "adopted {} v{} for this run, but storing it failed ({e}); it will be gone \
                     after a restart — fix the PIB directory ({})",
                    ctx.namespace(),
                    ctx.version(),
                    self.pib_root.display()
                ),
            )
        })?;
        if let Some(publisher) = &self.publisher {
            publisher.publish(ctx, data);
        }
        Ok(stored)
    }
}

#[async_trait::async_trait]
impl ndn_mgmt::TrustAdminMgmtBackend for TrustAdmin {
    async fn adopt(
        &self,
        link_uri: String,
    ) -> Result<ndn_mgmt::AdoptedContextInfo, ndn_mgmt::TrustRefusal> {
        let refuse = |e: AdoptError| refusal(status_of(&e), e.to_string());
        let link = AnchorLink::from_uri(&link_uri).map_err(refuse)?;
        // A fetched context must come from the forwarders serving the
        // namespace, not from this node's own publisher (which holds only the
        // versions this node already has).
        let bypass = match (&self.publisher, &link.context_data) {
            (Some(publisher), None) => Some(publisher.bypass(&link.namespace)),
            _ => None,
        };
        let adopted =
            ndn_identity::adopt_anchor_link_via_engine(&self.engine, &self.keyring, &link)
                .await
                .map_err(|e| {
                    tracing::warn!(
                        target: "security",
                        namespace = %link.namespace,
                        error = %e,
                        "trust context not adopted"
                    );
                    refuse(e)
                })?;
        drop(bypass);
        self.keep_adopted(&adopted, &link.expected_fingerprint)
    }

    async fn enroll(
        &self,
        request: ndn_mgmt::EnrollRequest,
    ) -> Result<ndn_mgmt::EnrollOutcome, ndn_mgmt::TrustRefusal> {
        crate::enroll::enroll(self, request).await
    }

    async fn revoke(
        &self,
        request: ndn_mgmt::RevokeRequest,
    ) -> Result<ndn_mgmt::RevokedInfo, ndn_mgmt::TrustRefusal> {
        crate::revoke::revoke(self, request).await
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
