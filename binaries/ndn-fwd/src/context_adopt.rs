//! The running daemon's trust-admin backend: `security/context-adopt`
//! (`ndn-fwd adopt`), `security/enroll` (`ndn-fwd enroll`, see
//! [`crate::enroll`]), `security/context-refresh` (`ndn-fwd context
//! refresh`, see [`crate::context_refresh`]), `security/context-update`
//! (`ndn-fwd revoke`, `ndn-fwd recovery-kit`, `ndn-fwd recover`: a version
//! signed on this device, see [`crate::context_refresh::apply_update`]),
//! `security/renew` (`ndn-fwd renew`, see [`crate::renewal`]) and the
//! signing identity `security/identity-status` reports.
//!
//! Every version this node keeps, by whichever path it was adopted, is also
//! followed by its namespace CA if it runs one ([`TrustAdmin::keep`],
//! [`crate::revoke::ca_follow`]): the CA stops serving every certificate the
//! version revokes.
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

use ndn_cert::{AdoptError, AnchorLink, CaRevocation, CaState, LinkAdoption};
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
    /// This node's CA (`[ca]`); `None` when the node runs none. It follows
    /// every version of its namespace's trust context this node keeps
    /// ([`TrustAdmin::keep`]).
    pub(crate) ca: Option<Arc<CaState>>,
    /// One context change handed over on this node at a time
    /// (`security/context-update`), so none works from a version another is
    /// replacing. A refresh takes no lock: it adopts only if the version it
    /// fetched against is still held.
    pub(crate) context_change: tokio::sync::Mutex<()>,
    /// One certificate renewal at a time (`security/renew` and the renewal
    /// timer).
    pub(crate) renewing: tokio::sync::Mutex<()>,
    /// Woken whenever this node's certificates change (an enrollment, a
    /// renewal), so the renewal timer reads them again.
    pub(crate) certificates_changed: tokio::sync::Notify,
    /// The namespaces' sync groups (`[security] context_sync`): every
    /// version this node keeps is handed to it, so the groups follow the
    /// namespaces held and the root device puts each new version into its
    /// namespace's group. `None` when off.
    pub(crate) context_sync: Option<crate::context_sync::ContextSync>,
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

/// What [`TrustAdmin::keep`] did with a version this node adopted.
pub(crate) struct Kept {
    /// Where it is stored, or why storing it failed (it holds for this run,
    /// and is gone after a restart).
    pub(crate) stored: Result<PathBuf, ndn_mgmt::TrustRefusal>,
    /// What this node's CA of the namespace stopped serving because the
    /// version revokes it; `None` when the node runs no CA of it.
    pub(crate) ca: Option<CaRevocation>,
}

impl Kept {
    /// The CA's part, worded to end an answer's detail; empty when the CA
    /// had nothing to stop serving.
    pub(crate) fn ca_detail(&self) -> String {
        let Some(ca) = &self.ca else {
            return String::new();
        };
        let mut detail = String::new();
        if !ca.revoked.is_empty() {
            let names: Vec<String> = ca.revoked.iter().map(ToString::to_string).collect();
            detail = format!(
                "; this node's CA no longer serves {} (the version revokes their keys) and \
                 their device names are free for a new key",
                names.join(", ")
            );
        }
        if let Some(e) = &ca.not_persisted {
            detail.push_str(&format!(
                "; the CA could not record that in its store ({e}): it holds for this run, and \
                 the CA follows the stored trust context again when the daemon starts"
            ));
        }
        detail
    }
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
        let stored = self.keep(ctx, &adopted.data)?.stored?;
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

    /// Keep `ctx` (signed Data `data`), already in the keyring: this node's
    /// CA of its namespace stops serving every certificate it revokes
    /// ([`crate::revoke::ca_follow`]), and it is stored in `<pib>/contexts/`
    /// and published by name as the namespace's newest version (the versions
    /// before it stay stored and served). Refused (`409`) when the keyring
    /// meanwhile holds a newer version of the namespace: that one is what is
    /// kept (and followed). A failure to store it is reported in
    /// [`Kept::stored`]: the version holds for this run all the same.
    pub(crate) fn keep(
        &self,
        ctx: &SignedTrustContext,
        data: &Data,
    ) -> Result<Kept, ndn_mgmt::TrustRefusal> {
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
        let ca = self
            .ca
            .as_deref()
            .and_then(|ca| crate::revoke::ca_follow(ca, ctx));
        Ok(Kept {
            stored: self.store_and_publish(ctx, data),
            ca,
        })
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
        if let Some(sync) = &self.context_sync {
            sync.kept(ctx, data);
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
