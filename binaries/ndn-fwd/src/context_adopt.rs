//! The running daemon's trust-admin backend: `security/context-adopt`
//! (`ndn-fwd adopt`), `security/enroll` (`ndn-fwd enroll`, see
//! [`crate::enroll`]) and the signing identity `security/identity-status`
//! reports.
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

use ndn_cert::{AdoptError, AnchorLink, LinkAdoption};
use ndn_engine::ForwarderEngine;
use ndn_mgmt_wire::control_response::status;
use ndn_security::Keyring;

use crate::active_identity::ActiveIdentity;
use crate::context_publisher::PublishedContexts;

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
        let stored = ndn_cert::persist_context(&self.pib_root, ctx, &adopted.data).map_err(|e| {
            refusal(
                status::SERVER_ERROR,
                format!(
                    "adopted {} v{} for this run, but storing it failed ({e}); it will be gone \
                     after a restart — fix the PIB directory ({}) and adopt again",
                    ctx.namespace(),
                    ctx.version(),
                    self.pib_root.display()
                ),
            )
        })?;
        if let Some(publisher) = &self.publisher {
            publisher.publish(ctx, &adopted.data);
        }
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
        // version this node already has).
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

    fn signing_identity(&self) -> Option<ndn_mgmt::SigningIdentityInfo> {
        self.signing.as_ref().map(|s| {
            let (key, ephemeral) = s.current();
            ndn_mgmt::SigningIdentityInfo { key, ephemeral }
        })
    }
}
