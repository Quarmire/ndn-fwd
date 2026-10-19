//! Keeping held trust contexts current: `ndn-fwd context refresh [<ns>]`
//! (the `security/context-refresh` management verb) and the periodic check
//! every `[security] context_refresh_secs` — [`ndn_namespace::refresh`]
//! over the daemon's [`TrustAdmin`]. A version made on this device by a CLI
//! that signs offline — `ndn-fwd revoke` and `ndn-fwd recovery-kit` on the
//! root device, `ndn-fwd recover` on a replacement — is handed over with
//! `security/context-update` ([`apply_update`],
//! [`ndn_namespace::keep::apply_update`]).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_mgmt::{ContextRefreshInfo, TrustRefusal};
use ndn_packet::Name;
use tokio_util::sync::CancellationToken;

use crate::context_adopt::TrustAdmin;

pub(crate) async fn refresh_contexts(
    admin: &TrustAdmin,
    namespace: Option<Name>,
) -> Result<Vec<ContextRefreshInfo>, TrustRefusal> {
    ndn_namespace::refresh::refresh_contexts(&admin.ns, namespace).await
}

/// `security/context-update`: see [`ndn_namespace::keep::apply_update`].
pub(crate) async fn apply_update(
    admin: &TrustAdmin,
    wire: Bytes,
) -> Result<ContextRefreshInfo, TrustRefusal> {
    ndn_namespace::keep::apply_update(&admin.ns, wire).await
}

/// Check every held context every `period_secs` (0: never), until `cancel`.
pub(crate) fn spawn_periodic(admin: Arc<TrustAdmin>, period_secs: u64, cancel: CancellationToken) {
    if period_secs == 0 {
        tracing::info!(
            target: "security",
            "[security] context_refresh_secs = 0: held trust contexts are refreshed only by \
             `ndn-fwd context refresh`"
        );
        return;
    }
    tracing::info!(target: "security", period_secs, "refreshing held trust contexts periodically");
    ndn_namespace::refresh::spawn_periodic(
        Arc::clone(&admin.ns),
        Duration::from_secs(period_secs),
        cancel,
    );
}

#[cfg(test)]
mod tests {
    use ndn_cert::RootStore;
    use ndn_packet::Name;
    use ndn_security::{Ed25519Signer, FilePib, SignedTrustContext};

    use super::*;
    use crate::enroll::tests::node;

    /// A version handed to the daemon (`security/context-update`) is
    /// adopted, stored and kept only under the continuity rule: one a
    /// stranger signs, or one not newer, changes nothing; one the root signs
    /// (adding a recovery kit) is adopted and stored.
    #[tokio::test]
    async fn a_handed_version_is_adopted_only_under_the_continuity_rule() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &[]).await;
        let ns: Name = "/home/bob".parse().unwrap();

        let stranger: Arc<dyn ndn_security::Signer> = Arc::new(Ed25519Signer::from_seed(
            &[5; 32],
            "/home/bob/KEY/stranger".parse().unwrap(),
        ));
        let forged =
            SignedTrustContext::decode_content(node.context_data.content().unwrap(), 2).unwrap();
        forged.add_anchor(
            ndn_cert::recovery_anchor(Arc::clone(&stranger))
                .await
                .unwrap(),
        );
        let forged = forged
            .sign_into_data_async(stranger.as_ref())
            .await
            .unwrap();
        let refused = apply_update(&node.admin, forged.raw().clone())
            .await
            .unwrap_err();
        assert_eq!(refused.status_code, 403, "{}", refused.reason);
        assert_eq!(node.admin.ns.keyring().version_of(&ns), Some(1));
        assert!(
            ndn_cert::read_stored_context(device.path(), &ns)
                .unwrap()
                .is_none()
        );

        let pib = FilePib::open(root_dev.path()).unwrap();
        let root = RootStore::open(&pib)
            .unwrap()
            .unwrap()
            .signer(None)
            .await
            .unwrap();
        let seed = ndn_cert::RecoverySeed::generate().unwrap();
        let kit = ndn_cert::recovery_anchor(Arc::new(seed.signer(&ns)))
            .await
            .unwrap();
        let bump = ndn_cert::add_recovery_anchor(root.as_ref(), &node.context_data, &kit)
            .await
            .unwrap();
        let info = apply_update(&node.admin, bump.data.raw().clone())
            .await
            .unwrap();
        assert_eq!((info.held_version, info.version), (1, 2));
        let (stored, _) = ndn_cert::read_stored_context(device.path(), &ns)
            .unwrap()
            .unwrap();
        assert_eq!(stored.version(), 2);
        assert!(stored.has_key_role(&kit.key_name(), ndn_security::KeyRole::RECOVERY_ANCHOR));

        // Handed over again (a CLI that got no answer asks again): taken,
        // never refused — a refusal would make the CLI undo what this node
        // holds. Another v2 is still refused.
        let again = apply_update(&node.admin, bump.data.raw().clone())
            .await
            .unwrap();
        assert_eq!((info.version, again.version), (2, 2));
        let other_kit = ndn_cert::recovery_anchor(Arc::new(
            ndn_cert::RecoverySeed::generate().unwrap().signer(&ns),
        ))
        .await
        .unwrap();
        let other = ndn_cert::add_recovery_anchor(root.as_ref(), &node.context_data, &other_kit)
            .await
            .unwrap();
        let refused = apply_update(&node.admin, other.data.raw().clone())
            .await
            .unwrap_err();
        assert_eq!(refused.status_code, 403, "{}", refused.reason);
        assert_eq!(node.admin.ns.keyring().version_of(&ns), Some(2));
        let (stored, data) = ndn_cert::read_stored_context(device.path(), &ns)
            .unwrap()
            .unwrap();
        assert!(stored.has_key_role(&kit.key_name(), ndn_security::KeyRole::RECOVERY_ANCHOR));
        assert_eq!(data.raw(), bump.data.raw());
        node.shutdown.shutdown().await;
    }
}
