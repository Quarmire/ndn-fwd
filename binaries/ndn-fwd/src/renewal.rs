//! Renewing this node's certificates before they expire: `ndn-fwd renew`
//! (the `security/renew` management verb) and the renewal timer (`[security]
//! renew_before`), over [`ndn_namespace::renewal`] with the node's PIB as the
//! key vault. What is renewed, when, and how failures back off is the
//! library's ([`ndn_identity::renewal::RenewalSchedule`]).

use std::sync::Arc;

use ndn_config::RenewBeforeConfig;
use ndn_identity::RenewBefore;
use ndn_mgmt::{RenewalInfo, TrustRefusal};
use ndn_namespace::KeyVault;
use tokio_util::sync::CancellationToken;

use crate::context_adopt::TrustAdmin;

/// `security/renew`: renew every certificate a namespace CA issued to this
/// node's keys now, whatever their remaining validity.
pub(crate) async fn renew_now(admin: &TrustAdmin) -> Result<Vec<RenewalInfo>, TrustRefusal> {
    ndn_namespace::renewal::renew_now(&admin.ns, admin.vault.as_ref()).await
}

/// Renew each held certificate once its remaining validity falls below
/// `renew_before`, until `cancel`. `Off`: never (only `ndn-fwd renew`).
pub(crate) fn spawn_periodic(
    admin: Arc<TrustAdmin>,
    renew_before: RenewBeforeConfig,
    cancel: CancellationToken,
) {
    let before = match renew_before {
        RenewBeforeConfig::Off => {
            tracing::info!(
                target: "security",
                "[security] renew_before = 0: certificates are renewed only by `ndn-fwd renew`"
            );
            return;
        }
        RenewBeforeConfig::Fraction(f) => RenewBefore::Fraction(f),
        RenewBeforeConfig::Before(d) => RenewBefore::Remaining(d),
    };
    let vault: Arc<dyn KeyVault> = admin.vault.clone();
    ndn_namespace::renewal::spawn_periodic(Arc::clone(&admin.ns), vault, before, cancel);
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ndn_mgmt::RenewalState;
    use ndn_packet::{Data, Name};
    use ndn_security::{Certificate, FilePib};

    use super::*;
    use crate::enroll::tests::{node, request};

    /// The certificate the PIB at `pib` stores for `key`.
    fn stored(pib: &std::path::Path, key: &Name) -> Certificate {
        let pib = FilePib::open(pib).unwrap();
        let wire = pib.get_issued_cert(key).unwrap().unwrap();
        Certificate::decode(&Data::decode(wire).unwrap()).unwrap()
    }

    /// `ndn-fwd renew` on an enrolled node: the same key gets a new
    /// certificate, under a new name, from the CA without a token; the PIB
    /// stores it beside the old one, and the node keeps signing with that key.
    #[tokio::test]
    async fn renew_keeps_the_key_and_stores_the_new_certificate() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-m1"]).await;
        let ndn_mgmt::EnrollOutcome::Enrolled(enrolled) = crate::enroll::enroll(
            &node.admin,
            request(&node, "member", "member-m1", "laptop", false),
        )
        .await
        .expect("enrolls") else {
            panic!("an invite enrolls at once")
        };
        let key: Name = enrolled.key.parse().unwrap();
        let (signing_before, _) = node.admin.signing.as_ref().unwrap().current();
        let before = stored(device.path(), &key);
        // Validity periods are stored to the second.
        tokio::time::sleep(Duration::from_millis(1_100)).await;

        let results = renew_now(&node.admin)
            .await
            .expect("a node holding a certificate renews");
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.state, RenewalState::Renewed, "{}", r.detail);
        assert_eq!(r.key, enrolled.key);

        let after = stored(device.path(), &key);
        assert!(
            after.valid_until > before.valid_until,
            "the PIB holds the new certificate"
        );
        assert_eq!(after.public_key, before.public_key, "for the same key");
        assert_ne!(
            after.name, before.name,
            "a renewed certificate has its own name"
        );
        let pib = FilePib::open(device.path()).unwrap();
        assert_eq!(
            pib.valid_cert_wires(&key).unwrap().len(),
            2,
            "the old one is kept until it expires"
        );
        assert_eq!(pib.list_keys().unwrap(), vec![key.clone()], "no new key");
        let (signing_after, _) = node.admin.signing.as_ref().unwrap().current();
        assert_eq!(
            signing_after, signing_before,
            "the node keeps signing with the same key"
        );
        node.shutdown.shutdown().await;
    }

    /// A key the root device revoked at its CA is refused, the stored
    /// certificate stays as it was, and a node with nothing to renew says so.
    #[tokio::test]
    async fn a_revoked_key_is_refused_and_nothing_changes() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-m1"]).await;
        assert_eq!(renew_now(&node.admin).await.unwrap_err().status_code, 404);

        let ndn_mgmt::EnrollOutcome::Enrolled(enrolled) = crate::enroll::enroll(
            &node.admin,
            request(&node, "member", "member-m1", "laptop", false),
        )
        .await
        .expect("enrolls") else {
            panic!("an invite enrolls at once")
        };
        let key: Name = enrolled.key.parse().unwrap();
        let before = stored(device.path(), &key);
        node.ca.revoke_issued_under(&key);

        let results = renew_now(&node.admin).await.unwrap();
        assert_eq!(results[0].state, RenewalState::Refused, "{:?}", results[0]);
        let after = stored(device.path(), &key);
        assert_eq!(
            after.valid_until, before.valid_until,
            "the stored certificate is kept"
        );
        node.shutdown.shutdown().await;
    }

    /// The renewal timer renews a certificate that is due, without being
    /// asked.
    #[tokio::test]
    async fn the_timer_renews_a_due_certificate() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-m1"]).await;
        let ndn_mgmt::EnrollOutcome::Enrolled(enrolled) = crate::enroll::enroll(
            &node.admin,
            request(&node, "member", "member-m1", "laptop", false),
        )
        .await
        .expect("enrolls") else {
            panic!("an invite enrolls at once")
        };
        let key: Name = enrolled.key.parse().unwrap();
        let before = stored(device.path(), &key);
        let crate::enroll::tests::Node {
            admin, shutdown, ..
        } = node;
        let admin = Arc::new(admin);
        // Validity periods are stored to the second.
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        // Due at once: renew while nearly the whole lifetime is left.
        let cancel = CancellationToken::new();
        spawn_periodic(
            Arc::clone(&admin),
            RenewBeforeConfig::Fraction(0.999_999),
            cancel.clone(),
        );
        admin.ns.notify_certificates_changed();
        let renewed = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let now = stored(device.path(), &key);
                if now.valid_until > before.valid_until {
                    return now;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the timer renews the due certificate");
        assert_eq!(renewed.public_key, before.public_key, "for the same key");
        cancel.cancel();
        shutdown.shutdown().await;
    }

    /// A `renew_before` longer than the lifetime the CA issues never makes
    /// the timer renew in a loop (each new certificate due as it is issued).
    #[tokio::test]
    async fn renew_before_longer_than_the_lifetime_does_not_renew_in_a_loop() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-m1"]).await;
        let ndn_mgmt::EnrollOutcome::Enrolled(enrolled) = crate::enroll::enroll(
            &node.admin,
            request(&node, "member", "member-m1", "laptop", false),
        )
        .await
        .expect("enrolls") else {
            panic!("an invite enrolls at once")
        };
        let key: Name = enrolled.key.parse().unwrap();
        let lifetime = Duration::from_secs(enrolled.validity_secs);
        let crate::enroll::tests::Node {
            admin, shutdown, ..
        } = node;
        let admin = Arc::new(admin);
        let cancel = CancellationToken::new();
        spawn_periodic(
            Arc::clone(&admin),
            RenewBeforeConfig::Before(lifetime + Duration::from_secs(86_400)),
            cancel.clone(),
        );
        admin.ns.notify_certificates_changed();
        tokio::time::sleep(Duration::from_secs(4)).await;
        let pib = FilePib::open(device.path()).unwrap();
        assert!(
            pib.valid_cert_wires(&key).unwrap().len() <= 2,
            "renewed at most once"
        );
        cancel.cancel();
        shutdown.shutdown().await;
    }

    /// A PIB the daemon cannot read is refused as unreadable, not as a node
    /// holding nothing (whose advice, enrolling again, would burn an invite).
    #[tokio::test]
    async fn an_unreadable_pib_is_not_reported_as_holding_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-m1"]).await;
        crate::enroll::enroll(
            &node.admin,
            request(&node, "member", "member-m1", "laptop", false),
        )
        .await
        .expect("enrolls");
        let keys = device.path().join("keys");
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Permissions bind only an unprivileged user.
        let enforced = std::fs::read_dir(&keys).is_err();
        let refused = renew_now(&node.admin).await;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).unwrap();
        if enforced {
            assert_ne!(refused.unwrap_err().status_code, 404);
        }
        node.shutdown.shutdown().await;
    }
}
