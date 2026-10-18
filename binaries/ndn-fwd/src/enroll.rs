//! The running daemon's side of `ndn-fwd enroll`: the `security/enroll` and
//! `security/enroll-status` management verbs, and the status watch that
//! finishes an enrollment the moment an admin approves it —
//! [`ndn_namespace::enroll`] and [`ndn_namespace::approval_wait`] over the
//! daemon's PIB ([`crate::pib_vault::PibVault`]).
//!
//! The key `/<ns>/<role>/<device>/KEY/<id>` is generated in the daemon's
//! PIB (the private key never leaves it); the certificate is stored beside
//! it (and the issuer certificates of its chain under `<pib>/issuers`), and
//! the identity becomes the PIB's default — loaded at every start unless
//! `[security] identity` names another one (the config file is never
//! edited). The running daemon then signs its management responses and
//! discovery records with the new key from the next packet on. DV routing in
//! the `static`/`lvs` trust modes keeps the key it started with (neighbours
//! list it in their `trusted_keys`) until the next start. Requests for an
//! admin's approval are recorded under `<pib>/requests/`.

use std::sync::Arc;

use ndn_cert::OutgoingRequest;
use ndn_mgmt::{EnrollOutcome, EnrollRequest, TrustRefusal};
use ndn_namespace::KeyVault;
use tokio_util::sync::CancellationToken;

use crate::context_adopt::TrustAdmin;

pub(crate) async fn enroll(
    admin: &TrustAdmin,
    request: EnrollRequest,
) -> Result<EnrollOutcome, TrustRefusal> {
    ndn_namespace::enroll::enroll(&admin.ns, admin.vault.as_ref(), request).await
}

/// `security/enroll-status`: this node's requests for an admin's approval,
/// oldest first.
pub(crate) fn enroll_status(admin: &TrustAdmin) -> Result<Vec<OutgoingRequest>, TrustRefusal> {
    ndn_namespace::enroll::enroll_status(admin.vault.as_ref(), admin.ns.words())
}

/// Finish this node's requests for an admin's approval, until `cancel`
/// ([`ndn_namespace::approval_wait::spawn_status_watch`]).
pub(crate) fn spawn_status_watch(admin: Arc<TrustAdmin>, cancel: CancellationToken) {
    let vault: Arc<dyn KeyVault> = admin.vault.clone();
    ndn_namespace::approval_wait::spawn_status_watch(Arc::clone(&admin.ns), vault, cancel);
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::Path;
    use std::time::Duration;

    use ndn_cert::OutgoingState;
    use ndn_config::{ChallengeConfig, CaTomlConfig};
    use ndn_engine::{EngineBuilder, EngineConfig, ShutdownHandle};
    use ndn_mgmt::RefreshState;
    use ndn_mgmt_wire::control_response::status;
    use ndn_namespace::enroll::certified_in;
    use ndn_packet::Name;
    use ndn_security::{Ed25519Signer, FilePib, Keyring, SecurityManager, Signer};
    use ndn_trust_envelope::TrustEnvelope;

    use super::*;
    use crate::active_identity::ActiveIdentity;
    use crate::context_adopt::TrustAdminParts;

    pub(crate) struct Node {
        pub(crate) admin: TrustAdmin,
        pub(crate) startup_key: Name,
        pub(crate) fingerprint: [u8; 32],
        /// The signed trust context the node holds.
        pub(crate) context_data: ndn_packet::Data,
        /// The root device's CA, on the same engine.
        pub(crate) ca: Arc<ndn_cert::CaState>,
        /// The root device's CA's approval records (its local operator
        /// decides through them).
        pub(crate) approvals: ndn_cert::ApprovalStore,
        /// The root device's trust-context publisher, on the same engine: it
        /// answers the node's refreshes.
        pub(crate) root_contexts: ndn_namespace::publish::PublishedContexts,
        pub(crate) shutdown: ShutdownHandle,
    }

    /// One engine carrying the root device's CA (PIB `root_dev`, tokens `tokens`) and
    /// trust-context publisher, and the enrolling node's trust-admin backend (PIB
    /// `device`, holding the root device's trust context already, signing with an
    /// ephemeral key).
    pub(crate) async fn node(root_dev: &Path, device: &Path, tokens: &[&str]) -> Node {
        let ns: Name = "/home/bob".parse().unwrap();
        let pib = FilePib::new(root_dev).unwrap();
        let persisted =
            ndn_cert::init_namespace_in_pib(&pib, &ns, "desk", false, &ndn_cert::NewRootStore::File)
                .await
                .unwrap();
        let cfg = CaTomlConfig {
            enabled: true,
            prefix: "/home/bob".into(),
            identity: "/home/bob/CA".into(),
            challenges: vec![ChallengeConfig {
                kind: "token".into(),
                tokens: tokens.iter().map(|t| t.to_string()).collect(),
                pin: None,
                max_tries: None,
                ttl_secs: None,
                smtp: None,
            }],
            // Above the 90 days a device once asked for: the CA's setting,
            // not the request, decides the lifetime.
            cert_validity_days: ndn_config::CertValidityDays::uniform(200),
            ..CaTomlConfig::default()
        };
        let (faces, ca) = crate::ca::prepare(&cfg, root_dev).await.unwrap();
        let (context_face, publisher) = crate::context_publisher::prepare(root_dev);
        let mut builder = EngineBuilder::new(EngineConfig::default())
            .security_profile(ndn_security::SecurityProfile::Disabled)
            .security(Arc::new(SecurityManager::new()))
            .face(context_face);
        for face in faces {
            builder = builder.face(face);
        }
        let (engine, shutdown) = builder.build().await.unwrap();
        engine.fib().add_nexthop(&ca.prefix, ca.face_id, 0);
        let running = crate::ca::spawn(ca, &cfg, &engine).unwrap();
        let (ca, approvals) = (
            running.state,
            running.approvals.expect("a namespace CA offers device-approval"),
        );
        let root_contexts = publisher.spawn(&engine);

        let keyring = Arc::new(Keyring::new());
        let fingerprint = ndn_cert::anchor_fingerprint(&persisted.init.anchor);
        ndn_cert::adopt_with_tofu(&keyring, &persisted.init.context_data, &ns, &fingerprint)
            .unwrap();
        let startup: Arc<dyn Signer> = Arc::new(Ed25519Signer::from_seed(
            &[1; 32],
            "/ndn-fwd/test/KEY/e".parse().unwrap(),
        ));
        Node {
            startup_key: startup.key_name().clone(),
            admin: TrustAdmin::new(TrustAdminParts {
                engine,
                keyring,
                pib_root: device.to_path_buf(),
                publisher: None,
                signing: Some(Arc::new(ActiveIdentity::new(startup, true))),
                own_certs: None,
                dv_keeps_startup_key: false,
                configured_identity: None,
                ca: None,
                context_sync: None,
            }),
            fingerprint,
            context_data: ndn_packet::Data::decode(persisted.init.context_data.raw().clone())
                .unwrap(),
            ca,
            approvals,
            root_contexts,
            shutdown,
        }
    }

    pub(crate) fn request(
        node: &Node,
        role: &str,
        token: &str,
        device: &str,
        force: bool,
    ) -> EnrollRequest {
        EnrollRequest {
            link_uri: TrustEnvelope::Invite {
                ca_prefix: "/home/bob".into(),
                identity_namespace: format!("/home/bob/{role}"),
                token: token.into(),
                ttl_secs: None,
                anchor_fingerprint: Some(node.fingerprint),
            }
            .to_uri(),
            identity: format!("/home/bob/{role}/{device}").parse().unwrap(),
            force,
        }
    }

    /// Of two adoptions of one namespace, the one finishing last never
    /// stores (or publishes) an older version than the keyring holds.
    #[tokio::test]
    async fn an_older_adoption_never_overwrites_the_held_version() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-x"]).await;
        let ns: Name = "/home/bob".parse().unwrap();
        let held = node.admin.ns.keyring().contexts().pop().unwrap();
        let older = ndn_cert::LinkAdoption {
            context: Arc::clone(&held),
            data: ndn_packet::Data::decode(node.context_data.raw().clone()).unwrap(),
            fetched: false,
        };
        // Another command adopted a newer version meanwhile.
        node.admin.ns.keyring().adopt(Arc::new(
            ndn_security::SignedTrustContext::hierarchical(ns.clone())
                .with_version(held.version() + 1),
        ));
        let refused = ndn_namespace::keep::keep_adopted(&node.admin.ns, &older, &node.fingerprint);
        assert_eq!(refused.unwrap_err().status_code, 409);
        assert!(!ndn_cert::context_file_path(device.path(), &ns).exists());
        node.shutdown.shutdown().await;
    }

    /// What the node's state is: PIB keys, default identity, signing key.
    fn state(node: &Node) -> (Vec<Name>, Option<Name>, Name) {
        let pib = FilePib::new(&node.admin.pib_root).unwrap();
        let (signing, _) = node.admin.signing.as_ref().unwrap().current();
        (pib.list_keys().unwrap(), pib.get_default_identity().unwrap(), signing)
    }

    /// A successful enrollment generates the key in the node's PIB (it
    /// signs there; nothing in the answer carries it), stores the issued
    /// certificate, selects the identity and switches the node's signer.
    #[tokio::test]
    async fn enrolled_key_stays_in_the_pib_and_is_selected() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-m1"]).await;
        assert_eq!(state(&node), (vec![], None, node.startup_key.clone()));

        let EnrollOutcome::Enrolled(info) =
            enroll(&node.admin, request(&node, "member", "member-m1", "laptop", false))
                .await
                .expect("enrolls") else { panic!("an invite enrolls at once") };
        let key: Name = info.key.parse().unwrap();
        let identity: Name = "/home/bob/member/laptop".parse().unwrap();
        assert!(key.has_prefix(&identity));
        assert_eq!(info.issuer, "/home/bob/CA/KEY/ca");
        let cert: Name = info.certificate.parse().unwrap();
        assert_eq!(
            cert.components()[..cert.len() - 1],
            key.clone().append("NDNCERT").components()[..],
            "the certificate is named <key>/NDNCERT/<version>"
        );
        assert!(cert.components().last().unwrap().as_version().is_some());
        assert!(info.signing_now);
        assert_eq!(info.validity_secs / 86_400, 200, "the CA's cert_validity_days decides");

        let pib = FilePib::open(device.path()).unwrap();
        assert_eq!(state(&node), (vec![key.clone()], Some(identity), key.clone()));
        assert!(pib.get_issued_cert(&key).unwrap().is_some());
        let secret = pib.export_pkcs8(&key).unwrap();
        let answer = serde_json::to_string(&EnrollOutcome::Enrolled(info)).unwrap();
        let hex_secret: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!answer.contains(&hex_secret));
        node.shutdown.shutdown().await;
    }

    /// Every refused enrollment — a spent token, a token rewritten into
    /// another role, a second enrollment without `force`, a forced one under
    /// the device name the node already holds — leaves the PIB, its default
    /// identity and the node's signer exactly as they were.
    #[tokio::test]
    async fn refused_enrollment_leaves_the_previous_identity_selected() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-m1", "member-m2", "guest-g1"]).await;
        enroll(&node.admin, request(&node, "member", "member-m1", "laptop", false))
            .await
            .expect("first enrollment");
        let before = state(&node);

        let spent = enroll(&node.admin, request(&node, "member", "member-m1", "phone", true)).await;
        assert_eq!(spent.unwrap_err().status_code, status::UNAUTHORIZED);
        assert_eq!(state(&node), before);

        let forged = enroll(&node.admin, request(&node, "member", "guest-g1", "tab", true)).await;
        assert_eq!(forged.unwrap_err().status_code, status::BAD_PARAMS);
        assert_eq!(state(&node), before);

        let again = enroll(&node.admin, request(&node, "member", "member-m2", "tab", false)).await;
        assert_eq!(again.unwrap_err().status_code, 409);
        assert_eq!(state(&node), before);

        let wrong_device = enroll(&node.admin, request(&node, "member", "member-m2", "KEY", true)).await;
        assert_eq!(wrong_device.unwrap_err().status_code, status::BAD_PARAMS);
        assert_eq!(state(&node), before);

        // The CA keeps the device name to the key it certified.
        let same_name =
            enroll(&node.admin, request(&node, "member", "member-m2", "laptop", true)).await;
        assert_eq!(same_name.unwrap_err().status_code, 409);
        assert_eq!(state(&node), before);

        // With `force` the same (unspent) token enrolls a second key under
        // another name; the first stays.
        let EnrollOutcome::Enrolled(info) =
            enroll(&node.admin, request(&node, "member", "member-m2", "tab", true))
                .await
                .expect("forced enrollment") else { panic!("an invite enrolls at once") };
        assert_eq!(info.still_valid.len(), 1);
        assert_eq!(state(&node).0.len(), 2);
        node.shutdown.shutdown().await;
    }

    /// A certificate whose chain the held trust context revokes — its CA
    /// key, or the root above it (a recovery after a compromise) — is not
    /// a held, valid certificate: it validates nowhere.
    #[tokio::test]
    async fn a_certificate_under_a_revoked_issuer_is_not_held() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-m1"]).await;
        let EnrollOutcome::Enrolled(info) =
            enroll(&node.admin, request(&node, "member", "member-m1", "laptop", false))
                .await
                .expect("enrolls") else { panic!("an invite enrolls at once") };
        let ns: Name = "/home/bob".parse().unwrap();
        let held = certified_in(&node.admin.ns, node.admin.vault.as_ref(), &ns);
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].revoked, None, "nothing revokes a fresh certificate's chain");

        let version = node.admin.ns.keyring().version_of(&ns).unwrap();
        for (bump, revoked) in [ndn_cert::namespace::ca_key_name(&ns), ndn_cert::namespace::root_key_name(&ns)]
            .into_iter()
            .enumerate()
        {
            node.admin.ns.keyring().adopt(Arc::new(
                ndn_security::SignedTrustContext::hierarchical(ns.clone())
                    .with_version(version + 1 + bump as u64)
                    .with_revocation(revoked.clone()),
            ));
            let held = certified_in(&node.admin.ns, node.admin.vault.as_ref(), &ns);
            assert_eq!(held[0].key.to_string(), info.key);
            assert_eq!(held[0].revoked.as_ref(), Some(&revoked), "revoking {revoked}");
        }
        node.shutdown.shutdown().await;
    }

    /// Enrollment judges the certificates the node holds against the
    /// namespace's newest trust context, not the stale one it holds: when a
    /// version the node has not fetched yet revokes its key, that key is
    /// listed as unusable (never "still valid") and does not block enrolling
    /// another — and the node holds the newer version afterwards.
    #[tokio::test]
    async fn held_certificates_are_judged_against_the_newest_context() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-m1", "member-m2"]).await;
        let ns: Name = "/home/bob".parse().unwrap();
        let EnrollOutcome::Enrolled(first) =
            enroll(&node.admin, request(&node, "member", "member-m1", "laptop", false))
                .await
                .expect("first enrollment") else { panic!("an invite enrolls at once") };
        let laptop: Name = first.key.parse().unwrap();
        let held = node.admin.ns.keyring().version_of(&ns).unwrap();

        // The root device revokes the laptop's key in a new version; the
        // node has not fetched it.
        let root = ndn_cert::RootStore::open(&FilePib::open(root_dev.path()).unwrap())
            .unwrap()
            .unwrap()
            .signer(None)
            .await
            .unwrap();
        let bump = ndn_cert::bump_context_revoking(
            root.as_ref(),
            &node.context_data,
            std::slice::from_ref(&laptop),
        )
        .await
        .unwrap()
        .unwrap();
        node.root_contexts.publish(&bump.context, &bump.data);
        assert_eq!(node.admin.ns.keyring().version_of(&ns), Some(held));
        // The first enrollment's check left the publisher's metadata (v1) in
        // the shared engine's Content Store; publishing v2 purges it, so the
        // next check is answered by the publisher at once.

        let EnrollOutcome::Enrolled(second) =
            enroll(&node.admin, request(&node, "member", "member-m2", "tab", false))
                .await
                .expect("the only certificate held is revoked by the newest version") else {
                panic!("an invite enrolls at once")
            };
        assert!(second.still_valid.is_empty(), "{:?}", second.still_valid);
        assert_eq!(second.unusable.len(), 1, "{:?}", second.unusable);
        assert!(second.unusable[0].starts_with(&first.key));
        let check = second.context_check.expect("the held context was checked");
        assert_eq!(check.state, RefreshState::Updated, "{}", check.detail);
        assert_eq!(node.admin.ns.keyring().version_of(&ns), Some(bump.context.version()));
        node.shutdown.shutdown().await;
    }

    /// `security/enroll` of `/home/bob/<role>/<device>` with the namespace's
    /// anchor link (its root's expected fingerprint `fingerprint`).
    fn approval_request(fingerprint: [u8; 32], role: &str, device: &str, force: bool) -> EnrollRequest {
        EnrollRequest {
            link_uri: TrustEnvelope::Anchor {
                namespace: Some("/home/bob".into()),
                fingerprint: Some(fingerprint),
                version: None,
                context_data: None,
                context_content: None,
            }
            .to_uri(),
            identity: format!("/home/bob/{role}/{device}").parse().unwrap(),
            force,
        }
    }

    /// The record of `request` once it left `pending`, which must happen
    /// within `within` — far shorter than a status Interest's lifetime, so
    /// only the held Interest's answer can have brought the decision.
    async fn resolved(admin: &TrustAdmin, request: &str, within: Duration) -> OutgoingRequest {
        assert!(within * 5 < ndn_cert::approval::STATUS_LIFETIME);
        tokio::time::timeout(within, async {
            loop {
                let records = enroll_status(admin).unwrap();
                let record = records.into_iter().find(|r| r.request_id == request).unwrap();
                if record.state != OutgoingState::Pending {
                    return record;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the decision reaches the waiting requester at once")
    }

    /// Enrollment on an admin's approval: `pending` with the code the CA
    /// shows (asking again answers the same request, no second key). The
    /// daemon waits on the CA with a held status Interest, resumed from its
    /// records after a restart; the moment the CA host's operator approves,
    /// the certificate is installed with no further request. A request made
    /// while the daemon runs is waited on at once; denied, it is recorded
    /// with its reason and its key deleted.
    #[tokio::test]
    async fn a_decision_reaches_the_waiting_requester_at_once_across_its_restart() {
        let settle = Duration::from_millis(500);
        let at_once = Duration::from_secs(3);
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &[]).await;
        let EnrollOutcome::Pending(pending) =
            enroll(&node.admin, approval_request(node.fingerprint, "admin", "tablet", false))
                .await
                .expect("the request is made")
        else {
            panic!("an admin certificate waits for an admin's approval")
        };
        let at_ca = node.approvals.pending();
        assert_eq!(at_ca.len(), 1);
        assert_eq!((&at_ca[0].request_id, &at_ca[0].code), (&pending.request, &pending.code));
        let EnrollOutcome::Pending(again) =
            enroll(&node.admin, approval_request(node.fingerprint, "admin", "tablet", false))
                .await
                .expect("asking again")
        else {
            panic!("still pending")
        };
        assert_eq!((again.request, again.key), (pending.request.clone(), pending.key.clone()));
        assert_eq!(state(&node).0.len(), 1, "one key for one request");

        let crate::enroll::tests::Node {
            admin,
            approvals,
            fingerprint,
            shutdown,
            ..
        } = node;
        let admin = Arc::new(admin);
        // The daemon that made the request stops while its status Interest
        // is held; the next start resumes from `<pib>/requests/`.
        let before_restart = CancellationToken::new();
        spawn_status_watch(Arc::clone(&admin), before_restart.clone());
        tokio::time::sleep(settle).await;
        before_restart.cancel();
        let cancel = CancellationToken::new();
        spawn_status_watch(Arc::clone(&admin), cancel.clone());
        tokio::time::sleep(settle).await;
        approvals
            .decide_locally(&pending.code, ndn_cert::Decision::Approve, "uid 1000 (alice)")
            .unwrap();
        let OutgoingState::Issued { certificate } =
            resolved(&admin, &pending.request, at_once).await.state
        else {
            panic!("approved: issued")
        };
        let key: Name = pending.key.parse().unwrap();
        let pib = FilePib::open(device.path()).unwrap();
        assert!(certificate.starts_with(&pending.key));
        assert!(pib.get_issued_cert(&key).unwrap().is_some());
        assert_eq!(
            pib.get_default_identity().unwrap(),
            Some("/home/bob/admin/tablet".parse().unwrap())
        );

        let EnrollOutcome::Pending(relay) =
            enroll(&admin, approval_request(fingerprint, "node", "relay", true))
                .await
                .expect("the request is made")
        else {
            panic!("a node certificate waits for an admin's approval")
        };
        tokio::time::sleep(settle).await;
        approvals
            .decide_locally(
                &relay.request,
                ndn_cert::Decision::Deny {
                    reason: "not my relay".into(),
                },
                "uid 1000 (alice)",
            )
            .unwrap();
        let OutgoingState::Denied { reason } = resolved(&admin, &relay.request, at_once).await.state
        else {
            panic!("denied")
        };
        assert!(reason.contains("not my relay"), "{reason}");
        let relay_key: Name = relay.key.parse().unwrap();
        assert!(!pib.list_keys().unwrap().contains(&relay_key), "the denied key is deleted");
        cancel.cancel();
        shutdown.shutdown().await;
    }
}
