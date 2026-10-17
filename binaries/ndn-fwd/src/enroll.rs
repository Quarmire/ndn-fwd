//! The running daemon's side of `ndn-fwd enroll <invite>`: the
//! `security/enroll` management verb.
//!
//! The daemon owns every piece of state: it generates the device key
//! `/<ns>/<role>/<device>/KEY/<id>` in its own PIB (the private key never
//! leaves it), lets [`ndn_identity::enroll_with_invite_via_engine`] adopt the
//! namespace's trust context if it is not held and obtain a certificate from
//! the namespace's CA with the invite's token, stores the issued certificate
//! beside the key (and the issuer certificates of its chain under
//! `<pib>/issuers`, [`ndn_cert::issuers`]), and makes the identity the PIB's
//! default — loaded at every start unless `[security] identity` names another
//! one (the config file is never edited). The running daemon then signs its
//! management responses and discovery records with the new key from the next
//! packet on. DV routing in the `static`/`lvs` trust modes keeps the key it
//! started with (neighbours list it in their `trusted_keys`) until the next
//! start.
//!
//! A failed enrollment leaves the previous state: the new key (and anything
//! stored for it) is deleted and the default identity is only changed as the
//! last step, after the certificate is stored.

use std::sync::Arc;

use ndn_cert::roles::parse_device_key;
use ndn_cert::{InviteEnrollError, InviteLink, new_device_key_name};
use ndn_mgmt::{EnrollOutcome, EnrollRequest, EnrolledInfo, TrustRefusal};
use ndn_mgmt_wire::control_response::status;
use ndn_packet::{Data, Name};
use ndn_security::{Certificate, FilePib, Signer, SignedTrustContext};

use crate::context_adopt::{TrustAdmin, refusal};

fn status_of(e: &InviteEnrollError) -> u64 {
    use InviteEnrollError as E;
    match e {
        E::BadInvite(_)
        | E::NotInvite(_)
        | E::InviteField { .. }
        | E::InviteRole(_)
        | E::TokenRole { .. }
        | E::Device(_)
        | E::KeyOutsideInvite { .. }
        | E::NoExpectedFingerprint { .. } => status::BAD_PARAMS,
        E::ContextUnreachable { .. } | E::CaUnreachable { .. } => 504,
        E::NameRefused(_) => 409,
        E::Adopt {
            source: ndn_cert::AdoptError::InProgress(_),
            ..
        } => 409,
        E::Signing(_) => status::SERVER_ERROR,
        _ => status::UNAUTHORIZED,
    }
}

pub(crate) fn iso(ns: u64) -> String {
    let basic = ndn_security::iso8601::format_iso_basic(ns);
    format!("{}Z", String::from_utf8_lossy(&basic))
}

/// The device component of `identity` when it is `<identity_prefix>/<device>`.
fn device_of<'a>(invite: &InviteLink, identity: &'a Name) -> Result<&'a str, TrustRefusal> {
    let comps = identity.components();
    let device = (identity.has_prefix(&invite.identity_prefix)
        && comps.len() == invite.identity_prefix.len() + 1)
        .then(|| std::str::from_utf8(&comps[comps.len() - 1].value).ok())
        .flatten();
    device.ok_or_else(|| {
        refusal(
            status::BAD_PARAMS,
            format!(
                "the identity to enroll, {identity}, is not <device> under the invite's \
                 identity namespace {}",
                invite.identity_prefix
            ),
        )
    })
}

/// A device key of a namespace this PIB holds a currently valid certificate
/// for.
struct Certified {
    key: Name,
    valid_until: u64,
    /// What the held trust context revokes on the certificate's chain — the
    /// key itself, or an issuer up to the root: the certificate validates
    /// nowhere.
    revoked: Option<Name>,
}

/// Device keys in `namespace` this PIB holds a currently valid certificate
/// for, each with what revokes its chain, if anything. Issuer certificates
/// come from those kept under `<pib>/issuers` ([`ndn_cert::issuers`]), else
/// the validation cache.
fn certified_in(admin: &TrustAdmin, pib: &FilePib, namespace: &Name) -> Vec<Certified> {
    let kept: Vec<Certificate> = ndn_cert::issuers::stored_issuer_certs(&admin.pib_root)
        .into_iter()
        .filter_map(|wire| Certificate::decode(&Data::decode(wire).ok()?).ok())
        .collect();
    let issuer_cert = |key: &Name| {
        kept.iter()
            .filter(|c| c.name.has_prefix(key))
            .max_by_key(|c| c.valid_from)
            .cloned()
            .or_else(|| admin.engine.security()?.cert_cache().get_valid(key))
    };
    let mut held: Vec<Certified> = pib
        .list_keys()
        .unwrap_or_default()
        .into_iter()
        .filter(|k| parse_device_key(namespace, k).is_some())
        .filter_map(|key| {
            let cert = pib.get_cert(&key).ok()?;
            if !cert.is_valid_now() {
                return None;
            }
            let revoked = revoked_on_chain(&admin.keyring.context_for(&key), &cert, &issuer_cert);
            Some(Certified {
                key,
                valid_until: cert.valid_until,
                revoked,
            })
        })
        .collect();
    held.sort_by(|a, b| a.key.cmp(&b.key));
    held
}

/// The first name on `cert`'s chain that `ctx` revokes: each certificate
/// (a revoked key or identity is a prefix of its certificates' names) and
/// each issuer key, walking issuer certificates `issuer_cert` resolves up to
/// a self-signed one or one it cannot resolve.
fn revoked_on_chain(
    ctx: &SignedTrustContext,
    cert: &Certificate,
    issuer_cert: impl Fn(&Name) -> Option<Certificate>,
) -> Option<Name> {
    const MAX_CHAIN: usize = 8;
    let mut current = cert.clone();
    for _ in 0..MAX_CHAIN {
        if ctx.is_revoked(&current.name) {
            return Some((*current.name).clone());
        }
        let issuer = current.issuer.clone()?;
        if ctx.is_revoked(&issuer) {
            return Some((*issuer).clone());
        }
        let next = issuer_cert(&issuer)?;
        if next.name == current.name {
            return None;
        }
        current = next;
    }
    None
}

/// Delete a key this enrollment generated (and whatever was stored for it).
fn discard(pib: &FilePib, key: &Name) {
    if let Err(e) = pib.delete_key(key) {
        tracing::error!(
            target: "security",
            key = %key,
            error = %e,
            "could not delete the key of a failed enrollment; it is not the default identity"
        );
    }
}

pub(crate) async fn enroll(
    admin: &TrustAdmin,
    request: EnrollRequest,
) -> Result<EnrollOutcome, TrustRefusal> {
    let Ok(_one_at_a_time) = admin.enrolling.try_lock() else {
        return Err(refusal(
            409,
            "another enrollment is running on this node; wait for it to finish",
        ));
    };
    let invite = InviteLink::from_uri(&request.invite_uri)
        .map_err(|e| refusal(status_of(&e), e.to_string()))?;
    let device = device_of(&invite, &request.identity)?;
    let identity = invite
        .device_identity(device)
        .map_err(|e| refusal(status_of(&e), e.to_string()))?;

    let pib = FilePib::new(&admin.pib_root).map_err(|e| {
        refusal(
            status::SERVER_ERROR,
            format!("cannot open the PIB {}: {e}", admin.pib_root.display()),
        )
    })?;
    let previous_identity = pib.get_default_identity().ok().flatten();
    let (unusable, held): (Vec<Certified>, Vec<Certified>) =
        certified_in(admin, &pib, &invite.namespace)
            .into_iter()
            .partition(|c| c.revoked.is_some());
    let still_valid: Vec<String> = held
        .iter()
        .map(|c| format!("{} (valid until {})", c.key, iso(c.valid_until)))
        .collect();
    if !held.is_empty() && !request.force {
        return Err(refusal(
            409,
            format!(
                "this node already holds a certificate in {}: {}. To enroll another key anyway, \
                 run again with --force and another --device name (the CA certifies a new key \
                 for a device name it already certified only once that certificate is revoked \
                 or an admin approves the new key); the certificate this node holds stays valid \
                 until it expires or is revoked",
                invite.namespace,
                still_valid.join(", ")
            ),
        ));
    }
    let unusable: Vec<String> = unusable
        .iter()
        .filter_map(|c| Some(format!("{} (revoked: {})", c.key, c.revoked.as_ref()?)))
        .collect();

    let key = new_device_key_name(&identity);
    let generated = pib.generate_ed25519(&key).map_err(|e| {
        refusal(
            status::SERVER_ERROR,
            format!("cannot generate the device key in {}: {e}", admin.pib_root.display()),
        )
    })?;
    let signer: Arc<dyn Signer> = Arc::new(generated);
    tracing::info!(
        target: "security",
        key = %key,
        ca = %invite.ca_prefix,
        "enrolling with an invite"
    );

    let enrollment = match ndn_identity::enroll_with_invite_via_engine(
        &admin.engine,
        &admin.keyring,
        &invite,
        Arc::clone(&signer),
    )
    .await
    {
        Ok(enrollment) => enrollment,
        Err(failure) => {
            discard(&pib, &key);
            let mut reason = failure.error.to_string();
            if let (Some(adopted), Some(fp)) = (&failure.adopted, &invite.expected_fingerprint) {
                // The context passed the fingerprint check on its own; keep
                // what the keyring already holds across a restart.
                match admin.keep_adopted(adopted, fp) {
                    Ok(info) => reason.push_str(&format!(
                        ". The trust context {} v{} was adopted on the way and stays adopted",
                        info.namespace, info.version
                    )),
                    Err(e) => reason.push_str(&format!(". Also: {}", e.reason)),
                }
            }
            tracing::warn!(
                target: "security",
                identity = %identity,
                error = %reason,
                "enrollment failed; nothing was kept for the new key"
            );
            return Err(refusal(status_of(&failure.error), reason));
        }
    };

    // The certificate is issued and the token spent: whatever happens to
    // the adopted context's copy on disk, keep the certificate.
    let mut context_warning = None;
    let adopted_context = match (&enrollment.adopted, &invite.expected_fingerprint) {
        (Some(adopted), Some(fp)) => match admin.keep_adopted(adopted, fp) {
            Ok(info) => Some(info),
            Err(e) => {
                tracing::warn!(
                    target: "security",
                    reason = %e.reason,
                    "enrolled, but the adopted trust context was not stored"
                );
                context_warning = Some(e.reason);
                None
            }
        },
        _ => None,
    };
    let issued = &enrollment.issued;
    let kept = pib
        .store_issued_cert(&key, issued.data.raw())
        .and_then(|_| pib.set_default_identity(&identity));
    if let Err(e) = kept {
        discard(&pib, &key);
        return Err(refusal(
            status::SERVER_ERROR,
            format!(
                "the CA issued {}, but storing it in {} failed ({e}); nothing was kept and the \
                 previous identity stays selected. The token is spent: fix the PIB directory and \
                 ask for a new invite",
                issued.cert.name,
                admin.pib_root.display()
            ),
        ));
    }

    // The certificate's issuer chain, kept beside the PIB: it is served with
    // this node's certificates and sent with a renewal, so a later CA of the
    // namespace can verify the chain once nobody else serves this CA's
    // certificate (`ndn_cert::issuers`).
    if let Err(e) = ndn_cert::issuers::keep_issuer_certs(&admin.pib_root, &issued.issuers) {
        tracing::warn!(
            target: "security",
            error = %e,
            "enrolled, but the issuer certificates of its chain were not kept"
        );
    }

    // The live daemon: the engine's key store holds the identity (so an app
    // asking the engine to sign as it can), and — unless the config pins
    // another identity — this key signs the daemon's own packets from now on.
    if let Some(mgr) = admin.engine.security() {
        mgr.register_signer(key.clone(), Arc::clone(&signer));
        mgr.cert_cache().insert(issued.cert.clone());
    }
    // Peers validating this node's Data can fetch the certificate, and its
    // issuers, from it.
    if let Some(own) = &admin.own_certs {
        own.serve(issued.data.raw().clone());
        for issuer in &issued.issuers {
            own.serve(issuer.raw().clone());
        }
    }
    // The renewal timer schedules the new certificate's renewal.
    admin.certificates_changed.notify_one();
    let mut at_next_start = Vec::new();
    if let Some(reason) = context_warning {
        at_next_start.push(format!(
            "the trust context for {} is held for this run only: {reason}",
            invite.namespace
        ));
    }
    if admin.dv_keeps_startup_key {
        at_next_start.push(format!(
            "DV routing: it keeps signing with the key this node started with (DV `static`/`lvs` \
             trust); it signs with {key} after a restart, so add that key to every DV \
             neighbour's [routing.dv.trust] trusted_keys before restarting"
        ));
    }
    let signing_now = match (&admin.configured_identity, &admin.signing) {
        (Some(configured), _) => {
            at_next_start.push(format!(
                "nothing: [security] identity = \"{configured}\" in this node's config takes \
                 precedence over the PIB's default identity; remove that line to sign as \
                 {identity}"
            ));
            false
        }
        (None, Some(active)) => {
            active.switch_to(Arc::clone(&signer));
            true
        }
        (None, None) => {
            at_next_start.push(format!(
                "management responses: this node started without a signing key; it signs as \
                 {identity} after a restart"
            ));
            false
        }
    };
    tracing::info!(
        target: "security",
        identity = %identity,
        certificate = %issued.cert.name,
        issuer = ?issued.issuer.as_ref().map(Name::to_string),
        signing_now,
        "enrolled; the PIB's default identity is now this one"
    );
    Ok(EnrollOutcome::Enrolled(EnrolledInfo {
        identity: identity.to_string(),
        key: key.to_string(),
        certificate: issued.cert.name.to_string(),
        issuer: issued
            .issuer
            .as_ref()
            .map(Name::to_string)
            .unwrap_or_default(),
        valid_until: iso(issued.cert.valid_until),
        validity_secs: issued.cert.valid_until.saturating_sub(issued.cert.valid_from)
            / 1_000_000_000,
        adopted_context,
        pib: admin.pib_root.display().to_string(),
        previous_identity: previous_identity.map(|n| n.to_string()),
        signing_now,
        at_next_start,
        still_valid,
        unusable,
    }))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::Path;

    use ndn_config::{ChallengeConfig, CaTomlConfig};
    use ndn_engine::{EngineBuilder, EngineConfig, ShutdownHandle};
    use ndn_security::{Ed25519Signer, Keyring, SecurityManager};
    use ndn_trust_envelope::TrustEnvelope;

    use super::*;
    use crate::active_identity::ActiveIdentity;

    pub(crate) struct Node {
        pub(crate) admin: TrustAdmin,
        pub(crate) startup_key: Name,
        pub(crate) fingerprint: [u8; 32],
        /// The signed trust context the node holds.
        pub(crate) context_data: ndn_packet::Data,
        /// The root device's CA, on the same engine.
        pub(crate) ca: Arc<ndn_cert::CaState>,
        pub(crate) shutdown: ShutdownHandle,
    }

    /// One engine carrying the root device's CA (PIB `root_dev`, tokens `tokens`) and
    /// the enrolling node's trust-admin backend (PIB `device`, holding the root device's
    /// trust context already, signing with an ephemeral key).
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
        let mut builder = EngineBuilder::new(EngineConfig::default())
            .security_profile(ndn_security::SecurityProfile::Disabled)
            .security(Arc::new(SecurityManager::new()));
        for face in faces {
            builder = builder.face(face);
        }
        let (engine, shutdown) = builder.build().await.unwrap();
        engine.fib().add_nexthop(&ca.prefix, ca.face_id, 0);
        let ca = crate::ca::spawn(ca, &cfg, &engine).unwrap().state;

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
            admin: TrustAdmin {
                engine,
                keyring,
                pib_root: device.to_path_buf(),
                publisher: None,
                signing: Some(Arc::new(ActiveIdentity::new(startup, true))),
                own_certs: None,
                dv_keeps_startup_key: false,
                configured_identity: None,
                enrolling: tokio::sync::Mutex::new(()),
                keeping: std::sync::Mutex::new(()),
                ca: None,
                context_change: tokio::sync::Mutex::new(()),
                renewing: tokio::sync::Mutex::new(()),
                certificates_changed: tokio::sync::Notify::new(),
            },
            fingerprint,
            context_data: ndn_packet::Data::decode(persisted.init.context_data.raw().clone())
                .unwrap(),
            ca,
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
            invite_uri: TrustEnvelope::Invite {
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
        let held = node.admin.keyring.contexts().pop().unwrap();
        let older = ndn_cert::LinkAdoption {
            context: Arc::clone(&held),
            data: ndn_packet::Data::decode(node.context_data.raw().clone()).unwrap(),
            fetched: false,
        };
        // Another command adopted a newer version meanwhile.
        node.admin.keyring.adopt(Arc::new(
            ndn_security::SignedTrustContext::hierarchical(ns.clone())
                .with_version(held.version() + 1),
        ));
        let refused = node.admin.keep_adopted(&older, &node.fingerprint);
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
                .expect("enrolls");
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
                .expect("forced enrollment");
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
                .expect("enrolls");
        let ns: Name = "/home/bob".parse().unwrap();
        let pib = FilePib::open(device.path()).unwrap();
        let held = certified_in(&node.admin, &pib, &ns);
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].revoked, None, "nothing revokes a fresh certificate's chain");

        let version = node.admin.keyring.version_of(&ns).unwrap();
        for (bump, revoked) in [ndn_cert::namespace::ca_key_name(&ns), ndn_cert::namespace::root_key_name(&ns)]
            .into_iter()
            .enumerate()
        {
            node.admin.keyring.adopt(Arc::new(
                ndn_security::SignedTrustContext::hierarchical(ns.clone())
                    .with_version(version + 1 + bump as u64)
                    .with_revocation(revoked.clone()),
            ));
            let held = certified_in(&node.admin, &pib, &ns);
            assert_eq!(held[0].key.to_string(), info.key);
            assert_eq!(held[0].revoked.as_ref(), Some(&revoked), "revoking {revoked}");
        }
        node.shutdown.shutdown().await;
    }
}
