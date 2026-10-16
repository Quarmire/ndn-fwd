//! The running daemon's side of `ndn-fwd enroll <invite>`: the
//! `security/enroll` management verb.
//!
//! The daemon owns every piece of state: it generates the device key
//! `/<ns>/<role>/<device>/KEY/<id>` in its own PIB (the private key never
//! leaves it), lets [`ndn_identity::enroll_with_invite_via_engine`] adopt the
//! namespace's trust context if it is not held and obtain a certificate from
//! the namespace's CA with the invite's token, stores the issued certificate
//! beside the key, and makes the identity the PIB's default — loaded at every
//! start unless `[security] identity` names another one (the config file is
//! never edited). The running daemon then signs its management responses,
//! discovery records and DV routing with the new key from the next packet on.
//!
//! A failed enrollment leaves the previous state: the new key (and anything
//! stored for it) is deleted and the default identity is only changed as the
//! last step, after the certificate is stored.

use std::sync::Arc;

use ndn_cert::roles::parse_device_key;
use ndn_cert::{INVITE_CERT_VALIDITY_SECS, InviteEnrollError, InviteLink, new_device_key_name};
use ndn_mgmt::{EnrollOutcome, EnrollRequest, EnrolledInfo, TrustRefusal};
use ndn_mgmt_wire::control_response::status;
use ndn_packet::Name;
use ndn_security::{FilePib, Signer};

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

fn iso(ns: u64) -> String {
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

/// Device keys in `namespace` this PIB holds a currently valid certificate
/// for: `(key, valid until)`.
fn certified_in(pib: &FilePib, namespace: &Name) -> Vec<(Name, u64)> {
    let mut held: Vec<(Name, u64)> = pib
        .list_keys()
        .unwrap_or_default()
        .into_iter()
        .filter(|k| parse_device_key(namespace, k).is_some())
        .filter_map(|k| {
            let cert = pib.get_cert(&k).ok()?;
            cert.is_valid_now().then_some((k, cert.valid_until))
        })
        .collect();
    held.sort();
    held
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
    let held = certified_in(&pib, &invite.namespace);
    if !held.is_empty() && !request.force {
        let list: Vec<String> = held
            .iter()
            .map(|(k, until)| format!("{k} (valid until {})", iso(*until)))
            .collect();
        return Err(refusal(
            409,
            format!(
                "this node already holds a certificate in {}: {}. To enroll another key anyway, \
                 run again with --force and another --device name (the CA certifies a new key \
                 for a device name it already certified only once that certificate is revoked \
                 or an admin approves the new key); the certificate this node holds stays valid \
                 until it is revoked",
                invite.namespace,
                list.join(", ")
            ),
        ));
    }

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
        INVITE_CERT_VALIDITY_SECS,
    )
    .await
    {
        Ok(enrollment) => enrollment,
        Err(failure) => {
            discard(&pib, &key);
            if let (Some(adopted), Some(fp)) = (&failure.adopted, &invite.expected_fingerprint) {
                // The context passed the fingerprint check on its own; keep
                // what the keyring already holds across a restart.
                let _ = admin.keep_adopted(adopted, fp);
            }
            tracing::warn!(
                target: "security",
                identity = %identity,
                error = %failure.error,
                "enrollment failed; nothing was kept for the new key"
            );
            return Err(refusal(status_of(&failure.error), failure.error.to_string()));
        }
    };

    let adopted_context = match (&enrollment.adopted, &invite.expected_fingerprint) {
        (Some(adopted), Some(fp)) => match admin.keep_adopted(adopted, fp) {
            Ok(info) => Some(info),
            Err(e) => {
                discard(&pib, &key);
                return Err(e);
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

    // The live daemon: the engine's key store holds the identity (so an app
    // asking the engine to sign as it can), and — unless the config pins
    // another identity — this key signs the daemon's own packets from now on.
    if let Some(mgr) = admin.engine.security() {
        mgr.register_signer(key.clone(), Arc::clone(&signer));
        mgr.cert_cache().insert(issued.cert.clone());
    }
    let mut at_next_start = Vec::new();
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
    let still_valid: Vec<String> = held
        .iter()
        .map(|(k, until)| format!("{k} (valid until {})", iso(*until)))
        .collect();

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
        requested_validity_secs: INVITE_CERT_VALIDITY_SECS,
        adopted_context,
        pib: admin.pib_root.display().to_string(),
        previous_identity: previous_identity.map(|n| n.to_string()),
        signing_now,
        at_next_start,
        still_valid,
    }))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use ndn_config::{ChallengeConfig, DemoCaConfig};
    use ndn_engine::{EngineBuilder, EngineConfig, ShutdownHandle};
    use ndn_security::{Ed25519Signer, Keyring, SecurityManager};
    use ndn_trust_envelope::TrustEnvelope;

    use super::*;
    use crate::active_identity::ActiveIdentity;

    struct Node {
        admin: TrustAdmin,
        startup_key: Name,
        fingerprint: [u8; 32],
        shutdown: ShutdownHandle,
    }

    /// One engine carrying the hub's CA (PIB `hub`, tokens `tokens`) and the
    /// enrolling node's trust-admin backend (PIB `device`, holding the hub's
    /// trust context already, signing with an ephemeral key).
    async fn node(hub: &Path, device: &Path, tokens: &[&str]) -> Node {
        let ns: Name = "/home/bob".parse().unwrap();
        let pib = FilePib::new(hub).unwrap();
        let persisted = ndn_cert::init_hub_in_pib(&pib, &ns, "desk", false).unwrap();
        let cfg = DemoCaConfig {
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
            ..DemoCaConfig::default()
        };
        let (faces, ca) = crate::demo_ca::prepare(&cfg, hub).await.unwrap();
        let mut builder = EngineBuilder::new(EngineConfig::default())
            .security_profile(ndn_security::SecurityProfile::Disabled)
            .security(Arc::new(SecurityManager::new()));
        for face in faces {
            builder = builder.face(face);
        }
        let (engine, shutdown) = builder.build().await.unwrap();
        engine.fib().add_nexthop(&ca.prefix, ca.face_id, 0);
        crate::demo_ca::spawn(ca, &cfg, &engine).unwrap();

        let keyring = Arc::new(Keyring::new());
        let fingerprint = ndn_cert::anchor_fingerprint(&persisted.hub.anchor);
        ndn_cert::adopt_with_tofu(&keyring, &persisted.hub.context_data, &ns, &fingerprint)
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
                configured_identity: None,
                enrolling: tokio::sync::Mutex::new(()),
            },
            fingerprint,
            shutdown,
        }
    }

    fn request(node: &Node, role: &str, token: &str, device: &str, force: bool) -> EnrollRequest {
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
        let (hub, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(hub.path(), device.path(), &["member-m1"]).await;
        assert_eq!(state(&node), (vec![], None, node.startup_key.clone()));

        let EnrollOutcome::Enrolled(info) =
            enroll(&node.admin, request(&node, "member", "member-m1", "laptop", false))
                .await
                .expect("enrolls");
        let key: Name = info.key.parse().unwrap();
        let identity: Name = "/home/bob/member/laptop".parse().unwrap();
        assert!(key.has_prefix(&identity));
        assert_eq!(info.issuer, "/home/bob/CA/KEY/ca");
        assert!(info.signing_now);

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
        let (hub, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(hub.path(), device.path(), &["member-m1", "member-m2", "guest-g1"]).await;
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
}
