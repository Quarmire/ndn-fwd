//! The root device's side of `ndn-fwd revoke <device | key | certificate>`:
//! the `security/revoke` management verb.
//!
//! The root device holds both the namespace root key (in its root store,
//! [`ndn_cert::root_store`]) and the namespace's CA, so it revokes in both
//! places:
//!
//! 1. **CA (immediate).** Every certificate the CA issued for the key is
//!    marked revoked in its store (`<pib>/ca/revoked/`, kept across
//!    restarts): the CA stops serving it, never certifies that key again, and
//!    the device name is free for a new key (one key per device name).
//! 2. **Trust context (authoritative).** Version `N+1` of the namespace's
//!    context lists the key name as revoked, signed by the root key
//!    ([`ndn_cert::bump_context_revoking`]); the daemon adopts it, stores it
//!    in `<pib>/contexts/` and publishes it by name. Every node's validator
//!    refuses a chain through a revoked key — any certificate of it, also
//!    ones issued later — once it holds that version, which other nodes
//!    fetch with their next refresh ([`crate::context_refresh`]).
//!
//! The root is unlocked for this one signature: a `sealed-file` root with
//! the passphrase, a `yubikey-piv` root with the PIN that came with the
//! command (asked by the CLI, sent over the local management socket); an
//! `os-keyring` root through the keychain. The signer is dropped (and a
//! software key zeroed) when the revocation is done.
//!
//! Nothing changes unless both are possible: a node without the root key or
//! without the namespace's CA refuses and says where to run it, and so does
//! a root that the operator did not unlock. Who may ask is decided before
//! this runs, by the management socket's peer credentials.

use std::sync::Arc;

use ndn_cert::{BumpError, CaState, RootSecret, RootStore, RootStoreError, key_name_of};
use ndn_mgmt::{RevokeRequest, RevokedInfo, TrustRefusal};
use ndn_mgmt_wire::control_response::status;
use ndn_packet::{Data, Name};
use ndn_security::{FilePib, SignedTrustContext};

use crate::context_adopt::{TrustAdmin, refusal};

fn status_of(e: &BumpError) -> u64 {
    match e {
        BumpError::NotAnAnchor { .. } => status::UNAUTHORIZED,
        BumpError::NotAKeyOfNamespace { .. } | BumpError::CoversRoot { .. } => status::BAD_PARAMS,
        _ => status::SERVER_ERROR,
    }
}

/// The status a root store that did not unlock is refused with.
fn unlock_status(e: &RootStoreError) -> u64 {
    match e {
        RootStoreError::UnlockNeeded { .. } => status::UNAUTHORIZED,
        RootStoreError::WrongPassphrase { .. } | RootStoreError::Yubikey(_) => 403,
        RootStoreError::KeychainUnavailable { .. }
        | RootStoreError::KeychainEntryMissing { .. }
        | RootStoreError::NotBuilt { .. } => 503,
        _ => status::SERVER_ERROR,
    }
}

/// The held context governing `name` (longest namespace prefix) and its
/// signed Data as stored — the version a new one is made from.
fn held_context(
    admin: &TrustAdmin,
    name: &Name,
) -> Result<(Arc<SignedTrustContext>, Data), TrustRefusal> {
    let held = admin
        .keyring
        .contexts()
        .into_iter()
        .filter(|c| name.has_prefix(c.namespace()))
        .max_by_key(|c| c.namespace().len())
        .ok_or_else(|| {
            refusal(
                status::NOT_FOUND,
                format!(
                    "this node holds no trust context for a namespace containing {name}; run \
                     `ndn-fwd revoke` on the root device of that namespace"
                ),
            )
        })?;
    let ns = held.namespace();
    let stored = ndn_cert::read_stored_context(&admin.pib_root, ns).map_err(|e| {
        refusal(
            status::SERVER_ERROR,
            format!("cannot read the stored trust context of {ns}: {e}"),
        )
    })?;
    match stored {
        Some((stored, data)) if stored.version() == held.version() => Ok((held, data)),
        Some((stored, _)) => Err(refusal(
            status::SERVER_ERROR,
            format!(
                "{ns}: this node holds v{} but its store ({}) has v{}; restart the daemon so \
                 both agree, then revoke again",
                held.version(),
                admin.pib_root.display(),
                stored.version()
            ),
        )),
        None => Err(refusal(
            status::SERVER_ERROR,
            format!(
                "{ns}: this node holds v{} but did not store it under {}; restart the daemon \
                 and revoke again",
                held.version(),
                admin.pib_root.display()
            ),
        )),
    }
}

/// This node's CA, if it is the CA of `namespace` (`<ns>/CA`).
fn namespace_ca<'a>(
    admin: &'a TrustAdmin,
    namespace: &Name,
) -> Result<&'a Arc<CaState>, TrustRefusal> {
    admin
        .ca
        .as_ref()
        .filter(|ca| ca.signing_key_name().is_some_and(|k| k.has_prefix(namespace)))
        .ok_or_else(|| {
            refusal(
                status::NOT_FOUND,
                format!(
                    "this node runs no CA for {namespace} (a [ca] section with identity \
                     {namespace}/CA): run `ndn-fwd revoke` on the root device, which holds the \
                     namespace root key and runs its CA"
                ),
            )
        })
}

/// The key names `name` designates: itself (or the key of a certificate
/// name), else every key this CA certified for the device identity `name`.
fn keys_to_revoke(ca: &CaState, name: &Name) -> Result<Vec<Name>, TrustRefusal> {
    if let Some(key) = key_name_of(name) {
        return Ok(vec![key]);
    }
    let mut keys: Vec<Name> = Vec::new();
    for (cert, _) in ca.issued_under(name) {
        let Some(key) = key_name_of(&cert) else {
            continue;
        };
        // `<identity>/KEY/<k>`: only keys of exactly this identity, not of
        // names below it.
        if key.len() == name.len() + 2 && !keys.contains(&key) {
            keys.push(key);
        }
    }
    if keys.is_empty() {
        return Err(refusal(
            status::NOT_FOUND,
            format!(
                "this node's CA issued no certificate for {name}; pass the device identity as \
                 enrolled (/<namespace>/<role>/<device>), or a key name \
                 (<identity>/KEY/<key-id>) to revoke a key this CA did not certify"
            ),
        ));
    }
    Ok(keys)
}

pub(crate) async fn revoke(
    admin: &TrustAdmin,
    request: RevokeRequest,
) -> Result<RevokedInfo, TrustRefusal> {
    let RevokeRequest { name, unlock } = request;
    // Held as the root store's secret type (zeroed on drop) from here on.
    let unlock = unlock.map(|s| RootSecret::new(s.expose().to_vec()));
    let _one_change = admin.context_change.lock().await;
    let (held, held_data) = held_context(admin, &name)?;
    let namespace = held.namespace().clone();
    let pib = FilePib::open(&admin.pib_root).map_err(|e| {
        refusal(
            status::SERVER_ERROR,
            format!("cannot open the PIB {}: {e}", admin.pib_root.display()),
        )
    })?;
    // Nothing changes anywhere unless this node holds the root of the
    // namespace (decided from its root store's descriptor, without the key)…
    let store = RootStore::open(&pib)
        .map_err(|e| refusal(status::SERVER_ERROR, e.to_string()))?
        .filter(|store| store.holds_anchor_of(&held))
        .ok_or_else(|| {
            refusal(
                status::UNAUTHORIZED,
                format!(
                    "this node does not hold the root key of {namespace}, so it cannot sign a \
                     new version of its trust context: run `ndn-fwd revoke` on the root device \
                     (where `ndn-fwd init --namespace {namespace}` ran)"
                ),
            )
        })?;
    let ca = namespace_ca(admin, &namespace)?;
    let keys = keys_to_revoke(ca, &name)?;
    if let Some(ca_key) = ca.signing_key_name()
        && keys.iter().any(|k| ca_key.has_prefix(k))
    {
        return Err(refusal(
            status::BAD_PARAMS,
            format!(
                "refusing to revoke the CA's own key {ca_key}: every device certificate of \
                 {namespace} chains to it. Replacing the CA (a compromised relay) is not built \
                 yet; revoke the devices one by one instead"
            ),
        ));
    }
    // …and the operator unlocked it for this operation.
    let signer = store
        .signer(unlock.as_ref())
        .await
        .map_err(|e| refusal(unlock_status(&e), e.to_string()))?;
    drop(unlock);
    let bump = ndn_cert::bump_context_revoking(signer.as_ref(), &held_data, &keys)
        .await
        .map_err(|e| refusal(status_of(&e), e.to_string()))?;
    drop(signer);

    // 1. CA: immediate.
    let mut ca_revoked = Vec::new();
    let mut ca_not_persisted = None;
    for key in &keys {
        let out = ca.revoke_issued_under(key);
        ca_revoked.extend(out.revoked.iter().map(Name::to_string));
        if let Some(e) = out.not_persisted {
            ca_not_persisted.get_or_insert(e.to_string());
        }
    }

    // 2. Trust context: adopt, store, publish the new version.
    let previous_version = held.version();
    let (version, stored) = match bump {
        Some(bump) => {
            let context = Arc::new(bump.context);
            admin
                .keyring
                .adopt_update(Arc::clone(&context))
                .map_err(|now| {
                    refusal(
                        409,
                        format!(
                            "{namespace} changed meanwhile (now v{}); revoke again",
                            now.unwrap_or_default()
                        ),
                    )
                })?;
            let stored = admin.keep(&context, &bump.data)?;
            (context.version(), Some(stored.display().to_string()))
        }
        // Every key was already revoked by the held version.
        None => (previous_version, None),
    };
    tracing::info!(
        target: "security",
        namespace = %namespace,
        keys = ?keys.iter().map(Name::to_string).collect::<Vec<_>>(),
        ca_revoked = ca_revoked.len(),
        previous_version,
        version,
        root_store = %store.kind(),
        "revoked"
    );
    Ok(RevokedInfo {
        namespace: namespace.to_string(),
        keys: keys.iter().map(Name::to_string).collect(),
        ca_revoked,
        ca_not_persisted,
        previous_version,
        version,
        stored,
        published: admin.publisher.is_some(),
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use ndn_mgmt::EnrollOutcome;
    use ndn_security::Keyring;

    use super::*;
    use crate::enroll::tests::{Node, node, request};

    /// The root device's backend on `node`'s engine: the root key's PIB
    /// `root_dev`, its stored context, and (`with_ca`) its CA.
    fn root_admin(node: &Node, root_dev: &Path, with_ca: bool) -> TrustAdmin {
        let keyring = Arc::new(Keyring::new());
        ndn_cert::load_persisted_contexts(root_dev, &keyring).unwrap();
        TrustAdmin {
            engine: node.admin.engine.clone(),
            keyring,
            pib_root: root_dev.to_path_buf(),
            publisher: None,
            signing: None,
            own_certs: None,
            dv_keeps_startup_key: false,
            configured_identity: None,
            enrolling: tokio::sync::Mutex::new(()),
            keeping: std::sync::Mutex::new(()),
            ca: with_ca.then(|| Arc::clone(&node.ca)),
            context_change: tokio::sync::Mutex::new(()),
            renewing: tokio::sync::Mutex::new(()),
            certificates_changed: tokio::sync::Notify::new(),
        }
    }

    /// A revocation of `name` carrying `unlock` as its root unlock.
    fn req(name: &Name, unlock: Option<&str>) -> RevokeRequest {
        RevokeRequest {
            name: name.clone(),
            unlock: unlock.map(|s| ndn_mgmt_wire::UnlockSecret::new(s.as_bytes().to_vec())),
        }
    }

    /// Revoking an enrolled device on the root device: the CA stops serving
    /// its certificate at once, and version 2 of the context — signed by the
    /// root, stored, held — revokes the key (every certificate of it). A node
    /// without the root key or without the CA changes nothing, and the root
    /// and CA keys are never revoked this way.
    #[tokio::test]
    async fn revoke_on_the_root_device_revokes_at_the_ca_and_in_a_new_context_version() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-a"]).await;
        let ns: Name = "/home/bob".parse().unwrap();
        let EnrollOutcome::Enrolled(enrolled) =
            crate::enroll::enroll(&node.admin, request(&node, "member", "member-a", "phone", false))
                .await
                .unwrap();
        let key: Name = enrolled.key.parse().unwrap();
        let identity: Name = enrolled.identity.parse().unwrap();

        // The device itself holds the context but not the root key.
        let held = node.admin.keyring.contexts().pop().unwrap();
        ndn_cert::persist_context(device.path(), &held, &node.context_data).unwrap();
        let refused = revoke(&node.admin, req(&identity, None)).await.unwrap_err();
        assert_eq!(refused.status_code, status::UNAUTHORIZED, "{}", refused.reason);
        assert!(refused.reason.contains("root device"), "{}", refused.reason);

        // The root key without the namespace's CA: refused, nothing changes.
        let no_ca = root_admin(&node, root_dev.path(), false);
        let refused = revoke(&no_ca, req(&identity, None)).await.unwrap_err();
        assert_eq!(refused.status_code, status::NOT_FOUND, "{}", refused.reason);
        assert_eq!(no_ca.keyring.version_of(&ns), Some(1));
        assert!(node.ca.get_served_cert(&enrolled.certificate).is_some());

        let root = root_admin(&node, root_dev.path(), true);
        let info = revoke(&root, req(&identity, None)).await.unwrap();
        assert_eq!(info.keys, [key.to_string()]);
        assert_eq!(info.ca_revoked, [enrolled.certificate.clone()]);
        assert_eq!((info.previous_version, info.version), (1, 2));
        assert!(info.ca_not_persisted.is_none());
        assert!(node.ca.get_served_cert(&enrolled.certificate).is_none(), "CA stops serving it");
        let now = root.keyring.contexts().pop().unwrap();
        assert_eq!(now.version(), 2);
        assert!(now.is_revoked(&key));
        assert!(
            now.is_revoked(&key.clone().append("NDNCERT").append_version(9)),
            "every certificate of the key, also one issued later"
        );
        assert!(!now.is_revoked(&"/home/bob/member/tablet/KEY/k".parse().unwrap()));
        let (stored, _) = ndn_cert::read_stored_context(root_dev.path(), &ns).unwrap().unwrap();
        assert_eq!(stored.version(), 2, "stored: a restart loads v2");

        // Already revoked: no new version.
        let again = revoke(&root, req(&key, None)).await.unwrap();
        assert_eq!((again.previous_version, again.version), (2, 2));
        assert!(again.ca_revoked.is_empty() && again.stored.is_none());

        // Never the root or the CA key.
        for name in ["/home/bob/KEY/root", "/home/bob/CA/KEY/ca", "/home/bob/CA"] {
            let refused = revoke(&root, req(&name.parse().unwrap(), None)).await.unwrap_err();
            assert_ne!(refused.status_code, 200, "{name}");
        }
        assert_eq!(root.keyring.version_of(&ns), Some(2));
        node.shutdown.shutdown().await;
    }

    /// With the root sealed by a passphrase, a revocation without it or with
    /// a wrong one is refused and changes nothing — not at the CA, not in
    /// the context; with it, the root signs v2.
    #[tokio::test]
    async fn a_sealed_root_revokes_only_with_its_passphrase() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-a"]).await;
        let ns: Name = "/home/bob".parse().unwrap();
        let EnrollOutcome::Enrolled(enrolled) =
            crate::enroll::enroll(&node.admin, request(&node, "member", "member-a", "phone", false))
                .await
                .unwrap();
        let identity: Name = enrolled.identity.parse().unwrap();
        let pib = FilePib::open(root_dev.path()).unwrap();
        let passphrase = ndn_cert::RootSecret::new(b"sealed".to_vec());
        RootStore::open(&pib)
            .unwrap()
            .unwrap()
            .move_to(&pib, ndn_cert::RootStoreKind::SealedFile, None, Some(&passphrase))
            .await
            .unwrap();

        let root = root_admin(&node, root_dev.path(), true);
        for (unlock, code) in [(None, status::UNAUTHORIZED), (Some("wrong"), 403)] {
            let refused = revoke(&root, req(&identity, unlock)).await.unwrap_err();
            assert_eq!(refused.status_code, code, "{}", refused.reason);
            assert_eq!(root.keyring.version_of(&ns), Some(1));
            assert!(node.ca.get_served_cert(&enrolled.certificate).is_some());
        }
        let info = revoke(&root, req(&identity, Some("sealed"))).await.unwrap();
        assert_eq!((info.previous_version, info.version), (1, 2));
        assert!(node.ca.get_served_cert(&enrolled.certificate).is_none());
        node.shutdown.shutdown().await;
    }
}
