//! Keeping held trust contexts current: `ndn-fwd context refresh [<ns>]`
//! (the `security/context-refresh` management verb) and the periodic check
//! every `[security] context_refresh_secs`.
//!
//! For each held context the daemon asks its upstream for the newest version
//! ([`ndn_identity::refresh_context_via_engine`]: RDR metadata, then the
//! signed context Data) and adopts it only if it is newer and signed by an
//! anchor of the version it holds (continuity), then stores and publishes it
//! — so the next node downstream fetches it from this one: updates travel hop
//! by hop through relays that hold the context. When the newest is not
//! signed by an anchor of the held version (a recovery kit installed a new
//! root in a version this node missed), the versions in between are fetched
//! by exact name and followed one by one ([`ndn_cert::follow_versions`]);
//! they are stored and published too, so the nodes behind this one follow
//! the same way. During the fetch the route from the namespace's
//! trust-context prefix to this node's own publisher is withdrawn
//! ([`crate::context_publisher::PublishedContexts::bypass`]), so the
//! Interests go upstream instead of being answered with the versions held.
//!
//! A node holding the namespace root key (the root device) is where new
//! versions are made, so it does not fetch its own namespace. That is
//! decided from its root store's descriptor and the context's anchor public
//! keys ([`ndn_cert::RootStore::holds_anchor_of`]): the root's private key is
//! never loaded for it. A failed or
//! refused refresh is logged with its reason and changes nothing: the held
//! version stays in force, and a missed refresh only delays an update.
//!
//! A version made on this device by a CLI that signs offline — `ndn-fwd
//! recovery-kit` on the root device, `ndn-fwd recover` on a replacement — is
//! handed over with `security/context-update` ([`apply_update`]) and adopted
//! under the same continuity rule as a fetched one.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_cert::{ContextRefresh, RootStore};
use ndn_mgmt::{ContextRefreshInfo, RefreshState, TrustRefusal};
use ndn_mgmt_wire::control_response::status;
use ndn_packet::{Data, Name};
use ndn_security::{FilePib, SignedTrustContext};
use tokio_util::sync::CancellationToken;

use crate::context_adopt::{TrustAdmin, refusal};

/// The first periodic check runs this soon after start (or after one period,
/// if shorter), so a node that was off catches up without waiting a period.
const FIRST_CHECK_AFTER: Duration = Duration::from_secs(30);

/// Whether this node is the root device of `ctx`'s namespace — its root
/// store holds the key of one of `ctx`'s anchors — which makes new versions
/// rather than fetching them. Public keys only; the root stays locked.
fn holds_root_key(admin: &TrustAdmin, ctx: &SignedTrustContext) -> bool {
    let Ok(pib) = FilePib::open(&admin.pib_root) else {
        return false;
    };
    RootStore::open(&pib)
        .ok()
        .flatten()
        .is_some_and(|store| store.holds_anchor_of(ctx))
}

pub(crate) async fn refresh_contexts(
    admin: &TrustAdmin,
    namespace: Option<Name>,
) -> Result<Vec<ContextRefreshInfo>, TrustRefusal> {
    let held = admin.keyring.contexts();
    let targets = match namespace {
        Some(ns) => vec![held.into_iter().find(|c| *c.namespace() == ns).ok_or_else(|| {
            refusal(
                status::NOT_FOUND,
                format!("this node holds no trust context for {ns}; adopt it first (`ndn-fwd adopt`)"),
            )
        })?],
        None => held,
    };
    // No lock across the fetches (a catch-up walk may take many round
    // trips): `ndn_cert::refresh_context` adopts only if the version it
    // checked against is still held (`Keyring::adopt_update_from`), so a
    // version a revocation or hand-over adopts meanwhile is never skipped.
    let mut results = Vec::with_capacity(targets.len());
    for ctx in targets {
        results.push(refresh_one(admin, &ctx).await);
    }
    Ok(results)
}

async fn refresh_one(admin: &TrustAdmin, held: &SignedTrustContext) -> ContextRefreshInfo {
    let namespace = held.namespace().clone();
    let held_version = admin.keyring.version_of(&namespace).unwrap_or(held.version());
    let info = |state, version, revoked: Vec<String>, detail: String| ContextRefreshInfo {
        namespace: namespace.to_string(),
        state,
        held_version,
        version,
        revoked,
        detail,
    };
    if holds_root_key(admin, held) {
        return info(
            RefreshState::Source,
            held_version,
            Vec::new(),
            "this node holds the namespace root key: new versions are made here".into(),
        );
    }

    let bypass = admin.publisher.as_ref().map(|p| p.bypass(&namespace));
    let result =
        ndn_identity::refresh_context_via_engine(&admin.engine, &admin.keyring, &namespace).await;
    drop(bypass);

    match result {
        Ok(ContextRefresh::Current { version }) => {
            tracing::debug!(target: "security", namespace = %namespace, version, "trust context is current");
            info(
                RefreshState::Current,
                version,
                Vec::new(),
                format!("the namespace serves v{version}, the version held"),
            )
        }
        Ok(ContextRefresh::UpstreamOlder { held, offered }) => {
            tracing::info!(
                target: "security",
                namespace = %namespace,
                held,
                offered,
                "upstream serves an older trust context; keeping the held one"
            );
            info(
                RefreshState::UpstreamOlder,
                held,
                Vec::new(),
                format!(
                    "the forwarder that answered serves v{offered}, older than the held v{held} \
                     (it has not refreshed yet); nothing changed"
                ),
            )
        }
        Ok(ContextRefresh::Updated(update)) => {
            let version = update.context.version();
            let revoked: Vec<String> = update.revoked.iter().map(Name::to_string).collect();
            // Kept by name for the nodes behind this one; a failure to store
            // one is logged and does not undo the adoption.
            for step in &update.walked {
                if let Err(e) = admin.keep_walked(&step.context, &step.data) {
                    tracing::warn!(
                        target: "security",
                        namespace = %namespace,
                        version = step.context.version(),
                        error = %e.reason,
                        "could not keep a trust-context version walked through"
                    );
                }
            }
            let stored = admin.keep(&update.context, &update.data);
            let walked: Vec<u64> = update.walked.iter().map(|s| s.context.version()).collect();
            tracing::info!(
                target: "security",
                namespace = %namespace,
                previous = update.previous,
                version,
                walked = ?walked,
                signer = %update.signer.name,
                revoked = ?revoked,
                stored = stored.is_ok(),
                "adopted trust-context update"
            );
            let through = match walked.as_slice() {
                [] => String::new(),
                walked => format!(
                    " through {} (each signed by an anchor of the version before it)",
                    walked
                        .iter()
                        .map(|v| format!("v{v}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            };
            let from = walked.last().copied().unwrap_or(update.previous);
            let detail = match stored {
                Ok(path) => format!(
                    "adopted v{version} (signed by {}, an anchor of v{from}){through}; stored {}{}",
                    update.signer.name,
                    path.display(),
                    publication(admin)
                ),
                Err(e) => format!("adopted v{version}{through} for this run, but {}", e.reason),
            };
            info(RefreshState::Updated, version, revoked, detail)
        }
        Err(e) => {
            tracing::warn!(
                target: "security",
                namespace = %namespace,
                error = %e,
                "trust-context refresh failed"
            );
            let state = match e {
                ndn_cert::RefreshError::NoAnswer { .. } => RefreshState::Unreachable,
                _ => RefreshState::Failed,
            };
            info(state, held_version, Vec::new(), e.to_string())
        }
    }
}

/// `security/context-update`: adopt `wire` (a signed trust-context Data) as
/// the next version of the context this node holds for its namespace — only
/// if it is strictly newer and signed by an anchor of the held version, as a
/// refresh requires — then store it and (with `[security] serve_contexts`)
/// publish it.
///
/// The answer says what became of the version, so a CLI may undo its own
/// work only on a refusal: `200` once it is adopted (even if storing it then
/// failed — the detail says so), and `200` for a version this node already
/// took and stores byte for byte, so a CLI that got no answer can hand the
/// same version over again and learn the outcome (the second request waits
/// for the first, behind `context_change`). Any other answer means it was
/// not adopted.
pub(crate) async fn apply_update(
    admin: &TrustAdmin,
    wire: Bytes,
) -> Result<ContextRefreshInfo, TrustRefusal> {
    let data = Data::decode(wire)
        .map_err(|e| refusal(status::BAD_PARAMS, format!("not a Data packet: {e}")))?;
    let namespace = ndn_security::context_namespace_of(&data.name).ok_or_else(|| {
        refusal(
            status::BAD_PARAMS,
            format!("{} is not a trust-context name (<ns>/32=trust-context/v=<N>)", data.name),
        )
    })?;
    let _one_change = admin.context_change.lock().await;
    let held = admin
        .keyring
        .contexts()
        .into_iter()
        .find(|c| *c.namespace() == namespace)
        .ok_or_else(|| {
            refusal(
                status::NOT_FOUND,
                format!(
                    "this node holds no trust context for {namespace}; adopt it first (`ndn-fwd \
                     adopt`)"
                ),
            )
        })?;
    if let Some((version, path)) = stored_copy(admin, &held, &data) {
        return Ok(ContextRefreshInfo {
            namespace: namespace.to_string(),
            state: RefreshState::Current,
            held_version: held.version(),
            version,
            revoked: Vec::new(),
            detail: format!(
                "already took v{version} (holds v{}); stored {}",
                held.version(),
                path.display()
            ),
        });
    }
    let (ctx, signer) = ndn_cert::open_context_update(&held, &data)
        .await
        .map_err(|e| {
            refusal(
                403,
                format!(
                    "refused a trust-context update for {namespace}: {e}; the held version v{} \
                     stays in force",
                    held.version()
                ),
            )
        })?;
    let context = Arc::new(ctx);
    admin
        .keyring
        .adopt_update_from(&held, Arc::clone(&context))
        .map_err(|now| {
            refusal(
                409,
                format!(
                    "{namespace} changed meanwhile (now v{}); make the new version again",
                    now.unwrap_or_default()
                ),
            )
        })?;
    let kept = admin.keep(&context, &data);
    let revoked: Vec<String> = context
        .revocations()
        .iter()
        .filter(|r| !held.revocations().contains(r))
        .map(Name::to_string)
        .collect();
    tracing::info!(
        target: "security",
        namespace = %namespace,
        previous = held.version(),
        version = context.version(),
        signer = %signer.name,
        revoked = ?revoked,
        stored = kept.is_ok(),
        "adopted trust-context version made on this device"
    );
    let adopted = format!(
        "adopted v{} (signed by {}, an anchor of v{})",
        context.version(),
        signer.name,
        held.version()
    );
    Ok(ContextRefreshInfo {
        namespace: namespace.to_string(),
        state: RefreshState::Updated,
        held_version: held.version(),
        version: context.version(),
        revoked,
        detail: match kept {
            Ok(stored) => format!("{adopted}; stored {}{}", stored.display(), publication(admin)),
            Err(e) => format!("{adopted}, but {}", e.reason),
        },
    })
}

/// The version `data` carries and where this node stores it, when it is no
/// newer than `held` and stored exactly (a version this node already took).
fn stored_copy(
    admin: &TrustAdmin,
    held: &SignedTrustContext,
    data: &Data,
) -> Option<(u64, std::path::PathBuf)> {
    let version = data
        .name
        .components()
        .last()
        .and_then(ndn_packet::NameComponent::as_version)?;
    if version > held.version() {
        return None;
    }
    ndn_cert::read_stored_versions(&admin.pib_root, held.namespace())
        .ok()?
        .into_iter()
        .find_map(|(path, read)| {
            let (_, stored) = read.ok()?;
            (stored.raw() == data.raw()).then_some((version, path))
        })
}

/// Whether a version this node keeps is published ([`TrustAdmin::keep`]
/// publishes only with `[security] serve_contexts`), worded for a detail.
fn publication(admin: &TrustAdmin) -> &'static str {
    if admin.publisher.is_some() {
        " and published"
    } else {
        "; not published: [security] serve_contexts = false, so no node fetches it from this one"
    }
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
    let period = Duration::from_secs(period_secs);
    tracing::info!(target: "security", period_secs, "refreshing held trust contexts periodically");
    tokio::spawn(async move {
        let mut wait = period.min(FIRST_CHECK_AFTER);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(wait) => {}
            }
            wait = period;
            if admin.keyring.is_empty() {
                continue;
            }
            // Each namespace's outcome is logged by `refresh_one`.
            if let Err(e) = refresh_contexts(&admin, None).await {
                tracing::warn!(target: "security", error = %e.reason, "trust-context refresh failed");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use ndn_security::Ed25519Signer;

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
        let forged = SignedTrustContext::decode_content(node.context_data.content().unwrap(), 2)
            .unwrap();
        forged.add_anchor(ndn_cert::recovery_anchor(Arc::clone(&stranger)).await.unwrap());
        let forged = forged.sign_into_data_async(stranger.as_ref()).await.unwrap();
        let refused = apply_update(&node.admin, forged.raw().clone()).await.unwrap_err();
        assert_eq!(refused.status_code, 403, "{}", refused.reason);
        assert_eq!(node.admin.keyring.version_of(&ns), Some(1));
        assert!(ndn_cert::read_stored_context(device.path(), &ns).unwrap().is_none());

        let pib = FilePib::open(root_dev.path()).unwrap();
        let root = RootStore::open(&pib).unwrap().unwrap().signer(None).await.unwrap();
        let seed = ndn_cert::RecoverySeed::generate().unwrap();
        let kit = ndn_cert::recovery_anchor(Arc::new(seed.signer(&ns))).await.unwrap();
        let bump = ndn_cert::add_recovery_anchor(root.as_ref(), &node.context_data, &kit)
            .await
            .unwrap();
        let info = apply_update(&node.admin, bump.data.raw().clone()).await.unwrap();
        assert_eq!((info.held_version, info.version), (1, 2));
        let (stored, _) = ndn_cert::read_stored_context(device.path(), &ns).unwrap().unwrap();
        assert_eq!(stored.version(), 2);
        assert!(stored.has_key_role(&kit.key_name(), ndn_security::KeyRole::RECOVERY_ANCHOR));

        // Handed over again (a CLI that got no answer asks again): taken,
        // never refused — a refusal would make the CLI undo what this node
        // holds. Another v2 is still refused.
        let again = apply_update(&node.admin, bump.data.raw().clone()).await.unwrap();
        assert_eq!((info.version, again.version), (2, 2));
        let other_kit = ndn_cert::recovery_anchor(Arc::new(
            ndn_cert::RecoverySeed::generate().unwrap().signer(&ns),
        ))
        .await
        .unwrap();
        let other = ndn_cert::add_recovery_anchor(root.as_ref(), &node.context_data, &other_kit)
            .await
            .unwrap();
        let refused = apply_update(&node.admin, other.data.raw().clone()).await.unwrap_err();
        assert_eq!(refused.status_code, 403, "{}", refused.reason);
        assert_eq!(node.admin.keyring.version_of(&ns), Some(2));
        let (stored, data) = ndn_cert::read_stored_context(device.path(), &ns).unwrap().unwrap();
        assert!(stored.has_key_role(&kit.key_name(), ndn_security::KeyRole::RECOVERY_ANCHOR));
        assert_eq!(data.raw(), bump.data.raw());
        node.shutdown.shutdown().await;
    }

    /// A node offline across a recovery catches up through the daemon's
    /// refresh: it holds v2; an upstream node that kept every version serves
    /// v3 (signed by the recovery key) and v4 (the new root's, newest). v4
    /// alone does not follow from v2, so the daemon follows v3 then v4 by
    /// exact name, adopts v4, and keeps both, so the nodes behind it can
    /// follow the same way.
    #[tokio::test]
    async fn a_refresh_follows_a_recovery_and_keeps_every_version_it_walked() {
        use ndn_engine::{EngineBuilder, EngineConfig};
        use ndn_security::{Keyring, SecurityManager};

        let dirs: Vec<_> = (0..4).map(|_| tempfile::tempdir().unwrap()).collect();
        let (root_dev, replacement, upstream, device) =
            (dirs[0].path(), dirs[1].path(), dirs[2].path(), dirs[3].path());
        let ns: Name = "/home/bob".parse().unwrap();

        let pib = FilePib::new(root_dev).unwrap();
        let init =
            ndn_cert::init_namespace_in_pib(&pib, &ns, "desk", false, &ndn_cert::NewRootStore::File)
                .await
                .unwrap();
        let root = RootStore::open(&pib).unwrap().unwrap().signer(None).await.unwrap();
        let seed = ndn_cert::RecoverySeed::generate().unwrap();
        let kit = ndn_cert::recovery_anchor(Arc::new(seed.signer(&ns))).await.unwrap();
        let v2 = ndn_cert::add_recovery_anchor(root.as_ref(), &init.init.context_data, &kit)
            .await
            .unwrap();
        let recovered = ndn_cert::recover_namespace_in_pib(
            &FilePib::new(replacement).unwrap(),
            &v2.data,
            &seed.signer(&ns),
            "phone",
            ndn_cert::OldRoot::Destroyed,
            &[],
            &ndn_cert::NewRootStore::File,
        )
        .await
        .unwrap();
        for bump in [&v2, &recovered.version.bump, &recovered.root_version] {
            ndn_cert::persist_context(upstream, &bump.context, &bump.data).unwrap();
        }

        let (face, publisher) = crate::context_publisher::prepare(upstream);
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .security_profile(ndn_security::SecurityProfile::Disabled)
            .security(Arc::new(SecurityManager::new()))
            .face(face)
            .build()
            .await
            .unwrap();
        let _serving = publisher.spawn(&engine);
        let keyring = Arc::new(Keyring::new());
        assert!(keyring.adopt(Arc::new(ndn_cert::open_signed_context(&v2.data).unwrap().0)));
        let admin = TrustAdmin {
            engine,
            keyring,
            pib_root: device.to_path_buf(),
            publisher: None,
            signing: None,
            own_certs: None,
            dv_keeps_startup_key: false,
            configured_identity: None,
            enrolling: tokio::sync::Mutex::new(()),
            keeping: std::sync::Mutex::new(()),
            ca: None,
            context_change: tokio::sync::Mutex::new(()),
            renewing: tokio::sync::Mutex::new(()),
            certificates_changed: tokio::sync::Notify::new(),
        };

        let results = refresh_contexts(&admin, Some(ns.clone())).await.unwrap();
        assert_eq!(results[0].state, RefreshState::Updated, "{}", results[0].detail);
        assert_eq!((results[0].held_version, results[0].version), (2, 4));
        assert_eq!(admin.keyring.version_of(&ns), Some(4));
        let (newest, _) = ndn_cert::read_stored_context(device, &ns).unwrap().unwrap();
        assert_eq!(newest.version(), 4);
        let kept: Vec<u64> = ndn_cert::read_stored_versions(device, &ns)
            .unwrap()
            .into_iter()
            .map(|(_, stored)| stored.unwrap().0.version())
            .collect();
        assert_eq!(kept, [3, 4]);
        shutdown.shutdown().await;
    }

    /// A node that reaches nobody serving its namespace (the recovering
    /// device after the root device is gone) reports `unreachable`, not a
    /// refusal, keeping the held version: `ndn-fwd recover --from-held` may
    /// go on from there, never from a version that answered and was refused.
    #[tokio::test]
    async fn a_refresh_nobody_answers_is_unreachable_not_refused() {
        use ndn_engine::{EngineBuilder, EngineConfig};
        use ndn_security::{Keyring, SecurityManager};

        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let ns: Name = "/home/bob".parse().unwrap();
        let init = ndn_cert::init_namespace_in_pib(
            &FilePib::new(root_dev.path()).unwrap(),
            &ns,
            "desk",
            false,
            &ndn_cert::NewRootStore::File,
        )
        .await
        .unwrap();
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .security_profile(ndn_security::SecurityProfile::Disabled)
            .security(Arc::new(SecurityManager::new()))
            .build()
            .await
            .unwrap();
        let keyring = Arc::new(Keyring::new());
        let held = ndn_cert::open_signed_context(&init.init.context_data).unwrap().0;
        assert!(keyring.adopt(Arc::new(held)));
        let admin = TrustAdmin {
            engine,
            keyring,
            pib_root: device.path().to_path_buf(),
            publisher: None,
            signing: None,
            own_certs: None,
            dv_keeps_startup_key: false,
            configured_identity: None,
            enrolling: tokio::sync::Mutex::new(()),
            keeping: std::sync::Mutex::new(()),
            ca: None,
            context_change: tokio::sync::Mutex::new(()),
            renewing: tokio::sync::Mutex::new(()),
            certificates_changed: tokio::sync::Notify::new(),
        };

        let results = refresh_contexts(&admin, Some(ns.clone())).await.unwrap();
        assert_eq!(results[0].state, RefreshState::Unreachable, "{}", results[0].detail);
        assert_eq!((results[0].held_version, results[0].version), (1, 1));
        assert_eq!(admin.keyring.version_of(&ns), Some(1));
        shutdown.shutdown().await;
    }
}
