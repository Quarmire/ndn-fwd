//! Keeping held trust contexts current: `ndn-fwd context refresh [<ns>]`
//! (the `security/context-refresh` management verb) and the periodic check
//! every `[security] context_refresh_secs`.
//!
//! For each held context the daemon asks its upstream for the newest version
//! ([`ndn_identity::refresh_context_via_engine`]: RDR metadata, then the
//! signed context Data) and adopts it only if it is newer and signed by an
//! anchor of the version it holds (continuity), then stores and publishes it
//! — so the next node downstream fetches it from this one: updates travel hop
//! by hop through relays that hold the context. During the fetch the route
//! from the namespace's trust-context prefix to this node's own publisher is
//! withdrawn ([`crate::context_publisher::PublishedContexts::bypass`]), so the
//! Interests go upstream instead of being answered with the version held.
//!
//! A node holding the namespace root key (the root device) is where new
//! versions are made, so it does not fetch its own namespace. That is
//! decided from its root store's descriptor and the context's anchor public
//! keys ([`ndn_cert::RootStore::holds_anchor_of`]): the root's private key is
//! never loaded for it. A failed or
//! refused refresh is logged with its reason and changes nothing: the held
//! version stays in force, and a missed refresh only delays an update.

use std::sync::Arc;
use std::time::Duration;

use ndn_cert::{ContextRefresh, RootStore};
use ndn_mgmt::{ContextRefreshInfo, RefreshState, TrustRefusal};
use ndn_mgmt_wire::control_response::status;
use ndn_packet::Name;
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
    let _one_change = admin.context_change.lock().await;
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
            let stored = admin.keep(&update.context, &update.data);
            tracing::info!(
                target: "security",
                namespace = %namespace,
                previous = update.previous,
                version,
                signer = %update.signer.name,
                revoked = ?revoked,
                stored = stored.is_ok(),
                "adopted trust-context update"
            );
            let detail = match stored {
                Ok(path) => format!(
                    "adopted v{version} (signed by {}, an anchor of v{}); stored {} and \
                     published",
                    update.signer.name,
                    update.previous,
                    path.display()
                ),
                Err(e) => format!("adopted v{version} for this run, but {}", e.reason),
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
            info(RefreshState::Failed, held_version, Vec::new(), e.to_string())
        }
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
