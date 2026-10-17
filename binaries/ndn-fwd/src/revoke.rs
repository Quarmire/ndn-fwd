//! `ndn-fwd revoke <device | key | certificate>` on the root device, and how
//! a namespace CA follows the revocations of its trust context.
//!
//! **The revocation is a new version of the trust context.** The CLI opens
//! the root store of the root device's PIB (the PIB of the daemon it hands
//! the version to, [`crate::recovery_kit::ensure_daemon_pib`]) and checks,
//! before asking for anything, that this is the root device, which keys the
//! name designates (a key or certificate name: its key; a device identity:
//! every key the namespace CA certified for it, read from the CA store in
//! the PIB), that none is the root's or the CA's, and that the held version
//! does not revoke them all already. Only then is the root unlocked — a
//! `sealed-file` root with its passphrase, a `yubikey-piv` root with its PIN,
//! asked here; an `os-keyring` root through the keychain — to sign version
//! `N+1`, which lists the keys as revoked ([`ndn_cert::bump_context_revoking`]).
//! The signer is dropped (a software key zeroed) right after. The secret
//! never leaves the CLI: the daemon receives only the signed version
//! (`security/context-update`), which it adopts under the continuity rule,
//! stores and publishes ([`crate::recovery_kit::hand_over`]); with no daemon
//! listening it is stored for the daemon's next start. Every node's validator
//! refuses a chain through a revoked key — any certificate of it, also ones
//! issued later — once it holds that version, which other nodes fetch with
//! their next refresh ([`crate::context_refresh`]).
//!
//! **The CA follows the signed version** ([`ca_follow`]), never a separate
//! request: whenever the daemon keeps a version of its namespace's context —
//! handed over, refreshed, adopted by link ([`TrustAdmin::keep`]) — and when
//! its CA starts ([`ca_follow_held`]), the CA stops serving every certificate
//! it issued that the version revokes, records that in its store
//! (`<pib>/ca/revoked/`), never certifies such a key again, and the device
//! name the key held is free for a new key (one key per device name).
//!
//! [`TrustAdmin::keep`]: crate::context_adopt::TrustAdmin::keep

use std::path::Path;

use anyhow::{Context, Result, bail};
use ndn_cert::namespace::CA_DIR;
use ndn_cert::{CaRevocation, CaState, CaStore, FileCaStore, RootStore, key_name_of};
use ndn_packet::{Data, Name};
use ndn_security::{FilePib, Keyring, SignedTrustContext};

use crate::onboard::{face_socket, pib_dir, positionals};
use crate::recovery_kit::{NotTaken, ensure_daemon_pib, hand_over, root_device};

/// Make `ca` follow `ctx`, a version of a trust context this node holds now:
/// when `ca` is the CA of its namespace (identity `<ns>/CA`), it stops
/// serving every certificate it issued that `ctx` revokes, and records that
/// in its store. Idempotent: certificates revoked already are skipped, so
/// following the same version again changes nothing. `None` when `ca` is not
/// the CA of `ctx`'s namespace.
pub(crate) fn ca_follow(ca: &CaState, ctx: &SignedTrustContext) -> Option<CaRevocation> {
    let ca_identity = ctx.namespace().clone().append("CA");
    let key = ca.signing_key_name()?;
    if !(key.has_prefix(&ca_identity) && key.len() == ca_identity.len() + 2) {
        return None;
    }
    let mut followed = CaRevocation::default();
    for revoked in ctx.revocations() {
        let out = ca.revoke_issued_under(revoked);
        followed.revoked.extend(out.revoked);
        if followed.not_persisted.is_none() {
            followed.not_persisted = out.not_persisted;
        }
    }
    if !followed.revoked.is_empty() {
        tracing::info!(
            target: "ca",
            namespace = %ctx.namespace(),
            version = ctx.version(),
            revoked = ?followed.revoked.iter().map(Name::to_string).collect::<Vec<_>>(),
            "the trust context revokes certificates this CA issued: no longer served, and \
             their device names are free for a new key"
        );
    }
    if let Some(e) = &followed.not_persisted {
        tracing::warn!(
            target: "ca",
            namespace = %ctx.namespace(),
            version = ctx.version(),
            error = %e,
            "could not record a revocation in the CA store: it holds for this run, and the CA \
             follows the stored trust context again at the next start"
        );
    }
    Some(followed)
}

/// Make `ca` follow every trust context `keyring` holds ([`ca_follow`]): at
/// the CA's start, for versions adopted while it did not run — one stored
/// for the next start by a CLI that found no daemon, or a revocation its
/// store could not record.
pub(crate) fn ca_follow_held(ca: &CaState, keyring: &Keyring) {
    for ctx in keyring.contexts() {
        ca_follow(ca, &ctx);
    }
}

/// The key names `name` designates: itself (or the key of a certificate
/// name), else every key the namespace CA of the PIB `pib_dir` certified for
/// the device identity `name`.
fn keys_to_revoke(pib_dir: &Path, name: &Name) -> Result<Vec<Name>> {
    if let Some(key) = key_name_of(name) {
        return Ok(vec![key]);
    }
    let ca_dir = pib_dir.join(CA_DIR);
    let issued = if ca_dir.is_dir() {
        FileCaStore::open(&ca_dir)
            .and_then(|store| store.load())
            .with_context(|| format!("read the CA store {}", ca_dir.display()))?
            .issued
    } else {
        Vec::new()
    };
    let mut keys: Vec<Name> = Vec::new();
    for (cert, _) in issued {
        let Some(key) = cert.parse::<Name>().ok().as_ref().and_then(key_name_of) else {
            continue;
        };
        // `<identity>/KEY/<k>`: only keys of exactly this identity, not of
        // names below it.
        if key.has_prefix(name) && key.len() == name.len() + 2 && !keys.contains(&key) {
            keys.push(key);
        }
    }
    if keys.is_empty() {
        bail!(
            "the namespace CA of {} issued no certificate for {name}, so there is no key to \
             revoke under that name; pass the device identity as enrolled \
             (/<namespace>/<role>/<device>), or a key name (<identity>/KEY/<key-id>) to revoke \
             a key this CA did not certify. Nothing was signed",
            pib_dir.display()
        );
    }
    Ok(keys)
}

/// What `ndn-fwd revoke` signs, decided before the root is unlocked.
struct Plan {
    store: RootStore,
    held: SignedTrustContext,
    held_data: Data,
    /// The key names the command names.
    keys: Vec<Name>,
    /// Those the held version does not revoke yet; empty when it revokes all.
    adding: Vec<Name>,
}

/// Every check that needs no key: this PIB is the root device of the
/// namespace containing `name`, and `name` designates keys that may be
/// revoked — never the root's (every key chains to it) nor the CA's.
fn plan(pib_dir: &Path, name: &Name) -> Result<Plan> {
    let pib =
        FilePib::open(pib_dir).with_context(|| format!("open PIB at {}", pib_dir.display()))?;
    let (store, held, held_data) = root_device(&pib, pib_dir, "devices are revoked")?;
    let namespace = held.namespace().clone();
    if !name.has_prefix(&namespace) {
        bail!(
            "{name} is not in {namespace}, the namespace whose root this device holds; nothing \
             was signed"
        );
    }
    let ca_identity = namespace.clone().append("CA");
    if name.has_prefix(&ca_identity) {
        bail!(
            "refusing to revoke {name}: it is the namespace CA, and every device certificate of \
             {namespace} chains to it. Replacing the CA (a compromised relay) is not built yet; \
             revoke the devices one by one instead. Nothing was signed"
        );
    }
    let keys = keys_to_revoke(pib_dir, name)?;
    let adding = ndn_cert::revocations_to_add(&held, &keys)
        .map_err(|e| anyhow::anyhow!("{e}; nothing was signed"))?;
    Ok(Plan {
        store,
        held,
        held_data,
        keys,
        adding,
    })
}

/// Before the root is unlocked: refuse when the daemon listening on the
/// socket uses another PIB (it must not take a version made from this one).
/// No daemon listening is no refusal: the version is stored for its next
/// start.
async fn check_daemon(args: &[String], pib_dir: &Path) -> Result<()> {
    let socket = face_socket(args)?;
    match ndn_ipc::MgmtClient::connect(&socket).await {
        Ok(client) => ensure_daemon_pib(&client, &socket, pib_dir)
            .await
            .context("nothing was signed"),
        Err(ndn_ipc::ForwarderError::Io(e))
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(())
        }
        Err(e) => bail!(
            "cannot use the daemon's socket {socket} ({e}): run this as a user the daemon \
             accepts, or pass -c with the config of the daemon that uses {}. Nothing was signed",
            pib_dir.display()
        ),
    }
}

/// `ndn-fwd revoke <device | key | certificate>`.
pub(crate) async fn run(args: &[String]) -> Result<()> {
    let target = *positionals(args).first().context(
        "revoke requires a device identity (/<ns>/<role>/<device>), a key name \
         (<identity>/KEY/<id>) or a certificate name",
    )?;
    let name: Name = target
        .parse()
        .map_err(|e| anyhow::anyhow!("revoke refused: {target:?} is not an NDN name: {e}"))?;
    let pib_dir = pib_dir(args)?;
    let Plan {
        store,
        held,
        held_data,
        keys,
        adding,
    } = plan(&pib_dir, &name)?;
    let namespace = held.namespace().clone();
    if adding.is_empty() {
        println!("# ndn-fwd revoke");
        println!("namespace      = {namespace}");
        for key in &keys {
            println!("revoked_key    = {key} (already)");
        }
        println!(
            "trust_context  = v{} (already revokes every key named; nothing signed)",
            held.version()
        );
        return Ok(());
    }
    check_daemon(args, &pib_dir).await?;

    let unlock = crate::root_key::operator_secret(
        args,
        store.unlock_kind(),
        &format!("Revoking {name} signs a new trust context version"),
        false,
    )?;
    let root = store
        .signer(unlock.as_ref())
        .await
        .context("the root did not unlock; nothing was signed")?;
    drop(unlock);
    let bump = ndn_cert::bump_context_revoking(root.as_ref(), &held_data, &keys)
        .await?
        .context("the held trust context revokes every key named already; nothing was signed")?;
    drop(root);
    let version = bump.context.version();
    let added: Vec<String> = bump.added.iter().map(Name::to_string).collect();
    let handed = hand_over(args, &pib_dir, &bump)
        .await
        .map_err(|not| match not {
            NotTaken::Refused(e) => e.context(format!(
                "nothing was revoked: the trust context stays v{} and the CA keeps serving the \
             certificates",
                held.version()
            )),
            NotTaken::Unknown(e) => e.context(format!(
                "whether the daemon adopted v{version} (revoking {}) is not known: once the daemon \
             is idle, run `ndn-fwd revoke {name} --pib {}` again — it reports the keys revoked \
             already if the daemon took v{version}, and signs the version again if not",
                added.join(", "),
                pib_dir.display()
            )),
        })?;
    println!("# ndn-fwd revoke");
    println!("namespace      = {namespace}");
    for key in &bump.added {
        println!("revoked_key    = {key}");
    }
    println!(
        "trust_context  = v{} -> v{version} (signed by the root {})",
        held.version(),
        store.key_name()
    );
    println!("handed_over    = {handed}");
    println!();
    println!("# The CA of {namespace} stops serving the certificates of these keys once its");
    println!("# daemon holds v{version}, and the device name is free to enroll again with a");
    println!("# new key. Every other node refuses the keys once it holds v{version}: at its next");
    println!("# refresh ([security] context_refresh_secs, default 300 s), or at once with");
    println!("# `ndn-fwd context refresh`.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ndn_mgmt::EnrollOutcome;

    use super::*;
    use crate::context_adopt::TrustAdmin;
    use crate::enroll::tests::{Node, node, request};

    /// A daemon on `engine` holding the contexts stored in `pib`, with `ca`.
    fn admin(
        engine: ndn_engine::ForwarderEngine,
        pib: &Path,
        ca: Option<Arc<CaState>>,
    ) -> TrustAdmin {
        let keyring = Arc::new(Keyring::new());
        ndn_cert::load_persisted_contexts(pib, &keyring).unwrap();
        TrustAdmin {
            engine,
            keyring,
            pib_root: pib.to_path_buf(),
            publisher: None,
            signing: None,
            own_certs: None,
            dv_keeps_startup_key: false,
            configured_identity: None,
            enrolling: tokio::sync::Mutex::new(()),
            keeping: std::sync::Mutex::new(()),
            ca,
            context_change: tokio::sync::Mutex::new(()),
            renewing: tokio::sync::Mutex::new(()),
            certificates_changed: tokio::sync::Notify::new(),
            context_sync: None,
        }
    }

    /// An enrolled device: its identity, key and certificate.
    async fn enrolled(node: &Node, token: &str) -> (Name, Name, String) {
        let EnrollOutcome::Enrolled(e) =
            crate::enroll::enroll(&node.admin, request(node, "member", token, "phone", true))
                .await
                .unwrap();
        (
            e.identity.parse().unwrap(),
            e.key.parse().unwrap(),
            e.certificate,
        )
    }

    /// Version 2 of the root device's context, revoking what `name`
    /// designates, signed by the root as `ndn-fwd revoke` signs it.
    async fn revocation(root_dev: &Path, name: &Name) -> ndn_cert::ContextBump {
        let plan = plan(root_dev, name).unwrap();
        let root = plan.store.signer(None).await.unwrap();
        ndn_cert::bump_context_revoking(root.as_ref(), &plan.held_data, &plan.keys)
            .await
            .unwrap()
            .unwrap()
    }

    /// The checks before the root is unlocked: only on the root device, never
    /// the root or the CA key, only names the CA certified (or key names),
    /// and nothing to sign when the held version revokes them already.
    #[tokio::test]
    async fn revoke_is_planned_only_on_the_root_device_and_never_for_the_root_or_the_ca() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-a"]).await;
        let (identity, key, _) = enrolled(&node, "member-a").await;

        let held = node.admin.keyring.contexts().pop().unwrap();
        ndn_cert::persist_context(device.path(), &held, &node.context_data).unwrap();
        assert!(
            plan(device.path(), &identity).is_err(),
            "not the root device"
        );

        let planned = plan(root_dev.path(), &identity).unwrap();
        assert_eq!(
            (planned.keys.clone(), planned.adding),
            (vec![key.clone()], vec![key])
        );
        for name in [
            "/home/bob/KEY/root",
            "/home/bob/CA",
            "/home/bob/CA/KEY/ca",
            "/home/bob/member/tablet",
            "/home/alice/member/phone/KEY/k",
        ] {
            assert!(
                plan(root_dev.path(), &name.parse().unwrap()).is_err(),
                "{name}"
            );
        }
        node.shutdown.shutdown().await;
    }

    /// A revocation handed to the daemon (`security/context-update`): the
    /// daemon adopts v2 and its CA, following v2, stops serving the device's
    /// certificate — the device name is free for a new key — and a key the
    /// held version revokes already plans nothing to sign.
    #[tokio::test]
    async fn a_revocation_handed_over_makes_the_ca_stop_serving_the_device() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-a", "member-b"]).await;
        let ns: Name = "/home/bob".parse().unwrap();
        let (identity, key, certificate) = enrolled(&node, "member-a").await;

        let bump = revocation(root_dev.path(), &identity).await;
        let daemon = admin(
            node.admin.engine.clone(),
            root_dev.path(),
            Some(Arc::clone(&node.ca)),
        );
        let info = crate::context_refresh::apply_update(&daemon, bump.data.raw().clone())
            .await
            .unwrap();
        assert_eq!((info.held_version, info.version), (1, 2));
        assert!(daemon.keyring.contexts().pop().unwrap().is_revoked(&key));
        assert!(
            node.ca.get_served_cert(&certificate).is_none(),
            "the CA stops serving it"
        );
        assert!(node.ca.is_revoked(&certificate));
        let (stored, _) = ndn_cert::read_stored_context(root_dev.path(), &ns)
            .unwrap()
            .unwrap();
        assert_eq!(stored.version(), 2);
        assert!(plan(root_dev.path(), &key).unwrap().adding.is_empty());

        let (again, other_key, _) = enrolled(&node, "member-b").await;
        assert_eq!(again, identity);
        assert_ne!(other_key, key, "the device name took a new key");
        node.shutdown.shutdown().await;
    }

    /// A revocation a CA node fetches with a refresh (a CA on a node other
    /// than the root device) makes its CA stop serving the device too.
    #[tokio::test]
    async fn a_revocation_adopted_by_refresh_makes_the_ca_stop_serving_the_device() {
        use ndn_engine::{EngineBuilder, EngineConfig};
        use ndn_security::SecurityManager;

        let dirs: Vec<_> = (0..4).map(|_| tempfile::tempdir().unwrap()).collect();
        let (root_dev, device, upstream, relay) = (
            dirs[0].path(),
            dirs[1].path(),
            dirs[2].path(),
            dirs[3].path(),
        );
        let node = node(root_dev, device, &["member-a"]).await;
        let ns: Name = "/home/bob".parse().unwrap();
        let (identity, _, certificate) = enrolled(&node, "member-a").await;
        let bump = revocation(root_dev, &identity).await;

        let held = node.admin.keyring.contexts().pop().unwrap();
        ndn_cert::persist_context(relay, &held, &node.context_data).unwrap();
        ndn_cert::persist_context(upstream, &bump.context, &bump.data).unwrap();
        let (face, publisher) = crate::context_publisher::prepare(upstream);
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .security_profile(ndn_security::SecurityProfile::Disabled)
            .security(Arc::new(SecurityManager::new()))
            .face(face)
            .build()
            .await
            .unwrap();
        let _serving = publisher.spawn(&engine);
        let relay = admin(engine, relay, Some(Arc::clone(&node.ca)));
        assert!(node.ca.get_served_cert(&certificate).is_some());

        let results = crate::context_refresh::refresh_contexts(&relay, Some(ns.clone()))
            .await
            .unwrap();
        assert_eq!(results[0].version, 2, "{}", results[0].detail);
        assert!(
            node.ca.get_served_cert(&certificate).is_none(),
            "the CA stops serving it"
        );
        shutdown.shutdown().await;
        node.shutdown.shutdown().await;
    }

    /// A revocation stored for the daemon's next start (no daemon listened):
    /// the CA follows it when it starts, from the contexts loaded.
    #[tokio::test]
    async fn a_revocation_stored_for_the_next_start_is_followed_when_the_ca_starts() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-a"]).await;
        let (identity, _, certificate) = enrolled(&node, "member-a").await;
        let bump = revocation(root_dev.path(), &identity).await;
        ndn_cert::persist_context(root_dev.path(), &bump.context, &bump.data).unwrap();

        let keyring = Keyring::new();
        ndn_cert::load_persisted_contexts(root_dev.path(), &keyring).unwrap();
        ca_follow_held(&node.ca, &keyring);
        assert!(node.ca.get_served_cert(&certificate).is_none());
        node.shutdown.shutdown().await;
    }
}
