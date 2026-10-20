//! `ndn-fwd revoke <device | key | certificate>` on the root device: the
//! CLI over [`ndn_namespace::root::revoke`].
//!
//! **The revocation is a new version of the trust context.** The CLI works
//! on the PIB of the daemon it hands the version to; the library checks,
//! before asking for anything, that this is the root device of the trusted
//! prefix the name is in (of those whose root the PIB holds, the longest
//! covering it; `--namespace` must name that one when given), which keys
//! the name designates (a key or certificate name: its key; a device
//! identity: every key the namespace CA certified for it, read from that
//! CA's store in the PIB), that none is the root's or the CA's, and that
//! the held version does not revoke them all already
//! ([`ndn_cert::plan_revocation`]). Only then is the root unlocked — a
//! `sealed-file` root with its passphrase, a `yubikey-piv` root with its
//! PIN, asked here ([`crate::root_host::Secrets`]); an `os-keyring` root
//! through the keychain — to sign version `N+1`, which lists the keys as
//! revoked ([`ndn_cert::bump_context_revoking`]). The signer is dropped (a
//! software key zeroed) right after. The secret never leaves the CLI: the
//! daemon receives only the signed version (`security/context-update`),
//! which it adopts under the continuity rule, stores and publishes; with no
//! daemon listening it is stored for the daemon's next start. Every node's
//! validator refuses a chain through a revoked key — any certificate of it,
//! also ones issued later — once it holds that version, which other nodes
//! fetch with their next refresh ([`crate::context_refresh`]).
//!
//! **The CA follows the signed version**
//! ([`ndn_cert::CaState::follow_context`]), never a separate request:
//! whenever the daemon keeps a version of its namespace's context — handed
//! over, refreshed, adopted by link ([`ndn_namespace::keep`]) — and when its
//! CA starts ([`ndn_cert::CaState::follow_held`]), the CA stops serving
//! every certificate it issued that the version revokes, records that in its
//! store (`revoked/` in the CA's directory, [`ndn_cert::ca_dir`]), never
//! certifies such a key again, and the device name the key held is free for
//! a new key (one key per device name).

use std::path::Path;

use anyhow::{Context, Result};
use ndn_cert::report::code;
use ndn_namespace::root::{self, RootError};
use ndn_packet::Name;

use crate::onboard::{pib_dir, positionals};
use crate::root_host::{
    Secrets, daemon, handed_text, namespace_arg, render, render_before_signing,
};

/// A refused revocation of `name` (on the PIB at `pib_dir`, the held
/// version `held`), as the CLI says it.
fn refused(e: RootError, name: &Name, pib_dir: &Path, held: u64) -> anyhow::Error {
    if e.is(code::VERSION_NOT_TAKEN) {
        return render(e).context(format!(
            "nothing was revoked: the trust context stays v{held} and the CA keeps serving the \
             certificates"
        ));
    }
    if e.is(code::HAND_OVER_UNKNOWN) {
        let version = e.param("version").unwrap_or_default().to_string();
        let keys = e.param("keys").unwrap_or_default().to_string();
        return render(e).context(format!(
            "whether the daemon adopted v{version} (revoking {keys}) is not known: once the daemon \
             is idle, run `ndn-fwd revoke {name} --pib {}` again — it reports the keys revoked \
             already if the daemon took v{version}, and signs the version again if not",
            pib_dir.display()
        ));
    }
    if e.is(code::NOTHING_TO_SIGN) {
        return anyhow::anyhow!(
            "the held trust context revokes every key named already; nothing was signed"
        );
    }
    render_before_signing(e)
}

/// A refused plan, as the CLI says it.
fn plan_refused(e: RootError) -> anyhow::Error {
    if e.is(code::REVOKE_OTHER_NAMESPACE) {
        let p = |key| e.param(key).unwrap_or_default();
        return anyhow::anyhow!(
            "{} is in the trusted prefix {}, not {}: revoke it there (or leave out \
             --namespace). Nothing was signed",
            p("name"),
            p("namespace"),
            p("requested")
        );
    }
    render(e)
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
    let planned =
        root::revoke::plan(&pib_dir, &name, namespace_arg(args)?.as_ref()).map_err(plan_refused)?;
    let held = planned.root.context.version();
    if planned.adding.is_empty() {
        println!("# ndn-fwd revoke");
        println!("namespace      = {}", planned.root.context.namespace());
        for key in &planned.keys {
            println!("revoked_key    = {key} (already)");
        }
        println!("trust_context  = v{held} (already revokes every key named; nothing signed)");
        return Ok(());
    }
    let daemon = daemon(args)?;
    let revoked = root::revoke::revoke(planned, &name, &pib_dir, &daemon, &Secrets { args })
        .await
        .map_err(|e| refused(e, &name, &pib_dir, held))?;
    let (namespace, version) = (&revoked.namespace, revoked.version);
    println!("# ndn-fwd revoke");
    println!("namespace      = {namespace}");
    for key in &revoked.revoked {
        println!("revoked_key    = {key}");
    }
    println!(
        "trust_context  = v{held} -> v{version} (signed by the root {})",
        revoked.root_key
    );
    println!(
        "handed_over    = {}",
        handed_text(&revoked.handed_over, &daemon, version, &pib_dir)
    );
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

    use ndn_cert::CaState;
    use ndn_mgmt::EnrollOutcome;
    use ndn_security::Keyring;

    use super::*;
    use crate::context_adopt::{TrustAdmin, TrustAdminParts};
    use crate::enroll::tests::{Node, node, request};
    use ndn_namespace::root::revoke::plan;

    /// A daemon on `engine` holding the contexts stored in `pib`, running
    /// `cas`.
    fn admin(
        engine: ndn_engine::ForwarderEngine,
        pib: &Path,
        cas: Vec<Arc<CaState>>,
    ) -> TrustAdmin {
        let keyring = Arc::new(Keyring::new());
        ndn_cert::load_persisted_contexts(pib, &keyring).unwrap();
        TrustAdmin::new(TrustAdminParts {
            engine,
            keyring,
            pib_root: pib.to_path_buf(),
            publisher: None,
            signing: None,
            own_certs: None,
            dv_keeps_startup_key: false,
            configured_identity: None,
            cas,
            context_sync: None,
        })
    }

    /// An enrolled device: its identity, key and certificate.
    async fn enrolled(node: &Node, token: &str) -> (Name, Name, String) {
        let EnrollOutcome::Enrolled(e) =
            crate::enroll::enroll(&node.admin, request(node, "member", token, "phone", true))
                .await
                .unwrap()
        else {
            panic!("an invite enrolls at once")
        };
        (
            e.identity.parse().unwrap(),
            e.key.parse().unwrap(),
            e.certificate,
        )
    }

    /// Version 2 of the root device's context, revoking what `name`
    /// designates, signed by the root as `ndn-fwd revoke` signs it.
    async fn revocation(root_dev: &Path, name: &Name) -> ndn_cert::ContextBump {
        let plan = plan(root_dev, name, None).unwrap();
        let root = plan.root.store.signer(None).await.unwrap();
        ndn_cert::bump_context_revoking(root.as_ref(), &plan.root.data, &plan.keys)
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

        let held = node.admin.ns.keyring().contexts().pop().unwrap();
        ndn_cert::persist_context(device.path(), &held, &node.context_data).unwrap();
        assert!(
            plan(device.path(), &identity, None).is_err(),
            "not the root device"
        );

        let planned = plan(root_dev.path(), &identity, None).unwrap();
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
                plan(root_dev.path(), &name.parse().unwrap(), None).is_err(),
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
            node.admin.ns.engine().clone(),
            root_dev.path(),
            vec![Arc::clone(&node.ca)],
        );
        let info = crate::context_refresh::apply_update(&daemon, bump.data.raw().clone())
            .await
            .unwrap();
        assert_eq!((info.held_version, info.version), (1, 2));
        assert!(
            daemon
                .ns
                .keyring()
                .contexts()
                .pop()
                .unwrap()
                .is_revoked(&key)
        );
        assert!(
            node.ca.get_served_cert(&certificate).is_none(),
            "the CA stops serving it"
        );
        assert!(node.ca.is_revoked(&certificate));
        let (stored, _) = ndn_cert::read_stored_context(root_dev.path(), &ns)
            .unwrap()
            .unwrap();
        assert_eq!(stored.version(), 2);
        assert!(plan(root_dev.path(), &key, None).unwrap().adding.is_empty());

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

        let held = node.admin.ns.keyring().contexts().pop().unwrap();
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
        let relay = admin(engine, relay, vec![Arc::clone(&node.ca)]);
        assert!(node.ca.get_served_cert(&certificate).is_some());

        let results = crate::context_refresh::refresh_contexts(&relay, Some(ns.clone()))
            .await
            .unwrap();
        assert_eq!(results[0].version, 2, "{:?}", results[0].detail);
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
        node.ca.follow_held(&keyring);
        assert!(node.ca.get_served_cert(&certificate).is_none());
        node.shutdown.shutdown().await;
    }
}
