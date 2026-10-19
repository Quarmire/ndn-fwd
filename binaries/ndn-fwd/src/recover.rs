//! `ndn-fwd recover`: make a replacement device the root device of a
//! namespace whose root device is lost, with a recovery kit
//! ([`ndn_cert::recovery`]).
//!
//! On the replacement device, its own daemon running (the one that uses the
//! PIB recovered into) and linked to the namespace (directly or through a
//! relay):
//!
//! 1. **The newest version, by name.** The daemon refreshes the context it
//!    holds (RDR, under the continuity rule — the same as `ndn-fwd context
//!    refresh`); a device holding none adopts it first from a file kit's
//!    expected fingerprint. Recovering from an older version than the
//!    namespace serves would fork it, so a failed refresh stops here. When
//!    nothing answers at all (the lost root device was the only other node
//!    reachable), `--from-held` recovers from the version held: the
//!    operator vouches that no newer one exists. A version that answers and
//!    is refused still stops it ([`ndn_namespace::admin::fetch_newest`]).
//! 2. **The kit.** Its key must be a recovery anchor of that version (and
//!    the version must verify under its own anchors), else nothing is
//!    signed. A mistyped word list is refused by its checksum. A YubiKey
//!    kit's token is selected with `--kit-yubikey-serial/--kit-yubikey-slot`.
//! 3. **The new root device.** [`ndn_cert::recover_namespace_in_pib`]: a new
//!    root in the root store the operator picks (as `init`; never on the
//!    kit's token, nor over an occupied slot without `--replace-slot`), a
//!    new CA key and admin identity with fresh key ids, version `N+1` signed
//!    by the recovery key — the old root kept as an anchor with every
//!    recovery kit (`--old-root destroyed`), or removed and revoked with the
//!    old CA and admin keys and every recovery kit but the one used and
//!    those named with `--keep-kit` (`--old-root compromised`: whoever held
//!    the root could have added a kit) — and version `N+2`, the same content
//!    signed by the new root. Every anchor `N+1` keeps is printed.
//! 4. **Hand-over.** `N+1`, then `N+2`, go to the daemon
//!    (`security/context-update`), which adopts each by the continuity rule,
//!    stores and publishes it; every other node adopts them the same way at
//!    its next refresh, one after the other (a node that missed `N+1`
//!    follows the versions by name, `ndn_cert::follow_versions`). Only the
//!    daemon's refusal of `N+1` removes what step 3 wrote; a request it does
//!    not answer in time is made again, and the answer says what became of
//!    `N+1` ([`crate::recovery_kit::hand_over`]). Once `N+2` is taken, the
//!    newest version is signed by the new root, so the root's fingerprint is
//!    the namespace's expected fingerprint again: the anchor link printed,
//!    and invites minted from then on, carry it. Until then no link is
//!    printed.

use anyhow::{Context, Result, bail};
use ndn_cert::{
    OldRoot, anchor_fingerprint, kit_anchor, read_stored_context, recover_namespace_in_pib,
};
use ndn_mgmt::ContextRefreshInfo;
use ndn_mgmt_wire::control_response::status;
use ndn_namespace::admin::{Newest, NewestSource, fetch_newest};
use ndn_namespace::hex;
use ndn_packet::Name;
use ndn_security::FilePib;
use ndn_trust_envelope::TrustEnvelope;

use crate::onboard::{flag, pib_dir};
use crate::recovery_kit::{KitSpec, NotTaken, hand_over, open_kit};

/// How long the CLI waits for the daemon to fetch the newest version.
const DAEMON_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// The daemon at `socket`: refreshes and adopts the namespace for
/// [`fetch_newest`] (`security/context-refresh`, `security/context-adopt`).
struct Daemon<'a> {
    client: &'a ndn_ipc::MgmtClient,
    socket: &'a str,
}

#[async_trait::async_trait]
impl NewestSource for Daemon<'_> {
    type Error = anyhow::Error;

    async fn refresh(&self, namespace: &Name) -> Result<Option<ContextRefreshInfo>> {
        let socket = self.socket;
        let resp = self
            .client
            .security_context_refresh(Some(namespace), DAEMON_FETCH_TIMEOUT)
            .await
            .with_context(|| format!("ask the daemon at {socket} for the newest version"))?;
        if resp.is_ok() {
            let results: Vec<ContextRefreshInfo> = serde_json::from_str(&resp.status_text)
                .with_context(|| {
                    format!("unreadable answer from the daemon: {}", resp.status_text)
                })?;
            return results
                .into_iter()
                .next()
                .context("the daemon answered no refresh result")
                .map(Some);
        }
        if resp.status_code != status::NOT_FOUND {
            bail!(
                "the daemon at {socket} could not refresh {namespace} ({}): {}",
                resp.status_code,
                resp.status_text
            );
        }
        Ok(None)
    }

    async fn adopt(&self, namespace: &Name, fingerprint: &[u8; 32]) -> Result<u64> {
        let link = TrustEnvelope::Anchor {
            namespace: Some(namespace.to_string()),
            fingerprint: Some(*fingerprint),
            version: None,
            context_data: None,
            context_content: None,
        }
        .to_uri();
        let resp = self
            .client
            .security_context_adopt(&link, DAEMON_FETCH_TIMEOUT)
            .await
            .with_context(|| format!("ask the daemon at {} to adopt {namespace}", self.socket))?;
        if !resp.is_ok() {
            bail!(
                "this device holds no trust context for {namespace}, and adopting it with the \
                 kit's expected fingerprint failed ({}): {}. Adopt it with the namespace's anchor \
                 link (`ndn-fwd adopt`), then retry",
                resp.status_code,
                resp.status_text
            );
        }
        let info: ndn_mgmt::AdoptedContextInfo = serde_json::from_str(&resp.status_text)
            .with_context(|| format!("unreadable answer from the daemon: {}", resp.status_text))?;
        Ok(info.version)
    }
}

pub(crate) async fn run(args: &[String]) -> Result<()> {
    let old_root: OldRoot = match flag(args, &["--old-root"]) {
        Some(choice) => choice.parse().map_err(|e: String| anyhow::anyhow!(e))?,
        None => bail!(
            "recover needs --old-root destroyed|compromised: say what happened to the lost root \
             device. {}",
            OldRoot::CHOICE
        ),
    };
    let spec = KitSpec::parse(
        flag(args, &["--kit"]).context("recover needs --kit words|yubikey|<kit-file>")?,
    );
    let pib_dir = pib_dir(args)?;
    let namespace = crate::recovery_kit::kit_namespace(args, Some(&spec), &pib_dir)?;
    let device = match flag(args, &["--device"]) {
        Some(device) => device.to_string(),
        None => crate::onboard::default_device()?,
    };
    let kit_fingerprint = match &spec {
        KitSpec::File(path) => ndn_cert::FileKit::read(path)?.fingerprint,
        _ => None,
    };
    let pib =
        FilePib::new(&pib_dir).with_context(|| format!("open PIB at {}", pib_dir.display()))?;
    // Refused only when this PIB already holds the root of this namespace:
    // the roots of other trusted prefixes stay beside the recovered one.
    if let Some(store) = ndn_cert::RootStore::open_for(&pib, &namespace)? {
        bail!(
            "{} holds the root of {namespace} ({} root store): this already is a root device of \
             it. Recover on a replacement device whose PIB holds no root of {namespace} (the \
             roots of other trusted prefixes may stay)",
            pib_dir.display(),
            store.kind()
        );
    }

    // 1. The newest version, by name — from the daemon that uses this PIB,
    //    which is also the one the new versions go to.
    let (client, socket) = crate::onboard::daemon(args, "recover").await?;
    crate::recovery_kit::ensure_daemon_pib(&client, &socket, &pib_dir).await?;
    let from_held = args.iter().any(|a| a == "--from-held");
    let daemon = Daemon {
        client: &client,
        socket: &socket,
    };
    let Newest {
        version: newest,
        confirmed,
    } = fetch_newest(
        &daemon,
        &namespace,
        kit_fingerprint,
        from_held,
        &crate::context_adopt::namespace_words(),
    )
    .await?;
    let (held, held_data) = read_stored_context(&pib_dir, &namespace)?.with_context(|| {
        format!(
            "the daemon holds {namespace} v{newest} but {} has no stored copy; is -c/--pib the \
             daemon's PIB?",
            pib_dir.display()
        )
    })?;
    if held.version() != newest {
        bail!(
            "the daemon holds {namespace} v{newest} but {} stores v{}; is -c/--pib the daemon's \
             PIB?",
            pib_dir.display(),
            held.version()
        );
    }
    // The stored version verifies under its own anchors (self-consistent).
    ndn_security::SignedTrustContext::open_signed(&held_data)
        .await
        .with_context(|| format!("the stored {namespace} v{newest} does not verify"))?;

    // 2. The kit: its key must be a recovery anchor of v{newest}.
    let (recovery, kit_token) =
        open_kit(args, &spec, &namespace, &format!("Recovering {namespace}")).await?;
    kit_anchor(
        &held,
        &recovery
            .public_key()
            .context("the kit's key reports no public key")?,
    )?;

    // 3. The new root device: never on the kit's token, which must sign
    //    N+1 after the new root exists.
    let mut root = crate::root_key::new_root_store(args)?;
    if let (ndn_cert::NewRootStore::YubikeyPiv { guard, .. }, Some(serial)) = (&mut root, kit_token)
    {
        guard.not_on = Some((serial, "the recovery kit used here".to_string()));
    }
    let kept_kits = crate::onboard::flag_values(args, "--keep-kit")
        .into_iter()
        .map(|key| {
            key.parse::<Name>()
                .map_err(|e| anyhow::anyhow!("--keep-kit {key:?} is not an NDN name: {e}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let recovered = recover_namespace_in_pib(
        &pib,
        &held_data,
        recovery.as_ref(),
        &device,
        old_root,
        &kept_kits,
        &root,
    )
    .await?;
    drop(root);
    drop(recovery);

    // 4. Hand N+1, then N+2, to the daemon. Only the daemon's refusal of
    //    N+1 undoes step 3: without an answer it may still adopt N+1, which
    //    names the new root.
    let next = recovered.version.bump.context.version();
    let handed = match hand_over(args, &pib_dir, &recovered.version.bump).await {
        Ok(handed) => handed,
        Err(NotTaken::Refused(e)) => {
            recovered.undo(&pib);
            return Err(e.context(
                "the daemon did not take the recovered version; everything this command wrote \
                 to the PIB was removed again and nothing changed",
            ));
        }
        Err(NotTaken::Unknown(e)) => {
            return Err(e.context(format!(
                "whether the daemon adopted v{next} is not known, so nothing this command wrote \
                 was removed (v{next} names the new root {}). `ndn-fwd recovery-kit list --pib \
                 {pib}` shows the version the daemon stored: v{next} means the recovery took — \
                 run `ndn-fwd recovery-kit create --pib {pib}` then, so the new root signs the \
                 newest version; v{} once the daemon is idle or restarted means it did not — \
                 remove {pib}/root, {pib}/ca and the keys {} and {} from the PIB, and recover \
                 again",
                recovered.anchor.key_name(),
                recovered.previous_version,
                recovered.ca_key,
                recovered.device_key,
                pib = pib_dir.display(),
            )));
        }
    };
    // N+1 is the namespace's from here on (its new root is an anchor of
    // it): nothing is undone any more. N+2 makes the root the signer of the
    // newest version.
    let root_handed = hand_over(args, &pib_dir, &recovered.root_version).await;

    let v = &recovered.version;
    let settled = recovered.root_version.context.version();
    let root_fp = hex(&anchor_fingerprint(&recovered.anchor));
    let pib_abs = std::fs::canonicalize(&pib_dir).unwrap_or_else(|_| pib_dir.clone());
    println!("# ndn-fwd recover: this device is the root device of {namespace} now");
    println!("namespace      = {namespace}");
    println!(
        "recovered_with = {} ({} kit)",
        v.recovery_key,
        spec.format()
    );
    println!("old_root       = {old_root}");
    if !confirmed {
        println!(
            "newest_check   = not confirmed: nothing answered for {namespace}; recovered from the \
             held v{} (--from-held)",
            recovered.previous_version
        );
    }
    println!(
        "trust_context  = v{} -> v{next} (signed by the recovery key; {handed})",
        recovered.previous_version
    );
    match &root_handed {
        Ok(handed) => println!(
            "trust_context  = v{next} -> v{settled} (the same, signed by the new root; {handed})"
        ),
        Err(NotTaken::Refused(e)) => println!(
            "trust_context  = v{settled} (the same, signed by the new root) NOT taken: {e:#}"
        ),
        Err(NotTaken::Unknown(e)) => println!(
            "trust_context  = v{settled} (the same, signed by the new root) NOT KNOWN whether \
             taken: {e:#}"
        ),
    }
    println!("root_key       = {}", recovered.anchor.key_name());
    println!("anchor_fp      = {root_fp}");
    for line in crate::root_key::describe_new_root(&recovered.root_store, &pib_abs) {
        println!("{line}");
    }
    println!("ca_key         = {}", recovered.ca_key);
    println!(
        "ca_cert        = {} (issued by the new root)",
        recovered.ca_cert_path.display()
    );
    println!("device         = {} (admin)", recovered.device_identity);
    println!("device_key     = {}", recovered.device_key);
    println!(
        "device_cert    = {} (issued by the new CA)",
        recovered.device_cert_path.display()
    );
    // Every anchor v{next} keeps, so a key nobody expects stands out.
    let mut anchors: Vec<Name> = v
        .bump
        .context
        .anchors()
        .iter()
        .map(|a| a.value().key_name())
        .collect();
    anchors.sort();
    anchors.dedup();
    for key in &anchors {
        let what = if *key == recovered.anchor.key_name() {
            "the new root"
        } else if *key == v.recovery_key {
            "recovery kit, used here"
        } else if v.kept_kits.contains(key) {
            "recovery kit"
        } else {
            "the old root; its certificates stay valid"
        };
        println!("anchor         = {key} ({what})");
    }
    for key in &v.bump.added {
        let what = if v.removed_kits.contains(key) {
            "a recovery kit not named with --keep-kit"
        } else if v.old_root_keys.contains(key) {
            "the old root"
        } else {
            "a key of the old root device"
        };
        println!("revoked        = {key} ({what})");
    }
    // An anchor link names the newest version's signer as the expected
    // fingerprint: the new root, once it signed v{settled}. Until then no
    // link is printed — one with the recovery key's fingerprint would stop
    // working as soon as the root signs anything, and would put the kit's
    // fingerprint into circulation.
    if root_handed.is_ok() {
        let link = |context_data| TrustEnvelope::Anchor {
            namespace: Some(namespace.to_string()),
            fingerprint: Some(anchor_fingerprint(&recovered.anchor)),
            version: Some(settled),
            context_data,
            context_content: None,
        };
        println!(
            "anchor_uri     = {}",
            link(Some(recovered.root_version.data.raw().clone())).to_uri()
        );
        println!("anchor_uri_fp  = {}", link(None).to_uri());
    }
    println!();
    println!("# Restart this device's daemon with these lines in ndn-fwd.toml, so it signs as its");
    println!("# admin identity and runs the namespace CA (the endpoint stays {namespace}/CA; one");
    println!(
        "# [[ca]] table per trusted prefix this device is the root of); copy the [[ca.challenge]]"
    );
    println!("# set of the old root device (token and device-approval):");
    println!("[security]");
    println!("identity = \"{}\"", recovered.device_identity);
    println!("pib_path = \"{}\"", pib_abs.display());
    println!("[[ca]]");
    println!("enabled  = true");
    println!("prefix   = \"{namespace}\"");
    println!("identity = \"{namespace}/CA\"");
    println!();
    println!("# Every other node adopts v{next} and v{settled} at its next refresh ([security]");
    println!(
        "# context_refresh_secs) or at once with `ndn-fwd context refresh`: v{next} is signed by"
    );
    println!(
        "# the recovery key, an anchor of v{}, and v{settled} by the new root, which v{next} made",
        recovered.previous_version
    );
    println!("# an anchor. A node that missed them follows them one by one, from any node that");
    println!("# holds them (every node keeps and serves the versions it held).");
    match &root_handed {
        Ok(_) => {
            println!(
                "# The namespace's expected fingerprint is the new root's now ({root_fp}): the"
            );
            println!("# anchor links above and every invite minted from now on carry it:");
            println!(
                "#   ndn-fwd-tokens new --ca {namespace} --namespace {namespace} --anchor-fp {root_fp} --role member"
            );
            println!(
                "# Links and invites minted before carry the old root's fingerprint: they no longer"
            );
            println!("# adopt the namespace on a device that holds nothing. Mint new ones.");
        }
        Err(_) => {
            println!(
                "# v{settled} is not known to be taken, so the newest version may be signed by the"
            );
            println!(
                "# recovery key, and no anchor link is printed. Once the daemon is reachable and"
            );
            println!(
                "# holds v{next} (`ndn-fwd recovery-kit list --pib {}`), run `ndn-fwd recovery-kit",
                pib_abs.display()
            );
            println!(
                "# create`: the root signs the newest version, and its fingerprint ({root_fp})"
            );
            println!(
                "# becomes the namespace's expected fingerprint for anchor links and invites."
            );
        }
    }
    match old_root {
        OldRoot::Destroyed => {
            println!("#");
            println!(
                "# The old root stays an anchor: devices keep their certificates and renew them"
            );
            println!("# with the new CA (`ndn-fwd renew`, or their renewal timer).");
        }
        OldRoot::Compromised => {
            println!("#");
            println!(
                "# Revoked: the old root, CA and admin keys. Every device certificate the old CA"
            );
            println!(
                "# issued stops validating once a node holds v{next}. Each such device enrolls"
            );
            println!("# again with a new invite from this device, once it holds v{next}:");
            println!(
                "#   here:   ndn-fwd-tokens new --ca {namespace} --namespace {namespace} --anchor-fp {root_fp} --role member"
            );
            println!("#   there:  ndn-fwd context refresh && ndn-fwd enroll <invite> --force");
            println!("# (admins and relays: by device approval from this device).");
            if v.root_device_keys_unrecorded {
                println!(
                    "# v{} recorded no root-device keys (a namespace made before they were): the CA",
                    recovered.previous_version
                );
                println!(
                    "# key init names was revoked; revoke the old root device's admin key too:"
                );
                println!("#   ndn-fwd revoke {namespace}/admin/<old-device>/KEY/device");
            }
        }
    }
    println!("#");
    if !v.removed_kits.is_empty() {
        println!(
            "# Revoked recovery kits (whoever held the old root could have added them): any of"
        );
        println!("# them that was yours no longer recovers anything; create new ones.");
    }
    println!("# Create a new recovery kit now (`ndn-fwd recovery-kit create`); the kit used here");
    println!(
        "# stays a recovery anchor until `ndn-fwd recovery-kit revoke {}`.",
        v.recovery_key
    );
    Ok(())
}
