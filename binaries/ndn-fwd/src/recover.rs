//! `ndn-fwd recover`: make a replacement device the root device of a
//! namespace whose root device is lost, with a recovery kit
//! ([`ndn_cert::recovery`]).
//!
//! On the replacement device, its own daemon running and linked to the
//! namespace (directly or through a relay):
//!
//! 1. **The newest version, by name.** The daemon refreshes the context it
//!    holds (RDR, under the continuity rule — the same as `ndn-fwd context
//!    refresh`); a device holding none adopts it first from a file kit's
//!    expected fingerprint. Recovering from an older version than the
//!    namespace serves would fork it, so a failed refresh stops here. When
//!    nothing answers at all (the lost root device was the only other node
//!    reachable), `--from-held` recovers from the version held: the
//!    operator vouches that no newer one exists. A version that answers and
//!    is refused still stops it.
//! 2. **The kit.** Its key must be a recovery anchor of that version (and
//!    the version must verify under its own anchors), else nothing is
//!    signed. A mistyped word list is refused by its checksum.
//! 3. **The new root device.** [`ndn_cert::recover_namespace_in_pib`]: a new
//!    root in the root store the operator picks (as `init`), a new CA key
//!    and admin identity with fresh key ids, version `N+1` signed by the
//!    recovery key — the old root kept as an anchor (`--old-root
//!    destroyed`) or removed and revoked with the old CA and admin keys
//!    (`--old-root compromised`) — and version `N+2`, the same content
//!    signed by the new root.
//! 4. **Hand-over.** `N+1`, then `N+2`, go to the daemon
//!    (`security/context-update`), which adopts each by the continuity rule,
//!    stores and publishes it; every other node adopts them the same way at
//!    its next refresh, one after the other (a node that missed `N+1`
//!    follows the versions by name, `ndn_cert::follow_versions`). If the
//!    daemon refuses `N+1`, everything step 3 wrote is removed again. Once
//!    `N+2` is taken, the newest version is signed by the new root, so the
//!    root's fingerprint is the namespace's expected fingerprint again: the
//!    anchor link printed, and invites minted from then on, carry it.

use anyhow::{Context, Result, bail};
use ndn_cert::{
    OldRoot, anchor_fingerprint, kit_anchor, read_stored_context, recover_namespace_in_pib,
};
use ndn_mgmt::RefreshState;
use ndn_mgmt_wire::control_response::status;
use ndn_packet::Name;
use ndn_security::FilePib;
use ndn_trust_envelope::TrustEnvelope;

use crate::onboard::{flag, pib_dir};
use crate::recovery_kit::{KitSpec, hand_over, open_kit};

/// How long the CLI waits for the daemon to fetch the newest version.
const DAEMON_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Make the daemon hold the newest version of `namespace`, fetched by name;
/// returns that version, and whether a node confirmed it is the newest
/// (`false` only when nothing answered and `from_held` accepts the held one).
async fn fetch_newest(
    client: &ndn_ipc::MgmtClient,
    socket: &str,
    namespace: &Name,
    kit_fingerprint: Option<[u8; 32]>,
    from_held: bool,
) -> Result<(u64, bool)> {
    let resp = client
        .security_context_refresh(Some(namespace), DAEMON_FETCH_TIMEOUT)
        .await
        .with_context(|| format!("ask the daemon at {socket} for the newest version"))?;
    if resp.is_ok() {
        let results: Vec<ndn_mgmt::ContextRefreshInfo> = serde_json::from_str(&resp.status_text)
            .with_context(|| format!("unreadable answer from the daemon: {}", resp.status_text))?;
        let r = results
            .into_iter()
            .next()
            .context("the daemon answered no refresh result")?;
        return match r.state {
            RefreshState::Updated | RefreshState::Current | RefreshState::UpstreamOlder => {
                Ok((r.version, true))
            }
            RefreshState::Unreachable if from_held => Ok((r.held_version, false)),
            RefreshState::Unreachable => bail!(
                "{}. Recovering from the held v{} without knowing it is the newest could fork \
                 the namespace: \
                 give this device a face and a route toward a relay or member that holds it, \
                 then retry. If no other node holding {namespace} exists or can be reached, \
                 and you know no version newer than v{} was made, retry with --from-held",
                r.detail,
                r.held_version,
                r.held_version
            ),
            RefreshState::Source => bail!(
                "this device holds the root of {namespace} (`ndn-fwd root-key status`): it is \
                 the root device, nothing to recover"
            ),
            RefreshState::Failed => bail!(
                "could not get the newest trust context of {namespace} by name ({}). Recovering \
                 from v{} without knowing it is the newest would fork the namespace: make sure \
                 this device reaches the namespace (a face and a route toward a relay or member \
                 that holds it), then retry",
                r.detail,
                r.held_version
            ),
        };
    }
    if resp.status_code != status::NOT_FOUND {
        bail!(
            "the daemon at {socket} could not refresh {namespace} ({}): {}",
            resp.status_code,
            resp.status_text
        );
    }
    // Not held. A context fetched with nothing to check it against could be
    // a forgery that lists the kit's (public) anchor; the recovery key would
    // then sign it and every node would adopt it. Only a file kit carries
    // the namespace's expected fingerprint.
    let Some(fingerprint) = kit_fingerprint else {
        bail!(
            "this device's daemon holds no trust context for {namespace}. Adopt it first with \
             the namespace's anchor link (`ndn-fwd adopt <ndn-trust://anchor/…>`, the link \
             `ndn-fwd init` printed), so the version recovered from is authenticated, then \
             retry"
        );
    };
    let link = TrustEnvelope::Anchor {
        namespace: Some(namespace.to_string()),
        fingerprint: Some(fingerprint),
        version: None,
        context_data: None,
        context_content: None,
    }
    .to_uri();
    let resp = client
        .security_context_adopt(&link, DAEMON_FETCH_TIMEOUT)
        .await
        .with_context(|| format!("ask the daemon at {socket} to adopt {namespace}"))?;
    if !resp.is_ok() {
        bail!(
            "this device holds no trust context for {namespace}, and adopting it with the kit's \
             expected fingerprint failed ({}): {}. Adopt it with the namespace's anchor link \
             (`ndn-fwd adopt`), then retry",
            resp.status_code,
            resp.status_text
        );
    }
    let info: ndn_mgmt::AdoptedContextInfo = serde_json::from_str(&resp.status_text)
        .with_context(|| format!("unreadable answer from the daemon: {}", resp.status_text))?;
    Ok((info.version, true))
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
    if let Some(store) = ndn_cert::RootStore::open(&pib)? {
        bail!(
            "{} holds the root of {} ({} root store): this already is a root device. Recover \
             on a replacement device whose PIB holds no root",
            pib_dir.display(),
            store.namespace(),
            store.kind()
        );
    }

    // 1. The newest version, by name.
    let (client, socket) = crate::onboard::daemon(args, "recover").await?;
    let from_held = args.iter().any(|a| a == "--from-held");
    let (newest, confirmed) =
        fetch_newest(&client, &socket, &namespace, kit_fingerprint, from_held).await?;
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
    let recovery = open_kit(args, &spec, &namespace, &format!("Recovering {namespace}")).await?;
    let recovery_key = kit_anchor(
        &held,
        &recovery
            .public_key()
            .context("the kit's key reports no public key")?,
    )?;

    // 3. The new root device.
    let root = crate::root_key::new_root_store(args)?;
    let recovered = recover_namespace_in_pib(
        &pib,
        &held_data,
        recovery.as_ref(),
        &device,
        old_root,
        &root,
    )
    .await?;
    drop(root);
    let recovery_fp = held
        .anchor_for(&recovery_key)
        .map(|a| anchor_fingerprint(&a))
        .unwrap_or_default();
    drop(recovery);

    // 4. Hand N+1, then N+2, to the daemon.
    let handed = match hand_over(args, &pib_dir, &recovered.version.bump).await {
        Ok(handed) => handed,
        Err(e) => {
            recovered.undo(&pib);
            return Err(e.context(
                "the daemon did not take the recovered version; everything this command wrote \
                 to the PIB was removed again and nothing changed",
            ));
        }
    };
    // N+1 is the namespace's from here on (its new root is an anchor of
    // it): nothing is undone any more. N+2 makes the root the signer of the
    // newest version.
    let root_handed = hand_over(args, &pib_dir, &recovered.root_version).await;

    let v = &recovered.version;
    let next = v.bump.context.version();
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
        Err(e) => println!(
            "trust_context  = v{settled} (the same, signed by the new root) NOT taken: {e:#}"
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
    match old_root {
        OldRoot::Destroyed => {
            for key in &v.old_root_keys {
                println!("kept_anchor    = {key} (the old root; its certificates stay valid)");
            }
        }
        OldRoot::Compromised => {
            for key in &v.bump.added {
                println!("revoked        = {key}");
            }
        }
    }
    // The newest version's signer is what an anchor link's expected
    // fingerprint authenticates: the new root once it signed v{settled}.
    let (fingerprint, version, newest) = match &root_handed {
        Ok(_) => (
            anchor_fingerprint(&recovered.anchor),
            settled,
            &recovered.root_version.data,
        ),
        Err(_) => (recovery_fp, next, &v.bump.data),
    };
    let link = |context_data| TrustEnvelope::Anchor {
        namespace: Some(namespace.to_string()),
        fingerprint: Some(fingerprint),
        version: Some(version),
        context_data,
        context_content: None,
    };
    println!("anchor_uri     = {}", link(Some(newest.raw().clone())).to_uri());
    println!("anchor_uri_fp  = {}", link(None).to_uri());
    println!();
    println!("# Restart this device's daemon with these lines in ndn-fwd.toml, so it signs as its");
    println!(
        "# admin identity and runs the namespace CA (the endpoint stays {namespace}/CA); copy"
    );
    println!("# the [[ca.challenge]] set of the old root device (token and device-approval):");
    println!("[security]");
    println!("identity = \"{}\"", recovered.device_identity);
    println!("pib_path = \"{}\"", pib_abs.display());
    println!("[ca]");
    println!("enabled  = true");
    println!("prefix   = \"{namespace}\"");
    println!("identity = \"{namespace}/CA\"");
    println!();
    println!(
        "# Every other node adopts v{next} and v{settled} at its next refresh ([security]"
    );
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
                "# v{settled} was not taken, so the newest version is signed by the recovery key and"
            );
            println!(
                "# the anchor links carry its fingerprint. Run `ndn-fwd recovery-kit create` now: the"
            );
            println!(
                "# root signs that version, and its fingerprint ({root_fp}) becomes the namespace's"
            );
            println!("# expected fingerprint for anchor links and invites.");
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
    println!("# Create a new recovery kit now (`ndn-fwd recovery-kit create`); the kit used here");
    println!(
        "# stays a recovery anchor until `ndn-fwd recovery-kit revoke {}`.",
        v.recovery_key
    );
    Ok(())
}
