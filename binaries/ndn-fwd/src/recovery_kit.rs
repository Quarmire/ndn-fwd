//! `ndn-fwd recovery-kit create|list|check|revoke`: the recovery kits of a
//! namespace — the CLI over [`ndn_namespace::root::kit`].
//!
//! A kit holds a separate **recovery key**, never a copy of the root. On the
//! root device, `create` makes the key (24 words shown once, a
//! passphrase-sealed file, or a key generated on a second YubiKey), and the
//! root — unlocked from its root store for this one signature — signs a new
//! version of the trust context that lists the key as a recovery anchor.
//! `revoke` signs a version without it, revoking its key. Both sign here, in
//! the CLI, and hand the version to the running daemon that uses the same
//! PIB (`security/context-update`), which adopts it under the continuity
//! rule, stores and publishes it; when no daemon listens on the socket it
//! is stored in `<pib>/contexts/` for the daemon's next start. `list` and
//! `check` read the held context only and sign nothing. A PIB holding the
//! roots of several trusted prefixes names the one with `--namespace`
//! (`revoke` without it acts on the prefix covering the recovery key).
//!
//! A YubiKey kit's token is selected with `--kit-yubikey-serial` /
//! `--kit-yubikey-slot` (`--yubikey-*` always mean the root's token), and is
//! never the root's own token or an occupied slot unless `--replace-slot`
//! says the slot's key is not needed ([`ndn_cert::SlotGuard`]).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ndn_cert::recovery::DEFAULT_KIT_SLOT;
use ndn_cert::report::code;
use ndn_cert::{KitFormat, YubikeyKit};
use ndn_namespace::hex;
use ndn_namespace::root::RootError;
use ndn_namespace::root::kit::{self, KitLocation, KitRequest, KitSpec};
use ndn_packet::Name;

use crate::onboard::{flag, pib_dir, positionals};
use crate::root_host::{Daemon, Secrets, handed_text, listed, namespace_arg, render};

/// A kit named on the command line: `words`, `yubikey` (the token and slot
/// of `--kit-yubikey-*`), or a kit file.
pub(crate) fn kit_spec(args: &[String], s: &str) -> Result<KitSpec> {
    Ok(match s {
        "words" => KitSpec::Words,
        "yubikey" => KitSpec::Yubikey(yubikey_kit(args)?),
        path => KitSpec::File(PathBuf::from(path)),
    })
}

/// The token and slot of a YubiKey kit from the command line.
fn yubikey_kit(args: &[String]) -> Result<YubikeyKit> {
    Ok(YubikeyKit {
        serial: flag(args, &["--kit-yubikey-serial"])
            .map(str::parse::<u32>)
            .transpose()
            .context("--kit-yubikey-serial must be the kit token's serial number")?,
        slot: flag(args, &["--kit-yubikey-slot"])
            .unwrap_or(DEFAULT_KIT_SLOT)
            .to_string(),
        touch_policy: flag(args, &["--kit-touch-policy"])
            .unwrap_or("always")
            .to_string(),
    })
}

/// `ndn-fwd recovery-kit …`.
pub(crate) async fn run(args: &[String]) -> Result<()> {
    match positionals(args).first().copied() {
        Some("create") => create(args).await,
        Some("list") => list(args),
        Some("check") => check(args).await,
        Some("revoke") => revoke(args).await,
        other => bail!(
            "unknown `ndn-fwd recovery-kit` command {other:?}; usage: ndn-fwd recovery-kit \
             create --format words|file|yubikey [--out <path>] [--namespace <prefix>] | list \
             [--namespace <prefix>] | check words|yubikey|<kit-file> [--namespace <prefix>] | \
             revoke <recovery-key-name> [--namespace <prefix>] (each takes --pib <dir> or -c \
             <config>; --namespace names the trusted prefix when the PIB holds several roots)"
        ),
    }
}

/// A refused `create`, as the CLI says it.
fn create_refused(e: RootError) -> anyhow::Error {
    if e.is(code::KIT_FILE_EXISTS) {
        return anyhow::anyhow!(
            "{} exists; refusing to overwrite a kit",
            e.param("path").unwrap_or_default()
        );
    }
    if e.is(code::KIT_NOT_ADDED) {
        return render(e).context("no recovery kit was added; the trust context is unchanged");
    }
    render(e)
}

async fn create(args: &[String]) -> Result<()> {
    let format: KitFormat = flag(args, &["--format"])
        .context("recovery-kit create needs --format words|file|yubikey")?
        .parse()
        .map_err(|e| anyhow::anyhow!("--format: {e}"))?;
    let out = match format {
        KitFormat::File => Some(PathBuf::from(
            flag(args, &["--out"]).context("a file kit needs --out <path> to write it to")?,
        )),
        _ => None,
    };
    let yubikey = match format {
        KitFormat::Yubikey => yubikey_kit(args)?,
        _ => YubikeyKit {
            serial: None,
            slot: DEFAULT_KIT_SLOT.to_string(),
            touch_policy: "always".to_string(),
        },
    };
    let pib_dir = pib_dir(args)?;
    let daemon = Daemon::new(args, &pib_dir);
    let created = kit::create(
        KitRequest {
            pib_dir: pib_dir.clone(),
            namespace: namespace_arg(args)?,
            format,
            out: out.clone(),
            yubikey,
            replace_slot: args.iter().any(|a| a == "--replace-slot"),
        },
        &daemon,
        &Secrets { args },
    )
    .await
    .map_err(create_refused)?;
    let kit::KitCreated {
        namespace,
        key,
        fingerprint,
        kit,
        words,
        held_version,
        version,
        root_key,
        handed,
        ..
    } = created;
    let handed = match handed {
        Ok(taken) => Some(taken),
        // The version listing the kit may still be adopted: the kit is kept
        // and shown, so no anchor is left without its kit.
        Err(unknown) => {
            eprintln!("warning: {:#}", render(unknown));
            None
        }
    };
    let location = match &kit {
        KitLocation::Words => "words".to_string(),
        KitLocation::File(_) => "file".to_string(),
        KitLocation::Yubikey { serial, slot } => format!("YubiKey {serial}, PIV slot {slot}"),
    };

    println!("# ndn-fwd recovery-kit create ({format})");
    println!("namespace      = {namespace}");
    println!("recovery_key   = {key}");
    println!("fingerprint    = {}", hex(&fingerprint));
    println!("kit            = {location}");
    match &handed {
        Some((handed, kits)) => {
            println!(
                "trust_context  = v{held_version} -> v{version} (signed by the root {root_key})"
            );
            println!(
                "handed_over    = {}",
                handed_text(handed, &daemon, version, &pib_dir)
            );
            println!("recovery_kits  = {kits}");
        }
        None => {
            println!(
                "trust_context  = v{held_version} -> v{version} (signed by the root {root_key}): \
                 NOT KNOWN whether the daemon adopted it"
            );
            println!(
                "# The kit is kept, as that version may still be adopted. `ndn-fwd recovery-kit \
                 list --pib {}` lists {key} once it is; if it does not once the daemon is idle \
                 (or restarted), this kit is no anchor: discard it and create another.",
                pib_dir.display()
            );
        }
    }
    println!();
    match format {
        KitFormat::Words => {
            let seed = words.as_ref().expect("a word kit has a seed");
            let words = seed.to_words();
            println!(
                "# Write these 24 words down, in order, and keep them offline. They are shown"
            );
            println!("# once: nothing about them is stored. Whoever holds them can take over");
            println!("# {namespace} (a recovery key is root-equivalent). The last word carries a");
            println!("# checksum, so a mistyped word is refused rather than used.");
            for (i, word) in words.split(' ').enumerate() {
                println!("  {:>2}. {word}", i + 1);
            }
        }
        KitFormat::File => {
            let out = out.as_ref().expect("a file kit has --out");
            println!(
                "# The kit is {} (owner-only): the recovery key sealed by your kit",
                out.display()
            );
            println!(
                "# passphrase, with the namespace and its expected fingerprint. Keep it offline"
            );
            println!(
                "# and the passphrase apart from it; without the passphrase it opens nothing."
            );
        }
        KitFormat::Yubikey => {
            println!(
                "# The recovery key was generated on the token and never leaves it; recovering"
            );
            println!(
                "# needs this token and its PIN (and a touch). Keep it apart from the root device."
            );
        }
    }
    println!("# Check the kit now, and from time to time:");
    println!(
        "#   ndn-fwd recovery-kit check {} --namespace {namespace} --pib {}",
        match (&format, &out) {
            (KitFormat::File, Some(out)) => out.display().to_string(),
            _ => format.to_string(),
        },
        pib_dir.display()
    );
    Ok(())
}

fn list(args: &[String]) -> Result<()> {
    let pib_dir = pib_dir(args)?;
    let only: Option<Name> = flag(args, &["--namespace"])
        .map(|ns| ns.parse())
        .transpose()
        .map_err(|e| anyhow::anyhow!("--namespace: {e}"))?;
    let listed = kit::list(&pib_dir, only.as_ref()).map_err(render)?;
    for (path, e) in &listed.skipped {
        eprintln!("skipping {}: {e}", path.display());
    }
    for ctx in &listed.contexts {
        println!("namespace      = {} (v{})", ctx.namespace, ctx.version);
        for anchor in &ctx.anchors {
            let role = if anchor.recovery_kit {
                "recovery-kit"
            } else {
                "root"
            };
            println!(
                "{role:<14} = {} (fingerprint {})",
                anchor.key,
                hex(&anchor.fingerprint)
            );
        }
        for key in &ctx.root_device_keys {
            println!("root-device    = {key}");
        }
        println!("recovery_kits  = {}", ctx.recovery_kits);
        println!();
    }
    if listed.contexts.is_empty() {
        println!("# {} holds no matching trust context", pib_dir.display());
    }
    Ok(())
}

async fn check(args: &[String]) -> Result<()> {
    let positional = positionals(args);
    let spec = kit_spec(
        args,
        positional.get(1).context(
            "recovery-kit check needs the kit: words, yubikey, or the path of a kit file",
        )?,
    )?;
    let pib_dir = pib_dir(args)?;
    let namespace = namespace_arg(args)?;
    let checked = kit::check(&pib_dir, &spec, namespace.as_ref(), &Secrets { args })
        .await
        .map_err(render)?;
    println!("# ndn-fwd recovery-kit check ({})", checked.format);
    println!("namespace      = {}", checked.namespace);
    println!("recovery_key   = {}", checked.key);
    println!(
        "ok             = the kit opens, and its key is a recovery anchor of the held trust \
         context v{} (nothing was signed)",
        checked.version
    );
    Ok(())
}

/// A refused `revoke` of the kit `key`, as the CLI says it.
fn revoke_refused(e: RootError, key: &Name, pib_dir: &Path) -> anyhow::Error {
    let p = |param| e.param(param).unwrap_or_default().to_string();
    if e.is(code::REVOKE_OUTSIDE_NAMESPACE) {
        return anyhow::anyhow!(
            "{key} is not in a trusted prefix whose root this device holds ({}): {} on the root \
             device of its prefix",
            listed(e.param("namespace")),
            p("operation")
        );
    }
    if e.is(code::NOT_A_RECOVERY_KIT) {
        return anyhow::anyhow!(
            "{key} is not a recovery kit of {} v{} (`ndn-fwd recovery-kit list` shows them); \
             nothing was signed",
            p("namespace"),
            p("version")
        );
    }
    if e.is(code::VERSION_NOT_TAKEN) {
        return render(e).context("the kit was not revoked; the trust context is unchanged");
    }
    if e.is(code::HAND_OVER_UNKNOWN) {
        let version = p("version");
        return render(e).context(format!(
            "whether the daemon adopted v{version} (without the kit) is not known: `ndn-fwd \
             recovery-kit list --pib {}` stops listing {key} once it did; if it still lists it \
             once the daemon is idle, revoke it again",
            pib_dir.display()
        ));
    }
    render(e)
}

async fn revoke(args: &[String]) -> Result<()> {
    let positional = positionals(args);
    let target = positional
        .get(1)
        .context("recovery-kit revoke needs the recovery key name (`ndn-fwd recovery-kit list`)")?;
    let key: Name = target
        .parse()
        .map_err(|e| anyhow::anyhow!("{target:?} is not an NDN name: {e}"))?;
    let pib_dir = pib_dir(args)?;
    let namespace = namespace_arg(args)?;
    let daemon = Daemon::new(args, &pib_dir);
    let revoked = kit::revoke(
        &pib_dir,
        &key,
        namespace.as_ref(),
        &daemon,
        &Secrets { args },
    )
    .await
    .map_err(|e| revoke_refused(e, &key, &pib_dir))?;
    println!("# ndn-fwd recovery-kit revoke");
    println!("namespace      = {}", revoked.namespace);
    println!("revoked_key    = {key}");
    println!(
        "trust_context  = v{} -> v{} (signed by the root {})",
        revoked.held_version, revoked.version, revoked.root_key
    );
    println!(
        "handed_over    = {}",
        handed_text(&revoked.handed_over, &daemon, revoked.version, &pib_dir)
    );
    println!("recovery_kits  = {}", revoked.recovery_kits);
    println!();
    println!("# The kit is no longer an anchor and its key is revoked: once a node holds");
    println!(
        "# v{}, a version the kit signs is refused there.",
        revoked.version
    );
    Ok(())
}
