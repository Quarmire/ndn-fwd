//! `ndn-fwd recovery-kit create|list|check|revoke`: the recovery kits of a
//! namespace, the operator's side of [`ndn_cert::recovery`].
//!
//! A kit holds a separate **recovery key**, never a copy of the root. On the
//! root device, `create` makes the key (24 words shown once, a
//! passphrase-sealed file, or a key generated on a second YubiKey), and the
//! root — unlocked from its root store for this one signature — signs a new
//! version of the trust context that lists the key as a recovery anchor.
//! `revoke` signs a version without it, revoking its key. Both sign here, in
//! the CLI, and hand the version to the running daemon
//! (`security/context-update`), which adopts it under the continuity rule,
//! stores and publishes it; without a reachable daemon it is stored in
//! `<pib>/contexts/` for the daemon's next start. `list` and `check` read
//! the held context only and sign nothing.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use ndn_cert::context_update::ContextBump;
use ndn_cert::recovery::{DEFAULT_KIT_SLOT, KIT_PASSPHRASE_ENV, KIT_PIN_ENV, KIT_WORDS_ENV};
use ndn_cert::{
    FileKit, KitFormat, RecoverySeed, RootSecret, RootStore, YubikeyKit, add_recovery_anchor,
    anchor_fingerprint, kit_anchor, read_secret, read_stored_context, recovery_anchor,
    remove_recovery_anchor, seal_file_kit,
};
use ndn_packet::{Data, Name};
use ndn_security::{FilePib, KeyRole, SignedTrustContext, Signer};

use crate::onboard::{flag, pib_dir, positionals};

/// How long the CLI waits for the daemon to take a new version (local work:
/// verify, store, publish).
const DAEMON_UPDATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// A kit named on the command line: `words`, `yubikey`, or a kit file.
pub(crate) enum KitSpec {
    Words,
    Yubikey,
    File(PathBuf),
}

impl KitSpec {
    pub(crate) fn parse(s: &str) -> KitSpec {
        match s {
            "words" => KitSpec::Words,
            "yubikey" => KitSpec::Yubikey,
            path => KitSpec::File(PathBuf::from(path)),
        }
    }

    pub(crate) fn format(&self) -> KitFormat {
        match self {
            KitSpec::Words => KitFormat::Words,
            KitSpec::Yubikey => KitFormat::Yubikey,
            KitSpec::File(_) => KitFormat::File,
        }
    }
}

/// The token and slot of a YubiKey kit from the command line.
fn yubikey_kit(args: &[String]) -> Result<YubikeyKit> {
    Ok(YubikeyKit {
        serial: flag(args, &["--yubikey-serial"])
            .map(str::parse::<u32>)
            .transpose()
            .context("--yubikey-serial must be the token's serial number")?,
        slot: flag(args, &["--yubikey-slot"])
            .unwrap_or(DEFAULT_KIT_SLOT)
            .to_string(),
        touch_policy: flag(args, &["--touch-policy"])
            .unwrap_or("always")
            .to_string(),
    })
}

fn kit_passphrase(args: &[String], purpose: &str, confirm: bool) -> Result<RootSecret> {
    Ok(read_secret(
        Some(KIT_PASSPHRASE_ENV),
        "--kit-passphrase-file",
        flag(args, &["--kit-passphrase-file"]).map(Path::new),
        confirm,
        purpose,
        "recovery kit passphrase",
    )?)
}

fn kit_pin(args: &[String], purpose: &str) -> Result<RootSecret> {
    Ok(read_secret(
        Some(KIT_PIN_ENV),
        "--kit-pin-file",
        flag(args, &["--kit-pin-file"]).map(Path::new),
        false,
        purpose,
        "recovery kit YubiKey PIN",
    )?)
}

fn kit_words(args: &[String], purpose: &str) -> Result<RecoverySeed> {
    let words = read_secret(
        Some(KIT_WORDS_ENV),
        "--words-file",
        flag(args, &["--words-file"]).map(Path::new),
        false,
        purpose,
        "24 recovery words",
    )?;
    let words = std::str::from_utf8(words.expose()).context("the recovery words are not text")?;
    Ok(RecoverySeed::from_words(words)?)
}

/// Open the kit `spec` as the recovery key of `namespace` (asking for its
/// words, passphrase or PIN). Nothing is signed.
pub(crate) async fn open_kit(
    args: &[String],
    spec: &KitSpec,
    namespace: &Name,
    purpose: &str,
) -> Result<Arc<dyn Signer>> {
    Ok(match spec {
        KitSpec::Words => Arc::new(kit_words(args, purpose)?.signer(namespace)),
        KitSpec::File(path) => {
            let kit = FileKit::read(path)?;
            if kit.namespace != *namespace {
                bail!(
                    "{} is a recovery kit for {}, not {namespace}",
                    path.display(),
                    kit.namespace
                );
            }
            Arc::new(kit.open(&kit_passphrase(args, purpose, false)?)?)
        }
        KitSpec::Yubikey => {
            yubikey_kit(args)?
                .signer(namespace, &kit_pin(args, purpose)?)
                .await?
        }
    })
}

/// The namespace a command acts on: `--namespace`, else the one a file kit
/// names, else the only context this PIB holds.
pub(crate) fn kit_namespace(
    args: &[String],
    spec: Option<&KitSpec>,
    pib_dir: &Path,
) -> Result<Name> {
    if let Some(ns) = flag(args, &["--namespace"]) {
        return ns
            .parse()
            .map_err(|e| anyhow::anyhow!("--namespace {ns:?} is not an NDN name: {e}"));
    }
    if let Some(KitSpec::File(path)) = spec {
        return Ok(FileKit::read(path)?.namespace);
    }
    let held: Vec<Name> = ndn_cert::read_stored_contexts(pib_dir)?
        .into_iter()
        .filter_map(|(_, r)| r.ok().map(|(ctx, _)| ctx.namespace().clone()))
        .collect();
    match held.as_slice() {
        [one] => Ok(one.clone()),
        [] => bail!(
            "{} holds no trust context; pass --namespace <ns>",
            pib_dir.display()
        ),
        _ => bail!(
            "{} holds several trust contexts; pass --namespace <ns>",
            pib_dir.display()
        ),
    }
}

/// The context this PIB holds for `namespace`, as stored.
fn held(pib_dir: &Path, namespace: &Name) -> Result<(SignedTrustContext, Data)> {
    read_stored_context(pib_dir, namespace)?.with_context(|| {
        format!(
            "{} holds no trust context for {namespace} (adopt it first: ndn-fwd adopt <link>)",
            pib_dir.display()
        )
    })
}

/// This PIB's root store and the context it is the root of.
fn root_device(pib: &FilePib, pib_dir: &Path) -> Result<(RootStore, SignedTrustContext, Data)> {
    let store = RootStore::open(pib)?.with_context(|| {
        format!(
            "{} holds no namespace root: recovery kits are made and revoked on the root device \
             (where `ndn-fwd init` ran, or a device that ran `ndn-fwd recover`)",
            pib_dir.display()
        )
    })?;
    let (ctx, data) = held(pib_dir, store.namespace())?;
    if !store.holds_anchor_of(&ctx) {
        bail!(
            "the root key {} of this PIB is not an anchor of the held trust context of {} (v{}): \
             this is no longer the root device of the namespace",
            store.key_name(),
            store.namespace(),
            ctx.version()
        );
    }
    Ok((store, ctx, data))
}

/// Hand a version signed here to the running daemon, which adopts it by the
/// continuity rule, stores and publishes it; with no daemon reachable, store
/// it for the daemon's next start. Returns what happened.
pub(crate) async fn hand_over(
    args: &[String],
    pib_dir: &Path,
    bump: &ContextBump,
) -> Result<String> {
    let socket = crate::onboard::face_socket(args)?;
    match ndn_ipc::MgmtClient::connect(&socket).await {
        Ok(client) => {
            let resp = client
                .security_context_update(bump.data.raw().clone(), DAEMON_UPDATE_TIMEOUT)
                .await
                .with_context(|| {
                    format!("hand v{} to the daemon at {socket}", bump.context.version())
                })?;
            if !resp.is_ok() {
                bail!(
                    "the daemon at {socket} refused v{} ({}): {}",
                    bump.context.version(),
                    resp.status_code,
                    resp.status_text
                );
            }
            let info: ndn_mgmt::ContextRefreshInfo = serde_json::from_str(&resp.status_text)
                .with_context(|| {
                    format!("unreadable answer from the daemon: {}", resp.status_text)
                })?;
            Ok(format!("the daemon at {socket} {}", info.detail))
        }
        Err(_) => {
            let path = ndn_cert::persist_context(pib_dir, &bump.context, &bump.data)?;
            Ok(format!(
                "no daemon at {socket}: stored {}; the daemon loads and publishes it when it \
                 starts",
                path.display()
            ))
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
             create --format words|file|yubikey [--out <path>] | list [--namespace <ns>] | check \
             words|yubikey|<kit-file> [--namespace <ns>] | revoke <recovery-key-name> \
             (each takes --pib <dir> or -c <config>)"
        ),
    }
}

async fn create(args: &[String]) -> Result<()> {
    let format: KitFormat = flag(args, &["--format"])
        .context("recovery-kit create needs --format words|file|yubikey")?
        .parse()
        .map_err(|e| anyhow::anyhow!("--format: {e}"))?;
    let out = match format {
        KitFormat::File => {
            let out = PathBuf::from(
                flag(args, &["--out"]).context("a file kit needs --out <path> to write it to")?,
            );
            if out.exists() {
                bail!("{} exists; refusing to overwrite a kit", out.display());
            }
            Some(out)
        }
        _ => None,
    };
    let pib_dir = pib_dir(args)?;
    let pib =
        FilePib::open(&pib_dir).with_context(|| format!("open PIB at {}", pib_dir.display()))?;
    let (store, ctx, held_data) = root_device(&pib, &pib_dir)?;
    let namespace = store.namespace().clone();
    let purpose = format!("Creating a recovery kit for {namespace}");

    // The recovery key: in memory (words, file) or on the token.
    let (seed, signer, location): (Option<RecoverySeed>, Arc<dyn Signer>, String) = match format {
        KitFormat::Words | KitFormat::File => {
            let seed = RecoverySeed::generate()?;
            let signer = Arc::new(seed.signer(&namespace));
            (Some(seed), signer, format.to_string())
        }
        KitFormat::Yubikey => {
            let kit = yubikey_kit(args)?;
            let pin = kit_pin(args, &purpose)?;
            let (signer, serial) = kit.generate(&namespace, &pin).await?;
            (
                None,
                signer,
                format!("YubiKey {serial}, PIV slot {}", kit.slot),
            )
        }
    };
    let anchor = recovery_anchor(Arc::clone(&signer)).await?;
    drop(signer);
    let key = anchor.key_name();

    // A file kit is written before the root signs, and removed again if the
    // new version does not land: no anchor without its kit.
    if let (Some(out), Some(seed)) = (&out, &seed) {
        let passphrase = kit_passphrase(args, "Sealing the recovery kit", true)?;
        let root_fp = ctx
            .anchors()
            .iter()
            .find(|a| {
                ndn_cert::root_store::same_public_key(&a.value().public_key, store.public_key())
            })
            .map(|a| anchor_fingerprint(a.value()));
        let uri = seal_file_kit(seed, &anchor, &namespace, root_fp, &passphrase)?;
        ndn_security::secure_fs::write_private(out, format!("{uri}\n"))
            .with_context(|| format!("write {}", out.display()))?;
    }
    let remove_out = || {
        if let Some(out) = &out {
            let _ = std::fs::remove_file(out);
        }
    };

    let signed = async {
        let unlock = crate::root_key::operator_secret(
            args,
            store.unlock_kind(),
            &format!("Adding a recovery kit to {namespace} signs a new trust context version"),
            false,
        )?;
        let root = store.signer(unlock.as_ref()).await?;
        drop(unlock);
        let bump = add_recovery_anchor(root.as_ref(), &held_data, &anchor).await?;
        let handed = hand_over(args, &pib_dir, &bump).await?;
        anyhow::Ok((bump, handed))
    }
    .await;
    let (bump, handed) = match signed {
        Ok(done) => done,
        Err(e) => {
            remove_out();
            return Err(e.context("no recovery kit was added; the trust context is unchanged"));
        }
    };
    let kits = bump
        .context
        .keys_with_role(KeyRole::RECOVERY_ANCHOR)
        .count();

    println!("# ndn-fwd recovery-kit create ({format})");
    println!("namespace      = {namespace}");
    println!("recovery_key   = {key}");
    println!("fingerprint    = {}", hex(&anchor_fingerprint(&anchor)));
    println!("kit            = {location}");
    println!(
        "trust_context  = v{} -> v{} (signed by the root {})",
        ctx.version(),
        bump.context.version(),
        store.key_name()
    );
    println!("handed_over    = {handed}");
    println!("recovery_kits  = {kits}");
    println!();
    match format {
        KitFormat::Words => {
            let seed = seed.expect("a word kit has a seed");
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
    let mut shown = 0;
    for (path, read) in ndn_cert::read_stored_contexts(&pib_dir)? {
        let (ctx, _) = match read {
            Ok(held) => held,
            Err(e) => {
                eprintln!("skipping {}: {e}", path.display());
                continue;
            }
        };
        if only.as_ref().is_some_and(|ns| ns != ctx.namespace()) {
            continue;
        }
        shown += 1;
        println!("namespace      = {} (v{})", ctx.namespace(), ctx.version());
        let mut anchors: Vec<_> = ctx.anchors().iter().map(|a| a.value().clone()).collect();
        anchors.sort_by_key(|a| a.name.to_string());
        let mut kits = 0;
        for anchor in &anchors {
            let key = anchor.key_name();
            let role = if ctx.has_key_role(&key, KeyRole::RECOVERY_ANCHOR) {
                kits += 1;
                "recovery-kit"
            } else {
                "root"
            };
            println!(
                "{role:<14} = {key} (fingerprint {})",
                hex(&anchor_fingerprint(anchor))
            );
        }
        for key in ctx.keys_with_role(KeyRole::ROOT_DEVICE) {
            println!("root-device    = {key}");
        }
        println!("recovery_kits  = {kits}");
        println!();
    }
    if shown == 0 {
        println!("# {} holds no matching trust context", pib_dir.display());
    }
    Ok(())
}

async fn check(args: &[String]) -> Result<()> {
    let positional = positionals(args);
    let spec =
        KitSpec::parse(positional.get(1).context(
            "recovery-kit check needs the kit: words, yubikey, or the path of a kit file",
        )?);
    let pib_dir = pib_dir(args)?;
    let namespace = kit_namespace(args, Some(&spec), &pib_dir)?;
    let (ctx, _) = held(&pib_dir, &namespace)?;
    let signer = open_kit(
        args,
        &spec,
        &namespace,
        &format!("Checking a recovery kit of {namespace}"),
    )
    .await?;
    let public_key = signer
        .public_key()
        .context("the kit's key reports no public key")?;
    let key = kit_anchor(&ctx, &public_key)?;
    println!("# ndn-fwd recovery-kit check ({})", spec.format());
    println!("namespace      = {namespace}");
    println!("recovery_key   = {key}");
    println!(
        "ok             = the kit opens, and its key is a recovery anchor of the held trust \
         context v{} (nothing was signed)",
        ctx.version()
    );
    Ok(())
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
    let pib =
        FilePib::open(&pib_dir).with_context(|| format!("open PIB at {}", pib_dir.display()))?;
    let (store, ctx, held_data) = root_device(&pib, &pib_dir)?;
    let namespace = store.namespace().clone();
    if !ctx.has_key_role(&key, KeyRole::RECOVERY_ANCHOR) {
        bail!(
            "{key} is not a recovery kit of {namespace} v{} (`ndn-fwd recovery-kit list` shows \
             them); nothing was signed",
            ctx.version()
        );
    }
    let unlock = crate::root_key::operator_secret(
        args,
        store.unlock_kind(),
        &format!("Revoking the recovery kit {key} signs a new trust context version"),
        false,
    )?;
    let root = store.signer(unlock.as_ref()).await?;
    drop(unlock);
    let bump = remove_recovery_anchor(root.as_ref(), &held_data, &key).await?;
    drop(root);
    let handed = hand_over(args, &pib_dir, &bump).await?;
    println!("# ndn-fwd recovery-kit revoke");
    println!("namespace      = {namespace}");
    println!("revoked_key    = {key}");
    println!(
        "trust_context  = v{} -> v{} (signed by the root {})",
        ctx.version(),
        bump.context.version(),
        store.key_name()
    );
    println!("handed_over    = {handed}");
    println!(
        "recovery_kits  = {}",
        bump.context
            .keys_with_role(KeyRole::RECOVERY_ANCHOR)
            .count()
    );
    println!();
    println!("# The kit is no longer an anchor and its key is revoked: once a node holds");
    println!(
        "# v{}, a version the kit signs is refused there.",
        bump.context.version()
    );
    Ok(())
}
