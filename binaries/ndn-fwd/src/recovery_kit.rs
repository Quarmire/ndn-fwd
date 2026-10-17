//! `ndn-fwd recovery-kit create|list|check|revoke`: the recovery kits of a
//! namespace, the operator's side of [`ndn_cert::recovery`].
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
//! `check` read the held context only and sign nothing.
//!
//! A YubiKey kit's token is selected with `--kit-yubikey-serial` /
//! `--kit-yubikey-slot` (`--yubikey-*` always mean the root's token), and is
//! never the root's own token or an occupied slot unless `--replace-slot`
//! says the slot's key is not needed ([`ndn_cert::SlotGuard`]).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use ndn_cert::context_update::ContextBump;
use ndn_cert::recovery::{DEFAULT_KIT_SLOT, KIT_PASSPHRASE_ENV, KIT_PIN_ENV, KIT_WORDS_ENV};
use ndn_cert::{
    FileKit, KitFormat, RecoverySeed, RootSecret, RootStore, SlotGuard, YubikeyKit,
    add_recovery_anchor, anchor_fingerprint, kit_anchor, read_secret, read_stored_context,
    recovery_anchor, remove_recovery_anchor, seal_file_kit,
};
use ndn_packet::{Data, Name};
use ndn_security::{FilePib, KeyRole, SignedTrustContext, Signer};

use crate::onboard::{flag, pib_dir, positionals};

/// How long one request waits for the daemon to take a new version (local
/// work: verify, store, publish — after any other change of the namespace
/// running there). Without an answer the same version is handed over again;
/// the answer to that one says what became of it.
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
/// words, passphrase or PIN). Nothing is signed. Returns the key and, for a
/// YubiKey kit, its token's serial.
pub(crate) async fn open_kit(
    args: &[String],
    spec: &KitSpec,
    namespace: &Name,
    purpose: &str,
) -> Result<(Arc<dyn Signer>, Option<u32>)> {
    Ok(match spec {
        KitSpec::Words => (Arc::new(kit_words(args, purpose)?.signer(namespace)), None),
        KitSpec::File(path) => {
            let kit = FileKit::read(path)?;
            if kit.namespace != *namespace {
                bail!(
                    "{} is a recovery kit for {}, not {namespace}",
                    path.display(),
                    kit.namespace
                );
            }
            (Arc::new(kit.open(&kit_passphrase(args, purpose, false)?)?), None)
        }
        KitSpec::Yubikey => {
            let (signer, serial) = yubikey_kit(args)?
                .signer(namespace, &kit_pin(args, purpose)?)
                .await?;
            (signer, Some(serial))
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

/// This PIB's root store and the context it is the root of. `work` says what
/// is done only on the root device, for the refusal on any other device.
pub(crate) fn root_device(
    pib: &FilePib,
    pib_dir: &Path,
    work: &str,
) -> Result<(RootStore, SignedTrustContext, Data)> {
    let store = RootStore::open(pib)?.with_context(|| {
        format!(
            "{} holds no namespace root: {work} on the root device (where `ndn-fwd init` ran, \
             or a device that ran `ndn-fwd recover`)",
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

/// Why a version handed to the daemon ([`hand_over`]) was not taken.
pub(crate) enum NotTaken {
    /// Nothing was handed over, or the daemon answered that it did not
    /// adopt it: nothing changed there, so what was made for the version
    /// may be undone.
    Refused(anyhow::Error),
    /// Handed over, and no answer says what became of it: the daemon may
    /// still adopt it, so nothing made for it may be undone.
    Unknown(anyhow::Error),
}

/// How many transport failures in a row, other than a wait without an
/// answer, end a hand-over as [`NotTaken::Unknown`].
const HAND_OVER_FAILURES: usize = 2;

/// Hand a version signed here to the running daemon that uses `pib_dir`,
/// which adopts it by the continuity rule, stores and publishes it. With no
/// daemon listening on the socket, store it in `pib_dir` for the daemon's
/// next start. Returns what happened.
///
/// The outcome comes from the daemon's answer, never from a timeout: a
/// request it does not answer in time (it may be busy with another change
/// of the namespace) is made again with the same version, which it answers
/// once that version is decided — taken (`200`, also when it took it
/// already) or refused. A daemon that stopped meanwhile left on disk what
/// it took.
pub(crate) async fn hand_over(
    args: &[String],
    pib_dir: &Path,
    bump: &ContextBump,
) -> Result<String, NotTaken> {
    let version = bump.context.version();
    let socket = crate::onboard::face_socket(args).map_err(NotTaken::Refused)?;
    let mut sent = false;
    let mut failures = 0;
    loop {
        let unsure = |e: anyhow::Error| {
            if sent {
                NotTaken::Unknown(e)
            } else {
                NotTaken::Refused(e)
            }
        };
        let client = match ndn_ipc::MgmtClient::connect(&socket).await {
            Ok(client) => client,
            Err(ndn_ipc::ForwarderError::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                return keep_for_next_start(pib_dir, bump, &socket).map_err(unsure);
            }
            Err(e) => {
                return Err(unsure(anyhow::anyhow!(
                    "cannot use the daemon's socket {socket} ({e}): run this as a user the \
                     daemon accepts, or pass -c with the config of the daemon that uses {}",
                    pib_dir.display()
                )));
            }
        };
        ensure_daemon_pib(&client, &socket, pib_dir)
            .await
            .map_err(unsure)?;
        sent = true;
        let failure = match client
            .security_context_update(bump.data.raw().clone(), DAEMON_UPDATE_TIMEOUT)
            .await
        {
            Ok(resp) if resp.is_ok() => {
                let info: ndn_mgmt::ContextRefreshInfo = serde_json::from_str(&resp.status_text)
                    .map_err(|e| {
                        NotTaken::Unknown(anyhow::anyhow!(
                            "the daemon at {socket} answered for v{version} unreadably ({e}): {}",
                            resp.status_text
                        ))
                    })?;
                return Ok(format!("the daemon at {socket} {}", info.detail));
            }
            Ok(resp) => {
                return Err(NotTaken::Refused(anyhow::anyhow!(
                    "the daemon at {socket} did not take v{version} ({}): {}",
                    resp.status_code,
                    resp.status_text
                )));
            }
            Err(ndn_ipc::ForwarderError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut => {
                eprintln!(
                    "# no answer yet from the daemon at {socket} on v{version} (another change \
                     of the namespace may be running there); asking again with the same version"
                );
                failures = 0;
                continue;
            }
            Err(e) => e,
        };
        failures += 1;
        if failures >= HAND_OVER_FAILURES {
            return Err(NotTaken::Unknown(anyhow::anyhow!(
                "handing v{version} to the daemon at {socket} failed without an answer \
                 ({failure})"
            )));
        }
    }
}

/// No daemon listens on `socket`: keep `bump` in `pib_dir` for the next
/// start — unless a daemon took it before it stopped (it is stored already).
fn keep_for_next_start(pib_dir: &Path, bump: &ContextBump, socket: &str) -> Result<String> {
    let version = bump.context.version();
    let stored = ndn_cert::read_stored_versions(pib_dir, bump.context.namespace())?
        .into_iter()
        .find_map(|(path, read)| {
            read.ok()
                .is_some_and(|(_, data)| data.raw() == bump.data.raw())
                .then_some(path)
        });
    let path = match stored {
        Some(path) => path,
        None => ndn_cert::persist_context(pib_dir, &bump.context, &bump.data)?,
    };
    Ok(format!(
        "no daemon listens at {socket}: v{version} is stored in {}; (re)start the daemon that \
         uses {} so it loads, adopts and publishes it (one running with another socket keeps \
         the version before until it restarts)",
        path.display(),
        pib_dir.display()
    ))
}

/// The PIB directory a daemon reports (`security/identity-status`,
/// `pib_path=`).
async fn daemon_pib(client: &ndn_ipc::MgmtClient, socket: &str) -> Result<PathBuf> {
    let resp = client
        .security_identity_status()
        .await
        .with_context(|| format!("ask the daemon at {socket} which PIB it uses"))?;
    resp.is_ok()
        .then(|| {
            resp.status_text
                .split_whitespace()
                .find_map(|field| field.strip_prefix("pib_path="))
        })
        .flatten()
        .map(PathBuf::from)
        .with_context(|| {
            format!(
                "the daemon at {socket} does not say which PIB it uses ({}): {}",
                resp.status_code, resp.status_text
            )
        })
}

/// Refuse unless the daemon at `socket` uses `pib_dir`: a version made from
/// the context stored there, handed to a daemon of another PIB holding the
/// same namespace, would be adopted there while this PIB stays behind — and
/// the next version made here would be a second, different one with the
/// same number.
pub(crate) async fn ensure_daemon_pib(
    client: &ndn_ipc::MgmtClient,
    socket: &str,
    pib_dir: &Path,
) -> Result<()> {
    let theirs = daemon_pib(client, socket).await?;
    let canonical = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    if canonical(&theirs) != canonical(pib_dir) {
        bail!(
            "the daemon at {socket} uses the PIB {}, not {}: what is made here from {} must go \
             to the daemon that uses it. Pass -c with that daemon's config (its [management] \
             face_socket), or --pib {} to work on the PIB of the daemon at {socket}",
            theirs.display(),
            pib_dir.display(),
            pib_dir.display(),
            theirs.display()
        );
    }
    Ok(())
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
    let (store, ctx, held_data) =
        root_device(&pib, &pib_dir, "recovery kits are made and revoked")?;
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
            // Never on the root's own token (one lost token would lose both),
            // never over a slot's key unless the operator says it is unneeded.
            let guard = SlotGuard {
                replace: args.iter().any(|a| a == "--replace-slot"),
                not_on: store
                    .yubikey()
                    .map(|y| (y.serial, format!("the root of {namespace}"))),
            };
            let (signer, serial) = kit.generate(&namespace, &pin, &guard).await?;
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
        anyhow::Ok(add_recovery_anchor(root.as_ref(), &held_data, &anchor).await?)
    }
    .await
    .map_err(NotTaken::Refused);
    let handed = match signed {
        Ok(bump) => hand_over(args, &pib_dir, &bump).await.map(|h| (bump, h)),
        Err(e) => Err(e),
    };
    let taken = match handed {
        Ok(done) => Some(done),
        Err(NotTaken::Refused(e)) => {
            remove_out();
            return Err(e.context("no recovery kit was added; the trust context is unchanged"));
        }
        // The version listing the kit may still be adopted: the kit is kept
        // and shown, so no anchor is left without its kit.
        Err(NotTaken::Unknown(e)) => {
            eprintln!("warning: {e:#}");
            None
        }
    };

    println!("# ndn-fwd recovery-kit create ({format})");
    println!("namespace      = {namespace}");
    println!("recovery_key   = {key}");
    println!("fingerprint    = {}", hex(&anchor_fingerprint(&anchor)));
    println!("kit            = {location}");
    match &taken {
        Some((bump, handed)) => {
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
        }
        None => {
            println!(
                "trust_context  = v{} -> v{} (signed by the root {}): NOT KNOWN whether the \
                 daemon adopted it",
                ctx.version(),
                ctx.version() + 1,
                store.key_name()
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
    let (signer, _) = open_kit(
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
    let (store, ctx, held_data) =
        root_device(&pib, &pib_dir, "recovery kits are made and revoked")?;
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
    let handed = hand_over(args, &pib_dir, &bump).await.map_err(|not| match not {
        NotTaken::Refused(e) => e.context("the kit was not revoked; the trust context is unchanged"),
        NotTaken::Unknown(e) => e.context(format!(
            "whether the daemon adopted v{} (without the kit) is not known: `ndn-fwd \
             recovery-kit list --pib {}` stops listing {key} once it did; if it still lists it \
             once the daemon is idle, revoke it again",
            bump.context.version(),
            pib_dir.display()
        )),
    })?;
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
