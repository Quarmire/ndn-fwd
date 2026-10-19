//! The namespace root keys on their root device: where `ndn-fwd init` puts
//! one, how a root operation gets it unlocked, `ndn-fwd root-key
//! status|move`, and what the daemon reports and warns about. The
//! mechanism is [`ndn_cert::root_store`]; this is the operator's side. A
//! device can hold the roots of several trusted prefixes, one store each: a
//! command acting on one root takes `--namespace <prefix>`, and picks the
//! root itself only when the PIB holds one.
//!
//! - **Choosing a store** (`init --root-store`): `os-keyring` when an OS
//!   keychain is reachable (the default; refused with advice when none is),
//!   `sealed-file` (a passphrase, asked twice), `yubikey-piv` (generated on
//!   the token; PIN), or `file` (plaintext; tests and development).
//! - **Unlocking** (`revoke`, `recovery-kit create|revoke`): the CLI opens the
//!   root store of the PIB itself and asks for the passphrase / PIN —
//!   `NDN_ROOT_PASSPHRASE` / `NDN_ROOT_PIN`, else `--passphrase-file` /
//!   `--pin-file`, else the terminal without echo, never the command line.
//!   The root signs the one new trust-context version there and is dropped;
//!   the daemon receives only the signed version (`security/context-update`),
//!   never the secret.
//! - **Moving** (`root-key move --to`): offline on the PIB; safe while the
//!   daemon runs, which reads the store's descriptor per operation.

use std::path::Path;

use anyhow::{Context, Result, bail};
use ndn_cert::{
    NewRootStore, RootSecret, RootStore, RootStoreKind, RootUnlockKind, os_keychain_reachable,
    read_root_secret,
};
use ndn_packet::Name;
use ndn_security::FilePib;

use crate::onboard::{flag, pib_dir, positionals};

/// `--namespace <prefix>`, when given: the trusted prefix whose root a
/// root command acts on.
pub(crate) fn namespace_arg(args: &[String]) -> Result<Option<Name>> {
    flag(args, &["--namespace"])
        .map(|ns| {
            ns.parse::<Name>()
                .map_err(|e| anyhow::anyhow!("--namespace {ns:?} is not an NDN name: {e}"))
        })
        .transpose()
}

/// The root store a root command acts on: that of `--namespace`, else the
/// only one the PIB holds. Refused with what to do when the PIB holds none
/// (of that prefix) or several and none is named.
pub(crate) fn chosen_root(pib: &FilePib, args: &[String], work: &str) -> Result<RootStore> {
    let namespace = namespace_arg(args)?;
    if let Some(store) = RootStore::open_named(pib, namespace.as_ref())? {
        return Ok(store);
    }
    let held: Vec<String> = RootStore::open_all(pib)?
        .iter()
        .map(|s| s.namespace().to_string())
        .collect();
    match namespace {
        Some(ns) if !held.is_empty() => bail!(
            "{} holds no root of {ns} (it holds the roots of {}): {work} on the root device of \
             {ns}, or name one of those with --namespace",
            pib.root().display(),
            held.join(", ")
        ),
        _ => bail!(
            "{} holds no namespace root: {work} on the root device (where `ndn-fwd init` ran, \
             or a device that ran `ndn-fwd recover`)",
            pib.root().display()
        ),
    }
}

/// The passphrase or PIN a root operation on a `kind` store needs, asked of
/// the operator (`confirm`: choosing a new one, asked twice). `None` for a
/// store that needs nothing.
pub(crate) fn operator_secret(
    args: &[String],
    kind: RootUnlockKind,
    purpose: &str,
    confirm: bool,
) -> Result<Option<RootSecret>> {
    let file = match kind {
        RootUnlockKind::Nothing => return Ok(None),
        RootUnlockKind::Passphrase => flag(args, &["--passphrase-file"]),
        RootUnlockKind::Pin => flag(args, &["--pin-file"]),
    };
    let secret = read_root_secret(kind, file.map(Path::new), confirm, purpose)?;
    Ok(Some(secret))
}

/// The store `ndn-fwd init` creates the root in: `--root-store`, else the
/// OS keychain when one is reachable; without one, refused with what to do.
pub(crate) fn new_root_store(args: &[String]) -> Result<NewRootStore> {
    let kind = match flag(args, &["--root-store"]) {
        Some(kind) => kind
            .parse::<RootStoreKind>()
            .map_err(|e| anyhow::anyhow!("--root-store: {e}"))?,
        None => {
            if let Err(why) = os_keychain_reachable() {
                bail!(
                    "{why}. Choose the root store explicitly: `--root-store sealed-file` keeps \
                     the root in a passphrase-sealed file (or `--root-store yubikey-piv` on a \
                     YubiKey)"
                );
            }
            RootStoreKind::OsKeyring
        }
    };
    let purpose = "Creating the namespace root";
    Ok(match kind {
        RootStoreKind::OsKeyring => NewRootStore::OsKeyring,
        RootStoreKind::SealedFile => NewRootStore::SealedFile {
            passphrase: operator_secret(args, RootUnlockKind::Passphrase, purpose, true)?
                .context("a sealed-file root needs a passphrase")?,
        },
        RootStoreKind::YubikeyPiv => NewRootStore::YubikeyPiv {
            pin: operator_secret(args, RootUnlockKind::Pin, purpose, false)?
                .context("a yubikey-piv root needs the PIV PIN")?,
            slot: flag(args, &["--yubikey-slot"])
                .unwrap_or(ndn_cert::root_store::DEFAULT_YUBIKEY_SLOT)
                .to_string(),
            touch_policy: flag(args, &["--touch-policy"])
                .unwrap_or("always")
                .to_string(),
            serial: flag(args, &["--yubikey-serial"])
                .map(|s| s.parse::<u32>())
                .transpose()
                .context("--yubikey-serial must be the token's serial number")?,
            // An occupied slot is refused unless the operator says its key
            // is not needed; `recover` also keeps the root off the kit's
            // token.
            guard: ndn_cert::SlotGuard {
                replace: args.iter().any(|a| a == "--replace-slot"),
                not_on: None,
            },
        },
        RootStoreKind::File => {
            eprintln!(
                "warning: --root-store file keeps the namespace root key in plaintext in the \
                 PIB, protected only by file modes; use it for tests, and seal it later with \
                 `ndn-fwd root-key move --to os-keyring` (or `--to sealed-file`)"
            );
            NewRootStore::File
        }
    })
}

/// What `init` prints about where the root went (`pib`: the PIB directory).
pub(crate) fn describe_new_root(store: &RootStore, pib: &Path) -> Vec<String> {
    let note = match store.kind() {
        RootStoreKind::File => format!(
            "# WARNING: the root key is stored unprotected. Seal it: ndn-fwd root-key move --to \
             os-keyring --pib {}",
            pib.display()
        ),
        RootStoreKind::OsKeyring => "# The root key is sealed by your OS keychain: root \
             operations (ndn-fwd revoke) unlock it with your login, without a prompt."
            .to_string(),
        RootStoreKind::SealedFile => "# The root key is sealed by your passphrase: root \
             operations (ndn-fwd revoke) ask for it. Losing it loses the root."
            .to_string(),
        RootStoreKind::YubikeyPiv => "# The root key never leaves the YubiKey: root operations \
             (ndn-fwd revoke) ask for its PIN (and a touch). Losing the token loses the root."
            .to_string(),
    };
    vec![
        format!("root_store     = {} ({})", store.kind(), store.location()),
        note,
    ]
}

/// What `root-key status` prints about one root store; `several`: the PIB
/// holds other roots too, so the commands it suggests name this one.
fn print_status(store: &RootStore, pib_dir: &Path, several: bool) {
    let named = if several {
        format!(" --namespace {}", store.namespace())
    } else {
        String::new()
    };
    println!("namespace      = {}", store.namespace());
    println!("root_key       = {}", store.key_name());
    println!("root_store     = {}", store.kind());
    println!("location       = {}", store.location());
    println!("unlock         = {}", store.unlock_kind().as_str());
    match ndn_cert::read_stored_context(pib_dir, store.namespace()) {
        Ok(Some((ctx, _))) => {
            let kits = ctx
                .keys_with_role(ndn_security::KeyRole::RECOVERY_ANCHOR)
                .count();
            println!(
                "recovery_kits  = {kits} (recovery anchors of the held context v{})",
                ctx.version()
            );
            if kits == 0 {
                println!(
                    "# No recovery kit: losing this device loses the namespace. Create one: \
                     ndn-fwd recovery-kit create --format words|file|yubikey{named}"
                );
            }
        }
        Ok(None) => println!(
            "recovery_kits  = ? (no stored trust context of {})",
            store.namespace()
        ),
        Err(e) => println!("recovery_kits  = ? (stored trust context unreadable: {e})"),
    }
    if store.kind() == RootStoreKind::File {
        println!();
        println!(
            "# The root key is unprotected{}. Seal it:",
            if store.is_legacy() {
                " (this namespace was made before root stores)"
            } else {
                ""
            }
        );
        println!(
            "#   ndn-fwd root-key move --to os-keyring{named} --pib {}",
            pib_dir.display()
        );
        println!("# or, without an OS keychain:");
        println!(
            "#   ndn-fwd root-key move --to sealed-file{named} --pib {}",
            pib_dir.display()
        );
    }
}

/// `ndn-fwd root-key status|move`.
pub(crate) async fn run(args: &[String]) -> Result<()> {
    let positional = positionals(args);
    let pib_dir = pib_dir(args)?;
    let pib =
        FilePib::open(&pib_dir).with_context(|| format!("open PIB at {}", pib_dir.display()))?;
    match positional.first().copied() {
        Some("status") => {
            // Every root, or the one `--namespace` names.
            let all = RootStore::open_all(&pib)?;
            let several = all.len() > 1;
            let shown = match namespace_arg(args)? {
                Some(_) => vec![chosen_root(&pib, args, "its root key is reported")?],
                None => all,
            };
            if shown.is_empty() {
                println!(
                    "# {} holds no namespace root (this is not a root device)",
                    pib_dir.display()
                );
            }
            for (i, store) in shown.iter().enumerate() {
                if i > 0 {
                    println!();
                }
                print_status(store, &pib_dir, several);
            }
            Ok(())
        }
        Some("move") => {
            let store = chosen_root(&pib, args, "a root key is moved")?;
            let to: RootStoreKind = flag(args, &["--to"])
                .context("root-key move needs --to <os-keyring | sealed-file>")?
                .parse()
                .map_err(|e| anyhow::anyhow!("--to: {e}"))?;
            let from = store.kind();
            // Secrets are asked only for a move the store can make (the
            // library refuses the others with why). The current store and
            // the target never need the same secret — a store is never moved
            // to its own kind — so one --passphrase-file serves either side.
            let movable = !matches!(to, RootStoreKind::YubikeyPiv | RootStoreKind::File)
                && to != from
                && from != RootStoreKind::YubikeyPiv;
            let (current, new_passphrase) = if movable {
                let current = operator_secret(
                    args,
                    store.unlock_kind(),
                    "Unlocking the namespace root",
                    false,
                )?;
                let new_passphrase = match to {
                    RootStoreKind::SealedFile => operator_secret(
                        args,
                        RootUnlockKind::Passphrase,
                        "Sealing the namespace root",
                        true,
                    )?,
                    _ => None,
                };
                (current, new_passphrase)
            } else {
                (None, None)
            };
            let moved = store
                .move_to(&pib, to, current.as_ref(), new_passphrase.as_ref())
                .await?;
            println!("# ndn-fwd root-key move");
            println!("root_key       = {}", moved.key_name());
            println!("moved          = {from} -> {}", moved.kind());
            println!("location       = {}", moved.location());
            println!(
                "# The new store signed as the root before the old copy was removed{}.",
                if from == RootStoreKind::File {
                    " (the plaintext key file was overwritten, then deleted)"
                } else {
                    ""
                }
            );
            Ok(())
        }
        other => bail!(
            "unknown `ndn-fwd root-key` command {other:?}; usage: ndn-fwd root-key status \
             [--namespace <prefix>] [--pib <dir>] | ndn-fwd root-key move --to \
             <os-keyring|sealed-file> [--namespace <prefix>] [--pib <dir>] [--passphrase-file \
             <path>]"
        ),
    }
}

/// This PIB's root stores, by namespace, for `security/identity-status`.
pub(crate) fn status_info(pib_root: &Path) -> Vec<ndn_mgmt::RootStoreInfo> {
    let Ok(pib) = FilePib::open(pib_root) else {
        return Vec::new();
    };
    RootStore::open_all(&pib)
        .unwrap_or_default()
        .into_iter()
        .map(|store| ndn_mgmt::RootStoreInfo {
            namespace: store.namespace().clone(),
            kind: store.kind().to_string(),
            key: store.key_name().clone(),
        })
        .collect()
}

/// At startup on a root device: warn about each root key that is
/// plaintext.
pub(crate) fn warn_if_unprotected(pib_root: &Path) {
    let Ok(pib) = FilePib::open(pib_root) else {
        return;
    };
    let stores = match RootStore::open_all(&pib) {
        Ok(stores) => stores,
        Err(e) => {
            tracing::warn!(target: "security", error = %e, "cannot read the root stores");
            return;
        }
    };
    for store in stores.iter().filter(|s| s.kind() == RootStoreKind::File) {
        tracing::warn!(
            target: "security",
            namespace = %store.namespace(),
            root_key = %store.key_name(),
            pib = %pib_root.display(),
            "the namespace root key is stored unprotected (plaintext in the PIB); seal it with \
             `ndn-fwd root-key move --to os-keyring --namespace {} --pib {}` (or `--to \
             sealed-file`)",
            store.namespace(),
            pib_root.display()
        );
    }
}
