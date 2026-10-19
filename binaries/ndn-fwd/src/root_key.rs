//! The namespace root keys on their root device: where `ndn-fwd init` puts
//! one, `ndn-fwd root-key status|move`, and what the daemon reports and
//! warns about — the CLI over [`ndn_namespace::root::key`]. The mechanism
//! is [`ndn_cert::root_store`]. A device can hold the roots of several
//! trusted prefixes, one store each: a command acting on one root takes
//! `--namespace <prefix>`, and picks the root itself only when the PIB
//! holds one.
//!
//! - **Choosing a store** (`init --root-store`): `os-keyring` when an OS
//!   keychain is reachable (the default; refused with advice when none is),
//!   `sealed-file` (a passphrase, asked twice), `yubikey-piv` (generated on
//!   the token; PIN), or `file` (plaintext; tests and development).
//! - **Unlocking** (`revoke`, `recovery-kit create|revoke`, `schema
//!   update`): the root store of the PIB is opened here and the passphrase
//!   / PIN asked ([`crate::root_host::Secrets`]) — `NDN_ROOT_PASSPHRASE` /
//!   `NDN_ROOT_PIN`, else `--passphrase-file` / `--pin-file`, else the
//!   terminal without echo, never the command line. The root signs the one
//!   new trust-context version there and is dropped; the daemon receives
//!   only the signed version (`security/context-update`), never the secret.
//! - **Moving** (`root-key move --to`): offline on the PIB; safe while the
//!   daemon runs, which reads the store's descriptor per operation.

use std::path::Path;

use anyhow::{Context, Result, bail};
use ndn_cert::report::code;
use ndn_cert::{RootStore, RootStoreKind};
use ndn_namespace::root::RootError;
use ndn_namespace::root::init::{RootStoreChoice, YubikeyRoot};
use ndn_namespace::root::key::{self, HeldKits, RootKeyStatus};
use ndn_security::FilePib;

use crate::onboard::{flag, pib_dir, positionals};
use crate::root_host::{Secrets, listed, namespace_arg, render};

/// Where `ndn-fwd init` / `recover` create the root: `--root-store`, else
/// the OS keychain when one is reachable (the library refuses without
/// one).
pub(crate) fn root_store_choice(args: &[String]) -> Result<RootStoreChoice> {
    let Some(kind) = flag(args, &["--root-store"]) else {
        return Ok(RootStoreChoice::Default);
    };
    let kind = kind
        .parse::<RootStoreKind>()
        .map_err(|e| anyhow::anyhow!("--root-store: {e}"))?;
    Ok(match kind {
        RootStoreKind::OsKeyring => RootStoreChoice::OsKeyring,
        RootStoreKind::SealedFile => RootStoreChoice::SealedFile,
        RootStoreKind::YubikeyPiv => RootStoreChoice::YubikeyPiv(YubikeyRoot {
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
            replace_slot: args.iter().any(|a| a == "--replace-slot"),
        }),
        RootStoreKind::File => RootStoreChoice::File,
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

/// A refused `root-key` command, as the CLI says it.
fn refused(e: RootError) -> anyhow::Error {
    let p = |key: &str| e.param(key).unwrap_or_default().to_string();
    if e.is(code::NOT_ROOT_DEVICE) {
        return anyhow::anyhow!(
            "{} holds no namespace root: {} on the root device (where `ndn-fwd init` ran, or a \
             device that ran `ndn-fwd recover`)",
            p("pib"),
            p("operation")
        );
    }
    if e.is(code::OTHER_NAMESPACE_ROOT) {
        let ns = p("requested");
        return anyhow::anyhow!(
            "{} holds no root of {ns} (it holds the roots of {}): {} on the root device of \
             {ns}, or name one of those with --namespace",
            p("pib"),
            listed(e.param("namespace")),
            p("operation")
        );
    }
    render(e)
}

/// What `root-key status` prints about one root; `several`: the PIB holds
/// other roots too, so the commands it suggests name this one.
fn print_status(status: &RootKeyStatus, pib_dir: &Path, several: bool) {
    let named = if several {
        format!(" --namespace {}", status.namespace)
    } else {
        String::new()
    };
    println!("namespace      = {}", status.namespace);
    println!("root_key       = {}", status.key);
    println!("root_store     = {}", status.store.kind);
    println!("location       = {}", status.store.location);
    println!("unlock         = {}", status.unlock.as_str());
    match &status.kits {
        HeldKits::Held { version, kits } => {
            println!("recovery_kits  = {kits} (recovery anchors of the held context v{version})");
            if *kits == 0 {
                println!(
                    "# No recovery kit: losing this device loses the namespace. Create one: \
                     ndn-fwd recovery-kit create --format words|file|yubikey{named}"
                );
            }
        }
        HeldKits::NotStored => println!(
            "recovery_kits  = ? (no stored trust context of {})",
            status.namespace
        ),
        HeldKits::Unreadable(e) => {
            println!("recovery_kits  = ? (stored trust context unreadable: {e})")
        }
    }
    if status.store.kind == RootStoreKind::File {
        println!();
        println!(
            "# The root key is unprotected{}. Seal it:",
            if status.legacy {
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
    let roots = key::open(&pib_dir).map_err(refused)?;
    match positional.first().copied() {
        Some("status") => {
            // Every root, or the one `--namespace` names.
            let several = roots.stores().len() > 1;
            let shown = roots
                .status(namespace_arg(args)?.as_ref())
                .map_err(refused)?;
            if shown.is_empty() {
                println!(
                    "# {} holds no namespace root (this is not a root device)",
                    pib_dir.display()
                );
            }
            for (i, status) in shown.iter().enumerate() {
                if i > 0 {
                    println!();
                }
                print_status(status, &pib_dir, several);
            }
            Ok(())
        }
        Some("move") => {
            let to: RootStoreKind = flag(args, &["--to"])
                .context("root-key move needs --to <os-keyring | sealed-file>")?
                .parse()
                .map_err(|e| anyhow::anyhow!("--to: {e}"))?;
            let moved = roots
                .move_to(namespace_arg(args)?.as_ref(), to, &Secrets { args })
                .await
                .map_err(refused)?;
            println!("# ndn-fwd root-key move");
            println!("root_key       = {}", moved.key);
            println!("moved          = {} -> {}", moved.from, moved.to.kind);
            println!("location       = {}", moved.to.location);
            println!(
                "# The new store signed as the root before the old copy was removed{}.",
                if moved.from == RootStoreKind::File {
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
