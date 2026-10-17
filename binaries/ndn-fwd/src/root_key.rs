//! The namespace root key on its root device: where `ndn-fwd init` puts it,
//! how a root operation gets it unlocked, `ndn-fwd root-key status|move`,
//! and what the daemon reports and warns about. The mechanism is
//! [`ndn_cert::root_store`]; this is the operator's side.
//!
//! - **Choosing a store** (`init --root-store`): `os-keyring` when an OS
//!   keychain is reachable (the default; refused with advice when none is),
//!   `sealed-file` (a passphrase, asked twice), `yubikey-piv` (generated on
//!   the token; PIN), or `file` (plaintext; tests and development).
//! - **Unlocking** (`revoke`): the CLI learns the store kind from the
//!   daemon's `security/identity-status` (`root_unlock=`), asks for the
//!   passphrase / PIN — `NDN_ROOT_PASSPHRASE` / `NDN_ROOT_PIN`, else
//!   `--passphrase-file` / `--pin-file`, else the terminal without echo, never
//!   the command line — and sends it with the command over the local
//!   management socket (peer-credential gated, refused over `/localhop`), in
//!   the command's ApplicationParameters. The daemon unlocks the root for that
//!   one signature and drops it.
//! - **Moving** (`root-key move --to`): offline on the PIB; safe while the
//!   daemon runs, which reads the store's descriptor per operation.

use std::path::Path;

use anyhow::{Context, Result, bail};
use ndn_cert::{
    NewRootStore, RootSecret, RootStore, RootStoreKind, RootUnlockKind, os_keychain_reachable,
    read_root_secret,
};
use ndn_security::FilePib;

use crate::onboard::{flag, pib_dir, positionals};

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

/// `ndn-fwd root-key status|move`.
pub(crate) async fn run(args: &[String]) -> Result<()> {
    let positional = positionals(args);
    let pib_dir = pib_dir(args)?;
    let pib = FilePib::open(&pib_dir)
        .with_context(|| format!("open PIB at {}", pib_dir.display()))?;
    let store = RootStore::open(&pib)?;
    match positional.first().copied() {
        Some("status") => {
            let Some(store) = store else {
                println!(
                    "# {} holds no namespace root (this is not a root device)",
                    pib_dir.display()
                );
                return Ok(());
            };
            println!("namespace      = {}", store.namespace());
            println!("root_key       = {}", store.key_name());
            println!("root_store     = {}", store.kind());
            println!("location       = {}", store.location());
            println!("unlock         = {}", store.unlock_kind().as_str());
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
                println!("#   ndn-fwd root-key move --to os-keyring --pib {}", pib_dir.display());
                println!("# or, without an OS keychain:");
                println!("#   ndn-fwd root-key move --to sealed-file --pib {}", pib_dir.display());
            }
            Ok(())
        }
        Some("move") => {
            let store = store.with_context(|| {
                format!("{} holds no namespace root to move", pib_dir.display())
            })?;
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
                let current =
                    operator_secret(args, store.unlock_kind(), "Unlocking the namespace root", false)?;
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
             [--pib <dir>] | ndn-fwd root-key move --to <os-keyring|sealed-file> [--pib <dir>] \
             [--passphrase-file <path>]"
        ),
    }
}

/// This PIB's root store, for `security/identity-status`.
pub(crate) fn status_info(pib_root: &Path) -> Option<ndn_mgmt::RootStoreInfo> {
    let pib = FilePib::open(pib_root).ok()?;
    let store = RootStore::open(&pib).ok()??;
    Some(ndn_mgmt::RootStoreInfo {
        kind: store.kind().to_string(),
        key: store.key_name().clone(),
        unlock: store.unlock_kind().as_str().to_string(),
    })
}

/// At startup on a root device: warn when the root key is plaintext.
pub(crate) fn warn_if_unprotected(pib_root: &Path) {
    let Ok(pib) = FilePib::open(pib_root) else {
        return;
    };
    match RootStore::open(&pib) {
        Ok(Some(store)) if store.kind() == RootStoreKind::File => tracing::warn!(
            target: "security",
            namespace = %store.namespace(),
            root_key = %store.key_name(),
            pib = %pib_root.display(),
            "the namespace root key is stored unprotected (plaintext in the PIB); seal it with \
             `ndn-fwd root-key move --to os-keyring --pib {}` (or `--to sealed-file`)",
            pib_root.display()
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!(target: "security", error = %e, "cannot read the root store"),
    }
}

/// What the daemon's root store needs to unlock (`root_unlock=` in
/// `security/identity-status`), `None` when it is no root device or does
/// not say.
pub(crate) async fn daemon_root_unlock(client: &ndn_ipc::MgmtClient) -> Option<RootUnlockKind> {
    let resp = client.security_identity_status().await.ok()?;
    if !resp.is_ok() {
        return None;
    }
    resp.status_text
        .split_whitespace()
        .find_map(|field| field.strip_prefix("root_unlock="))
        .and_then(|kind| kind.parse().ok())
}
