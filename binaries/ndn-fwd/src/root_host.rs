//! The CLI's side of the root-device operations of
//! [`ndn_namespace::root`]: where secrets come from ([`Secrets`]), the
//! running daemon that takes the versions signed here ([`daemon`]), and
//! the CLI's wording of the refusals every root command shares
//! ([`render`]). Each command module words its own outcomes and the
//! refusals only it gives.

use std::path::Path;

use ndn_cert::recovery::{KIT_PASSPHRASE_ENV, KIT_PIN_ENV, KIT_WORDS_ENV};
use ndn_cert::report::code;
use ndn_cert::{RootSecret, RootUnlockKind, read_root_secret, read_secret};
use ndn_namespace::admin::HandedOver;
use ndn_namespace::root::daemon::MgmtDevice;
use ndn_namespace::root::{
    RootError, SecretKind, SecretPurpose, SecretRequest, SecretSource, VersionChange,
};
use ndn_packet::Name;

use crate::context_adopt::namespace_words;
use crate::onboard::flag;

/// `--namespace <prefix>`, when given: the trusted prefix a root command
/// acts on.
pub(crate) fn namespace_arg(args: &[String]) -> anyhow::Result<Option<Name>> {
    flag(args, &["--namespace"])
        .map(|ns| {
            ns.parse::<Name>()
                .map_err(|e| anyhow::anyhow!("--namespace {ns:?} is not an NDN name: {e}"))
        })
        .transpose()
}

/// Secrets asked of the operator: the environment variable
/// (`NDN_ROOT_PASSPHRASE`, `NDN_ROOT_PIN`, `NDN_KIT_PASSPHRASE`,
/// `NDN_KIT_PIN`, `NDN_KIT_WORDS`), else the first line of
/// `--passphrase-file` / `--pin-file` / `--kit-passphrase-file` /
/// `--kit-pin-file` / `--words-file`, else the terminal without echo; never
/// the command line.
pub(crate) struct Secrets<'a> {
    pub(crate) args: &'a [String],
}

/// What a secret is for, as the prompt says it.
fn purpose_text(purpose: &SecretPurpose) -> String {
    match purpose {
        SecretPurpose::CreateRoot => "Creating the namespace root".to_string(),
        SecretPurpose::SignVersion(change) => {
            let change = match change {
                VersionChange::Revoke { name } => format!("Revoking {name}"),
                VersionChange::AddKit { namespace } => {
                    format!("Adding a recovery kit to {namespace}")
                }
                VersionChange::RevokeKit { key } => format!("Revoking the recovery kit {key}"),
                VersionChange::UpdateSchema { namespace } => {
                    format!("Updating the schema of {namespace}")
                }
            };
            format!("{change} signs a new trust context version")
        }
        SecretPurpose::MoveRoot => "Unlocking the namespace root".to_string(),
        SecretPurpose::SealRoot => "Sealing the namespace root".to_string(),
        SecretPurpose::CreateKit { namespace } => {
            format!("Creating a recovery kit for {namespace}")
        }
        SecretPurpose::SealKit => "Sealing the recovery kit".to_string(),
        SecretPurpose::CheckKit { namespace } => {
            format!("Checking a recovery kit of {namespace}")
        }
        SecretPurpose::Recover { namespace } => format!("Recovering {namespace}"),
    }
}

#[async_trait::async_trait]
impl SecretSource for Secrets<'_> {
    async fn secret(&self, request: &SecretRequest) -> Result<RootSecret, RootError> {
        let purpose = purpose_text(&request.purpose);
        let file = |name: &str| flag(self.args, &[name]).map(Path::new);
        let kit = |env, file_flag: &str, label| {
            read_secret(
                Some(env),
                file_flag,
                file(file_flag),
                request.confirm,
                &purpose,
                label,
            )
        };
        let secret = match request.kind {
            SecretKind::RootPassphrase => read_root_secret(
                RootUnlockKind::Passphrase,
                file("--passphrase-file"),
                request.confirm,
                &purpose,
            ),
            SecretKind::RootPin => read_root_secret(
                RootUnlockKind::Pin,
                file("--pin-file"),
                request.confirm,
                &purpose,
            ),
            SecretKind::KitPassphrase => kit(
                KIT_PASSPHRASE_ENV,
                "--kit-passphrase-file",
                "recovery kit passphrase",
            ),
            SecretKind::KitPin => kit(KIT_PIN_ENV, "--kit-pin-file", "recovery kit YubiKey PIN"),
            SecretKind::KitWords => kit(KIT_WORDS_ENV, "--words-file", "24 recovery words"),
        };
        secret.map_err(|e| RootError::from(e).with("secret", request.kind.as_str()))
    }

    fn unprotected_root(&self) {
        eprintln!(
            "warning: --root-store file keeps the namespace root key in plaintext in the \
             PIB, protected only by file modes; use it for tests, and seal it later with \
             `ndn-fwd root-key move --to os-keyring` (or `--to sealed-file`)"
        );
    }
}

/// The running daemon that uses the PIB a command works on, reached over
/// its management socket (`[management] face_socket` of `-c`, else the
/// default). Refusals it answers are in the CLI's words; a version it does
/// not answer on in time is handed over again, and the CLI says so.
pub(crate) fn daemon(args: &[String]) -> anyhow::Result<MgmtDevice> {
    let socket = crate::onboard::face_socket(args)?;
    let at = socket.clone();
    Ok(MgmtDevice::new(socket)
        .named("the daemon")
        .worded_by(|refusal| namespace_words().render(refusal))
        .on_no_answer(move |version| {
            eprintln!(
                "# no answer yet from the daemon at {at} on v{version} (another change of the \
                 namespace may be running there); asking again with the same version"
            );
        }))
}

/// Where a version handed over went, as the CLI says it.
pub(crate) fn handed_text(
    handed: &HandedOver,
    daemon: &MgmtDevice,
    version: u64,
    pib_dir: &Path,
) -> String {
    let socket = daemon.socket();
    match handed {
        HandedOver::Taken(info) => format!(
            "the daemon at {socket} {}",
            namespace_words().render_detail(&info.detail)
        ),
        HandedOver::Stored { location } => format!(
            "no daemon listens at {socket}: v{version} is stored in {location}; (re)start the \
             daemon that uses {} so it loads, adopts and publishes it (one running with another \
             socket keeps the version before until it restarts)",
            pib_dir.display()
        ),
    }
}

/// The namespaces of a comma-separated `namespaces`/`namespace` param, as
/// the CLI lists them.
pub(crate) fn listed(param: Option<&str>) -> String {
    param
        .unwrap_or_default()
        .split(',')
        .filter(|ns| !ns.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The refusals every root command words alike, with the error chain the
/// CLI printed before; a command words its own first and hands the rest
/// here. A refusal without a CLI wording of its own is shown as the failure
/// underneath says it (an `ndn-cert` refusal's text names the CLI's flags).
pub(crate) fn render(e: RootError) -> anyhow::Error {
    let refusal = e.refusal.clone();
    let p = |key: &str| refusal.param(key).unwrap_or_default().to_string();
    if e.is(code::DEVICE_OTHER_PIB) {
        let (socket, theirs, pib) = (p("address"), p("device_pib"), p("pib"));
        return anyhow::anyhow!(
            "the daemon at {socket} uses the PIB {theirs}, not {pib}: what is made here from {pib} \
             must go to the daemon that uses it. Pass -c with that daemon's config (its \
             [management] face_socket), or --pib {theirs} to work on the PIB of the daemon at \
             {socket}"
        );
    }
    if e.is(code::DEVICE_UNREACHABLE) {
        return anyhow::anyhow!(
            "cannot use the daemon's socket {} ({}): run this as a user the daemon accepts, or \
             pass -c with the config of the daemon that uses {}",
            p("address"),
            p("error"),
            p("pib")
        );
    }
    if e.is(code::DEVICE_PIB_UNKNOWN) {
        return anyhow::anyhow!(
            "the daemon at {} does not say which PIB it uses: {}",
            p("address"),
            p("error")
        );
    }
    if e.is(code::DEVICE_FAILED) {
        return anyhow::anyhow!(
            "an exchange with the daemon at {} failed: {}",
            p("address"),
            p("error")
        );
    }
    if e.is(code::NEWEST_NOT_ADOPTED) {
        let namespace = p("namespace");
        return anyhow::anyhow!(
            "this device holds no trust context for {namespace}, and adopting it with the kit's \
             expected fingerprint failed ({}): {}. Adopt it with the namespace's anchor link \
             (`ndn-fwd adopt`), then retry",
            p("status_code"),
            p("reason")
        );
    }
    if e.is(code::KIT_OTHER_NAMESPACE) && e.underlying().is_none() {
        return anyhow::anyhow!(
            "{} is a recovery kit for {}, not {}",
            p("path"),
            p("kit"),
            p("namespace")
        );
    }
    if e.is(code::NO_DEFAULT_ROOT_STORE) {
        return anyhow::anyhow!(
            "{}. Choose the root store explicitly: `--root-store sealed-file` keeps the root in \
             a passphrase-sealed file (or `--root-store yubikey-piv` on a YubiKey)",
            e.underlying().map(ToString::to_string).unwrap_or_default()
        );
    }
    if e.is(code::BAD_RECOVERY_WORDS)
        && e.underlying()
            .is_some_and(|s| s.is::<std::str::Utf8Error>())
    {
        return underneath(e).context("the recovery words are not text");
    }
    if e.is(code::PIB_UNREADABLE) {
        return underneath(e).context(format!("open PIB at {}", p("pib")));
    }
    if let Some(path) = refusal.param("write") {
        return underneath(e).context(format!("write {path}"));
    }
    if let Some(pib) = refusal.param("read") {
        return underneath(e).context(format!("read adopted contexts in {pib}"));
    }
    underneath(e)
}

/// What a refusal wraps: the refusal it wraps (worded by [`render`]), else
/// the failure underneath as it says it, else its `error` param or sentence.
fn underneath(e: RootError) -> anyhow::Error {
    let (refusal, source) = e.into_parts();
    match source {
        Some(source) => match source.downcast::<RootError>() {
            Ok(cause) => render(*cause),
            Err(source) => anyhow::anyhow!(source),
        },
        None => anyhow::anyhow!("{}", refusal.param("error").unwrap_or(&refusal.reason)),
    }
}

/// `e` as the error chain of a refusal before anything was signed: the
/// daemon checked before the root unlocks is "nothing was signed".
pub(crate) fn render_before_signing(e: RootError) -> anyhow::Error {
    if e.is(code::DEVICE_UNREACHABLE) {
        return anyhow::anyhow!("{}. Nothing was signed", render(e));
    }
    if e.is(code::DEVICE_OTHER_PIB) || e.is(code::DEVICE_PIB_UNKNOWN) {
        return render(e).context("nothing was signed");
    }
    if e.is(code::ROOT_NOT_UNLOCKED) {
        return render(e).context("the root did not unlock; nothing was signed");
    }
    render(e)
}
