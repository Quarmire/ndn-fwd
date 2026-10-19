//! The CLI's side of the root-device operations of
//! [`ndn_namespace::root`]: where secrets come from ([`Secrets`]), the
//! running daemon that takes the versions signed here ([`Daemon`]), and
//! the CLI's wording of the refusals every root command shares
//! ([`render`]). Each command module words its own outcomes and the
//! refusals only it gives.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::Context;
use ndn_cert::recovery::{KIT_PASSPHRASE_ENV, KIT_PIN_ENV, KIT_WORDS_ENV};
use ndn_cert::report::{TrustRefusal, code};
use ndn_cert::{RootSecret, RootUnlockKind, read_root_secret, read_secret};
use ndn_mgmt::ContextRefreshInfo;
use ndn_mgmt_wire::control_response::status;
use ndn_namespace::admin::{HandedOver, SinkError};
use ndn_namespace::root::{
    DeviceSession, Reach, RootError, RunningDevice, SecretKind, SecretPurpose, SecretRequest,
    SecretSource, VersionChange,
};
use ndn_packet::{Data, Name};
use ndn_trust_envelope::TrustEnvelope;

use crate::context_adopt::namespace_words;
use crate::onboard::flag;

/// How long one request waits for the daemon to take a new version (local
/// work: verify, store, publish — after any other change of the namespace
/// running there). Without an answer the same version is handed over again;
/// the answer to that one says what became of it. After
/// [`ndn_namespace::admin::HAND_OVER_WAITS`] waits (about five minutes) the
/// outcome is reported as not known.
const DAEMON_UPDATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long the CLI waits for the daemon to fetch the newest version.
const DAEMON_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

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
/// default — read when first reached).
pub(crate) struct Daemon<'a> {
    args: &'a [String],
    pib_dir: PathBuf,
    socket: OnceLock<String>,
}

impl<'a> Daemon<'a> {
    pub(crate) fn new(args: &'a [String], pib_dir: &Path) -> Self {
        Self {
            args,
            pib_dir: pib_dir.to_path_buf(),
            socket: OnceLock::new(),
        }
    }

    fn socket(&self) -> Result<&str, RootError> {
        if let Some(socket) = self.socket.get() {
            return Ok(socket);
        }
        let socket = crate::onboard::face_socket(self.args).map_err(host_error)?;
        Ok(self.socket.get_or_init(|| socket))
    }
}

/// A failure of the CLI itself (reading its config): shown as it is.
fn host_error(e: anyhow::Error) -> RootError {
    RootError::new(code::ROOT_LOCAL_FAILURE, e.to_string())
        .with("error", format!("{e:#}"))
        .caused_by(e)
}

/// A failure in an exchange with the daemon, shown as `e` says it.
fn daemon_failed(socket: &str, e: anyhow::Error) -> RootError {
    RootError::new(code::DEVICE_FAILED, e.to_string())
        .with("address", socket)
        .with("error", format!("{e:#}"))
        .caused_by(e)
}

#[async_trait::async_trait]
impl RunningDevice for Daemon<'_> {
    fn address(&self) -> String {
        self.socket.get().cloned().unwrap_or_default()
    }

    fn peer(&self) -> String {
        format!("the daemon at {}", self.address())
    }

    async fn reach(&self) -> Result<Reach, RootError> {
        let socket = self.socket()?.to_string();
        match ndn_ipc::MgmtClient::connect(&socket).await {
            Ok(client) => Ok(Reach::Running(Box::new(Session { client, socket }))),
            Err(ndn_ipc::ForwarderError::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                Ok(Reach::NotRunning {
                    error: ndn_ipc::ForwarderError::Io(e).to_string(),
                })
            }
            Err(e) => {
                let why = anyhow::anyhow!(
                    "cannot use the daemon's socket {socket} ({e}): run this as a user the \
                     daemon accepts, or pass -c with the config of the daemon that uses {}",
                    self.pib_dir.display()
                );
                Err(RootError::new(
                    code::DEVICE_UNREACHABLE,
                    "the running device cannot be used",
                )
                .with("address", &socket)
                .with("pib", self.pib_dir.display())
                .with("error", e)
                .caused_by(why))
            }
        }
    }

    fn no_answer_yet(&self, version: u64) {
        eprintln!(
            "# no answer yet from the daemon at {} on v{version} (another change of the \
             namespace may be running there); asking again with the same version",
            self.address()
        );
    }
}

/// One connection to the daemon.
struct Session {
    client: ndn_ipc::MgmtClient,
    socket: String,
}

impl Session {
    /// The PIB directory the daemon reports (`security/identity-status`).
    async fn daemon_pib(&self) -> anyhow::Result<PathBuf> {
        let socket = &self.socket;
        match self.client.security_identity_status().await {
            Ok(status) => Ok(PathBuf::from(status.pib_path)),
            Err(ndn_ipc::ForwarderError::Command { code, text }) => {
                let text = ndn_ipc::trust_refusal_of(code, &text)
                    .map_or(text, |r| namespace_words().render(&r));
                anyhow::bail!(
                    "the daemon at {socket} does not say which PIB it uses ({code}): {text}"
                )
            }
            Err(e) => {
                Err(e).with_context(|| format!("ask the daemon at {socket} which PIB it uses"))
            }
        }
    }
}

/// `refusal` with its sentence in the CLI's words.
fn worded(mut refusal: TrustRefusal) -> TrustRefusal {
    refusal.reason = namespace_words().render(&refusal);
    refusal
}

/// A refusal the daemon answered, in the CLI's words (a structured
/// refusal's, else the text as answered).
fn refusal_text(resp: &ndn_mgmt_wire::ControlResponse) -> String {
    ndn_ipc::trust_refusal(resp).map_or_else(
        || resp.status_text.clone(),
        |r| namespace_words().render(&r),
    )
}

#[async_trait::async_trait]
impl DeviceSession for Session {
    async fn pib(&self) -> Result<PathBuf, RootError> {
        self.daemon_pib().await.map_err(|e| {
            RootError::new(
                code::DEVICE_PIB_UNKNOWN,
                "the running device did not say which PIB it uses",
            )
            .with("address", &self.socket)
            .with("error", format!("{e:#}"))
            .caused_by(e)
        })
    }

    async fn take(&self, data: &Data) -> Result<ContextRefreshInfo, SinkError<RootError>> {
        match self
            .client
            .security_context_update(data.raw().clone(), DAEMON_UPDATE_TIMEOUT)
            .await
        {
            Ok(resp) if resp.is_ok() => {
                serde_json::from_str(&resp.status_text).map_err(|e| SinkError::Unreadable {
                    error: e.to_string(),
                    answer: resp.status_text.clone(),
                })
            }
            Ok(resp) => Err(SinkError::Refused(
                ndn_ipc::trust_refusal(&resp)
                    .map(worded)
                    .unwrap_or_else(|| {
                        let mut refusal =
                            TrustRefusal::new(code::HAND_OVER_REFUSED, resp.status_text.clone());
                        refusal.status_code = resp.status_code;
                        refusal
                    }),
            )),
            Err(ndn_ipc::ForwarderError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut => {
                Err(SinkError::NoAnswer)
            }
            Err(e) => Err(SinkError::Failed(daemon_failed(&self.socket, e.into()))),
        }
    }

    async fn refresh(&self, namespace: &Name) -> Result<Option<ContextRefreshInfo>, RootError> {
        let socket = &self.socket;
        let refreshed = async {
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
                anyhow::bail!(
                    "the daemon at {socket} could not refresh {namespace} ({}): {}",
                    resp.status_code,
                    refusal_text(&resp)
                );
            }
            Ok(None)
        };
        refreshed.await.map_err(|e| daemon_failed(socket, e))
    }

    async fn adopt(&self, namespace: &Name, fingerprint: &[u8; 32]) -> Result<u64, RootError> {
        let socket = &self.socket;
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
            .with_context(|| format!("ask the daemon at {socket} to adopt {namespace}"))
            .map_err(|e| daemon_failed(socket, e))?;
        if !resp.is_ok() {
            let reason = refusal_text(&resp);
            let why = anyhow::anyhow!(
                "this device holds no trust context for {namespace}, and adopting it with the \
                 kit's expected fingerprint failed ({}): {reason}. Adopt it with the namespace's \
                 anchor link (`ndn-fwd adopt`), then retry",
                resp.status_code,
            );
            return Err(RootError::new(
                code::NEWEST_NOT_ADOPTED,
                "adopting the namespace with the kit's expected fingerprint failed",
            )
            .with("namespace", namespace)
            .with("status_code", resp.status_code)
            .with("reason", reason)
            .caused_by(why));
        }
        let info: ndn_mgmt::AdoptedContextInfo = serde_json::from_str(&resp.status_text)
            .with_context(|| format!("unreadable answer from the daemon: {}", resp.status_text))
            .map_err(|e| daemon_failed(socket, e))?;
        Ok(info.version)
    }
}

/// Where a version handed over went, as the CLI says it.
pub(crate) fn handed_text(
    handed: &HandedOver,
    daemon: &Daemon<'_>,
    version: u64,
    pib_dir: &Path,
) -> String {
    let socket = daemon.address();
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
