//! Root operations of a trusted prefix this device is the main device of —
//! removing a device, recovery kits, moving the root key, updating the
//! schema — run in this process through `ndn_namespace::root`.
//!
//! The secrets they need are typed into the TUI ([`TuiSecrets`] asks the
//! screen through a channel) and never leave this process: the running
//! daemon receives only the signed version ([`DaemonDevice`]).

use std::path::{Path, PathBuf};
use std::time::Duration;

use ndn_cert::report::{ContextRefreshInfo, TrustRefusal, code};
use ndn_cert::{KitFormat, RootSecret, RootStoreKind, YubikeyKit};
use ndn_ipc::MgmtClient;
use ndn_namespace::admin::{HandedOver, SinkError};
use ndn_namespace::root::kit::{KitLocation, KitRequest, KitSpec};
use ndn_namespace::root::{
    DeviceSession, Reach, RootError, RunningDevice, SecretRequest, SecretSource, key, kit, revoke,
    schema,
};
use ndn_packet::{Data, Name};
use ndn_trust_envelope::TrustEnvelope;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use crate::daemon::{Failure, NETWORK_TIMEOUT};

/// How long the daemon may take to take a version handed over.
const UPDATE_TIMEOUT: Duration = Duration::from_secs(30);

/// A secret the running operation asks the screen for. The reply is the
/// secret as typed (`None`: none was given).
pub struct SecretAsk {
    pub request: SecretRequest,
    pub reply: oneshot::Sender<Option<Zeroizing<String>>>,
}

/// The secrets of a root operation, asked on the TUI's screen.
pub struct TuiSecrets {
    asks: mpsc::Sender<SecretAsk>,
}

impl TuiSecrets {
    pub fn new(asks: mpsc::Sender<SecretAsk>) -> Self {
        Self { asks }
    }
}

#[async_trait::async_trait]
impl SecretSource for TuiSecrets {
    async fn secret(&self, request: &SecretRequest) -> Result<RootSecret, RootError> {
        let unavailable = || {
            RootError::new(code::SECRET_UNAVAILABLE, "no secret was given")
                .with("secret", request.kind.as_str())
        };
        let (reply, answer) = oneshot::channel();
        self.asks
            .send(SecretAsk {
                request: request.clone(),
                reply,
            })
            .await
            .map_err(|_| unavailable())?;
        match answer.await {
            Ok(Some(secret)) if !secret.is_empty() => {
                Ok(RootSecret::new(secret.as_bytes().to_vec()))
            }
            _ => Err(unavailable()),
        }
    }
}

/// The daemon that uses this device's key storage, reached over its
/// management socket: it takes the versions signed here.
pub struct DaemonDevice {
    socket: String,
}

impl DaemonDevice {
    pub fn new(socket: &str) -> Self {
        Self {
            socket: socket.to_owned(),
        }
    }
}

/// A failed exchange with the daemon.
fn device_failed(socket: &str, error: impl std::fmt::Display) -> RootError {
    RootError::new(
        code::DEVICE_FAILED,
        "an exchange with the running device failed",
    )
    .with("address", socket)
    .with("error", error)
}

#[async_trait::async_trait]
impl RunningDevice for DaemonDevice {
    fn address(&self) -> String {
        self.socket.clone()
    }

    async fn reach(&self) -> Result<Reach, RootError> {
        match MgmtClient::connect(&self.socket).await {
            Ok(client) => Ok(Reach::Running(Box::new(Session {
                client,
                socket: self.socket.clone(),
            }))),
            Err(ndn_ipc::ForwarderError::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                Ok(Reach::NotRunning {
                    error: e.to_string(),
                })
            }
            Err(e) => Err(RootError::new(
                code::DEVICE_UNREACHABLE,
                "the running device cannot be used",
            )
            .with("address", &self.socket)
            .with("error", e)),
        }
    }
}

/// One connection to the daemon.
struct Session {
    client: MgmtClient,
    socket: String,
}

/// A refusal the daemon answered, else its status as an untyped refusal of
/// `kind`.
fn refused(
    resp: &ndn_mgmt_wire::ControlResponse,
    kind: ndn_cert::report::RefusalCode,
) -> TrustRefusal {
    ndn_ipc::trust_refusal(resp).unwrap_or_else(|| {
        let mut refusal = TrustRefusal::new(kind, resp.status_text.clone());
        refusal.status_code = resp.status_code;
        refusal
    })
}

#[async_trait::async_trait]
impl DeviceSession for Session {
    async fn pib(&self) -> Result<PathBuf, RootError> {
        match self.client.security_identity_status().await {
            Ok(status) => Ok(PathBuf::from(status.pib_path)),
            Err(e) => Err(RootError::new(
                code::DEVICE_PIB_UNKNOWN,
                "the running device did not say which key storage it uses",
            )
            .with("address", &self.socket)
            .with("error", e)),
        }
    }

    async fn take(&self, data: &Data) -> Result<ContextRefreshInfo, SinkError<RootError>> {
        match self
            .client
            .security_context_update(data.raw().clone(), UPDATE_TIMEOUT)
            .await
        {
            Ok(resp) if resp.is_ok() => {
                serde_json::from_str(&resp.status_text).map_err(|e| SinkError::Unreadable {
                    error: e.to_string(),
                    answer: resp.status_text.clone(),
                })
            }
            Ok(resp) => Err(SinkError::Refused(refused(&resp, code::HAND_OVER_REFUSED))),
            Err(ndn_ipc::ForwarderError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut => {
                Err(SinkError::NoAnswer)
            }
            Err(e) => Err(SinkError::Failed(device_failed(&self.socket, e))),
        }
    }

    async fn refresh(&self, namespace: &Name) -> Result<Option<ContextRefreshInfo>, RootError> {
        let resp = self
            .client
            .security_context_refresh(Some(namespace), NETWORK_TIMEOUT)
            .await
            .map_err(|e| device_failed(&self.socket, e))?;
        if resp.is_ok() {
            let results: Vec<ContextRefreshInfo> = serde_json::from_str(&resp.status_text)
                .map_err(|e| device_failed(&self.socket, e))?;
            return Ok(results.into_iter().next());
        }
        if resp.status_code == 404 {
            return Ok(None);
        }
        Err(device_failed(
            &self.socket,
            crate::words::refusal(&refused(&resp, code::DEVICE_FAILED)),
        ))
    }

    async fn adopt(&self, namespace: &Name, fingerprint: &[u8; 32]) -> Result<u64, RootError> {
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
            .security_context_adopt(&link, NETWORK_TIMEOUT)
            .await
            .map_err(|e| device_failed(&self.socket, e))?;
        if !resp.is_ok() {
            let refusal = refused(&resp, code::NEWEST_NOT_ADOPTED);
            return Err(RootError::new(
                code::NEWEST_NOT_ADOPTED,
                "adopting the namespace with the kit's expected fingerprint failed",
            )
            .with("namespace", namespace)
            .with("status_code", resp.status_code)
            .with("reason", crate::words::refusal(&refusal)));
        }
        let info: ndn_cert::report::AdoptedContextInfo =
            serde_json::from_str(&resp.status_text).map_err(|e| device_failed(&self.socket, e))?;
        Ok(info.version)
    }
}

/// Where a signed version went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handed {
    /// The running daemon took it.
    Taken,
    /// No daemon runs: it is kept for its next start, at `location`.
    Stored { location: String },
}

impl From<&HandedOver> for Handed {
    fn from(h: &HandedOver) -> Self {
        match h {
            HandedOver::Taken(_) => Handed::Taken,
            HandedOver::Stored { location } => Handed::Stored {
                location: location.clone(),
            },
        }
    }
}

/// A root operation to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootOp {
    /// Remove a device: revoke the keys `name` designates (a device
    /// identity, a key or a certificate).
    Revoke { namespace: Name, name: Name },
    /// Make a recovery kit: 24 words, a sealed file at `out`, or a key on a
    /// second security key.
    KitCreate {
        namespace: Name,
        format: KitFormat,
        out: Option<PathBuf>,
    },
    /// Open a kit and check it is a recovery kit of the held version.
    KitCheck { namespace: Name, spec: KitSpecArg },
    /// Revoke the recovery kit `key`.
    KitRevoke { namespace: Name, key: Name },
    /// Move the root key to a store of kind `to`.
    MoveRoot { namespace: Name, to: RootStoreKind },
    /// Bring the trust schema up to date with what this build generates.
    SchemaUpdate {
        namespace: Name,
        accept_narrowing: bool,
    },
}

/// A kit to open, as the screen chose it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KitSpecArg {
    Words,
    File(PathBuf),
    SecurityKey,
}

/// What a root operation did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootDone {
    Revoked {
        namespace: String,
        version: u64,
        revoked: Vec<String>,
        handed: Handed,
    },
    KitCreated {
        namespace: String,
        version: u64,
        key: String,
        /// The 24 words of a word kit: shown once, zeroed when dropped.
        words: Option<Zeroizing<String>>,
        /// A file kit's path, or a security key's serial and slot.
        location: Option<String>,
        /// `Err`: whether the daemon took the version is not known.
        handed: Result<Handed, TrustRefusal>,
    },
    KitChecked {
        namespace: String,
        key: String,
        version: u64,
    },
    KitRevoked {
        namespace: String,
        key: String,
        version: u64,
        kits_left: usize,
        handed: Handed,
    },
    RootMoved {
        namespace: String,
        from: String,
        to: String,
        location: String,
    },
    SchemaUpdated {
        namespace: String,
        version: u64,
        added: usize,
        removed: usize,
        handed: Handed,
    },
}

/// The default slot and touch policy of a security-key kit.
fn security_key_kit() -> YubikeyKit {
    YubikeyKit {
        serial: None,
        slot: ndn_cert::recovery::DEFAULT_KIT_SLOT.to_owned(),
        touch_policy: "always".to_owned(),
    }
}

/// Run `op` on the key storage at `pib`, handing what it signs to the
/// daemon at `socket`; secrets are asked through `secrets`.
pub async fn run(
    op: RootOp,
    pib: &Path,
    socket: &str,
    secrets: &TuiSecrets,
) -> Result<RootDone, Failure> {
    let device = DaemonDevice::new(socket);
    Ok(match op {
        RootOp::Revoke { namespace, name } => {
            let planned = revoke::plan(pib, &name, Some(&namespace))?;
            let done = revoke::revoke(planned, &name, pib, &device, secrets).await?;
            RootDone::Revoked {
                namespace: done.namespace.to_string(),
                version: done.version,
                revoked: done.revoked.iter().map(Name::to_string).collect(),
                handed: Handed::from(&done.handed_over),
            }
        }
        RootOp::KitCreate {
            namespace,
            format,
            out,
        } => {
            let done = kit::create(
                KitRequest {
                    pib_dir: pib.to_path_buf(),
                    namespace: Some(namespace),
                    format,
                    out,
                    yubikey: security_key_kit(),
                    replace_slot: false,
                },
                &device,
                secrets,
            )
            .await?;
            RootDone::KitCreated {
                namespace: done.namespace.to_string(),
                version: done.version,
                key: done.key.to_string(),
                words: done.words.as_ref().map(|seed| seed.to_words()),
                location: match &done.kit {
                    KitLocation::Words => None,
                    KitLocation::File(path) => Some(path.display().to_string()),
                    KitLocation::Yubikey { serial, slot } => Some(format!("{serial} slot {slot}")),
                },
                handed: match &done.handed {
                    Ok((handed, _)) => Ok(Handed::from(handed)),
                    Err(e) => Err(e.refusal.clone()),
                },
            }
        }
        RootOp::KitCheck { namespace, spec } => {
            let spec = match spec {
                KitSpecArg::Words => KitSpec::Words,
                KitSpecArg::File(path) => KitSpec::File(path),
                KitSpecArg::SecurityKey => KitSpec::Yubikey(security_key_kit()),
            };
            let done = kit::check(pib, &spec, Some(&namespace), secrets).await?;
            RootDone::KitChecked {
                namespace: done.namespace.to_string(),
                key: done.key.to_string(),
                version: done.version,
            }
        }
        RootOp::KitRevoke { namespace, key } => {
            let done = kit::revoke(pib, &key, Some(&namespace), &device, secrets).await?;
            RootDone::KitRevoked {
                namespace: done.namespace.to_string(),
                key: done.key.to_string(),
                version: done.version,
                kits_left: done.recovery_kits,
                handed: Handed::from(&done.handed_over),
            }
        }
        RootOp::MoveRoot { namespace, to } => {
            let moved = key::open(pib)?
                .move_to(Some(&namespace), to, secrets)
                .await?;
            RootDone::RootMoved {
                namespace: moved.namespace.to_string(),
                from: moved.from.as_str().to_owned(),
                to: moved.to.kind.as_str().to_owned(),
                location: moved.to.location,
            }
        }
        RootOp::SchemaUpdate {
            namespace,
            accept_narrowing,
        } => {
            let root = schema::root_of(pib, Some(&namespace))?;
            let planned =
                schema::plan_update(root, &ndn_cert::PolicyInput::default(), accept_narrowing)?;
            let done = schema::update(planned, pib, &device, secrets).await?;
            RootDone::SchemaUpdated {
                namespace: done.namespace.to_string(),
                version: done.version,
                added: done.change.added.len(),
                removed: done.change.removed.len(),
                handed: Handed::from(&done.handed_over),
            }
        }
    })
}

/// The schema of `namespace` as held in the key storage at `pib`, as lines
/// to show.
pub fn schema_lines(pib: &Path, namespace: &Name) -> Result<Vec<String>, Failure> {
    let adopted = schema::load(pib)?;
    let ctx = adopted.select(Some(namespace))?;
    let view = schema::view(&ctx);
    let mut lines = vec![
        format!("version {}", view.version),
        format!(
            "evaluation {}",
            match view.evaluation {
                schema::Evaluation::Authoritative => "schema on every certificate hop",
                schema::Evaluation::WithHierarchyFloor =>
                    "schema and name hierarchy, first signature",
                schema::Evaluation::FirstSignature => "schema, first signature",
            }
        ),
    ];
    for anchor in &view.anchors {
        lines.push(format!("anchor {anchor}"));
    }
    for ca in &view.ca_endpoints {
        lines.push(format!("certificate authority {ca}"));
    }
    for relay in &view.relays {
        lines.push(format!("relay {relay:?}"));
    }
    for (i, blob) in view.blobs.iter().enumerate() {
        match blob {
            Ok(schema::SchemaBlobView::Lvs { bytes, source }) => {
                lines.push(format!("schema {i}: LVS, {bytes} bytes"));
                lines.extend(source.lines().map(|l| format!("  {l}")));
            }
            Ok(schema::SchemaBlobView::Native { rules }) => {
                lines.push(format!("schema {i}: {} rules", rules.len()));
                lines.extend(rules.iter().map(|r| format!("  {r}")));
            }
            Ok(schema::SchemaBlobView::Unknown { format, bytes }) => {
                lines.push(format!(
                    "schema {i}: format {format}, {bytes} bytes (not read here)"
                ));
            }
            Err(e) => lines.push(format!("schema {i}: {}", crate::words::refusal(&e.refusal))),
        }
    }
    Ok(lines)
}
