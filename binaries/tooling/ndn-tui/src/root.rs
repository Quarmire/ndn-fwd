//! Root operations, run in this process through `ndn_namespace::root`:
//! starting a new trusted prefix and recovering one whose main device is
//! lost, and on a trusted prefix this device is the main device of —
//! removing a device, recovery kits, moving the root key, updating the
//! schema.
//!
//! The secrets they need are typed into the TUI ([`TuiSecrets`] asks the
//! screen through a channel) and never leave this process: the running
//! daemon receives only the signed version
//! ([`ndn_namespace::root::daemon::MgmtDevice`]).

use std::path::{Path, PathBuf};

use ndn_cert::report::{TrustRefusal, code};
use ndn_cert::{KitFormat, OldRoot, PolicyInput, RootSecret, RootStoreKind, YubikeyKit};
use ndn_config::ForwarderConfig;
use ndn_namespace::admin::{HandedOver, NotTaken};
use ndn_namespace::root::daemon::MgmtDevice;
use ndn_namespace::root::init::{InitRequest, RootStoreChoice, YubikeyRoot};
use ndn_namespace::root::kit::{KitLocation, KitRequest, KitSpec};
use ndn_namespace::root::recover::RecoverRequest;
use ndn_namespace::root::{
    RootError, SecretRequest, SecretSource, init, key, kit, recover, revoke, schema,
};
use ndn_packet::Name;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use crate::daemon::Failure;

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

/// The daemon at `socket`, as the running device that takes what is
/// signed here; refusals it answers in the TUI's words.
fn device(socket: &str) -> MgmtDevice {
    MgmtDevice::new(socket).worded_by(crate::words::refusal)
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
    /// Start a new trusted prefix on this device, which becomes its main
    /// device as `<namespace>/admin/<device>`; its main key in `store`.
    Init {
        namespace: Name,
        device: String,
        store: RootStoreKind,
    },
    /// Make this device the main device of a trusted prefix whose main
    /// device is lost, with a recovery kit; the new main key in `store`.
    Recover {
        /// `None`: the one a file kit names, else the only one held.
        namespace: Option<Name>,
        kit: KitSpecArg,
        device: String,
        /// The old main device may be in someone else's hands: its keys
        /// are revoked (else they stay trusted).
        compromised: bool,
        /// Nothing answers: the person vouches that no newer version than
        /// the one held exists.
        from_held: bool,
        store: RootStoreKind,
    },
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
    /// Bring the trust schema up to date with what this build generates,
    /// with the policy the configuration states for the prefix; signed only
    /// if it narrows nothing, or with `accept_narrowing`.
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

impl KitSpecArg {
    fn spec(self) -> KitSpec {
        match self {
            KitSpecArg::Words => KitSpec::Words,
            KitSpecArg::File(path) => KitSpec::File(path),
            KitSpecArg::SecurityKey => KitSpec::Yubikey(security_key_kit()),
        }
    }
}

/// What the daemon must be told to run a trusted prefix's certificate
/// authority and sign as this device's admin identity: lines of its
/// configuration, shown in details (the daemon reads them at its start).
fn settings(namespace: &Name, identity: &Name, pib: &Path) -> Vec<String> {
    vec![
        "[security]".to_owned(),
        format!("identity = \"{identity}\""),
        format!("pib_path = \"{}\"", pib.display()),
        "[[ca]]".to_owned(),
        "enabled  = true".to_owned(),
        format!("prefix   = \"{namespace}\""),
        format!("identity = \"{namespace}/CA\""),
    ]
}

/// 64 hex digits.
fn hex(fp: &[u8; 32]) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect()
}

/// What a root operation did.
#[derive(Debug, Clone, PartialEq)]
pub enum RootDone {
    /// A new trusted prefix, this device its main device.
    Initialized {
        namespace: String,
        version: u64,
        /// This device's admin identity in it.
        identity: String,
        /// The root store kind the main key is kept in.
        store: String,
        fingerprint: String,
        /// The anchor link with the trust rules inline: what the daemon
        /// adopts.
        link: String,
        /// The short anchor link (fetched by name): what others scan.
        short_link: String,
        /// The daemon's configuration lines for its certificate authority.
        settings: Vec<String>,
        /// Whether the running daemon follows it now (set once it was
        /// handed the link); `None`: not asked yet.
        followed: Option<Result<u64, Failure>>,
    },
    /// A trusted prefix recovered onto this device, now its main device.
    Recovered {
        namespace: String,
        /// The version recovered from.
        previous: u64,
        /// The newest version: signed by the new main key once `root_handed`
        /// is taken.
        version: u64,
        /// A node confirmed the version recovered from is the newest
        /// (`false`: nothing answered and the person vouched for it).
        confirmed: bool,
        compromised: bool,
        identity: String,
        fingerprint: String,
        /// Keys the recovery revoked.
        revoked: usize,
        handed: Handed,
        /// Where the version signed by the new main key went; `Err`: it is
        /// not (known to be) taken.
        root_handed: Result<Handed, TrustRefusal>,
        /// The short anchor link, once the newest version is the new main
        /// key's.
        short_link: Option<String>,
        settings: Vec<String>,
    },
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
        /// What devices lost, accepted before signing.
        narrowed: usize,
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

/// Where a new main key goes, for `kind`.
fn store_choice(kind: RootStoreKind) -> RootStoreChoice {
    match kind {
        RootStoreKind::OsKeyring => RootStoreChoice::OsKeyring,
        RootStoreKind::SealedFile => RootStoreChoice::SealedFile,
        RootStoreKind::YubikeyPiv => RootStoreChoice::YubikeyPiv(YubikeyRoot::default()),
        RootStoreKind::File => RootStoreChoice::File,
    }
}

/// The policy the configuration's certificate-authority entry for
/// `namespace` states (none without a configuration or an entry).
pub fn stated_policy(
    config: Option<&ForwarderConfig>,
    namespace: &Name,
) -> Result<PolicyInput, Failure> {
    match config.and_then(|c| c.ca_for(namespace)) {
        Some(ca) => ca.policy_input().map_err(|e| {
            Failure::Refused(
                TrustRefusal::new(
                    code::NAMESPACE_POLICY_REFUSED,
                    "the stated namespace policy is refused",
                )
                .with("error", e),
            )
        }),
        None => Ok(PolicyInput::default()),
    }
}

/// Run `op` on the key storage at `pib`, handing what it signs to the
/// daemon at `socket`; secrets are asked through `secrets`; the policy a
/// new prefix or a schema update states is `config`'s.
pub async fn run(
    op: RootOp,
    pib: &Path,
    socket: &str,
    config: Option<&ForwarderConfig>,
    secrets: &TuiSecrets,
) -> Result<RootDone, Failure> {
    let device = device(socket);
    Ok(match op {
        RootOp::Init {
            namespace,
            device: name,
            store,
        } => {
            let made = init::init(
                InitRequest {
                    pib_dir: pib.to_path_buf(),
                    stated: stated_policy(config, &namespace)?,
                    namespace: namespace.clone(),
                    device: name,
                    force: false,
                    root: store_choice(store),
                },
                secrets,
            )
            .await?;
            let out = &made.persisted;
            RootDone::Initialized {
                namespace: namespace.to_string(),
                version: out.init.context.version(),
                identity: out.device_identity.to_string(),
                store: out.root_store.kind().as_str().to_owned(),
                fingerprint: hex(&made.anchor_fingerprint),
                link: out.init.envelope.to_uri(),
                short_link: made.fingerprint_link.to_uri(),
                settings: settings(&namespace, &out.device_identity, &made.pib_abs),
                followed: None,
            }
        }
        RootOp::Recover {
            namespace,
            kit,
            device: name,
            compromised,
            from_held,
            store,
        } => {
            let done = recover::recover(
                RecoverRequest {
                    pib_dir: pib.to_path_buf(),
                    kit: kit.spec(),
                    namespace,
                    device: name,
                    old_root: if compromised {
                        OldRoot::Compromised
                    } else {
                        OldRoot::Destroyed
                    },
                    kept_kits: Vec::new(),
                    from_held,
                    root: store_choice(store),
                },
                &device,
                secrets,
            )
            .await?;
            let r = &done.recovered;
            RootDone::Recovered {
                namespace: done.namespace.to_string(),
                previous: r.previous_version,
                version: r.root_version.context.version(),
                confirmed: done.confirmed,
                compromised,
                identity: r.device_identity.to_string(),
                fingerprint: hex(&done.anchor_fingerprint),
                revoked: done.revoked.len(),
                handed: Handed::from(&done.handed),
                root_handed: match &done.root_handed {
                    Ok(handed) => Ok(Handed::from(handed)),
                    Err(NotTaken::Refused(e) | NotTaken::Unknown(e)) => Err(e.refusal.clone()),
                },
                short_link: done.anchor_links().map(|(_, short)| short.to_uri()),
                settings: settings(&done.namespace, &r.device_identity, &done.pib_abs),
            }
        }
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
            let done = kit::check(pib, &spec.spec(), Some(&namespace), secrets).await?;
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
            let stated = stated_policy(config, &namespace)?;
            let planned = schema::plan_update(root, &stated, accept_narrowing)?;
            let done = schema::update(planned, pib, &device, secrets).await?;
            let change = &done.change;
            RootDone::SchemaUpdated {
                namespace: done.namespace.to_string(),
                version: done.version,
                added: change.added.len(),
                removed: change.removed.len(),
                narrowed: change.removed.len()
                    + change.link_narrowed.len()
                    + change.relays_dropped.len(),
                handed: Handed::from(&done.handed_over),
            }
        }
    })
}

/// What a schema update of a trusted prefix would change, worked out
/// before anything is unlocked or signed: shown so the person decides,
/// and says yes to any narrowing, first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaPreview {
    pub namespace: String,
    /// The version held now; the update signs the next one.
    pub held: u64,
    /// The configuration states a policy for this prefix (else the held
    /// version's is kept).
    pub stated: bool,
    /// Rules devices gain.
    pub added: Vec<String>,
    /// Rules of the held version the update drops: what devices relying on
    /// them lose.
    pub removed: Vec<String>,
    /// Checking goes by the rules alone, on every certificate.
    pub becomes_authoritative: bool,
    /// How devices join, when it changes.
    pub enrollment: Option<String>,
    /// The link rules before and after, when they change.
    pub links: Option<(String, String)>,
    /// What linked devices could do and no longer can.
    pub links_narrowed: Vec<String>,
    /// The relays before and after, when they change.
    pub relays: Option<(Vec<String>, Vec<String>)>,
    /// Relays devices lose.
    pub relays_dropped: Vec<String>,
}

impl SchemaPreview {
    /// Whether the update takes anything away from devices.
    pub fn narrows(&self) -> bool {
        !self.removed.is_empty()
            || !self.links_narrowed.is_empty()
            || !self.relays_dropped.is_empty()
    }

    /// Whether there is nothing to sign.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && !self.becomes_authoritative
            && self.enrollment.is_none()
            && self.links.is_none()
            && self.relays.is_none()
    }
}

/// What updating the schema of `namespace` (held in the key storage at
/// `pib`) with the policy `config` states would change, narrowing
/// included. Nothing is unlocked or signed.
pub fn preview_schema(
    pib: &Path,
    namespace: &Name,
    config: Option<&ForwarderConfig>,
) -> Result<SchemaPreview, Failure> {
    let root = schema::root_of(pib, Some(namespace))?;
    let held = root.context.version();
    let stated = stated_policy(config, namespace)?;
    let planned = schema::plan_update(root, &stated, true)?;
    let (plan, change) = (&planned.plan, &planned.plan.change);
    fn relays<R: ToString>(list: &[R]) -> Vec<String> {
        list.iter().map(ToString::to_string).collect()
    }
    Ok(SchemaPreview {
        namespace: namespace.to_string(),
        held,
        stated: stated != PolicyInput::default(),
        added: change.added.clone(),
        removed: change.removed.clone(),
        becomes_authoritative: change.becomes_authoritative,
        enrollment: change.changes_hint().then(|| plan.policy.describe()),
        links: change
            .changes_link()
            .then(|| (change.link_before.describe(), change.link.describe())),
        links_narrowed: change.link_narrowed.clone(),
        relays: change
            .changes_relays()
            .then(|| (relays(&change.relays_before), relays(&change.relays))),
        relays_dropped: change.relays_dropped.clone(),
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
