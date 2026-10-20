//! The screens' state: which screen and selection, the open dialog, the
//! forms being typed — and what each key does. Keys turn into [`Effect`]s
//! (listings to read, commands to run) that the event loop carries out;
//! their results come back as [`Msg`]s. Nothing here waits or draws.

use std::path::PathBuf;

use ndn_cert::RootStoreKind;
use ndn_cert::report::{
    ApprovalDecision, DataInspection, Detail, EnrollOutcome, PendingEnrollInfo,
};
use ndn_cert::{CreatedInvite, InviteEntry, InviteRequest, InviteState, IssuedEntry, KitFormat};
use ndn_mgmt_wire::{LinkModeArg, PendingApproval};
use ndn_packet::Name;
use ndn_trust_envelope::TrustEnvelope;
use zeroize::Zeroizing;

use crate::daemon::Failure;
use crate::model::{Listing, Model, Update};
use crate::root::{KitSpecArg, RootDone, RootOp, SchemaPreview, SecretAsk};
use crate::words;

/// A screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screen {
    /// The trusted prefixes (home).
    Prefixes,
    /// One trusted prefix.
    Prefix(String),
    Data,
    Connections,
    Node,
}

/// The part of a prefix's screen that has the selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Requests,
    Members,
    Invites,
    Kits,
}

impl Section {
    const ORDER: [Section; 4] = [
        Section::Requests,
        Section::Members,
        Section::Invites,
        Section::Kits,
    ];
}

/// A command for the daemon or this device's key storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    CreateInvite {
        ca: Name,
        request: InviteRequest,
    },
    WithdrawInvite {
        ca: Name,
        id: String,
    },
    Approve {
        request: String,
    },
    Deny {
        request: String,
        reason: String,
    },
    Follow {
        link: String,
    },
    Join {
        link: String,
        identity: Name,
    },
    LinkMode {
        label: String,
        mode: LinkModeArg,
    },
    LinkConnect {
        label: String,
    },
    LinkDisconnect {
        label: String,
    },
    Inspect {
        name: Name,
    },
    /// Read the page of cached names after `after`.
    MoreCached {
        after: Name,
    },
    Schema {
        namespace: Name,
    },
    /// Work out what a schema update would change (nothing signed).
    PreviewSchema {
        namespace: Name,
    },
    Refresh {
        namespace: Option<Name>,
    },
    Root(RootOp),
}

/// What the event loop does for the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Load(Listing),
    Run(Command),
    Quit,
}

/// What a command answered.
#[derive(Debug)]
pub enum Outcome {
    InviteMade(Result<CreatedInvite, Failure>),
    InviteWithdrawn(Result<InviteEntry, Failure>),
    Decided(Result<ApprovalDecision, Failure>),
    Followed(Result<ndn_cert::report::AdoptedContextInfo, Failure>),
    Joined(Result<EnrollOutcome, Failure>),
    Link(Result<Detail, Failure>),
    Inspected(Result<DataInspection, Failure>),
    Schema(Name, Result<Vec<String>, Failure>),
    SchemaPreview(Result<SchemaPreview, Failure>),
    Root(Result<RootDone, Failure>),
}

/// What reaches the app.
#[derive(Debug)]
pub enum Msg {
    Key(Key),
    Update(Update),
    Done(Box<Outcome>),
    Secret(SecretAsk),
}

impl std::fmt::Debug for SecretAsk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretAsk")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

/// A key, as the app reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Enter,
    Esc,
    Tab,
    BackTab,
    Up,
    Down,
    Backspace,
    /// Ctrl-C.
    Interrupt,
}

/// A line of text being typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Input {
    pub text: String,
}

impl Input {
    fn edit(&mut self, key: Key) -> bool {
        match key {
            Key::Char(c) => {
                self.text.push(c);
                true
            }
            Key::Backspace => {
                self.text.pop();
                true
            }
            _ => false,
        }
    }
}

/// How long an invite stays redeemable.
pub const EXPIRIES: [(&str, Option<u64>); 5] = [
    ("1 hour", Some(3_600)),
    ("1 day", Some(86_400)),
    ("7 days", Some(7 * 86_400)),
    ("30 days", Some(30 * 86_400)),
    ("until used or withdrawn", None),
];

/// The roles an invite admits (the others are certified on an approval).
pub const INVITE_ROLES: [&str; 2] = ["member", "guest"];
/// The roles a device asks an admin's approval for.
pub const APPROVAL_ROLES: [&str; 4] = ["admin", "node", "member", "guest"];
/// Where a new main key may be kept, in the order offered.
pub const NEW_ROOT_STORES: [RootStoreKind; 3] = [
    RootStoreKind::SealedFile,
    RootStoreKind::OsKeyring,
    RootStoreKind::YubikeyPiv,
];
/// The kinds of recovery kit, in the order offered.
pub const KIT_KINDS: [KitFormat; 3] = [KitFormat::Words, KitFormat::File, KitFormat::Yubikey];

/// A new trusted prefix being set up ("start a new trusted prefix").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPrefixForm {
    /// The prefix, e.g. `/home`.
    pub prefix: Input,
    /// This device's name in it.
    pub device: Input,
    /// Where the main key is kept ([`NEW_ROOT_STORES`]).
    pub store: usize,
    /// 0 prefix, 1 device, 2 store.
    pub field: usize,
    /// Why the form cannot go on yet.
    pub problem: Option<String>,
}

impl NewPrefixForm {
    const FIELDS: usize = 3;

    /// The prefix typed, when it is one.
    pub fn prefix(&self) -> Result<Name, String> {
        prefix_of(&self.prefix.text)
    }
}

/// A trusted prefix being recovered onto this device ("I lost my main
/// device").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverForm {
    /// The kind of kit ([`KIT_KINDS`]).
    pub kit: usize,
    /// A file kit's path.
    pub file: Input,
    /// The prefix; a file kit names its own, else the only one this device
    /// follows is taken.
    pub prefix: Input,
    /// This device's name in it.
    pub device: Input,
    /// The old main device may be in someone else's hands.
    pub compromised: bool,
    /// Where the new main key is kept ([`NEW_ROOT_STORES`]).
    pub store: usize,
    /// 0 kit, 1 file, 2 prefix, 3 device, 4 old device, 5 store.
    pub field: usize,
    pub problem: Option<String>,
}

impl RecoverForm {
    const FIELDS: usize = 6;

    /// The operation the form asks for, or why it cannot go on yet.
    pub fn op(&self, from_held: bool) -> Result<RootOp, String> {
        let kit = match KIT_KINDS[self.kit] {
            KitFormat::Words => KitSpecArg::Words,
            KitFormat::Yubikey => KitSpecArg::SecurityKey,
            KitFormat::File => {
                let path = self.file.text.trim();
                if path.is_empty() {
                    return Err("Type where the kit file is.".into());
                }
                KitSpecArg::File(PathBuf::from(path))
            }
        };
        let namespace = match self.prefix.text.trim() {
            "" => None,
            typed => Some(prefix_of(typed)?),
        };
        let device = device_of(&self.device.text)?;
        Ok(RootOp::Recover {
            namespace,
            kit,
            device,
            compromised: self.compromised,
            from_held,
            store: NEW_ROOT_STORES[self.store],
        })
    }
}

/// A typed trusted prefix, when it is one.
fn prefix_of(text: &str) -> Result<Name, String> {
    let text = text.trim();
    if !text.starts_with('/') || text.len() < 2 {
        return Err("A trusted prefix is a name that starts with /, e.g. /home.".into());
    }
    text.parse()
        .map_err(|_| format!("{text} is not a name this device can use."))
}

/// A typed device name, when it is one.
fn device_of(text: &str) -> Result<String, String> {
    let text = text.trim();
    if text.is_empty()
        || !text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err("A device name is letters, digits, - _ or . (e.g. desk).".into());
    }
    Ok(text.to_owned())
}

/// A trusted prefix this device started or recovered, as its dialog shows
/// it.
#[derive(Debug, Clone, PartialEq)]
pub struct Started {
    pub title: String,
    pub lines: Vec<String>,
    /// The short anchor link to scan (QR) or share.
    pub link: Option<String>,
    /// The prefix's expected fingerprint (hex), shown in details.
    pub fingerprint: String,
    /// The daemon's configuration lines, shown in details.
    pub settings: Vec<String>,
}

/// The invite being made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteForm {
    pub namespace: String,
    pub ca: String,
    pub role: usize,
    pub expiry: usize,
    pub device: Input,
    /// 0 role, 1 expiry, 2 device.
    pub field: usize,
}

/// What a pasted link is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkKind {
    /// Not read yet, or not a link.
    Unknown(Option<String>),
    /// An anchor link of `namespace`: follow it, or ask to join.
    Anchor { namespace: Option<String> },
    /// An invite to `scope` (`/<prefix>/<role>`), suggesting `device`.
    Invite {
        scope: String,
        device: Option<String>,
    },
}

/// The follow / join dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinForm {
    pub link: Input,
    pub kind: LinkKind,
    pub device: Input,
    /// For an anchor link: the role asked for.
    pub role: usize,
    /// 0 link, 1 device, 2 role.
    pub field: usize,
}

impl JoinForm {
    fn read_link(&mut self) {
        let text = self.link.text.trim();
        self.kind = if text.is_empty() {
            LinkKind::Unknown(None)
        } else {
            match TrustEnvelope::from_uri(text) {
                Ok(TrustEnvelope::Anchor { namespace, .. }) => LinkKind::Anchor { namespace },
                Ok(TrustEnvelope::Invite {
                    identity_namespace,
                    device,
                    ..
                }) => {
                    if self.device.text.is_empty()
                        && let Some(d) = &device
                    {
                        self.device.text = d.clone();
                    }
                    LinkKind::Invite {
                        scope: identity_namespace,
                        device,
                    }
                }
                Ok(_) => LinkKind::Unknown(Some(
                    "this link is neither an anchor link nor an invite".into(),
                )),
                Err(e) => {
                    LinkKind::Unknown(Some(format!("this is not a link this device reads ({e})")))
                }
            }
        };
    }

    /// The identity this device would join as.
    pub fn identity(&self) -> Option<Name> {
        let device = self.device.text.trim();
        if device.is_empty() {
            return None;
        }
        let text = match &self.kind {
            LinkKind::Invite { scope, .. } => format!("{}/{device}", scope.trim_end_matches('/')),
            LinkKind::Anchor {
                namespace: Some(ns),
            } => format!(
                "{}/{}/{device}",
                ns.trim_end_matches('/'),
                APPROVAL_ROLES[self.role]
            ),
            _ => return None,
        };
        text.parse().ok()
    }
}

/// A request for an admin's approval this device made, followed live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Waiting {
    pub pending: PendingEnrollInfo,
}

/// The choices of a recovery-kit dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KitAction {
    Create,
    Check,
}

/// An open dialog.
#[derive(Debug)]
pub enum Modal {
    Join(JoinForm),
    Waiting(Waiting),
    Invite(InviteForm),
    InviteMade(CreatedInvite),
    Approve(PendingApproval),
    Deny {
        row: PendingApproval,
        reason: Input,
    },
    Remove {
        namespace: String,
        member: IssuedEntry,
    },
    Kit {
        namespace: String,
        action: KitAction,
        path: Option<Input>,
    },
    RevokeKit {
        namespace: String,
        key: String,
    },
    KitWords {
        namespace: String,
        words: Zeroizing<String>,
    },
    MoveRoot {
        namespace: String,
    },
    Schema {
        namespace: String,
        lines: Vec<String>,
        scroll: usize,
    },
    /// What a schema update would change, before it is signed.
    SchemaPreview(SchemaPreview),
    NewPrefix(NewPrefixForm),
    Recover(RecoverForm),
    /// A recovery stopped because nothing answered whether a newer version
    /// exists: the person may vouch for the held one.
    RecoverUnconfirmed {
        op: RootOp,
        failure: Failure,
    },
    Started(Started),
    Secret(SecretDialog),
    Ask {
        name: Input,
    },
    Inspected(DataInspection),
    Message {
        title: String,
        lines: Vec<String>,
    },
    Busy(String),
}

/// A secret being typed.
#[derive(Debug)]
pub struct SecretDialog {
    pub ask: SecretAsk,
    pub prompt: String,
    pub input: Zeroizing<String>,
    /// The first entry of a new secret, while it is typed again.
    pub first: Option<Zeroizing<String>>,
    /// The two entries differed.
    pub mismatch: bool,
}

/// The TUI's whole state.
#[derive(Debug)]
pub struct App {
    pub model: Model,
    pub screen: Screen,
    pub details: bool,
    /// Selected row per list.
    pub selected: usize,
    pub section: Section,
    pub modal: Option<Modal>,
    /// A dialog a secret prompt covers, shown again when it is answered.
    pub covered: Option<Box<Modal>>,
    /// The last thing that happened, and whether it went wrong.
    pub status: Option<(String, bool)>,
    /// The daemon's management socket.
    pub socket: String,
    /// The PIB the daemon uses, where root operations work.
    pub pib: Option<PathBuf>,
    /// The waiting join, kept when its dialog is closed.
    pub waiting: Option<Waiting>,
    /// The recovery under way, offered again (vouching for the held
    /// version) when nothing answered whether a newer one exists.
    pub recovering: Option<RootOp>,
    /// The page of cached names being read (from after this name).
    pub paging: Option<Name>,
}

impl App {
    pub fn new(socket: &str) -> Self {
        Self {
            model: Model::default(),
            screen: Screen::Prefixes,
            details: false,
            selected: 0,
            section: Section::Requests,
            modal: None,
            covered: None,
            status: None,
            socket: socket.to_owned(),
            pib: None,
            waiting: None,
            recovering: None,
            paging: None,
        }
    }

    /// The effects of the first load.
    pub fn start(&self) -> Vec<Effect> {
        Listing::ALL.iter().map(|l| Effect::Load(*l)).collect()
    }

    /// On the data screen, read the next page of cached names once the
    /// selection is within a screen of the end of those listed.
    fn page_cached(&mut self) -> Vec<Effect> {
        const AHEAD: usize = 40;
        if self.screen != Screen::Data || self.selected + AHEAD < self.rows() {
            return Vec::new();
        }
        match self.model.cached_next() {
            Some(after) if self.paging.as_ref() != Some(&after) => {
                self.paging = Some(after.clone());
                vec![Effect::Run(Command::MoreCached { after })]
            }
            _ => Vec::new(),
        }
    }

    /// Take `msg` in.
    pub fn handle(&mut self, msg: Msg) -> Vec<Effect> {
        match msg {
            Msg::Key(key) => self.key(key),
            Msg::Update(update) => {
                let identity = matches!(update, Update::Identity(Ok(_)));
                if matches!(update, Update::Cached(_) | Update::CachedPage(_)) {
                    self.paging = None;
                }
                let mut effects: Vec<Effect> = self
                    .model
                    .apply(update)
                    .into_iter()
                    .map(Effect::Load)
                    .collect();
                if identity {
                    let pib = self
                        .model
                        .identity
                        .get()
                        .map(|s| PathBuf::from(&s.pib_path));
                    if pib != self.pib {
                        self.pib = pib;
                        effects.push(Effect::Load(Listing::Roots));
                    }
                }
                self.follow_waiting();
                effects
            }
            Msg::Done(outcome) => self.done(*outcome),
            Msg::Secret(ask) => {
                let prompt = words::secret_prompt(&ask.request);
                if let Some(open) = self.modal.take()
                    && !matches!(open, Modal::Busy(_))
                {
                    self.covered = Some(Box::new(open));
                }
                self.modal = Some(Modal::Secret(SecretDialog {
                    ask,
                    prompt,
                    input: Zeroizing::new(String::new()),
                    first: None,
                    mismatch: false,
                }));
                Vec::new()
            }
        }
    }

    fn say(&mut self, text: impl Into<String>) {
        self.status = Some((text.into(), false));
    }

    fn fail(&mut self, failure: &Failure) {
        self.status = Some((failure.words(), true));
    }

    /// The waiting join ended: say how.
    fn follow_waiting(&mut self) {
        let Some(waiting) = &self.waiting else { return };
        let Some(request) = self.model.request(&waiting.pending.request) else {
            return;
        };
        use ndn_cert::OutgoingState as S;
        let ended = match &request.state {
            S::Pending => return,
            S::Issued { .. } => format!(
                "Approved: this device is now {} in {}.",
                waiting.pending.identity, waiting.pending.namespace
            ),
            S::Denied { reason } | S::Expired { reason } | S::Failed { reason } => {
                words::detail(reason)
            }
        };
        let namespace = waiting.pending.namespace.clone();
        self.waiting = None;
        if matches!(self.modal, Some(Modal::Waiting(_))) {
            self.modal = Some(Modal::Message {
                title: format!("Joining {namespace}"),
                lines: vec![ended.clone()],
            });
        }
        self.say(ended);
    }

    fn done(&mut self, outcome: Outcome) -> Vec<Effect> {
        if matches!(self.modal, Some(Modal::Busy(_))) {
            self.modal = self.covered.take().map(|b| *b);
        }
        match outcome {
            Outcome::InviteMade(Ok(invite)) => {
                self.modal = Some(Modal::InviteMade(invite));
                vec![Effect::Load(Listing::Invites)]
            }
            Outcome::InviteWithdrawn(Ok(entry)) => {
                self.say(format!("Invite {} withdrawn.", entry.id));
                vec![Effect::Load(Listing::Invites)]
            }
            Outcome::Decided(Ok(decision)) => {
                self.say(format!(
                    "{} {} ({}).",
                    if decision.state == "approved" {
                        "Approved"
                    } else {
                        "Denied"
                    },
                    if decision.device.is_empty() {
                        &decision.key_name
                    } else {
                        &decision.device
                    },
                    words::role(&decision.role)
                ));
                vec![
                    Effect::Load(Listing::Approvals),
                    Effect::Load(Listing::Issued),
                ]
            }
            Outcome::Followed(Ok(info)) => {
                self.say(format!(
                    "Following {} (version {}).",
                    info.namespace, info.version
                ));
                vec![Effect::Load(Listing::Memberships)]
            }
            Outcome::Joined(Ok(EnrollOutcome::Enrolled(info))) => {
                self.say(format!("Joined: this device is now {}.", info.identity));
                vec![
                    Effect::Load(Listing::Memberships),
                    Effect::Load(Listing::Identity),
                ]
            }
            Outcome::Joined(Ok(EnrollOutcome::Pending(pending))) => {
                let waiting = Waiting { pending };
                self.waiting = Some(waiting.clone());
                self.modal = Some(Modal::Waiting(waiting));
                vec![Effect::Load(Listing::Requests)]
            }
            Outcome::Link(Ok(detail)) => {
                self.say(words::detail(&detail));
                vec![Effect::Load(Listing::Links)]
            }
            Outcome::Inspected(Ok(inspection)) => {
                self.modal = Some(Modal::Inspected(inspection));
                Vec::new()
            }
            Outcome::Schema(namespace, Ok(lines)) => {
                self.modal = Some(Modal::Schema {
                    namespace: namespace.to_string(),
                    lines,
                    scroll: 0,
                });
                Vec::new()
            }
            Outcome::SchemaPreview(Ok(preview)) => {
                if preview.is_empty() {
                    self.modal = Some(Modal::Message {
                        title: format!("Schema of {}", preview.namespace),
                        lines: vec![format!(
                            "Nothing to update: version {} of {} already carries this build's trust rules and the policy stated for it. Nothing was signed.",
                            preview.held, preview.namespace
                        )],
                    });
                } else {
                    self.modal = Some(Modal::SchemaPreview(preview));
                }
                Vec::new()
            }
            Outcome::Root(Ok(done)) => {
                self.recovering = None;
                self.root_done(done)
            }
            Outcome::Root(Err(f))
                if self.recovering.is_some()
                    && f.refusal()
                        .is_some_and(|r| r.is(ndn_cert::report::code::NEWEST_UNCONFIRMED)) =>
            {
                let op = self.recovering.take().expect("a recovery under way");
                self.modal = Some(Modal::RecoverUnconfirmed { op, failure: f });
                Vec::new()
            }
            Outcome::InviteMade(Err(f))
            | Outcome::InviteWithdrawn(Err(f))
            | Outcome::Decided(Err(f))
            | Outcome::Followed(Err(f))
            | Outcome::Joined(Err(f))
            | Outcome::Link(Err(f))
            | Outcome::Inspected(Err(f))
            | Outcome::Schema(_, Err(f))
            | Outcome::SchemaPreview(Err(f))
            | Outcome::Root(Err(f)) => {
                self.recovering = None;
                self.fail(&f);
                Vec::new()
            }
        }
    }

    fn root_done(&mut self, done: RootDone) -> Vec<Effect> {
        let handed = |h: &crate::root::Handed| match h {
            crate::root::Handed::Taken => "This device took it now.".to_owned(),
            crate::root::Handed::Stored { location } => format!(
                "The daemon is not running: the version is kept for its next start ({location})."
            ),
        };
        let authority = |namespace: &str, identity: &str| {
            format!(
                "For devices to join {namespace} (invites, approvals), the daemon must run its certificate authority and sign as {identity}: that takes the settings shown in details (d), then a restart of the daemon."
            )
        };
        match done {
            RootDone::Initialized {
                namespace,
                version,
                identity,
                store,
                fingerprint,
                short_link,
                settings,
                followed,
                ..
            } => {
                let lines = vec![
                    format!(
                        "{namespace} is a new trusted prefix (version {version}), and this device is its main device as {identity}."
                    ),
                    format!("Its main key is kept in {}.", words::root_store(&store)),
                    match &followed {
                        Some(Ok(_)) | None => {
                            "The daemon holds its trust rules now: other devices follow it with the link below.".to_owned()
                        }
                        Some(Err(f)) => format!(
                            "The daemon has not taken its trust rules yet ({}); it loads them at its next start.",
                            f.words()
                        ),
                    },
                    authority(&namespace, &identity),
                    "Next: make a recovery kit (open it and press k), so losing this device does not lose the prefix.".to_owned(),
                ];
                self.say(format!("Started {namespace}."));
                self.modal = Some(Modal::Started(Started {
                    title: format!("{namespace} started"),
                    lines,
                    link: Some(short_link),
                    fingerprint,
                    settings,
                }));
            }
            RootDone::Recovered {
                namespace,
                previous,
                version,
                confirmed,
                compromised,
                identity,
                fingerprint,
                revoked,
                handed: h,
                root_handed,
                short_link,
                settings,
            } => {
                let mut lines = vec![
                    format!("This device is now the main device of {namespace}, as {identity}."),
                    if compromised {
                        format!(
                            "Version {version} replaces version {previous}: it revokes {revoked} key{} of the old main device and the kits not used, so devices certified through the old main device join again.",
                            if revoked == 1 { "" } else { "s" }
                        )
                    } else {
                        format!(
                            "Version {version} replaces version {previous}: the old main device's certificates stay valid, so the other devices keep working."
                        )
                    },
                ];
                if !confirmed {
                    lines.push(format!(
                        "No device answered that version {previous} was the newest: you vouched for it."
                    ));
                }
                lines.push(handed(&h));
                match &root_handed {
                    Ok(_) => lines.push(
                        "The new main key signs it: share the link below from now on.".to_owned(),
                    ),
                    Err(r) => lines.push(format!(
                        "The version signed by the new main key is not known to be taken yet: {} Until it is, share no anchor link: one made now would stop working once it is.",
                        words::refusal(r)
                    )),
                }
                lines.push(authority(&namespace, &identity));
                lines.push("Next: make a new recovery kit (open it and press k).".to_owned());
                self.say(format!("Recovered {namespace}."));
                self.modal = Some(Modal::Started(Started {
                    title: format!("{namespace} recovered"),
                    lines,
                    link: short_link,
                    fingerprint,
                    settings,
                }));
            }
            RootDone::Revoked {
                namespace,
                version,
                revoked,
                handed: h,
            } => {
                self.modal = Some(Modal::Message {
                    title: format!("Removed from {namespace}"),
                    lines: vec![
                        format!(
                            "Version {version} of {namespace} no longer trusts {} key{}.",
                            revoked.len(),
                            if revoked.len() == 1 { "" } else { "s" }
                        ),
                        handed(&h),
                    ],
                });
            }
            RootDone::KitCreated {
                namespace,
                version,
                words: Some(words),
                ..
            } => {
                self.say(format!(
                    "Recovery kit made: version {version} of {namespace} lists it."
                ));
                self.modal = Some(Modal::KitWords { namespace, words });
            }
            RootDone::KitCreated {
                namespace,
                version,
                location,
                handed: h,
                ..
            } => {
                let mut lines = vec![format!(
                    "Version {version} of {namespace} lists the new kit."
                )];
                if let Some(location) = location {
                    lines.push(format!("Kept at: {location}"));
                }
                lines.push(match &h {
                    Ok(h) => handed(h),
                    Err(refusal) => words::refusal(refusal),
                });
                self.modal = Some(Modal::Message {
                    title: "Recovery kit made".into(),
                    lines,
                });
            }
            RootDone::KitChecked {
                namespace, version, ..
            } => {
                self.modal = Some(Modal::Message {
                    title: "Recovery kit checked".into(),
                    lines: vec![format!(
                        "The kit opens and recovers {namespace} (version {version} lists it)."
                    )],
                });
            }
            RootDone::KitRevoked {
                namespace,
                version,
                kits_left,
                handed: h,
                ..
            } => {
                self.modal = Some(Modal::Message {
                    title: "Recovery kit revoked".into(),
                    lines: vec![
                        format!(
                            "Version {version} of {namespace} no longer accepts that kit; {kits_left} kit{} left.",
                            if kits_left == 1 { "" } else { "s" }
                        ),
                        handed(&h),
                    ],
                });
            }
            RootDone::RootMoved {
                namespace,
                to,
                location,
                ..
            } => {
                self.modal = Some(Modal::Message {
                    title: "Main key moved".into(),
                    lines: vec![format!(
                        "The main key of {namespace} is now kept in {} ({location}).",
                        words::root_store(&to)
                    )],
                });
            }
            RootDone::SchemaUpdated {
                namespace,
                version,
                added,
                removed,
                narrowed,
                handed: h,
            } => {
                let mut lines = vec![format!(
                    "Version {version} of {namespace}: {added} rule{} added, {removed} removed.",
                    if added == 1 { "" } else { "s" }
                )];
                if narrowed > 0 {
                    lines.push(format!(
                        "It narrows what devices may do ({narrowed} change{}, as accepted): a device relying on them is refused once it holds version {version}.",
                        if narrowed == 1 { "" } else { "s" }
                    ));
                }
                lines.push(handed(&h));
                self.modal = Some(Modal::Message {
                    title: "Schema updated".into(),
                    lines,
                });
            }
        }
        vec![
            Effect::Load(Listing::Memberships),
            Effect::Load(Listing::Roots),
            Effect::Load(Listing::Issued),
        ]
    }

    fn busy(&mut self, what: impl Into<String>, command: Command) -> Vec<Effect> {
        self.modal = Some(Modal::Busy(what.into()));
        vec![Effect::Run(command)]
    }

    fn key(&mut self, key: Key) -> Vec<Effect> {
        if key == Key::Interrupt {
            return vec![Effect::Quit];
        }
        if self.modal.is_some() {
            return self.modal_key(key);
        }
        match key {
            Key::Char('q') => return vec![Effect::Quit],
            Key::Char('d') => self.details = !self.details,
            Key::Char('1') => self.go(Screen::Prefixes),
            Key::Char('2') => self.go(Screen::Data),
            Key::Char('3') => self.go(Screen::Connections),
            Key::Char('4') => self.go(Screen::Node),
            Key::Char('u') => {
                self.say("Checking for newer versions…");
                return vec![
                    Effect::Run(Command::Refresh { namespace: None }),
                    Effect::Load(Listing::Approvals),
                    Effect::Load(Listing::Links),
                    Effect::Load(Listing::Routes),
                    Effect::Load(Listing::Cached),
                ];
            }
            Key::Char('j') | Key::Char('f') => {
                self.modal = Some(Modal::Join(JoinForm {
                    link: Input::default(),
                    kind: LinkKind::Unknown(None),
                    device: Input { text: hostname() },
                    role: 2,
                    field: 0,
                }));
            }
            Key::Char('w') if self.screen != Screen::Prefixes || self.waiting.is_none() => {
                return self.screen_key(key);
            }
            Key::Char('w') => {
                if let Some(w) = &self.waiting {
                    self.modal = Some(Modal::Waiting(w.clone()));
                }
            }
            Key::Up => self.selected = self.selected.saturating_sub(1),
            Key::Down => {
                if self.selected + 1 < self.rows() {
                    self.selected += 1;
                }
                return self.page_cached();
            }
            Key::Esc => {
                if let Screen::Prefix(_) = self.screen {
                    self.go(Screen::Prefixes);
                }
            }
            _ => return self.screen_key(key),
        }
        Vec::new()
    }

    fn go(&mut self, screen: Screen) {
        self.screen = screen;
        self.selected = 0;
        self.section = Section::Requests;
    }

    /// How many rows the selection moves over.
    pub fn rows(&self) -> usize {
        match &self.screen {
            Screen::Prefixes => self.model.prefixes().len(),
            Screen::Prefix(ns) => self.section_rows(ns, self.section),
            Screen::Data => self.data_rows().len(),
            Screen::Connections => self.model.links.get().map_or(0, |l| l.links.len()),
            Screen::Node => 0,
        }
    }

    fn section_rows(&self, ns: &str, section: Section) -> usize {
        match section {
            Section::Requests => self.model.pending_in(ns).len(),
            Section::Members => self.model.members_in(ns).len(),
            Section::Invites => self.model.invites_in(ns).len(),
            Section::Kits => self.model.root_of(ns).map_or(0, |r| r.kits().count()),
        }
    }

    /// The sections a prefix's screen shows, for this device's powers.
    pub fn sections(&self, ns: &str) -> Vec<Section> {
        let powers = self.model.powers(ns);
        Section::ORDER
            .into_iter()
            .filter(|s| match s {
                Section::Requests => powers.approve,
                Section::Members => true,
                Section::Invites => powers.invite,
                Section::Kits => powers.root,
            })
            .collect()
    }

    /// The names the data screen lists: served prefixes, then cached
    /// names.
    pub fn data_rows(&self) -> Vec<(String, bool)> {
        let mut rows: Vec<(String, bool)> = self
            .model
            .served()
            .into_iter()
            .map(|(n, _)| (n, true))
            .collect();
        if let Some(cached) = self.model.cached.get() {
            rows.extend(cached.entries.iter().map(|e| (e.name.to_string(), false)));
        }
        rows
    }

    fn screen_key(&mut self, key: Key) -> Vec<Effect> {
        match self.screen.clone() {
            Screen::Prefixes => match key {
                Key::Enter => {
                    if let Some(row) = self.model.prefixes().get(self.selected) {
                        let ns = row.namespace.clone();
                        self.go(Screen::Prefix(ns.clone()));
                        self.section = self
                            .sections(&ns)
                            .into_iter()
                            .find(|s| self.section_rows(&ns, *s) > 0)
                            .unwrap_or(Section::Members);
                    }
                }
                Key::Char('a') => {
                    if let Some(first) = self.model.pending().first() {
                        let ns = self
                            .model
                            .prefixes()
                            .into_iter()
                            .find(|p| p.pending > 0)
                            .map(|p| p.namespace);
                        let row = (*first).clone();
                        if let Some(ns) = ns {
                            self.go(Screen::Prefix(ns));
                        }
                        self.modal = Some(Modal::Approve(row));
                    }
                }
                Key::Char('n') => {
                    self.modal = Some(Modal::NewPrefix(NewPrefixForm {
                        prefix: Input::default(),
                        device: Input { text: hostname() },
                        store: 0,
                        field: 0,
                        problem: None,
                    }));
                }
                Key::Char('r') => {
                    // The prefix this device follows, when it follows one only.
                    let prefixes = self.model.prefixes();
                    let prefix = match prefixes.as_slice() {
                        [only] => only.namespace.clone(),
                        _ => String::new(),
                    };
                    self.modal = Some(Modal::Recover(RecoverForm {
                        kit: 0,
                        file: Input::default(),
                        prefix: Input { text: prefix },
                        device: Input { text: hostname() },
                        compromised: false,
                        store: 0,
                        field: 0,
                        problem: None,
                    }));
                }
                _ => {}
            },
            Screen::Prefix(ns) => return self.prefix_key(&ns, key),
            Screen::Data => match key {
                Key::Enter => {
                    if let Some((name, _)) = self.data_rows().get(self.selected)
                        && let Ok(name) = name.parse::<Name>()
                    {
                        return self.busy(format!("Fetching {name}…"), Command::Inspect { name });
                    }
                }
                Key::Char('/') | Key::Char('g') => {
                    self.modal = Some(Modal::Ask {
                        name: Input::default(),
                    });
                }
                _ => {}
            },
            Screen::Connections => {
                let Some(entry) = self
                    .model
                    .links
                    .get()
                    .and_then(|l| l.links.get(self.selected))
                    .cloned()
                else {
                    return Vec::new();
                };
                let label = entry.label.clone();
                match key {
                    Key::Char('m') => {
                        let mode = match entry.mode.as_deref() {
                            Some("always") => LinkModeArg::OnDemand { idle_secs: None },
                            Some("on-demand") => LinkModeArg::Off,
                            _ => LinkModeArg::Always,
                        };
                        return vec![Effect::Run(Command::LinkMode { label, mode })];
                    }
                    Key::Char('c') => return vec![Effect::Run(Command::LinkConnect { label })],
                    Key::Char('x') => {
                        return vec![Effect::Run(Command::LinkDisconnect { label })];
                    }
                    _ => {}
                }
            }
            Screen::Node => {}
        }
        Vec::new()
    }

    fn prefix_key(&mut self, ns: &str, key: Key) -> Vec<Effect> {
        let powers = self.model.powers(ns);
        let sections = self.sections(ns);
        match key {
            Key::Tab | Key::BackTab => {
                if let Some(at) = sections.iter().position(|s| *s == self.section) {
                    let n = sections.len();
                    let next = if key == Key::Tab { at + 1 } else { at + n - 1 };
                    self.section = sections[next % n];
                } else if let Some(first) = sections.first() {
                    self.section = *first;
                }
                self.selected = 0;
            }
            Key::Char('a') if self.section == Section::Requests => {
                if let Some(row) = self.model.pending_in(ns).get(self.selected) {
                    self.modal = Some(Modal::Approve((*row).clone()));
                }
            }
            Key::Char('n') if self.section == Section::Requests => {
                if let Some(row) = self.model.pending_in(ns).get(self.selected) {
                    self.modal = Some(Modal::Deny {
                        row: (*row).clone(),
                        reason: Input::default(),
                    });
                }
            }
            Key::Char('i') if powers.invite => {
                if let Some(ca) = self.model.invite_ca(ns) {
                    self.modal = Some(Modal::Invite(InviteForm {
                        namespace: ns.to_owned(),
                        ca: ca.ca.clone(),
                        role: 0,
                        expiry: 1,
                        device: Input::default(),
                        field: 0,
                    }));
                }
            }
            Key::Char('w') if self.section == Section::Invites => {
                let invite = self
                    .model
                    .invites_in(ns)
                    .get(self.selected)
                    .map(|i| (i.id.clone(), i.info.state));
                if let (Some((id, InviteState::Outstanding)), Some(ca)) =
                    (invite, self.model.invite_ca(ns).map(|c| c.ca.clone()))
                    && let Ok(ca) = ca.parse()
                {
                    return vec![Effect::Run(Command::WithdrawInvite { ca, id })];
                }
            }
            Key::Char('x') if self.section == Section::Members && powers.root => {
                if let Some(member) = self.model.members_in(ns).get(self.selected)
                    && !member.revoked
                {
                    self.modal = Some(Modal::Remove {
                        namespace: ns.to_owned(),
                        member: (*member).clone(),
                    });
                }
            }
            Key::Char('x') if self.section == Section::Kits && powers.root => {
                if let Some(kit) = self
                    .model
                    .root_of(ns)
                    .and_then(|r| r.kits().nth(self.selected))
                {
                    self.modal = Some(Modal::RevokeKit {
                        namespace: ns.to_owned(),
                        key: kit.key.clone(),
                    });
                }
            }
            Key::Char('k') if powers.root => {
                self.modal = Some(Modal::Kit {
                    namespace: ns.to_owned(),
                    action: KitAction::Create,
                    path: None,
                });
            }
            Key::Char('c') if powers.root => {
                self.modal = Some(Modal::Kit {
                    namespace: ns.to_owned(),
                    action: KitAction::Check,
                    path: None,
                });
            }
            Key::Char('m') if powers.root => {
                self.modal = Some(Modal::MoveRoot {
                    namespace: ns.to_owned(),
                });
            }
            Key::Char('s') => {
                if let Ok(namespace) = ns.parse() {
                    return self.busy("Reading the schema…", Command::Schema { namespace });
                }
            }
            _ => {}
        }
        Vec::new()
    }

    fn modal_key(&mut self, key: Key) -> Vec<Effect> {
        let Some(modal) = self.modal.take() else {
            return Vec::new();
        };
        let (keep, effects) = self.dialog(modal, key);
        if self.modal.is_none() {
            self.modal = keep;
        }
        if self.modal.is_none() {
            self.modal = self.covered.take().map(|b| *b);
        }
        effects
    }

    /// One key in the open dialog: the dialog to keep open (`None`: close)
    /// and what to do.
    fn dialog(&mut self, modal: Modal, key: Key) -> (Option<Modal>, Vec<Effect>) {
        let none = Vec::new;
        match modal {
            Modal::Busy(what) => (Some(Modal::Busy(what)), none()),
            Modal::Secret(mut dialog) => match key {
                Key::Esc => {
                    let _ = dialog.ask.reply.send(None);
                    (None, none())
                }
                Key::Enter => {
                    let typed = std::mem::replace(&mut dialog.input, Zeroizing::new(String::new()));
                    if dialog.ask.request.confirm {
                        match dialog.first.take() {
                            None => {
                                dialog.first = Some(typed);
                                dialog.mismatch = false;
                                return (Some(Modal::Secret(dialog)), none());
                            }
                            Some(first) if *first != *typed => {
                                dialog.mismatch = true;
                                return (Some(Modal::Secret(dialog)), none());
                            }
                            Some(_) => {}
                        }
                    }
                    let _ = dialog.ask.reply.send(Some(typed));
                    (Some(Modal::Busy("Working…".into())), none())
                }
                Key::Backspace => {
                    dialog.input.pop();
                    (Some(Modal::Secret(dialog)), none())
                }
                Key::Char(c) => {
                    dialog.input.push(c);
                    (Some(Modal::Secret(dialog)), none())
                }
                _ => (Some(Modal::Secret(dialog)), none()),
            },
            Modal::Join(mut form) => match key {
                Key::Esc => (None, none()),
                Key::Tab | Key::Down => {
                    form.field = (form.field + 1) % 3;
                    (Some(Modal::Join(form)), none())
                }
                Key::BackTab | Key::Up => {
                    form.field = (form.field + 2) % 3;
                    (Some(Modal::Join(form)), none())
                }
                Key::Char('f') if form.field == 2 => match &form.kind {
                    LinkKind::Anchor { .. } => {
                        let link = form.link.text.trim().to_owned();
                        self.modal = Some(Modal::Busy("Following…".into()));
                        (None, vec![Effect::Run(Command::Follow { link })])
                    }
                    _ => (Some(Modal::Join(form)), none()),
                },
                Key::Char('<') | Key::Char('>') if form.field == 2 => {
                    let n = APPROVAL_ROLES.len();
                    form.role = if key == Key::Char('>') {
                        (form.role + 1) % n
                    } else {
                        (form.role + n - 1) % n
                    };
                    (Some(Modal::Join(form)), none())
                }
                Key::Enter => {
                    let identity = form.identity();
                    match (&form.kind, identity) {
                        (
                            LinkKind::Invite { .. } | LinkKind::Anchor { namespace: Some(_) },
                            Some(identity),
                        ) => {
                            let link = form.link.text.trim().to_owned();
                            self.modal = Some(Modal::Busy(format!("Joining as {identity}…")));
                            (None, vec![Effect::Run(Command::Join { link, identity })])
                        }
                        _ => {
                            form.field = (form.field + 1) % 3;
                            (Some(Modal::Join(form)), none())
                        }
                    }
                }
                other => {
                    let edited = match form.field {
                        0 => {
                            let changed = form.link.edit(other);
                            if changed {
                                form.read_link();
                            }
                            changed
                        }
                        1 => form.device.edit(other),
                        _ => false,
                    };
                    let _ = edited;
                    (Some(Modal::Join(form)), none())
                }
            },
            Modal::Waiting(w) => match key {
                Key::Esc | Key::Enter => {
                    self.say("Still waiting for an admin; press w to see the code again.");
                    (None, none())
                }
                _ => (Some(Modal::Waiting(w)), none()),
            },
            Modal::Invite(mut form) => match key {
                Key::Esc => (None, none()),
                Key::Tab | Key::Down => {
                    form.field = (form.field + 1) % 3;
                    (Some(Modal::Invite(form)), none())
                }
                Key::BackTab | Key::Up => {
                    form.field = (form.field + 2) % 3;
                    (Some(Modal::Invite(form)), none())
                }
                Key::Char('<') | Key::Char('>') if form.field < 2 => {
                    let forward = key == Key::Char('>');
                    let step = |at: usize, n: usize| {
                        if forward {
                            (at + 1) % n
                        } else {
                            (at + n - 1) % n
                        }
                    };
                    if form.field == 0 {
                        form.role = step(form.role, INVITE_ROLES.len());
                    } else {
                        form.expiry = step(form.expiry, EXPIRIES.len());
                    }
                    (Some(Modal::Invite(form)), none())
                }
                Key::Enter => {
                    let Ok(ca) = form.ca.parse::<Name>() else {
                        return (None, none());
                    };
                    let device = form.device.text.trim();
                    let request = InviteRequest {
                        role: INVITE_ROLES[form.role].to_owned(),
                        ttl_secs: EXPIRIES[form.expiry].1,
                        device: (!device.is_empty()).then(|| device.to_owned()),
                    };
                    self.modal = Some(Modal::Busy("Making the invite…".into()));
                    (
                        None,
                        vec![Effect::Run(Command::CreateInvite { ca, request })],
                    )
                }
                other => {
                    if form.field == 2 {
                        form.device.edit(other);
                    }
                    (Some(Modal::Invite(form)), none())
                }
            },
            Modal::InviteMade(invite) => match key {
                Key::Esc | Key::Enter => (None, none()),
                _ => (Some(Modal::InviteMade(invite)), none()),
            },
            Modal::Approve(row) => match key {
                Key::Char('a') | Key::Char('y') => {
                    let request = row.request_id.clone();
                    self.modal = Some(Modal::Busy("Approving…".into()));
                    (None, vec![Effect::Run(Command::Approve { request })])
                }
                Key::Char('n') => (
                    Some(Modal::Deny {
                        row,
                        reason: Input::default(),
                    }),
                    none(),
                ),
                Key::Esc => (None, none()),
                _ => (Some(Modal::Approve(row)), none()),
            },
            Modal::Deny { row, mut reason } => match key {
                Key::Esc => (None, none()),
                Key::Enter => {
                    let request = row.request_id.clone();
                    let reason = reason.text.trim().to_owned();
                    self.modal = Some(Modal::Busy("Denying…".into()));
                    (None, vec![Effect::Run(Command::Deny { request, reason })])
                }
                other => {
                    reason.edit(other);
                    (Some(Modal::Deny { row, reason }), none())
                }
            },
            Modal::Remove { namespace, member } => match key {
                Key::Char('y') => {
                    let (Ok(ns), Ok(name)) = (namespace.parse(), member.identity.parse()) else {
                        return (None, none());
                    };
                    self.modal = Some(Modal::Busy(format!("Removing {}…", member.identity)));
                    (
                        None,
                        vec![Effect::Run(Command::Root(RootOp::Revoke {
                            namespace: ns,
                            name,
                        }))],
                    )
                }
                Key::Esc | Key::Char('n') => (None, none()),
                _ => (Some(Modal::Remove { namespace, member }), none()),
            },
            Modal::Kit {
                namespace,
                action,
                path: Some(mut path),
            } => match key {
                Key::Esc => (None, none()),
                Key::Enter => {
                    let file = PathBuf::from(path.text.trim());
                    let Ok(ns) = namespace.parse::<Name>() else {
                        return (None, none());
                    };
                    let op = match action {
                        KitAction::Create => RootOp::KitCreate {
                            namespace: ns,
                            format: KitFormat::File,
                            out: Some(file),
                        },
                        KitAction::Check => RootOp::KitCheck {
                            namespace: ns,
                            spec: KitSpecArg::File(file),
                        },
                    };
                    self.modal = Some(Modal::Busy("Working…".into()));
                    (None, vec![Effect::Run(Command::Root(op))])
                }
                other => {
                    path.edit(other);
                    (
                        Some(Modal::Kit {
                            namespace,
                            action,
                            path: Some(path),
                        }),
                        none(),
                    )
                }
            },
            Modal::Kit {
                namespace,
                action,
                path: None,
            } => {
                let Ok(ns) = namespace.parse::<Name>() else {
                    return (None, none());
                };
                let op = match (key, action) {
                    (Key::Esc, _) => return (None, none()),
                    (Key::Char('f'), _) => {
                        let default = home_file(&namespace);
                        return (
                            Some(Modal::Kit {
                                namespace,
                                action,
                                path: Some(Input { text: default }),
                            }),
                            none(),
                        );
                    }
                    (Key::Char('w'), KitAction::Create) => RootOp::KitCreate {
                        namespace: ns,
                        format: KitFormat::Words,
                        out: None,
                    },
                    (Key::Char('h'), KitAction::Create) => RootOp::KitCreate {
                        namespace: ns,
                        format: KitFormat::Yubikey,
                        out: None,
                    },
                    (Key::Char('w'), KitAction::Check) => RootOp::KitCheck {
                        namespace: ns,
                        spec: KitSpecArg::Words,
                    },
                    (Key::Char('h'), KitAction::Check) => RootOp::KitCheck {
                        namespace: ns,
                        spec: KitSpecArg::SecurityKey,
                    },
                    _ => {
                        return (
                            Some(Modal::Kit {
                                namespace,
                                action,
                                path: None,
                            }),
                            none(),
                        );
                    }
                };
                self.modal = Some(Modal::Busy("Working…".into()));
                (None, vec![Effect::Run(Command::Root(op))])
            }
            Modal::RevokeKit {
                namespace,
                key: kit,
            } => match key {
                Key::Char('y') => {
                    let (Ok(ns), Ok(k)) = (namespace.parse(), kit.parse()) else {
                        return (None, none());
                    };
                    self.modal = Some(Modal::Busy("Revoking the kit…".into()));
                    (
                        None,
                        vec![Effect::Run(Command::Root(RootOp::KitRevoke {
                            namespace: ns,
                            key: k,
                        }))],
                    )
                }
                Key::Esc | Key::Char('n') => (None, none()),
                _ => (
                    Some(Modal::RevokeKit {
                        namespace,
                        key: kit,
                    }),
                    none(),
                ),
            },
            Modal::KitWords { namespace, words } => match key {
                // The words are dropped (zeroed) once the dialog closes.
                Key::Enter | Key::Esc => (None, none()),
                _ => (Some(Modal::KitWords { namespace, words }), none()),
            },
            Modal::MoveRoot { namespace } => {
                let to = match key {
                    Key::Char('k') => RootStoreKind::OsKeyring,
                    Key::Char('p') => RootStoreKind::SealedFile,
                    Key::Esc => return (None, none()),
                    _ => return (Some(Modal::MoveRoot { namespace }), none()),
                };
                let Ok(ns) = namespace.parse() else {
                    return (None, none());
                };
                self.modal = Some(Modal::Busy("Moving the main key…".into()));
                (
                    None,
                    vec![Effect::Run(Command::Root(RootOp::MoveRoot {
                        namespace: ns,
                        to,
                    }))],
                )
            }
            Modal::Schema {
                namespace,
                lines,
                mut scroll,
            } => match key {
                Key::Esc | Key::Enter => (None, none()),
                Key::Down => {
                    scroll = (scroll + 1).min(lines.len().saturating_sub(1));
                    (
                        Some(Modal::Schema {
                            namespace,
                            lines,
                            scroll,
                        }),
                        none(),
                    )
                }
                Key::Up => {
                    scroll = scroll.saturating_sub(1);
                    (
                        Some(Modal::Schema {
                            namespace,
                            lines,
                            scroll,
                        }),
                        none(),
                    )
                }
                Key::Char('u') if self.model.powers(&namespace).root => {
                    let Ok(ns) = namespace.parse() else {
                        return (None, none());
                    };
                    self.modal = Some(Modal::Busy(
                        "Working out what the update changes (nothing is signed yet)…".into(),
                    ));
                    (
                        None,
                        vec![Effect::Run(Command::PreviewSchema { namespace: ns })],
                    )
                }
                _ => (
                    Some(Modal::Schema {
                        namespace,
                        lines,
                        scroll,
                    }),
                    none(),
                ),
            },
            Modal::Ask { mut name } => match key {
                Key::Esc => (None, none()),
                Key::Enter => match name.text.trim().parse::<Name>() {
                    Ok(name) => {
                        self.modal = Some(Modal::Busy(format!("Fetching {name}…")));
                        (None, vec![Effect::Run(Command::Inspect { name })])
                    }
                    Err(_) => {
                        self.status = Some(("That is not a name (it starts with /).".into(), true));
                        (Some(Modal::Ask { name }), none())
                    }
                },
                other => {
                    name.edit(other);
                    (Some(Modal::Ask { name }), none())
                }
            },
            Modal::Inspected(inspection) => match key {
                Key::Esc | Key::Enter => (None, none()),
                _ => (Some(Modal::Inspected(inspection)), none()),
            },
            Modal::SchemaPreview(preview) => {
                let sign = match key {
                    Key::Char('y') if !preview.narrows() => Some(false),
                    Key::Char('a') if preview.narrows() => Some(true),
                    Key::Esc | Key::Char('n') => return (None, none()),
                    _ => None,
                };
                match (sign, preview.namespace.parse()) {
                    (Some(accept_narrowing), Ok(ns)) => {
                        self.modal = Some(Modal::Busy("Updating the schema…".into()));
                        (
                            None,
                            vec![Effect::Run(Command::Root(RootOp::SchemaUpdate {
                                namespace: ns,
                                accept_narrowing,
                            }))],
                        )
                    }
                    _ => (Some(Modal::SchemaPreview(preview)), none()),
                }
            }
            Modal::NewPrefix(mut form) => match key {
                Key::Esc => (None, none()),
                Key::Tab | Key::Down => {
                    form.field = (form.field + 1) % NewPrefixForm::FIELDS;
                    (Some(Modal::NewPrefix(form)), none())
                }
                Key::BackTab | Key::Up => {
                    form.field = (form.field + NewPrefixForm::FIELDS - 1) % NewPrefixForm::FIELDS;
                    (Some(Modal::NewPrefix(form)), none())
                }
                Key::Char('<') | Key::Char('>') if form.field == 2 => {
                    form.store = step(form.store, NEW_ROOT_STORES.len(), key);
                    (Some(Modal::NewPrefix(form)), none())
                }
                Key::Enter => {
                    let op = form.prefix().and_then(|namespace| {
                        Ok(RootOp::Init {
                            namespace,
                            device: device_of(&form.device.text)?,
                            store: NEW_ROOT_STORES[form.store],
                        })
                    });
                    match op {
                        Ok(op) => {
                            form.problem = None;
                            self.covered = Some(Box::new(Modal::NewPrefix(form)));
                            self.modal = Some(Modal::Busy("Starting the trusted prefix…".into()));
                            (None, vec![Effect::Run(Command::Root(op))])
                        }
                        Err(problem) => {
                            form.problem = Some(problem);
                            (Some(Modal::NewPrefix(form)), none())
                        }
                    }
                }
                other => {
                    match form.field {
                        0 => form.prefix.edit(other),
                        1 => form.device.edit(other),
                        _ => false,
                    };
                    (Some(Modal::NewPrefix(form)), none())
                }
            },
            Modal::Recover(mut form) => {
                // The file field is there only for a file kit.
                let skip = |form: &RecoverForm, field: usize| {
                    field == 1 && KIT_KINDS[form.kit] != KitFormat::File
                };
                match key {
                    Key::Esc => (None, none()),
                    Key::Tab | Key::Down | Key::BackTab | Key::Up => {
                        let n = RecoverForm::FIELDS;
                        let forward = matches!(key, Key::Tab | Key::Down);
                        loop {
                            form.field = if forward {
                                (form.field + 1) % n
                            } else {
                                (form.field + n - 1) % n
                            };
                            if !skip(&form, form.field) {
                                break;
                            }
                        }
                        (Some(Modal::Recover(form)), none())
                    }
                    Key::Char('<') | Key::Char('>') if matches!(form.field, 0 | 4 | 5) => {
                        match form.field {
                            0 => form.kit = step(form.kit, KIT_KINDS.len(), key),
                            4 => form.compromised = !form.compromised,
                            _ => form.store = step(form.store, NEW_ROOT_STORES.len(), key),
                        }
                        (Some(Modal::Recover(form)), none())
                    }
                    Key::Enter => match form.op(false) {
                        Ok(op) => {
                            form.problem = None;
                            self.recovering = Some(op.clone());
                            self.covered = Some(Box::new(Modal::Recover(form)));
                            self.modal = Some(Modal::Busy(
                                "Recovering: checking for the newest version first…".into(),
                            ));
                            (None, vec![Effect::Run(Command::Root(op))])
                        }
                        Err(problem) => {
                            form.problem = Some(problem);
                            (Some(Modal::Recover(form)), none())
                        }
                    },
                    other => {
                        match form.field {
                            1 => form.file.edit(other),
                            2 => form.prefix.edit(other),
                            3 => form.device.edit(other),
                            _ => false,
                        };
                        (Some(Modal::Recover(form)), none())
                    }
                }
            }
            Modal::RecoverUnconfirmed { op, failure } => match (key, op) {
                (
                    Key::Char('h'),
                    RootOp::Recover {
                        namespace,
                        kit,
                        device,
                        compromised,
                        store,
                        ..
                    },
                ) => {
                    let op = RootOp::Recover {
                        namespace,
                        kit,
                        device,
                        compromised,
                        from_held: true,
                        store,
                    };
                    self.recovering = Some(op.clone());
                    self.modal = Some(Modal::Busy(
                        "Recovering from the version this device holds…".into(),
                    ));
                    (None, vec![Effect::Run(Command::Root(op))])
                }
                (Key::Esc | Key::Enter, _) => (None, none()),
                (_, op) => (Some(Modal::RecoverUnconfirmed { op, failure }), none()),
            },
            Modal::Started(started) => match key {
                Key::Esc | Key::Enter => (None, none()),
                Key::Char('d') => {
                    self.details = !self.details;
                    (Some(Modal::Started(started)), none())
                }
                _ => (Some(Modal::Started(started)), none()),
            },
            Modal::Message { title, lines } => match key {
                Key::Esc | Key::Enter => (None, none()),
                _ => (Some(Modal::Message { title, lines }), none()),
            },
        }
    }
}

/// This machine's host name: the default device name to join as.
pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_owned())
        .unwrap_or_default()
}

/// Where a file kit of `namespace` is written by default.
fn home_file(namespace: &str) -> String {
    let base = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let name: String = namespace
        .trim_matches('/')
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("{base}/{name}-recovery-kit")
}

/// The choice after (`>`) or before (`<`) `at` of `n`.
fn step(at: usize, n: usize, key: Key) -> usize {
    if key == Key::Char('>') {
        (at + 1) % n
    } else {
        (at + n - 1) % n
    }
}
