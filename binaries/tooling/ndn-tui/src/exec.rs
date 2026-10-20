//! Carrying out the app's commands: each one asks the daemon (or runs a
//! root operation in this process) and comes back as a [`Msg`].

use std::path::PathBuf;
use std::sync::Arc;

use crate::app::{Command, Msg, Outcome};
use crate::daemon::{Daemon, Failure};
use crate::model::Update;
use crate::root::{self, TuiSecrets};

/// What commands run with.
pub struct Runner {
    pub daemon: Arc<Daemon>,
    pub secrets: Arc<TuiSecrets>,
    /// The daemon's configuration, when given: the policy its
    /// certificate-authority entry states for a prefix goes into a new
    /// prefix and a schema update.
    pub config: Option<ndn_config::ForwarderConfig>,
}

/// The key storage is not known yet (the daemon has not said where).
fn no_pib() -> Failure {
    Failure::Unreachable("the daemon has not said where its keys are kept".into())
}

impl Runner {
    /// Run `command`; `pib` is the daemon's key storage, where root
    /// operations work.
    pub async fn run(&self, command: Command, pib: Option<PathBuf>) -> Msg {
        let d = &self.daemon;
        let done = |o: Outcome| Msg::Done(Box::new(o));
        match command {
            Command::CreateInvite { ca, request } => {
                done(Outcome::InviteMade(d.create_invite(&ca, &request).await))
            }
            Command::WithdrawInvite { ca, id } => {
                done(Outcome::InviteWithdrawn(d.withdraw_invite(&ca, &id).await))
            }
            Command::Approve { request } => done(Outcome::Decided(d.approve(&request).await)),
            Command::Deny { request, reason } => {
                done(Outcome::Decided(d.deny(&request, &reason).await))
            }
            Command::Follow { link } => done(Outcome::Followed(d.follow(&link).await)),
            Command::Join { link, identity } => {
                done(Outcome::Joined(d.join(&link, &identity).await))
            }
            Command::LinkMode { label, mode } => {
                done(Outcome::Link(d.set_link_mode(&label, mode).await))
            }
            Command::LinkConnect { label } => done(Outcome::Link(d.connect_link(&label).await)),
            Command::LinkDisconnect { label } => {
                done(Outcome::Link(d.disconnect_link(&label).await))
            }
            Command::Inspect { name } => done(Outcome::Inspected(d.inspect(&name).await)),
            Command::MoreCached { after } => {
                Msg::Update(Update::CachedPage(d.cached(None, Some(&after)).await))
            }
            Command::Refresh { namespace } => {
                Msg::Update(Update::Refreshed(d.refresh(namespace.as_ref()).await))
            }
            Command::Schema { namespace } => {
                let lines = match &pib {
                    Some(pib) => root::schema_lines(pib, &namespace),
                    None => Err(no_pib()),
                };
                done(Outcome::Schema(namespace, lines))
            }
            Command::PreviewSchema { namespace } => done(Outcome::SchemaPreview(match &pib {
                Some(pib) => root::preview_schema(pib, &namespace, self.config.as_ref()),
                None => Err(no_pib()),
            })),
            Command::Root(op) => {
                let mut result = match &pib {
                    Some(pib) => {
                        root::run(op, pib, d.socket(), self.config.as_ref(), &self.secrets).await
                    }
                    None => Err(no_pib()),
                };
                // A new prefix is in the key storage; the running daemon
                // follows it once handed its anchor link (the trust rules
                // inline, nothing fetched).
                if let Ok(root::RootDone::Initialized { link, followed, .. }) = &mut result {
                    *followed = Some(d.follow(link).await.map(|info| info.version));
                }
                done(Outcome::Root(result))
            }
        }
    }
}
