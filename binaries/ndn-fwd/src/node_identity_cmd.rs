//! `ndn-fwd node-identity [<identity>] [--pib <dir>] [-c <config>]`: show
//! or change the node identity — the identity the daemon signs its own
//! packets as (management responses, discovery records, QUIC links, DV
//! routing), as opposed to the Data it publishes under each trusted prefix,
//! which is signed with that prefix's key.
//!
//! Without `<identity>` it prints the node identity the daemon starts with
//! and why ([`ndn_cert::choose_node_identity`]), and the identities it signs
//! Data as. With one it records `<identity>` as the PIB's default identity
//! — the node identity from the daemon's next start, unless `[security]
//! identity` in its config names another. Enrolling in a trusted prefix
//! never changes the node identity once there is one; this is the operator's
//! way to.

use anyhow::{Context, Result, bail};
use ndn_cert::{NodeIdentitySource, choose_node_identity};
use ndn_config::ForwarderConfig;
use ndn_packet::Name;
use ndn_security::{FilePib, SecurityManager};

use crate::onboard::{flag, pib_dir, positionals};

pub(crate) async fn run(args: &[String]) -> Result<()> {
    let pib_path = pib_dir(args)?;
    let configured = configured_identity(args)?;
    let pib =
        FilePib::open(&pib_path).with_context(|| format!("open PIB at {}", pib_path.display()))?;
    match positionals(args).first() {
        None => show(&pib, configured.as_ref()),
        Some(identity) => {
            let identity: Name = identity
                .parse()
                .with_context(|| format!("invalid identity {identity:?}"))?;
            set(&pib, &identity, configured.as_ref())
        }
    }
}

/// `[security] identity` from the `-c` config, if any.
fn configured_identity(args: &[String]) -> Result<Option<Name>> {
    let Some(path) = flag(args, &["-c", "--config"]) else {
        return Ok(None);
    };
    let toml = std::fs::read_to_string(path).with_context(|| format!("read config {path}"))?;
    let cfg: ForwarderConfig = toml
        .parse()
        .with_context(|| format!("parse config {path}"))?;
    cfg.security
        .identity
        .map(|uri| {
            uri.parse()
                .with_context(|| format!("[security] identity {uri:?} is not a valid NDN name"))
        })
        .transpose()
}

fn show(pib: &FilePib, configured: Option<&Name>) -> Result<()> {
    let chosen = choose_node_identity(Some(pib), configured);
    match &chosen.identity {
        Some(identity) => println!("node identity: {identity} ({})", chosen.source.describe()),
        None => println!("node identity: none — {}", chosen.source.describe()),
    }
    let mgr = match &chosen.identity {
        Some(identity) => SecurityManager::from_pib(pib, identity)?,
        None => {
            let mgr = SecurityManager::new();
            mgr.load_pib_identities(pib)?;
            mgr
        }
    };
    // The held trust contexts tell a namespace's root and CA keys (which
    // never sign Data by name) from its device identities.
    let _ = ndn_cert::load_persisted_contexts(pib.root(), mgr.keyring());
    let signing = mgr.signing_identities();
    if signing.is_empty() {
        println!("signs Data as: no identity (enroll in a trusted prefix: `ndn-fwd enroll`)");
    } else {
        println!("signs Data as (each trusted prefix with its own key):");
        for s in signing {
            println!("  {}  key {}", s.identity, s.key);
        }
    }
    Ok(())
}

fn set(pib: &FilePib, identity: &Name, configured: Option<&Name>) -> Result<()> {
    if pib.identity_keys(identity)?.is_empty() {
        bail!(
            "the PIB {} holds no key of {identity}: the node identity must be one of this \
             device's identities (`ndn-fwd node-identity` lists them; `ndn-fwd enroll` adds one)",
            pib.root().display()
        );
    }
    let before = choose_node_identity(Some(pib), configured);
    pib.set_default_identity(identity)
        .with_context(|| format!("record {identity} as the PIB's default identity"))?;
    println!(
        "recorded {identity} as the PIB's default identity in {}",
        pib.root().display()
    );
    match (configured, before.identity) {
        (Some(configured), _) => println!(
            "the node identity stays {configured}: [security] identity in the config names it \
             and takes precedence; remove that line for {identity} to become the node identity"
        ),
        (None, Some(previous)) if &previous == identity => {
            println!("{identity} already is the node identity")
        }
        (None, previous) => {
            let was = match (previous, before.source) {
                (Some(previous), _) => format!(" (it was {previous})"),
                (None, NodeIdentitySource::Ephemeral) => {
                    " (the daemon ran on an ephemeral key)".to_owned()
                }
                (None, _) => String::new(),
            };
            println!(
                "{identity} becomes the node identity at the daemon's next start{was}: restart \
                 it to sign its management responses, discovery records, links and DV routing \
                 as {identity}. Data under each trusted prefix keeps being signed with that \
                 prefix's key."
            );
        }
    }
    Ok(())
}
