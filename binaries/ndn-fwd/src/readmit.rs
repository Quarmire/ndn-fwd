//! `ndn-fwd readmit <key> <full-name>...` on the root device: the CLI over
//! [`ndn_namespace::root::readmit`].
//!
//! A key revoked with a cut ([`crate::revoke`]) keeps the packets its cut
//! accepts; any other packet it signed is refused, and a device reports the
//! refused one with its full name (its name ending in the implicit digest
//! component, `sha256digest=<64 hex>`). When the owner decides that packet
//! is genuine, this signs version `N+1` adding exactly those full names to
//! the key's cut: each accepts that name with those bytes, never a range,
//! so a neighbouring sequence number or another packet at the same name
//! stays refused. The checks come before anything is asked: this is the
//! root device of the key's namespace (`--namespace` must name it when
//! given), the held version holds a cut for exactly that key, and each name
//! is a full name in the key's device log `<device>/32=log/...`. Names the
//! cut accepts already are left out; with none left, nothing is signed.
//! Then the root is unlocked as for a revocation, the signer dropped right
//! after, and the version handed to the daemon that uses the PIB (stored
//! for its next start when none listens).

use std::path::Path;

use anyhow::{Context, Result};
use ndn_cert::report::code;
use ndn_namespace::root::{self, RootError};
use ndn_packet::Name;

use crate::onboard::{pib_dir, positionals};
use crate::root_host::{
    Secrets, daemon, handed_text, namespace_arg, render, render_before_signing,
};

/// A refused re-admission into the cut of `key` (on the PIB at `pib_dir`,
/// the held version `held`), as the CLI says it.
fn refused(e: RootError, key: &Name, pib_dir: &Path, held: u64) -> anyhow::Error {
    if e.is(code::VERSION_NOT_TAKEN) {
        return render(e).context(format!(
            "nothing was re-admitted: the trust context stays v{held}"
        ));
    }
    if e.is(code::HAND_OVER_UNKNOWN) {
        let version = e.param("version").unwrap_or_default().to_string();
        return render(e).context(format!(
            "whether the daemon adopted v{version} (re-admitting into the cut of {key}) is not \
             known: once the daemon is idle, run the same `ndn-fwd readmit {key} … --pib {}` \
             again — it reports the names admitted already if the daemon took v{version}, and \
             signs the version again if not",
            pib_dir.display()
        ));
    }
    render_before_signing(e)
}

/// A refused plan, as the CLI says it.
fn plan_refused(e: RootError) -> anyhow::Error {
    if e.is(code::REVOKE_OTHER_NAMESPACE) {
        let p = |key| e.param(key).unwrap_or_default();
        return anyhow::anyhow!(
            "{} is in the trusted prefix {}, not {}: re-admit there (or leave out \
             --namespace). Nothing was signed",
            p("name"),
            p("namespace"),
            p("requested")
        );
    }
    render(e)
}

/// `ndn-fwd readmit <key> <full-name>...`.
pub(crate) async fn run(args: &[String]) -> Result<()> {
    let words = positionals(args);
    let (target, full_names) = words.split_first().context(
        "readmit requires the revoked key (<identity>/KEY/<id>) and at least one full name \
         (ending in sha256digest=<64 hex>) of a packet to re-admit",
    )?;
    if full_names.is_empty() {
        anyhow::bail!(
            "readmit requires at least one full name (ending in sha256digest=<64 hex>) after the \
             key: the name of each refused packet to re-admit, as its refusal reported it"
        );
    }
    let parse = |word: &&str| {
        word.parse::<Name>()
            .map_err(|e| anyhow::anyhow!("readmit refused: {word:?} is not an NDN name: {e}"))
    };
    let key = parse(target)?;
    let names = full_names.iter().map(parse).collect::<Result<Vec<_>>>()?;
    let pib_dir = pib_dir(args)?;
    let planned = root::readmit::plan(&pib_dir, &key, &names, namespace_arg(args)?.as_ref())
        .map_err(plan_refused)?;
    let held = planned.root.context.version();
    if planned.adding.is_empty() {
        println!("# ndn-fwd readmit");
        println!("namespace      = {}", planned.root.context.namespace());
        println!("key            = {key}");
        for name in &names {
            println!("readmitted     = {name} (already)");
        }
        println!("trust_context  = v{held} (its cut accepts every name given; nothing signed)");
        return Ok(());
    }
    let daemon = daemon(args)?;
    let done = root::readmit::readmit(planned, &pib_dir, &daemon, &Secrets { args })
        .await
        .map_err(|e| refused(e, &key, &pib_dir, held))?;
    let (namespace, version) = (&done.namespace, done.version);
    println!("# ndn-fwd readmit");
    println!("namespace      = {namespace}");
    println!("key            = {}", done.key);
    for name in &done.readmitted {
        println!("readmitted     = {name}");
    }
    println!(
        "trust_context  = v{held} -> v{version} (signed by the root {})",
        done.root_key
    );
    println!(
        "handed_over    = {}",
        handed_text(&done.handed_over, &daemon, version, &pib_dir)
    );
    println!();
    println!(
        "# Every node accepts these exact packets (name and bytes) of {} once it holds",
        done.key
    );
    println!("# v{version}: at its next refresh, or at once with `ndn-fwd context refresh`. Any");
    println!("# other packet outside the key's cut stays refused.");
    Ok(())
}
