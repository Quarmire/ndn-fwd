//! `ndn-fwd status` and `ndn-fwd end-keys` on the root device: the keys
//! whose authority over Data has ended but that no version revokes yet, and
//! ending them ([`ndn_namespace::root::end_keys`]).
//!
//! Data is judged without a clock, so a key's authority over Data ends only
//! by a revocation. Two kinds of keys must end although nobody lost them: a
//! **lapsed** key of a role the trust context lists in `DataRequiresCut`
//! (`guest` in a namespace `ndn-fwd init` made) whose newest certificate
//! expired — every node refuses its Data meanwhile — and a key **replaced**
//! by a newer key the CA certified for the same device — whose Data stays
//! accepted until it is revoked. Each is ended by a revocation with a cut
//! bounded at the moment it ended (its NotAfter, or the replacement's
//! enrollment), so what it published before stays accepted.
//!
//! - `ndn-fwd status [--pib <dir>]` lists them (read from the PIB: the
//!   namespace CA's issued certificates and the held version), each with
//!   the ndn-data host line that writes its cut file. Every root command
//!   lists them too after its own outcome.
//! - `ndn-fwd end-keys --cut <file>... [--namespace <ns>] [--yes]` signs
//!   ONE version revoking every key to end that has a cut file, with its
//!   cut, after one confirmation. A key without a cut file is listed and
//!   left: revoking it without a cut would refuse forever what it published
//!   honestly (a cut comes only with its key's revocation). `--yes` signs
//!   without asking, and only when the root unlocks without a secret (OS
//!   keychain, plain file): that is how an owner ends keys unattended, from
//!   a timer on the root device running the ndn-data host's `cut` lines and
//!   then `end-keys --yes`. The running daemon never unlocks the root.

use anyhow::Result;
use ndn_cert::RootUnlockKind;
use ndn_namespace::root::end_keys;
use ndn_namespace::root::revoke::format_when;

use crate::onboard::{flag_values, pib_dir};
use crate::revoke::{cut_refused, cut_text, print_left_out, read_cut_file};
use crate::root_host::{
    Secrets, daemon, ending_text, handed_text, namespace_arg, now_ms, print_keys_to_end, render,
    render_before_signing,
};

/// `ndn-fwd status`: the roots this PIB holds, their held versions, and
/// the keys to end.
pub(crate) fn run_status(args: &[String]) -> Result<()> {
    let pib_dir = pib_dir(args)?;
    let pending = end_keys::pending_all(&pib_dir, now_ms()).map_err(render)?;
    println!("# ndn-fwd status");
    println!("pib            = {}", pib_dir.display());
    if pending.is_empty() {
        println!("root_of        = (none: this PIB holds no namespace root)");
        return Ok(());
    }
    for ns in &pending {
        println!(
            "root_of        = {} (trust context v{}; {} key(s) to end)",
            ns.namespace,
            ns.version,
            ns.ending.len()
        );
    }
    print_keys_to_end(&pib_dir);
    Ok(())
}

/// Ask once whether to sign `what`; `--yes` answers yes without asking.
fn confirmed(args: &[String], what: &str) -> Result<bool> {
    use std::io::IsTerminal as _;
    if args.iter().any(|a| a == "--yes") {
        return Ok(true);
    }
    if !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
        anyhow::bail!(
            "end-keys refused: there is no terminal to confirm {what}; run it on a terminal, or \
             with --yes (only for a root that unlocks without a secret). Nothing was signed"
        );
    }
    eprint!("{what}? [y/N] ");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let mut answer = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

/// `ndn-fwd end-keys --cut <file>... [--namespace <ns>] [--yes]`.
pub(crate) async fn run(args: &[String]) -> Result<()> {
    let pib_dir = pib_dir(args)?;
    let namespace = namespace_arg(args)?;
    let mut files = Vec::new();
    for path in flag_values(args, "--cut") {
        files.push(read_cut_file(path, "end-keys")?);
    }
    let planned = end_keys::plan(&pib_dir, namespace.as_ref(), files, now_ms())
        .map_err(|e| cut_refused(e, "end-keys"))?;
    let ns = planned.root.context.namespace().clone();
    let held = planned.root.context.version();
    println!("# ndn-fwd end-keys");
    println!("namespace      = {ns}");
    for (key, file) in &planned.ending {
        println!("ending_key     = {}", ending_text(key));
        println!("cut            = {}: {}", key.key, cut_text(&file.cut));
        print_left_out(file);
    }
    for key in &planned.without_cut {
        println!(
            "ending_key     = {} — no cut file given: not ended now",
            ending_text(key)
        );
        println!(
            "#   in the ndn-data host: cut {} <file> --held-before {}",
            key.key,
            format_when(key.held_before)
        );
    }
    if planned.ending.is_empty() {
        println!("trust_context  = v{held} (no key to end has a cut file; nothing signed)");
        return Ok(());
    }
    if args.iter().any(|a| a == "--yes")
        && planned.root.store.unlock_kind() != RootUnlockKind::Nothing
    {
        anyhow::bail!(
            "end-keys refused: --yes signs unattended, but the root of {ns} unlocks with a {} \
             ({} store): run it on a terminal without --yes, or keep the root where it unlocks \
             without one (`ndn-fwd root-key move --to os-keyring`). Nothing was signed",
            planned.root.store.unlock_kind().as_str(),
            planned.root.store.kind()
        );
    }
    let what = format!(
        "Revoke these {} key(s) of {ns}, each with its cut, in one new version",
        planned.ending.len()
    );
    if !confirmed(args, &what)? {
        println!("trust_context  = v{held} (not confirmed; nothing signed)");
        return Ok(());
    }
    let daemon = daemon(args)?;
    let ended = end_keys::end(planned, &pib_dir, &daemon, &Secrets { args })
        .await
        .map_err(render_before_signing)?;
    for (key, _) in &ended.ended {
        println!("revoked_key    = {}", key.key);
    }
    println!(
        "trust_context  = v{} -> v{} (signed by the root {})",
        ended.held_version, ended.version, ended.root_key
    );
    println!(
        "handed_over    = {}",
        handed_text(&ended.handed_over, &daemon, ended.version, &pib_dir)
    );
    println!("# Each key's packets its cut accepts stay accepted; everything else it signed is");
    println!("# refused. A genuine packet left out is re-admitted by its full name:");
    println!("#   ndn-fwd readmit <key> <full-name>");
    print_keys_to_end(&pib_dir);
    Ok(())
}
