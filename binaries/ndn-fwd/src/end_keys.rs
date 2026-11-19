//! `ndn-fwd status` and `ndn-fwd end-keys` on the root device: the keys
//! whose authority over Data has ended but that no version revokes yet, and
//! ending them ([`ndn_namespace::root::end_keys`]).
//!
//! Data is judged without a clock, so a key's authority over Data ends only
//! by a revocation. Two kinds of keys must end although nobody lost them: a
//! **lapsed** key of a role the trust context lists in `DataRequiresCut`
//! (every role in a namespace `ndn-fwd init` makes; `guest` alone in an
//! older one) whose newest certificate expired — every node refuses its
//! Data meanwhile — and a key **replaced**
//! by a newer key the CA certified for the same device — whose Data stays
//! accepted until it is revoked. Each is ended by a revocation with a cut
//! bounded at the moment it ended (its NotAfter, or the replacement's
//! enrollment), so what it published before stays accepted.
//!
//! - `ndn-fwd status [--pib <dir>]` lists them (read from the PIB: the
//!   namespace CA's issued certificates and the held version), each with
//!   the ndn-data host line that writes its cut file. Every root command
//!   lists them too after its own outcome. For a held context that lists
//!   fewer than every role in `DataRequiresCut` (one made before `init`
//!   listed all four) it also prints a `notice` naming the
//!   `ndn-fwd schema data-requires-cut` command that lists them all.
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
use ndn_cert::roles::Role;
use ndn_namespace::root::end_keys;
use ndn_namespace::root::revoke::format_when;
use ndn_packet::Name;

use crate::onboard::{flag_values, pib_dir};
use crate::revoke::{cut_refused, cut_text, print_left_out, read_cut_file};
use crate::root_host::{
    Secrets, daemon, ending_text, handed_text, namespace_arg, now_ms, print_keys_to_end, render,
    render_before_signing,
};

/// What `ndn-fwd status` says of a held root context that lists fewer than
/// every device role in `DataRequiresCut`: such a context was made before
/// `ndn-fwd init` listed every role, and a context is root-signed data that
/// nothing rewrites, so the owner is told the one command that does. `None`
/// when `listed` (the roles the held version lists) holds every role.
pub(crate) fn data_requires_cut_notice(namespace: &Name, listed: &[String]) -> Option<String> {
    if Role::ALL
        .iter()
        .all(|role| listed.iter().any(|l| l == role.as_str()))
    {
        return None;
    }
    let every = Role::ALL.map(Role::as_str).join(",");
    let refused = if listed.is_empty() {
        "for no role".to_string()
    } else {
        format!("only for roles {}", listed.join(","))
    };
    Some(format!(
        "{namespace}: Data of lapsed keys is refused {refused}; to refuse it for every role, \
         run on the root device: ndn-fwd schema data-requires-cut {every} --namespace {namespace}"
    ))
}

/// The notices `ndn-fwd status` prints under the roots it holds
/// ([`data_requires_cut_notice`] of each).
fn status_notices(pending: &[end_keys::Pending]) -> Vec<String> {
    pending
        .iter()
        .filter_map(|p| data_requires_cut_notice(&p.namespace, &p.data_requires_cut))
        .collect()
}

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
    for notice in status_notices(&pending) {
        println!("notice         = {notice}");
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

#[cfg(test)]
mod tests {
    use ndn_cert::{NewRootStore, bump_context_data_requires_cut, persist_context};
    use ndn_packet::Data;
    use ndn_security::FilePib;

    use super::*;

    fn ns() -> Name {
        "/home/bob".parse().unwrap()
    }

    fn roles(listed: &[&str]) -> Vec<String> {
        listed.iter().map(|r| r.to_string()).collect()
    }

    /// A context that lists every role says nothing; one that lists fewer
    /// (made before `init` listed all four) names the command that lists them
    /// all, the namespace, and the roles it lists now.
    #[test]
    fn a_context_listing_fewer_than_every_role_is_told_the_command_that_lists_them_all() {
        assert_eq!(
            data_requires_cut_notice(&ns(), &roles(&["admin", "guest", "member", "node"])),
            None
        );
        assert_eq!(
            data_requires_cut_notice(&ns(), &roles(&["guest"])).as_deref(),
            Some(
                "/home/bob: Data of lapsed keys is refused only for roles guest; to refuse it \
                 for every role, run on the root device: ndn-fwd schema data-requires-cut \
                 admin,member,node,guest --namespace /home/bob"
            )
        );
        let some = data_requires_cut_notice(&ns(), &roles(&["guest", "member"])).unwrap();
        assert!(some.contains("only for roles guest,member"), "{some}");
        let none = data_requires_cut_notice(&ns(), &[]).unwrap();
        assert!(none.contains("refused for no role"), "{none}");
    }

    /// `status` over a real PIB: a root made by `init` lists every role and
    /// gets no notice; the same root whose held version lists `guest` alone
    /// (a namespace from an earlier release) gets one naming the command.
    #[test]
    fn status_notes_a_held_root_context_that_lists_only_guest() {
        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        let made = futures::executor::block_on(ndn_cert::init_namespace_in_pib(
            &pib,
            &ns(),
            "desk",
            false,
            &NewRootStore::File,
        ))
        .unwrap();

        let pending = end_keys::pending_all(dir.path(), now_ms()).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].data_requires_cut,
            ["admin", "guest", "member", "node"]
        );
        assert_eq!(status_notices(&pending), Vec::<String>::new());

        // The root signs version 2 listing `guest` alone, as a namespace made
        // by an earlier release holds.
        let root = pib
            .get_signer(&ndn_cert::root_key_name(&ns()))
            .expect("the root key is in the PIB");
        let held = Data::decode(made.init.context_data.raw().clone()).unwrap();
        let bump = futures::executor::block_on(bump_context_data_requires_cut(
            root.as_ref(),
            &held,
            &[Role::Guest],
        ))
        .unwrap()
        .expect("a change");
        persist_context(dir.path(), &bump.context, &bump.data).unwrap();

        let pending = end_keys::pending_all(dir.path(), now_ms()).unwrap();
        assert_eq!(pending[0].version, 2);
        assert_eq!(pending[0].data_requires_cut, ["guest"]);
        assert_eq!(
            status_notices(&pending),
            [
                "/home/bob: Data of lapsed keys is refused only for roles guest; to refuse it \
                 for every role, run on the root device: ndn-fwd schema data-requires-cut \
                 admin,member,node,guest --namespace /home/bob"
            ]
        );
    }
}
