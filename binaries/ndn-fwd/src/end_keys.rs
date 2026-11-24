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
//!   the ndn-heap host line that writes its cut file. Every root command
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
//!   a timer on the root device running the ndn-heap host's `cut` lines and
//!   then `end-keys --yes`. The running daemon never unlocks the root.

use std::path::Path;

use anyhow::Result;
use ndn_cert::RootUnlockKind;
use ndn_namespace::root::RootError;
use ndn_namespace::root::end_keys;
use ndn_namespace::root::revoke::format_when;

use crate::onboard::{flag_values, pib_dir};
use crate::revoke::{cut_refused, cut_text, print_left_out, read_cut_file};
use crate::root_host::{
    Secrets, daemon, ending_text, handed_text, namespace_arg, now_ms, print_keys_to_end, render,
    render_before_signing,
};

/// The notices `ndn-fwd status` prints under the roots it holds
/// ([`end_keys::data_requires_cut_notice`] of each).
fn status_notices(pending: &[end_keys::Pending]) -> Vec<String> {
    pending
        .iter()
        .filter_map(|p| end_keys::data_requires_cut_notice(&p.namespace, &p.data_requires_cut))
        .collect()
}

/// What `ndn-fwd status` says of this PIB's own keys whose certificates
/// lapsed at `now` (ms since the Unix epoch) — the keys of a relay or member
/// PIB, which holds no root to list them as keys to end: every node refuses
/// the Data such a key signs until the device is enrolled again. A key the
/// root device lists as one to end (`pending`) is said there instead, where
/// its owner ends it.
fn own_lapse_lines(
    pib_dir: &Path,
    pending: &[end_keys::Pending],
    now: u64,
) -> Result<Vec<String>, RootError> {
    Ok(end_keys::lapsed_own_keys(pib_dir, now)?
        .into_iter()
        .filter(|own| {
            !pending
                .iter()
                .any(|p| p.ending.iter().any(|e| e.key == own.key))
        })
        .map(|own| {
            format!(
                "own_key        = {}: this device's certificate lapsed at {}: Data it signs is \
                 refused until it is re-enrolled (ask the owner of the namespace for a new \
                 invite, then `ndn-fwd enroll <invite-link>`)",
                own.key,
                format_when(own.not_after)
            )
        })
        .collect())
}

/// `ndn-fwd status`: the roots this PIB holds, their held versions, the
/// keys to end, and this device's own keys whose certificates lapsed.
pub(crate) fn run_status(args: &[String]) -> Result<()> {
    let pib_dir = pib_dir(args)?;
    let now = now_ms();
    let pending = end_keys::pending_all(&pib_dir, now).map_err(render)?;
    println!("# ndn-fwd status");
    println!("pib            = {}", pib_dir.display());
    if pending.is_empty() {
        println!("root_of        = (none: this PIB holds no namespace root)");
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
    for line in own_lapse_lines(&pib_dir, &pending, now).map_err(render)? {
        println!("{line}");
    }
    print_keys_to_end(&pib_dir);
    Ok(())
}

/// Ask once whether to proceed with `what`; `--yes` answers yes without
/// asking. `command` is the subcommand that refuses without a terminal.
pub(crate) fn confirmed(args: &[String], command: &str, what: &str) -> Result<bool> {
    use std::io::IsTerminal as _;
    if args.iter().any(|a| a == "--yes") {
        return Ok(true);
    }
    if !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
        anyhow::bail!(
            "{command} refused: there is no terminal to confirm {what}; run it on a terminal, \
             or with --yes. Nothing was signed"
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
            "#   in the ndn-heap host: cut {} <file> --held-before {}",
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
    if !confirmed(args, "end-keys", &what)? {
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
    use ndn_cert::roles::Role;
    use ndn_cert::{NewRootStore, bump_context_data_requires_cut, persist_context};
    use ndn_namespace::root::end_keys::data_requires_cut_notice;
    use ndn_packet::{Data, Name};
    use ndn_security::{FilePib, Signer};

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

    /// Round-8 L-b: `status` on a relay's or member's PIB, which holds no
    /// root, still explains a lapsed own certificate: the key, when its
    /// certificate lapsed, that its Data is refused until it is enrolled
    /// again. A key whose certificate is current is not mentioned.
    #[test]
    fn status_explains_a_lapsed_own_certificate_on_a_pib_that_holds_no_root() {
        // The owner's root device makes the namespace.
        let owner = tempfile::tempdir().unwrap();
        let made = futures::executor::block_on(ndn_cert::init_namespace_in_pib(
            &FilePib::new(owner.path()).unwrap(),
            &ns(),
            "desk",
            false,
            &NewRootStore::File,
        ))
        .unwrap();

        // A member's PIB: the owner's context as adopted, no root, and two
        // member keys: one whose only certificate was valid for a
        // millisecond, one with a certificate good for a day.
        let dir = tempfile::tempdir().unwrap();
        let pib = FilePib::new(dir.path()).unwrap();
        persist_context(dir.path(), &made.init.context, &made.init.context_data).unwrap();
        let mgr = ndn_security::SecurityManager::new();
        let ca: Name = "/home/bob/CA/KEY/ca".parse().unwrap();
        mgr.generate_ed25519(ca.clone()).unwrap();
        for (device, validity_ms) in [("tv", 1), ("phone", 24 * 3600 * 1000)] {
            let key: Name = format!("/home/bob/member/{device}/KEY/k1").parse().unwrap();
            let public = pib.generate_ed25519(&key).unwrap().public_key().unwrap();
            let cert =
                futures::executor::block_on(mgr.certify(&key, public, &ca, validity_ms)).unwrap();
            pib.store_cert(&key, &cert).unwrap();
        }

        let pending = end_keys::pending_all(dir.path(), now_ms()).unwrap();
        assert!(pending.is_empty(), "a member PIB holds no root");
        let lines = own_lapse_lines(dir.path(), &pending, now_ms() + 60_000).unwrap();
        assert_eq!(lines.len(), 1, "{lines:?}");
        let line = &lines[0];
        for want in [
            "/home/bob/member/tv/KEY/k1",
            "this device's certificate lapsed at",
            "Data it signs is refused until it is re-enrolled",
        ] {
            assert!(line.contains(want), "{want:?} missing from: {line}");
        }
        assert!(!line.contains("phone"), "a current certificate: {line}");
    }
}
