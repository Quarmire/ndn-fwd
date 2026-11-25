//! `ndn-fwd revoke <device | key | certificate> [--cut <file>]` on the root
//! device: the CLI over [`ndn_namespace::root::revoke`].
//!
//! **The revocation is a new version of the trust context.** The CLI works
//! on the PIB of the daemon it hands the version to; the library checks,
//! before asking for anything, that this is the root device of the trusted
//! prefix the name is in (of those whose root the PIB holds, the longest
//! covering it; `--namespace` must name that one when given), which keys
//! the name designates (a key or certificate name: its key; a device
//! identity: every key the namespace CA certified for it, read from that
//! CA's store in the PIB), that none is the root's or the CA's, and that
//! the held version does not revoke them all already
//! ([`ndn_cert::plan_revocation`]). Only then is the root unlocked — a
//! `sealed-file` root with its passphrase, a `yubikey-piv` root with its
//! PIN, asked here ([`crate::root_host::Secrets`]); an `os-keyring` root
//! through the keychain — to sign version `N+1`, which lists the keys as
//! revoked ([`ndn_cert::bump_context_revoking`]). The signer is dropped (a
//! software key zeroed) right after. The secret never leaves the CLI: the
//! daemon receives only the signed version (`security/context-update`),
//! which it adopts under the continuity rule, stores and publishes; with no
//! daemon listening it is stored for the daemon's next start. Every node's
//! validator refuses a chain through a revoked key — any certificate of it,
//! also ones issued later — once it holds that version, which other nodes
//! fetch with their next refresh ([`crate::context_refresh`]).
//!
//! **A revocation cut** (`--cut <file>`: the cut file a device's data layer
//! writes with its `cut` verb — the RevocationCut TLV 0x0428, the bound it
//! used, the entries the bound left out and the cut manifest's packets, if
//! the cut has a manifest) is
//! signed in the same version, beside the revocation of exactly its key:
//! the packets it accepts (the key's log entries the data layer first
//! verified before the loss, each by its exact bytes as the manifest lists
//! them; or, in a cut of tips, the packets below each log's tip by name and
//! the tip by the digest of its signed region, each device's data layer
//! keeping below a tip only the tip's own chain) stay accepted everywhere,
//! every other packet the key signed is
//! refused. The CLI asks **"When did you lose it?"** (`--lost <when>`
//! without a terminal: RFC 3339, `2h ago`, or `now`) and refuses a cut
//! file made without a time bound, or bounded later than that answer — it
//! could accept what a thief wrote after the loss. Its key must be one the
//! version revokes, the cut must list only that key's device log, name the
//! key's public key and carry its whole manifest (a cut of tips needs none),
//! else nothing is signed
//! (`cut-refused`). The manifest's packets, if any, are stored beside the
//! contexts and served with the version. The entries the bound left out (in
//! a cut of tips also the entries off a tip's chain) are listed:
//! each is refused with the rest, and a genuine one is re-admitted later by
//! its full name ([`crate::readmit`]).
//!
//! **The CA follows the signed version**
//! ([`ndn_cert::CaState::follow_context`]), never a separate request:
//! whenever the daemon keeps a version of its namespace's context — handed
//! over, refreshed, adopted by link ([`ndn_namespace::keep`]) — and when its
//! CA starts ([`ndn_cert::CaState::follow_held`]), the CA records every
//! certificate it issued that the version revokes as revoked in its store
//! (`revoked/` in the CA's directory, [`ndn_cert::ca_dir`]), never certifies
//! such a key again, and the device name the key held is free for a new key
//! (one key per device name). It stops serving those certificates, except
//! those of a key revoked with a cut: readers verify the packets the cut
//! accepts with them.

use std::path::Path;

use anyhow::{Context, Result};
use ndn_cert::report::code;
use ndn_cert::{CutFile, GivenCut};
use ndn_namespace::root::revoke::{LOSS_QUESTION, format_when, parse_when};
use ndn_namespace::root::{self, RootError};
use ndn_packet::Name;
use ndn_security::RevocationCut;

use crate::onboard::{flag, hex_lower, pib_dir, positionals};
use crate::root_host::{
    Secrets, daemon, handed_text, namespace_arg, now_ms, print_keys_to_end, render,
    render_before_signing,
};

/// A refused revocation of `name` (on the PIB at `pib_dir`, the held
/// version `held`), as the CLI says it.
fn refused(e: RootError, name: &Name, pib_dir: &Path, held: u64) -> anyhow::Error {
    if e.is(code::VERSION_NOT_TAKEN) {
        return render(e).context(format!(
            "nothing was revoked: the trust context stays v{held} and the CA keeps serving the \
             certificates"
        ));
    }
    if e.is(code::HAND_OVER_UNKNOWN) {
        let version = e.param("version").unwrap_or_default().to_string();
        let keys = e.param("keys").unwrap_or_default().to_string();
        return render(e).context(format!(
            "whether the daemon adopted v{version} (revoking {keys}) is not known: once the daemon \
             is idle, run `ndn-fwd revoke {name} --pib {}` again — it reports the keys revoked \
             already if the daemon took v{version}, and signs the version again if not",
            pib_dir.display()
        ));
    }
    if e.is(code::NOTHING_TO_SIGN) {
        return anyhow::anyhow!(
            "the held trust context revokes every key named already; nothing was signed"
        );
    }
    render_before_signing(e)
}

/// A refused plan, as the CLI says it.
fn plan_refused(e: RootError) -> anyhow::Error {
    if e.is(code::REVOKE_OTHER_NAMESPACE) {
        let p = |key| e.param(key).unwrap_or_default();
        return anyhow::anyhow!(
            "{} is in the trusted prefix {}, not {}: revoke it there (or leave out \
             --namespace). Nothing was signed",
            p("name"),
            p("namespace"),
            p("requested")
        );
    }
    cut_refused(e, "revoke")
}

/// A `cut-refused` for a cut file's bound, in the CLI's words (times in RFC
/// 3339, the line that writes the cut again); any other refusal as
/// [`render`] says it.
pub(crate) fn cut_refused(e: RootError, command: &str) -> anyhow::Error {
    let p = |k| e.param(k).unwrap_or_default().to_string();
    let ms = |k| {
        p(k).parse::<u64>()
            .map(format_when)
            .unwrap_or_else(|_| p(k))
    };
    if e.is(code::CUT_REFUSED) {
        match e.param("why") {
            Some("after-loss") => {
                return anyhow::anyhow!(
                    "{command} refused: the cut file of {} keeps entries first verified until \
                     {}, after {} (when it was lost): what a thief wrote after the loss could be \
                     in it. Write the cut again in the ndn-heap host: `cut {} <file> \
                     --held-before {}`. Nothing was signed",
                    p("key"),
                    ms("held_before"),
                    ms("lost"),
                    p("key"),
                    ms("lost")
                );
            }
            Some("unbounded") => {
                return anyhow::anyhow!(
                    "{command} refused: the cut file of {} was written without a time bound, so \
                     it may accept what a thief wrote after the loss. Write it again in the \
                     ndn-heap host: `cut {} <file> --held-before <when you lost it>`. Nothing \
                     was signed",
                    p("key"),
                    p("key")
                );
            }
            _ => {}
        }
    }
    render(e)
}

/// The cut file at `path` (as a device's data layer writes it with its
/// `cut` verb), for `command`'s refusal.
pub(crate) fn read_cut_file(path: &str, command: &str) -> Result<CutFile> {
    let wire = std::fs::read(path).map_err(|e| {
        anyhow::anyhow!(
            "{command} refused: cannot read the cut file {path}: {e}. Nothing was signed"
        )
    })?;
    CutFile::decode(&wire).map_err(|e| {
        anyhow::anyhow!(
            "{command} refused: {path} is not a cut file ({e}): give the file the key's \
             device's data layer wrote with `cut <key> <file> --held-before <when>`. Nothing \
             was signed"
        )
    })
}

/// When the owner lost `what` (a key, or the old root device): `--lost
/// <when>`, else asked on the terminal ([`LOSS_QUESTION`]). Without either,
/// refused: a cut must be checked against it.
pub(crate) fn loss_time(args: &[String], what: &str, command: &str) -> Result<u64> {
    use std::io::IsTerminal as _;
    let now = now_ms();
    if let Some(when) = flag(args, &["--lost"]) {
        return parse_when(when, now)
            .map_err(|e| anyhow::anyhow!("{command} refused: --lost {e}. Nothing was signed"));
    }
    if !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
        anyhow::bail!(
            "{command} refused: a cut is checked against when {what} was lost, and there is no \
             terminal to ask: give --lost <when> (RFC 3339 like 2026-11-04T10:00:00Z, a span \
             like `2h ago`, or `now`). Nothing was signed"
        );
    }
    loop {
        eprintln!("The cut keeps only what {what} published before it was lost.");
        eprint!("{LOSS_QUESTION} (e.g. 2026-11-04T10:00:00Z, 2h ago, now): ");
        let _ = std::io::Write::flush(&mut std::io::stderr());
        let mut answer = String::new();
        if std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut answer)? == 0 {
            anyhow::bail!(
                "{command} refused: no answer to \"{LOSS_QUESTION}\". Nothing was signed"
            );
        }
        match parse_when(&answer, now) {
            Ok(at) => return Ok(at),
            Err(e) => eprintln!("{e}"),
        }
    }
}

/// The cut file at `path` with the loss time it is checked against
/// (`--lost`, else asked), for `command`.
pub(crate) fn given_cut(args: &[String], path: &str, command: &str) -> Result<GivenCut> {
    let file = read_cut_file(path, command)?;
    let lost = loss_time(args, &file.cut.key().to_string(), command)?;
    Ok(GivenCut { file, lost })
}

/// The lines saying how a cut file is bounded and what its bound left
/// out, and how to re-admit a genuine entry left out.
pub(crate) fn print_left_out(file: &CutFile) {
    if let Some(held_before) = file.held_before {
        println!(
            "cut_bound      = first verified before {}",
            format_when(held_before)
        );
    }
    for (collection, seq) in &file.upto {
        println!("cut_bound      = {collection} up to seq {seq}");
    }
    for name in &file.left_out {
        println!("left_out       = {name}");
    }
    for line in left_out_lines(file) {
        println!("{line}");
    }
}

/// The comment lines after the entries a cut left out: why they are refused
/// and how to re-admit a genuine one; none when the cut left nothing out.
/// A cut of tips leaves out also the entries off a tip's chain.
fn left_out_lines(file: &CutFile) -> Vec<String> {
    if file.left_out.is_empty() {
        return Vec::new();
    }
    let why = match file.cut.tips().is_empty() {
        true => "verified at or after the loss",
        false => "verified at or after the loss, or off the chain of a tip",
    };
    vec![
        format!("# The entries left out ({why}) are refused with the"),
        "# rest. Re-admit one you know is genuine, one by one, by its full name:".to_string(),
        format!("#   ndn-fwd readmit {} <full-name>", file.cut.key()),
    ]
}

/// The comment lines saying what a revocation with `cut` keeps, and how to
/// re-admit a genuine packet outside it. A cut with a manifest keeps the
/// packets it lists by their exact bytes; a cut of tips keeps the packets
/// below each tip by name (each device's data layer keeps below a tip only
/// the chain of the tip) and each tip by the digest of its signed region.
fn cut_keeps_lines(cut: &RevocationCut) -> Vec<String> {
    let key = cut.key();
    let mut lines = Vec::new();
    match (cut.manifest().is_some(), cut.tips().is_empty()) {
        (_, true) => {
            lines.push(
                "# With the cut, the packets it lists (by their exact bytes, as its manifest"
                    .to_string(),
            );
            lines.push(
                "# lists them) stay accepted, and the CA keeps serving the certificates of"
                    .to_string(),
            );
        }
        (false, false) => {
            lines.push(
                "# With the cut, the packets below each of its tips (by name; a device keeps"
                    .to_string(),
            );
            lines.push(
                "# below a tip only the tip's own chain) and each tip (by the digest of its"
                    .to_string(),
            );
            lines.push(
                "# signed region) stay accepted, and the CA keeps serving the certificates of"
                    .to_string(),
            );
        }
        (true, false) => {
            lines.push(
                "# With the cut, the packets its manifest lists (by their exact bytes), the"
                    .to_string(),
            );
            lines.push(
                "# packets below each of its tips (by name; a device keeps below a tip only"
                    .to_string(),
            );
            lines.push(
                "# the tip's own chain) and each tip (by the digest of its signed region) stay"
                    .to_string(),
            );
            lines.push("# accepted, and the CA keeps serving the certificates of".to_string());
        }
    }
    lines.push(format!(
        "# {key} to verify them; everything else it signed is refused. A genuine"
    ));
    lines.push("# packet outside the cut is re-admitted by its full name:".to_string());
    lines.push(format!("#   ndn-fwd readmit {key} <full-name>"));
    lines
}

/// `cut` as the CLI shows it: per prefix its sequence-number runs, then per
/// log its tip (`<log prefix> tip seq <n> digest <hex>`: the digest is the
/// SHA-256 of the tip entry's signed region), then how many exact packets it
/// re-admits.
pub(crate) fn cut_text(cut: &RevocationCut) -> String {
    let mut parts: Vec<String> = cut
        .ranges()
        .iter()
        .map(|range| {
            let runs: Vec<String> = range
                .runs
                .iter()
                .map(|(first, last)| match first == last {
                    true => first.to_string(),
                    false => format!("{first}..{last}"),
                })
                .collect();
            format!("{} seq {}", range.prefix, runs.join(","))
        })
        .collect();
    parts.extend(cut.tips().iter().map(|tip| {
        format!(
            "{} tip seq {} digest {}",
            tip.prefix,
            tip.seq,
            hex_lower(&tip.digest)
        )
    }));
    if !cut.exact().is_empty() {
        parts.push(format!("{} exact packet(s)", cut.exact().len()));
    }
    match parts.is_empty() {
        true => "accepts nothing".to_string(),
        false => parts.join("; "),
    }
}

/// `ndn-fwd revoke <device | key | certificate> [--cut <file> [--lost <when>]]`.
pub(crate) async fn run(args: &[String]) -> Result<()> {
    let target = *positionals(args).first().context(
        "revoke requires a device identity (/<ns>/<role>/<device>), a key name \
         (<identity>/KEY/<id>) or a certificate name",
    )?;
    let name: Name = target
        .parse()
        .map_err(|e| anyhow::anyhow!("revoke refused: {target:?} is not an NDN name: {e}"))?;
    let cut = flag(args, &["--cut"])
        .map(|path| given_cut(args, path, "revoke"))
        .transpose()?;
    let pib_dir = pib_dir(args)?;
    let planned = root::revoke::plan(&pib_dir, &name, namespace_arg(args)?.as_ref(), cut)
        .map_err(plan_refused)?;
    let held = planned.root.context.version();
    if planned.adding.is_empty() {
        println!("# ndn-fwd revoke");
        println!("namespace      = {}", planned.root.context.namespace());
        for key in &planned.keys {
            println!("revoked_key    = {key} (already)");
            if let Some(cut) = planned.root.context.revocation_cut(key) {
                println!("cut            = {key}: {} (already)", cut_text(cut));
            }
        }
        println!("trust_context  = v{held} (already revokes every key named; nothing signed)");
        print_keys_to_end(&pib_dir);
        return Ok(());
    }
    let daemon = daemon(args)?;
    let revoked = root::revoke::revoke(planned, &name, &pib_dir, &daemon, &Secrets { args })
        .await
        .map_err(|e| refused(e, &name, &pib_dir, held))?;
    let (namespace, version) = (&revoked.namespace, revoked.version);
    println!("# ndn-fwd revoke");
    println!("namespace      = {namespace}");
    for key in &revoked.revoked {
        println!("revoked_key    = {key}");
    }
    if let Some(file) = &revoked.cut {
        println!(
            "cut            = {}: {}",
            file.cut.key(),
            cut_text(&file.cut)
        );
        print_left_out(file);
    }
    println!(
        "trust_context  = v{held} -> v{version} (signed by the root {})",
        revoked.root_key
    );
    println!(
        "handed_over    = {}",
        handed_text(&revoked.handed_over, &daemon, version, &pib_dir)
    );
    println!();
    println!("# The CA of {namespace} never certifies these keys again once its daemon holds");
    println!("# v{version}, and the device name is free to enroll again with a new key. Every");
    println!("# other node refuses the keys once it holds v{version}: at its next refresh");
    println!("# ([security] context_refresh_secs, default 300 s), or at once with");
    println!("# `ndn-fwd context refresh`.");
    match &revoked.cut {
        None => {
            println!("# No cut: every packet these keys signed is refused, and the CA stops");
            println!("# serving their certificates.");
        }
        Some(file) => {
            for line in cut_keeps_lines(&file.cut) {
                println!("{line}");
            }
        }
    }
    print_keys_to_end(&pib_dir);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ndn_cert::CaState;
    use ndn_mgmt::EnrollOutcome;
    use ndn_security::Keyring;

    use super::*;
    use crate::context_adopt::{TrustAdmin, TrustAdminParts};
    use crate::enroll::tests::{Node, node, request};
    use ndn_namespace::root::revoke::plan;

    /// A daemon on `engine` holding the contexts stored in `pib`, running
    /// `cas`.
    fn admin(
        engine: ndn_engine::ForwarderEngine,
        pib: &Path,
        cas: Vec<Arc<CaState>>,
    ) -> TrustAdmin {
        let keyring = Arc::new(Keyring::new());
        ndn_cert::load_persisted_contexts(pib, &keyring).unwrap();
        TrustAdmin::new(TrustAdminParts {
            engine,
            keyring,
            pib_root: pib.to_path_buf(),
            publisher: None,
            signing: None,
            own_certs: None,
            dv_keeps_startup_key: false,
            configured_identity: None,
            cas,
            context_sync: None,
        })
    }

    /// An enrolled device: its identity, key and certificate.
    async fn enrolled(node: &Node, token: &str) -> (Name, Name, String) {
        let EnrollOutcome::Enrolled(e) =
            crate::enroll::enroll(&node.admin, request(node, "member", token, "phone", true))
                .await
                .unwrap()
        else {
            panic!("an invite enrolls at once")
        };
        (
            e.identity.parse().unwrap(),
            e.key.parse().unwrap(),
            e.certificate,
        )
    }

    /// Version 2 of the root device's context, revoking what `name`
    /// designates (with `cut`, if any), signed by the root as `ndn-fwd
    /// revoke` signs it.
    async fn revocation_with(
        root_dev: &Path,
        name: &Name,
        cut: Option<GivenCut>,
    ) -> ndn_cert::ContextBump {
        let plan = plan(root_dev, name, None, cut).unwrap();
        let root = plan.root.store.signer(None).await.unwrap();
        let cuts: Vec<RevocationCut> = plan.cut.iter().map(|f| f.cut.clone()).collect();
        ndn_cert::bump_context_revoking(root.as_ref(), &plan.root.data, &plan.keys, &cuts)
            .await
            .unwrap()
            .unwrap()
    }

    async fn revocation(root_dev: &Path, name: &Name) -> ndn_cert::ContextBump {
        revocation_with(root_dev, name, None).await
    }

    /// The cut file of `key` accepting seqs 1..=3 of its `notes`, first
    /// verified before `held_before` (ms), as the data layer writes it.
    fn cut_file(key: &Name, held_before: Option<u64>) -> CutFile {
        let notes = ndn_cert::device_log_of(key).append("notes");
        let entries: Vec<(Name, u64, [u8; 32])> =
            (1..=3).map(|s| (notes.clone(), s, [s as u8; 32])).collect();
        let ns: Name = "/home/bob".parse().unwrap();
        let built = ndn_security::cut_manifest::build(&ns, key, &entries).unwrap();
        let mut cut = RevocationCut::new(key.clone());
        cut.add_run(&notes, 1, 3);
        cut.set_key_digest([5; 32]);
        cut.set_manifest(built.root).unwrap();
        let mut file = CutFile::new(cut);
        file.held_before = held_before;
        file.manifest = built.packets;
        file
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// A revocation with a cut handed to the daemon: the key is revoked
    /// (the device name free for a new key), the cut is held as signed, the
    /// CA keeps serving the key's certificate for the packets the cut
    /// accepts, and a cut file the CLI reads is the cut signed.
    #[tokio::test]
    async fn a_revocation_with_a_cut_keeps_the_certificate_served() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-a"]).await;
        let (identity, key, certificate) = enrolled(&node, "member-a").await;
        let written = cut_file(&key, Some(1_000));
        let file = root_dev.path().join("phone.cut");
        std::fs::write(&file, written.encode()).unwrap();
        let path = file.to_str().unwrap();
        let given = given_cut(&args(&["--lost", "2026-01-01T00:00:00Z"]), path, "revoke").unwrap();
        assert_eq!(given.file, written);
        let cut = written.cut.clone();

        let bump = revocation_with(root_dev.path(), &identity, Some(given)).await;
        let daemon = admin(
            node.admin.ns.engine().clone(),
            root_dev.path(),
            vec![Arc::clone(&node.ca)],
        );
        crate::context_refresh::apply_update(&daemon, bump.data.raw().clone())
            .await
            .unwrap();
        let held = daemon.ns.keyring().contexts().pop().unwrap();
        assert!(held.is_revoked(&key));
        assert_eq!(held.revocation_cut(&key), Some(&cut));
        assert!(node.ca.is_revoked(&certificate));
        assert!(
            node.ca.get_served_cert(&certificate).is_some(),
            "the CA keeps serving it"
        );
        node.shutdown.shutdown().await;
    }

    /// S5-01: `revoke --cut` signs only a cut bounded by the root's own
    /// observation at or before the loss: a cut file without a time bound
    /// (a bare RevocationCut, or one bounded only by sequence numbers), or
    /// bounded after the loss time given, is refused before anything is
    /// asked or signed; so is a loss time the CLI cannot read.
    #[tokio::test]
    async fn a_cut_file_is_refused_unless_bounded_before_the_loss() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-a"]).await;
        let (identity, key, _) = enrolled(&node, "member-a").await;
        let lost = "2026-01-01T00:00:00Z";
        let lost_ms = parse_when(lost, now_ms()).unwrap();
        let write = |name: &str, wire: bytes::Bytes| {
            let path = root_dev.path().join(name);
            std::fs::write(&path, wire).unwrap();
            path.to_str().unwrap().to_owned()
        };
        let refused = |path: &str| {
            let given = given_cut(&args(&["--lost", lost]), path, "revoke").unwrap();
            let e = plan(root_dev.path(), &identity, None, Some(given))
                .err()
                .expect("refused");
            assert!(e.is(code::CUT_REFUSED), "{path}: {e:?}");
            e.param("why").unwrap_or_default().to_owned()
        };

        let bare = write("bare.cut", cut_file(&key, None).cut.encode());
        assert_eq!(refused(&bare), "unbounded");
        let mut by_seq = cut_file(&key, None);
        by_seq
            .upto
            .insert(ndn_cert::device_log_of(&key).append("notes"), 3);
        let by_seq = write("seq.cut", by_seq.encode());
        assert_eq!(refused(&by_seq), "unbounded");
        let late = write("late.cut", cut_file(&key, Some(lost_ms + 1)).encode());
        assert_eq!(refused(&late), "after-loss");

        let at_loss = write("ok.cut", cut_file(&key, Some(lost_ms)).encode());
        let given = given_cut(&args(&["--lost", lost]), &at_loss, "revoke").unwrap();
        assert!(plan(root_dev.path(), &identity, None, Some(given)).is_ok());
        assert!(given_cut(&args(&["--lost", "next week"]), &at_loss, "revoke").is_err());
        assert!(
            given_cut(
                &args(&["--lost", "2999-01-01T00:00:00Z"]),
                &at_loss,
                "revoke"
            )
            .is_err()
        );
        node.shutdown.shutdown().await;
    }

    /// The checks before the root is unlocked: only on the root device, never
    /// the root or the CA key, only names the CA certified (or key names),
    /// and nothing to sign when the held version revokes them already.
    #[tokio::test]
    async fn revoke_is_planned_only_on_the_root_device_and_never_for_the_root_or_the_ca() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-a"]).await;
        let (identity, key, _) = enrolled(&node, "member-a").await;

        let held = node.admin.ns.keyring().contexts().pop().unwrap();
        ndn_cert::persist_context(device.path(), &held, &node.context_data).unwrap();
        assert!(
            plan(device.path(), &identity, None, None).is_err(),
            "not the root device"
        );

        let planned = plan(root_dev.path(), &identity, None, None).unwrap();
        assert_eq!(
            (planned.keys.clone(), planned.adding),
            (vec![key.clone()], vec![key])
        );
        for name in [
            "/home/bob/KEY/root",
            "/home/bob/CA",
            "/home/bob/CA/KEY/ca",
            "/home/bob/member/tablet",
            "/home/alice/member/phone/KEY/k",
        ] {
            assert!(
                plan(root_dev.path(), &name.parse().unwrap(), None, None).is_err(),
                "{name}"
            );
        }
        node.shutdown.shutdown().await;
    }

    /// A revocation handed to the daemon (`security/context-update`): the
    /// daemon adopts v2 and its CA, following v2, stops serving the device's
    /// certificate — the device name is free for a new key — and a key the
    /// held version revokes already plans nothing to sign.
    #[tokio::test]
    async fn a_revocation_handed_over_makes_the_ca_stop_serving_the_device() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-a", "member-b"]).await;
        let ns: Name = "/home/bob".parse().unwrap();
        let (identity, key, certificate) = enrolled(&node, "member-a").await;

        let bump = revocation(root_dev.path(), &identity).await;
        let daemon = admin(
            node.admin.ns.engine().clone(),
            root_dev.path(),
            vec![Arc::clone(&node.ca)],
        );
        let info = crate::context_refresh::apply_update(&daemon, bump.data.raw().clone())
            .await
            .unwrap();
        assert_eq!((info.held_version, info.version), (1, 2));
        assert!(
            daemon
                .ns
                .keyring()
                .contexts()
                .pop()
                .unwrap()
                .is_revoked(&key)
        );
        assert!(
            node.ca.get_served_cert(&certificate).is_none(),
            "the CA stops serving it"
        );
        assert!(node.ca.is_revoked(&certificate));
        let (stored, _) = ndn_cert::read_stored_context(root_dev.path(), &ns)
            .unwrap()
            .unwrap();
        assert_eq!(stored.version(), 2);
        assert!(
            plan(root_dev.path(), &key, None, None)
                .unwrap()
                .adding
                .is_empty()
        );

        let (again, other_key, _) = enrolled(&node, "member-b").await;
        assert_eq!(again, identity);
        assert_ne!(other_key, key, "the device name took a new key");
        node.shutdown.shutdown().await;
    }

    /// A revocation a CA node fetches with a refresh (a CA on a node other
    /// than the root device) makes its CA stop serving the device too.
    #[tokio::test]
    async fn a_revocation_adopted_by_refresh_makes_the_ca_stop_serving_the_device() {
        use ndn_engine::{EngineBuilder, EngineConfig};
        use ndn_security::SecurityManager;

        let dirs: Vec<_> = (0..4).map(|_| tempfile::tempdir().unwrap()).collect();
        let (root_dev, device, upstream, relay) = (
            dirs[0].path(),
            dirs[1].path(),
            dirs[2].path(),
            dirs[3].path(),
        );
        let node = node(root_dev, device, &["member-a"]).await;
        let ns: Name = "/home/bob".parse().unwrap();
        let (identity, _, certificate) = enrolled(&node, "member-a").await;
        let bump = revocation(root_dev, &identity).await;

        let held = node.admin.ns.keyring().contexts().pop().unwrap();
        ndn_cert::persist_context(relay, &held, &node.context_data).unwrap();
        ndn_cert::persist_context(upstream, &bump.context, &bump.data).unwrap();
        let (face, publisher) = crate::context_publisher::prepare(upstream);
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .security_profile(ndn_security::SecurityProfile::Disabled)
            .security(Arc::new(SecurityManager::new()))
            .face(face)
            .build()
            .await
            .unwrap();
        let _serving = publisher.spawn(&engine);
        let relay = admin(engine, relay, vec![Arc::clone(&node.ca)]);
        assert!(node.ca.get_served_cert(&certificate).is_some());

        let results = crate::context_refresh::refresh_contexts(&relay, Some(ns.clone()))
            .await
            .unwrap();
        assert_eq!(results[0].version, 2, "{:?}", results[0].detail);
        assert!(
            node.ca.get_served_cert(&certificate).is_none(),
            "the CA stops serving it"
        );
        shutdown.shutdown().await;
        node.shutdown.shutdown().await;
    }

    /// A revocation stored for the daemon's next start (no daemon listened):
    /// the CA follows it when it starts, from the contexts loaded.
    #[tokio::test]
    async fn a_revocation_stored_for_the_next_start_is_followed_when_the_ca_starts() {
        let (root_dev, device) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let node = node(root_dev.path(), device.path(), &["member-a"]).await;
        let (identity, _, certificate) = enrolled(&node, "member-a").await;
        let bump = revocation(root_dev.path(), &identity).await;
        ndn_cert::persist_context(root_dev.path(), &bump.context, &bump.data).unwrap();

        let keyring = Keyring::new();
        ndn_cert::load_persisted_contexts(root_dev.path(), &keyring).unwrap();
        node.ca.follow_held(&keyring);
        assert!(node.ca.get_served_cert(&certificate).is_none());
        node.shutdown.shutdown().await;
    }
}

#[cfg(test)]
mod cut_text_tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    /// A cut of tips: the log prefix, the tip's seq and its digest in hex,
    /// beside the ranges of a cut with a manifest.
    fn tip_cut() -> RevocationCut {
        let mut cut = RevocationCut::new(n("/home/member/phone/KEY/1"));
        cut.add_tip(&n("/home/member/phone/32=log/notes"), 7, [0xab; 32]);
        cut
    }

    fn file_of(cut: RevocationCut, left_out: &[&str]) -> CutFile {
        let mut file = CutFile::new(cut);
        file.left_out = left_out.iter().map(|s| n(s)).collect();
        file
    }

    /// The CLI lists a cut's tips (prefix, seq, digest in hex) as well as
    /// its ranges and exact packets, so the owner checking a cut sees every
    /// form it takes; a cut with none says it accepts nothing.
    #[test]
    fn a_cut_text_lists_the_tips_beside_the_ranges() {
        assert_eq!(
            cut_text(&tip_cut()),
            format!(
                "{} tip seq 7 digest {}",
                n("/home/member/phone/32=log/notes"),
                "ab".repeat(32)
            )
        );
        let mut both = tip_cut();
        both.add_run(&n("/home/member/phone/32=log/todo"), 1, 3);
        let text = cut_text(&both);
        assert!(
            text.starts_with(&format!(
                "{} seq 1..3; ",
                n("/home/member/phone/32=log/todo")
            )) && text.contains(" tip seq 7 digest "),
            "{text}"
        );
        assert_eq!(
            cut_text(&RevocationCut::new(n("/home/member/phone/KEY/1"))),
            "accepts nothing"
        );
    }

    /// A cut of tips says it keeps the packets below each tip by name and
    /// each tip by its signed-region digest, and not that a manifest lists
    /// them: a cut with a manifest still says its manifest.
    #[test]
    fn what_a_cut_keeps_names_tips_where_there_is_no_manifest() {
        let tips = cut_keeps_lines(&tip_cut()).join("\n");
        assert!(
            tips.contains("below each of its tips") && tips.contains("signed region"),
            "{tips}"
        );
        assert!(!tips.contains("manifest"), "{tips}");
        assert!(
            tips.contains("ndn-fwd readmit /home/member/phone/KEY/1 <full-name>"),
            "{tips}"
        );
        let mut listed = RevocationCut::new(n("/home/member/phone/KEY/1"));
        let notes = n("/home/member/phone/32=log/notes");
        let built = ndn_security::cut_manifest::build(
            &n("/home/bob"),
            listed.key(),
            &[(notes.clone(), 1, [1; 32])],
        )
        .unwrap();
        listed.add_run(&notes, 1, 1);
        listed.set_manifest(built.root).unwrap();
        let manifest = cut_keeps_lines(&listed).join("\n");
        assert!(manifest.contains("manifest"), "{manifest}");
        assert!(!manifest.contains("tip"), "{manifest}");
    }

    /// The entries a cut of tips leaves out include those off a tip's chain,
    /// and the note says so; a cut without tips says what it always said;
    /// no entry left out, no note.
    #[test]
    fn the_left_out_note_names_the_chain_of_a_tip() {
        let out = ["/home/member/phone/32=log/notes/seq=2"];
        let tips = left_out_lines(&file_of(tip_cut(), &out)).join("\n");
        assert!(tips.contains("off the chain of a tip"), "{tips}");
        let mut ranged = RevocationCut::new(n("/home/member/phone/KEY/1"));
        ranged.add_run(&n("/home/member/phone/32=log/notes"), 1, 3);
        let plain = left_out_lines(&file_of(ranged, &out)).join("\n");
        assert!(!plain.contains("tip"), "{plain}");
        assert!(left_out_lines(&file_of(tip_cut(), &[])).is_empty());
    }
}
