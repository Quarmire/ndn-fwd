//! `ndn-fwd recover`: make a replacement device the root device of a
//! namespace whose root device is lost, with a recovery kit — the CLI over
//! [`ndn_namespace::root::recover`].
//!
//! On the replacement device, its own daemon running (the one that uses the
//! PIB recovered into) and linked to the namespace (directly or through a
//! relay):
//!
//! 1. **The newest version, by name.** The daemon refreshes the context it
//!    holds (RDR, under the continuity rule — the same as `ndn-fwd context
//!    refresh`); a device holding none adopts it first from a file kit's
//!    expected fingerprint. Recovering from an older version than the
//!    namespace serves would fork it, so a failed refresh stops here. When
//!    nothing answers at all (the lost root device was the only other node
//!    reachable), `--from-held` recovers from the version held: the
//!    operator vouches that no newer one exists. A version that answers and
//!    is refused still stops it ([`ndn_namespace::admin::fetch_newest`]).
//! 2. **The kit.** Its key must be a recovery anchor of that version (and
//!    the version must verify under its own anchors), else nothing is
//!    signed. A mistyped word list is refused by its checksum. A YubiKey
//!    kit's token is selected with `--kit-yubikey-serial/--kit-yubikey-slot`.
//! 3. **The new root device.** [`ndn_cert::recover_namespace_in_pib`]: a new
//!    root in the root store the operator picks (as `init`; never on the
//!    kit's token, nor over an occupied slot without `--replace-slot`), a
//!    new CA key and admin identity with fresh key ids, version `N+1` signed
//!    by the recovery key — the old root kept as an anchor with every
//!    recovery kit (`--old-root destroyed`), or removed and revoked with the
//!    old CA and admin keys and every recovery kit but the one used and
//!    those named with `--keep-kit` (`--old-root compromised`: whoever held
//!    the root could have added a kit) — and version `N+2`, the same content
//!    signed by the new root. Every anchor `N+1` keeps is printed. The roots
//!    of other trusted prefixes this PIB holds stay beside the recovered one.
//! 4. **Hand-over.** `N+1`, then `N+2`, go to the daemon
//!    (`security/context-update`), which adopts each by the continuity rule,
//!    stores and publishes it; every other node adopts them the same way at
//!    its next refresh, one after the other (a node that missed `N+1`
//!    follows the versions by name, `ndn_cert::follow_versions`). Only the
//!    daemon's refusal of `N+1` removes what step 3 wrote; a request it does
//!    not answer in time is made again, and the answer says what became of
//!    `N+1` ([`ndn_namespace::admin::hand_over`]). Once `N+2` is taken, the
//!    newest version is signed by the new root, so the root's fingerprint is
//!    the namespace's expected fingerprint again: the anchor link printed,
//!    and invites minted from then on, carry it. Until then no link is
//!    printed.
//!
//! **Revocation cuts.** `N+1` and `N+2` carry every cut the held version
//! holds, except orphan cuts and cuts naming packets outside their key's
//! device log, which whoever held a compromised root could have planted:
//! those are dropped and listed (`dropped_cut`). With `--old-root
//! compromised`, `--cut <file>` (repeatable) adds the cut of a key the
//! recovery newly revokes (the old admin key, a kit not kept), beside its
//! revocation: a cut file the device's data layer wrote, bounded at or
//! before the time the old root device was lost (**"When did you lose
//! it?"**, `--lost <when>` without a terminal) and carrying its whole
//! manifest, else nothing is signed (`cut-refused`); its manifest packets
//! are stored and served with `N+1`, and the entries its bound left out
//! are listed for re-admission one by one ([`crate::readmit`]). The old CA
//! no longer chains then, so a key revoked with a cut could not renew and
//! the packets its cut accepts would stop verifying: once `N+1` is taken,
//! the cuts it holds are shown and the operator is asked whether the new
//! CA certifies those keys again (`--recertify-cuts yes|no` without a
//! terminal; no answer is no). Only a certificate of each key whose public
//! key is the one its cut names (CutKeyDigest) is certified again (a
//! certificate of the new CA, recorded in its store and served from its
//! next start; the key stays revoked for everything else); a cut naming no
//! public key is never re-certified (`no_key_digest`). A key of none held
//! is listed; `ndn-fwd recertify <cert-file>` certifies it once its
//! certificate is at hand ([`run_recertify`]).

use anyhow::{Context, Result, bail};
use ndn_cert::report::{Detail, code};
use ndn_cert::{CutKeyCertificates, GivenCut, OldRoot};
use ndn_namespace::admin::NotTaken;
use ndn_namespace::hex;
use ndn_namespace::root::RootError;
use ndn_namespace::root::recover::{self, AnchorKind, Recertify, RecoverRequest, RevokedKind};
use ndn_packet::{Data, Name};
use ndn_security::{Certificate, RevocationCut};

use crate::context_adopt::namespace_words;
use crate::onboard::{flag, flag_values, pib_dir, positionals};
use crate::recovery_kit::kit_spec;
use crate::revoke::{cut_refused, cut_text, loss_time, print_left_out, read_cut_file};
use crate::root_host::{Secrets, daemon, handed_text, namespace_arg, print_keys_to_end, render};

/// The question a compromised recovery asks once `N+1` is taken.
const RECERTIFY_QUESTION: &str = "Certify these keys again with the new CA? [y/N]";

/// The cuts re-certification considers, one line each, as the CLI shows
/// them before it asks.
fn print_cuts_to_recertify(cuts: &[RevocationCut]) {
    eprintln!("These keys are revoked with a cut. Certifying one again lets the packets its");
    eprintln!("cut accepts verify under the CA; check that each cut is one you made:");
    for cut in cuts {
        let digest = match cut.key_digest() {
            Some(_) => "names its public key",
            None => "names no public key: never certified again",
        };
        eprintln!("  {}: {} ({digest})", cut.key(), cut_text(cut));
    }
}

/// Ask `question` on the terminal, showing `cuts`: only `y` or `yes`
/// certifies.
fn ask_recertify(cuts: &[RevocationCut], question: &str) -> bool {
    print_cuts_to_recertify(cuts);
    eprint!("{question} ");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let mut answer = String::new();
    match std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut answer) {
        Ok(_) => matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"),
        Err(_) => false,
    }
}

/// Whether there is a terminal to ask on.
fn interactive() -> bool {
    use std::io::IsTerminal as _;
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// `--recertify-cuts yes|no`, else asked once `N+1` is taken when there is
/// a terminal, else not now (`ndn-fwd recertify` does it later).
fn recertify_choice(args: &[String]) -> Result<Recertify> {
    match flag(args, &["--recertify-cuts"]) {
        Some("yes") => Ok(Recertify::Yes),
        Some("no") => Ok(Recertify::No),
        Some(other) => bail!(
            "recover refused: --recertify-cuts {other:?}: say `yes` (the new CA certifies again \
             the keys revoked with a cut whose certificate this PIB holds) or `no` (later, with \
             `ndn-fwd recertify`). Nothing was signed"
        ),
        None if interactive() => Ok(Recertify::Ask(Box::new(|cuts| {
            ask_recertify(cuts, RECERTIFY_QUESTION)
        }))),
        None => Ok(Recertify::No),
    }
}

/// The lines of a re-certification's outcome, with the PIB `pib` for the
/// command that finishes it.
fn print_recertified(done: &CutKeyCertificates, pib: &std::path::Path, what: &str) {
    for cert in &done.issued {
        println!(
            "recertified    = {} (revoked with a cut; certified again by {what})",
            cert.name
        );
    }
    for key in &done.unheld {
        println!(
            "not_recertified = {key} (unheld: no certificate of it with the public key its cut \
             names is given or kept here; the packets its cut accepts stop verifying until \
             `ndn-fwd recertify <its certificate file> --pib {}`)",
            pib.display()
        );
    }
    for key in &done.no_key_digest {
        println!(
            "not_recertified = {key} (no_key_digest: its cut names no public key, so nothing \
             ties it to the key that signed what it accepts; never certified again)"
        );
    }
}

/// The answer the anti-fork check refused on, in the CLI's words: the
/// detail it carries as its cause.
fn newest_detail(e: &RootError) -> String {
    let detail = Detail {
        code: e.param("cause").unwrap_or_default().to_string(),
        params: e.refusal.params.clone(),
        text: e.param("detail").unwrap_or_default().to_string(),
    };
    namespace_words().render_detail(&detail)
}

/// A refused recovery, as the CLI says it.
fn refused(e: RootError) -> anyhow::Error {
    let p = |key: &str| e.param(key).unwrap_or_default().to_string();
    let (namespace, held) = (p("namespace"), p("held_version"));
    if e.is(code::ALREADY_ROOT_DEVICE) && e.underlying().is_none() {
        return anyhow::anyhow!(
            "{} holds the root of {namespace} ({} root store): this already is a root device of \
             it. Recover on a replacement device whose PIB holds no root of {namespace} (the \
             roots of other trusted prefixes may stay)",
            p("pib"),
            p("store")
        );
    }
    if e.is(code::DEVICE_NOT_RUNNING) || e.is(code::DEVICE_UNREACHABLE) {
        return anyhow::anyhow!(
            "recover refused: the daemon is not reachable at {} ({}). The running daemon does \
             it; start ndn-fwd (with `-c <config>` if it uses another socket) and retry",
            p("address"),
            p("error")
        );
    }
    if e.is(code::NEWEST_BEHIND) {
        return anyhow::anyhow!(
            "{}. A newer version of {namespace} exists than the held v{held}: recovering from it \
             would fork the namespace; refresh until it is held, then retry",
            newest_detail(&e)
        );
    }
    if e.is(code::NEWEST_UNCONFIRMED) {
        return anyhow::anyhow!(
            "{}. Recovering from the held v{held} without knowing it is the newest could fork \
             the namespace: give this device a face and a route toward a relay or member that \
             holds it, then retry. If no other node holding {namespace} exists or can be \
             reached, and you know no version newer than v{held} was made, retry with \
             --from-held",
            newest_detail(&e)
        );
    }
    if e.is(code::NEWEST_FAILED) {
        return anyhow::anyhow!(
            "could not get the newest trust context of {namespace} by name ({}). Recovering from \
             v{held} without knowing it is the newest would fork the namespace: make sure this \
             device reaches the namespace (a face and a route toward a relay or member that \
             holds it), then retry",
            newest_detail(&e)
        );
    }
    if e.is(code::RECOVER_ON_ROOT_DEVICE) {
        return anyhow::anyhow!(
            "this device holds the root of {namespace} (`ndn-fwd root-key status`): it is the \
             root device, nothing to recover"
        );
    }
    if e.is(code::NEWEST_NOT_HELD) {
        return anyhow::anyhow!(
            "this device's daemon holds no trust context for {namespace}. Adopt it first with \
             the namespace's anchor link (`ndn-fwd adopt <ndn-trust://anchor/…>`, the link \
             `ndn-fwd init` printed), so the version recovered from is authenticated, then retry"
        );
    }
    if e.is(code::DEVICE_STORE_MISMATCH) {
        let stored = match e.param("stored") {
            Some(stored) => format!("stores v{stored}"),
            None => "has no stored copy".to_string(),
        };
        return anyhow::anyhow!(
            "the daemon holds {namespace} v{} but {} {stored}; is -c/--pib the daemon's PIB?",
            p("version"),
            p("pib")
        );
    }
    if e.is(code::HELD_CONTEXT_INVALID) {
        let context = format!("the stored {namespace} v{} does not verify", p("version"));
        return render(e).context(context);
    }
    if e.is(code::VERSION_NOT_TAKEN) {
        return render(e).context(
            "the daemon did not take the recovered version; everything this command wrote to the \
             PIB was removed again and nothing changed",
        );
    }
    if e.is(code::HAND_OVER_UNKNOWN) {
        let (next, pib) = (p("version"), p("pib"));
        let context = format!(
            "whether the daemon adopted v{next} is not known, so nothing this command wrote was \
             removed (v{next} names the new root {}). `ndn-fwd recovery-kit list --pib {pib}` \
             shows the version the daemon stored: v{next} means the recovery took — run \
             `ndn-fwd recovery-kit create --pib {pib}` then, so the new root signs the newest \
             version; v{held} once the daemon is idle or restarted means it did not — remove \
             {pib}/root, {pib}/ca and the keys {} and {} from the PIB, and recover again",
            p("root_key"),
            p("ca_key"),
            p("device_key"),
        );
        return render(e).context(context);
    }
    cut_refused(e, "recover")
}

pub(crate) async fn run(args: &[String]) -> Result<()> {
    let old_root: OldRoot = match flag(args, &["--old-root"]) {
        Some(choice) => choice.parse().map_err(|e: String| anyhow::anyhow!(e))?,
        None => bail!(
            "recover needs --old-root destroyed|compromised: say what happened to the lost root \
             device. {}",
            OldRoot::CHOICE
        ),
    };
    let kit = kit_spec(
        args,
        flag(args, &["--kit"]).context("recover needs --kit words|yubikey|<kit-file>")?,
    )?;
    let kit_format = kit.format();
    let pib_dir = pib_dir(args)?;
    let namespace = namespace_arg(args)?;
    let device = match flag(args, &["--device"]) {
        Some(device) => device.to_string(),
        None => crate::onboard::default_device()?,
    };
    let kept_kits = flag_values(args, "--keep-kit")
        .into_iter()
        .map(|key| {
            key.parse::<Name>()
                .map_err(|e| anyhow::anyhow!("--keep-kit {key:?} is not an NDN name: {e}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let cut_files = flag_values(args, "--cut")
        .into_iter()
        .map(|path| read_cut_file(path, "recover"))
        .collect::<Result<Vec<_>>>()?;
    // One loss time for every cut: when the old root device was lost.
    let cuts: Vec<GivenCut> = match cut_files.is_empty() {
        true => Vec::new(),
        false => {
            let lost = loss_time(args, "the old root device", "recover")?;
            cut_files
                .into_iter()
                .map(|file| GivenCut { file, lost })
                .collect()
        }
    };
    let recertify = recertify_choice(args)?;
    let root = crate::root_key::root_store_choice(args)?;
    let daemon = daemon(args)?;
    let done = recover::recover(
        RecoverRequest {
            pib_dir: pib_dir.clone(),
            kit,
            namespace,
            device,
            old_root,
            kept_kits,
            cuts,
            from_held: args.iter().any(|a| a == "--from-held"),
            root,
            recertify,
        },
        &daemon,
        &Secrets { args },
    )
    .await
    .map_err(refused)?;

    let links = done.anchor_links();
    let recover::Recovered {
        namespace,
        confirmed,
        recovered,
        handed,
        root_handed,
        anchor_fingerprint,
        pib_abs,
        anchors,
        revoked,
        cuts: cut_files,
        recertified,
        ..
    } = done;
    let v = &recovered.version;
    let next = v.bump.context.version();
    let settled = recovered.root_version.context.version();
    let root_fp = hex(&anchor_fingerprint);
    println!("# ndn-fwd recover: this device is the root device of {namespace} now");
    println!("namespace      = {namespace}");
    println!("recovered_with = {} ({kit_format} kit)", v.recovery_key);
    println!("old_root       = {old_root}");
    if !confirmed {
        println!(
            "newest_check   = not confirmed: nothing answered for {namespace}; recovered from the \
             held v{} (--from-held)",
            recovered.previous_version
        );
    }
    println!(
        "trust_context  = v{} -> v{next} (signed by the recovery key; {})",
        recovered.previous_version,
        handed_text(&handed, &daemon, next, &pib_dir)
    );
    // Whether the new root signs the newest version.
    let root_taken = match root_handed {
        Ok(handed) => {
            println!(
                "trust_context  = v{next} -> v{settled} (the same, signed by the new root; {})",
                handed_text(&handed, &daemon, settled, &pib_dir)
            );
            true
        }
        Err(NotTaken::Refused(e)) => {
            println!(
                "trust_context  = v{settled} (the same, signed by the new root) NOT taken: {:#}",
                render(e)
            );
            false
        }
        Err(NotTaken::Unknown(e)) => {
            println!(
                "trust_context  = v{settled} (the same, signed by the new root) NOT KNOWN whether \
                 taken: {:#}",
                render(e)
            );
            false
        }
    };
    println!("root_key       = {}", recovered.anchor.key_name());
    println!("anchor_fp      = {root_fp}");
    for line in crate::root_key::describe_new_root(&recovered.root_store, &pib_abs) {
        println!("{line}");
    }
    println!("ca_key         = {}", recovered.ca_key);
    println!(
        "ca_cert        = {} (issued by the new root)",
        recovered.ca_cert_path.display()
    );
    println!("device         = {} (admin)", recovered.device_identity);
    println!("device_key     = {}", recovered.device_key);
    println!(
        "device_cert    = {} (issued by the new CA)",
        recovered.device_cert_path.display()
    );
    // Every anchor v{next} keeps, so a key nobody expects stands out.
    for (key, kind) in &anchors {
        let what = match kind {
            AnchorKind::NewRoot => "the new root",
            AnchorKind::KitUsed => "recovery kit, used here",
            AnchorKind::RecoveryKit => "recovery kit",
            AnchorKind::OldRoot => "the old root; its certificates stay valid",
        };
        println!("anchor         = {key} ({what})");
    }
    for (key, kind) in &revoked {
        let what = match kind {
            RevokedKind::UnkeptKit => "a recovery kit not named with --keep-kit",
            RevokedKind::OldRoot => "the old root",
            RevokedKind::OldRootDeviceKey => "a key of the old root device",
        };
        println!("revoked        = {key} ({what})");
    }
    // Every cut v{next} holds: the held ones, carried, and those given.
    for cut in v.bump.context.revocation_cuts() {
        println!("cut            = {}: {}", cut.key(), cut_text(cut));
    }
    for file in &cut_files {
        print_left_out(file);
    }
    // Cuts of v{previous} not carried: orphan cuts (no revocation names their
    // key) and cuts naming packets outside their key's device log.
    for dropped in &v.dropped_cuts {
        println!("dropped_cut    = {}: {}", dropped.key, dropped.reason);
    }
    match recertified {
        Some(Ok(done)) => print_recertified(&done, &pib_abs, "the new CA"),
        Some(Err(e)) => println!(
            "recertified    = NOT done ({:#}): run `ndn-fwd recertify --pib {}` to certify them \
             again",
            render(e),
            pib_abs.display()
        ),
        None if old_root == OldRoot::Compromised
            && v.bump
                .context
                .revocation_cuts()
                .iter()
                .any(|c| v.bump.context.revocations().contains(c.key())) =>
        {
            println!(
                "recertified    = not now (not confirmed): the packets the cuts above accept stop \
                 verifying where the old CA no longer chains, until `ndn-fwd recertify --pib {}`",
                pib_abs.display()
            );
        }
        None => {}
    }
    // An anchor link names the newest version's signer as the expected
    // fingerprint: the new root, once it signed v{settled}. Until then no
    // link is printed — one with the recovery key's fingerprint would stop
    // working as soon as the root signs anything, and would put the kit's
    // fingerprint into circulation.
    if let Some((full, fingerprint_only)) = links {
        println!("anchor_uri     = {}", full.to_uri());
        println!("anchor_uri_fp  = {}", fingerprint_only.to_uri());
    }
    println!();
    println!("# Restart this device's daemon with these lines in ndn-fwd.toml, so it signs as its");
    println!("# admin identity and runs the namespace CA (the endpoint stays {namespace}/CA; one");
    println!(
        "# [[ca]] table per trusted prefix this device is the root of); copy the [[ca.challenge]]"
    );
    println!("# set of the old root device (token and device-approval):");
    println!("[security]");
    println!("identity = \"{}\"", recovered.device_identity);
    println!("pib_path = \"{}\"", pib_abs.display());
    println!("[[ca]]");
    println!("enabled  = true");
    println!("prefix   = \"{namespace}\"");
    println!("identity = \"{namespace}/CA\"");
    println!();
    println!("# Every other node adopts v{next} and v{settled} at its next refresh ([security]");
    println!(
        "# context_refresh_secs) or at once with `ndn-fwd context refresh`: v{next} is signed by"
    );
    println!(
        "# the recovery key, an anchor of v{}, and v{settled} by the new root, which v{next} made",
        recovered.previous_version
    );
    println!("# an anchor. A node that missed them follows them one by one, from any node that");
    println!("# holds them (every node keeps and serves the versions it held).");
    match root_taken {
        true => {
            println!(
                "# The namespace's expected fingerprint is the new root's now ({root_fp}): the"
            );
            println!("# anchor links above and every invite minted from now on carry it:");
            println!("#   ndn-fwd-tokens new -c <config> --namespace {namespace} --role member");
            println!(
                "# Links and invites minted before carry the old root's fingerprint: they no longer"
            );
            println!("# adopt the namespace on a device that holds nothing. Mint new ones.");
        }
        false => {
            println!(
                "# v{settled} is not known to be taken, so the newest version may be signed by the"
            );
            println!(
                "# recovery key, and no anchor link is printed. Once the daemon is reachable and"
            );
            println!(
                "# holds v{next} (`ndn-fwd recovery-kit list --pib {}`), run `ndn-fwd recovery-kit",
                pib_abs.display()
            );
            println!(
                "# create`: the root signs the newest version, and its fingerprint ({root_fp})"
            );
            println!(
                "# becomes the namespace's expected fingerprint for anchor links and invites."
            );
        }
    }
    match old_root {
        OldRoot::Destroyed => {
            println!("#");
            println!(
                "# The old root stays an anchor: devices keep their certificates and renew them"
            );
            println!("# with the new CA (`ndn-fwd renew`, or their renewal timer).");
        }
        OldRoot::Compromised => {
            println!("#");
            println!(
                "# Revoked: the old root, CA and admin keys. Every device certificate the old CA"
            );
            println!(
                "# issued stops validating once a node holds v{next}. Each such device enrolls"
            );
            println!("# again with a new invite from this device, once it holds v{next}:");
            println!(
                "#   here:   ndn-fwd-tokens new -c <config> --namespace {namespace} --role member"
            );
            println!("#   there:  ndn-fwd context refresh && ndn-fwd enroll <invite> --force");
            println!("# (admins and relays: by device approval from this device).");
            if v.root_device_keys_unrecorded {
                println!(
                    "# v{} recorded no root-device keys (a namespace made before they were): the CA",
                    recovered.previous_version
                );
                println!(
                    "# key init names was revoked; revoke the old root device's admin key too:"
                );
                println!("#   ndn-fwd revoke {namespace}/admin/<old-device>/KEY/device");
            }
        }
    }
    println!("#");
    if !v.removed_kits.is_empty() {
        println!(
            "# Revoked recovery kits (whoever held the old root could have added them): any of"
        );
        println!("# them that was yours no longer recovers anything; create new ones.");
    }
    println!("# Create a new recovery kit now (`ndn-fwd recovery-kit create`); the kit used here");
    println!(
        "# stays a recovery anchor until `ndn-fwd recovery-kit revoke {}`.",
        v.recovery_key
    );
    Ok(())
}

/// The certificate in the file `path` (a certificate Data, as `ndn-fwd`
/// writes certificate files), for `recertify`'s refusal.
fn read_certificate(path: &str) -> Result<Certificate> {
    let wire = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("recertify refused: cannot read {path}: {e}"))?;
    Data::decode(bytes::Bytes::from(wire))
        .map_err(|e| e.to_string())
        .and_then(|data| Certificate::decode(&data).map_err(|e| e.to_string()))
        .map_err(|e| {
            anyhow::anyhow!(
                "recertify refused: {path} is not a certificate ({e}): give the certificate Data \
                 file of the revoked key (e.g. the device's own certificate file). Nothing was \
                 certified"
            )
        })
}

/// `ndn-fwd recertify [<cert-file>]... [--yes]`: on the root device, certify
/// again, by the namespace CA, each key the held version revokes with a cut
/// naming its public key that the CA has not certified yet, from a
/// certificate with exactly that public key given (or kept in the PIB) —
/// what a compromised recovery listed as `not_recertified`. The cuts are
/// shown first and the operator confirms (`--yes` beforehand; without a
/// terminal and without `--yes`, nothing is certified). Only certificates
/// the operator holds are used, never ones fetched from the network:
/// whoever held the old root could have forged those.
pub(crate) async fn run_recertify(args: &[String]) -> Result<()> {
    let certificates = positionals(args)
        .into_iter()
        .map(read_certificate)
        .collect::<Result<Vec<_>>>()?;
    let pib_dir = pib_dir(args)?;
    let (namespace, cuts) =
        recover::cut_keys(&pib_dir, namespace_arg(args)?.as_ref()).map_err(render)?;
    println!("# ndn-fwd recertify");
    println!("namespace      = {namespace}");
    if cuts.is_empty() {
        println!("# The held version revokes no key with a cut; nothing to certify.");
        print_keys_to_end(&pib_dir);
        return Ok(());
    }
    for cut in &cuts {
        println!("cut            = {}: {}", cut.key(), cut_text(cut));
    }
    if !args.iter().any(|a| a == "--yes") {
        if !interactive() {
            bail!(
                "recertify refused: certifying these keys again lets the packets their cuts \
                 accept verify, and there is no terminal to confirm the cuts listed above: check \
                 that each is one you made, then run again with --yes. Nothing was certified"
            );
        }
        if !ask_recertify(&cuts, "Certify these keys again with the CA? [y/N]") {
            println!("# Not confirmed; nothing was certified.");
            return Ok(());
        }
    }
    let (namespace, done) = recover::recertify(&pib_dir, Some(&namespace), &certificates)
        .await
        .map_err(render)?;
    print_recertified(&done, &pib_dir, "the CA");
    if done.issued.is_empty() && done.unheld.is_empty() && done.no_key_digest.is_empty() {
        println!("# Every key revoked with a cut is certified by the CA of {namespace} already;");
        println!("# nothing issued.");
    }
    if !done.issued.is_empty() {
        println!();
        println!("# Restart this device's daemon: its CA serves these certificates from its next");
        println!("# start, so the packets each key's cut accepts verify again. The keys stay");
        println!("# revoked for everything else (never enrolled or renewed).");
    }
    print_keys_to_end(&pib_dir);
    Ok(())
}
