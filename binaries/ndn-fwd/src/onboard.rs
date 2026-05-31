//! `ndn-fwd init --profile hub` and `ndn-fwd adopt <ticket>` — the two-command
//! onboarding UX over the [`ndn_cert::hub`] / [`ndn_cert::onboarding`]
//! primitives. A node does not "join a network"; it *adopts* a trust context.
//!
//! These are early-exit subcommands: when `args[1]` is `init` or `adopt`, the
//! daemon does not start. `init` stands up a network root and prints its
//! `TrustContext` + a bootstrap ticket; `adopt` parses a ticket and reports the
//! TOFU fingerprint it will pin (full context fetch + enrollment is wired by
//! the forwarder's faces, which aren't running in this one-shot path).

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use ndn_cert::{BootstrapTicket, init_hub};
use ndn_security::SecurityManager;

/// Inspect `argv`; if it names an onboarding subcommand, run it and return
/// `Some(result)`. Returns `None` for the normal daemon path.
pub fn maybe_run() -> Option<Result<()>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("init") => Some(run_init(&args[2..])),
        Some("adopt") => Some(run_adopt(&args[2..])),
        _ => None,
    }
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn run_init(args: &[String]) -> Result<()> {
    let profile = flag(args, "--profile").unwrap_or("hub");
    if profile != "hub" {
        bail!("only --profile hub is supported (got {profile:?})");
    }
    let namespace = flag(args, "--namespace")
        .context("init requires --namespace <ndn-name>, e.g. /home/bob")?
        .parse()
        .context("invalid --namespace NDN name")?;

    // In-memory root for the one-shot. A persistent hub keeps the signing key
    // in a 0600 PIB under [security].pib_path; that wiring lives with the
    // daemon's security_init, not this print-and-exit path.
    let mgr = SecurityManager::new();
    let hub = init_hub(&mgr, &namespace).map_err(|e| anyhow::anyhow!("init_hub: {e}"))?;

    let content_b64 = base64::engine::general_purpose::STANDARD.encode(hub.published_content());

    println!("# ndn-fwd hub initialized");
    println!("namespace      = {}", namespace);
    println!("anchor_key     = {}", hub.anchor_key);
    println!("enrollment     = token AND device-approval");
    println!("bootstrap_url      = {}", hub.ticket.to_url("ndn.local"));
    println!("bootstrap_fragment = {}", hub.ticket.to_fragment());
    println!("context_v1_b64     = {content_b64}");
    println!();
    println!("# Scan the bootstrap_url as a QR, or share the fragment. Adopting it");
    println!("# lets a peer VERIFY this namespace; producing still needs enrollment.");
    Ok(())
}

fn run_adopt(args: &[String]) -> Result<()> {
    let ticket_str = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .context("adopt requires a <ticket> (a bootstrap URL or fragment)")?;
    let ticket = BootstrapTicket::from_fragment(ticket_str)
        .map_err(|e| anyhow::anyhow!("parse bootstrap ticket: {e}"))?;

    let ns = ticket
        .namespace_name()
        .context("ticket carries no valid namespace")?;
    let fp = ticket
        .fingerprint()
        .context("ticket carries no valid anchor fingerprint")?;

    println!("# ndn-fwd adopt");
    println!("namespace        = {ns}");
    println!("pin_anchor_fp    = {}", hex_lower(&fp));
    if let Some(face) = &ticket.bootstrap_face {
        println!("bootstrap_face   = {face}");
    }
    println!("has_token        = {}", ticket.token.is_some());
    println!();
    println!("# This node will fetch {ns}/32=trust-context, TOFU-check its anchor");
    println!("# against pin_anchor_fp, then adopt it. Run the daemon with a face to");
    println!(
        "# the bootstrap hint to complete the fetch{}.",
        if ticket.token.is_some() {
            " + enrollment"
        } else {
            ""
        }
    );
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
