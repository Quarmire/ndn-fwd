//! `ndn-fwd init --profile hub` and `ndn-fwd adopt <envelope>` — the two-command
//! onboarding UX over the [`ndn_cert::hub`] / [`ndn_cert::onboarding`]
//! primitives. A node does not "join a network"; it *adopts* a trust context.
//!
//! These are early-exit subcommands: when `args[1]` is `init` or `adopt`, the
//! daemon does not start. Both act on the node's PIB directory (`--pib <dir>`,
//! else `[security].pib_path` from `-c/--config`, else `~/.ndn/pib`):
//!
//! - `init` mints the network root `<ns>/KEY/root`, the CA signing identity
//!   `<ns>/CA` and this node's own identity `<ns>/<node-name>` (`--node-name`,
//!   default `hub`), both certified by the root, into the PIB, signs the trust
//!   context with the root, stores it in `<pib>/contexts/`, and prints the
//!   `ndn-trust://anchor` envelope plus the `[security]` lines that make the
//!   daemon load the node identity. Config files are never edited. An existing
//!   root is never replaced unless `--force` is given.
//! - `adopt` verifies an anchor envelope's inline signed context against the
//!   anchor fingerprint it pins (TOFU) and stores it in `<pib>/contexts/`; the
//!   daemon loads that store into its keyring at startup.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use ndn_cert::hub::DEFAULT_NODE_NAME;
use ndn_cert::{adopt_envelope_into_store, anchor_fingerprint, init_hub_in_pib};
use ndn_config::ForwarderConfig;
use ndn_packet::Name;
use ndn_security::FilePib;
use ndn_trust_envelope::TrustEnvelope;

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

/// Options that take a value (so their value is not mistaken for a positional).
const VALUE_FLAGS: &[&str] = &[
    "--profile",
    "--namespace",
    "--node-name",
    "--pib",
    "-c",
    "--config",
];

fn flag<'a>(args: &'a [String], names: &[&str]) -> Option<&'a str> {
    args.iter()
        .position(|a| names.contains(&a.as_str()))
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// The PIB directory: `--pib`, else the config's `[security].pib_path`, else
/// the daemon's default (`~/.ndn/pib`).
fn pib_dir(args: &[String]) -> Result<PathBuf> {
    if let Some(dir) = flag(args, &["--pib"]) {
        return Ok(PathBuf::from(dir));
    }
    if let Some(path) = flag(args, &["-c", "--config"]) {
        let toml = std::fs::read_to_string(path).with_context(|| format!("read config {path}"))?;
        let cfg: ForwarderConfig = toml
            .parse()
            .with_context(|| format!("parse config {path}"))?;
        if let Some(dir) = cfg.security.pib_path {
            return Ok(PathBuf::from(dir));
        }
    }
    Ok(crate::security_init::default_pib_path())
}

fn run_init(args: &[String]) -> Result<()> {
    let profile = flag(args, &["--profile"]).unwrap_or("hub");
    if profile != "hub" {
        bail!("only --profile hub is supported (got {profile:?})");
    }
    let namespace: Name = flag(args, &["--namespace"])
        .context("init requires --namespace <ndn-name>, e.g. /home/bob")?
        .parse()
        .context("invalid --namespace NDN name")?;
    let node_name = flag(args, &["--node-name"]).unwrap_or(DEFAULT_NODE_NAME);
    let force = args.iter().any(|a| a == "--force");
    let pib_dir = pib_dir(args)?;
    let pib =
        FilePib::new(&pib_dir).with_context(|| format!("open PIB at {}", pib_dir.display()))?;

    let out = init_hub_in_pib(&pib, &namespace, node_name, force)?;
    let hub = &out.hub;
    // The daemon may run from another directory: print an absolute path.
    let pib_abs = std::fs::canonicalize(&pib_dir).unwrap_or_else(|_| pib_dir.clone());

    println!("# ndn-fwd hub initialized");
    println!("namespace      = {namespace}");
    println!("pib            = {}", pib_dir.display());
    println!("anchor_key     = {}", hub.anchor_key);
    println!(
        "anchor_fp      = {}",
        hex_lower(&anchor_fingerprint(&hub.anchor))
    );
    println!("ca_key         = {}", out.ca_key);
    println!("ca_cert        = {}", out.ca_cert_path.display());
    println!("node_identity  = {}", out.node_identity);
    println!("node_key       = {}", out.node_key);
    println!("node_cert      = {}", out.node_cert_path.display());
    println!(
        "context        = {} (v{})",
        out.context_path.display(),
        hub.context.version()
    );
    println!("enrollment     = token AND device-approval");
    println!("anchor_uri     = {}", hub.envelope.to_uri());
    println!(
        "anchor_url     = {}",
        hub.envelope.to_https_url("ndn.local")
    );
    println!();
    println!("# Scan anchor_uri as a QR, or share anchor_url. Adopting it lets a");
    println!("# peer VERIFY this namespace; producing still needs enrollment.");
    println!("# The root key now lives in the PIB: keep a recovery copy offline.");
    println!("#");
    println!("# Put these lines in ndn-fwd.toml so the daemon signs as this node's");
    println!("# identity (certified by the root) instead of an ephemeral key:");
    println!("[security]");
    println!(
        "identity = {}",
        toml_basic_string(&out.node_identity.to_string())
    );
    println!(
        "pib_path = {}",
        toml_basic_string(&pib_abs.display().to_string())
    );
    Ok(())
}

/// `s` as a TOML basic string (quoted, with `\`, `"` and control characters
/// escaped).
fn toml_basic_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn run_adopt(args: &[String]) -> Result<()> {
    // The envelope is the first argument that is neither a flag nor a flag's value.
    let uri = args
        .iter()
        .enumerate()
        .find(|(i, a)| {
            !a.starts_with('-') && (*i == 0 || !VALUE_FLAGS.contains(&args[i - 1].as_str()))
        })
        .map(|(_, a)| a)
        .context("adopt requires an <envelope> (an ndn-trust://anchor URI or its https mirror)")?;
    let envelope =
        TrustEnvelope::from_uri(uri).map_err(|e| anyhow::anyhow!("parse trust envelope: {e}"))?;
    let pib_dir = pib_dir(args)?;

    let (ctx, path) = adopt_envelope_into_store(&pib_dir, &envelope)
        .map_err(|e| anyhow::anyhow!("adopt refused: {e}"))?;
    let pinned_fp = match &envelope {
        TrustEnvelope::Anchor {
            fingerprint: Some(fp),
            ..
        } => hex_lower(fp),
        _ => String::new(),
    };

    println!("# ndn-fwd adopt");
    println!("namespace      = {}", ctx.namespace());
    println!("version        = {}", ctx.version());
    println!("pinned_fp      = {pinned_fp}");
    println!("anchors        = {}", ctx.anchors().len());
    println!("ca_endpoints   = {}", ctx.ca_endpoints().len());
    println!("stored         = {}", path.display());
    println!();
    println!("# Signature verified under the pinned anchor. The daemon loads this");
    println!("# context at startup (same pib_path); producing still needs enrollment.");
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
