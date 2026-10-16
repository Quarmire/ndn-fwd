//! `ndn-fwd init --profile hub` and `ndn-fwd adopt <envelope>` — the two-command
//! onboarding UX over the [`ndn_cert::hub`] / [`ndn_cert::onboarding`]
//! primitives. A node does not "join a network"; it *adopts* a trust context.
//!
//! These are early-exit subcommands: when `args[1]` is `init`, `adopt` or
//! `schema` ([`crate::schema_cmd`]), the daemon does not start. They act on
//! the node's PIB directory (`--pib <dir>`, else `[security].pib_path` from
//! `-c/--config`, else `~/.ndn/pib`):
//!
//! - `init` mints the network root `<ns>/KEY/root`, the CA signing identity
//!   `<ns>/CA` (certified by the root) and this primary device's admin
//!   identity `<ns>/admin/<device>` (`--device`, default derived from the
//!   host name; certified by the CA) into the PIB, signs the trust context —
//!   carrying the generated personal-network schema — with the root, stores
//!   it in `<pib>/contexts/`, and prints the `ndn-trust://anchor` envelope
//!   plus the `[security]` lines that make the daemon load the device
//!   identity. Config files are never edited. An existing root is never
//!   replaced unless `--force` is given.
//! - `adopt` adopts the network an anchor link (`ndn-trust://anchor/…`)
//!   names. With the daemon running (its management socket from `-c`, else
//!   the default), the daemon does it: a link with the context inline is
//!   verified against the expected fingerprint; a fingerprint-only link makes
//!   the daemon fetch the context by name from the network. Either way the
//!   daemon trusts, stores and publishes it at once. With no daemon, a link
//!   with the context inline is verified and stored in `<pib>/contexts/`,
//!   loaded at the next start; a fingerprint-only link needs the daemon.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use ndn_cert::roles::sanitize_device_name;
use ndn_cert::{AnchorLink, adopt_envelope_into_store, anchor_fingerprint, init_hub_in_pib};
use ndn_config::ForwarderConfig;
use ndn_packet::Name;
use ndn_security::FilePib;
use ndn_trust_envelope::TrustEnvelope;

/// Inspect `argv`; if it names an onboarding subcommand, run it and return
/// `Some(result)`. Returns `None` for the normal daemon path.
pub async fn maybe_run() -> Option<Result<()>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("init") => Some(run_init(&args[2..])),
        Some("adopt") => Some(run_adopt(&args[2..]).await),
        Some("schema") => Some(crate::schema_cmd::run(&args[2..])),
        _ => None,
    }
}

/// Options that take a value (so their value is not mistaken for a positional).
pub(crate) const VALUE_FLAGS: &[&str] = &[
    "--profile",
    "--namespace",
    "--device",
    "--pib",
    "-c",
    "--config",
];

pub(crate) fn flag<'a>(args: &'a [String], names: &[&str]) -> Option<&'a str> {
    args.iter()
        .position(|a| names.contains(&a.as_str()))
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// The arguments that are neither a flag (`-c`, `--pib`, …) nor a value
/// flag's value, in order.
pub(crate) fn positionals(args: &[String]) -> Vec<&str> {
    args.iter()
        .enumerate()
        .filter(|(i, a)| {
            !a.starts_with('-') && (*i == 0 || !VALUE_FLAGS.contains(&args[i - 1].as_str()))
        })
        .map(|(_, a)| a.as_str())
        .collect()
}

/// The PIB directory: `--pib`, else the config's `[security].pib_path`, else
/// the daemon's default (`~/.ndn/pib`).
pub(crate) fn pib_dir(args: &[String]) -> Result<PathBuf> {
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

/// This host's name, for the default `--device`: the kernel's, else
/// `/etc/hostname`, else `$HOSTNAME`.
fn host_name() -> Option<String> {
    ["/proc/sys/kernel/hostname", "/etc/hostname"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
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
    let device = match flag(args, &["--device"]) {
        Some(device) => device.to_string(),
        None => {
            let host = host_name().unwrap_or_default();
            sanitize_device_name(&host).with_context(|| {
                format!(
                    "cannot derive a device name from the host name {host:?}; pass \
                     --device <name> (letters, digits, '-', '_', '.')"
                )
            })?
        }
    };
    let force = args.iter().any(|a| a == "--force");
    let pib_dir = pib_dir(args)?;
    let pib =
        FilePib::new(&pib_dir).with_context(|| format!("open PIB at {}", pib_dir.display()))?;

    let out = init_hub_in_pib(&pib, &namespace, &device, force)?;
    let hub = &out.hub;
    // The daemon may run from another directory: print an absolute path.
    let pib_abs = std::fs::canonicalize(&pib_dir).unwrap_or_else(|_| pib_dir.clone());
    let anchor_fp = hex_lower(&anchor_fingerprint(&hub.anchor));

    println!("# ndn-fwd hub initialized");
    println!("namespace      = {namespace}");
    println!("pib            = {}", pib_dir.display());
    println!("anchor_key     = {}", hub.anchor_key);
    println!("anchor_fp      = {anchor_fp}");
    println!("ca_key         = {}", out.ca_key);
    println!("ca_cert        = {}", out.ca_cert_path.display());
    println!("device         = {} (admin)", out.device_identity);
    println!("device_key     = {}", out.device_key);
    println!("device_cert    = {} (issued by the CA)", out.device_cert_path.display());
    println!(
        "context        = {} (v{})",
        out.context_path.display(),
        hub.context.version()
    );
    println!("schema         = generated personal-network schema (see `ndn-fwd schema show`)");
    println!("enrollment     = token AND device-approval");
    println!("anchor_uri     = {}", hub.envelope.to_uri());
    println!(
        "anchor_url     = {}",
        hub.envelope.to_https_url("ndn.local")
    );
    // The same link without the context: a short QR, fetched over the network.
    let fingerprint_only = TrustEnvelope::Anchor {
        namespace: Some(namespace.to_string()),
        fingerprint: Some(anchor_fingerprint(&hub.anchor)),
        version: Some(hub.context.version()),
        context_data: None,
        context_content: None,
    };
    println!("anchor_uri_fp  = {}", fingerprint_only.to_uri());
    println!();
    println!("# Scan anchor_uri as a QR, or share anchor_url. anchor_uri_fp is the short");
    println!("# form (namespace + expected fingerprint + version): the adopting device's");
    println!("# daemon fetches the context by name, so it needs a route to this node.");
    println!("# Adopting lets a peer VERIFY this namespace; producing still needs enrollment as");
    println!("# {namespace}/<role>/<device>: members and guests by invite token");
    println!(
        "# (ndn-fwd-tokens new --ca {namespace} --namespace {namespace} --anchor-fp {anchor_fp}"
    );
    println!("#  --role member|guest), admins and super nodes by device approval.");
    println!("# The root key now lives in the PIB: keep a recovery copy offline.");
    println!("#");
    println!("# Put these lines in ndn-fwd.toml so the daemon signs as this device's");
    println!("# admin identity (certified by the CA) instead of an ephemeral key:");
    println!("[security]");
    println!(
        "identity = {}",
        toml_basic_string(&out.device_identity.to_string())
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

/// How long the CLI waits for the daemon to adopt (it may fetch the context
/// over the network: two Interests of at most ~4.5 s each).
const DAEMON_ADOPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// The daemon's management socket: `[management] face_socket` from
/// `-c/--config`, else the default.
fn face_socket(args: &[String]) -> Result<String> {
    let cfg = match flag(args, &["-c", "--config"]) {
        Some(path) => {
            let toml =
                std::fs::read_to_string(path).with_context(|| format!("read config {path}"))?;
            toml.parse::<ForwarderConfig>()
                .with_context(|| format!("parse config {path}"))?
        }
        None => ForwarderConfig::default(),
    };
    Ok(cfg.management.face_socket)
}

async fn run_adopt(args: &[String]) -> Result<()> {
    // The link is the first argument that is neither a flag nor a flag's value.
    let uri = *positionals(args)
        .first()
        .context("adopt requires an <anchor link> (an ndn-trust://anchor URI or its https mirror)")?;
    // Read it here first so a malformed link is reported without a daemon.
    let link = AnchorLink::from_uri(uri).map_err(|e| anyhow::anyhow!("adopt refused: {e}"))?;
    let socket = face_socket(args)?;

    match ndn_ipc::MgmtClient::connect(&socket).await {
        Ok(client) => adopt_via_daemon(&client, uri, &socket).await,
        Err(e) if link.context_data.is_some() => adopt_offline(args, uri, &socket, &e),
        Err(e) => bail!(
            "adopt refused: the daemon is not reachable at {socket} ({e}). This link carries \
             only the expected fingerprint, so the network's context has to be fetched, which \
             needs the running daemon with a route toward the network: start ndn-fwd (with \
             `-c <config>` if it uses another socket) and retry, or ask for an anchor link with \
             the context inline (`ndn-fwd init` prints one as anchor_uri)"
        ),
    }
}

async fn adopt_via_daemon(client: &ndn_ipc::MgmtClient, uri: &str, socket: &str) -> Result<()> {
    let resp = client
        .security_context_adopt(uri, DAEMON_ADOPT_TIMEOUT)
        .await
        .with_context(|| format!("ask the daemon at {socket} to adopt"))?;
    if !resp.is_ok() {
        bail!("adopt refused by the daemon ({}): {}", resp.status_code, resp.status_text);
    }
    let info: ndn_mgmt::AdoptedContextInfo = serde_json::from_str(&resp.status_text)
        .with_context(|| format!("unreadable answer from the daemon: {}", resp.status_text))?;
    println!("# ndn-fwd adopt (by the running daemon at {socket})");
    println!("namespace            = {}", info.namespace);
    println!("version              = {}", info.version);
    println!("expected_fingerprint = {}", info.expected_fingerprint);
    println!(
        "source               = {}",
        if info.fetched {
            "fetched from the network"
        } else {
            "inline in the link"
        }
    );
    println!("anchors              = {}", info.anchors);
    println!("ca_endpoints         = {}", info.ca_endpoints);
    println!("stored               = {}", info.stored);
    println!("published            = {}", info.published);
    println!();
    println!("# Signed by the anchor with the expected fingerprint. The daemon trusts it");
    println!("# now and loads it again at every start; producing still needs enrollment.");
    Ok(())
}

fn adopt_offline(
    args: &[String],
    uri: &str,
    socket: &str,
    unreachable: &ndn_ipc::ForwarderError,
) -> Result<()> {
    let envelope =
        TrustEnvelope::from_uri(uri).map_err(|e| anyhow::anyhow!("parse trust link: {e}"))?;
    let pib_dir = pib_dir(args)?;
    let (ctx, path) = adopt_envelope_into_store(&pib_dir, &envelope)
        .map_err(|e| anyhow::anyhow!("adopt refused: {e}"))?;
    let expected_fingerprint = match &envelope {
        TrustEnvelope::Anchor {
            fingerprint: Some(fp),
            ..
        } => hex_lower(fp),
        _ => String::new(),
    };

    println!("# ndn-fwd adopt (offline: no daemon at {socket}: {unreachable})");
    println!("namespace            = {}", ctx.namespace());
    println!("version              = {}", ctx.version());
    println!("expected_fingerprint = {expected_fingerprint}");
    println!("source               = inline in the link");
    println!("anchors              = {}", ctx.anchors().len());
    println!("ca_endpoints         = {}", ctx.ca_endpoints().len());
    println!("stored               = {}", path.display());
    println!();
    println!("# Signed by the anchor with the expected fingerprint. The daemon loads this");
    println!("# context at its next start (same pib_path); producing still needs enrollment.");
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every flag form, short or long, before or after the positionals, is
    /// skipped together with its value.
    #[test]
    fn positionals_skip_flags_and_their_values() {
        let args: Vec<String> = ["/d", "-c", "x.toml", "/k", "--pib", "p", "--force"]
            .map(String::from)
            .to_vec();
        assert_eq!(positionals(&args), ["/d", "/k"]);
        let args: Vec<String> = ["--config", "x.toml", "/d", "/k"].map(String::from).to_vec();
        assert_eq!(positionals(&args), ["/d", "/k"]);
    }
}
