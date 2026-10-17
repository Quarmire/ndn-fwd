//! `ndn-fwd init --namespace <ns>`, `ndn-fwd adopt <envelope>`, `ndn-fwd
//! enroll <invite>`, `ndn-fwd renew`, `ndn-fwd revoke <name>` and `ndn-fwd
//! context refresh` —
//! the onboarding UX over the [`ndn_cert::namespace`] /
//! [`ndn_cert::onboarding`] / [`ndn_cert::invite`] /
//! [`ndn_cert::context_update`] primitives. A node does not "join" anything:
//! it *adopts* a namespace's trust context and *enrolls* a key with the
//! namespace's CA. Neither forms a link; links and routes toward other
//! forwarders are configured separately.
//!
//! These are early-exit subcommands: when `args[1]` is `init`, `adopt`,
//! `enroll`, `renew`, `revoke`, `context` or `schema` ([`crate::schema_cmd`]), the
//! daemon does not start. They act on the node's PIB directory (`--pib
//! <dir>`, else `[security].pib_path` from `-c/--config`, else
//! `~/.ndn/pib`) or ask the running daemon:
//!
//! - `init` (run on the root device) mints the namespace root `<ns>/KEY/root`
//!   into a root store (`--root-store`: the OS keychain by default, a
//!   passphrase-sealed file, a YubiKey, or plaintext `file`; see
//!   [`crate::root_key`]), the CA signing identity `<ns>/CA` (certified by
//!   the root) and this primary device's admin
//!   identity `<ns>/admin/<device>` (`--device`, default derived from the
//!   host name; certified by the CA) into the PIB, signs the trust context —
//!   carrying the generated namespace schema — with the root, stores
//!   it in `<pib>/contexts/`, and prints the `ndn-trust://anchor` envelope
//!   plus the `[security]` lines that make the daemon load the device
//!   identity. Config files are never edited. An existing root is never
//!   replaced unless `--force` is given.
//! - `adopt` adopts the namespace an anchor link (`ndn-trust://anchor/…`)
//!   names. With the daemon running (its management socket from `-c`, else
//!   the default), the daemon does it: a link with the context inline is
//!   verified against the expected fingerprint; a fingerprint-only link makes
//!   the daemon fetch the context by name over its routes. Either way the
//!   daemon trusts, stores and publishes it at once. With no daemon, a link
//!   with the context inline is verified and stored in `<pib>/contexts/`,
//!   loaded at the next start; a fingerprint-only link needs the daemon.
//! - `enroll` asks the running daemon to enroll with the CA an invite link
//!   (`ndn-trust://invite/…`) names, as `<ns>/<role>/<device>` (`--device`,
//!   default derived from the host name): the daemon generates the key in its
//!   PIB, adopts the namespace's trust context if it holds none, redeems the
//!   token and makes the certified identity the PIB's default (see
//!   [`crate::enroll`]). There is no offline form: the key belongs to the
//!   daemon and the CA is reached through it.
//! - `renew` asks the running daemon to renew, now, every certificate the
//!   namespace CA issued to its keys — the same key, re-certified on proof
//!   of the current certificate, no invite (see [`crate::renewal`]).
//! - `revoke` (run on the root device) asks the running daemon to revoke a
//!   device identity, key or certificate at its CA and in a new, root-signed
//!   version of the namespace's trust context (see [`crate::revoke`]),
//!   sending the root store's passphrase or PIN when it needs one.
//! - `context refresh [<ns>]` asks the running daemon to check its held trust
//!   contexts for a newer version now (see [`crate::context_refresh`]).
//! - `root-key status|move` shows or moves where the root key lives
//!   ([`crate::root_key`]).
//! - `recovery-kit create|list|check|revoke` manages the recovery kits of
//!   the namespace ([`crate::recovery_kit`]); `recover` makes a replacement
//!   device the root device with one ([`crate::recover`]).

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use ndn_cert::roles::sanitize_device_name;
use ndn_cert::{
    AnchorLink, InviteLink, adopt_envelope_into_store, anchor_fingerprint, init_namespace_in_pib,
};
use ndn_config::ForwarderConfig;
use ndn_packet::Name;
use ndn_security::FilePib;
use ndn_trust_envelope::TrustEnvelope;

/// Inspect `argv`; if it names an onboarding subcommand, run it and return
/// `Some(result)`. Returns `None` for the normal daemon path.
pub async fn maybe_run() -> Option<Result<()>> {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str)?;
    if let Some((name, spec)) = arg_spec(command, &args[2..])
        && let Err(e) = check_args(&name, &args[2..], spec)
    {
        return Some(Err(e));
    }
    match command {
        "init" => Some(run_init(&args[2..]).await),
        "adopt" => Some(run_adopt(&args[2..]).await),
        "enroll" => Some(run_enroll(&args[2..]).await),
        "revoke" => Some(run_revoke(&args[2..]).await),
        "renew" => Some(run_renew(&args[2..]).await),
        "context" => Some(run_context(&args[2..]).await),
        "schema" => Some(crate::schema_cmd::run(&args[2..])),
        "root-key" => Some(crate::root_key::run(&args[2..]).await),
        "recovery-kit" => Some(crate::recovery_kit::run(&args[2..]).await),
        "recover" => Some(crate::recover::run(&args[2..]).await),
        _ => None,
    }
}

/// Options that take a value (so their value is not mistaken for a
/// positional): every value flag of [`ARG_SPECS`].
pub(crate) const VALUE_FLAGS: &[&str] = &[
    "--namespace",
    "--device",
    "--pib",
    "-c",
    "--config",
    "--root-store",
    "--passphrase-file",
    "--pin-file",
    "--yubikey-slot",
    "--yubikey-serial",
    "--touch-policy",
    "--to",
    "--format",
    "--out",
    "--kit",
    "--old-root",
    "--kit-passphrase-file",
    "--kit-pin-file",
    "--words-file",
    "--kit-yubikey-serial",
    "--kit-yubikey-slot",
    "--kit-touch-policy",
    "--keep-kit",
];

/// The arguments one onboarding subcommand takes.
struct ArgSpec {
    /// Flags followed by a value (`--pib <dir>`).
    values: &'static [&'static str],
    /// Those of `values` that may be given more than once.
    repeatable: &'static [&'static str],
    /// Flags without a value (`--force`).
    switches: &'static [&'static str],
    /// The most positional arguments; a subcommand word (`refresh`,
    /// `create`) counts.
    positionals: usize,
}

/// Per subcommand (and its subcommand word, if it has them): the arguments
/// it takes. Anything else is refused before it runs, so no argument is
/// silently ignored.
const ARG_SPECS: &[(&str, Option<&str>, ArgSpec)] = &[
    ("init", None, ArgSpec {
        values: &[
            "--namespace", "--device", "--pib", "-c", "--config", "--root-store",
            "--passphrase-file", "--pin-file", "--yubikey-slot", "--yubikey-serial",
            "--touch-policy",
        ],
        repeatable: &[],
        switches: &["--force", "--replace-slot"],
        positionals: 0,
    }),
    ("adopt", None, ArgSpec {
        values: &["--pib", "-c", "--config"],
        repeatable: &[],
        switches: &[],
        positionals: 1,
    }),
    ("enroll", None, ArgSpec {
        values: &["--device", "-c", "--config"],
        repeatable: &[],
        switches: &["--force"],
        positionals: 1,
    }),
    ("revoke", None, ArgSpec {
        values: &["-c", "--config", "--passphrase-file", "--pin-file"],
        repeatable: &[],
        switches: &[],
        positionals: 1,
    }),
    ("renew", None, ArgSpec {
        values: &["-c", "--config"],
        repeatable: &[],
        switches: &[],
        positionals: 0,
    }),
    ("context", Some("refresh"), ArgSpec {
        values: &["-c", "--config"],
        repeatable: &[],
        switches: &[],
        positionals: 2,
    }),
    ("schema", Some("show"), ArgSpec {
        values: &["--namespace", "--pib", "-c", "--config"],
        repeatable: &[],
        switches: &[],
        positionals: 1,
    }),
    ("schema", Some("explain"), ArgSpec {
        values: &["--namespace", "--pib", "-c", "--config"],
        repeatable: &[],
        switches: &[],
        positionals: 3,
    }),
    ("root-key", Some("status"), ArgSpec {
        values: &["--pib", "-c", "--config"],
        repeatable: &[],
        switches: &[],
        positionals: 1,
    }),
    ("root-key", Some("move"), ArgSpec {
        values: &["--to", "--passphrase-file", "--pin-file", "--pib", "-c", "--config"],
        repeatable: &[],
        switches: &[],
        positionals: 1,
    }),
    ("recovery-kit", Some("create"), ArgSpec {
        values: &[
            "--format", "--out", "--pib", "-c", "--config", "--passphrase-file", "--pin-file",
            "--kit-passphrase-file", "--kit-pin-file", "--kit-yubikey-serial",
            "--kit-yubikey-slot", "--kit-touch-policy",
        ],
        repeatable: &[],
        switches: &["--replace-slot"],
        positionals: 1,
    }),
    ("recovery-kit", Some("list"), ArgSpec {
        values: &["--namespace", "--pib", "-c", "--config"],
        repeatable: &[],
        switches: &[],
        positionals: 1,
    }),
    ("recovery-kit", Some("check"), ArgSpec {
        values: &[
            "--namespace", "--pib", "-c", "--config", "--kit-passphrase-file", "--kit-pin-file",
            "--words-file", "--kit-yubikey-serial", "--kit-yubikey-slot",
        ],
        repeatable: &[],
        switches: &[],
        positionals: 2,
    }),
    ("recovery-kit", Some("revoke"), ArgSpec {
        values: &["--pib", "-c", "--config", "--passphrase-file", "--pin-file"],
        repeatable: &[],
        switches: &[],
        positionals: 2,
    }),
    ("recover", None, ArgSpec {
        values: &[
            "--old-root", "--kit", "--namespace", "--device", "--pib", "-c", "--config",
            "--kit-passphrase-file", "--kit-pin-file", "--words-file", "--kit-yubikey-serial",
            "--kit-yubikey-slot", "--root-store", "--passphrase-file", "--pin-file",
            "--yubikey-slot", "--yubikey-serial", "--touch-policy", "--keep-kit",
        ],
        repeatable: &["--keep-kit"],
        switches: &["--from-held", "--replace-slot"],
        positionals: 0,
    }),
];

/// The spec of `ndn-fwd <command> <rest…>` and its name for refusals
/// (`recovery-kit create`). `None`: not an onboarding subcommand, or a
/// subcommand word it does not have (the subcommand refuses that itself,
/// with its usage).
fn arg_spec(command: &str, rest: &[String]) -> Option<(String, &'static ArgSpec)> {
    let word = positionals(rest).first().copied();
    ARG_SPECS.iter().find_map(|(cmd, sub, spec)| match sub {
        _ if *cmd != command => None,
        None => Some((command.to_string(), spec)),
        Some(sub) if word == Some(*sub) => Some((format!("{command} {sub}"), spec)),
        Some(_) => None,
    })
}

/// Refuse an argument `ndn-fwd <command>` does not take — an unknown flag,
/// `--flag=value`, a value flag without its value (or followed by another
/// flag), a value flag given twice, a surplus positional — instead of
/// ignoring it.
fn check_args(command: &str, args: &[String], spec: &ArgSpec) -> Result<()> {
    let refuse = |what: String| anyhow::anyhow!("{what} for `ndn-fwd {command}`; see `ndn-fwd --help`");
    let mut given: Vec<&str> = Vec::new();
    let mut positionals = 0;
    let mut rest = args.iter().map(String::as_str);
    while let Some(arg) = rest.next() {
        if !arg.starts_with('-') {
            positionals += 1;
            if positionals > spec.positionals {
                return Err(refuse(format!("unexpected argument {arg:?}")));
            }
            continue;
        }
        if let Some((name, value)) = arg.split_once('=')
            && (spec.values.contains(&name) || spec.switches.contains(&name))
        {
            return Err(refuse(format!(
                "unrecognized argument {arg:?} (write `{name} {value}`, with a space)"
            )));
        }
        if spec.switches.contains(&arg) {
            continue;
        }
        if !spec.values.contains(&arg) {
            return Err(refuse(format!("unrecognized argument {arg:?}")));
        }
        match rest.next() {
            Some(value) if !value.starts_with('-') => {}
            Some(other) => return Err(refuse(format!("{arg} needs a value, not {other:?},"))),
            None => return Err(refuse(format!("{arg} needs a value"))),
        }
        // `-c` and `--config` are one flag.
        let flag = if arg == "--config" { "-c" } else { arg };
        if given.contains(&flag) && !spec.repeatable.contains(&arg) {
            return Err(refuse(format!("{arg} is given more than once")));
        }
        given.push(flag);
    }
    Ok(())
}

pub(crate) fn flag<'a>(args: &'a [String], names: &[&str]) -> Option<&'a str> {
    args.iter()
        .position(|a| names.contains(&a.as_str()))
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// Every value of a repeatable value flag `name`, in order.
pub(crate) fn flag_values<'a>(args: &'a [String], name: &str) -> Vec<&'a str> {
    args.windows(2)
        .filter(|pair| pair[0] == name)
        .map(|pair| pair[1].as_str())
        .collect()
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

/// The default `--device`: the host name, sanitized into a device name.
pub(crate) fn default_device() -> Result<String> {
    let host = host_name().unwrap_or_default();
    sanitize_device_name(&host).with_context(|| {
        format!(
            "cannot derive a device name from the host name {host:?}; pass --device <name> \
             (letters, digits, '-', '_', '.')"
        )
    })
}

async fn run_init(args: &[String]) -> Result<()> {
    let namespace: Name = flag(args, &["--namespace"])
        .context("init requires --namespace <ndn-name>, e.g. /home/bob")?
        .parse()
        .context("invalid --namespace NDN name")?;
    let device = match flag(args, &["--device"]) {
        Some(device) => device.to_string(),
        None => default_device()?,
    };
    let force = args.iter().any(|a| a == "--force");
    let pib_dir = pib_dir(args)?;
    // Where the root goes, and its passphrase / PIN — asked now, never
    // taken from the command line.
    let root = crate::root_key::new_root_store(args)?;
    let pib =
        FilePib::new(&pib_dir).with_context(|| format!("open PIB at {}", pib_dir.display()))?;

    let out = init_namespace_in_pib(&pib, &namespace, &device, force, &root).await?;
    drop(root);
    let root_dev = &out.init;
    // The daemon may run from another directory: print an absolute path.
    let pib_abs = std::fs::canonicalize(&pib_dir).unwrap_or_else(|_| pib_dir.clone());
    let anchor_fp = hex_lower(&anchor_fingerprint(&root_dev.anchor));

    println!("# ndn-fwd namespace initialized on this root device");
    println!("namespace      = {namespace}");
    println!("pib            = {}", pib_dir.display());
    println!("anchor_key     = {}", root_dev.anchor_key);
    println!("anchor_fp      = {anchor_fp}");
    println!("ca_key         = {}", out.ca_key);
    println!("ca_cert        = {}", out.ca_cert_path.display());
    println!("device         = {} (admin)", out.device_identity);
    println!("device_key     = {}", out.device_key);
    println!("device_cert    = {} (issued by the CA)", out.device_cert_path.display());
    let root_lines = crate::root_key::describe_new_root(&out.root_store, &pib_dir);
    println!("{}", root_lines[0]);
    println!(
        "context        = {} (v{})",
        out.context_path.display(),
        root_dev.context.version()
    );
    println!("schema         = generated namespace schema (see `ndn-fwd schema show`)");
    println!("enrollment     = token AND device-approval");
    println!("anchor_uri     = {}", root_dev.envelope.to_uri());
    println!(
        "anchor_url     = {}",
        root_dev.envelope.to_https_url("ndn.local")
    );
    // The same link without the context: a short QR; the context is fetched by name.
    let fingerprint_only = TrustEnvelope::Anchor {
        namespace: Some(namespace.to_string()),
        fingerprint: Some(anchor_fingerprint(&root_dev.anchor)),
        version: Some(root_dev.context.version()),
        context_data: None,
        context_content: None,
    };
    println!("anchor_uri_fp  = {}", fingerprint_only.to_uri());
    println!();
    println!("# Scan anchor_uri as a QR, or share anchor_url. anchor_uri_fp is the short");
    println!("# form (namespace + expected fingerprint + version): the adopting device's");
    println!("# daemon fetches the context by name, so it needs a link and a route to this node.");
    println!("# Adopting lets a peer VERIFY this namespace; producing still needs enrollment as");
    println!("# {namespace}/<role>/<device>: members and guests by invite token");
    println!(
        "# (ndn-fwd-tokens new --ca {namespace} --namespace {namespace} --anchor-fp {anchor_fp}"
    );
    println!("#  --role member|guest), admins and relays by device approval.");
    for line in &root_lines[1..] {
        println!("{line}");
    }
    println!("#");
    println!("# Losing this device would lose the namespace: create a recovery kit now (a");
    println!("# separate recovery key the namespace trusts, kept offline), e.g.");
    println!(
        "#   ndn-fwd recovery-kit create --format words --pib {}",
        pib_abs.display()
    );
    println!("# (--format file --out <path> for a passphrase-sealed file, --format yubikey for a");
    println!("# second YubiKey; several kits may coexist).");
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
pub(crate) fn face_socket(args: &[String]) -> Result<String> {
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
             only the expected fingerprint, so the namespace's trust context has to be fetched, \
             which needs the running daemon with a route toward a forwarder serving {}: start \
             ndn-fwd (with `-c <config>` if it uses another socket) and retry, or ask for an \
             anchor link with the context inline (`ndn-fwd init` prints one as anchor_uri)",
            link.namespace
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
            "fetched by name"
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

/// How long the CLI waits for the daemon to enroll: the longest the daemon's
/// enrollment can take (every exchange timing out), plus a margin for the
/// key generation and storing.
fn daemon_enroll_timeout() -> std::time::Duration {
    ndn_identity::enroll_via_engine_budget() + std::time::Duration::from_secs(5)
}

async fn run_enroll(args: &[String]) -> Result<()> {
    let uri = *positionals(args).first().context(
        "enroll requires an <invite link> (an ndn-trust://invite URI or its https mirror, as \
         `ndn-fwd-tokens new` prints it)",
    )?;
    // Read it here first so a malformed invite is reported without a daemon.
    let invite = InviteLink::from_uri(uri).map_err(|e| anyhow::anyhow!("enroll refused: {e}"))?;
    let device = match flag(args, &["--device"]) {
        Some(device) => device.to_string(),
        None => default_device()?,
    };
    let identity = invite
        .device_identity(&device)
        .map_err(|e| anyhow::anyhow!("enroll refused: {e}"))?;
    let force = args.iter().any(|a| a == "--force");
    let socket = face_socket(args)?;
    let client = ndn_ipc::MgmtClient::connect(&socket).await.map_err(|e| {
        anyhow::anyhow!(
            "enroll refused: the daemon is not reachable at {socket} ({e}). The running daemon \
             enrolls: it generates the key in its own PIB and reaches the CA through its faces. \
             Start ndn-fwd (with `-c <config>` if it uses another socket), give it a face and a \
             route for {} toward a forwarder that serves it, and retry",
            invite.namespace
        )
    })?;
    let wait = daemon_enroll_timeout();
    let resp = match client.security_enroll(uri, &identity, force, wait).await {
        Ok(resp) => resp,
        Err(ndn_ipc::ForwarderError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut => bail!(
            "no answer from the daemon at {socket} within {}s. It may still complete the \
             enrollment: check `ndn-ctl status` (signing: identity=…) or the daemon's log \
             before retrying — once it holds a certificate in {}, enrolling again is refused \
             as already enrolled",
            wait.as_secs(),
            invite.namespace
        ),
        Err(e) => {
            return Err(e).with_context(|| format!("ask the daemon at {socket} to enroll"));
        }
    };
    if !resp.is_ok() {
        bail!("enroll refused by the daemon ({}): {}", resp.status_code, resp.status_text);
    }
    let outcome: ndn_mgmt::EnrollOutcome = serde_json::from_str(&resp.status_text)
        .with_context(|| format!("unreadable answer from the daemon: {}", resp.status_text))?;
    let ndn_mgmt::EnrollOutcome::Enrolled(info) = outcome;
    println!("# ndn-fwd enroll (by the running daemon at {socket})");
    match &info.adopted_context {
        Some(ctx) => {
            println!(
                "trust_context    = adopted {} v{} ({}; root fingerprint {} as the invite \
                 expects)",
                ctx.namespace,
                ctx.version,
                if ctx.fetched {
                    "fetched by name"
                } else {
                    "inline"
                },
                ctx.expected_fingerprint
            );
            println!("context_stored   = {}", ctx.stored);
        }
        None => println!(
            "trust_context    = {} (already held; signed by the root the invite expects)",
            invite.namespace
        ),
    }
    println!("identity         = {}", info.identity);
    println!("key              = {} (generated in the daemon's PIB)", info.key);
    println!("certificate      = {}", info.certificate);
    println!(
        "issued_by        = {} (chain checked to the root of {} under its schema)",
        info.issuer, invite.namespace
    );
    println!(
        "valid_until      = {} ({}, as the CA's policy decides)",
        info.valid_until,
        days(info.validity_secs)
    );
    println!("pib              = {}", info.pib);
    println!(
        "default_identity = {} (was: {})",
        info.identity,
        info.previous_identity.as_deref().unwrap_or("none")
    );
    println!("signing_now      = {}", info.signing_now);
    println!();
    if info.signing_now {
        println!("# The daemon signs its management responses and discovery records with this");
        println!("# key now, and loads this identity at every start (the PIB's default");
        println!("# identity; [security] identity in the config would take precedence).");
    }
    println!("# The daemon renews this certificate for the same key before it expires");
    println!("# ([security] renew_before) if the CA renews the role; `ndn-fwd renew` renews now.");
    for note in &info.at_next_start {
        println!("# At the next start: {note}");
    }
    for old in &info.still_valid {
        println!("# Also held, still valid: {old}");
    }
    for dead in &info.unusable {
        println!(
            "# Unusable: {dead}; the trust context revokes its chain, so it validates nowhere \
             (the key enrolled now takes its place)"
        );
    }
    Ok(())
}

/// The running daemon's management client, or why it is needed.
pub(crate) async fn daemon(args: &[String], what: &str) -> Result<(ndn_ipc::MgmtClient, String)> {
    let socket = face_socket(args)?;
    let client = ndn_ipc::MgmtClient::connect(&socket).await.map_err(|e| {
        anyhow::anyhow!(
            "{what} refused: the daemon is not reachable at {socket} ({e}). The running daemon \
             does it; start ndn-fwd (with `-c <config>` if it uses another socket) and retry"
        )
    })?;
    Ok((client, socket))
}

/// How long the CLI waits for the daemon to revoke (local work only: the
/// CA store, the PIB, the context store — and, for a YubiKey root, the
/// operator's touch).
const DAEMON_REVOKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

async fn run_revoke(args: &[String]) -> Result<()> {
    let target = *positionals(args).first().context(
        "revoke requires a device identity (/<ns>/<role>/<device>), a key name \
         (<identity>/KEY/<id>) or a certificate name",
    )?;
    let name: Name = target
        .parse()
        .map_err(|e| anyhow::anyhow!("revoke refused: {target:?} is not an NDN name: {e}"))?;
    let (client, socket) = daemon(args, "revoke").await?;
    // A sealed or hardware root is unlocked for this one signature: its
    // passphrase / PIN is asked here and travels with the command over the
    // local management socket.
    let unlock = match crate::root_key::daemon_root_unlock(&client).await {
        Some(kind) => crate::root_key::operator_secret(
            args,
            kind,
            &format!("Revoking {name} signs a new trust context version"),
            false,
        )?,
        None => None,
    };
    let resp = client
        .security_revoke(
            &name,
            unlock.map(|s| ndn_mgmt_wire::UnlockSecret::new(s.expose().to_vec())),
            DAEMON_REVOKE_TIMEOUT,
        )
        .await
        .with_context(|| format!("ask the daemon at {socket} to revoke"))?;
    if !resp.is_ok() {
        bail!("revoke refused by the daemon ({}): {}", resp.status_code, resp.status_text);
    }
    let info: ndn_mgmt::RevokedInfo = serde_json::from_str(&resp.status_text)
        .with_context(|| format!("unreadable answer from the daemon: {}", resp.status_text))?;
    println!("# ndn-fwd revoke (by the running daemon at {socket})");
    println!("namespace        = {}", info.namespace);
    for key in &info.keys {
        println!("revoked_key      = {key}");
    }
    for cert in &info.ca_revoked {
        println!("ca_revoked       = {cert} (no longer served by the CA)");
    }
    if let Some(e) = &info.ca_not_persisted {
        println!("ca_not_persisted = {e} (holds until the CA restarts)");
    }
    if info.version > info.previous_version {
        println!(
            "trust_context    = v{} -> v{} (signed by the root, stored and {})",
            info.previous_version,
            info.version,
            if info.published {
                "published"
            } else {
                "not published: [security] serve_contexts = false"
            }
        );
        if let Some(stored) = &info.stored {
            println!("stored           = {stored}");
        }
    } else {
        println!(
            "trust_context    = v{} (already revokes every key named; no new version)",
            info.version
        );
    }
    println!();
    println!("# This node and its CA refuse the key now. Every other node refuses it once it");
    println!("# holds v{}: it fetches it at its next refresh ([security]", info.version);
    println!("# context_refresh_secs, default 300 s), or at once with `ndn-fwd context refresh`.");
    println!("# The device name is free to enroll again with a new key.");
    Ok(())
}

/// How long the CLI waits for the daemon to renew: one renewal's exchanges
/// for each of the (few) certificates it holds.
fn daemon_renew_timeout() -> std::time::Duration {
    ndn_identity::renew_via_engine_budget() * 2 + std::time::Duration::from_secs(5)
}

async fn run_renew(args: &[String]) -> Result<()> {
    let (client, socket) = daemon(args, "renew").await?;
    let wait = daemon_renew_timeout();
    let resp = match client.security_renew(wait).await {
        Ok(resp) => resp,
        Err(ndn_ipc::ForwarderError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut => bail!(
            "no answer from the daemon at {socket} within {}s; it may still complete the \
             renewal: check `ndn-ctl status` (signing: … valid_until=…) or the daemon's log",
            wait.as_secs()
        ),
        Err(e) => return Err(e).with_context(|| format!("ask the daemon at {socket} to renew")),
    };
    if !resp.is_ok() {
        bail!("renew refused by the daemon ({}): {}", resp.status_code, resp.status_text);
    }
    let results: Vec<ndn_mgmt::RenewalInfo> = serde_json::from_str(&resp.status_text)
        .with_context(|| format!("unreadable answer from the daemon: {}", resp.status_text))?;
    println!("# ndn-fwd renew (by the running daemon at {socket})");
    let mut not_renewed = false;
    for r in &results {
        println!("key              = {}", r.key);
        println!("previous         = {} (valid until {})", r.previous, r.previous_valid_until);
        match r.state {
            ndn_mgmt::RenewalState::Renewed => {
                println!(
                    "certificate      = {} (same key; stored, served, signing with it)",
                    r.certificate.as_deref().unwrap_or("?")
                );
                println!(
                    "valid_until      = {} ({}, as the CA's policy for the role decides)",
                    r.valid_until.as_deref().unwrap_or("?"),
                    days(r.validity_secs.unwrap_or(0))
                );
            }
            ndn_mgmt::RenewalState::Refused => {
                not_renewed = true;
                println!("refused          = {}", r.detail);
            }
            ndn_mgmt::RenewalState::Failed => {
                not_renewed = true;
                println!("failed           = {}", r.detail);
            }
        }
        println!();
    }
    if not_renewed {
        bail!(
            "a certificate was not renewed (see above); it keeps working until it expires. A \
             failed renewal can be retried (the daemon also retries on its own); a refused one \
             needs what the reason says — for an expired certificate, a revoked key or a role \
             that does not renew, a new invite"
        );
    }
    Ok(())
}

/// How long the CLI waits for a refresh: per namespace two fetches of at most
/// the app timeout each, for a handful of namespaces — or the versions a
/// catch-up walk follows, each answered at once by a node that holds it (or
/// Nacked by one that serves the namespace without it).
const DAEMON_REFRESH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

async fn run_context(args: &[String]) -> Result<()> {
    let positional = positionals(args);
    match positional.first().copied() {
        Some("refresh") => {}
        other => bail!(
            "unknown `ndn-fwd context` command {other:?}; usage: ndn-fwd context refresh \
             [<namespace>] [-c <config>]"
        ),
    }
    let namespace = positional
        .get(1)
        .map(|ns| {
            ns.parse::<Name>()
                .map_err(|e| anyhow::anyhow!("{ns:?} is not an NDN name: {e}"))
        })
        .transpose()?;
    let (client, socket) = daemon(args, "context refresh").await?;
    let resp = client
        .security_context_refresh(namespace.as_ref(), DAEMON_REFRESH_TIMEOUT)
        .await
        .with_context(|| format!("ask the daemon at {socket} to refresh"))?;
    if !resp.is_ok() {
        bail!(
            "context refresh refused by the daemon ({}): {}",
            resp.status_code,
            resp.status_text
        );
    }
    let results: Vec<ndn_mgmt::ContextRefreshInfo> = serde_json::from_str(&resp.status_text)
        .with_context(|| format!("unreadable answer from the daemon: {}", resp.status_text))?;
    println!("# ndn-fwd context refresh (by the running daemon at {socket})");
    if results.is_empty() {
        println!("# this node holds no trust context");
    }
    let mut failed = false;
    for r in &results {
        let state = match r.state {
            ndn_mgmt::RefreshState::Updated => "updated",
            ndn_mgmt::RefreshState::Current => "current",
            ndn_mgmt::RefreshState::UpstreamOlder => "upstream-older",
            ndn_mgmt::RefreshState::Source => "source",
            ndn_mgmt::RefreshState::Unreachable => {
                failed = true;
                "unreachable"
            }
            ndn_mgmt::RefreshState::Failed => {
                failed = true;
                "failed"
            }
        };
        println!("{} v{} -> v{}: {state}", r.namespace, r.held_version, r.version);
        for revoked in &r.revoked {
            println!("  revoked {revoked}");
        }
        println!("  {}", r.detail);
    }
    if failed {
        bail!("a refresh failed or was refused (see above); the held versions stay in force");
    }
    Ok(())
}

/// A lifetime in days, for display (whole days when within a minute of one:
/// certificate validity periods are stored to the second).
fn days(secs: u64) -> String {
    let whole = (secs + 60) / 86_400;
    if secs.abs_diff(whole * 86_400) <= 60 {
        format!("{whole} days")
    } else {
        format!("{:.1} days", secs as f64 / 86_400.0)
    }
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

    fn check(argv: &[&str]) -> Result<()> {
        let argv: Vec<String> = argv.iter().map(|a| a.to_string()).collect();
        let (name, spec) = arg_spec(&argv[0], &argv[1..]).expect("an onboarding subcommand");
        check_args(&name, &argv[1..], spec)
    }

    /// A choice on the command line is used or refused, never silently
    /// dropped: unknown flags, `--flag=value`, a flag taken as another's
    /// value, a flag given twice and surplus positionals are refused.
    #[test]
    fn arguments_a_subcommand_does_not_take_are_refused() {
        check(&["init", "--namespace", "/home/bob", "--root-store", "sealed-file", "--force"])
            .expect("init's own flags");
        check(&["recovery-kit", "check", "words", "--pib", "p", "--words-file", "w"])
            .expect("a subcommand word and its flags");
        check(&["recover", "--old-root", "destroyed", "--kit", "words", "--keep-kit", "/a", "--keep-kit", "/b"])
            .expect("a repeatable flag");
        for refused in [
            &["init", "--namespace", "/home/bob", "--root-store=sealed-file"][..],
            &["init", "--namespace=/home/bob"],
            &["recover", "--old-root", "destroyed", "--kit", "words", "--from-hold"],
            &["revoke", "/a", "/b"],
            &["adopt", "ndn-trust://anchor/x", "--pib", "--force"],
            &["renew", "-c"],
            &["renew", "-c", "a.toml", "--config", "b.toml"],
            &["enroll", "ndn-trust://invite/x", "--yubikey-slot", "9c"],
        ] {
            assert!(check(refused).is_err(), "{refused:?} must be refused");
        }
    }

    /// Every value flag a subcommand takes is skipped with its value when
    /// positionals are read, so a value is never taken for a positional.
    #[test]
    fn every_value_flag_is_known_to_positionals() {
        for (_, _, spec) in ARG_SPECS {
            for flag in spec.values {
                assert!(VALUE_FLAGS.contains(flag), "{flag} is missing from VALUE_FLAGS");
            }
        }
    }
}
