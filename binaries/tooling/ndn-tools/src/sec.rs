//! `ndn-sec` — manage a file-based PIB of Ed25519 / ECDSA-P256 keys and
//! self-signed certificates for `ndn-fwd` and other NDN tools.
//!
//! Beyond key generation, `ndn-sec export` / `ndn-sec import` move whole
//! identities — certificate plus password-encrypted private key — through
//! the ndn-cxx-compatible SafeBag wire (`ndnsec export`/`import` interop)
//! for both supported signature types.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use bytes::Bytes;
use clap::{Parser, Subcommand, ValueEnum};
use ndn_packet::Name;
use ndn_security::{
    cert_cache::Certificate,
    pib::{FilePib, name_to_uri},
    safe_bag::SafeBag,
    spki,
};

/// Signature/key algorithm for a freshly generated identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum KeyType {
    /// Ed25519 (compact, fast; ndn-rs-native — not verifiable by ndn-cxx/NFD).
    Ed25519,
    /// ECDSA P-256 (interops with ndn-cxx / NFD and `ndnsec`).
    Ecdsa,
}

#[derive(Parser)]
#[command(
    name = "ndn-sec",
    about = "NDN key and certificate management",
    version
)]
struct Cli {
    /// Path to the PIB directory.  Defaults to $NDN_PIB or ~/.ndn/pib.
    #[arg(long, global = true, env = "NDN_PIB")]
    pib: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new key pair and self-signed certificate.
    Keygen {
        /// NDN identity name (e.g., /ndn/router1).
        name: String,

        /// Key algorithm: `ed25519` (default) or `ecdsa` (P-256, ndn-cxx-interop).
        #[arg(long, value_enum, default_value_t = KeyType::Ed25519)]
        r#type: KeyType,

        /// Also register the new certificate as a trust anchor in the PIB.
        #[arg(long)]
        anchor: bool,

        /// Certificate validity in days (default: 365).
        #[arg(long, default_value = "365")]
        days: u64,

        /// Skip silently if a key for this identity already exists in the PIB.
        ///
        /// Useful for idempotent NixOS / systemd ExecStartPre invocations:
        /// the key is generated on first boot and ignored on subsequent starts.
        #[arg(long)]
        skip_if_exists: bool,
    },

    /// Display certificate details for a stored key.
    Certdump {
        /// NDN identity name.
        name: String,
    },

    /// List all keys stored in the PIB.
    List,

    /// Delete a key and its certificate from the PIB.
    Delete {
        /// NDN identity name.
        name: String,
    },

    /// Export an identity as a SafeBag (cert + password-encrypted private
    /// key), compatible with `ndnsec import`. Works for both Ed25519 and
    /// ECDSA-P256 keys.
    Export {
        /// NDN identity name (e.g., /ndn/router1).
        name: String,

        /// Output file. Defaults to `<identity-tail>.safebag` in the CWD;
        /// `-` writes to stdout.
        #[arg(short, long)]
        out: Option<String>,

        /// Passphrase to encrypt the private key. Prompted on stdin when
        /// omitted (or piped: `echo pw | ndn-sec export … `).
        #[arg(long)]
        password: Option<String>,

        /// Wire encoding: `base64` (default, `ndnsec`-compatible text) or
        /// `raw` (binary SafeBag TLV).
        #[arg(long, value_enum, default_value_t = WireFormat::Base64)]
        format: WireFormat,
    },

    /// Import a SafeBag (from `ndn-sec export` or `ndnsec export`) into the
    /// PIB. The file may be raw TLV or base64; the key name is taken from
    /// the embedded certificate. Works for both Ed25519 and ECDSA-P256.
    Import {
        /// SafeBag file to import; `-` reads from stdin.
        file: String,

        /// Passphrase that decrypts the SafeBag. Prompted on stdin when
        /// omitted.
        #[arg(long)]
        password: Option<String>,

        /// Also register the imported certificate as a trust anchor.
        #[arg(long)]
        anchor: bool,
    },

    /// Trust anchor sub-commands.
    #[command(subcommand_value_name = "SUBCOMMAND")]
    Anchor {
        #[command(subcommand)]
        subcmd: AnchorCmd,
    },
}

/// On-wire encoding for `ndn-sec export`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum WireFormat {
    /// Base64 text — what `ndnsec export` emits; safe to paste/email.
    Base64,
    /// Raw binary SafeBag TLV.
    Raw,
}

#[derive(Subcommand)]
enum AnchorCmd {
    /// Mark an existing key's certificate as a trust anchor.
    Add {
        /// NDN identity name.
        name: String,
    },
    /// Remove a trust anchor from the PIB.
    Remove {
        /// NDN identity name.
        name: String,
    },
    /// List all trust anchors stored in the PIB.
    List,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let pib_path = resolve_pib_path(cli.pib.as_deref());

    match cli.command {
        Command::Keygen {
            name,
            r#type,
            anchor,
            days,
            skip_if_exists,
        } => {
            cmd_keygen(&pib_path, &name, r#type, anchor, days, skip_if_exists)?;
        }
        Command::Certdump { name } => {
            cmd_certdump(&pib_path, &name)?;
        }
        Command::List => {
            cmd_list(&pib_path)?;
        }
        Command::Delete { name } => {
            cmd_delete(&pib_path, &name)?;
        }
        Command::Export {
            name,
            out,
            password,
            format,
        } => {
            cmd_export(&pib_path, &name, out.as_deref(), password, format)?;
        }
        Command::Import {
            file,
            password,
            anchor,
        } => {
            cmd_import(&pib_path, &file, password, anchor)?;
        }
        Command::Anchor { subcmd } => match subcmd {
            AnchorCmd::Add { name } => cmd_anchor_add(&pib_path, &name)?,
            AnchorCmd::Remove { name } => cmd_anchor_remove(&pib_path, &name)?,
            AnchorCmd::List => cmd_anchor_list(&pib_path)?,
        },
    }

    Ok(())
}

fn cmd_keygen(
    pib_path: &PathBuf,
    name_str: &str,
    key_type: KeyType,
    make_anchor: bool,
    days: u64,
    skip_if_exists: bool,
) -> anyhow::Result<()> {
    use ndn_security::Signer as _;

    let key_name = parse_name(name_str)?;
    let pib = FilePib::new(pib_path)?;

    if skip_if_exists
        && let Ok(existing_pib) = FilePib::open(pib_path)
        && find_cert_name(&existing_pib, &key_name).is_some()
    {
        return Ok(());
    }

    // Cert name: `<identity>/KEY/<keyid>/<issuer>/<version>` per
    // Certificate Format v2.
    let cert_name = build_cert_name(&key_name);

    // The PIB stores the public key in SPKI-wrapped form for both
    // algorithms; the SafeBag export path re-signs from this same shape.
    let (pk, sig_type) = match key_type {
        KeyType::Ed25519 => {
            let signer = pib.generate_ed25519(&cert_name)?;
            // Certificate Format v2 §3: SPKI-wrap the raw public key.
            let raw_pk = signer.public_key_bytes();
            let mut arr = [0u8; spki::ED25519_KEY_LEN];
            arr.copy_from_slice(&raw_pk);
            (
                spki::wrap_ed25519(&arr),
                ndn_packet::SignatureType::SignatureEd25519,
            )
        }
        KeyType::Ecdsa => {
            let signer = pib.generate_ecdsa_p256(&cert_name)?;
            // `EcdsaP256Signer::public_key()` already returns SPKI DER.
            let pk = signer
                .public_key()
                .ok_or_else(|| anyhow::anyhow!("ECDSA signer produced no public key"))?;
            (pk, ndn_packet::SignatureType::SignatureSha256WithEcdsa)
        }
    };

    let now = now_ns();
    let validity_ns = days * 24 * 3600 * 1_000_000_000;
    let cert = Certificate {
        name: Arc::new(cert_name.clone()),
        public_key: pk.clone(),
        valid_from: now,
        valid_until: now.saturating_add(validity_ns),
        issuer: None,
        signed_region: None,
        sig_value: None,
        sig_type,
    };
    pib.store_cert(&cert_name, &cert)?;

    if make_anchor {
        pib.add_trust_anchor(&cert_name, &cert)?;
        println!("Generated key and self-signed certificate for {name_str} (trust anchor).");
    } else {
        println!("Generated key and self-signed certificate for {name_str}.");
    }

    println!("  Algorithm  : {}", key_type_label(key_type));
    println!("  Cert name  : {}", cert_name);
    println!("  Public key : {}", hex_encode(&pk));
    println!("  Valid from : {}", format_ns(now));
    println!("  Valid until: {}", format_ns(cert.valid_until));
    println!("  PIB        : {}", pib_path.display());

    Ok(())
}

fn cmd_export(
    pib_path: &PathBuf,
    name_str: &str,
    out: Option<&str>,
    password: Option<String>,
    format: WireFormat,
) -> anyhow::Result<()> {
    let identity = parse_name(name_str)?;
    let pib = open_pib(pib_path)?;
    let cert_name = find_cert_name(&pib, &identity).ok_or_else(|| {
        anyhow::anyhow!("No key for {name_str}. Run `ndn-sec keygen {name_str}` first.")
    })?;

    let password = resolve_password(password, "Passphrase to encrypt the private key: ", true)?;
    if password.is_empty() {
        anyhow::bail!("refusing to export with an empty passphrase");
    }

    let wire = pib
        .export_safebag(&cert_name, password.as_bytes())
        .map_err(|e| anyhow::anyhow!("export failed: {e}"))?;

    let payload: Vec<u8> = match format {
        WireFormat::Raw => wire,
        WireFormat::Base64 => {
            let mut s = base64::engine::general_purpose::STANDARD.encode(&wire);
            s.push('\n');
            s.into_bytes()
        }
    };

    // Default file name from the identity tail, e.g. /ndn/router1 → router1.safebag.
    let default_name = identity
        .components()
        .last()
        .map(|c| String::from_utf8_lossy(c.value.as_ref()).into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "identity".to_owned());
    let out = out
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{default_name}.safebag"));

    if out == "-" {
        std::io::stdout().write_all(&payload)?;
    } else {
        std::fs::write(&out, &payload)?;
        eprintln!("Exported {cert_name}");
        eprintln!("  → {out} ({} bytes, {})", payload.len(), format_label(format));
        eprintln!("  Import elsewhere with `ndn-sec import {out}` or `ndnsec import {out}`.");
    }
    Ok(())
}

fn cmd_import(
    pib_path: &PathBuf,
    file: &str,
    password: Option<String>,
    make_anchor: bool,
) -> anyhow::Result<()> {
    let raw = if file == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        std::fs::read(file).map_err(|e| anyhow::anyhow!("read {file}: {e}"))?
    };
    let wire = normalize_safebag_bytes(&raw)
        .ok_or_else(|| anyhow::anyhow!("input is neither a raw SafeBag TLV nor base64"))?;

    // The embedded certificate names the key, so the operator doesn't have
    // to restate it.
    let bag = SafeBag::decode(&wire).map_err(|e| anyhow::anyhow!("SafeBag decode: {e}"))?;
    let cert_data = ndn_packet::Data::decode(Bytes::copy_from_slice(&bag.certificate))
        .map_err(|e| anyhow::anyhow!("certificate Data decode: {e:?}"))?;
    let cert = Certificate::decode(&cert_data)
        .map_err(|e| anyhow::anyhow!("Certificate decode: {e}"))?;
    let cert_name = (*cert.name).clone();

    let password = resolve_password(password, "Passphrase that decrypts the SafeBag: ", false)?;

    let pib = FilePib::new(pib_path)?;
    let stored = pib
        .store_safebag(&cert_name, &wire, password.as_bytes())
        .map_err(|e| anyhow::anyhow!("import failed (wrong passphrase or unsupported key?): {e}"))?;

    println!("Imported identity into {}", pib_path.display());
    println!("  Cert name  : {}", stored.name);

    if make_anchor {
        pib.add_trust_anchor(&cert_name, &stored)
            .map_err(|e| anyhow::anyhow!("imported, but anchor-add failed: {e}"))?;
        println!("  Trust anchor: yes");
    }
    Ok(())
}

/// Accept either a raw SafeBag TLV (starts with the 0x80 type byte) or a
/// base64-encoded one (what `ndnsec export` emits). Returns the raw wire.
fn normalize_safebag_bytes(input: &[u8]) -> Option<Vec<u8>> {
    if input.first() == Some(&0x80) {
        return Some(input.to_vec());
    }
    // Strip whitespace/newlines, then base64-decode.
    let cleaned: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .ok()
        .filter(|w| w.first() == Some(&0x80))
}

/// Resolve a passphrase from the `--password` flag or an interactive/piped
/// stdin read. `confirm` re-prompts to catch typos on the export side.
///
/// Note: stdin input is not hidden (no extra dependency); pipe the password
/// or use `--password` in scripts. Empty input is returned verbatim so the
/// caller can decide whether to reject it.
fn resolve_password(flag: Option<String>, prompt: &str, confirm: bool) -> anyhow::Result<String> {
    if let Some(p) = flag {
        return Ok(p);
    }
    let pw = read_line_prompt(prompt)?;
    // Re-prompt only on an interactive terminal — a piped password has no
    // second line to read.
    if confirm && std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        let again = read_line_prompt("Confirm passphrase: ")?;
        if pw != again {
            anyhow::bail!("passphrases did not match");
        }
    }
    Ok(pw)
}

/// Print `prompt` to stderr and read one line from stdin (trailing newline
/// stripped). Works for both interactive and piped input.
fn read_line_prompt(prompt: &str) -> anyhow::Result<String> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

fn key_type_label(t: KeyType) -> &'static str {
    match t {
        KeyType::Ed25519 => "Ed25519",
        KeyType::Ecdsa => "ECDSA P-256",
    }
}

fn format_label(f: WireFormat) -> &'static str {
    match f {
        WireFormat::Base64 => "base64",
        WireFormat::Raw => "raw TLV",
    }
}

fn cmd_certdump(pib_path: &PathBuf, name_str: &str) -> anyhow::Result<()> {
    let identity = parse_name(name_str)?;
    let pib = open_pib(pib_path)?;
    let cert_name = find_cert_name(&pib, &identity).ok_or_else(|| {
        anyhow::anyhow!("No key for {name_str}. Run `ndn-sec keygen {name_str}` first.")
    })?;
    let cert = pib
        .get_cert(&cert_name)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let expired = cert.valid_until != u64::MAX && cert.valid_until < now_ns();
    println!("Certificate for {name_str}");
    println!("  Cert name  : {cert_name}");
    println!("  Public key : {}", hex_encode(&cert.public_key));
    println!("  Valid from : {}", format_ns(cert.valid_from));
    println!(
        "  Valid until: {}{}",
        format_ns(cert.valid_until),
        if expired { "  [EXPIRED]" } else { "" }
    );

    Ok(())
}

fn cmd_list(pib_path: &PathBuf) -> anyhow::Result<()> {
    let pib = open_pib(pib_path)?;
    let keys = pib.list_keys()?;

    if keys.is_empty() {
        println!("No keys in PIB at {}.", pib_path.display());
        return Ok(());
    }

    println!("Keys in {} ({}):", pib_path.display(), keys.len());
    for name in &keys {
        let uri = name_to_uri(name);
        let has_cert = pib.get_cert(name).is_ok();
        println!(
            "  {}  {}",
            uri,
            if has_cert { "[cert]" } else { "[no cert]" }
        );
    }

    Ok(())
}

fn cmd_delete(pib_path: &PathBuf, name_str: &str) -> anyhow::Result<()> {
    let identity = parse_name(name_str)?;
    let pib = open_pib(pib_path)?;
    let cert_name =
        find_cert_name(&pib, &identity).ok_or_else(|| anyhow::anyhow!("No key for {name_str}."))?;
    pib.delete_key(&cert_name)?;
    println!("Deleted {name_str} from PIB.");
    Ok(())
}

fn cmd_anchor_add(pib_path: &PathBuf, name_str: &str) -> anyhow::Result<()> {
    let identity = parse_name(name_str)?;
    let pib = open_pib(pib_path)?;
    let cert_name = find_cert_name(&pib, &identity).ok_or_else(|| {
        anyhow::anyhow!("No certificate for {name_str}. Run `ndn-sec keygen {name_str}` first.")
    })?;
    let cert = pib
        .get_cert(&cert_name)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    pib.add_trust_anchor(&cert_name, &cert)?;
    println!("Marked {name_str} as a trust anchor.");
    Ok(())
}

fn cmd_anchor_remove(pib_path: &PathBuf, name_str: &str) -> anyhow::Result<()> {
    let identity = parse_name(name_str)?;
    let pib = open_pib(pib_path)?;
    let cert_name =
        find_cert_name(&pib, &identity).ok_or_else(|| anyhow::anyhow!("No key for {name_str}."))?;
    pib.remove_trust_anchor(&cert_name)?;
    println!("Removed {name_str} from trust anchors.");
    Ok(())
}

fn cmd_anchor_list(pib_path: &PathBuf) -> anyhow::Result<()> {
    let pib = open_pib(pib_path)?;
    let names = pib.list_anchors()?;

    if names.is_empty() {
        println!("No trust anchors in PIB at {}.", pib_path.display());
        return Ok(());
    }

    println!("Trust anchors ({}):", names.len());
    for name in &names {
        println!("  {}", name_to_uri(name));
    }

    Ok(())
}

/// Resolve the PIB path: CLI flag → $NDN_PIB → ~/.ndn/pib.
fn resolve_pib_path(arg: Option<&str>) -> PathBuf {
    if let Some(p) = arg {
        return PathBuf::from(p);
    }
    if let Ok(p) = std::env::var("NDN_PIB") {
        return PathBuf::from(p);
    }
    let mut home = dirs_next();
    home.push(".ndn");
    home.push("pib");
    home
}

/// Return the user's home directory, falling back to `/tmp/ndn-pib`.
fn dirs_next() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/ndn-pib-fallback"))
}

fn open_pib(path: &PathBuf) -> anyhow::Result<FilePib> {
    FilePib::open(path).map_err(|e| {
        anyhow::anyhow!(
            "{e}\nRun `ndn-sec keygen <name>` to create a PIB at {}.",
            path.display()
        )
    })
}

/// Build a Certificate Format v2 cert name from an identity name.
///
/// Produces `<identity>/KEY/<keyid>/self/<version>` per
/// ndn-cxx `Certificate::isValidName` (security/certificate.hpp:152-158).
/// The keyid is derived from the current nanosecond timestamp so successive
/// keygen calls for the same identity produce distinct cert names.
fn build_cert_name(identity: &Name) -> Name {
    let keyid = format!("{:016x}", now_ns());
    identity
        .clone()
        .append("KEY")
        .append_component(ndn_packet::NameComponent::generic(Bytes::copy_from_slice(
            keyid.as_bytes(),
        )))
        .append_component(ndn_packet::NameComponent::generic(Bytes::from_static(
            b"self",
        )))
        .append_version(0)
}

/// Find the cert name (e.g. `/ndn/router1/KEY/<id>/self/v=0`) stored in the
/// PIB for a given identity prefix.  Returns the first matching key name whose
/// components begin with `identity` followed by a `KEY` component.
fn find_cert_name(pib: &FilePib, identity: &Name) -> Option<Name> {
    let key_prefix = identity.clone().append("KEY");
    pib.list_keys()
        .ok()?
        .into_iter()
        .find(|k| k.has_prefix(&key_prefix))
}

/// Parse an NDN URI like `/ndn/router1` into a `Name`.
fn parse_name(s: &str) -> anyhow::Result<Name> {
    s.parse()
        .map_err(|e| anyhow::anyhow!("Invalid NDN name '{s}': {e}"))
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Format a nanosecond Unix timestamp as a human-readable date/time.
fn format_ns(ns: u64) -> String {
    if ns == u64::MAX {
        return "never".to_string();
    }
    let secs = ns / 1_000_000_000;
    format_unix_secs(secs)
}

/// Minimal RFC 3339 date formatter using only stdlib arithmetic.
///
/// Handles all dates representable as a u64 nanosecond timestamp (year ≥ 1970).
fn format_unix_secs(secs: u64) -> String {
    let s_in_day = secs % 86400;
    let h = s_in_day / 3600;
    let m = (s_in_day % 3600) / 60;
    let s = s_in_day % 60;

    // Civil calendar from https://howardhinnant.github.io/date_algorithms.html
    let z = (secs / 86400) as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
