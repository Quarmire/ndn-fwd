//! `ndn-fwd-tokens` — mint invite tokens for the onboarding-link flow and
//! render them as `ndn-trust://invite` envelopes (or their
//! `https://<domain>/t/invite#…` universal-link mirror) and QR codes (ASCII or
//! SVG). Tokens go into `[demo_ca].tokens` in `ndn-fwd.toml`; the running CA
//! picks them up on restart.

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use ndn_trust_envelope::{ANCHOR_FINGERPRINT_LEN, TrustEnvelope};
use qrcode::QrCode;

#[derive(Parser)]
#[command(name = "ndn-fwd-tokens", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

/// What every invite envelope carries besides the token itself.
#[derive(Args)]
struct InviteArgs {
    /// NDNCERT CA prefix the invitee enrolls against (e.g. `/demo`).
    #[arg(long)]
    ca: String,
    /// Identity namespace the invitee is certified under (e.g. `/demo/users`).
    #[arg(long)]
    namespace: String,
    /// Optional lowercase-hex SHA-256 of the CA's root anchor public key, so
    /// the invitee can pin the CA it trusts.
    #[arg(long)]
    anchor_fp: Option<String>,
    /// Public domain serving the host's `JoinClient` page. When set, emit the
    /// `https://<domain>/t/invite#…` mirror; otherwise `ndn-trust://invite/…`.
    #[arg(long)]
    domain: Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate one or more random tokens + their matching invite envelopes.
    /// The token strings go into `[demo_ca].tokens` in `ndn-fwd.toml`;
    /// the invites go to your users.
    New {
        #[command(flatten)]
        invite: InviteArgs,
        /// Number of tokens to mint (default 1).
        #[arg(long, default_value_t = 1)]
        count: usize,
        /// Token byte length (default 16 — 128 bits, fits a small QR).
        #[arg(long, default_value_t = 16)]
        bytes: usize,
        /// Render a QR code for each invite in addition to the text line.
        #[arg(long, default_value_t = false)]
        qr: bool,
        /// QR encoding when `--qr` is set: `ascii` (terminal-friendly)
        /// or `svg` (writes `<token>.svg` in the current directory).
        #[arg(long, value_enum, default_value_t = QrFormat::Ascii)]
        qr_format: QrFormat,
    },
    /// Render an existing token's invite as a QR code (e.g. for a paper handoff).
    Qr {
        #[command(flatten)]
        invite: InviteArgs,
        #[arg(long)]
        token: String,
        #[arg(long, value_enum, default_value_t = QrFormat::Ascii)]
        format: QrFormat,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum QrFormat {
    Ascii,
    Svg,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::New {
            invite,
            count,
            bytes,
            qr,
            qr_format,
        } => {
            for _ in 0..count {
                let token = mint_token(bytes)?;
                let url = invite_url(&invite, &token)?;
                println!("token  = \"{token}\"");
                println!("invite = {url}");
                if qr {
                    render_qr(&url, qr_format, &token)?;
                }
                println!();
            }
        }
        Cmd::Qr {
            invite,
            token,
            format,
        } => {
            let url = invite_url(&invite, &token)?;
            render_qr(&url, format, &token)?;
        }
    }
    Ok(())
}

/// The invite envelope for `token`. The https mirror keeps the payload in the
/// URL fragment, not the query: fragments don't traverse the HTTP request line,
/// so the token stays out of intermediary access logs.
fn invite_url(args: &InviteArgs, token: &str) -> Result<String> {
    let anchor_fingerprint = args.anchor_fp.as_deref().map(parse_fp).transpose()?;
    let envelope = TrustEnvelope::Invite {
        ca_prefix: args.ca.clone(),
        identity_namespace: args.namespace.clone(),
        token: token.to_owned(),
        ttl_secs: None,
        anchor_fingerprint,
    };
    Ok(match &args.domain {
        Some(domain) => envelope.to_https_url(domain),
        None => envelope.to_uri(),
    })
}

fn parse_fp(hex: &str) -> Result<[u8; ANCHOR_FINGERPRINT_LEN]> {
    let hex = hex.trim();
    if !hex.is_ascii() || hex.len() != ANCHOR_FINGERPRINT_LEN * 2 {
        bail!(
            "--anchor-fp must be {} hex characters (SHA-256), got {hex:?}",
            ANCHOR_FINGERPRINT_LEN * 2
        );
    }
    let mut out = [0u8; ANCHOR_FINGERPRINT_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("--anchor-fp is not hex: {hex}"))?;
    }
    Ok(out)
}

fn mint_token(bytes: usize) -> Result<String> {
    use std::io::Read;
    let mut buf = vec![0u8; bytes];
    std::fs::File::open("/dev/urandom")
        .context("open /dev/urandom (this CLI is Unix-only today)")?
        .read_exact(&mut buf)
        .context("read /dev/urandom")?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

fn render_qr(url: &str, format: QrFormat, token: &str) -> Result<()> {
    let code = QrCode::new(url.as_bytes()).context("QR encoding")?;
    match format {
        QrFormat::Ascii => {
            let s = code
                .render::<char>()
                .module_dimensions(2, 1)
                .quiet_zone(true)
                .dark_color('█')
                .light_color(' ')
                .build();
            println!("{s}");
        }
        QrFormat::Svg => {
            let image = code
                .render::<qrcode::render::svg::Color<'_>>()
                .min_dimensions(256, 256)
                .build();
            let path = format!("{token}.svg");
            std::fs::write(&path, image).with_context(|| format!("write {path}"))?;
            println!("(wrote QR to {path})");
        }
    }
    Ok(())
}
