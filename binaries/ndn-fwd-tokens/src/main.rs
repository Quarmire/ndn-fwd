//! `ndn-fwd-tokens` — operator CLI for invite-token onboarding.
//!
//! Mints fresh tokens, prints the matching join URL, and renders
//! the URL as a QR code (ASCII or PNG) for paste-into-Slack /
//! scan-with-phone delivery. Doesn't talk to a running ndn-fwd —
//! tokens go into `[demo_ca].tokens` in the toml; restart picks
//! them up. (Live token management against the running CA is a
//! future ndn-fwd-mgmt subcommand.)
//!
//! Usage examples:
//!
//!     ndn-fwd-tokens new --domain ndn.example.com
//!     ndn-fwd-tokens new --domain ndn.example.com --count 5
//!     ndn-fwd-tokens qr  --domain ndn.example.com --token 8f3a...

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use qrcode::QrCode;

#[derive(Parser)]
#[command(name = "ndn-fwd-tokens", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate one or more random tokens + their matching join URLs.
    /// The token strings go into `[demo_ca].tokens` in `ndn-fwd.toml`;
    /// the URLs go to your users.
    New {
        /// Public domain serving the host's `JoinClient` page.
        #[arg(long)]
        domain: String,
        /// Number of tokens to mint (default 1).
        #[arg(long, default_value_t = 1)]
        count: usize,
        /// Token byte length (default 16 — 128 bits, fits a small QR).
        #[arg(long, default_value_t = 16)]
        bytes: usize,
        /// Render a QR code for each URL in addition to the text line.
        #[arg(long, default_value_t = false)]
        qr: bool,
        /// QR encoding when `--qr` is set: `ascii` (terminal-friendly)
        /// or `png` (writes `<token>.png` in the current directory).
        #[arg(long, value_enum, default_value_t = QrFormat::Ascii)]
        qr_format: QrFormat,
    },
    /// Render an existing token as a QR code (e.g. for a paper handoff).
    Qr {
        #[arg(long)]
        domain: String,
        #[arg(long)]
        token: String,
        #[arg(long, value_enum, default_value_t = QrFormat::Ascii)]
        format: QrFormat,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum QrFormat {
    Ascii,
    Png,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::New {
            domain,
            count,
            bytes,
            qr,
            qr_format,
        } => {
            for _ in 0..count {
                let token = mint_token(bytes)?;
                let url = join_url(&domain, &token);
                println!("token = \"{token}\"");
                println!("url   = {url}");
                if qr {
                    render_qr(&url, qr_format, &token)?;
                }
                println!();
            }
        }
        Cmd::Qr { domain, token, format } => {
            let url = join_url(&domain, &token);
            render_qr(&url, format, &token)?;
        }
    }
    Ok(())
}

fn join_url(domain: &str, token: &str) -> String {
    // Token in the URL fragment, not the query: fragments aren't
    // sent in the HTTP request line, so the token doesn't show up
    // in server access logs en route.
    format!("https://{domain}/#join={token}")
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
            // Terminal-friendly: small modules, dark-on-light.
            let s = code
                .render::<char>()
                .module_dimensions(2, 1)
                .quiet_zone(true)
                .dark_color('█')
                .light_color(' ')
                .build();
            println!("{s}");
        }
        QrFormat::Png => {
            // 8x scaling so it stays sharp when displayed.
            let image = code
                .render::<qrcode::render::svg::Color<'_>>()
                .min_dimensions(256, 256)
                .build();
            let path = format!("{token}.svg");
            std::fs::write(&path, image)
                .with_context(|| format!("write {path}"))?;
            println!("(wrote QR to {path})");
        }
    }
    Ok(())
}
