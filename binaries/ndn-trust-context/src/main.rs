//! `ndn-trust-context` — author a trust context and render it as a QR/NFC join
//! payload an end user scans to adopt it.
//!
//! ```text
//! ndn-trust-context build --namespace /home/bob --version 2 \
//!     --anchor home-ca.cert --schema-lvs home.lvs --qr
//! ndn-trust-context inspect "ndn-ctx:1:2:…"
//! ```

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use ndn_packet::Name;
use ndn_security::SignedTrustContext;
use ndn_trust_context::{ContextSpec, build_join_payload, parse_envelope};
use qrcode::QrCode;

#[derive(Parser)]
#[command(name = "ndn-trust-context", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Author a context and print its join payload (and optionally a QR).
    Build {
        /// The context namespace, e.g. `/home/bob`.
        #[arg(long)]
        namespace: String,
        /// Monotonic context version (anti-rollback on the receiver).
        #[arg(long, default_value_t = 1)]
        version: u64,
        /// Accept-all schema (any cert under an anchor may sign any name);
        /// default is the hierarchical floor.
        #[arg(long, default_value_t = false)]
        accept_all: bool,
        /// Trust-anchor certificate file (NDN Data wire). Repeatable.
        #[arg(long = "anchor")]
        anchors: Vec<PathBuf>,
        /// python-lvs-compiled binary schema file.
        #[arg(long)]
        schema_lvs: Option<PathBuf>,
        /// CA endpoint name for enrollment. Repeatable.
        #[arg(long = "ca")]
        ca_endpoints: Vec<String>,
        /// Revoked key/cert name. Repeatable.
        #[arg(long = "revoke")]
        revocations: Vec<String>,
        /// Also render the payload as a QR code.
        #[arg(long, default_value_t = false)]
        qr: bool,
        /// QR encoding when `--qr` is set: `ascii` (terminal) or `svg`
        /// (writes `<namespace>.svg`).
        #[arg(long, value_enum, default_value_t = QrFormat::Ascii)]
        qr_format: QrFormat,
    },
    /// Decode a join payload and print what it grants (round-trip / debugging).
    Inspect {
        /// The `ndn-ctx:1:…` envelope string.
        payload: String,
    },
}

#[derive(Clone, ValueEnum)]
enum QrFormat {
    Ascii,
    Svg,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Build {
            namespace,
            version,
            accept_all,
            anchors,
            schema_lvs,
            ca_endpoints,
            revocations,
            qr,
            qr_format,
        } => {
            let spec = ContextSpec {
                namespace: parse_name(&namespace)?,
                version,
                accept_all,
                anchor_wires: anchors
                    .iter()
                    .map(|p| std::fs::read(p).with_context(|| format!("read anchor {}", p.display())))
                    .collect::<Result<_>>()?,
                schema_lvs: schema_lvs
                    .as_ref()
                    .map(|p| std::fs::read(p).with_context(|| format!("read schema {}", p.display())))
                    .transpose()?,
                ca_endpoints: ca_endpoints
                    .iter()
                    .map(|s| parse_name(s))
                    .collect::<Result<_>>()?,
                revocations: revocations
                    .iter()
                    .map(|s| parse_name(s))
                    .collect::<Result<_>>()?,
            };
            let payload = build_join_payload(&spec)?;
            println!("{payload}");
            if qr {
                render_qr(&payload, &qr_format, &namespace)?;
            }
        }
        Cmd::Inspect { payload } => {
            let (version, content) = parse_envelope(&payload)?;
            let ctx = SignedTrustContext::decode_content(&content, version)
                .map_err(|e| anyhow::anyhow!("decode context: {e}"))?;
            println!("namespace:    {}", ctx.namespace());
            println!("version:      {}", ctx.version());
            println!("hierarchy:    {}", ctx.enforces_hierarchy());
            println!("anchors:      {}", ctx.anchors().len());
            println!("ca_endpoints: {}", ctx.ca_endpoints().len());
            println!("revocations:  {}", ctx.revocations().len());
        }
    }
    Ok(())
}

fn parse_name(s: &str) -> Result<Name> {
    s.parse::<Name>()
        .map_err(|e| anyhow::anyhow!("invalid NDN name `{s}`: {e:?}"))
}

fn render_qr(payload: &str, format: &QrFormat, label: &str) -> Result<()> {
    let code = QrCode::new(payload.as_bytes()).context("QR encoding (payload too large?)")?;
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
            let path = format!("{}.svg", label.trim_start_matches('/').replace('/', "-"));
            std::fs::write(&path, image).with_context(|| format!("write {path}"))?;
            println!("(wrote QR to {path})");
        }
    }
    Ok(())
}
