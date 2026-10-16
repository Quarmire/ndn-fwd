//! `ndn-trust-context` — author a trust context and render it as an
//! `ndn-trust://anchor` QR/NFC payload an end user scans to adopt it.
//!
//! ```text
//! ndn-trust-context build --namespace /home/bob --version 2 \
//!     --anchor home-ca.cert --schema-lvs home.lvs \
//!     --pib ~/.ndn/pib --sign-key /home/bob/KEY/root --qr
//! ndn-trust-context inspect "ndn-trust://anchor/…"
//! ```
//!
//! With `--pib` + `--sign-key` (a key of one of the context's anchors) the
//! payload carries the **signed** context Data, which adopters verify against
//! the expected fingerprint. Without them it carries the unsigned legacy content,
//! which adopters refuse by default.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use ndn_packet::Name;
use ndn_security::{FilePib, SignedTrustContext};
use ndn_trust_context::{ContextSpec, build_anchor_envelope, build_signed_anchor_envelope};
use ndn_trust_envelope::TrustEnvelope;
use qrcode::QrCode;

#[derive(Parser)]
#[command(name = "ndn-trust-context", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Author a context and print its `ndn-trust://anchor` URI (and optionally a QR).
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
        /// PIB directory holding `--sign-key`.
        #[arg(long, requires = "sign_key")]
        pib: Option<PathBuf>,
        /// Key (in `--pib`) of one of the context's anchors: sign the context
        /// and emit the signed form adopters verify. Without it the payload
        /// is the unsigned legacy form, which adopters refuse by default.
        #[arg(long, requires = "pib")]
        sign_key: Option<String>,
        /// Also render the payload as a QR code.
        #[arg(long, default_value_t = false)]
        qr: bool,
        /// QR encoding when `--qr` is set: `ascii` (terminal) or `svg`
        /// (writes `<namespace>.svg`).
        #[arg(long, value_enum, default_value_t = QrFormat::Ascii)]
        qr_format: QrFormat,
    },
    /// Decode an anchor envelope and print what it grants (round-trip / debugging).
    Inspect {
        /// The `ndn-trust://anchor/…` URI (or its https mirror; legacy
        /// `ndn-ctx:1:…` payloads still parse).
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
            pib,
            sign_key,
            qr,
            qr_format,
        } => {
            let spec = ContextSpec {
                namespace: parse_name(&namespace)?,
                version,
                accept_all,
                anchor_wires: anchors
                    .iter()
                    .map(|p| {
                        std::fs::read(p).with_context(|| format!("read anchor {}", p.display()))
                    })
                    .collect::<Result<_>>()?,
                schema_lvs: schema_lvs
                    .as_ref()
                    .map(|p| {
                        std::fs::read(p).with_context(|| format!("read schema {}", p.display()))
                    })
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
            let envelope = match (pib, sign_key) {
                (Some(pib), Some(key)) => {
                    let pib = FilePib::open(&pib)
                        .with_context(|| format!("open PIB {}", pib.display()))?;
                    let signer = pib
                        .get_signer(&parse_name(&key)?)
                        .with_context(|| format!("load signing key {key}"))?;
                    build_signed_anchor_envelope(&spec, signer.as_ref())?
                }
                _ => {
                    eprintln!(
                        "warning: no --pib/--sign-key: emitting the UNSIGNED legacy form, \
                         which adopters refuse by default"
                    );
                    build_anchor_envelope(&spec)?
                }
            };
            let payload = envelope.to_uri();
            println!("{payload}");
            if qr {
                render_qr(&payload, &qr_format, &namespace)?;
            }
        }
        Cmd::Inspect { payload } => {
            let envelope = TrustEnvelope::from_uri(&payload)
                .map_err(|e| anyhow::anyhow!("parse trust envelope: {e}"))?;
            let kind = envelope.kind();
            let TrustEnvelope::Anchor {
                namespace,
                fingerprint,
                version,
                context_data,
                context_content,
            } = envelope
            else {
                bail!("expected an anchor envelope, got a {} envelope", kind.as_str());
            };
            if let Some(fp) = fingerprint {
                let hex: String = fp.iter().map(|b| format!("{b:02x}")).collect();
                println!("expected_fingerprint: {hex}");
            }
            let ctx = match (context_data, context_content) {
                (Some(wire), _) => {
                    let data = ndn_packet::Data::decode(wire)
                        .map_err(|e| anyhow::anyhow!("decode context Data: {e}"))?;
                    let (ctx, signer) = ndn_cert::open_signed_context(&data)
                        .map_err(|e| anyhow::anyhow!("signed context does not verify: {e}"))?;
                    let signer_fp = ndn_cert::anchor_fingerprint(&signer);
                    println!("signed_by:    {}", signer.name);
                    println!(
                        "fingerprint_matches: {}",
                        fingerprint.map_or("no expected fingerprint".to_string(), |fp| {
                            (fp == signer_fp).to_string()
                        })
                    );
                    ctx
                }
                (None, Some(content)) => {
                    let version =
                        version.context("inline anchor envelope carries no context version")?;
                    println!("signed_by:    UNSIGNED legacy content (refused by default)");
                    SignedTrustContext::decode_content(&content, version)
                        .map_err(|e| anyhow::anyhow!("decode context: {e}"))?
                }
                (None, None) => {
                    // By-reference anchor: nothing inline to decode.
                    println!(
                        "namespace:    {}",
                        namespace.as_deref().unwrap_or("(unspecified)")
                    );
                    println!("context:      by reference (not inline)");
                    return Ok(());
                }
            };
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
