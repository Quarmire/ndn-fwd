//! Testbed-only SafeBag interop helper.
//!
//! This binary exists so the audit harness can prove the SafeBag wire shape
//! against ndn-cxx `ndnsec import` / `ndnsec export` without teaching the
//! operator-facing `ndn-sec` CLI a half-finished identity migration UX.

use std::path::PathBuf;

use anyhow::{Context, bail};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use ndn_packet::{Data, Name, NameComponent};
use ndn_security::safe_bag::SafeBag;
use ndn_security::{Certificate, EcdsaP256Signer, Signer, encode_cert_data};

#[derive(Parser)]
#[command(name = "ndn-safebag-witness", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Emit a deterministic ECDSA-P256 SafeBag for ndnsec import.
    ExportEcdsa {
        #[arg(long)]
        identity: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Decode a SafeBag exported by ndnsec and prove key/cert consistency.
    ImportVerify {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        password: String,
        #[arg(long)]
        identity: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::ExportEcdsa {
            identity,
            password,
            out,
        } => export_ecdsa(&identity, password.as_bytes(), out).await,
        Command::ImportVerify {
            input,
            password,
            identity,
        } => import_verify(input, password.as_bytes(), identity.as_deref()),
    }
}

async fn export_ecdsa(identity: &str, password: &[u8], out: PathBuf) -> anyhow::Result<()> {
    let identity: Name = identity.parse().context("identity Name parse")?;
    let cert_name = build_cert_name(&identity);
    let key_name = key_name_from_cert_name(&cert_name)?;

    let signer =
        EcdsaP256Signer::from_seed(&[0x24; 32], key_name).context("deterministic ECDSA signer")?;
    let public_key = signer.public_key().context("ECDSA signer public key")?;
    let cert_wire = encode_cert_data(
        &cert_name,
        &public_key,
        &signer,
        0,
        4_102_444_800_000_000_000, // 2100-01-01T00:00:00Z
    )
    .await
    .context("self-signed certificate encode")?;
    let pkcs8 = signer.to_pkcs8_der().context("ECDSA PKCS#8 export")?;
    let bag = SafeBag::encrypt(Bytes::copy_from_slice(&cert_wire), &pkcs8, password)
        .context("SafeBag encrypt")?;

    std::fs::write(&out, bag.encode()).with_context(|| format!("write {}", out.display()))?;
    println!("identity={identity}");
    println!("cert={cert_name}");
    println!("out={}", out.display());
    Ok(())
}

fn import_verify(input: PathBuf, password: &[u8], identity: Option<&str>) -> anyhow::Result<()> {
    let wire = std::fs::read(&input).with_context(|| format!("read {}", input.display()))?;
    let bag = SafeBag::decode(&wire).context("SafeBag decode")?;
    let pkcs8 = bag.decrypt_key(password).context("SafeBag decrypt")?;
    let cert_data = Data::decode(Bytes::copy_from_slice(&bag.certificate))
        .context("certificate Data decode")?;
    let cert = Certificate::decode(&cert_data).context("CertificateV2 decode")?;

    if let Some(identity) = identity {
        let identity: Name = identity.parse().context("identity Name parse")?;
        if !cert.name.has_prefix(&identity) {
            bail!(
                "certificate {} is not under identity {}",
                cert.name,
                identity
            );
        }
    }

    let key_name = key_name_from_cert_name(&cert.name)?;
    let signer =
        EcdsaP256Signer::from_pkcs8_der(&pkcs8, key_name).context("ECDSA PKCS#8 import")?;
    let public_key = signer.public_key().context("ECDSA signer public key")?;
    if cert.public_key != public_key {
        bail!(
            "certificate public key does not match decrypted SafeBag private key: cert={} input={}",
            cert.name,
            input.display()
        );
    }

    println!("verified cert={}", cert.name);
    println!("input={}", input.display());
    Ok(())
}

fn build_cert_name(identity: &Name) -> Name {
    identity
        .clone()
        .append("KEY")
        .append_component(NameComponent::generic(Bytes::from_static(b"rs-safebag")))
        .append_component(NameComponent::generic(Bytes::from_static(b"self")))
        .append_version(0)
}

fn key_name_from_cert_name(cert_name: &Name) -> anyhow::Result<Name> {
    let Some(key_idx) = cert_name
        .components()
        .iter()
        .position(|c| c.typ == ndn_packet::tlv_type::NAME_COMPONENT && c.value.as_ref() == b"KEY")
    else {
        bail!("certificate name {cert_name} has no KEY component");
    };
    if key_idx + 1 >= cert_name.len() {
        bail!("certificate name {cert_name} has no key-id after KEY");
    }
    Ok(Name::from_components(
        cert_name.components()[..=key_idx + 1].iter().cloned(),
    ))
}
