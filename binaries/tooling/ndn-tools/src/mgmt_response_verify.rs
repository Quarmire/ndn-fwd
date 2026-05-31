//! Verify that an ndn-fwd management control response is key-signed by a
//! configured trust anchor.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use bytes::Bytes;
use clap::Parser;
use ndn_config::{
    ControlParameters, ControlResponse,
    nfd_command::{command_name, module, verb},
};
use ndn_face_native::local::ipc_face_connect;
use ndn_packet::{
    Data, Name, SignatureType,
    encode::InterestBuilder,
    lp::{LpPacket, encode_lp_packet, is_lp_packet},
};
use ndn_security::{FilePib, VerifyOutcome, verifier::verify_by_sig_type};
use ndn_transport::{FaceId, Transport};

#[derive(Parser)]
#[command(
    name = "ndn-mgmt-response-verify",
    about = "Fetch and verify an ndn-fwd management control-response Data packet"
)]
struct Cli {
    /// ndn-fwd Unix management socket.
    #[arg(long, default_value = "/run/ndn-fwd/ndn-fwd.sock")]
    socket: String,

    /// PIB containing the management response signing trust anchor.
    #[arg(long)]
    pib: PathBuf,

    /// Required prefix of the response Data name.
    #[arg(long, default_value = "/localhost/nfd/cs/config")]
    data_prefix: Name,

    /// Required prefix of the KeyLocator/certificate name.
    #[arg(long)]
    key_prefix: Name,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let response = fetch_cs_config_response(&cli.socket).await?;
    verify_response(&response, &cli.pib, &cli.data_prefix, &cli.key_prefix).await?;

    let content = response
        .content()
        .context("management response Data carried no content")?;
    let control = ControlResponse::decode(Bytes::copy_from_slice(content))
        .context("response content was not an NFD ControlResponse")?;

    println!("ok: Data name {}", response.name);
    println!(
        "ok: ControlResponse {} {}",
        control.status_code, control.status_text
    );
    Ok(())
}

async fn fetch_cs_config_response(socket: &str) -> anyhow::Result<Data> {
    let params = ControlParameters::default();
    let name = command_name(module::CS, verb::CONFIG, &params);
    let interest = InterestBuilder::new(name).must_be_fresh().build();
    let face = ipc_face_connect(FaceId(0), socket)
        .await
        .with_context(|| format!("connect to ndn-fwd socket {socket}"))?;

    face.send_bytes(encode_lp_packet(&interest))
        .await
        .context("send management Interest")?;

    let wire = face
        .recv_bytes()
        .await
        .map(strip_lp)
        .context("receive management response Data")?;

    Data::decode(wire).context("decode management response Data")
}

async fn verify_response(
    data: &Data,
    pib_path: &Path,
    data_prefix: &Name,
    key_prefix: &Name,
) -> anyhow::Result<()> {
    if !name_has_prefix(&data.name, data_prefix) {
        bail!(
            "response Data name {} is not under {}",
            data.name,
            data_prefix
        );
    }

    let sig_info = data
        .sig_info()
        .context("response Data lacks SignatureInfo")?;
    if sig_info.sig_type == SignatureType::DigestSha256 {
        bail!("response Data used DigestSha256 instead of a key-backed signature");
    }

    let key_name = sig_info
        .key_locator_name()
        .context("key-backed response Data lacks KeyLocator Name")?;
    if !name_has_prefix(key_name.as_ref(), key_prefix) {
        bail!("KeyLocator {} is not under {}", key_name, key_prefix);
    }

    let pib = FilePib::open(pib_path)
        .with_context(|| format!("open trust-anchor PIB {}", pib_path.display()))?;
    let anchors = pib.trust_anchors().context("load PIB trust anchors")?;
    let cert = anchors
        .iter()
        .find(|cert| cert.name.as_ref() == key_name.as_ref())
        .with_context(|| format!("no PIB trust anchor matching KeyLocator {key_name}"))?;

    let outcome = verify_by_sig_type(
        sig_info.sig_type,
        data.signed_region(),
        data.sig_value(),
        &cert.public_key,
    )
    .await
    .context("verify response signature")?;

    if outcome != VerifyOutcome::Valid {
        bail!("response signature did not verify against trust anchor {key_name}");
    }

    println!(
        "ok: {:?} signature verified with trust anchor {}",
        sig_info.sig_type, key_name
    );
    Ok(())
}

fn strip_lp(raw: Bytes) -> Bytes {
    if is_lp_packet(&raw)
        && let Ok(lp) = LpPacket::decode(raw.clone())
    {
        if lp.nack.is_some() {
            return raw;
        }
        if let Some(fragment) = lp.fragment {
            return fragment;
        }
    }
    raw
}

fn name_has_prefix(name: &Name, prefix: &Name) -> bool {
    let name_components = name.components();
    let prefix_components = prefix.components();
    name_components.len() >= prefix_components.len()
        && name_components
            .iter()
            .zip(prefix_components.iter())
            .all(|(a, b)| a == b)
}
