//! Fetch one NFD-style management notification Data packet.

use std::time::Duration;

use anyhow::{Context, bail};
use bytes::Bytes;
use clap::Parser;
use ndn_face::local::ipc_face_connect;
use ndn_packet::{
    Data, Name, NameComponent,
    encode::InterestBuilder,
    lp::{LpPacket, encode_lp_packet, is_lp_packet},
};
use ndn_transport::{FaceId, Transport};

#[derive(Parser)]
#[command(
    name = "ndn-mgmt-notification-fetch",
    about = "Fetch an ndn-fwd management notification event"
)]
struct Cli {
    /// ndn-fwd Unix management socket.
    #[arg(long, default_value = "/run/ndn-fwd/ndn-fwd.sock")]
    socket: String,

    /// Management module name, e.g. faces, rib, or strategy-choice.
    #[arg(long)]
    module: String,

    /// Optional SequenceNumberComponent to fetch. Omit to fetch the latest event.
    #[arg(long)]
    seq: Option<u64>,

    /// Interest timeout in milliseconds.
    #[arg(long, default_value_t = 5000)]
    timeout_ms: u64,

    /// Require the notification Content text to contain this substring.
    #[arg(long = "expect-contains")]
    expect_contains: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let data = fetch_notification(&cli).await?;
    let content = data.content().cloned().unwrap_or_default();
    let text = String::from_utf8_lossy(&content);

    for needle in &cli.expect_contains {
        if !text.contains(needle) {
            bail!("notification content did not contain {needle:?}: {text}");
        }
    }

    println!("ok: Data name {}", data.name);
    if text
        .chars()
        .all(|c| !c.is_control() || c == '\n' || c == '\t')
    {
        println!("ok: Content {text}");
    } else {
        println!("ok: Content {} bytes", content.len());
    }
    Ok(())
}

async fn fetch_notification(cli: &Cli) -> anyhow::Result<Data> {
    let mut name = notifications_prefix(&cli.module)?;
    if let Some(seq) = cli.seq {
        name = name.append_sequence_num(seq);
    }

    let mut interest = InterestBuilder::new(name)
        .must_be_fresh()
        .lifetime(Duration::from_millis(cli.timeout_ms));
    if cli.seq.is_none() {
        interest = interest.can_be_prefix();
    }
    let interest = interest.build();
    let face = ipc_face_connect(FaceId(0), &cli.socket)
        .await
        .with_context(|| format!("connect to ndn-fwd socket {}", cli.socket))?;

    face.send_bytes(encode_lp_packet(&interest))
        .await
        .context("send notification Interest")?;

    let wire = tokio::time::timeout(
        Duration::from_millis(cli.timeout_ms + 500),
        face.recv_bytes(),
    )
    .await
    .context("notification timeout")?
    .map(strip_lp)
    .context("receive notification Data")?;

    Data::decode(wire).context("decode notification Data")
}

fn notifications_prefix(module: &str) -> anyhow::Result<Name> {
    if module.is_empty() || module.bytes().any(|b| b == b'/') {
        bail!("module must be a single non-empty name component");
    }
    Ok(Name::from_components([
        NameComponent::generic(Bytes::from_static(b"localhost")),
        NameComponent::generic(Bytes::from_static(b"nfd")),
        NameComponent::generic(Bytes::copy_from_slice(module.as_bytes())),
        NameComponent::generic(Bytes::from_static(b"notifications")),
    ]))
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
