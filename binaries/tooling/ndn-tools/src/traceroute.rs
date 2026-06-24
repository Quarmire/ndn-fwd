//! `ndn-traceroute` — measure the forwarder-hop distance to a named (ping-style)
//! responder by ramping the Interest `HopLimit`. Connects to ndn-fwd over a Unix socket.

use anyhow::Result;
use clap::Parser;
use tokio::sync::mpsc;

use ndn_tools_core::common::{ConnectConfig, EventLevel, ToolEvent};
use ndn_tools_core::traceroute::{TracerouteParams, run_client};

#[derive(Parser)]
#[command(
    name = "ndn-traceroute",
    about = "Active NDN hop-distance traceroute (ramps HopLimit to a ping responder)"
)]
struct Cli {
    /// Forwarder face socket path.
    #[arg(long, default_value = "/run/nfd/nfd.sock")]
    face_socket: String,

    /// Disable SHM and use the Unix socket for the data plane.
    #[arg(long)]
    no_shm: bool,

    /// Prefix of a ping-style responder to probe (run `ndn-ping server` there).
    #[arg(long, default_value = "/ndn")]
    prefix: String,

    /// Highest hop limit to try.
    #[arg(long, short = 'm', default_value_t = 16)]
    max_hops: u8,

    /// Probes per hop limit.
    #[arg(long, short = 'q', default_value_t = 3)]
    probes: u8,

    /// Per-probe Interest lifetime in milliseconds.
    #[arg(long, default_value_t = 1000)]
    lifetime: u64,

    /// Name each hop: mark probes so forwarders running a traceroute responder reply with
    /// their identity (hops without one still show as `*`).
    #[arg(long)]
    identify: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let (tx, mut rx) = mpsc::channel::<ToolEvent>(256);
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            match ev.level {
                EventLevel::Error | EventLevel::Warn => eprintln!("{}", ev.text),
                _ => println!("{}", ev.text),
            }
        }
    });

    run_client(
        TracerouteParams {
            conn: ConnectConfig {
                face_socket: cli.face_socket,
                use_shm: !cli.no_shm,
                mtu: None,
            },
            prefix: cli.prefix,
            max_hops: cli.max_hops,
            probes: cli.probes,
            lifetime_ms: cli.lifetime,
            identify: cli.identify,
        },
        tx,
    )
    .await
}
