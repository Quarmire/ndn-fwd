//! `ndn-peek` — fetch a named Data packet (single or segmented) and print
//! or save the content. Segmented fetch uses ndnputchunks-compatible naming
//! (CanBePrefix discovery + SegmentNameComponent).

use anyhow::Result;
use clap::Parser;
use tokio::sync::mpsc;

use ndn_tools_core::common::ConnectConfig;
use ndn_tools_core::common::{EventLevel, ToolEvent};
use ndn_tools_core::peek::{PeekParams, run_peek};

#[derive(Parser)]
#[command(
    name = "ndn-peek",
    about = "Fetch a named Data packet from the NDN network"
)]
struct Cli {
    name: String,

    #[arg(long, default_value_t = 4000)]
    lifetime: u64,

    #[arg(long, short = 'o')]
    output: Option<String>,

    /// Segmented fetch pipeline depth.
    #[arg(long, short = 'p')]
    pipeline: Option<usize>,

    #[arg(long)]
    hex: bool,

    #[arg(long, short = 'm')]
    meta: bool,

    #[arg(long, short = 'v')]
    verbose: bool,

    #[arg(long)]
    can_be_prefix: bool,

    #[arg(long, default_value_t = ndn_config::ManagementConfig::default().face_socket)]
    face_socket: String,

    #[arg(long)]
    no_shm: bool,

    /// Hint for the SHM ring slot size: maximum Data content body
    /// the consumer expects to receive, in bytes. Use this when
    /// fetching segments larger than ~256 KiB over SHM. Ignored with
    /// `--no-shm`.
    #[arg(long)]
    mtu: Option<usize>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let (tx, mut rx) = mpsc::channel::<ToolEvent>(256);
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            match ev.level {
                EventLevel::Error | EventLevel::Warn => eprintln!("{}", ev.text),
                _ => {
                    if !ev.text.is_empty() {
                        println!("{}", ev.text);
                    }
                }
            }
        }
    });

    run_peek(
        PeekParams {
            conn: ConnectConfig {
                face_socket: cli.face_socket,
                use_shm: !cli.no_shm,
                mtu: cli.mtu,
            },
            name: cli.name,
            lifetime_ms: cli.lifetime,
            output: cli.output,
            pipeline: cli.pipeline,
            hex: cli.hex,
            meta_only: cli.meta,
            verbose: cli.verbose,
            can_be_prefix: cli.can_be_prefix,
        },
        tx,
    )
    .await
}
