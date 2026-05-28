//! `ndn-psync-consumer` — observe PSync FullProducer updates through a
//! running forwarder.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use ndn_app::Consumer;
use ndn_packet::Name;
use ndn_sync::{PSyncConfig, PSyncInbound, join_psync_group};

#[derive(Parser)]
#[command(
    name = "ndn-psync-consumer",
    about = "Subscribe to a PSync FullProducer group and print updates"
)]
struct Cli {
    /// PSync group prefix.
    sync_prefix: String,

    /// Number of updates to observe before exiting.
    #[arg(long, default_value_t = 1)]
    count: usize,

    /// Overall timeout in seconds.
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    /// Sync Interest interval in milliseconds.
    #[arg(long, default_value_t = 500)]
    interval_ms: u64,

    /// IPC socket for ndn-fwd/NFD.
    #[arg(long, default_value_t = ndn_config::ManagementConfig::default().face_socket)]
    face_socket: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let group: Name = cli
        .sync_prefix
        .parse()
        .map_err(|e| anyhow::anyhow!("bad sync prefix: {e}"))?;

    let consumer = Arc::new(
        Consumer::connect(&cli.face_socket)
            .await
            .with_context(|| format!("connect {}", cli.face_socket))?,
    );
    let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(256);
    let (in_tx, in_rx) = mpsc::channel::<PSyncInbound>(256);
    let cancel = CancellationToken::new();

    let send_consumer = Arc::clone(&consumer);
    let send_cancel = cancel.clone();
    let sender = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = send_cancel.cancelled() => break,
                Some(packet) = out_rx.recv() => {
                    if let Err(e) = send_consumer.send_raw(packet).await {
                        eprintln!("send failed: {e}");
                        break;
                    }
                }
            }
        }
    });

    let recv_consumer = Arc::clone(&consumer);
    let recv_cancel = cancel.clone();
    let receiver = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = recv_cancel.cancelled() => break,
                packet = recv_consumer.recv_raw() => {
                    let Some(packet) = packet else { break };
                    if in_tx.send(PSyncInbound::from(packet)).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let config = PSyncConfig {
        sync_interval: Duration::from_millis(cli.interval_ms),
        jitter_ms: 0,
        ..Default::default()
    };
    let mut handle = join_psync_group(group, out_tx, in_rx, config);

    let deadline = tokio::time::sleep(Duration::from_secs(cli.timeout));
    tokio::pin!(deadline);
    let mut seen = 0usize;

    loop {
        tokio::select! {
            _ = &mut deadline => {
                cancel.cancel();
                handle.leave();
                let _ = sender.await;
                let _ = receiver.await;
                anyhow::bail!("timed out after observing {seen}/{} PSync updates", cli.count);
            }
            update = handle.recv() => {
                let Some(update) = update else {
                    cancel.cancel();
                    anyhow::bail!("PSync task stopped before observing {} updates", cli.count);
                };
                println!("{update}");
                seen += 1;
                if seen >= cli.count {
                    cancel.cancel();
                    handle.leave();
                    let _ = sender.await;
                    let _ = receiver.await;
                    return Ok(());
                }
            }
        }
    }
}
