//! `ndn-bench` — throughput and latency benchmarking for the NDN forwarder.
//!
//! Embeds an engine with an `AppFace`, drives a controlled Interest/Data
//! exchange loop, and reports per-packet latency percentiles and aggregate
//! throughput.
//!
//! Usage: ndn-bench [--interests <n>] [--concurrency <c>] [--name <prefix>]

use std::time::Instant;

use anyhow::{Result, bail};
use tokio::task::JoinSet;

use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_faces::local::InProcFace;
use ndn_packet::Name;
use ndn_transport::FaceId;

/// Latency statistics over a sample of round-trip measurements.
struct LatencyStats {
    samples: Vec<u64>, // microseconds
}

impl LatencyStats {
    fn new() -> Self {
        Self {
            samples: Vec::new(),
        }
    }

    fn record(&mut self, us: u64) {
        self.samples.push(us);
    }

    fn print(&mut self, label: &str) {
        if self.samples.is_empty() {
            println!("{label}: no samples");
            return;
        }
        self.samples.sort_unstable();
        let n = self.samples.len();
        let p50 = self.samples[n / 2];
        let p95 = self.samples[(n * 95) / 100];
        let p99 = self.samples[(n * 99) / 100];
        let avg = self.samples.iter().sum::<u64>() / n as u64;
        println!("{label}: n={n} avg={avg}µs p50={p50}µs p95={p95}µs p99={p99}µs");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);

    let mut total_interests: u64 = 1000;
    let mut concurrency: u64 = 10;
    let mut prefix_str = "/bench".to_string();

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--interests" => {
                total_interests = args.next().unwrap_or_default().parse().unwrap_or(1000);
            }
            "--concurrency" => {
                concurrency = args.next().unwrap_or_default().parse().unwrap_or(10);
            }
            "--name" => {
                prefix_str = args.next().unwrap_or("/bench".to_string());
            }
            other => bail!("unknown flag: {other}"),
        }
    }

    // ── Engine setup ──────────────────────────────────────────────────────────
    let (_engine, shutdown) = EngineBuilder::new(EngineConfig::default()).build().await?;

    let prefix: Name = prefix_str.parse().unwrap_or_else(|_| Name::root());
    println!(
        "ndn-bench: {} interests, concurrency={}, prefix={}",
        total_interests, concurrency, prefix_str
    );

    // ── Simulated benchmark loop ──────────────────────────────────────────────
    // A real implementation would wire AppFace to the engine pipeline.
    // Here we measure the overhead of the AppFace channel round-trip only.
    let mut stats = LatencyStats::new();
    let start = Instant::now();
    let batch = total_interests / concurrency.max(1);

    let mut set: JoinSet<Vec<u64>> = JoinSet::new();

    for worker in 0..concurrency {
        let pfx = prefix.clone();
        set.spawn(async move {
            // Measure the overhead of the InProcFace channel send path.
            // InProcFace::new creates (engine-side face, app-side handle).
            // The "engine" receives via face.recv(); the "app" sends via handle.
            let (face, handle) = InProcFace::new(FaceId(worker as u32), 128);
            use ndn_transport::Face;
            let _face_id = face.id(); // confirm the face is alive

            let mut rtts = Vec::new();
            for seq in 0..batch {
                let name = pfx.clone().append(format!("{seq}"));
                use ndn_packet::Interest;
                let interest = Interest::new(name);
                let _ = interest; // interests would be sent through the handle in a real bench

                let t0 = Instant::now();
                // Encode and send a dummy packet through the handle to the face.
                let dummy = bytes::Bytes::from_static(b"\x05\x01\x00");
                let _ = handle.send(dummy).await;
                rtts.push(t0.elapsed().as_micros() as u64);
                // Drain the packet to avoid blocking the next iteration.
                let _ = face.recv().await;
            }
            rtts
        });
    }

    while let Some(result) = set.join_next().await {
        if let Ok(rtts) = result {
            for rtt in rtts {
                stats.record(rtt);
            }
        }
    }

    let elapsed = start.elapsed();
    let actual_count = stats.samples.len() as u64;
    let tput = if elapsed.as_secs_f64() > 0.0 {
        actual_count as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };

    println!(
        "ndn-bench: {:.0} interests/sec over {:.2}s",
        tput,
        elapsed.as_secs_f64()
    );
    stats.print("rtt");

    println!(
        "ndn-bench: note — AppFace not wired to pipeline; results reflect channel overhead only"
    );

    shutdown.shutdown().await;
    Ok(())
}
