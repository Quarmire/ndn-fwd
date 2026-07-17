//! # rtc_rendezvous — connect two NDF/NDN nodes across NAT or Wi-Fi client isolation
//!
//! This is the single, runnable answer to "how do I connect two nodes that
//! cannot open a listening port to each other?" — laptops behind home NAT,
//! phones on a carrier CGNAT, two machines on a coffee-shop AP with client
//! isolation turned on. None of those can accept an inbound TCP/QUIC/WebSocket
//! connection, but both can *dial out* to a public HTTP rendezvous point and
//! then to STUN/TURN — which is exactly what WebRTC needs to punch a direct
//! peer-to-peer datachannel between them. Once the datachannel is up it becomes
//! an ordinary NDN face and Interests/Data flow across it like any other link.
//!
//! It is a productized, two-machine version of the in-crate end-to-end witness
//! `ndn-rtc-signaling-relay/tests/native_via_relay.rs`: that test drives both
//! halves in one process; here each half is a separate `cargo run` invocation
//! you launch on a different host.
//!
//! ## The three roles
//!
//! You need **one relay** reachable by both peers (a tiny stateless HTTP box on
//! any public IP / VPS), an **accept** side that serves some named data, and a
//! **dial** side that fetches it. The relay only brokers the SDP offer/answer
//! handshake; it never sees your Interests or Data — those go peer-to-peer.
//!
//! ```text
//!   accept (behind NAT)          relay (public HTTP)          dial (behind NAT)
//!        │  GET /…/offer  ◄──────────────┼───────────  POST /…/offer  │
//!        │  POST /…/answer ──────────────┼──────────►  GET /…/answer   │
//!        │                                                             │
//!        │ ◄────────── direct WebRTC (DTLS/SCTP) datachannel ────────► │
//!        │            Interest ──►                                     │
//!        │                     ◄── Data                                │
//! ```
//!
//! ## Run it (three terminals / three machines)
//!
//! 1. On a host both peers can reach over HTTP (e.g. a VPS at `203.0.113.10`):
//!    ```sh
//!    cargo run -p ndn-fwd --features webrtc --example rtc_rendezvous -- \
//!        relay --bind 0.0.0.0:8888
//!    ```
//!
//! 2. On the machine that owns the data (the answerer). Both peers must agree on
//!    the same `--session` string out of band — it is just a rendezvous slot id:
//!    ```sh
//!    cargo run -p ndn-fwd --features webrtc --example rtc_rendezvous -- \
//!        accept --relay http://203.0.113.10:8888 --session demo-1 --serve /demo/roaming
//!    ```
//!
//! 3. On the machine that wants the data (the offerer):
//!    ```sh
//!    cargo run -p ndn-fwd --features webrtc --example rtc_rendezvous -- \
//!        dial --relay http://203.0.113.10:8888 --session demo-1 --name /demo/roaming
//!    ```
//!    It prints the fetched Data — an Interest that crossed a live WebRTC
//!    datachannel punched through both NATs.
//!
//! ## STUN vs TURN (symmetric NAT)
//!
//! The connector is configured with an [`IceServers`] policy. The default set
//! is public Google STUN only:
//!
//! ```text
//! IceServers::default() = { stun: ["stun:stun.l.google.com:19302", …], turn: [] }
//! ```
//!
//! **STUN** lets each peer discover its own public `ip:port` so the two can try
//! a direct hole-punched path. That works for the common "full-cone" / "address
//! restricted" home routers. It does **not** work when either side sits behind a
//! **symmetric NAT** (many carrier CGNATs, some corporate firewalls): the NAT
//! assigns a *different* external port per destination, so the address STUN
//! learned toward the relay is useless toward the peer, and the punch fails.
//!
//! **TURN** is the fallback for that case: a relay that both peers can reach
//! forwards the media for them, so connectivity no longer depends on predicting
//! NAT ports. TURN needs operator credentials, so it is opt-in. To use it, swap
//! the `IceServers::default()` calls below for something like:
//!
//! ```no_run
//! # use ndn_face_webrtc::{IceServers, TurnServer};
//! let ice = IceServers {
//!     stun: vec!["stun:stun.l.google.com:19302".into()],
//!     turn: vec![TurnServer {
//!         url: "turn:turn.example.com:3478".into(),
//!         username: "user".into(),
//!         credential: "secret".into(),
//!     }],
//! };
//! ```
//!
//! (In `ndn-fwd` proper, the same policy comes from `[[face]]`/listener config
//! `ice_servers`; see `transport_listeners::run_webrtc_listener`.)
//!
//! ## Compile status
//!
//! This example is composed entirely from existing public API. Both halves of
//! the signaling handshake are wrapped and symmetric: the **accept** (answerer)
//! side via [`WebRtcListener::accept_one`], the **dial** (offerer) side via
//! [`WebRtcDialer::connect_one`].

use std::net::SocketAddr;
use std::time::Duration;

use ndn_app::{EngineAppExt, EngineBuilder};
use ndn_face_webrtc::IceServers;
use ndn_rtc_signaling_relay::{RelayServer, WebRtcDialer, WebRtcListener};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let args: Vec<String> = std::env::args().collect();
    let role = args.get(1).map(String::as_str);
    let rest = &args[args.len().min(2)..];

    match role {
        Some("relay") => run_relay(rest).await,
        Some("accept") => run_accept(rest).await,
        Some("dial") => run_dial(rest).await,
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    }
}

const USAGE: &str = "\
rtc_rendezvous — connect two nodes across NAT / Wi-Fi client isolation via WebRTC

USAGE:
  rtc_rendezvous relay  [--bind 0.0.0.0:8888]
  rtc_rendezvous accept --relay <url> --session <id> [--serve <ndn-name>]
  rtc_rendezvous dial   --relay <url> --session <id> --name <ndn-name>

  relay   Broker the SDP handshake over HTTP (run on a host both peers reach).
  accept  Answerer: serve <ndn-name>; accept WebRTC peers dialing <session>.
  dial    Offerer: dial <session>, then fetch <ndn-name> over the datachannel.";

/// Pull a `--flag value` pair out of the remaining argv.
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// `relay` role: bind the HTTP rendezvous server and run it forever.
async fn run_relay(args: &[String]) -> anyhow::Result<()> {
    let bind = flag(args, "--bind").unwrap_or_else(|| "0.0.0.0:8888".to_string());
    let addr: SocketAddr = bind.parse()?;

    // `serve` returns the actually-bound address (useful when binding :0) and a
    // future that drives the server; awaiting it runs until the process dies.
    let (bound, server) = RelayServer::serve(addr).await?;
    println!("relay: listening on http://{bound}  (share this URL with both peers)");
    server.await?;
    Ok(())
}

/// `accept` role (answerer): stand up an engine, serve some named data, and
/// keep accepting WebRTC peers that dial our session id. Mirrors the forwarder's
/// own `transport_listeners::run_webrtc_listener`.
async fn run_accept(args: &[String]) -> anyhow::Result<()> {
    let relay = flag(args, "--relay").ok_or_else(|| anyhow::anyhow!("--relay <url> required"))?;
    let session = flag(args, "--session").ok_or_else(|| anyhow::anyhow!("--session <id> required"))?;
    let serve = flag(args, "--serve").unwrap_or_else(|| "/demo/roaming".to_string());

    // A default engine is a full forwarder: PIT, FIB, content store, strategies.
    let (engine, shutdown) = EngineBuilder::new(Default::default()).build().await?;
    // Run for the life of the process — `detach()` is the intentional
    // "no teardown" (vs. leaking the handle by hand).
    shutdown.detach();

    let cancel = CancellationToken::new();
    let node = engine.app_node(cancel.child_token());

    // Register a producer for `--serve`. `serve` installs a FIB route to this
    // producer's app face, so an Interest arriving over the WebRTC face is
    // forwarded here and answered; the Data flows back out the same face along
    // the PIT reverse path. The guard must stay alive, so hold it below.
    let label = serve.clone();
    let _guard = node
        .serve(serve.clone(), move |i, r| {
            let label = label.clone();
            async move {
                let body = format!("hello from {label} — this Data crossed a WebRTC datachannel");
                let _ = r.respond((*i.name).clone(), body).await;
            }
        })
        .await?;
    println!("accept: serving {serve}; waiting for peers on session '{session}' via {relay}");

    // One peer per session-id at a time: accept, register the face, loop.
    let listener = WebRtcListener::new(relay, IceServers::default());
    loop {
        match listener.accept_one(&session, Duration::from_secs(60)).await {
            Ok(mut face) => {
                let id = engine.faces().alloc_id();
                face.set_id(id);
                engine.add_face(face, cancel.child_token());
                println!("accept: WebRTC peer connected on face {}", id.0);
                // Let the just-registered face settle before re-opening the slot.
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => {
                eprintln!("accept: handshake failed ({e}); retrying in 5s");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

/// `dial` role (offerer): stand up an engine, complete the offerer half of the
/// signaling dance via [`WebRtcDialer::connect_one`] (the symmetric twin of the
/// answerer's `accept_one`), register the resulting face, route `--name` toward
/// it, and fetch once.
async fn run_dial(args: &[String]) -> anyhow::Result<()> {
    let relay = flag(args, "--relay").ok_or_else(|| anyhow::anyhow!("--relay <url> required"))?;
    let session = flag(args, "--session").ok_or_else(|| anyhow::anyhow!("--session <id> required"))?;
    let name = flag(args, "--name").ok_or_else(|| anyhow::anyhow!("--name <ndn-name> required"))?;
    let ndn_name: ndn_packet::Name = name.parse()?;

    let (engine, shutdown) = EngineBuilder::new(Default::default()).build().await?;
    shutdown.detach();

    let cancel = CancellationToken::new();
    let node = engine.app_node(cancel.child_token());

    // Offerer half, wrapped: post the offer, long-poll for the answer, and
    // return the live face once SCTP is up — symmetric to accept_one.
    println!("dial: offering on session '{session}' via {relay}");
    let dialer = WebRtcDialer::new(relay, IceServers::default());
    let mut face = dialer.connect_one(&session, Duration::from_secs(60)).await?;

    // Plug the face into the engine and point `--name` at it so our Interest
    // egresses over the datachannel rather than looking for a local producer.
    let face_id = engine.faces().alloc_id();
    face.set_id(face_id);
    engine.add_face(face, cancel.child_token());
    engine.fib().add_nexthop(&ndn_name, face_id, 0);
    println!("dial: WebRTC face {} up; routing {ndn_name} to it", face_id.0);

    // Express one Interest across the link and print the Data.
    let data = node.fetch(ndn_name.clone()).await?;
    match data.content() {
        Some(c) => println!(
            "dial: got Data for {ndn_name}: {:?}",
            String::from_utf8_lossy(c.as_ref())
        ),
        None => println!("dial: got Data for {ndn_name} (no content)"),
    }
    Ok(())
}
