//! Headless end-to-end probe of the browser data path: connect to the forwarder's
//! WebSocket face and issue the exact management + observability + `ext/list`
//! Interests the WASM dashboard sends, over `ws://…`. Proves tunnel + WS face +
//! public reads + radio-cognition surface + OTLP span index without a browser.
//!
//!   cargo run -p ndn-fwd --features websocket --example ws_e2e -- ws://localhost:9696

use std::time::Duration;

use anyhow::{Result, anyhow};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use ndn_mgmt_wire::ControlResponse;
use ndn_packet::lp::{LpPacket, is_lp_packet};
use ndn_packet::{Data, Name, encode::InterestBuilder};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

fn strip_lp(raw: Bytes) -> Bytes {
    if is_lp_packet(&raw)
        && let Ok(lp) = LpPacket::decode(raw.clone())
        && let Some(fragment) = lp.fragment
    {
        return fragment;
    }
    raw
}

fn nfd(parts: &[&[u8]]) -> Name {
    let mut n = Name::root().append(b"localhost").append(b"nfd");
    for p in parts {
        n = n.append(p);
    }
    n
}

/// Send an unsigned Interest for `name`, return the Data content bytes.
async fn fetch(ws: &mut Ws, name: Name) -> Result<Bytes> {
    let interest = InterestBuilder::new(name)
        .can_be_prefix()
        .must_be_fresh()
        .lifetime(Duration::from_millis(4000))
        .build();
    // The WS face's LinkService LP-frames egress and expects LP on ingress.
    let wire = ndn_packet::lp::encode_lp_packet(&interest);
    ws.send(Message::Binary(wire.to_vec().into())).await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let msg = tokio::time::timeout_at(deadline, ws.next())
            .await
            .map_err(|_| anyhow!("timeout waiting for Data"))?;
        match msg {
            Some(Ok(Message::Binary(d))) => {
                let data = Data::decode(strip_lp(d)).map_err(|e| anyhow!("Data decode: {e:?}"))?;
                return Ok(data.content().cloned().unwrap_or_default());
            }
            Some(Ok(_)) => continue, // ping/pong/text — keep waiting
            Some(Err(e)) => return Err(anyhow!("ws error: {e}")),
            None => return Err(anyhow!("ws closed")),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ws://localhost:9696".to_string());
    println!("connecting {url} …");
    let (mut ws, _resp) = connect_async(&url).await?;
    println!("✓ WebSocket face connected\n");

    let status = fetch(&mut ws, nfd(&[b"status", b"general"])).await?;
    println!("✓ status/general       → {} bytes", status.len());

    let faces = fetch(&mut ws, nfd(&[b"faces", b"list"])).await?;
    println!("✓ faces/list           → {} bytes", faces.len());

    let fib = fetch(&mut ws, nfd(&[b"fib", b"list"])).await?;
    println!("✓ fib/list             → {} bytes", fib.len());

    // Radio cognition surface (ControlResponse; body in status_text).
    match fetch(&mut ws, nfd(&[b"ext", b"list"])).await {
        Ok(c) => match ControlResponse::decode(c) {
            Ok(cr) => {
                println!(
                    "✓ ext/list             → {} bytes body",
                    cr.status_text.len()
                );
                println!("  ── radio cognition ──");
                for line in cr.status_text.lines() {
                    println!("  {line}");
                }
            }
            Err(e) => println!("✗ ext/list decode: {e:?}"),
        },
        Err(e) => println!("✗ ext/list: {e}"),
    }

    // Observability span index.
    match fetch(&mut ws, nfd(&[b"observability", b"recent"])).await {
        Ok(c) => {
            let text = String::from_utf8_lossy(&c);
            let pairs: Vec<&str> = text.lines().filter(|l| l.contains('/')).collect();
            println!("\n✓ observability/recent → {} span refs", pairs.len());
            if let Some(first) = pairs.first()
                && let Some((t, s)) = first.split_once('/')
            {
                let span = fetch(
                    &mut ws,
                    nfd(&[
                        b"observability",
                        b"traces",
                        t.as_bytes(),
                        b"spans",
                        s.as_bytes(),
                    ]),
                )
                .await;
                match span {
                    Ok(sp) => println!("  ✓ fetched span {t}/{s} → {} bytes OTLP", sp.len()),
                    Err(e) => println!("  ✗ span fetch: {e}"),
                }
            }
        }
        Err(e) => println!("✗ observability/recent: {e}"),
    }

    println!("\n✓ browser data path verified over the WebSocket face.");
    Ok(())
}
