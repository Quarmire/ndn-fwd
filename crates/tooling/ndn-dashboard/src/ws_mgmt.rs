//! NDN management client for the web build.
//!
//! Two interchangeable transports, both speaking the NFD management
//! protocol (TLV Interest/Data on `/localhost/nfd/...`):
//!
//! - **WebSocket** — `WsMgmtClient::new(url)` dials a remote forwarder
//!   over a binary WebSocket channel. Used when the dashboard is
//!   configured against a deployed `ndn-fwd` / NFD / YaNFD.
//! - **Local** — `WsMgmtClient::new_local(channels)` reads/writes
//!   directly through the in-page `ForwarderEngine`'s app face (set up
//!   by [`crate::browser_engine`]). Used when `?engine=local` selects
//!   the in-page engine. The wire protocol is identical; the only
//!   difference is the channel implementation.
//!
//! Wire encoding/decoding goes through the spec crates
//! ([`ndn_packet::encode::InterestBuilder`], [`ndn_packet::Data`],
//! [`ndn_config::ControlParameters`], [`ndn_config::ControlResponse`])
//! — no hand-rolled TLV in this module. Those crates all build for
//! wasm32 via `ndn-packet/std-wasm`.

#![cfg(feature = "web")]

use std::time::Duration;

use anyhow::{Result, anyhow};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use gloo_net::websocket::{Message, futures::WebSocket};
#[cfg(feature = "browser-engine")]
use tokio::sync::{Mutex as AsyncMutex, mpsc};

use ndn_config::{ControlParameters, ControlResponse};
use ndn_packet::lp::{LpPacket, is_lp_packet};
use ndn_packet::{Data, Name, encode::InterestBuilder};

#[cfg(feature = "browser-engine")]
use crate::browser_engine::LocalMgmtChannels;

/// Management response surfaced to view code.
///
/// For control verbs the forwarder returns a `ControlResponse` envelope;
/// `status_code` / `status_text` come from that envelope and `body` is
/// the Data Content (which may contain a `ControlParameters` body inside
/// the envelope — view code already calls `ControlParameters::decode_all`
/// on it where applicable).
///
/// For dataset verbs (`*/list`, `*/info`) the Content is the raw dataset
/// TLV concatenation; we synthesise `status_code = 200`.
#[derive(Debug, Clone)]
pub struct MgmtResponse {
    pub status_code: u64,
    pub status_text: String,
    pub body: Bytes,
}

impl MgmtResponse {
    pub fn is_ok(&self) -> bool {
        (200..300).contains(&self.status_code)
    }
}

/// Transport backing a [`WsMgmtClient`].
enum Transport {
    /// Remote forwarder over a binary WebSocket. `None` until
    /// [`WsMgmtClient::connect`] succeeds; reconnect simply replaces
    /// the inner `WebSocket`.
    WebSocket(Option<WebSocket>),
    /// In-page engine reached through its app-face channel pair.
    #[cfg(feature = "browser-engine")]
    Local {
        tx: mpsc::Sender<Bytes>,
        rx: AsyncMutex<mpsc::Receiver<Bytes>>,
    },
}

/// NDN management client.
pub struct WsMgmtClient {
    ws_url: String,
    transport: Transport,
}

impl WsMgmtClient {
    /// Create a client targeting a remote forwarder over WebSocket.
    /// Call [`Self::connect`] to actually open the socket.
    pub fn new(url: &str) -> Self {
        Self {
            ws_url: url.to_string(),
            transport: Transport::WebSocket(None),
        }
    }

    /// Create a client that speaks management directly against the
    /// in-page `ForwarderEngine` via its app-face channel pair.
    /// `connect()` is a no-op for this transport.
    #[cfg(feature = "browser-engine")]
    pub fn new_local(channels: LocalMgmtChannels) -> Self {
        Self {
            ws_url: String::new(),
            transport: Transport::Local {
                tx: channels.to_engine,
                rx: AsyncMutex::new(channels.from_engine),
            },
        }
    }

    /// Open the underlying transport. For Local clients this is a no-op.
    pub async fn connect(&mut self) -> Result<()> {
        match &mut self.transport {
            Transport::WebSocket(slot) => {
                let ws = WebSocket::open(&self.ws_url)
                    .map_err(|e| anyhow!("WebSocket connect failed: {:?}", e))?;
                *slot = Some(ws);
                Ok(())
            }
            #[cfg(feature = "browser-engine")]
            Transport::Local { .. } => Ok(()),
        }
    }

    /// True if the transport is ready to send a command.
    pub fn is_connected(&self) -> bool {
        match &self.transport {
            Transport::WebSocket(slot) => slot.is_some(),
            #[cfg(feature = "browser-engine")]
            Transport::Local { .. } => true,
        }
    }

    /// Send a management command and await the response.
    ///
    /// The command is encoded as an NFD management Interest:
    /// `/localhost/nfd/{module}/{verb}` with optional spec-canonical
    /// `ControlParameters` carried in `ApplicationParameters`. The
    /// `InterestBuilder` adds the required
    /// `ParametersSha256DigestComponent` when parameters are present.
    pub async fn send_cmd(
        &mut self,
        module: &str,
        verb: &str,
        params: Option<&ControlParameters>,
    ) -> Result<MgmtResponse> {
        let name = Name::root()
            .append(b"localhost")
            .append(b"nfd")
            .append(module.as_bytes())
            .append(verb.as_bytes());

        let mut builder = InterestBuilder::new(name)
            // Dataset verbs (`*/list`) reply with `<base>/v=<v>/seg=<n>`,
            // so the bare-name Interest needs CanBePrefix. Control verbs
            // are fine with it set. MustBeFresh avoids stale dataset hits.
            .can_be_prefix()
            .must_be_fresh()
            .lifetime(Duration::from_millis(4000));
        if let Some(cp) = params {
            builder = builder.app_parameters(cp.encode().to_vec());
        }
        let wire = builder.build();

        let data_wire = self.exchange(wire).await?;
        Self::parse_response(data_wire)
    }

    async fn exchange(&mut self, interest_wire: Bytes) -> Result<Bytes> {
        match &mut self.transport {
            Transport::WebSocket(slot) => {
                let ws = slot.as_mut().ok_or_else(|| anyhow!("not connected"))?;
                ws.send(Message::Bytes(interest_wire.to_vec()))
                    .await
                    .map_err(|e| anyhow!("WebSocket send failed: {:?}", e))?;
                match ws.next().await {
                    Some(Ok(Message::Bytes(data))) => Ok(Bytes::from(data)),
                    Some(Ok(Message::Text(text))) => {
                        Err(anyhow!("unexpected text response: {}", text))
                    }
                    Some(Err(e)) => {
                        *slot = None;
                        Err(anyhow!("WebSocket recv error: {:?}", e))
                    }
                    None => {
                        *slot = None;
                        Err(anyhow!("WebSocket closed"))
                    }
                }
            }
            #[cfg(feature = "browser-engine")]
            Transport::Local { tx, rx } => {
                tx.send(interest_wire)
                    .await
                    .map_err(|_| anyhow!("local engine channel closed (send)"))?;
                rx.lock()
                    .await
                    .recv()
                    .await
                    .ok_or_else(|| anyhow!("local engine channel closed (recv)"))
            }
        }
    }

    fn parse_response(data_wire: Bytes) -> Result<MgmtResponse> {
        // ndn-fwd's WebSocket face LP-wraps every outgoing packet
        // (`ndn_packet::lp::encode_lp_packet`), so the bytes arriving
        // here are an `LpPacket` whose fragment is the actual Data.
        // The Unix-socket transport does the same; this mirrors
        // `ndn-ipc::forwarder_client::strip_lp`. Bare-Data wires (no LP
        // header) pass through unchanged.
        let data_wire = strip_lp(data_wire);
        let data = Data::decode(data_wire).map_err(|e| anyhow!("Data decode: {:?}", e))?;
        let content = data.content().cloned().unwrap_or_default();

        match ControlResponse::decode(content.clone()) {
            Ok(cr) => Ok(MgmtResponse {
                status_code: cr.status_code,
                status_text: cr.status_text,
                // For control verbs, body bytes carry the inner CP if any.
                // View code that wants it can call ControlParameters::decode_all.
                body: content,
            }),
            Err(_) => Ok(MgmtResponse {
                status_code: 200,
                status_text: String::from("OK"),
                body: content,
            }),
        }
    }

    // ── Convenience read methods matching MgmtClient API ───────────────

    pub async fn status_general(&mut self) -> Result<MgmtResponse> {
        self.send_cmd("status", "general", None).await
    }

    pub async fn list_faces(&mut self) -> Result<MgmtResponse> {
        self.send_cmd("faces", "list", None).await
    }

    pub async fn list_fib(&mut self) -> Result<MgmtResponse> {
        self.send_cmd("fib", "list", None).await
    }

    pub async fn list_rib(&mut self) -> Result<MgmtResponse> {
        self.send_cmd("rib", "list", None).await
    }

    pub async fn cs_info(&mut self) -> Result<MgmtResponse> {
        self.send_cmd("cs", "info", None).await
    }

    pub async fn list_strategy(&mut self) -> Result<MgmtResponse> {
        self.send_cmd("strategy-choice", "list", None).await
    }

    // ── Security reads (kickoff cross-cutting Phase B item) ────────────
    //
    // Auth-exempt verbs per `is_public_dataset_verb` in ndn-mgmt; the
    // web build polls these alongside status/faces/fib so the chip,
    // gate, and security tabs reach feature parity with desktop.

    pub async fn security_identity_list(&mut self) -> Result<MgmtResponse> {
        self.send_cmd("security", "identity-list", None).await
    }
    pub async fn security_identity_status(&mut self) -> Result<MgmtResponse> {
        self.send_cmd("security", "identity-status", None).await
    }
    pub async fn security_anchor_list(&mut self) -> Result<MgmtResponse> {
        self.send_cmd("security", "anchor-list", None).await
    }
    pub async fn security_schema_list(&mut self) -> Result<MgmtResponse> {
        self.send_cmd("security", "schema-list", None).await
    }
    pub async fn security_ca_info(&mut self) -> Result<MgmtResponse> {
        self.send_cmd("security", "ca-info", None).await
    }
    pub async fn security_policy_get(&mut self) -> Result<MgmtResponse> {
        self.send_cmd("security", "policy-get", None).await
    }
    pub async fn security_validation_stats(&mut self) -> Result<MgmtResponse> {
        self.send_cmd("security", "validation-stats", None).await
    }
    pub async fn security_validate(&mut self, target: &str) -> Result<MgmtResponse> {
        let name = target
            .parse::<Name>()
            .map_err(|e| anyhow!("invalid validate target name: {e:?}"))?;
        let cp = ControlParameters {
            name: Some(name),
            ..Default::default()
        };
        self.send_cmd("security", "validate", Some(&cp)).await
    }

    /// `security/safebag-import` — §5.1 dashboard drag-drop import.
    /// `key_name` is the embedded cert's key name; `safebag_wire` is
    /// the raw SafeBag TLV (0x80) bytes; `passphrase` decrypts the
    /// wrapped PKCS#8. Signed-command gated by the SECURITY extended
    /// module; the WS client just builds the params.
    pub async fn security_safebag_import(
        &mut self,
        key_name: &str,
        safebag_wire: &[u8],
        passphrase: &[u8],
    ) -> Result<MgmtResponse> {
        let name = key_name
            .parse::<Name>()
            .map_err(|e| anyhow!("invalid safebag-import key name: {e:?}"))?;
        let mut uri = String::with_capacity(safebag_wire.len() * 2 + passphrase.len() * 2 + 1);
        for b in safebag_wire {
            uri.push_str(&format!("{:02x}", b));
        }
        uri.push(':');
        for b in passphrase {
            uri.push_str(&format!("{:02x}", b));
        }
        let cp = ControlParameters {
            name: Some(name),
            uri: Some(uri),
            ..Default::default()
        };
        self.send_cmd("security", "safebag-import", Some(&cp)).await
    }
}

/// Unwrap an NDNLPv2 `LpPacket` and return its fragment; returns the
/// input unchanged if it isn't LP-wrapped. Mirrors
/// `ndn-ipc::forwarder_client::strip_lp` but inlined here so the web
/// build doesn't have to depend on the (Unix-socket-only) `ndn-ipc`
/// crate. We don't need the Nack carve-out the desktop version has
/// because management replies are always Data, never Nacks.
fn strip_lp(raw: Bytes) -> Bytes {
    if is_lp_packet(&raw)
        && let Ok(lp) = LpPacket::decode(raw.clone())
        && let Some(fragment) = lp.fragment
    {
        return fragment;
    }
    raw
}
