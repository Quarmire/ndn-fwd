//! NDN management client for the web build. Two interchangeable transports
//! speaking the NFD management protocol on `/localhost/nfd/...`: WebSocket to
//! a remote forwarder, or in-page `ForwarderEngine` app face via
//! [`crate::browser_engine`].

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

/// For control verbs `status_code`/`status_text` come from the `ControlResponse`
/// envelope; for dataset verbs we synthesise `status_code = 200`.
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

enum Transport {
    /// `None` until [`WsMgmtClient::connect`] succeeds.
    WebSocket(Option<WebSocket>),
    #[cfg(feature = "browser-engine")]
    Local {
        tx: mpsc::Sender<Bytes>,
        rx: AsyncMutex<mpsc::Receiver<Bytes>>,
    },
}

pub struct WsMgmtClient {
    ws_url: String,
    transport: Transport,
}

impl WsMgmtClient {
    pub fn new(url: &str) -> Self {
        Self {
            ws_url: url.to_string(),
            transport: Transport::WebSocket(None),
        }
    }

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

    /// No-op for Local clients.
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

    pub fn is_connected(&self) -> bool {
        match &self.transport {
            Transport::WebSocket(slot) => slot.is_some(),
            #[cfg(feature = "browser-engine")]
            Transport::Local { .. } => true,
        }
    }

    /// Sends an NFD management Interest `/localhost/nfd/{module}/{verb}` with
    /// optional `ControlParameters` in `ApplicationParameters`.
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
            // Dataset verbs reply at `<base>/v=<v>/seg=<n>`; CanBePrefix is
            // required there and harmless for control verbs.
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
        let data_wire = strip_lp(data_wire);
        let data = Data::decode(data_wire).map_err(|e| anyhow!("Data decode: {:?}", e))?;
        let content = data.content().cloned().unwrap_or_default();

        match ControlResponse::decode(content.clone()) {
            Ok(cr) => Ok(MgmtResponse {
                status_code: cr.status_code,
                status_text: cr.status_text,
                body: content,
            }),
            Err(_) => Ok(MgmtResponse {
                status_code: 200,
                status_text: String::from("OK"),
                body: content,
            }),
        }
    }

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

    /// `safebag_wire` is the raw SafeBag TLV (0x80) bytes; `passphrase` decrypts
    /// the wrapped PKCS#8.
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

/// Returns the input unchanged if it isn't LP-wrapped. Inlined from
/// `ndn-ipc::forwarder_client::strip_lp` to avoid the Unix-socket dependency;
/// no Nack carve-out is needed since mgmt replies are always Data.
fn strip_lp(raw: Bytes) -> Bytes {
    if is_lp_packet(&raw)
        && let Ok(lp) = LpPacket::decode(raw.clone())
        && let Some(fragment) = lp.fragment
    {
        return fragment;
    }
    raw
}
