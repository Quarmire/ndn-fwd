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
use ndn_security::Signer;

#[cfg(feature = "browser-engine")]
use crate::browser_engine::LocalMgmtChannels;

// The management response shape now lives in `ndn-dashboard-core` (the seam any
// UI/engine shares); re-exported here so existing `crate::ws_mgmt::MgmtResponse`
// paths keep resolving.
pub use ndn_dashboard_core::{ManagementClient, MgmtResponse};

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
        // Sign through the operator keyring when a key is provisioned (the gate,
        // mirroring the desktop MgmtClient path); otherwise leave the command
        // unsigned, as before.
        let wire = match crate::operator_keyring::command_signer() {
            Some(signer) => {
                let sig_type = signer.sig_type();
                let key_loc = signer
                    .cert_name()
                    .or_else(|| Some(signer.key_name()))
                    .cloned();
                builder
                    .sign_fallible(sig_type, key_loc.as_ref(), |region| {
                        let region = Bytes::copy_from_slice(region);
                        let signer = signer.clone();
                        async move {
                            signer
                                .sign(&region)
                                .await
                                .map_err(|e| anyhow!("operator sign: {e}"))
                        }
                    })
                    .await?
            }
            None => builder.build(),
        };

        let data_wire = self.exchange(wire).await?;
        Self::parse_response(data_wire)
    }

    /// Short-poll the latest event sequence on
    /// `/localhost/nfd/<module>/notifications` (CanBePrefix). Returns
    /// `Some(seq)` for the most recent event, or `None` if it timed out — e.g.
    /// no events have been published yet, so the producer holds the Interest.
    ///
    /// The live-event subscriber polls this instead of issuing a *held*
    /// long-poll for the next seq: over a WebSocket relay a held Interest may
    /// not be supported, and timing one out would cancel a pending recv and
    /// desync the connection. A "latest" fetch returns immediately whenever
    /// any event exists, so the timeout (and the cancel) only fires before the
    /// first event, where the caller simply reconnects.
    pub async fn latest_notification(
        &mut self,
        module: &str,
        timeout_ms: u32,
    ) -> Result<Option<u64>> {
        let name = Name::root()
            .append(b"localhost")
            .append(b"nfd")
            .append(module.as_bytes())
            .append(b"notifications");
        let interest_wire = InterestBuilder::new(name)
            .can_be_prefix()
            .must_be_fresh()
            .lifetime(Duration::from_millis(timeout_ms as u64))
            .build();

        let timeout = gloo_timers::future::TimeoutFuture::new(timeout_ms);
        let data_wire = match &mut self.transport {
            Transport::WebSocket(slot) => {
                let ws = slot.as_mut().ok_or_else(|| anyhow!("not connected"))?;
                ws.send(Message::Bytes(interest_wire.to_vec()))
                    .await
                    .map_err(|e| anyhow!("WebSocket send failed: {:?}", e))?;
                let recv = ws.next();
                futures::pin_mut!(recv);
                match futures::future::select(recv, timeout).await {
                    futures::future::Either::Left((Some(Ok(Message::Bytes(d))), _)) => {
                        Bytes::from(d)
                    }
                    futures::future::Either::Left((Some(Ok(Message::Text(t))), _)) => {
                        return Err(anyhow!("unexpected text response: {}", t));
                    }
                    futures::future::Either::Left((Some(Err(e)), _)) => {
                        *slot = None;
                        return Err(anyhow!("WebSocket recv error: {:?}", e));
                    }
                    futures::future::Either::Left((None, _)) => {
                        *slot = None;
                        return Err(anyhow!("WebSocket closed"));
                    }
                    futures::future::Either::Right(((), _)) => return Ok(None),
                }
            }
            #[cfg(feature = "browser-engine")]
            Transport::Local { tx, rx } => {
                tx.send(interest_wire)
                    .await
                    .map_err(|_| anyhow!("local engine channel closed (send)"))?;
                let recv = async { rx.lock().await.recv().await };
                futures::pin_mut!(recv);
                match futures::future::select(recv, timeout).await {
                    futures::future::Either::Left((Some(d), _)) => d,
                    futures::future::Either::Left((None, _)) => {
                        return Err(anyhow!("local engine channel closed (recv)"));
                    }
                    futures::future::Either::Right(((), _)) => return Ok(None),
                }
            }
        };

        let data =
            Data::decode(strip_lp(data_wire)).map_err(|e| anyhow!("Data decode: {:?}", e))?;
        let seq = data
            .name
            .components()
            .last()
            .filter(|c| c.typ == ndn_packet::tlv_type::SEQUENCE_NUM)
            .map(|c| {
                c.value
                    .as_ref()
                    .iter()
                    .fold(0u64, |n, b| (n << 8) | u64::from(*b))
            })
            .ok_or_else(|| anyhow!("notification Data missing sequence number"))?;
        Ok(Some(seq))
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

    // The forwarding-plane datasets (status/faces/fib/rib/cs/strategy) are now
    // polled through `DashboardEngine::poll_forwarding`; the security datasets
    // below stay here until the engine grows a security-poll path.

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

    /// `ca/list-approvals` — read-only introspection of the NDNCERT
    /// CA's pending device-approval requests. Powers the §5.5
    /// dashboard approver list.
    pub async fn ca_list_approvals(&mut self) -> Result<MgmtResponse> {
        self.send_cmd("ca", "list-approvals", None).await
    }

    /// `ca/approve` — approve a pending request by id. Signed-command
    /// gated; the recorded approver label is the conventional
    /// `"approved-via-mgmt"` until the canonical signed-Data path lands.
    pub async fn ca_approve(&mut self, request_id: &str) -> Result<MgmtResponse> {
        let cp = ControlParameters {
            uri: Some(request_id.to_owned()),
            ..Default::default()
        };
        self.send_cmd("ca", "approve", Some(&cp)).await
    }

    /// `ca/deny` — deny a pending request with an optional reason
    /// (encoded as `<id>:<reason>` in `uri`).
    pub async fn ca_deny(&mut self, request_id: &str, reason: &str) -> Result<MgmtResponse> {
        let uri = if reason.is_empty() {
            request_id.to_owned()
        } else {
            format!("{request_id}:{reason}")
        };
        let cp = ControlParameters {
            uri: Some(uri),
            ..Default::default()
        };
        self.send_cmd("ca", "deny", Some(&cp)).await
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

#[async_trait::async_trait(?Send)]
impl ManagementClient for WsMgmtClient {
    /// Delegates to the inherent `send_cmd` — method-call syntax resolves to the
    /// inherent method (which takes precedence over a trait method of the same
    /// name), so this doesn't recurse. The only adaptation is mapping the
    /// `anyhow` error to `String` so the seam stays transport-agnostic.
    async fn send_cmd(
        &mut self,
        module: &str,
        verb: &str,
        params: Option<&ControlParameters>,
    ) -> std::result::Result<MgmtResponse, String> {
        self.send_cmd(module, verb, params)
            .await
            .map_err(|e| e.to_string())
    }
}
