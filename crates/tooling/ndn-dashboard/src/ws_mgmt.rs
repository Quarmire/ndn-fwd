//! NDN management client for the web build.
//!
//! Two interchangeable transports, both speaking the NFD management
//! protocol (TLV Interest/Data on `/localhost/nfd/...`):
//!
//! - **WebSocket** — `WsMgmtClient::new(url)` dials a remote forwarder
//!   over a binary WebSocket channel.  Used when the dashboard is
//!   configured against a deployed `ndn-fwd` / NFD / YaNFD.
//! - **Local** — `WsMgmtClient::new_local(channels)` reads/writes
//!   directly through the in-page `ForwarderEngine`'s app face (set up
//!   by [`crate::browser_engine`]).  Used when `?engine=local` selects
//!   the in-page engine.  The wire protocol is identical; the only
//!   difference is the channel implementation.
//!
//! The TLV codec is pure Rust (`ndn-tlv` / `ndn-packet`), running
//! identically on native and in the browser.

#![cfg(feature = "web")]

use anyhow::{Result, anyhow};
use bytes::{BufMut, Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use gloo_net::websocket::{Message, futures::WebSocket};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
#[cfg(feature = "browser-engine")]
use tokio::sync::{Mutex as AsyncMutex, mpsc};

use ndn_packet::Name;
use ndn_tlv::{TlvWriter, write_varu64};

#[cfg(feature = "browser-engine")]
use crate::browser_engine::LocalMgmtChannels;

/// NFD management TLV types (subset needed for control commands).
mod tlv_type {
    pub const INTEREST: u64 = 0x05;
    pub const DATA: u64 = 0x06;
    pub const NAME: u64 = 0x07;
    pub const GENERIC_COMPONENT: u64 = 0x08;
    pub const NONCE: u64 = 0x0A;
    pub const INTEREST_LIFETIME: u64 = 0x0C;
    pub const MUST_BE_FRESH: u64 = 0x12;
    pub const CAN_BE_PREFIX: u64 = 0x21;
    pub const APPLICATION_PARAMETERS: u64 = 0x24;
    pub const CONTROL_PARAMETERS: u64 = 0x68;
    pub const CONTENT: u64 = 0x15;
    /// NFD ControlResponse envelope.
    pub const CONTROL_RESPONSE: u64 = 0x65;
    pub const CR_STATUS_CODE: u64 = 0x66;
    pub const CR_STATUS_TEXT: u64 = 0x67;
    pub const URI: u64 = 0x72;
    pub const FACE_ID: u64 = 0x69;
    pub const COST: u64 = 0x6A;
    pub const STRATEGY: u64 = 0x6B;
    pub const COUNT: u64 = 0x84;
}

/// Management response status.
#[derive(Debug, Clone)]
pub struct MgmtResponse {
    pub status_code: u64,
    pub status_text: String,
    pub body: Bytes,
}

impl MgmtResponse {
    pub fn is_ok(&self) -> bool {
        self.status_code == 200
    }
}

/// Transport backing a [`WsMgmtClient`].
enum Transport {
    /// Remote forwarder over a binary WebSocket. `None` until
    /// [`WsMgmtClient::connect`] succeeds; reconnect simply replaces
    /// the inner `WebSocket`.
    WebSocket(Option<WebSocket>),
    /// In-page engine reached through its app-face channel pair. The
    /// receiver is held inside an `AsyncMutex` so `send_cmd` can take
    /// it across `&mut self` boundaries without `Pin` gymnastics.
    #[cfg(feature = "browser-engine")]
    Local {
        tx: mpsc::Sender<Bytes>,
        rx: AsyncMutex<mpsc::Receiver<Bytes>>,
    },
}

/// NDN management client.
///
/// Type name preserved for source compatibility — see the module-level
/// doc for the two transport variants.
pub struct WsMgmtClient {
    ws_url: String,
    transport: Transport,
    pending: Arc<Mutex<HashMap<u32, futures::channel::oneshot::Sender<Bytes>>>>,
}

impl WsMgmtClient {
    /// Create a client targeting a remote forwarder over WebSocket.
    /// Call [`Self::connect`] to actually open the socket.
    pub fn new(url: &str) -> Self {
        Self {
            ws_url: url.to_string(),
            transport: Transport::WebSocket(None),
            pending: Arc::new(Mutex::new(HashMap::new())),
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
            pending: Arc::new(Mutex::new(HashMap::new())),
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
    /// `/localhost/nfd/{module}/{verb}` with optional `ControlParameters`.
    pub async fn send_cmd(
        &mut self,
        module: &str,
        verb: &str,
        params: Option<&[u8]>,
    ) -> Result<MgmtResponse> {
        let nonce = {
            let mut buf = [0u8; 4];
            getrandom::getrandom(&mut buf).unwrap_or_default();
            u32::from_be_bytes(buf)
        };
        let wire = Self::encode_mgmt_interest(module, verb, nonce, params);

        match &mut self.transport {
            Transport::WebSocket(slot) => {
                let ws = slot.as_mut().ok_or_else(|| anyhow!("not connected"))?;
                ws.send(Message::Bytes(wire.to_vec()))
                    .await
                    .map_err(|e| anyhow!("WebSocket send failed: {:?}", e))?;
                match ws.next().await {
                    Some(Ok(Message::Bytes(data))) => Self::parse_mgmt_response(&data),
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
                tx.send(wire)
                    .await
                    .map_err(|_| anyhow!("local engine channel closed (send)"))?;
                let data_wire = rx
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or_else(|| anyhow!("local engine channel closed (recv)"))?;
                Self::parse_mgmt_response(&data_wire)
            }
        }
    }

    // ── Convenience methods matching MgmtClient API ────────────────────

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

    // ── TLV encoding ───────────────────────────────────────────────────

    /// Encode an NFD management Interest as TLV wire bytes.
    fn encode_mgmt_interest(module: &str, verb: &str, nonce: u32, params: Option<&[u8]>) -> Bytes {
        // Build name: /localhost/nfd/{module}/{verb}
        let components: Vec<&[u8]> = vec![b"localhost", b"nfd", module.as_bytes(), verb.as_bytes()];

        // Pre-compute name TLV size
        let mut name_value_size = 0usize;
        for comp in &components {
            name_value_size += 1 + varu64_size(comp.len() as u64) + comp.len();
        }

        let nonce_tlv_size = 1 + 1 + 4; // type(1) + len(1) + value(4)
        let lifetime_tlv_size = 1 + 1 + 2; // 4000ms fits in 2 bytes
        // CanBePrefix and MustBeFresh are 2-byte empty TLVs each.
        // CanBePrefix is required for dataset verbs (`*/list`) — those
        // responses are named `<base>/v=<v>/seg=<n>`; without it the
        // bare-name Interest never matches in the PIT.  MustBeFresh
        // ensures the dashboard doesn't see stale cached datasets.
        let can_be_prefix_size = 2;
        let must_be_fresh_size = 2;

        let params_tlv_size = match params {
            Some(p) => 1 + varu64_size(p.len() as u64) + p.len(),
            None => 0,
        };

        let interest_value_size = 1
            + varu64_size(name_value_size as u64)
            + name_value_size
            + can_be_prefix_size
            + must_be_fresh_size
            + nonce_tlv_size
            + lifetime_tlv_size
            + params_tlv_size;

        let total = 1 + varu64_size(interest_value_size as u64) + interest_value_size;
        let mut buf = BytesMut::with_capacity(total);

        // Interest TLV
        buf.put_u8(tlv_type::INTEREST as u8);
        put_varu64(&mut buf, interest_value_size as u64);

        // Name TLV
        buf.put_u8(tlv_type::NAME as u8);
        put_varu64(&mut buf, name_value_size as u64);
        for comp in &components {
            buf.put_u8(tlv_type::GENERIC_COMPONENT as u8);
            put_varu64(&mut buf, comp.len() as u64);
            buf.put_slice(comp);
        }

        // CanBePrefix + MustBeFresh (both empty selector TLVs, ordered
        // before Nonce per the canonical Interest field order).
        buf.put_u8(tlv_type::CAN_BE_PREFIX as u8);
        buf.put_u8(0);
        buf.put_u8(tlv_type::MUST_BE_FRESH as u8);
        buf.put_u8(0);

        // Nonce
        buf.put_u8(tlv_type::NONCE as u8);
        buf.put_u8(4);
        buf.put_u32(nonce);

        // InterestLifetime (4000ms)
        buf.put_u8(tlv_type::INTEREST_LIFETIME as u8);
        buf.put_u8(2);
        buf.put_u16(4000);

        // ApplicationParameters (if any)
        if let Some(p) = params {
            buf.put_u8(tlv_type::APPLICATION_PARAMETERS as u8);
            put_varu64(&mut buf, p.len() as u64);
            buf.put_slice(p);
        }

        buf.freeze()
    }

    /// Parse a Data wire packet carrying either a `ControlResponse`
    /// (for control commands like `status/general`) or a dataset
    /// payload (for `*/list` verbs).  Returns the parsed status fields;
    /// `body` is the raw Content slice (caller decodes per-verb).
    fn parse_mgmt_response(data: &[u8]) -> Result<MgmtResponse> {
        // 1. Strip the Data envelope, get Content bytes.
        let content = data_content(data)?;

        // 2. Try ControlResponse first; fall back to dataset (200 OK).
        match parse_control_response(&content) {
            Some((status_code, status_text)) => Ok(MgmtResponse {
                status_code,
                status_text,
                body: content,
            }),
            None => Ok(MgmtResponse {
                status_code: 200,
                status_text: String::from("OK"),
                body: content,
            }),
        }
    }
}

/// Encode a variable-length unsigned integer (NDN TLV VarNumber).
fn put_varu64(buf: &mut BytesMut, val: u64) {
    if val < 253 {
        buf.put_u8(val as u8);
    } else if val <= 0xFFFF {
        buf.put_u8(253);
        buf.put_u16(val as u16);
    } else if val <= 0xFFFF_FFFF {
        buf.put_u8(254);
        buf.put_u32(val as u32);
    } else {
        buf.put_u8(255);
        buf.put_u64(val);
    }
}

/// Compute the wire size of a VarNumber encoding.
fn varu64_size(val: u64) -> usize {
    if val < 253 {
        1
    } else if val <= 0xFFFF {
        3
    } else if val <= 0xFFFF_FFFF {
        5
    } else {
        9
    }
}

// ─── Minimal TLV decoders (just what `parse_mgmt_response` needs) ────────────

fn read_varu64(buf: &[u8], off: usize) -> Option<(u64, usize)> {
    let b0 = *buf.get(off)?;
    if b0 < 253 {
        Some((b0 as u64, off + 1))
    } else if b0 == 253 {
        let v = u16::from_be_bytes([*buf.get(off + 1)?, *buf.get(off + 2)?]);
        Some((v as u64, off + 3))
    } else if b0 == 254 {
        let v = u32::from_be_bytes([
            *buf.get(off + 1)?,
            *buf.get(off + 2)?,
            *buf.get(off + 3)?,
            *buf.get(off + 4)?,
        ]);
        Some((v as u64, off + 5))
    } else {
        let mut bytes = [0u8; 8];
        for i in 0..8 {
            bytes[i] = *buf.get(off + 1 + i)?;
        }
        Some((u64::from_be_bytes(bytes), off + 9))
    }
}

fn decode_tlv(buf: &[u8], off: usize) -> Option<(u64, usize, usize)> {
    let (typ, len_off) = read_varu64(buf, off)?;
    let (len, val_off) = read_varu64(buf, len_off)?;
    let end = val_off + (len as usize);
    if end > buf.len() {
        return None;
    }
    Some((typ, val_off, end))
}

/// Strip the Data envelope and return Content bytes (or an error if
/// the wire isn't a well-formed Data with a Content TLV).
fn data_content(wire: &[u8]) -> Result<Bytes> {
    let (typ, val, end) = decode_tlv(wire, 0).ok_or_else(|| anyhow!("malformed Data wire"))?;
    if typ != tlv_type::DATA {
        return Err(anyhow!("expected Data TLV (0x06), got {:#x}", typ));
    }
    let mut off = val;
    while off < end {
        let (child_typ, child_val, child_end) =
            decode_tlv(wire, off).ok_or_else(|| anyhow!("malformed Data child TLV"))?;
        if child_typ == tlv_type::CONTENT {
            return Ok(Bytes::copy_from_slice(&wire[child_val..child_end]));
        }
        off = child_end;
    }
    // Data with no Content field — that's valid NDN; treat as empty body.
    Ok(Bytes::new())
}

/// Parse a `ControlResponse` TLV. Returns `None` if the slice doesn't
/// begin with a ControlResponse envelope (caller treats as a dataset).
fn parse_control_response(content: &[u8]) -> Option<(u64, String)> {
    let (typ, val, end) = decode_tlv(content, 0)?;
    if typ != tlv_type::CONTROL_RESPONSE {
        return None;
    }
    let mut status_code: u64 = 0;
    let mut status_text = String::new();
    let mut off = val;
    while off < end {
        let (child_typ, child_val, child_end) = decode_tlv(content, off)?;
        match child_typ {
            t if t == tlv_type::CR_STATUS_CODE => {
                let mut v = 0u64;
                for b in &content[child_val..child_end] {
                    v = v * 256 + *b as u64;
                }
                status_code = v;
            }
            t if t == tlv_type::CR_STATUS_TEXT => {
                status_text = String::from_utf8_lossy(&content[child_val..child_end]).into_owned();
            }
            _ => {}
        }
        off = child_end;
    }
    Some((status_code, status_text))
}
