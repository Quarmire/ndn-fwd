/// NFD-compatible management server.
///
/// Implements the NFD Management Protocol over NDN Interest/Data packets.
/// Management Interests use the name structure:
///
/// ```text
/// /localhost/nfd/<module>/<verb>/<ControlParameters>
/// ```
///
/// # Supported modules
///
/// - **rib**: `register`, `unregister`, `list`
/// - **faces**: `create`, `destroy`, `list`
/// - **fib**: `add-nexthop`, `remove-nexthop`, `list`
/// - **strategy-choice**: `set`, `unset`, `list`
/// - **cs**: `config`, `info`
/// - **neighbors**: `list`
/// - **service**: `list`, `browse`, `announce`, `withdraw`
/// - **status**: `general`, `shutdown`
///
/// # Source face propagation
///
/// When a command omits `FaceId`, the handler resolves the requesting face from
/// the PIT in-records via [`ForwarderEngine::source_face_id`].
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[cfg(feature = "yubikey-piv")]
use base64::Engine as _;
use bytes::Bytes;
use ndn_discovery::{
    DiscoveryConfig, HelloStrategyKind, NeighborState, PrefixAnnouncementMode,
    ServiceDiscoveryProtocol, ServiceRecord,
};
use ndn_engine::stages::ErasedStrategy;
use ndn_engine::{ForwarderEngine, RibRoute};
use ndn_faces::local::InProcHandle;
use ndn_packet::{Interest, Name, NameComponent, encode::encode_data_unsigned};
use ndn_routing::DvrConfig;
use ndn_security::{FilePib, SchemaRule};
use ndn_strategy::{BestRouteStrategy, MulticastStrategy};
use ndn_transport::{Face, FaceId, FaceKind, FacePersistency, FaceScope};
use tokio_util::sync::CancellationToken;

use ndn_config::{
    ControlParameters, ControlResponse,
    control_parameters::{origin, route_flags},
    control_response::status,
    nfd_command::{module, parse_command_name, verb},
    nfd_dataset,
};

// ─── Management response type ─────────────────────────────────────────────────

/// Response from a management command dispatch.
///
/// - `Control` — standard ControlResponse (type 0x65), encoded as NFD TLV and
///   wrapped in a Data content field.  Used for command results and ndn-rs
///   custom read-only endpoints.
/// - `Dataset` — raw NFD status dataset bytes (concatenated type-0x80 entries),
///   sent directly as the Data content.  Used for `faces/list`, `fib/list`,
///   `rib/list`, and `strategy-choice/list` so that yanfd-compatible clients
///   (e.g. `ndn-ctl`) can decode them.
enum MgmtResponse {
    Control(Box<ControlResponse>),
    Dataset(bytes::Bytes),
}

impl From<ControlResponse> for MgmtResponse {
    fn from(r: ControlResponse) -> Self {
        MgmtResponse::Control(Box::new(r))
    }
}

// ─── Socket helpers ──────────────────────────────────────────────────────────

/// Best-effort attempt to increase the socket receive buffer size.
///
/// Uses `SO_RCVBUF` via `libc::setsockopt`.  On Linux the effective maximum is
/// `net.core.rmem_max` (doubled by the kernel); on macOS it is `kern.ipc.maxsockbuf`.
/// Failure is logged but not fatal — the listener will still work, just with a
/// smaller buffer that may drop fragments under heavy load.
///
/// On Windows, tuning `SO_RCVBUF` via the `libc` crate is not supported; the
/// default OS buffer is used instead.
#[cfg(unix)]
fn set_recv_buf_size(socket: &tokio::net::UdpSocket, size: usize) {
    use std::os::fd::AsRawFd;
    let fd = socket.as_raw_fd();
    let size = size as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &size as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        tracing::warn!(
            target: "face.udp",
            error=%std::io::Error::last_os_error(),
            "udp-listener: failed to set SO_RCVBUF (continuing with default)"
        );
    }
}

#[cfg(not(unix))]
fn set_recv_buf_size(_socket: &tokio::net::UdpSocket, _size: usize) {
    // No-op on non-Unix platforms. The OS default receive buffer is used.
}

// ─── Management prefix ────────────────────────────────────────────────────────

/// Build the `/localhost/nfd` name prefix registered in the FIB.
pub fn mgmt_prefix() -> Name {
    Name::from_components([
        NameComponent::generic(Bytes::from_static(b"localhost")),
        NameComponent::generic(Bytes::from_static(b"nfd")),
    ])
}

// ─── Face listener ────────────────────────────────────────────────────────────

/// Accept NDN face connections on `path` and register each as a dynamic face.
///
/// `path` is a Unix domain socket path on Unix (e.g. `/run/nfd/nfd.sock`)
/// or a Named Pipe path on Windows (e.g. `\\.\pipe\ndn`).
pub async fn run_face_listener(path: &str, engine: ForwarderEngine, cancel: CancellationToken) {
    let listener = match ndn_faces::local::IpcListener::bind(path) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(target: "face.system", path = %path, error = %e, "face-listener: bind failed");
            return;
        }
    };

    tracing::info!(target: "face.system", path = %listener.uri(), "NDN face listener ready");

    loop {
        let face_id = engine.faces().alloc_id();
        let face = tokio::select! {
            _ = cancel.cancelled() => break,
            r = listener.accept(face_id) => match r {
                Ok(f)  => f,
                Err(e) => {
                    tracing::warn!(target: "face.system", error = %e, "face-listener: accept error");
                    continue;
                }
            },
        };

        tracing::debug!(target: "face.system", face = %face_id, "face-listener: accepted management connection");
        // Per-connection child token so that closing one connection only
        // cancels that connection's tasks, not the whole listener.
        let conn_cancel = cancel.child_token();
        engine.add_face(face, conn_cancel);
    }

    listener.cleanup();
    tracing::info!(target: "face.system", "NDN face listener stopped");
}

// ─── UDP listener ────────────────────────────────────────────────────────────

/// Listen for incoming UDP datagrams on `bind_addr` and auto-create a `UdpFace`
/// for each new source address seen.
///
/// NFD calls this the "UDP channel".  A single unconnected socket receives from
/// all peers.  The first datagram from a new source creates a per-peer `UdpFace`
/// (unconnected, using `send_to`).  Subsequent datagrams from that peer are
/// forwarded into the pipeline via the existing face's channel.
///
/// The per-peer face shares the listener socket for sending (via `send_to`) but
/// receives packets only through the listener's demux — the face's own `recv()`
/// is never called (it would compete for the same socket).  Instead, the
/// listener pushes received bytes directly into the pipeline channel.
pub async fn run_udp_listener(
    bind_addr: std::net::SocketAddr,
    engine: ForwarderEngine,
    cancel: CancellationToken,
) {
    let socket = match tokio::net::UdpSocket::bind(bind_addr).await {
        Ok(s) => {
            // Increase the receive buffer to handle fragment bursts.  At high
            // window sizes a single peer can send hundreds of fragments (7 per
            // Data) before the pipeline drains them.  The default OS buffer
            // (~212 KB on Linux) is too small and causes silent drops.
            set_recv_buf_size(&s, 4 * 1024 * 1024);
            Arc::new(s)
        }
        Err(e) => {
            tracing::error!(target: "face.udp", addr=%bind_addr, error=%e, "udp-listener: bind failed");
            return;
        }
    };

    let local = socket.local_addr().unwrap_or(bind_addr);
    tracing::info!(target: "face.udp", addr=%local, "UDP listener ready");

    // Deduplicate faces by the full remote address (IP + port).  This correctly
    // handles both NDN forwarder-to-forwarder traffic (source port is 6363) and
    // consumer application traffic (source port is ephemeral).  Replies go to
    // the actual source address of the datagram so that consumer apps — which
    // listen on their ephemeral port, not port 6363 — receive the Data.
    let mut peers = std::collections::HashMap::<std::net::SocketAddr, FaceId>::new();
    let mut buf = [0u8; 9000];

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            r = socket.recv_from(&mut buf) => {
                let (n, src) = match r {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!(target: "face.udp", error=%e, "udp-listener: recv error");
                        continue;
                    }
                };

                tracing::debug!(target: "face.udp", src=%src, len=n, "udp-listener: recv packet");
                let raw = bytes::Bytes::copy_from_slice(&buf[..n]);

                let face_id = if let Some(&id) = peers.get(&src) {
                    id
                } else {
                    // New peer — create a send-only UdpFace sharing the listener
                    // socket, targeting the exact source address of the datagram.
                    // Using the actual source port (not a fixed 6363) ensures that
                    // consumer apps with ephemeral source ports receive replies.
                    // No recv loop is spawned — the listener handles inbound
                    // packets and injects them via `inject_packet`.
                    let face_id = engine.faces().alloc_id();
                    let face = ndn_faces::net::UdpFace::from_shared_socket(
                        face_id, Arc::clone(&socket), src,
                    );
                    let peer_cancel = cancel.child_token();
                    engine.add_face_send_only(face, peer_cancel);
                    peers.insert(src, face_id);
                    tracing::info!(target: "face.udp", face=%face_id, peer=%src, "udp-listener: new face");
                    face_id
                };

                // Inject the raw datagram into the pipeline. Fragment reassembly
                // is handled by the TlvDecode stage (per-face reassembly buffers),
                // not here — keeping the listener simple and avoiding duplication.
                let arrival = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64;
                let meta = ndn_discovery::InboundMeta::udp(src);
                if engine.inject_packet(raw, face_id, arrival, meta).await.is_err() {
                    break; // Pipeline channel closed.
                }
            }
        }
    }

    tracing::info!(target: "face.udp", "UDP listener stopped");
}

// ─── TCP listener ────────────────────────────────────────────────────────────

/// Accept incoming TCP connections on `bind_addr` and create a `TcpFace` for
/// each.  TLV length-prefix framing is handled by `TcpFace` internally.
pub async fn run_tcp_listener(
    bind_addr: std::net::SocketAddr,
    engine: ForwarderEngine,
    cancel: CancellationToken,
) {
    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(target: "face.tcp", addr=%bind_addr, error=%e, "tcp-listener: bind failed");
            return;
        }
    };

    let local = listener.local_addr().unwrap_or(bind_addr);
    tracing::info!(target: "face.tcp", addr=%local, "TCP listener ready");

    loop {
        let (stream, peer) = tokio::select! {
            _ = cancel.cancelled() => break,
            r = listener.accept() => match r {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(target: "face.tcp", error=%e, "tcp-listener: accept error");
                    continue;
                }
            },
        };

        let face_id = engine.faces().alloc_id();
        let face = ndn_faces::net::tcp_face_from_stream(face_id, stream);
        let conn_cancel = cancel.child_token();
        engine.add_face(face, conn_cancel);
        tracing::info!(target: "face.tcp", face=%face_id, peer=%peer, "tcp-listener: accepted connection");
    }

    tracing::info!(target: "face.tcp", "TCP listener stopped");
}

// ─── Management handler ───────────────────────────────────────────────────────

/// Read Interests from the management `InProcHandle`, dispatch NFD commands,
/// and write Data responses back.
/// Runtime handles for management of pluggable protocol components.
pub struct MgmtHandles {
    /// Shared discovery config — `None` when discovery is disabled.
    pub discovery_cfg: Option<Arc<RwLock<DiscoveryConfig>>>,
    /// Shared DVR config — `None` when DVR is not running.
    pub dvr_cfg: Option<Arc<RwLock<DvrConfig>>>,
    /// Whether the active signing identity is ephemeral (in-memory, not persisted).
    pub security_is_ephemeral: bool,
    /// Validator used to authorise signed command Interests (audit
    /// finding E.01). When `None`, the auth gate is skipped and
    /// commands run unauthenticated — current default for backward
    /// compatibility while operators populate trust anchors.
    pub command_validator: Option<Arc<ndn_security::Validator>>,
    /// When `true`, an unsigned or invalid command Interest is rejected
    /// with `status::UNAUTHORIZED`; when `false` (default), a warning is
    /// logged but the command proceeds. Operators flip this to `true`
    /// once trust anchors are configured. Spec ref: NFD
    /// `daemon/mgmt/command-authenticator.cpp`; ndn-cxx
    /// `mgmt/dispatcher.cpp:166-185`.
    pub require_signed_commands: bool,
    /// Audit N.10 — sliding `SignatureTime` window per signer to defeat
    /// replay of captured signed commands. The cache is consulted only
    /// when a signed command actually validates; an unsigned command
    /// path (default `require_signed_commands=false`) does not touch
    /// it. `Some(empty cache)` enables enforcement; `None` skips the
    /// check entirely (back-compat for deployments running before the
    /// audit).
    pub command_replay_cache: Option<CommandReplayCache>,
    /// Audit N.12 — signer used for control-response Data packets. NFD
    /// signs control responses with the daemon's NFD key; ndn-cxx
    /// `nfd::Controller` configured against an NFD trust schema rejects
    /// the bare `DigestSha256` responses ndn-rs has emitted historically.
    /// `Some(signer)` switches `send_response` onto `DataBuilder::sign_sync`
    /// with that signer's `sig_type()` and key-locator name. `None`
    /// preserves the legacy DigestSha256 behaviour for back-compat.
    pub command_response_signer: Option<Arc<dyn ndn_security::Signer>>,
}

/// Audit N.11 — pure decision over a command's `ControlParameters` location.
///
/// NFD management Interests carry ControlParameters in either the Name's
/// 5th component or the `ApplicationParameters` field, never both. A peer
/// that supplies CP in both locations is malformed per spec — the mgmt
/// dispatcher must reject before the (possibly inconsistent) values reach
/// per-module handlers. Audit A.09's signed-region calculation already
/// covers both Name and AppParameters, so a SIGNED command with mismatched
/// CP-in-both-locations would also fail signature verification; this
/// rejection covers the unsigned and unbound-by-PSDC paths.
///
/// Returns the resolved `ControlParameters` slot to dispatch with, or an
/// `Err(reason)` describing why the command was rejected.
pub(crate) fn resolve_control_parameters(
    in_name: Option<ControlParameters>,
    in_app_params: Option<ControlParameters>,
) -> Result<Option<ControlParameters>, &'static str> {
    match (in_name, in_app_params) {
        (Some(_), Some(_)) => Err("ControlParameters present in both Name and AppParameters"),
        (Some(p), None) | (None, Some(p)) => Ok(Some(p)),
        (None, None) => Ok(None),
    }
}

/// Audit N.10 — sliding `SignatureTime` window per signer. Mirrors
/// ndn-cxx `ValidationPolicyCommandInterest` which keeps a per-signer
/// last-seen timestamp and rejects either out-of-window or
/// non-strictly-increasing values to defeat replay of captured signed
/// commands.
pub const COMMAND_SIG_TIME_TOLERANCE_MS: u64 = 120_000; // ±2 minutes

/// Audit N.10 — replay-protection cache mapping a signer's KeyLocator
/// (or fingerprint) to the last accepted `SignatureTime`. Keyed by the
/// canonical `Name` of the signer's certificate; one entry per active
/// command-issuing identity.
pub type CommandReplayCache =
    Arc<std::sync::Mutex<std::collections::HashMap<ndn_packet::Name, u64>>>;

/// Audit N.10 — pure decision over `(sig_time, now, last_seen)`. Returns
/// the accepted `sig_time_ms` so the caller can update the cache, or an
/// `Err(reason)` if the command must be rejected.
///
/// The check rejects:
/// - missing `SignatureTime`,
/// - `sig_time` further than `tolerance_ms` from the local clock
///   (handles both stale captures and far-future timestamps),
/// - `sig_time <= last_seen` (replay or out-of-order).
pub(crate) fn check_sig_time(
    sig_time_ms: Option<u64>,
    now_ms: u64,
    last_seen: Option<u64>,
    tolerance_ms: u64,
) -> Result<u64, String> {
    let Some(sig_time) = sig_time_ms else {
        return Err("signed command missing SignatureTime header".to_string());
    };
    let delta = now_ms.abs_diff(sig_time);
    if delta > tolerance_ms {
        return Err(format!(
            "command SignatureTime {sig_time} ms is outside ±{tolerance_ms} ms window of now={now_ms}"
        ));
    }
    if let Some(last) = last_seen
        && sig_time <= last
    {
        return Err(format!(
            "command SignatureTime {sig_time} ms <= last accepted {last} ms (replay or reorder)"
        ));
    }
    Ok(sig_time)
}

/// Audit E.03 — `true` when `module` is an ndn-rs extension beyond NFD's
/// canonical management surface. NFD ships only
/// `faces`, `fib`, `rib`, `cs`, `strategy-choice`, `status`. Every other
/// module under `/localhost/nfd/` (including `security`, `routing`,
/// `discovery`, `neighbors`, `service`, `measurements`, `config`, `log`)
/// is ndn-rs-only and exposes privileged surface (key generation, schema
/// edits, route changes) that must require signed commands regardless of
/// the operator's global `require_signed_commands` flag.
pub(crate) fn is_extended_module(module: &[u8]) -> bool {
    use ndn_config::nfd_command::module as m;
    let standard: [&[u8]; 6] = [m::FACES, m::FIB, m::RIB, m::CS, m::STRATEGY, m::STATUS];
    !standard.contains(&module)
}

/// Audit E.03 — effective auth gate for a parsed command. Extended modules
/// always require signed commands; standard modules use the operator's
/// `require_signed_commands` flag.
pub(crate) fn effective_require_signed(module: &[u8], require_signed_global: bool) -> bool {
    require_signed_global || is_extended_module(module)
}

/// Authorise a command Interest per audit finding E.01 / I.07 +
/// NFD `daemon/mgmt/command-authenticator.cpp`. Returns
/// `Ok(())` when the Interest is permitted to dispatch, or an
/// `Err(reason)` describing why it was rejected.
///
/// Behaviour:
/// - If `require_signed = false`, every Interest is permitted; an
///   unsigned-command warning is logged at the call site.
/// - If `require_signed = true` and `validator = None`, every
///   Interest is rejected — the operator opted in but didn't
///   wire trust anchors, which is configuration error, not a
///   silent pass.
/// - If `require_signed = true` and `validator = Some(v)`, the
///   Interest must be signed and `v.validate_interest` must return
///   `Valid`.
/// - If `replay_cache` is `Some(_)`, audit N.10's `SignatureTime`
///   window is enforced after the signature passes: timestamps must
///   be within ±`COMMAND_SIG_TIME_TOLERANCE_MS` of the local clock
///   AND strictly greater than the last accepted value for the same
///   signer.
pub(crate) async fn authorize_command(
    interest: &ndn_packet::Interest,
    validator: Option<&ndn_security::Validator>,
    require_signed: bool,
    replay_cache: Option<&CommandReplayCache>,
) -> Result<(), String> {
    if !require_signed {
        if interest.sig_info().is_none() {
            tracing::warn!(
                target: "mgmt.security",
                name = %interest.name,
                "nfd-mgmt: unsigned command accepted (require_signed_commands=false; \
                 enable in config to enforce E.01 / NFD command-authenticator parity)"
            );
        }
        return Ok(());
    }
    let Some(validator) = validator else {
        return Err(
            "command authentication required but no validator is configured".to_string(),
        );
    };
    // DigestSha256 verifies byte integrity but carries no key identity.
    // Per NFD command-authenticator.cpp, only key-backed signature types
    // (Ed25519, ECDSA, RSA, BLAKE3) are accepted when a key validator is
    // present. DigestSha256-only Interests are treated as unsigned here.
    if matches!(
        interest.sig_info().map(|s| s.sig_type),
        None | Some(ndn_packet::SignatureType::DigestSha256)
    ) {
        return Err(
            "command rejected: key-backed signature required \
             (DigestSha256 does not establish key identity)"
                .to_string(),
        );
    }
    use ndn_security::InterestValidationOutcome::*;
    match validator.validate_interest(interest).await {
        Valid => {}
        Invalid(e) => return Err(format!("invalid command signature: {e}")),
        Pending => return Err("signing certificate not yet resolved".to_string()),
    }

    // Audit N.10 — replay protection (only when the operator wired a
    // cache). Identifies the signer via the SignatureInfo's KeyLocator;
    // if the locator is missing or doesn't carry a `Name`, the command
    // is rejected (an auth path without a stable signer identity is
    // not a path that can be replay-protected).
    if let Some(cache) = replay_cache {
        let sig_info = interest
            .sig_info()
            .ok_or_else(|| "signed command missing SignatureInfo for replay check".to_string())?;
        let signer = sig_info
            .key_locator_name()
            .ok_or_else(|| {
                "signed command missing KeyLocator name for replay check".to_string()
            })
            .map(|arc_name| arc_name.as_ref().clone())?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let last_seen = cache
            .lock()
            .map_err(|_| "command replay cache poisoned".to_string())?
            .get(&signer)
            .copied();
        let accepted = check_sig_time(
            sig_info.sig_time,
            now_ms,
            last_seen,
            COMMAND_SIG_TIME_TOLERANCE_MS,
        )?;
        cache
            .lock()
            .map_err(|_| "command replay cache poisoned".to_string())?
            .insert(signer, accepted);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn run_ndn_mgmt_handler(
    handle: InProcHandle,
    engine: ForwarderEngine,
    cancel: CancellationToken,
    discovery_sd: Option<Arc<ServiceDiscoveryProtocol>>,
    discovery_claimed: Vec<Name>,
    config: Arc<ndn_config::ForwarderConfig>,
    pib: Option<Arc<FilePib>>,
    mgmt_handles: MgmtHandles,
) {
    loop {
        let raw = tokio::select! {
            _ = cancel.cancelled() => break,
            r = handle.recv() => match r {
                Some(b) => b,
                None    => break,
            },
        };

        let interest = match Interest::decode(raw) {
            Ok(i) => i,
            Err(e) => {
                tracing::warn!(target: "engine", error = %e, "nfd-mgmt: malformed Interest; skipping");
                continue;
            }
        };

        let source_face = engine.source_face_id(&interest);
        tracing::debug!(
            target: "engine",
            source_face = ?source_face,
            name = %interest.name,
            "nfd-mgmt: received command"
        );

        let parsed = match parse_command_name(&interest.name) {
            Some(p) => p,
            None => {
                let resp = ControlResponse::error(status::BAD_PARAMS, "invalid command name");
                send_response(&handle, &interest.name, &resp, mgmt_handles.command_response_signer.as_deref()).await;
                continue;
            }
        };

        // E.01 / I.07 — gate command dispatch on the operator's
        // command-authentication policy (NFD command-authenticator).
        // E.03 — extended (ndn-rs-only) modules unconditionally require
        // signed commands; the operator-level flag only relaxes the
        // standard NFD modules.
        let effective_required =
            effective_require_signed(&parsed.module, mgmt_handles.require_signed_commands);
        if let Err(reason) = authorize_command(
            &interest,
            mgmt_handles.command_validator.as_deref(),
            effective_required,
            mgmt_handles.command_replay_cache.as_ref(),
        )
        .await
        {
            let resp = ControlResponse::error(status::UNAUTHORIZED, reason);
            send_response(&handle, &interest.name, &resp, mgmt_handles.command_response_signer.as_deref()).await;
            continue;
        }

        // ControlParameters are at name[4] for ndn-cxx (NFD management v0.2 /
        // v0.3 Signed Interest style).  NDNts Signed Interest v0.3 may place
        // them in ApplicationParameters instead, so fall back to that field if
        // name-based parsing yielded nothing.
        //
        // Audit N.11 — ControlParameters MUST appear in exactly one location.
        // Signed commands have signed-region integrity over the entire wire
        // (audit A.09's signed-region calculation covers both Name and
        // AppParameters), but a peer that supplies CP in *both* locations is
        // malformed per spec: pick one. Reject with `BAD_PARAMS` to avoid
        // ambiguity that mgmt versions / proxies could resolve differently.
        let params_in_name = parsed.params.clone();
        let params_in_app = interest
            .app_parameters()
            .and_then(|app| ControlParameters::decode(app.clone()).ok());
        let params = match resolve_control_parameters(params_in_name, params_in_app) {
            Ok(opt) => opt.unwrap_or_default(),
            Err(reason) => {
                tracing::warn!(target: "engine", name = %interest.name, %reason, "nfd-mgmt: rejecting (N.11)");
                let resp = ControlResponse::error(status::BAD_PARAMS, reason);
                send_response(&handle, &interest.name, &resp, mgmt_handles.command_response_signer.as_deref()).await;
                continue;
            }
        };

        let resp = dispatch_command(
            parsed.module.as_ref(),
            parsed.verb.as_ref(),
            params,
            source_face,
            DispatchCtx {
                engine: &engine,
                cancel: &cancel,
                discovery_sd: discovery_sd.as_deref(),
                discovery_claimed: &discovery_claimed,
                config: &config,
                pib: pib.as_deref(),
                discovery_cfg: mgmt_handles.discovery_cfg.as_ref(),
                dvr_cfg: mgmt_handles.dvr_cfg.as_ref(),
                security_is_ephemeral: mgmt_handles.security_is_ephemeral,
            },
        )
        .await;

        match resp {
            MgmtResponse::Control(cr) => send_response(&handle, &interest.name, &cr, mgmt_handles.command_response_signer.as_deref()).await,
            MgmtResponse::Dataset(bytes) => {
                send_dataset(&handle, &interest.name, bytes).await;
            }
        }
    }

    tracing::info!(target: "engine", "NFD management handler stopped");
}

// ─── Command dispatch ─────────────────────────────────────────────────────────

struct DispatchCtx<'a> {
    engine: &'a ForwarderEngine,
    cancel: &'a CancellationToken,
    discovery_sd: Option<&'a ServiceDiscoveryProtocol>,
    discovery_claimed: &'a [Name],
    config: &'a ndn_config::ForwarderConfig,
    pib: Option<&'a FilePib>,
    /// Runtime-mutable discovery config (None when discovery is disabled).
    discovery_cfg: Option<&'a Arc<RwLock<DiscoveryConfig>>>,
    /// Runtime-mutable DVR config (None when DVR is not running).
    dvr_cfg: Option<&'a Arc<RwLock<DvrConfig>>>,
    /// Whether the active signing identity is ephemeral (not persisted to disk).
    security_is_ephemeral: bool,
}

async fn dispatch_command(
    module_name: &[u8],
    verb_name: &[u8],
    params: ControlParameters,
    source_face: Option<FaceId>,
    ctx: DispatchCtx<'_>,
) -> MgmtResponse {
    let DispatchCtx {
        engine,
        cancel,
        discovery_sd,
        discovery_claimed,
        config,
        pib,
        discovery_cfg,
        dvr_cfg,
        security_is_ephemeral,
    } = ctx;
    match module_name {
        m if m == module::RIB => handle_rib(verb_name, params, source_face, engine),
        m if m == module::ROUTING => handle_routing(verb_name, params, engine, dvr_cfg).into(),
        m if m == module::DISCOVERY => handle_discovery(verb_name, params, discovery_cfg).into(),
        m if m == module::FACES => handle_faces(verb_name, params, source_face, engine).await,
        m if m == module::FIB => handle_fib(verb_name, params, source_face, engine),
        m if m == module::STRATEGY => handle_strategy(verb_name, params, engine),
        m if m == module::CS => handle_cs(verb_name, params, engine).await.into(),
        m if m == module::NEIGHBORS => handle_neighbors(verb_name, engine).into(),
        m if m == module::SERVICE => handle_service(
            verb_name,
            params,
            engine,
            source_face,
            discovery_sd,
            discovery_claimed,
        )
        .into(),
        m if m == module::STATUS => handle_status(verb_name, engine, cancel).into(),
        m if m == module::MEASUREMENTS => handle_measurements(verb_name, engine).into(),
        m if m == module::CONFIG => handle_config(verb_name, config).into(),
        m if m == module::SECURITY => handle_security(
            verb_name,
            params,
            pib,
            engine,
            config,
            security_is_ephemeral,
        )
        .await
        .into(),
        m if m == module::LOG => handle_log(verb_name, params).into(),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown module").into(),
    }
}

// ─── RIB module ───────────────────────────────────────────────────────────────

fn handle_rib(
    verb_name: &[u8],
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> MgmtResponse {
    match verb_name {
        v if v == verb::REGISTER => rib_register(params, source_face, engine).into(),
        v if v == verb::UNREGISTER => rib_unregister(params, source_face, engine).into(),
        v if v == verb::LIST => MgmtResponse::Dataset(rib_list_dataset(engine)),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown rib verb").into(),
    }
}

fn rib_register(
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let name = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    // Block non-management faces from registering reserved prefixes.
    if is_reserved_name(&name) && !is_management_face(source_face, engine) {
        return ControlResponse::error(
            status::UNAUTHORIZED,
            format!("prefix {name} is reserved for operator use"),
        );
    }

    let face_id = match resolve_face_id(&params, source_face) {
        Ok(id) => id,
        Err(resp) => return *resp,
    };
    let cost = params.cost.unwrap_or(0) as u32;
    let orig = params.origin.unwrap_or(origin::APP);
    let flags = params.flags.unwrap_or(route_flags::CHILD_INHERIT);
    let expires_at = params
        .expiration_period
        .map(|ms| Instant::now() + Duration::from_millis(ms));

    engine.rib().add(
        &name,
        RibRoute {
            face_id,
            origin: orig,
            cost,
            flags,
            expires_at,
        },
    );
    engine.rib().apply_to_fib(&name, &engine.fib());

    tracing::info!(target: "mgmt.rib", prefix = %name, face = face_id.0, cost, origin = orig, "rib/register");

    let echo = ControlParameters {
        name: Some(name),
        face_id: Some(face_id.0 as u64),
        origin: Some(orig),
        cost: Some(cost as u64),
        flags: Some(flags),
        expiration_period: params.expiration_period,
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn rib_unregister(
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let name = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    let face_id = match resolve_face_id(&params, source_face) {
        Ok(id) => id,
        Err(resp) => return *resp,
    };

    // If origin is specified, remove only that (name, face_id, origin) entry.
    // If omitted, remove all origins for (name, face_id) — NFD-compatible behaviour.
    let orig = params.origin;
    if let Some(o) = orig {
        engine.rib().remove(&name, face_id, o);
    } else {
        engine.rib().remove_nexthop(&name, face_id);
    }
    engine.rib().apply_to_fib(&name, &engine.fib());

    tracing::info!(target: "mgmt.rib", prefix = %name, face = face_id.0, "rib/unregister");

    let echo = ControlParameters {
        name: Some(name),
        face_id: Some(face_id.0 as u64),
        origin: Some(orig.unwrap_or(origin::APP)),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn rib_list_dataset(engine: &ForwarderEngine) -> bytes::Bytes {
    let entries = engine.rib().dump();
    let mut buf = bytes::BytesMut::new();
    for (name, routes) in &entries {
        let rib_entry = nfd_dataset::RibEntry {
            name: name.clone(),
            routes: routes
                .iter()
                .map(|r| {
                    let expiration_period = r.expires_at.map(|exp| {
                        exp.saturating_duration_since(std::time::Instant::now())
                            .as_millis() as u64
                    });
                    nfd_dataset::Route {
                        face_id: r.face_id.0 as u64,
                        origin: r.origin,
                        cost: r.cost as u64,
                        flags: r.flags,
                        expiration_period,
                    }
                })
                .collect(),
        };
        buf.extend_from_slice(&rib_entry.encode());
    }
    buf.freeze()
}

// ─── Routing module ───────────────────────────────────────────────────────────

fn handle_routing(
    verb_name: &[u8],
    params: ControlParameters,
    engine: &ForwarderEngine,
    dvr_cfg: Option<&Arc<RwLock<DvrConfig>>>,
) -> ControlResponse {
    match verb_name {
        v if v == verb::LIST => routing_list(engine),
        v if v == b"disable" => routing_disable(params, engine),
        v if v == verb::DVR_STATUS => routing_dvr_status(dvr_cfg, engine),
        v if v == verb::DVR_CONFIG => routing_dvr_config(params, dvr_cfg),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown routing verb"),
    }
}

fn routing_list(engine: &ForwarderEngine) -> ControlResponse {
    let origins = engine.routing().running_origins();
    let mut text = format!("{} routing protocol(s)\n", origins.len());
    let mut sorted = origins;
    sorted.sort_unstable();
    for origin in &sorted {
        let name = match *origin {
            ndn_config::control_parameters::origin::DVR => "dvr",
            ndn_config::control_parameters::origin::AUTOCONF => "autoconf",
            ndn_config::control_parameters::origin::NLSR => "nlsr",
            ndn_config::control_parameters::origin::PREFIX_ANN => "prefix-ann",
            ndn_config::control_parameters::origin::STATIC => "static",
            _ => "custom",
        };
        text.push_str(&format!("  origin={origin} ({name})\n"));
    }
    ControlResponse::ok_empty(text)
}

fn routing_disable(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let origin = match params.origin {
        Some(o) => o,
        None => return ControlResponse::error(status::BAD_PARAMS, "Origin is required"),
    };
    if engine.routing().disable(origin) {
        tracing::info!(target: "mgmt.rib", origin, "routing/disable");
        let echo = ControlParameters {
            origin: Some(origin),
            ..Default::default()
        };
        ControlResponse::ok("OK", echo)
    } else {
        ControlResponse::error(
            status::NOT_FOUND,
            format!("no protocol running with origin {origin}"),
        )
    }
}

fn routing_dvr_status(
    dvr_cfg: Option<&Arc<RwLock<DvrConfig>>>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let Some(cfg_lock) = dvr_cfg else {
        return ControlResponse::error(status::NOT_FOUND, "DVR not running");
    };
    let cfg = cfg_lock.read().unwrap();
    // Count DVR-learned routes in the RIB.
    let dvr_route_count: usize = engine
        .rib()
        .dump()
        .iter()
        .map(|(_, routes)| {
            routes
                .iter()
                .filter(|r| r.origin == ndn_config::control_parameters::origin::DVR)
                .count()
        })
        .sum();
    let text = format!(
        "dvr: enabled\nupdate_interval_ms: {}\nroute_ttl_ms: {}\nroute_count: {}\n",
        cfg.update_interval.as_millis(),
        cfg.route_ttl.as_millis(),
        dvr_route_count,
    );
    ControlResponse::ok_empty(text)
}

fn routing_dvr_config(
    params: ControlParameters,
    dvr_cfg: Option<&Arc<RwLock<DvrConfig>>>,
) -> ControlResponse {
    let Some(cfg_lock) = dvr_cfg else {
        return ControlResponse::error(status::NOT_FOUND, "DVR not running");
    };
    // Parse updates from the `uri` field as a URL query string:
    // "update_interval_ms=30000&route_ttl_ms=90000"
    let Some(query) = &params.uri else {
        // No params — return current config.
        let cfg = cfg_lock.read().unwrap();
        let echo = ControlParameters {
            uri: Some(format!(
                "update_interval_ms={}&route_ttl_ms={}",
                cfg.update_interval.as_millis(),
                cfg.route_ttl.as_millis(),
            )),
            ..Default::default()
        };
        return ControlResponse::ok("OK", echo);
    };
    let mut cfg = cfg_lock.write().unwrap();
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or("").trim();
        let val = parts.next().unwrap_or("").trim();
        match key {
            "update_interval_ms" => {
                if let Ok(ms) = val.parse::<u64>() {
                    cfg.update_interval = Duration::from_millis(ms);
                }
            }
            "route_ttl_ms" => {
                if let Ok(ms) = val.parse::<u64>() {
                    cfg.route_ttl = Duration::from_millis(ms);
                }
            }
            _ => {}
        }
    }
    tracing::info!(
        target: "routing.dvr",
        update_interval_ms = cfg.update_interval.as_millis(),
        route_ttl_ms = cfg.route_ttl.as_millis(),
        "routing/dvr-config updated"
    );
    let echo = ControlParameters {
        uri: Some(format!(
            "update_interval_ms={}&route_ttl_ms={}",
            cfg.update_interval.as_millis(),
            cfg.route_ttl.as_millis(),
        )),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

// ─── Discovery module ─────────────────────────────────────────────────────────

fn handle_discovery(
    verb_name: &[u8],
    params: ControlParameters,
    discovery_cfg: Option<&Arc<RwLock<DiscoveryConfig>>>,
) -> ControlResponse {
    match verb_name {
        v if v == b"status" => discovery_status(discovery_cfg),
        v if v == verb::CONFIG => discovery_config_set(params, discovery_cfg),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown discovery verb"),
    }
}

fn discovery_status(discovery_cfg: Option<&Arc<RwLock<DiscoveryConfig>>>) -> ControlResponse {
    let Some(cfg_lock) = discovery_cfg else {
        return ControlResponse::error(status::NOT_FOUND, "discovery not enabled");
    };
    let cfg = cfg_lock.read().unwrap();
    let strategy_str = match cfg.hello_strategy {
        HelloStrategyKind::Backoff => "backoff",
        HelloStrategyKind::Reactive => "reactive",
        HelloStrategyKind::Passive => "passive",
    };
    let prefix_ann_str = match cfg.prefix_announcement {
        PrefixAnnouncementMode::Static => "static",
        PrefixAnnouncementMode::InHello => "in-hello",
        PrefixAnnouncementMode::NlsrLsa => "nlsr-lsa",
    };
    let text = format!(
        "discovery: enabled\n\
         hello_strategy: {strategy_str}\n\
         hello_interval_base_ms: {}\n\
         hello_interval_max_ms: {}\n\
         hello_jitter: {:.2}\n\
         liveness_timeout_ms: {}\n\
         liveness_miss_count: {}\n\
         probe_timeout_ms: {}\n\
         prefix_announcement: {prefix_ann_str}\n\
         auto_create_faces: {}\n\
         tick_interval_ms: {}\n",
        cfg.hello_interval_base.as_millis(),
        cfg.hello_interval_max.as_millis(),
        cfg.hello_jitter,
        cfg.liveness_timeout.as_millis(),
        cfg.liveness_miss_count,
        cfg.probe_timeout.as_millis(),
        cfg.auto_create_faces,
        cfg.tick_interval.as_millis(),
    );
    ControlResponse::ok_empty(text)
}

fn discovery_config_set(
    params: ControlParameters,
    discovery_cfg: Option<&Arc<RwLock<DiscoveryConfig>>>,
) -> ControlResponse {
    let Some(cfg_lock) = discovery_cfg else {
        return ControlResponse::error(status::NOT_FOUND, "discovery not enabled");
    };
    let Some(query) = &params.uri else {
        // No params — return current config as query string.
        return discovery_status(discovery_cfg);
    };
    {
        let mut cfg = cfg_lock.write().unwrap();
        for pair in query.split('&') {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next().unwrap_or("").trim();
            let val = parts.next().unwrap_or("").trim();
            match key {
                "hello_interval_base_ms" => {
                    if let Ok(ms) = val.parse::<u64>() {
                        cfg.hello_interval_base = Duration::from_millis(ms);
                    }
                }
                "hello_interval_max_ms" => {
                    if let Ok(ms) = val.parse::<u64>() {
                        cfg.hello_interval_max = Duration::from_millis(ms);
                    }
                }
                "hello_jitter" => {
                    if let Ok(v) = val.parse::<f32>() {
                        cfg.hello_jitter = v.clamp(0.0, 0.5);
                    }
                }
                "liveness_timeout_ms" => {
                    if let Ok(ms) = val.parse::<u64>() {
                        cfg.liveness_timeout = Duration::from_millis(ms);
                    }
                }
                "liveness_miss_count" => {
                    if let Ok(v) = val.parse::<u32>() {
                        cfg.liveness_miss_count = v;
                    }
                }
                "probe_timeout_ms" => {
                    if let Ok(ms) = val.parse::<u64>() {
                        cfg.probe_timeout = Duration::from_millis(ms);
                    }
                }
                "auto_create_faces" => {
                    cfg.auto_create_faces = val == "true" || val == "1";
                }
                _ => {}
            }
        }
        tracing::info!(target: "discovery", params = %query, "discovery/config updated");
    }
    discovery_status(discovery_cfg)
}

// ─── Faces module ─────────────────────────────────────────────────────────────

async fn handle_faces(
    verb_name: &[u8],
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> MgmtResponse {
    match verb_name {
        v if v == verb::CREATE => faces_create(params, source_face, engine).await.into(),
        v if v == verb::DESTROY => faces_destroy(params, source_face, engine).into(),
        v if v == verb::LIST => MgmtResponse::Dataset(faces_list_dataset(engine)),
        v if v == verb::COUNTERS => faces_counters(engine).into(),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown faces verb").into(),
    }
}

async fn faces_create(
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let uri = match &params.uri {
        Some(u) => u.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Uri is required"),
    };

    if let Some(shm_name) = uri.strip_prefix("shm://") {
        return faces_create_shm(shm_name, params.mtu, source_face, engine);
    }

    if let Some(addr_str) = uri.strip_prefix("udp4://") {
        return faces_create_udp(addr_str, engine).await;
    }

    if let Some(addr_str) = uri.strip_prefix("tcp4://") {
        return faces_create_tcp(addr_str, engine).await;
    }

    ControlResponse::error(status::BAD_PARAMS, format!("unsupported URI scheme: {uri}"))
}

async fn faces_create_udp(addr_str: &str, engine: &ForwarderEngine) -> ControlResponse {
    let peer: std::net::SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                format!("invalid UDP address '{addr_str}': {e}"),
            );
        }
    };

    let face_id = engine.faces().alloc_id();
    let local: std::net::SocketAddr = if peer.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };

    match ndn_faces::net::UdpFace::bind(local, peer, face_id).await {
        Ok(face) => {
            let local_uri = face.local_uri().unwrap_or_default();
            let cancel = CancellationToken::new();
            engine.add_face_with_persistency(face, cancel, FacePersistency::Persistent);
            tracing::info!(target: "mgmt.face", face = face_id.0, remote = %peer, "faces/create udp4");

            let echo = ControlParameters {
                face_id: Some(face_id.0 as u64),
                uri: Some(format!("udp4://{peer}")),
                local_uri: Some(local_uri),
                ..Default::default()
            };
            ControlResponse::ok("OK", echo)
        }
        Err(e) => {
            tracing::warn!(target: "mgmt.face", error = %e, remote = %peer, "faces/create udp4 failed");
            ControlResponse::error(
                status::SERVER_ERROR,
                format!("UDP face creation failed: {e}"),
            )
        }
    }
}

async fn faces_create_tcp(addr_str: &str, engine: &ForwarderEngine) -> ControlResponse {
    let peer: std::net::SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                format!("invalid TCP address '{addr_str}': {e}"),
            );
        }
    };

    let face_id = engine.faces().alloc_id();

    match ndn_faces::net::tcp_face_connect(face_id, peer).await {
        Ok(face) => {
            let local_uri = face.local_uri().unwrap_or_default();
            let cancel = CancellationToken::new();
            engine.add_face_with_persistency(face, cancel, FacePersistency::Persistent);
            tracing::info!(target: "mgmt.face", face = face_id.0, remote = %peer, "faces/create tcp4");

            let echo = ControlParameters {
                face_id: Some(face_id.0 as u64),
                uri: Some(format!("tcp4://{peer}")),
                local_uri: Some(local_uri),
                ..Default::default()
            };
            ControlResponse::ok("OK", echo)
        }
        Err(e) => {
            tracing::warn!(target: "mgmt.face", error = %e, remote = %peer, "faces/create tcp4 failed");
            ControlResponse::error(
                status::SERVER_ERROR,
                format!("TCP face creation failed: {e}"),
            )
        }
    }
}

#[cfg(all(unix, feature = "spsc-shm"))]
fn faces_create_shm(
    shm_name: &str,
    mtu: Option<u64>,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let face_id = engine.faces().alloc_id();

    // If the app announced its expected packet size via ControlParameters.mtu,
    // size the SHM slot to cover it. Otherwise use the default slot size,
    // which already covers Data packets up to a 256 KiB content body.
    let face_result = match mtu {
        Some(m) => ndn_faces::local::shm::spsc::SpscFace::create_for_mtu(
            face_id,
            shm_name,
            m as usize,
        ),
        None => ndn_faces::local::ShmFace::create(face_id, shm_name),
    };
    match face_result {
        Ok(face) => {
            // Use a child of the control face's cancel token so that when the
            // control face disconnects, this SHM face is also cancelled and
            // cleaned up (FIB routes removed, face removed from table).
            let cancel = source_face
                .and_then(|sf| engine.face_token(sf))
                .map(|t| t.child_token())
                .unwrap_or_default();
            // SHM faces are on-demand: when the control face disconnects
            // (app exits), the child cancel token fires and the face is
            // fully cleaned up (SHM region unlinked, FIB routes removed).
            engine.add_face(face, cancel);
            tracing::info!(target: "mgmt.face", face = face_id.0, shm = shm_name, mtu = ?mtu, "faces/create shm");

            let echo = ControlParameters {
                face_id: Some(face_id.0 as u64),
                uri: Some(format!("shm://{shm_name}")),
                mtu,
                ..Default::default()
            };
            ControlResponse::ok("OK", echo)
        }
        Err(e) => {
            tracing::warn!(target: "mgmt.face", error = %e, shm = shm_name, "faces/create shm failed");
            ControlResponse::error(status::SERVER_ERROR, format!("SHM creation failed: {e}"))
        }
    }
}

#[cfg(not(all(unix, feature = "spsc-shm")))]
fn faces_create_shm(
    _shm_name: &str,
    _mtu: Option<u64>,
    _source_face: Option<FaceId>,
    _engine: &ForwarderEngine,
) -> ControlResponse {
    ControlResponse::error(
        status::SERVER_ERROR,
        "SHM faces not supported on this platform",
    )
}

fn faces_destroy(
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let face_id = match params.face_id {
        Some(id) => FaceId(id as u32),
        None => return ControlResponse::error(status::BAD_PARAMS, "FaceId is required"),
    };

    let target = match engine.faces().get(face_id) {
        Some(f) => f,
        None => {
            return ControlResponse::error(
                status::NOT_FOUND,
                format!("face {} does not exist", face_id.0),
            );
        }
    };

    // Non-management faces cannot destroy management faces.
    if target.kind().is_management() && !is_management_face(source_face, engine) {
        return ControlResponse::error(
            status::UNAUTHORIZED,
            "cannot destroy a management face from a non-management face",
        );
    }

    // Cancel the face's token — this triggers run_face_reader cleanup which:
    // 1. Removes all FIB nexthops pointing to this face
    // 2. Propagates cancellation to child faces (e.g. SHM)
    // 3. Removes the face from the face table
    if let Some(token) = engine.face_token(face_id) {
        token.cancel();
    } else {
        // No token (shouldn't happen for dynamic faces) — fall back to manual cleanup.
        engine.fib().remove_face(face_id);
        engine.faces().remove(face_id);
    }

    tracing::info!(target: "mgmt.face", face = face_id.0, "faces/destroy");

    let echo = ControlParameters {
        face_id: Some(face_id.0 as u64),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn faces_list_dataset(engine: &ForwarderEngine) -> bytes::Bytes {
    use std::sync::atomic::Ordering;
    let entries = engine.faces().face_info();
    let face_states = engine.face_states();
    let mut buf = bytes::BytesMut::new();
    for info in &entries {
        let state = face_states.get(&info.id);
        let persistency = state
            .as_ref()
            .map(|s| s.persistency)
            .unwrap_or(FacePersistency::OnDemand);
        let face_persistency = match persistency {
            FacePersistency::Persistent => 0,
            FacePersistency::OnDemand => 1,
            FacePersistency::Permanent => 2,
        };
        let (n_in_interests, n_in_data, n_out_interests, n_out_data, n_in_bytes, n_out_bytes) =
            state
                .as_ref()
                .map(|s| {
                    (
                        s.counters.in_interests.load(Ordering::Relaxed),
                        s.counters.in_data.load(Ordering::Relaxed),
                        s.counters.out_interests.load(Ordering::Relaxed),
                        s.counters.out_data.load(Ordering::Relaxed),
                        s.counters.in_bytes.load(Ordering::Relaxed),
                        s.counters.out_bytes.load(Ordering::Relaxed),
                    )
                })
                .unwrap_or_default();
        let face_scope = if info.kind.scope() == FaceScope::Local {
            1
        } else {
            0
        };
        // Multi-access link types: EtherMulticast and Multicast faces.
        let link_type = match info.kind {
            FaceKind::EtherMulticast | FaceKind::Multicast => 1,
            _ => 0,
        };
        // Local faces have no remote_uri; use an "internal://<kind>" scheme so
        // the client can distinguish them from network faces.
        let uri = info
            .remote_uri
            .clone()
            .unwrap_or_else(|| format!("internal://{}", info.kind));
        let fs = nfd_dataset::FaceStatus {
            face_id: info.id.0 as u64,
            uri,
            local_uri: info.local_uri.clone().unwrap_or_default(),
            face_scope,
            face_persistency,
            link_type,
            mtu: None,
            base_congestion_marking_interval: None,
            default_congestion_threshold: None,
            n_in_interests,
            n_in_data,
            n_in_nacks: 0,
            n_out_interests,
            n_out_data,
            n_out_nacks: 0,
            n_in_bytes,
            n_out_bytes,
        };
        buf.extend_from_slice(&fs.encode());
    }
    buf.freeze()
}

// ─── FIB module ───────────────────────────────────────────────────────────────

fn handle_fib(
    verb_name: &[u8],
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> MgmtResponse {
    match verb_name {
        v if v == verb::ADD_NEXTHOP => fib_add_nexthop(params, source_face, engine).into(),
        v if v == verb::REMOVE_NEXTHOP => fib_remove_nexthop(params, source_face, engine).into(),
        v if v == verb::LIST => MgmtResponse::Dataset(fib_list_dataset(engine)),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown fib verb").into(),
    }
}

fn fib_add_nexthop(
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let name = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    // Block non-management faces from injecting nexthops into reserved prefixes.
    if is_reserved_name(&name) && !is_management_face(source_face, engine) {
        return ControlResponse::error(
            status::UNAUTHORIZED,
            format!("prefix {name} is reserved for operator use"),
        );
    }

    let face_id = match resolve_face_id(&params, source_face) {
        Ok(id) => id,
        Err(resp) => return *resp,
    };
    let cost = params.cost.unwrap_or(0) as u32;

    engine.fib().add_nexthop(&name, face_id, cost);
    tracing::info!(target: "mgmt.fib", prefix = %name, face = face_id.0, cost, "fib/add-nexthop");

    let echo = ControlParameters {
        name: Some(name),
        face_id: Some(face_id.0 as u64),
        cost: Some(cost as u64),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn fib_remove_nexthop(
    params: ControlParameters,
    source_face: Option<FaceId>,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let name = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    let face_id = match resolve_face_id(&params, source_face) {
        Ok(id) => id,
        Err(resp) => return *resp,
    };

    engine.fib().remove_nexthop(&name, face_id);
    tracing::info!(target: "mgmt.fib", prefix = %name, face = face_id.0, "fib/remove-nexthop");

    let echo = ControlParameters {
        name: Some(name),
        face_id: Some(face_id.0 as u64),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn fib_list_dataset(engine: &ForwarderEngine) -> bytes::Bytes {
    let routes = engine.fib().dump();
    let mut buf = bytes::BytesMut::new();
    for (name, entry) in &routes {
        let fib_entry = nfd_dataset::FibEntry {
            name: name.clone(),
            nexthops: entry
                .nexthops
                .iter()
                .map(|nh| nfd_dataset::NextHopRecord {
                    face_id: nh.face_id.0 as u64,
                    cost: nh.cost as u64,
                })
                .collect(),
        };
        buf.extend_from_slice(&fib_entry.encode());
    }
    buf.freeze()
}

// ─── Strategy-choice module ──────────────────────────────────────────────────

fn handle_strategy(
    verb_name: &[u8],
    params: ControlParameters,
    engine: &ForwarderEngine,
) -> MgmtResponse {
    match verb_name {
        v if v == verb::SET => strategy_set(params, engine).into(),
        v if v == verb::UNSET => strategy_unset(params, engine).into(),
        v if v == verb::LIST => MgmtResponse::Dataset(strategy_list_dataset(engine)),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown strategy-choice verb").into(),
    }
}

/// Instantiate a strategy by its NFD-style name.
///
/// Known strategies:
/// - `/localhost/nfd/strategy/best-route`
/// - `/localhost/nfd/strategy/multicast`
fn create_strategy_by_name(name: &Name) -> Option<Arc<dyn ErasedStrategy>> {
    let comps = name.components();
    // Expect /localhost/nfd/strategy/<name> — match on the last component.
    let short_name = if comps.len() >= 4
        && comps[0].value.as_ref() == b"localhost"
        && comps[1].value.as_ref() == b"nfd"
        && comps[2].value.as_ref() == b"strategy"
    {
        comps[3].value.as_ref()
    } else if comps.len() == 1 {
        // Allow bare name like just "best-route".
        comps[0].value.as_ref()
    } else {
        return None;
    };

    match short_name {
        b"best-route" => Some(Arc::new(BestRouteStrategy::new())),
        b"multicast" => Some(Arc::new(MulticastStrategy::new())),
        _ => None,
    }
}

fn strategy_set(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let prefix = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    let strategy_name = match &params.strategy {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Strategy is required"),
    };

    let strategy = match create_strategy_by_name(&strategy_name) {
        Some(s) => s,
        None => {
            return ControlResponse::error(
                status::NOT_FOUND,
                format!("unknown strategy: {}", strategy_name),
            );
        }
    };

    engine.strategy_table().insert(&prefix, strategy);

    tracing::info!(
        target: "mgmt.strategy",
        prefix = %prefix,
        strategy = %strategy_name,
        "strategy-choice/set"
    );

    let echo = ControlParameters {
        name: Some(prefix),
        strategy: Some(strategy_name),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn strategy_unset(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let prefix = match &params.name {
        Some(n) => n.clone(),
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    // Prevent unsetting the root strategy.
    if prefix.is_empty() {
        return ControlResponse::error(status::BAD_PARAMS, "cannot unset strategy at root prefix");
    }

    engine.strategy_table().remove(&prefix);

    tracing::info!(target: "mgmt.strategy", prefix = %prefix, "strategy-choice/unset");

    let echo = ControlParameters {
        name: Some(prefix),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn strategy_list_dataset(engine: &ForwarderEngine) -> bytes::Bytes {
    let entries = engine.strategy_table().dump();
    let mut buf = bytes::BytesMut::new();
    for (prefix, strategy) in &entries {
        let sc = nfd_dataset::StrategyChoice {
            name: prefix.clone(),
            strategy: strategy.name().clone(),
        };
        buf.extend_from_slice(&sc.encode());
    }
    buf.freeze()
}

// ─── CS module ───────────────────────────────────────────────────────────────

async fn handle_cs(
    verb_name: &[u8],
    params: ControlParameters,
    engine: &ForwarderEngine,
) -> ControlResponse {
    match verb_name {
        v if v == verb::CONFIG => cs_config(params, engine),
        v if v == verb::INFO => cs_info(engine),
        v if v == verb::ERASE => cs_erase(params, engine).await,
        _ => ControlResponse::error(status::NOT_FOUND, "unknown cs verb"),
    }
}

fn cs_config(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let cs = engine.cs();

    // If capacity is provided, update it at runtime.
    if let Some(new_cap) = params.capacity {
        cs.set_capacity(new_cap as usize);
        tracing::info!(target: "mgmt.cs", capacity = new_cap, "cs capacity updated");
    }

    let cap = cs.capacity();
    let echo = ControlParameters {
        capacity: Some(cap.max_bytes as u64),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn cs_info(engine: &ForwarderEngine) -> ControlResponse {
    let cs = engine.cs();
    let cap = cs.capacity();
    let n_entries = cs.len();
    let current = cs.current_bytes();
    let stats = cs.stats();
    let variant = cs.variant_name();

    let text = format!(
        "capacity={}B entries={} used={}B hits={} misses={} variant={}",
        cap.max_bytes, n_entries, current, stats.hits, stats.misses, variant,
    );
    ControlResponse::ok_empty(text)
}

async fn cs_erase(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let Some(ref name) = params.name else {
        return ControlResponse::error(status::BAD_PARAMS, "missing Name parameter");
    };
    let cs = engine.cs();
    let limit = params.count.map(|c| c as usize);
    let erased = cs.evict_prefix_erased(name, limit).await;

    let echo = ControlParameters {
        name: params.name,
        count: Some(erased as u64),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

// ─── Status module ────────────────────────────────────────────────────────────

fn handle_status(
    verb_name: &[u8],
    engine: &ForwarderEngine,
    cancel: &CancellationToken,
) -> ControlResponse {
    match verb_name {
        b"general" => {
            let n_faces = engine.faces().face_entries().len();
            let n_fib = engine.fib().dump().len();
            let n_pit = engine.pit().len();
            let n_cs = engine.cs().len();

            let text = format!("faces={n_faces} fib={n_fib} pit={n_pit} cs={n_cs}");
            ControlResponse::ok_empty(text)
        }
        b"shutdown" => {
            tracing::info!(target: "engine", "status/shutdown requested");
            cancel.cancel();
            ControlResponse::ok_empty("OK")
        }
        _ => ControlResponse::error(status::NOT_FOUND, "unknown status verb"),
    }
}

// ─── Neighbors module ─────────────────────────────────────────────────────────

fn handle_neighbors(verb_name: &[u8], engine: &ForwarderEngine) -> ControlResponse {
    match verb_name {
        v if v == verb::LIST => neighbors_list(engine),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown neighbors verb"),
    }
}

fn neighbors_list(engine: &ForwarderEngine) -> ControlResponse {
    let entries = engine.neighbors().all();
    let mut text = format!("{} neighbors\n", entries.len());
    for e in &entries {
        let face_ids: Vec<String> = e.faces.iter().map(|(id, _, _)| id.0.to_string()).collect();
        let state_str = match &e.state {
            NeighborState::Established { last_seen } => {
                let age_s = last_seen.elapsed().as_secs_f64();
                format!("state=Established  last_seen={:.1}s ago", age_s)
            }
            NeighborState::Stale {
                miss_count,
                last_seen,
            } => {
                let age_s = last_seen.elapsed().as_secs_f64();
                format!(
                    "state=Stale  miss={}  last_seen={:.1}s ago",
                    miss_count, age_s
                )
            }
            NeighborState::Probing { attempts, .. } => {
                format!("state=Probing  attempts={}", attempts)
            }
            NeighborState::Absent => "state=Absent".to_string(),
        };
        let rtt_str = match e.rtt_us {
            Some(us) => format!("  rtt={}us", us),
            None => "  rtt=None".to_string(),
        };
        text.push_str(&format!(
            "  {}  {}{}  faces=[{}]\n",
            e.node_name,
            state_str,
            rtt_str,
            face_ids.join(","),
        ));
    }
    ControlResponse::ok_empty(text)
}

// ─── Service module ───────────────────────────────────────────────────────────

fn handle_service(
    verb_name: &[u8],
    params: ControlParameters,
    engine: &ForwarderEngine,
    source_face: Option<FaceId>,
    discovery_sd: Option<&ServiceDiscoveryProtocol>,
    discovery_claimed: &[Name],
) -> ControlResponse {
    let sd = match discovery_sd {
        Some(s) => s,
        None => {
            return ControlResponse::error(status::NOT_FOUND, "service discovery is not enabled");
        }
    };
    match verb_name {
        v if v == verb::LIST => service_list(sd),
        v if v == verb::BROWSE => service_browse(params, sd),
        v if v == verb::ANNOUNCE => {
            service_announce(params, sd, engine, source_face, discovery_claimed)
        }
        v if v == verb::WITHDRAW => service_withdraw(params, sd),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown service verb"),
    }
}

fn service_list(sd: &ServiceDiscoveryProtocol) -> ControlResponse {
    let records = sd.local_records();
    let mut text = format!("{} services\n", records.len());
    for r in &records {
        text.push_str(&format!(
            "  {}  node={}  freshness={}ms\n",
            r.announced_prefix, r.node_name, r.freshness_ms,
        ));
    }
    ControlResponse::ok_empty(text)
}

fn service_browse(params: ControlParameters, sd: &ServiceDiscoveryProtocol) -> ControlResponse {
    let filter = params.name;
    let records = sd.all_records();
    let filtered: Vec<_> = records
        .iter()
        .filter(|r| {
            filter
                .as_ref()
                .is_none_or(|p| r.announced_prefix.has_prefix(p))
        })
        .collect();
    let mut text = format!("{} services\n", filtered.len());
    for r in &filtered {
        text.push_str(&format!(
            "  {}  node={}  freshness={}ms\n",
            r.announced_prefix, r.node_name, r.freshness_ms,
        ));
    }
    ControlResponse::ok_empty(text)
}

fn service_announce(
    params: ControlParameters,
    sd: &ServiceDiscoveryProtocol,
    engine: &ForwarderEngine,
    source_face: Option<FaceId>,
    discovery_claimed: &[Name],
) -> ControlResponse {
    let prefix = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    // Block announcements that would shadow a discovery-owned prefix.
    // Non-management faces in particular cannot claim prefixes already owned by
    // the discovery layer (e.g. /ndn/local/nd/, /ndn/local/sd/services/).
    if !is_management_face(source_face, engine) {
        let shadows_discovery = discovery_claimed
            .iter()
            .any(|cp| prefix.has_prefix(cp) || cp.has_prefix(&prefix));
        if shadows_discovery {
            return ControlResponse::error(
                status::UNAUTHORIZED,
                format!("prefix {prefix} overlaps with a discovery-owned namespace"),
            );
        }
    }

    // Also block reserved namespaces from non-management faces.
    if is_reserved_name(&prefix) && !is_management_face(source_face, engine) {
        return ControlResponse::error(
            status::UNAUTHORIZED,
            format!("prefix {prefix} is reserved for operator use"),
        );
    }

    // Derive node name from any existing service record (first one available).
    // If no records exist yet, use the prefix itself as a placeholder node name.
    let node_name = sd
        .local_records()
        .into_iter()
        .next()
        .map(|r| r.node_name)
        .unwrap_or_else(|| prefix.clone());

    // Find the FIB nexthop face for this prefix — that is the app's data face.
    // Linking the service record to that face means it is automatically
    // withdrawn when the app's face goes down (app exit, crash, disconnect),
    // without requiring the app to call service/withdraw explicitly.
    //
    // If no FIB route exists for the prefix yet, publish permanently and let
    // the operator call service/withdraw manually.
    let record = ServiceRecord::new(prefix.clone(), node_name);
    let owner_face = engine.fib().lpm(&prefix).and_then(|e| {
        // Prefer a non-management nexthop (the app's data face).
        e.nexthops_excluding(source_face.unwrap_or(FaceId(u32::MAX)))
            .into_iter()
            .next()
            .map(|nh| nh.face_id)
    });

    if let Some(face) = owner_face {
        sd.publish_with_owner(record, face);
        tracing::info!(target: "discovery", prefix = %prefix, owner_face = ?face, "service/announce (owned by face)");
    } else {
        sd.publish(record);
        tracing::info!(target: "discovery", prefix = %prefix, "service/announce (permanent — no FIB route found)");
    }

    let echo = ControlParameters {
        name: Some(prefix),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

fn service_withdraw(params: ControlParameters, sd: &ServiceDiscoveryProtocol) -> ControlResponse {
    let prefix = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };

    sd.withdraw(&prefix);
    tracing::info!(target: "discovery", prefix = %prefix, "service/withdraw");

    let echo = ControlParameters {
        name: Some(prefix),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

// ─── Security helpers ─────────────────────────────────────────────────────────

/// Reserved name prefixes that only management (operator) faces may register.
const RESERVED_PREFIXES: &[&str] = &["/ndn/local", "/localhost/nfd"];

/// Return `true` if `name` has a prefix that is reserved for the router.
fn is_reserved_name(name: &Name) -> bool {
    RESERVED_PREFIXES.iter().any(|r| {
        Name::from_str(r)
            .map(|p| name.has_prefix(&p) || *name == p)
            .unwrap_or(false)
    })
}

/// Return `true` if the source face has operator-level management trust.
///
/// A face is trusted if:
/// - It is `FaceKind::Management` (connected through the management socket), OR
/// - No source face is known (internally generated command).
fn is_management_face(source_face: Option<FaceId>, engine: &ForwarderEngine) -> bool {
    match source_face {
        None => true, // internal / no source
        Some(fid) => engine
            .faces()
            .get(fid)
            .map(|f| f.kind().is_management())
            .unwrap_or(false),
    }
}

// ─── Faces counters ───────────────────────────────────────────────────────────

fn faces_counters(engine: &ForwarderEngine) -> ControlResponse {
    use std::sync::atomic::Ordering;
    let face_states = engine.face_states();
    let entries = engine.faces().face_info();
    let mut text = format!("{} faces\n", entries.len());
    for info in &entries {
        if let Some(s) = face_states.get(&info.id) {
            text.push_str(&format!(
                "  faceid={} in_interests={} in_data={} out_interests={} out_data={} in_bytes={} out_bytes={}\n",
                info.id.0,
                s.counters.in_interests.load(Ordering::Relaxed),
                s.counters.in_data.load(Ordering::Relaxed),
                s.counters.out_interests.load(Ordering::Relaxed),
                s.counters.out_data.load(Ordering::Relaxed),
                s.counters.in_bytes.load(Ordering::Relaxed),
                s.counters.out_bytes.load(Ordering::Relaxed),
            ));
        }
    }
    ControlResponse::ok_empty(text)
}

// ─── Measurements module ──────────────────────────────────────────────────────

fn handle_measurements(verb_name: &[u8], engine: &ForwarderEngine) -> ControlResponse {
    match verb_name {
        v if v == verb::LIST => measurements_list(engine),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown measurements verb"),
    }
}

fn measurements_list(engine: &ForwarderEngine) -> ControlResponse {
    let entries = engine.measurements().dump();
    let mut text = format!("{} entries\n", entries.len());
    for (prefix, entry) in &entries {
        let face_rtts: Vec<String> = entry
            .rtt_per_face
            .iter()
            .map(|(fid, rtt)| format!("face{}={:.1}ms", fid.0, rtt.srtt_ns / 1_000_000.0))
            .collect();
        text.push_str(&format!(
            "  prefix={} sat_rate={:.3} rtt=[{}]\n",
            prefix,
            entry.satisfaction_rate,
            face_rtts.join(" "),
        ));
    }
    ControlResponse::ok_empty(text)
}

// ─── Security module ──────────────────────────────────────────────────────────

async fn handle_security(
    verb_name: &[u8],
    params: ControlParameters,
    pib: Option<&FilePib>,
    engine: &ForwarderEngine,
    config: &ndn_config::ForwarderConfig,
    is_ephemeral: bool,
) -> ControlResponse {
    // Verbs that don't need the PIB.
    match verb_name {
        v if v == verb::CA_INFO => return security_ca_info(config),
        v if v == verb::CA_REQUESTS => return security_ca_requests(),
        v if v == verb::CA_TOKEN_ADD => return security_ca_token_add(params),
        v if v == verb::YUBIKEY_DETECT => return security_yubikey_detect(),
        // Trust schema management — work directly with the engine's validator.
        v if v == verb::SCHEMA_RULE_ADD => return security_schema_rule_add(params, engine),
        v if v == verb::SCHEMA_RULE_REMOVE => return security_schema_rule_remove(params, engine),
        v if v == verb::SCHEMA_LIST => return security_schema_list(engine),
        v if v == verb::SCHEMA_SET => return security_schema_set(params, engine),
        // identity-status: reports active identity name + ephemeral flag.
        v if v == verb::IDENTITY_STATUS => {
            return security_identity_status(engine, config, is_ephemeral);
        }
        _ => {}
    }

    let pib = match pib {
        Some(p) => p,
        None => {
            return ControlResponse::error(
                status::NOT_FOUND,
                "security identity not configured (no [security] section in config)",
            );
        }
    };
    match verb_name {
        v if v == verb::IDENTITY_LIST => security_identity_list(pib),
        v if v == verb::IDENTITY_GENERATE => security_identity_generate(params, pib),
        v if v == verb::IDENTITY_DID => security_identity_did(params, pib),
        v if v == verb::ANCHOR_LIST => security_anchor_list(pib),
        v if v == verb::KEY_DELETE => security_key_delete(params, pib),
        v if v == verb::CA_ENROLL => security_ca_enroll(params, pib, engine).await,
        v if v == verb::YUBIKEY_GENERATE => security_yubikey_generate(params, pib).await,
        _ => ControlResponse::error(status::NOT_FOUND, "unknown security verb"),
    }
}

/// Return the active identity status: name, ephemeral flag, PIB path.
fn security_identity_status(
    engine: &ForwarderEngine,
    config: &ndn_config::ForwarderConfig,
    is_ephemeral: bool,
) -> ControlResponse {
    // Prefer the explicitly configured identity name; fall back to deriving it
    // from the first trust-anchor name in the SecurityManager.
    let identity_name: String = if let Some(id) = &config.security.identity {
        id.clone()
    } else if let Some(mgr) = engine.security() {
        mgr.trust_anchor_names()
            .first()
            .map(|n| {
                let s = n.to_string();
                // Strip /KEY/... suffix to get the bare identity prefix.
                if let Some(pos) = s.find("/KEY/") {
                    s[..pos].to_string()
                } else {
                    s
                }
            })
            .unwrap_or_else(|| "(none)".to_string())
    } else {
        "(none)".to_string()
    };

    let pib_path = config
        .security
        .pib_path
        .as_deref()
        .map(str::to_owned)
        .unwrap_or_else(|| dirs_or_tmp_pib().display().to_string());

    let text =
        format!("identity={identity_name} is_ephemeral={is_ephemeral} pib_path={pib_path}\n");
    ControlResponse::ok_empty(text)
}

/// Derive the default PIB path (mirrors default_pib_path() in main.rs).
fn dirs_or_tmp_pib() -> std::path::PathBuf {
    let mut p = std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));
    p.push(".ndn");
    p.push("pib");
    p
}

fn security_identity_list(pib: &FilePib) -> ControlResponse {
    let keys = match pib.list_keys() {
        Ok(k) => k,
        Err(e) => return ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    };
    let mut text = format!("{} identities\n", keys.len());
    for key_name in &keys {
        let cert = pib.get_cert(key_name);
        let (has_cert, valid_until) = match cert {
            Ok(c) => {
                let exp = if c.valid_until == u64::MAX {
                    "never".to_string()
                } else {
                    format!("{}ns", c.valid_until)
                };
                (true, exp)
            }
            Err(_) => (false, "-".to_string()),
        };
        text.push_str(&format!(
            "  name={} has_cert={} valid_until={}\n",
            key_name, has_cert, valid_until,
        ));
    }
    ControlResponse::ok_empty(text)
}

fn security_identity_generate(params: ControlParameters, pib: &FilePib) -> ControlResponse {
    let name = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };
    match pib.generate_ed25519(&name) {
        Ok(_signer) => {
            tracing::info!(target: "mgmt.security", name = %name, "security/identity-generate: generated Ed25519 key");
            let echo = ControlParameters {
                name: Some(name),
                ..Default::default()
            };
            ControlResponse::ok("OK", echo)
        }
        Err(e) => ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    }
}

fn security_anchor_list(pib: &FilePib) -> ControlResponse {
    let anchors = match pib.list_anchors() {
        Ok(a) => a,
        Err(e) => return ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    };
    let mut text = format!("{} anchors\n", anchors.len());
    for anchor_name in &anchors {
        text.push_str(&format!("  name={}\n", anchor_name));
    }
    ControlResponse::ok_empty(text)
}

fn security_key_delete(params: ControlParameters, pib: &FilePib) -> ControlResponse {
    let name = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };
    match pib.delete_key(&name) {
        Ok(()) => {
            tracing::info!(target: "mgmt.security", name = %name, "security/key-delete");
            let echo = ControlParameters {
                name: Some(name),
                ..Default::default()
            };
            ControlResponse::ok("OK", echo)
        }
        Err(e) => ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    }
}

fn security_identity_did(params: ControlParameters, pib: &FilePib) -> ControlResponse {
    let name = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "Name is required"),
    };
    // Verify the key actually exists.
    match pib.list_keys() {
        Ok(keys) if keys.contains(&name) => {}
        Ok(_) => return ControlResponse::error(status::NOT_FOUND, "identity not found in PIB"),
        Err(e) => return ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    }
    // Encode as did:ndn:<percent-encoded-name> per W3C DID spec.
    let encoded = name.to_string().replace('/', "%2F");
    let did = format!("did:ndn:{encoded}");
    ControlResponse::ok_empty(did)
}

// ─── Trust schema management ─────────────────────────────────────────────────

/// Helper: get the validator from the engine or return a 404 error.
macro_rules! require_validator {
    ($engine:expr) => {
        match $engine.validator() {
            Some(v) => v,
            None => {
                return ControlResponse::error(
                    status::NOT_FOUND,
                    "validation is disabled; set [security] profile = \"default\" or \
                     \"accept-signed\" to enable trust schema management",
                );
            }
        }
    };
}

/// `security/schema-rule-add` — append a rule to the active trust schema.
///
/// ControlParameters.uri must contain a rule in the form:
/// `"<data_pattern> => <key_pattern>"`
///
/// Example: `/sensor/<node>/<type> => /sensor/<node>/KEY/<id>`
fn security_schema_rule_add(
    params: ControlParameters,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let rule_text = match params.uri.as_deref() {
        Some(s) if !s.is_empty() => s.to_owned(),
        _ => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                "Uri is required: \"<data_pattern> => <key_pattern>\"",
            );
        }
    };

    let rule = match SchemaRule::parse(&rule_text) {
        Ok(r) => r,
        Err(e) => {
            return ControlResponse::error(status::BAD_PARAMS, format!("invalid rule: {e}"));
        }
    };

    let validator = require_validator!(engine);
    let rule_str = rule.to_string();
    validator.add_schema_rule(rule);
    tracing::info!(target: "mgmt.security", rule = %rule_str, "security/schema-rule-add");
    ControlResponse::ok_empty(format!("added rule: {rule_str}"))
}

/// `security/schema-rule-remove` — remove a rule by index.
///
/// ControlParameters.count must contain the 0-based rule index from `schema-list`.
fn security_schema_rule_remove(
    params: ControlParameters,
    engine: &ForwarderEngine,
) -> ControlResponse {
    let idx = match params.count {
        Some(i) => i as usize,
        None => {
            return ControlResponse::error(
                status::BAD_PARAMS,
                "Count is required: 0-based rule index from schema-list",
            );
        }
    };

    let validator = require_validator!(engine);
    match validator.remove_schema_rule(idx) {
        Some(rule) => {
            let rule_str = rule.to_string();
            tracing::info!(target: "mgmt.security", index = idx, rule = %rule_str, "security/schema-rule-remove");
            ControlResponse::ok_empty(format!("removed rule[{idx}]: {rule_str}"))
        }
        None => ControlResponse::error(status::NOT_FOUND, format!("rule index {idx} out of range")),
    }
}

/// `security/schema-list` — list all active trust schema rules.
fn security_schema_list(engine: &ForwarderEngine) -> ControlResponse {
    let validator = require_validator!(engine);
    let rules = validator.schema_rules_text();
    let mut text = format!("{} rule(s)\n", rules.len());
    for (i, (data_pat, key_pat)) in rules.iter().enumerate() {
        text.push_str(&format!("  [{i}] {data_pat} => {key_pat}\n"));
    }
    ControlResponse::ok_empty(text)
}

/// `security/schema-set` — replace the entire trust schema.
///
/// ControlParameters.uri must contain newline-separated rules, each in the form:
/// `"<data_pattern> => <key_pattern>"`
///
/// An empty uri clears all rules (schema rejects everything).
fn security_schema_set(params: ControlParameters, engine: &ForwarderEngine) -> ControlResponse {
    let text = params.uri.as_deref().unwrap_or("").trim().to_owned();

    let mut new_schema = ndn_security::TrustSchema::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match SchemaRule::parse(line) {
            Ok(rule) => new_schema.add_rule(rule),
            Err(e) => {
                return ControlResponse::error(
                    status::BAD_PARAMS,
                    format!("invalid rule {line:?}: {e}"),
                );
            }
        }
    }

    let validator = require_validator!(engine);
    let rule_count = new_schema.rules().len();
    validator.set_schema(new_schema);
    tracing::info!(target: "mgmt.security", rules = rule_count, "security/schema-set");
    ControlResponse::ok_empty(format!("schema replaced with {rule_count} rule(s)"))
}

fn security_ca_info(config: &ndn_config::ForwarderConfig) -> ControlResponse {
    let sec = &config.security;
    match &sec.ca_prefix {
        None => ControlResponse::error(
            status::NOT_FOUND,
            "no CA configured (set [security] ca_prefix in router TOML)",
        ),
        Some(prefix) => {
            let info = format!(
                "ca_prefix={}\nca_info={}\nmax_validity_days={}\nchallenges={}\n",
                prefix,
                sec.ca_info,
                sec.ca_max_validity_days,
                sec.ca_challenges.join(","),
            );
            ControlResponse::ok_empty(info)
        }
    }
}

fn security_ca_requests() -> ControlResponse {
    // CaState is not yet embedded in the router process; return empty list.
    // When ndn-cert's CaState is wired into the router, this will return the
    // in-flight pending DashMap entries.
    ControlResponse::ok_empty("0 pending requests\n".to_string())
}

fn security_ca_token_add(params: ControlParameters) -> ControlResponse {
    let description = params.uri.unwrap_or_default();
    // Generate a random hex token using OS randomness.
    let mut token_bytes = [0u8; 16];
    let _ = getrandom::getrandom(&mut token_bytes);
    let token: String = token_bytes.iter().map(|b| format!("{b:02x}")).collect();
    tracing::info!(target: "mgmt.security", token = %token, description = %description, "security/ca-token-add");
    let echo = ControlParameters {
        // Return the token in the `uri` field (repurposed as a generic string slot).
        uri: Some(format!("token={token} description={description}")),
        ..Default::default()
    };
    ControlResponse::ok("OK", echo)
}

/// Start a background NDNCERT enrollment session.
///
/// Creates a temporary [`AppFace`] registered with the engine so that
/// NDN Interests can be expressed through the live forwarder, then runs
/// the PROBE → NEW → CHALLENGE exchange against the requested CA prefix.
/// When the CA issues a certificate it is stored in the PIB.
async fn security_ca_enroll(
    params: ControlParameters,
    pib: &FilePib,
    engine: &ForwarderEngine,
) -> ControlResponse {
    use ndn_faces::local::InProcFace;

    let ca_name = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "ca_prefix (Name) is required"),
    };

    // `uri` encodes "challenge_type:challenge_param".
    let (challenge_type, challenge_param) = match params.uri.as_deref() {
        Some(s) => match s.split_once(':') {
            Some((t, p)) => (t.to_owned(), p.to_owned()),
            None => (s.to_owned(), String::new()),
        },
        None => return ControlResponse::error(status::BAD_PARAMS, "challenge type:param required"),
    };

    // We need an identity key to enroll with.
    let identity_name = match pib.list_keys() {
        Ok(keys) => match keys.into_iter().next() {
            Some(n) => n,
            None => return ControlResponse::error(status::NOT_FOUND, "no identity keys in PIB"),
        },
        Err(e) => return ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    };

    let public_key = match pib.get_signer(&identity_name) {
        Ok(s) => s.public_key_bytes().to_vec(),
        Err(e) => return ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    };

    // Allocate a temporary face ID (high range to avoid collisions).
    let face_id = FaceId(0xFFFF_0100 + (rand_u32() & 0x0FFF));
    let (app_face, app_handle) = InProcFace::new(face_id, 32);
    let face_cancel = CancellationToken::new();
    engine.add_face(app_face, face_cancel.clone());

    // Clone what we need for the background task.
    let engine_clone = engine.clone();
    let pib_path = pib.root().to_owned();
    let identity_name_echo = identity_name.clone();

    tokio::spawn(async move {
        let result = run_enrollment(
            app_handle,
            face_id,
            &ca_name,
            &identity_name,
            &public_key,
            &challenge_type,
            &challenge_param,
        )
        .await;

        face_cancel.cancel();

        match result {
            Ok(cert) => {
                // Store the issued certificate in the PIB.
                match ndn_security::FilePib::open(&pib_path) {
                    Ok(pib) => match pib.store_cert(&identity_name, &cert) {
                        Ok(()) => tracing::info!(
                            target: "mgmt.security",
                            name = %identity_name,
                            "ca-enroll: certificate installed"
                        ),
                        Err(e) => tracing::error!(target: "mgmt.security", error = %e, "ca-enroll: failed to store cert"),
                    },
                    Err(e) => tracing::error!(target: "mgmt.security", error = %e, "ca-enroll: failed to open PIB"),
                }
            }
            Err(e) => {
                tracing::error!(
                    target: "mgmt.security",
                    ca = %ca_name,
                    error = %e,
                    "ca-enroll: enrollment failed"
                );
            }
        }

        drop(engine_clone); // keep engine alive until task completes
    });

    let echo = ControlParameters {
        name: Some(identity_name_echo),
        ..Default::default()
    };
    ControlResponse::ok("started", echo)
}

/// Run the three-step NDNCERT enrollment exchange (PROBE → NEW → CHALLENGE)
/// using a temporary AppFace that routes Interests through the live forwarder.
async fn run_enrollment(
    handle: ndn_faces::local::InProcHandle,
    _face_id: ndn_transport::FaceId,
    ca_prefix: &Name,
    identity_name: &Name,
    public_key: &[u8],
    challenge_type: &str,
    challenge_param: &str,
) -> Result<ndn_security::Certificate, String> {
    use ndn_cert::client::EnrollmentSession;
    use ndn_packet::encode::encode_interest;

    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    // ── PROBE ────────────────────────────────────────────────────────────────
    let probe_name = ca_prefix.clone().append(b"CA").append(b"PROBE");
    let probe_interest = encode_interest(&probe_name, None);
    handle
        .send(probe_interest)
        .await
        .map_err(|e| format!("PROBE send: {e}"))?;

    let probe_resp = tokio::time::timeout(TIMEOUT, handle.recv())
        .await
        .map_err(|_| "PROBE timeout")?
        .ok_or("PROBE: face closed")?;

    tracing::debug!(
        target: "mgmt.security",
        bytes = probe_resp.len(),
        "ca-enroll: PROBE response received"
    );

    // ── NEW ──────────────────────────────────────────────────────────────────
    let mut session = EnrollmentSession::new(
        identity_name.clone(),
        public_key.to_vec(),
        86400, // 24h default; CA will cap to its max_validity
    );

    let new_body = session.new_request_body().map_err(|e| e.to_string())?;
    let new_name = ca_prefix.clone().append(b"CA").append(b"NEW");
    let new_interest = encode_interest(&new_name, Some(&new_body));
    handle
        .send(new_interest)
        .await
        .map_err(|e| format!("NEW send: {e}"))?;

    let new_resp = tokio::time::timeout(TIMEOUT, handle.recv())
        .await
        .map_err(|_| "NEW timeout")?
        .ok_or("NEW: face closed")?;

    let new_body_content = extract_data_content(&new_resp).ok_or("NEW: malformed Data")?;
    session
        .handle_new_response(&new_body_content)
        .map_err(|e| e.to_string())?;

    // ── CHALLENGE ────────────────────────────────────────────────────────────
    let mut challenge_params = serde_json::Map::new();
    challenge_params.insert(
        "code".to_owned(),
        serde_json::Value::String(challenge_param.to_owned()),
    );
    let chal_body = session
        .challenge_request_body(challenge_type, challenge_params)
        .map_err(|e| e.to_string())?;

    let request_id = session.request_id().unwrap_or("").to_owned();
    let chal_name = ca_prefix
        .clone()
        .append(b"CA")
        .append(b"CHALLENGE")
        .append(request_id.as_bytes());
    let chal_interest = encode_interest(&chal_name, Some(&chal_body));
    handle
        .send(chal_interest)
        .await
        .map_err(|e| format!("CHALLENGE send: {e}"))?;

    let chal_resp = tokio::time::timeout(TIMEOUT, handle.recv())
        .await
        .map_err(|_| "CHALLENGE timeout")?
        .ok_or("CHALLENGE: face closed")?;

    let chal_body_content = extract_data_content(&chal_resp).ok_or("CHALLENGE: malformed Data")?;
    session
        .handle_challenge_response(&chal_body_content)
        .map_err(|e| e.to_string())?;

    if session.is_complete() {
        session
            .into_certificate()
            .ok_or_else(|| "no cert after completion".to_owned())
    } else if session.needs_another_round() {
        let msg = session
            .challenge_status_message()
            .unwrap_or("another round required");
        Err(format!("multi-round challenge not supported: {msg}"))
    } else {
        Err("enrollment did not complete".to_owned())
    }
}

/// Extract the Content TLV value from a Data packet (best-effort).
fn extract_data_content(data_bytes: &[u8]) -> Option<Vec<u8>> {
    use ndn_packet::Data;
    Data::decode(bytes::Bytes::copy_from_slice(data_bytes))
        .ok()
        .and_then(|d| d.content().map(|c| c.to_vec()))
}

/// Generate a pseudo-random u32 for face ID allocation.
fn rand_u32() -> u32 {
    let mut buf = [0u8; 4];
    let _ = getrandom::getrandom(&mut buf);
    u32::from_le_bytes(buf)
}

// ─── Config module ────────────────────────────────────────────────────────────

fn handle_config(verb_name: &[u8], config: &ndn_config::ForwarderConfig) -> ControlResponse {
    match verb_name {
        v if v == verb::GET => config_get(config),
        _ => ControlResponse::error(status::NOT_FOUND, "unknown config verb"),
    }
}

fn config_get(config: &ndn_config::ForwarderConfig) -> ControlResponse {
    match config.to_toml_string() {
        Ok(toml) => ControlResponse::ok_empty(toml),
        Err(e) => ControlResponse::error(status::SERVER_ERROR, e.to_string()),
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Resolve FaceId from params or source face.
///
/// Returns the error as a `ControlResponse` via the `?` operator on `Result`.
fn resolve_face_id(
    params: &ControlParameters,
    source_face: Option<FaceId>,
) -> Result<FaceId, Box<ControlResponse>> {
    match params.face_id {
        // Face ID 0 is never valid (IDs are allocated from 1 upwards).
        // Treat it the same as omitted — fall back to the requesting face.
        // This matches NFD convention and fixes Unix-mode clients that pass 0.
        Some(0) | None => source_face.ok_or_else(|| {
            Box::new(ControlResponse::error(
                status::BAD_PARAMS,
                "cannot determine FaceId",
            ))
        }),
        Some(id) => Ok(FaceId(id as u32)),
    }
}

// ─── YubiKey commands ─────────────────────────────────────────────────────────

/// Detect whether a YubiKey is connected and accessible via PC/SC.
///
/// Returns `status_text = "present"` on success, or an error if no device is found.
/// Requires the `yubikey-piv` cargo feature; returns `NOT_FOUND` otherwise.
fn security_yubikey_detect() -> ControlResponse {
    #[cfg(feature = "yubikey-piv")]
    {
        match ndn_security::yubikey::YubikeyKeyStore::open() {
            Ok(_) => ControlResponse::ok_empty("present"),
            Err(e) => ControlResponse::error(status::NOT_FOUND, format!("YubiKey not found: {e}")),
        }
    }
    #[cfg(not(feature = "yubikey-piv"))]
    {
        ControlResponse::error(
            status::NOT_FOUND,
            "yubikey-piv feature is not compiled in; rebuild ndn-fwd with --features yubikey-piv",
        )
    }
}

/// Generate a P-256 key in YubiKey PIV slot 9a and register it under `params.name`.
///
/// The slot mapping is persisted to `{pib_root}/yubikey-slots.json` so that
/// subsequent operations can locate the key. The uncompressed 65-byte public key
/// is returned base64url-encoded in the `uri` field of the response.
///
/// Requires the `yubikey-piv` cargo feature.
async fn security_yubikey_generate(params: ControlParameters, pib: &FilePib) -> ControlResponse {
    let key_name = match params.name {
        Some(n) => n,
        None => return ControlResponse::error(status::BAD_PARAMS, "missing name parameter"),
    };

    #[cfg(feature = "yubikey-piv")]
    {
        use ndn_security::yubikey::{YubikeyKeyStore, YubikeySlot};

        let store = match YubikeyKeyStore::open() {
            Ok(s) => s,
            Err(e) => {
                return ControlResponse::error(
                    status::NOT_FOUND,
                    format!("YubiKey not found: {e}"),
                );
            }
        };

        let pub_bytes = match store
            .generate_in_slot(key_name.clone(), YubikeySlot::Authentication)
            .await
        {
            Ok(b) => b,
            Err(e) => {
                return ControlResponse::error(
                    status::SERVER_ERROR,
                    format!("YubiKey generate failed: {e}"),
                );
            }
        };

        // Persist the name→slot mapping alongside the PIB.
        let slot_file = pib.root().join("yubikey-slots.json");
        let entry = serde_json::json!({
            "name": key_name.to_string(),
            "slot": "9a"
        });
        let mut entries: Vec<serde_json::Value> = if slot_file.exists() {
            std::fs::read_to_string(&slot_file)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        // Remove any existing entry for this name, then append the new one.
        entries.retain(|e| e["name"].as_str() != Some(&key_name.to_string()));
        entries.push(entry);
        let _ = std::fs::write(
            &slot_file,
            serde_json::to_vec_pretty(&entries).unwrap_or_default(),
        );

        let pubkey_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pub_bytes);
        tracing::info!(
            target: "mgmt.security",
            name = %key_name,
            pubkey_len = pub_bytes.len(),
            "security/yubikey-generate: P-256 key generated in PIV slot 9a"
        );
        ControlResponse::ok(
            "generated",
            ControlParameters {
                name: Some(key_name),
                uri: Some(pubkey_b64),
                ..Default::default()
            },
        )
    }
    #[cfg(not(feature = "yubikey-piv"))]
    {
        let _ = (key_name, pib);
        ControlResponse::error(
            status::NOT_FOUND,
            "yubikey-piv feature is not compiled in; rebuild ndn-fwd with --features yubikey-piv",
        )
    }
}

// ─── Log module ───────────────────────────────────────────────────────────────

fn handle_log(verb_name: &[u8], params: ControlParameters) -> ControlResponse {
    match verb_name {
        v if v == verb::MODULES => {
            let body = ndn_engine::observability::targets::enumerate().join("\n");
            ControlResponse::ok_empty(body)
        }
        v if v == verb::GET_RECENT => {
            // `params.count` carries the last sequence number the client has seen.
            // We return only entries with seq > after_seq, plus the current max_seq
            // as the first line of the response body so the client can advance its cursor.
            let after_seq = params.count.unwrap_or(0);
            let body = crate::LOG_RING
                .get()
                .and_then(|r| r.lock().ok())
                .map(|g| {
                    let max_seq = g.back().map(|(s, _)| *s).unwrap_or(0);
                    let mut out = max_seq.to_string();
                    for (seq, line) in g.iter() {
                        if *seq > after_seq {
                            out.push('\n');
                            out.push_str(line);
                        }
                    }
                    out
                })
                .unwrap_or_else(|| "0".to_string());
            ControlResponse::ok_empty(body)
        }
        v if v == verb::GET_FILTER => {
            let filter = crate::LOG_FILTER
                .get()
                .and_then(|m| m.lock().ok())
                .map(|g| g.clone())
                .unwrap_or_default();
            ControlResponse::ok_empty(filter)
        }
        v if v == verb::SET_FILTER => {
            let filter_str = params.uri.unwrap_or_default();
            if filter_str.is_empty() {
                return ControlResponse::error(
                    status::BAD_PARAMS,
                    "uri field must contain the filter string",
                );
            }
            if let Some(apply) = crate::APPLY_FILTER.get() {
                apply(&filter_str);
                tracing::info!(target: "mgmt.log", filter = %filter_str, "log/set-filter: filter updated");
                ControlResponse::ok_empty(filter_str)
            } else {
                ControlResponse::error(status::NOT_FOUND, "filter reload not initialised")
            }
        }
        _ => ControlResponse::error(status::NOT_FOUND, "unknown log verb"),
    }
}

async fn send_response(
    handle: &InProcHandle,
    name: &Name,
    resp: &ControlResponse,
    signer: Option<&dyn ndn_security::Signer>,
) {
    let content = resp.encode();
    let data = build_mgmt_response_wire(name, &content, signer);
    if let Err(e) = handle.send(data).await {
        tracing::warn!(target: "engine", error = %e, "nfd-mgmt: failed to send Data response");
    }
}

/// Audit N.12 — encode a management control-response Data packet,
/// signed with `signer` when one is wired and otherwise falling back to
/// `DigestSha256` via `encode_data_unsigned`. NFD's
/// `nfd::ControlCommandResponseDispatcher` signs every response with the
/// daemon's identity key; ndn-cxx clients configured against an NFD
/// trust schema reject the bare-digest variant.
pub(crate) fn build_mgmt_response_wire(
    name: &Name,
    content: &[u8],
    signer: Option<&dyn ndn_security::Signer>,
) -> bytes::Bytes {
    use ndn_packet::encode::DataBuilder;
    match signer {
        Some(s) => {
            // FreshnessPeriod=0 keeps mgmt responses out of intermediate
            // caches, matching `encode_data_unsigned`'s existing policy.
            let key_name = s.cert_name().cloned().or_else(|| Some(s.key_name().clone()));
            DataBuilder::new(name.clone(), content)
                .freshness(std::time::Duration::ZERO)
                .sign_sync(s.sig_type(), key_name.as_ref(), |region| {
                    s.sign_sync(region).unwrap_or_default()
                })
        }
        None => encode_data_unsigned(name, content),
    }
}

/// ndn-cxx `mgmt/status-dataset-context.cpp` segments status datasets
/// into payloads no larger than `MAX_NDN_PACKET_SIZE - 800`. We use the
/// same conservative default; the constant is the dataset payload
/// budget per Data, not the wire size of the Data itself.
const MAX_DATASET_PAYLOAD_LEN: usize = 8000;

/// Build the segment Data wires for a status dataset response, per the
/// audit's E.04 finding (ndn-cxx `mgmt/dispatcher.cpp` +
/// `mgmt/status-dataset-context.cpp`).
///
/// The response name shape per segment is
/// `<interest>/v=<version>/seg=<n>`. The last segment carries
/// `FinalBlockId = seg=<last>` so the consumer can stop fetching.
fn build_segmented_dataset(base_name: &Name, version: u64, content: &[u8]) -> Vec<bytes::Bytes> {
    use ndn_packet::encode::DataBuilder;

    let total = content.len();
    let last_seg = if total == 0 {
        0
    } else {
        (total - 1) / MAX_DATASET_PAYLOAD_LEN
    };

    (0..=last_seg)
        .map(|seg| {
            let start = seg * MAX_DATASET_PAYLOAD_LEN;
            let end = ((seg + 1) * MAX_DATASET_PAYLOAD_LEN).min(total);
            let chunk = &content[start..end];

            let seg_name = base_name
                .clone()
                .append_version(version)
                .append_segment(seg as u64);

            let mut builder = DataBuilder::new(seg_name, chunk)
                .freshness(std::time::Duration::ZERO);
            if seg == last_seg {
                builder = builder.final_block_id_typed_seg(last_seg as u64);
            }
            builder.sign_digest_sha256()
        })
        .collect()
}

#[cfg(test)]
/// NDN NonNegativeInteger: 1, 2, 4, or 8 bytes big-endian (shortest form).
fn seg_to_nni(v: u64) -> Vec<u8> {
    let be = v.to_be_bytes();
    if v <= 0xFF {
        vec![be[7]]
    } else if v <= 0xFFFF {
        vec![be[6], be[7]]
    } else if v <= 0xFFFF_FFFF {
        vec![be[4], be[5], be[6], be[7]]
    } else {
        be.to_vec()
    }
}

async fn send_dataset(handle: &InProcHandle, name: &Name, content: bytes::Bytes) {
    let version = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    for wire in build_segmented_dataset(name, version, &content) {
        if let Err(e) = handle.send(wire).await {
            tracing::warn!(target: "engine", error = %e, "nfd-mgmt: failed to send dataset segment");
            return;
        }
    }
}

#[cfg(test)]
mod e01_tests {
    use super::*;
    use ndn_packet::Interest;
    use ndn_packet::encode::{InterestBuilder, encode_interest};
    use ndn_security::Validator;
    use ndn_security::trust_schema::{NamePattern, PatternComponent, SchemaRule, TrustSchema};

    fn open_schema() -> TrustSchema {
        let mut schema = TrustSchema::new();
        schema.add_rule(SchemaRule {
            data_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
            key_pattern: NamePattern(vec![PatternComponent::MultiCapture("_".into())]),
        });
        schema
    }

    /// E.01 — when `require_signed_commands = false` (default), every
    /// Interest is allowed to dispatch even if unsigned. The
    /// architecture is in place; the wire-level enforcement is opt-in
    /// while operators populate trust anchors.
    #[tokio::test]
    async fn e01_unsigned_command_passes_when_require_signed_false() {
        let cmd_name: Name = "/localhost/nfd/rib/register".parse().unwrap();
        let interest = Interest::decode(encode_interest(&cmd_name, None)).unwrap();
        assert!(authorize_command(&interest, None, false, None).await.is_ok());
    }

    /// E.01 — when `require_signed_commands = true` and no validator
    /// is wired, every command is rejected. Catches the misconfig of
    /// "we want to enforce auth but forgot to populate trust anchors."
    #[tokio::test]
    async fn e01_unsigned_command_rejected_when_require_signed_true_no_validator() {
        let cmd_name: Name = "/localhost/nfd/rib/register".parse().unwrap();
        let interest = Interest::decode(encode_interest(&cmd_name, None)).unwrap();
        assert!(authorize_command(&interest, None, true, None).await.is_err());
    }

    /// E.01 — when a validator is wired and `require_signed_commands =
    /// true`, an unsigned command is rejected.
    #[tokio::test]
    async fn e01_unsigned_command_rejected_when_validator_wired() {
        let cmd_name: Name = "/localhost/nfd/rib/register".parse().unwrap();
        let interest = Interest::decode(encode_interest(&cmd_name, None)).unwrap();
        let validator = Validator::new(open_schema());
        assert!(
            authorize_command(&interest, Some(&validator), true, None)
                .await
                .is_err()
        );
    }

    /// E.01 — DigestSha256-signed command is rejected when a key validator
    /// is wired; DigestSha256 establishes integrity only, not key identity.
    #[tokio::test]
    async fn e01_digest_sha256_rejected_when_validator_wired() {
        let cmd_name: Name = "/localhost/nfd/rib/register".parse().unwrap();
        let wire = InterestBuilder::new(cmd_name)
            .app_parameters(bytes::Bytes::from_static(b"params"))
            .sign_digest_sha256();
        let interest = Interest::decode(wire).unwrap();
        let validator = Validator::new(open_schema());
        let result = authorize_command(&interest, Some(&validator), true, None).await;
        assert!(result.is_err(), "DigestSha256 must be rejected with a key validator");
        assert!(
            result.unwrap_err().contains("key-backed"),
            "error message must explain why"
        );
    }

    /// E.01 — a properly-signed command Interest is dispatched when
    /// the validator's cert cache holds the signer's key.
    #[tokio::test]
    async fn e01_signed_command_passes_when_validator_wired() {
        use ndn_security::cert_cache::Certificate;
        use ndn_security::signer::{Ed25519Signer, Signer as _};

        let seed = [9u8; 32];
        let key_name: Name = "/operators/alice/KEY/k1".parse().unwrap();
        let signer = Ed25519Signer::from_seed(&seed, key_name.clone());
        let pubkey = signer.public_key_bytes();

        let cmd_name: Name = "/localhost/nfd/rib/register".parse().unwrap();
        let wire = InterestBuilder::new(cmd_name)
            .app_parameters(bytes::Bytes::from_static(b"params"))
            .sign_sync(
                ndn_packet::SignatureType::SignatureEd25519,
                Some(&key_name),
                |region| signer.sign_sync(region).expect("ed25519 sign"),
            );
        let interest = Interest::decode(wire).unwrap();

        let validator = Validator::new(open_schema());
        validator.cert_cache().insert(Certificate {
            name: Arc::new(key_name),
            public_key: bytes::Bytes::copy_from_slice(&pubkey),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        });

        assert!(
            authorize_command(&interest, Some(&validator), true, None)
                .await
                .is_ok()
        );
    }

    /// Audit N.10 — end-to-end replay protection.
    /// Build a signed command Interest with an explicit SignatureTime,
    /// run `authorize_command` twice with the same wire bytes through a
    /// `CommandReplayCache`. First call accepts and records the
    /// timestamp; second call rejects on the strictly-greater rule.
    #[tokio::test]
    async fn n10_replay_rejected_when_cache_enabled() {
        use ndn_security::cert_cache::Certificate;
        use ndn_security::signer::{Ed25519Signer, Signer as _};

        let seed = [13u8; 32];
        let key_name: Name = "/operators/n10/KEY/k0".parse().unwrap();
        let signer = Ed25519Signer::from_seed(&seed, key_name.clone());
        let pubkey = signer.public_key_bytes();

        // Build one signed Interest (whose `sign_sync` writes a fresh
        // SignatureTime ≈ now); decode the same wire bytes twice. Both
        // decoded Interests share that single SigTime, so the second
        // dispatch is a true replay.
        let cmd_name: Name = "/localhost/nfd/rib/register".parse().unwrap();
        let wire = InterestBuilder::new(cmd_name)
            .app_parameters(bytes::Bytes::from_static(b"params"))
            .sign_sync(
                ndn_packet::SignatureType::SignatureEd25519,
                Some(&key_name),
                |region| signer.sign_sync(region).expect("ed25519 sign"),
            );
        let interest = Interest::decode(wire.clone()).unwrap();
        let interest_replay = Interest::decode(wire).unwrap();

        let validator = Validator::new(open_schema());
        validator.cert_cache().insert(Certificate {
            name: Arc::new(key_name.clone()),
            public_key: bytes::Bytes::copy_from_slice(&pubkey),
            valid_from: 0,
            valid_until: u64::MAX,
            issuer: None,
            signed_region: None,
            sig_value: None,
            sig_type: ndn_packet::SignatureType::SignatureEd25519,
        });

        let cache: CommandReplayCache =
            Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

        // First dispatch — valid signature, fresh timestamp.
        assert!(
            authorize_command(&interest, Some(&validator), true, Some(&cache))
                .await
                .is_ok(),
            "first signed command must be accepted"
        );

        // Second dispatch with the same Interest = replay. The cache now
        // has `last_seen == sig_time`, so the strictly-greater rule
        // rejects.
        let err = authorize_command(&interest_replay, Some(&validator), true, Some(&cache))
            .await
            .expect_err("replayed signed command must be rejected (N.10)");
        assert!(
            err.contains("replay") || err.contains("reorder") || err.contains("SignatureTime"),
            "rejection reason should mention replay/reorder/SignatureTime, got: {err}"
        );
    }

    /// Audit N.12 — `build_mgmt_response_wire` falls back to the legacy
    /// `DigestSha256` shape when no signer is wired (back-compat).
    #[test]
    fn n12_response_falls_back_to_digest_sha256_when_no_signer() {
        use ndn_packet::Data;
        let name: Name = "/localhost/nfd/status".parse().unwrap();
        let wire = build_mgmt_response_wire(&name, b"ok", None);
        let data = Data::decode(wire).expect("response Data must decode");
        let si = data.sig_info().expect("sig_info present");
        assert_eq!(
            si.sig_type,
            ndn_packet::SignatureType::DigestSha256,
            "no-signer path must fall back to DigestSha256"
        );
        assert!(
            si.key_locator.is_none(),
            "DigestSha256 must not carry KeyLocator"
        );
    }

    /// Audit N.12 — when a signer is wired, the response Data is signed
    /// with that signer's `sig_type()` and the SignatureInfo carries a
    /// KeyLocator naming the signer's cert (or key) name. Mirrors NFD's
    /// control-response signing path.
    #[tokio::test]
    async fn n12_response_uses_signer_when_wired() {
        use ndn_packet::Data;
        use ndn_security::signer::Ed25519Signer;

        let seed = [21u8; 32];
        let key_name: Name = "/operators/n12/KEY/k0".parse().unwrap();
        let signer = Ed25519Signer::from_seed(&seed, key_name.clone());

        let name: Name = "/localhost/nfd/status".parse().unwrap();
        let wire = build_mgmt_response_wire(&name, b"ok", Some(&signer));
        let data = Data::decode(wire).expect("response Data must decode");
        let si = data.sig_info().expect("sig_info present");
        assert_eq!(
            si.sig_type,
            ndn_packet::SignatureType::SignatureEd25519,
            "signed response must label SignatureEd25519, not DigestSha256"
        );
        let kl = si.key_locator.as_ref().expect("KeyLocator must be set");
        assert_eq!(
            kl.to_string(),
            key_name.to_string(),
            "KeyLocator falls through to signer's key_name when no cert wired"
        );
        // Note: kl.to_string() works because KeyLocator implements Display.
    }

    /// Audit N.11 — `resolve_control_parameters` rejects the
    /// CP-in-both-locations shape that has ambiguous semantics; accepts a
    /// single-location ControlParameters; falls through to `None` when
    /// neither location populated. Mirrors NFD's spec-shaped requirement
    /// that ControlParameters appear in exactly one place per Interest.
    #[test]
    fn n11_resolve_control_parameters_rejects_both_locations() {
        let cp1 = ControlParameters::default();
        let cp2 = ControlParameters::default();
        let err = resolve_control_parameters(Some(cp1), Some(cp2))
            .expect_err("CP in both locations must be rejected");
        assert!(err.contains("both"), "{err}");
    }

    #[test]
    fn n11_resolve_control_parameters_accepts_name_only() {
        let cp = ControlParameters::default();
        let out =
            resolve_control_parameters(Some(cp.clone()), None).expect("Name-only CP must accept");
        assert_eq!(out, Some(cp));
    }

    #[test]
    fn n11_resolve_control_parameters_accepts_app_params_only() {
        let cp = ControlParameters::default();
        let out = resolve_control_parameters(None, Some(cp.clone()))
            .expect("AppParams-only CP must accept");
        assert_eq!(out, Some(cp));
    }

    #[test]
    fn n11_resolve_control_parameters_no_cp_returns_none() {
        let out =
            resolve_control_parameters(None, None).expect("absent CP must produce None, not Err");
        assert_eq!(out, None);
    }

    /// Audit N.10 — missing SignatureTime always rejected.
    #[test]
    fn n10_check_sig_time_rejects_missing() {
        let err = check_sig_time(None, 1_000, None, COMMAND_SIG_TIME_TOLERANCE_MS)
            .expect_err("missing SignatureTime must reject");
        assert!(err.contains("SignatureTime"), "{err}");
    }

    /// Audit N.10 — SignatureTime outside the ±tolerance window rejected.
    #[test]
    fn n10_check_sig_time_rejects_out_of_window() {
        let now = 10_000_000u64;
        let stale = now - (COMMAND_SIG_TIME_TOLERANCE_MS + 1);
        let future = now + (COMMAND_SIG_TIME_TOLERANCE_MS + 1);
        assert!(check_sig_time(Some(stale), now, None, COMMAND_SIG_TIME_TOLERANCE_MS).is_err());
        assert!(check_sig_time(Some(future), now, None, COMMAND_SIG_TIME_TOLERANCE_MS).is_err());
    }

    /// Audit N.10 — fresh SignatureTime within window with no prior
    /// observation is accepted.
    #[test]
    fn n10_check_sig_time_accepts_fresh_in_window() {
        let now = 10_000_000u64;
        let sig = now - 1_000;
        let accepted = check_sig_time(Some(sig), now, None, COMMAND_SIG_TIME_TOLERANCE_MS)
            .expect("fresh in-window SignatureTime must accept");
        assert_eq!(accepted, sig);
    }

    /// Audit N.10 — replay (same SignatureTime as last accepted) rejected.
    /// Mirrors ndn-cxx `ValidationPolicyCommandInterest`'s strict-greater
    /// rule.
    #[test]
    fn n10_check_sig_time_rejects_replay() {
        let now = 10_000_000u64;
        let sig = now - 5_000;
        // First call accepts
        let _ = check_sig_time(Some(sig), now, None, COMMAND_SIG_TIME_TOLERANCE_MS).unwrap();
        // Replay: identical sig_time with last_seen=sig must reject.
        let err = check_sig_time(Some(sig), now, Some(sig), COMMAND_SIG_TIME_TOLERANCE_MS)
            .expect_err("replay must reject");
        assert!(err.contains("replay") || err.contains("reorder"), "{err}");

        // Older-than-last also rejected.
        let stale_but_in_window = sig - 1;
        let err2 = check_sig_time(
            Some(stale_but_in_window),
            now,
            Some(sig),
            COMMAND_SIG_TIME_TOLERANCE_MS,
        )
        .expect_err("non-strictly-increasing must reject");
        assert!(err2.contains("replay") || err2.contains("reorder"), "{err2}");
    }

    /// Audit N.10 — strictly-greater SignatureTime within window accepted
    /// even when a prior observation exists for the same signer.
    #[test]
    fn n10_check_sig_time_accepts_strictly_greater() {
        let now = 10_000_000u64;
        let last = now - 5_000;
        let sig = last + 1; // strictly greater
        let accepted =
            check_sig_time(Some(sig), now, Some(last), COMMAND_SIG_TIME_TOLERANCE_MS).unwrap();
        assert_eq!(accepted, sig);
    }

    /// Audit E.03 — `is_extended_module` recognizes the NFD-canonical set.
    /// Anything outside `faces / fib / rib / cs / strategy-choice / status`
    /// is an ndn-rs extension and must be treated as privileged.
    #[test]
    fn e03_is_extended_module_classifies_correctly() {
        use ndn_config::nfd_command::module as m;
        // NFD-standard modules — never extended.
        for std_mod in [m::FACES, m::FIB, m::RIB, m::CS, m::STRATEGY, m::STATUS] {
            assert!(
                !is_extended_module(std_mod),
                "{} must NOT be extended",
                String::from_utf8_lossy(std_mod)
            );
        }
        // ndn-rs extensions — always extended.
        for ext_mod in [
            m::SECURITY,
            m::ROUTING,
            m::DISCOVERY,
            m::NEIGHBORS,
            m::SERVICE,
            m::MEASUREMENTS,
            m::CONFIG,
            m::LOG,
        ] {
            assert!(
                is_extended_module(ext_mod),
                "{} MUST be extended",
                String::from_utf8_lossy(ext_mod)
            );
        }
    }

    /// Audit E.03 — extended modules always require signed commands, even
    /// when the operator left `require_signed_commands = false`.
    #[test]
    fn e03_effective_require_signed_forces_extended_modules() {
        use ndn_config::nfd_command::module as m;
        // Standard module follows the global flag.
        assert!(!effective_require_signed(m::RIB, false));
        assert!(effective_require_signed(m::RIB, true));
        // Extended module ignores the global flag's `false` setting.
        assert!(effective_require_signed(m::SECURITY, false));
        assert!(effective_require_signed(m::ROUTING, false));
        assert!(effective_require_signed(m::CONFIG, false));
    }

    /// Audit E.03 — concretely: an unsigned `/localhost/nfd/security/...`
    /// Interest must be rejected by `authorize_command` when the gate is
    /// computed via `effective_require_signed`, even though the global
    /// `require_signed_commands` flag is `false`.
    #[tokio::test]
    async fn e03_unsigned_security_command_rejected_by_default() {
        use ndn_config::nfd_command::module as m;
        let cmd_name: Name = "/localhost/nfd/security/identity-generate"
            .parse()
            .unwrap();
        let interest = Interest::decode(encode_interest(&cmd_name, None)).unwrap();
        let global_flag = false;
        let effective = effective_require_signed(m::SECURITY, global_flag);
        assert!(
            effective,
            "extended module must escalate `require_signed`"
        );
        // No validator wired and effective_required=true → reject.
        assert!(authorize_command(&interest, None, effective, None).await.is_err());
    }
}

#[cfg(test)]
mod e04_tests {
    use super::*;
    use ndn_packet::Data;

    /// E.04 — status datasets must be segmented per ndn-cxx
    /// `mgmt/dispatcher.cpp:282-297`. A single-segment payload still
    /// gets `<base>/v=<v>/seg=0` naming and `FinalBlockId = seg=0`.
    #[test]
    fn e04_single_segment_response_carries_version_segment_and_final_block_id() {
        let base: Name = "/localhost/nfd/faces/list".parse().unwrap();
        let content = vec![0x42u8; 100];
        let segments = build_segmented_dataset(&base, 17, &content);

        assert_eq!(segments.len(), 1, "small dataset must produce 1 segment");

        let data = Data::decode(segments[0].clone()).expect("segment must parse");
        let comps = data.name.components();
        let n = comps.len();

        assert_eq!(comps[n - 2].typ, ndn_packet::tlv_type::VERSION);
        assert_eq!(comps[n - 1].typ, ndn_packet::tlv_type::SEGMENT);
        assert_eq!(comps[n - 1].as_segment(), Some(0));

        let mi = data.meta_info().expect("must carry MetaInfo");
        let fb = mi.final_block_id.as_ref().expect("FinalBlockId required");
        // FinalBlockId must be a full SegmentNameComponent TLV: type=0x32 len value
        assert_eq!(fb.as_ref(), &[0x32u8, 0x01, 0x00]);
    }

    /// E.04 — payloads larger than `MAX_DATASET_PAYLOAD_LEN` produce
    /// multiple segments; only the last carries `FinalBlockId`.
    #[test]
    fn e04_multi_segment_response_marks_only_last_segment_as_final() {
        let base: Name = "/localhost/nfd/rib/list".parse().unwrap();
        let content = vec![0xABu8; MAX_DATASET_PAYLOAD_LEN * 2 + 100];
        let segments = build_segmented_dataset(&base, 42, &content);

        assert_eq!(segments.len(), 3, "expected 3 segments for 2.x payload");

        for (i, wire) in segments.iter().enumerate() {
            let data = Data::decode(wire.clone()).expect("segment must parse");
            let comps = data.name.components();
            assert_eq!(
                comps[comps.len() - 1].as_segment(),
                Some(i as u64),
                "segment {i} must be named seg={i}"
            );
            let fb = data.meta_info().and_then(|mi| mi.final_block_id.clone());
            if i == segments.len() - 1 {
                let fb = fb.expect("last segment must carry FinalBlockId");
                // FinalBlockId must be a full SegmentNameComponent TLV:
                // type=0x32, length byte, then the NNI value of the last segment.
                let last_nni = seg_to_nni((segments.len() - 1) as u64);
                let mut expected = vec![0x32u8, last_nni.len() as u8];
                expected.extend_from_slice(&last_nni);
                assert_eq!(
                    fb.as_ref(),
                    expected.as_slice(),
                    "FinalBlockId must be a SegmentNameComponent TLV for the last segment"
                );
            } else {
                assert!(fb.is_none(), "non-final segment must not carry FinalBlockId");
            }
        }
    }
}
