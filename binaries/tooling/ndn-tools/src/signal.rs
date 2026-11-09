//! The signal verbs of `ndn-data`: live data that is never a version and
//! never stored (`ndn_surface::signal`, signals spec), and the capture a
//! relay's operator runs to see what a relay sees of them.
//!
//! The device's `Signals` start on the first signal verb, over a
//! connection to the daemon of their own (the daemon routes this device's
//! namespace group `<ns>/32=sync` to it once `Signals` registers it), so a
//! host that never uses signals runs exactly as before. A run is kept per
//! scope: `signal-send` and `signal-stream` send on the scope's open run,
//! opening one first when none is open.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use serde_json::{Value, json};
use tokio::sync::{Mutex as RunLock, OnceCell};

use ndn_app::{Connection, IpcConnection};
use ndn_data::Device;
use ndn_ipc::ForwarderClient;
use ndn_packet::lp::{LpPacket, is_lp_packet};
use ndn_packet::{Interest, Name, NameComponent};
use ndn_surface::signal::wire::{Packet, decode_packet, push_packet};
use ndn_surface::signal::{
    RunId, Signal, SignalError, SignalOptions, SignalRun, SignalStats, Signals,
};

use crate::{Verb, hex, next_step, next_token};

pub const SUBSCRIBE_USAGE: &str = "usage: signal-subscribe <folder or collection> (every signal \
                                   of the scope from now on, one line each)";
pub const OPEN_USAGE: &str = "usage: signal-open <folder or collection> (a run: a fresh run key, \
                              its header signed by this device's key)";
pub const SEND_USAGE: &str = "usage: signal-send <folder or collection> <address> <payload> (one \
                              signal on the scope's run; address at most 64 octets, payload at \
                              most 768)";
pub const STREAM_USAGE: &str = "usage: signal-stream <folder or collection> <address> <count> \
                                <hz> (count signals at hz per second on the scope's run, each \
                                payload `n=<i> sent_us=<µs since the epoch>`; answered once all \
                                are sent)";
pub const CLOSE_USAGE: &str = "usage: signal-close <folder or collection> (ends the scope's run)";
pub const CAPTURE_USAGE: &str = "usage: signal-capture <group> (a sync group `<ns>/32=sync`: \
                                 every signal pushed into it that reaches this daemon, one line \
                                 each)";

/// The highest rate a stream may ask for: the sender's limit is 120
/// packets per second per run.
const STREAM_HZ_MAX: f64 = 120.0;

/// One device's signals, as this host drives them.
pub struct SignalHost {
    device: Device,
    face_socket: String,
    options: SignalOptions,
    signals: OnceCell<Signals>,
    runs: Mutex<HashMap<Name, Arc<RunLock<SignalRun>>>>,
}

impl SignalHost {
    pub fn new(device: Device, face_socket: String, options: SignalOptions) -> Self {
        Self {
            device,
            face_socket,
            options,
            signals: OnceCell::new(),
            runs: Mutex::new(HashMap::new()),
        }
    }

    /// The device's `Signals`, started on first use over a connection of
    /// their own.
    async fn signals(&self) -> Result<&Signals, SignalError> {
        self.signals
            .get_or_try_init(|| async {
                let conn = connect(&self.face_socket).await?;
                Signals::start(self.device.clone(), conn, self.options.clone()).await
            })
            .await
    }

    /// The scope's open run, opened first when none is.
    async fn run_for(&self, scope: &Name) -> Result<Arc<RunLock<SignalRun>>, SignalError> {
        if let Some(run) = self.held(scope) {
            return Ok(run);
        }
        let run = Arc::new(RunLock::new(self.signals().await?.open(scope).await?));
        let mut runs = self.runs.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(Arc::clone(runs.entry(scope.clone()).or_insert(run)))
    }

    fn held(&self, scope: &Name) -> Option<Arc<RunLock<SignalRun>>> {
        let runs = self.runs.lock().unwrap_or_else(PoisonError::into_inner);
        runs.get(scope).cloned()
    }

    /// One signal verb line (`signal-…`).
    pub async fn run(&self, verb: &str, args: &[String]) -> Result<Verb, SignalError> {
        let usage = |s: &str| Ok(Verb::Usage(s.to_owned()));
        let name = |s: &str| {
            s.parse::<Name>()
                .map_err(|e| format!("{s:?} is no name: {e}"))
        };
        match (verb, args) {
            ("signal-subscribe", [scope]) => {
                let scope = match name(scope) {
                    Ok(s) => s,
                    Err(e) => return Ok(Verb::Usage(format!("{e}; {SUBSCRIBE_USAGE}"))),
                };
                let mut sub = self.signals().await?.subscribe(&scope).await?;
                tokio::spawn(async move {
                    while let Some(s) = sub.next().await {
                        println!("{}", json!({"signal": signal(&s)}));
                    }
                });
                Ok(Verb::Done(json!({"scope": scope.to_string()})))
            }
            ("signal-subscribe", _) => usage(SUBSCRIBE_USAGE),
            ("signal-open", [scope]) => {
                let scope = match name(scope) {
                    Ok(s) => s,
                    Err(e) => return Ok(Verb::Usage(format!("{e}; {OPEN_USAGE}"))),
                };
                if let Some(open) = self.held(&scope) {
                    let id = open.try_lock().map(|r| run_id(r.id())).ok();
                    return Ok(Verb::Usage(format!(
                        "a run is open over {scope} (run {}): send on it, or signal-close it \
                         first",
                        id.as_deref().unwrap_or("busy streaming")
                    )));
                }
                let run = self.run_for(&scope).await?;
                let id = run_id(run.lock().await.id());
                Ok(Verb::Done(json!({"scope": scope.to_string(), "run": id})))
            }
            ("signal-open", _) => usage(OPEN_USAGE),
            ("signal-send", [scope, address, payload]) => {
                let scope = match name(scope) {
                    Ok(s) => s,
                    Err(e) => return Ok(Verb::Usage(format!("{e}; {SEND_USAGE}"))),
                };
                let run = self.run_for(&scope).await?;
                let mut run = run.lock().await;
                let seq = run.send(address.as_bytes(), payload.as_bytes()).await?;
                Ok(Verb::Done(json!({
                    "scope": scope.to_string(),
                    "run": run_id(run.id()),
                    "seq": seq,
                })))
            }
            ("signal-send", _) => usage(SEND_USAGE),
            ("signal-stream", [scope, address, count, hz]) => {
                let (scope, count, hz) = match stream_options(scope, count, hz) {
                    Ok(o) => o,
                    Err(e) => return Ok(Verb::Usage(format!("{e}; {STREAM_USAGE}"))),
                };
                let run = self.run_for(&scope).await?;
                let address = address.clone();
                Ok(Verb::Later(Box::pin(async move {
                    stream(&scope, &run, &address, count, hz)
                        .await
                        .map_err(|e| error(&e))
                })))
            }
            ("signal-stream", _) => usage(STREAM_USAGE),
            ("signal-close", [scope]) => {
                let scope = match name(scope) {
                    Ok(s) => s,
                    Err(e) => return Ok(Verb::Usage(format!("{e}; {CLOSE_USAGE}"))),
                };
                let Some(run) = self.runs_remove(&scope) else {
                    return Ok(Verb::Usage(format!("no run is open over {scope}")));
                };
                match Arc::try_unwrap(run) {
                    Ok(run) => {
                        let run = run.into_inner();
                        let id = run_id(run.id());
                        run.close().await;
                        Ok(Verb::Done(
                            json!({"scope": scope.to_string(), "run": id, "closed": true}),
                        ))
                    }
                    Err(busy) => {
                        self.runs
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .insert(scope.clone(), busy);
                        Ok(Verb::Usage(format!(
                            "the run over {scope} is streaming: close it once its stream answered"
                        )))
                    }
                }
            }
            ("signal-close", _) => usage(CLOSE_USAGE),
            ("signal-stats", []) => Ok(Verb::Done(match self.signals.get() {
                Some(s) => json!({"started": true, "stats": stats(&s.stats())}),
                None => json!({"started": false, "stats": stats(&SignalStats::default())}),
            })),
            ("signal-stats", _) => usage("usage: signal-stats"),
            ("signal-capture", _) => capture(&self.face_socket, args).await,
            _ => usage(
                "signal verbs: signal-subscribe, signal-open, signal-send, signal-stream, \
                 signal-close, signal-stats, signal-capture",
            ),
        }
    }

    fn runs_remove(&self, scope: &Name) -> Option<Arc<RunLock<SignalRun>>> {
        let mut runs = self.runs.lock().unwrap_or_else(PoisonError::into_inner);
        runs.remove(scope)
    }

    /// Stop: every run closes (their rings end) and every subscriber ends.
    pub fn shutdown(&self) {
        if let Some(s) = self.signals.get() {
            s.shutdown();
        }
    }
}

/// A connection to the daemon at `face_socket` of its own.
async fn connect(face_socket: &str) -> Result<Arc<dyn Connection>, SignalError> {
    let client = ForwarderClient::connect(face_socket)
        .await
        .map_err(|e| SignalError::Io(format!("connect to the forwarder at {face_socket}: {e}")))?;
    Ok(Arc::new(IpcConnection::new(client)))
}

fn stream_options(scope: &str, count: &str, hz: &str) -> Result<(Name, u64, f64), String> {
    let scope = scope
        .parse::<Name>()
        .map_err(|e| format!("{scope:?} is no name: {e}"))?;
    let count = count
        .parse::<u64>()
        .ok()
        .filter(|c| *c > 0)
        .ok_or_else(|| format!("count {count:?} is no positive whole number"))?;
    let hz = hz
        .parse::<f64>()
        .ok()
        .filter(|h| *h > 0.0 && *h <= STREAM_HZ_MAX)
        .ok_or_else(|| {
            format!("hz {hz:?} is no rate above 0 and at most {STREAM_HZ_MAX} per second")
        })?;
    Ok((scope, count, hz))
}

/// `count` signals for `address` at `hz` on `run`, each payload
/// `n=<i> sent_us=<µs>`. A send over the sender's rate waits what it is
/// told and is sent again; any other refusal ends the stream.
async fn stream(
    scope: &Name,
    run: &RunLock<SignalRun>,
    address: &str,
    count: u64,
    hz: f64,
) -> Result<Value, SignalError> {
    let mut tick = tokio::time::interval(Duration::from_secs_f64(1.0 / hz));
    let started = Instant::now();
    let (mut first, mut last, mut waited) = (None, 0, 0u64);
    for n in 0..count {
        tick.tick().await;
        let payload = format!("n={n} sent_us={}", now_us());
        let seq = loop {
            let sent = run
                .lock()
                .await
                .send(address.as_bytes(), payload.as_bytes())
                .await;
            match sent {
                Err(SignalError::RateLimited { retry_after }) => {
                    waited += 1;
                    tokio::time::sleep(retry_after).await;
                }
                other => break other?,
            }
        };
        first.get_or_insert(seq);
        last = seq;
    }
    let id = run_id(run.lock().await.id());
    Ok(json!({
        "scope": scope.to_string(),
        "address": address,
        "run": id,
        "sent": count,
        "first_seq": first,
        "last_seq": last,
        "hz": hz,
        "elapsed_ms": started.elapsed().as_millis() as u64,
        "rate_limited": waited,
    }))
}

/// `signal-capture <group>`: register `group` on this daemon over a
/// connection of its own and print every signal Interest it is given — what
/// a relay's operator sees of signals in transit. Needs no device.
pub async fn capture(face_socket: &str, args: &[String]) -> Result<Verb, SignalError> {
    let [group] = args else {
        return Ok(Verb::Usage(CAPTURE_USAGE.to_owned()));
    };
    let group = match group.parse::<Name>() {
        Ok(g) => g,
        Err(e) => {
            return Ok(Verb::Usage(format!(
                "{group:?} is no name: {e}; {CAPTURE_USAGE}"
            )));
        }
    };
    let pushed = group
        .clone()
        .append_component(NameComponent::keyword(Bytes::from_static(b"signal")));
    let conn = connect(face_socket).await?;
    conn.register_prefix(&group).await.map_err(|e| {
        SignalError::Io(format!(
            "register {group} on the forwarder at {face_socket}: {e}"
        ))
    })?;
    let shown = group.to_string();
    tokio::spawn(async move {
        while let Some(wire) = conn.recv().await {
            if let Some(interest) = interest_of(wire)
                && interest.name.has_prefix(&pushed)
            {
                println!(
                    "{}",
                    json!({"capture": shown, "interest": captured(&interest)})
                );
            }
        }
    });
    Ok(Verb::Done(json!({"group": group.to_string()})))
}

/// The Interest a connection received, out of its link-protocol frame.
fn interest_of(wire: Bytes) -> Option<Interest> {
    let bare = if is_lp_packet(&wire) {
        LpPacket::decode(wire).ok()?.fragment?
    } else {
        wire
    };
    Interest::decode(bare).ok()
}

/// What a signal Interest shows whoever forwards it: its name, its
/// parameters' octets, whether its name's digest is theirs, and what the
/// parameters decode as by the signal wire alone (no key).
fn captured(interest: &Interest) -> Value {
    let params = interest.app_parameters().cloned().unwrap_or_default();
    let mut v = json!({
        "name": interest.name.to_string(),
        "octets": params.len(),
        "params_hex": hex(&params),
        "digest_ok": push_packet(interest).is_some(),
    });
    match decode_packet(params) {
        Ok(Packet::Sealed(s)) => {
            v["decodes_as"] = json!("SignalSealed");
            v["key_id"] = json!(hex(&s.key_id));
            v["ciphertext_octets"] = json!(s.ciphertext.len());
        }
        Ok(Packet::Body(b)) => {
            v["decodes_as"] = json!("SignalBody");
            v["scope"] = json!(b.scope.to_string());
            v["run"] = json!(run_id(b.run));
            v["header"] = json!(b.header.is_some());
            v["signals"] = json!(b.signals.len());
        }
        Err(e) => {
            v["decodes_as"] = json!("undecodable");
            v["why"] = json!(e.to_string());
        }
    }
    v
}

/// A received signal as its line shows it; `latency_us` when its payload
/// carries `sent_us=<µs>` (a stream's), by this host's clock.
fn signal(s: &Signal) -> Value {
    let mut v = json!({
        "scope": s.scope.to_string(),
        "sender": s.sender.to_string(),
        "run": run_id(s.run),
        "seq": s.seq,
        "address": octets(&s.address),
        "payload": octets(&s.payload),
        "expires_ms": s.expires,
        "local": s.local,
    });
    if let Some(sent) = sent_us(&s.payload) {
        v["latency_us"] = json!(now_us().saturating_sub(sent));
    }
    v
}

/// Octets as text when they are UTF-8, else `{"hex": …}`.
fn octets(b: &[u8]) -> Value {
    match std::str::from_utf8(b) {
        Ok(text) => json!(text),
        Err(_) => json!({"hex": hex(b)}),
    }
}

/// The send time a stream's payload carries.
fn sent_us(payload: &[u8]) -> Option<u64> {
    std::str::from_utf8(payload)
        .ok()?
        .split_whitespace()
        .find_map(|w| w.strip_prefix("sent_us="))?
        .parse()
        .ok()
}

fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as u64)
}

fn run_id(id: RunId) -> String {
    hex(&id.0)
}

fn stats(s: &SignalStats) -> Value {
    json!({
        "sent_packets": s.sent_packets,
        "sent_bytes": s.sent_bytes,
        "delivered": s.delivered,
        "local": s.local,
        "stale": s.stale,
        "replayed": s.replayed,
        "expired": s.expired,
        "not_member": s.not_member,
        "bad_signature": s.bad_signature,
        "unknown_run": s.unknown_run,
        "unknown_key": s.unknown_key,
        "flood": s.flood,
        "malformed": s.malformed,
        "unsubscribed": s.unsubscribed,
    })
}

/// A signal refusal as an error answer: why, whether to ask again, and
/// what to do next (`retry_after_ms` when over the sender's rate).
pub fn error(e: &SignalError) -> Value {
    let next = e.next();
    let mut v = json!({
        "message": e.to_string(),
        "retry": matches!(
            e,
            SignalError::NotReady { .. } | SignalError::RateLimited { .. } | SignalError::Io(_)
        ),
        "next": next_token(next),
        "next_step": next_step(next),
    });
    if let SignalError::RateLimited { retry_after } = e {
        v["retry_after_ms"] = json!(retry_after.as_millis() as u64);
    }
    v
}
