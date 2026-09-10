//! Node-level long-running watchers (uptime / forwarding-soak / per-radio link
//! quality) exposed as a `[monitors]` ControlSurface.
//!
//! The dashboard's Monitors view (the `ndn-viz` `Monitors` projection) reads
//! this through the generic `/localhost/nfd/ext/list` dataset — the same
//! mechanism as the named-radio cognition surface. Each watcher is a small
//! polling probe: a tokio task ticks the shared [`MonitorRegistry`] on an
//! interval, and the surface renders whatever the registry holds. Read-only.
//!
//! Wire contract (consumer: `ndn-viz::control::Monitors`): one `monitor` object
//! per watcher — `stat.monitor.<id>.{kind,status,detail,duration_s,ok,fail}` —
//! plus a flat `stat.count`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ndn_engine::FaceState;
use ndn_mgmt_wire::control_surface::{ControlInfo, ControlStats, ControlSurface};
use ndn_transport::FaceId;
use tokio_util::sync::CancellationToken;

/// One watcher's current state.
#[derive(Clone, Debug)]
pub struct MonitorEntry {
    pub id: String,
    pub kind: String,
    /// `running` while the probe is alive, `stopped` once ended.
    pub status: String,
    /// Latest probe detail (single line, operator-readable).
    pub detail: String,
    /// Cumulative ok / fail ticks since start.
    pub ok: u64,
    pub fail: u64,
    started: Instant,
}

/// A plain snapshot row (no `Instant`) for rendering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MonitorSnapshot {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub detail: String,
    pub ok: u64,
    pub fail: u64,
    pub duration_s: u64,
}

/// Thread-safe registry of long-running watchers.
#[derive(Default)]
pub struct MonitorRegistry {
    entries: Mutex<BTreeMap<String, MonitorEntry>>,
}

impl MonitorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a watcher as running (re-starting resets its counters).
    pub fn start(&self, id: &str, kind: &str) {
        let mut g = self.entries.lock().unwrap();
        g.insert(
            id.to_string(),
            MonitorEntry {
                id: id.to_string(),
                kind: kind.to_string(),
                status: "running".into(),
                detail: String::new(),
                ok: 0,
                fail: 0,
                started: Instant::now(),
            },
        );
    }

    /// Record one probe tick. Unknown ids are ignored (defensive).
    pub fn tick(&self, id: &str, ok: bool, detail: &str) {
        let mut g = self.entries.lock().unwrap();
        let Some(e) = g.get_mut(id) else {
            return;
        };
        if ok {
            e.ok += 1;
        } else {
            e.fail += 1;
        }
        e.detail = detail.to_string();
    }

    /// Mark a watcher stopped (keeps its history for the surface).
    pub fn stop(&self, id: &str) {
        let mut g = self.entries.lock().unwrap();
        if let Some(e) = g.get_mut(id) {
            e.status = "stopped".into();
        }
    }

    /// Snapshot all watchers, ordered by id.
    pub fn snapshot(&self) -> Vec<MonitorSnapshot> {
        let g = self.entries.lock().unwrap();
        g.values()
            .map(|e| MonitorSnapshot {
                id: e.id.clone(),
                kind: e.kind.clone(),
                status: e.status.clone(),
                detail: e.detail.clone(),
                ok: e.ok,
                fail: e.fail,
                duration_s: e.started.elapsed().as_secs(),
            })
            .collect()
    }
}

/// One tick of a probe: `(ok, detail)`.
pub type Probe = Arc<dyn Fn() -> (bool, String) + Send + Sync>;

/// A per-radio link-quality probe paired with the radio id it probes.
///
/// Only the `radio` feature builds the medium face that emits these, so the
/// alias is gated to match and stays dead-code-free without it.
#[cfg(feature = "radio")]
pub type LinkProbe = (String, Probe);

/// Spawn a polling task that ticks `id` every `interval` until cancelled.
/// The first tick fires immediately.
pub fn spawn_polling(
    registry: Arc<MonitorRegistry>,
    id: &str,
    kind: &str,
    interval: Duration,
    cancel: CancellationToken,
    probe: Probe,
) {
    registry.start(id, kind);
    let id = id.to_string();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = ticker.tick() => {
                    let (ok, detail) = probe();
                    registry.tick(&id, ok, &detail);
                }
            }
        }
        // Task ended (cancellation): mark the watcher stopped so a late
        // `ext/list` read during shutdown reports honest state.
        registry.stop(&id);
    });
}

/// Uptime probe: always ok; detail is the human-readable elapsed time.
pub fn uptime_probe(started: Instant) -> Probe {
    Arc::new(move || {
        let d = started.elapsed();
        let s = d.as_secs();
        (
            true,
            format!("up {}h{:02}m{:02}s", s / 3600, (s % 3600) / 60, s % 60),
        )
    })
}

/// Forwarding-liveness (soak) probe: samples the aggregate face counters and
/// fails a tick when egress drops appear (outbound queue full — a real
/// health signal, not mere quiet). Detail carries the per-tick deltas.
pub fn forwarding_probe(face_states: Arc<dashmap::DashMap<FaceId, FaceState>>) -> Probe {
    let prev: Arc<Mutex<(u64, u64)>> = Arc::new(Mutex::new((0, 0)));
    Arc::new(move || {
        use std::sync::atomic::Ordering;
        let mut pkts = 0u64;
        let mut drops = 0u64;
        let mut unsat = 0u64;
        for st in face_states.iter() {
            let c = &st.counters;
            pkts += c.in_interests.load(Ordering::Relaxed)
                + c.in_data.load(Ordering::Relaxed)
                + c.out_interests.load(Ordering::Relaxed)
                + c.out_data.load(Ordering::Relaxed);
            drops += c.out_drops.load(Ordering::Relaxed);
            unsat += c.in_unsatisfied_interests.load(Ordering::Relaxed);
        }
        let (p_pkts, p_drops) = {
            let mut g = prev.lock().unwrap();
            let old = *g;
            *g = (pkts, drops);
            old
        };
        let d_pkts = pkts.saturating_sub(p_pkts);
        let d_drops = drops.saturating_sub(p_drops);
        (
            d_drops == 0,
            format!("pkt_delta={d_pkts} drop_delta={d_drops} unsat={unsat}"),
        )
    })
}

/// The `[monitors]` control surface over a registry.
pub struct MonitorsSurface {
    registry: Arc<MonitorRegistry>,
}

impl MonitorsSurface {
    pub fn new(registry: Arc<MonitorRegistry>) -> Self {
        Self { registry }
    }
}

impl ControlSurface for MonitorsSurface {
    fn name(&self) -> &str {
        "monitors"
    }

    fn describe(&self) -> ControlInfo {
        ControlInfo {
            caps: vec![
                ("subsystem".into(), "node-monitors".into()),
                ("readonly".into(), "true".into()),
            ],
            options: Vec::new(),
        }
    }

    fn stats(&self) -> ControlStats {
        let snap = self.registry.snapshot();
        let mut entries: Vec<(String, String)> = Vec::with_capacity(1 + snap.len() * 6);
        entries.push(("count".into(), snap.len().to_string()));
        for m in &snap {
            let k = |f: &str| format!("monitor.{}.{}", m.id, f);
            entries.push((k("kind"), m.kind.clone()));
            entries.push((k("status"), m.status.clone()));
            entries.push((k("detail"), m.detail.clone()));
            entries.push((k("duration_s"), m.duration_s.to_string()));
            entries.push((k("ok"), m.ok.to_string()));
            entries.push((k("fail"), m.fail.to_string()));
        }
        ControlStats { entries }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_lifecycle_and_snapshot() {
        let r = MonitorRegistry::new();
        r.start("uptime", "uptime");
        r.start("link-0", "link");
        r.tick("uptime", true, "up 0h00m05s");
        r.tick("link-0", false, "rssi=-91 occ=12");
        r.tick("link-0", true, "rssi=-70 occ=12");
        r.tick("ghost", true, "ignored");
        let snap = r.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].id, "link-0"); // ordered by id
        assert_eq!(snap[1].id, "uptime");
        assert_eq!(
            snap[0],
            MonitorSnapshot {
                id: "link-0".into(),
                kind: "link".into(),
                status: "running".into(),
                detail: "rssi=-70 occ=12".into(),
                ok: 1,
                fail: 1,
                duration_s: 0,
            }
        );
        r.stop("link-0");
        assert_eq!(r.snapshot()[0].status, "stopped");
    }

    #[test]
    fn surface_renders_consumer_contract() {
        // Exact key shape the ndn-viz `Monitors` projection parses:
        // `stat.monitor.<id>.<field>` (3 dotted parts after `stat.`) + flat count.
        let r = Arc::new(MonitorRegistry::new());
        r.start("overnight", "soak");
        r.tick("overnight", true, "relay stable");
        let s = MonitorsSurface::new(r);
        assert_eq!(s.name(), "monitors");
        let stats = s.stats();
        let text: String = stats
            .entries
            .iter()
            .map(|(k, v)| format!("stat.{k}={v}\n"))
            .collect();
        assert!(text.contains("stat.count=1\n"));
        assert!(text.contains("stat.monitor.overnight.kind=soak\n"));
        assert!(text.contains("stat.monitor.overnight.status=running\n"));
        assert!(text.contains("stat.monitor.overnight.detail=relay stable\n"));
        assert!(text.contains("stat.monitor.overnight.ok=1\n"));
        assert!(text.contains("stat.monitor.overnight.fail=0\n"));
        assert!(text.contains("stat.monitor.overnight.duration_s=0\n"));
        // describe() carries the subsystem cap the consumer ignores but operators see.
        let info = s.describe();
        assert!(
            info.caps
                .iter()
                .any(|(k, v)| k == "subsystem" && v == "node-monitors")
        );
    }

    #[test]
    fn uptime_probe_reports_elapsed() {
        let p = uptime_probe(Instant::now());
        let (ok, detail) = p();
        assert!(ok);
        assert!(detail.starts_with("up 0h00m0"), "got: {detail}");
    }
}
