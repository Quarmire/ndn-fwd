//! Tracing subscriber and ring-buffer plumbing. Owns the `LOG_RING`,
//! `LOG_FILTER`, and `APPLY_FILTER` statics that the mgmt `log/*` verbs
//! read via [`build_log_inspector`].

use std::collections::VecDeque;
use std::io::Write as IoWrite;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

type FilterFn = Arc<dyn Fn(&str) + Send + Sync + 'static>;

/// Reload callback installed by `init_tracing`; the mgmt handler calls it
/// to swap the running subscriber's filter.
pub static APPLY_FILTER: OnceLock<FilterFn> = OnceLock::new();

/// Current active filter string, kept in sync with `APPLY_FILTER`.
pub static LOG_FILTER: OnceLock<Arc<Mutex<String>>> = OnceLock::new();

/// Monotonic id stamped on every log line. The dashboard polls with the
/// last seq it has seen to fetch only new entries.
pub static LOG_SEQ: AtomicU64 = AtomicU64::new(0);

type LogRingInner = VecDeque<(u64, String)>;

/// 500-entry ring of `(seq, line)` pairs.
pub static LOG_RING: OnceLock<Arc<Mutex<LogRingInner>>> = OnceLock::new();

struct RingWriter {
    ring: Arc<Mutex<LogRingInner>>,
}

impl IoWrite for RingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let line = String::from_utf8_lossy(buf)
            .trim_end_matches('\n')
            .to_string();
        if !line.is_empty()
            && let Ok(mut r) = self.ring.lock()
        {
            let seq = LOG_SEQ.fetch_add(1, Ordering::Relaxed);
            r.push_back((seq, line));
            if r.len() > 500 {
                r.pop_front();
            }
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct RingMakeWriter {
    ring: Arc<Mutex<LogRingInner>>,
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RingMakeWriter {
    type Writer = RingWriter;
    fn make_writer(&'a self) -> Self::Writer {
        RingWriter {
            ring: Arc::clone(&self.ring),
        }
    }
}

/// Returns `None` until `init_tracing` has populated all three statics.
pub fn build_log_inspector() -> Option<Arc<ndn_mgmt::LogInspector>> {
    let ring = LOG_RING.get()?.clone();
    let filter = LOG_FILTER.get()?.clone();
    let apply_filter = APPLY_FILTER.get()?.clone();
    Some(Arc::new(ndn_mgmt::LogInspector {
        ring,
        filter,
        apply_filter,
    }))
}

/// Bundles the log-appender guard (must outlive the process) and, when
/// observability is enabled, a handle to the `NdnObservabilityLayer` for
/// wiring the LP `TraceContextFeature` egress source.
pub struct TracingHandles {
    pub log_guard: Option<tracing_appender::non_blocking::WorkerGuard>,
    pub obs_layer: Option<ndn_observability::NdnObservabilityLayer>,
}

pub fn init_tracing(
    config: &ndn_config::LoggingConfig,
    cli_log_level: Option<&str>,
    obs_layer_args: Option<(std::sync::Arc<ndn_observability::SpanPublisher>, f64)>,
) -> TracingHandles {
    let obs_layer = obs_layer_args.map(|(publisher, sample)| {
        ndn_observability::NdnObservabilityLayer::new(
            publisher,
            ndn_observability::ratio_sampler(sample),
        )
    });
    let obs_layer_for_handle = obs_layer.clone();
    // Precedence: RUST_LOG > --log-level > [logging].level.
    let filter_str = if std::env::var("RUST_LOG").is_ok() {
        std::env::var("RUST_LOG").unwrap()
    } else if let Some(cli) = cli_log_level {
        cli.to_owned()
    } else {
        config.level.clone()
    };

    let _ = LOG_FILTER.set(Arc::new(Mutex::new(filter_str.clone())));
    let _ = LOG_RING.get_or_init(|| Arc::new(Mutex::new(VecDeque::<(u64, String)>::new())));

    let (filter_layer, filter_handle) =
        tracing_subscriber::reload::Layer::new(EnvFilter::new(&filter_str));

    let _ = APPLY_FILTER.set(Arc::new(move |s: &str| {
        let new_filter = EnvFilter::new(s);
        if let Err(e) = filter_handle.reload(new_filter) {
            tracing::warn!(target: "engine", error = %e, "failed to reload log filter");
        }
        if let Some(m) = LOG_FILTER.get()
            && let Ok(mut guard) = m.lock()
        {
            *guard = s.to_owned();
        }
    }));

    let stderr_layer = tracing_subscriber::fmt::layer()
        .compact()
        .with_target(true)
        .with_thread_ids(false)
        .with_ansi(false);

    if let Some(ref path) = config.file {
        let log_path = std::path::Path::new(path);

        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let file_appender = tracing_appender::rolling::never(
            log_path.parent().unwrap_or(std::path::Path::new(".")),
            log_path
                .file_name()
                .unwrap_or(std::ffi::OsStr::new("ndn-fwd.log")),
        );
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        let file_layer = tracing_subscriber::fmt::layer()
            .compact()
            .with_target(true)
            .with_thread_ids(false)
            .with_ansi(false)
            .with_writer(non_blocking);

        let ring_layer = LOG_RING.get().map(|ring| {
            tracing_subscriber::fmt::layer()
                .compact()
                .with_target(true)
                .with_thread_ids(false)
                .with_ansi(false)
                .with_writer(RingMakeWriter {
                    ring: Arc::clone(ring),
                })
        });
        #[cfg(feature = "console")]
        let registry = tracing_subscriber::registry()
            .with(filter_layer)
            .with(stderr_layer)
            .with(file_layer)
            .with(ring_layer)
            .with(obs_layer)
            .with(console_subscriber::spawn());
        #[cfg(not(feature = "console"))]
        let registry = tracing_subscriber::registry()
            .with(filter_layer)
            .with(stderr_layer)
            .with(file_layer)
            .with(ring_layer)
            .with(obs_layer);
        registry.init();

        TracingHandles {
            log_guard: Some(guard),
            obs_layer: obs_layer_for_handle,
        }
    } else {
        let ring_layer = LOG_RING.get().map(|ring| {
            tracing_subscriber::fmt::layer()
                .compact()
                .with_target(true)
                .with_thread_ids(false)
                .with_ansi(false)
                .with_writer(RingMakeWriter {
                    ring: Arc::clone(ring),
                })
        });
        #[cfg(feature = "console")]
        let registry = tracing_subscriber::registry()
            .with(filter_layer)
            .with(stderr_layer)
            .with(ring_layer)
            .with(obs_layer)
            .with(console_subscriber::spawn());
        #[cfg(not(feature = "console"))]
        let registry = tracing_subscriber::registry()
            .with(filter_layer)
            .with(stderr_layer)
            .with(ring_layer)
            .with(obs_layer);
        registry.init();

        TracingHandles {
            log_guard: None,
            obs_layer: obs_layer_for_handle,
        }
    }
}
