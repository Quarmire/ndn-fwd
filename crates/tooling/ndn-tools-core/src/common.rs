//! Shared types for streaming tool output to callers.

#[derive(Debug, Clone)]
pub struct ToolEvent {
    pub text: String,
    pub level: EventLevel,
    pub structured: Option<ToolData>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventLevel {
    Info,
    Warn,
    Error,
    Summary,
}

/// Structured payloads emitted alongside text events so UIs can drive live
/// widgets without parsing the text line.
#[derive(Debug, Clone)]
pub enum ToolData {
    PingResult {
        seq: u64,
        rtt_us: u64,
    },
    PingSummary {
        sent: u64,
        received: u64,
        nacks: u64,
        timeouts: u64,
        loss_pct: f64,
        rtt_min_us: u64,
        rtt_avg_us: u64,
        rtt_max_us: u64,
        rtt_p50_us: u64,
        rtt_p99_us: u64,
        rtt_stddev: f64,
    },
    IperfInterval {
        bytes: u64,
        throughput_bps: f64,
        rtt_avg_us: u64,
    },
    IperfSummary {
        duration_secs: f64,
        transferred_bytes: u64,
        throughput_bps: f64,
        sent: u64,
        received: u64,
        loss_pct: f64,
        rtt_avg_us: u64,
        rtt_p99_us: u64,
    },
    IperfClientConnected {
        flow_id: String,
        duration_secs: u64,
        sign_mode: String,
        payload_size: usize,
        reverse: bool,
    },
    PeekResult {
        name: String,
        bytes_received: u64,
        saved_to: Option<String>,
    },
    FetchProgress {
        received: usize,
        total: usize,
    },
    TransferProgress {
        bytes_done: u64,
        bytes_total: Option<u64>,
    },
    /// One traceroute probe round at a given HopLimit. `reached` is true when the response
    /// is from the destination (so it is `hop` forwarder-hops away). `node` is the
    /// responding hop's name when `--identify` is on and that hop runs a responder.
    TracerouteHop {
        hop: u8,
        reached: bool,
        rtt_us: Option<u64>,
        node: Option<String>,
    },
    TracerouteSummary {
        /// Forwarder-hop distance to the target (or `max_hops` if never reached).
        hops: u8,
        reached: bool,
    },
}

impl ToolEvent {
    pub fn info(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            level: EventLevel::Info,
            structured: None,
        }
    }
    pub fn warn(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            level: EventLevel::Warn,
            structured: None,
        }
    }
    pub fn error(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            level: EventLevel::Error,
            structured: None,
        }
    }
    pub fn summary(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            level: EventLevel::Summary,
            structured: None,
        }
    }
    pub fn with_data(mut self, data: ToolData) -> Self {
        self.structured = Some(data);
        self
    }
}

/// Connection parameters for tools that connect to an external router.
#[derive(Debug, Clone)]
pub struct ConnectConfig {
    pub face_socket: String,
    pub use_shm: bool,
    /// Maximum Data content body the tool expects to send or receive, in
    /// bytes. Sizes the SHM ring slot via `faces/create`'s `mtu`
    /// ControlParameter. `None` uses the router default (~256 KiB content).
    pub mtu: Option<usize>,
}

impl Default for ConnectConfig {
    fn default() -> Self {
        #[cfg(unix)]
        let face_socket = "/run/nfd/nfd.sock".to_string();
        #[cfg(windows)]
        let face_socket = r"\\.\pipe\ndn".to_string();
        Self {
            face_socket,
            use_shm: true,
            mtu: None,
        }
    }
}
