//! Shared UI state types for the demo. Kept platform-agnostic so the
//! main render path stays free of `wasm32` cfgs.

use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FaceStatus {
    Idle,
    Connecting,
    Connected,
    Disconnected(String),
}

impl FaceStatus {
    pub fn label(&self) -> &'static str {
        match self {
            FaceStatus::Idle => "idle",
            FaceStatus::Connecting => "connecting",
            FaceStatus::Connected => "connected",
            FaceStatus::Disconnected(_) => "disconnected",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DataView {
    pub name: String,
    pub content_type: u64,
    pub freshness: Option<Duration>,
    pub payload_len: usize,
    pub sig_type: String,
    pub rtt: Option<Duration>,
}

#[derive(Clone, Debug, Default)]
pub struct FaceCounters {
    pub bytes_in: u64,
    pub bytes_out: u64,
}
