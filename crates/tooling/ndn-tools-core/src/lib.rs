//! Embeddable NDN tool logic. Each tool is gated behind a Cargo feature of
//! the same name. Tool entry points accept typed `*Params`, stream
//! [`ToolEvent`]s on a `tokio::sync::mpsc::Sender`, and return when done,
//! cancelled, or when the receiver is dropped.

pub mod common;
pub use common::{ConnectConfig, EventLevel, ToolData, ToolEvent};

#[cfg(feature = "ping")]
pub mod ping;

#[cfg(feature = "iperf")]
pub mod iperf;

#[cfg(feature = "peek")]
pub mod peek;

#[cfg(feature = "put")]
pub mod put;
