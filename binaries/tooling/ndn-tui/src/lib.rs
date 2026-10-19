//! The admin and power-user terminal UI of a personal NDN device: the
//! trusted prefixes it takes part in (and how), their members, invites and
//! approvals, the data it serves and caches, and the connections that carry
//! it. Not the ordinary user's surface (apps are); the oversight and setup
//! tool for whoever runs the device.
//!
//! The daemon supplies codes and facts ([`daemon`], [`live`]); the TUI
//! supplies the words ([`words`]). [`model`] is the state layer: listings
//! and events in, what the screens show out. [`app`] turns keys into
//! effects, [`exec`] carries them out, [`ui`] draws. Secrets a root
//! operation needs are typed here and never leave this process ([`root`]).

pub mod app;
pub mod daemon;
pub mod driver;
pub mod exec;
pub mod live;
pub mod model;
pub mod root;
pub mod ui;
pub mod words;

/// The program's name, as shown in its title bar. (The binary's name is
/// set in Cargo.toml.)
pub const APP_NAME: &str = "ndn-tui";
