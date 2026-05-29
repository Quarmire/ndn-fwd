//! Next-generation NDN dashboard.
//!
//! This crate is intentionally shaped like a future standalone repository:
//! pure models live in `core`, management and platform concerns sit behind
//! adapters, and the Dioxus app consumes view models instead of raw wire
//! responses. The first milestone is mock-backed but executable across
//! desktop and browser targets.

pub mod app;
pub mod client;
pub mod core;
pub mod engine;
pub mod identity;
pub mod mutation;
pub mod observe;
pub mod platform;
pub mod tools;

pub use app::App;
