//! TOML-driven transparent HTTP(S) and DNS egress filtering for Linux.
//!
//! The crate is layered so that policy decisions, access-log formatting, firewall
//! plans, and rule-document editing are pure and unit-testable, while sockets,
//! files, signals, and subprocesses are confined to thin adapters.

pub mod app;
pub mod ca;
pub mod cli;
pub mod config;
pub mod dns;
pub mod error;
pub mod host;
pub mod net;
pub mod policy;
pub mod proxy;
pub mod runtime;
pub mod telemetry;
pub mod ui;

/// A boxed, sendable future used at dynamic trait boundaries.
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;
