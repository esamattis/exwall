//! Privileged host integration: firewall plans, executors, and lifecycle hooks.
//!
//! Plans are pure functions producing [`plan::Step`]s. A [`System`] runs the
//! commands: [`RealSystem`] executes and logs them, [`DryRunSystem`] prints them
//! against a simulated firewall, and tests use recording fakes.

pub mod command;
mod error;
pub mod files;
pub mod firewall;
mod hooks;
pub mod iptables;
pub mod plan;
pub mod simulate;
pub mod state;
mod system;

pub use error::HookError;
pub use hooks::{HookSettings, Hooks, LifecycleLock, Mode};
pub use system::{DryRunSystem, RealSystem, System};
