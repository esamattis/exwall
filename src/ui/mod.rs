//! The embedded web UI: assets, authentication, rule editing, and the JSON API.

mod api;
mod assets;
pub mod auth;
mod rule_files;
pub mod rules_doc;
mod server;

pub use api::{Api, ApiError, InternalError};
pub use rule_files::{RuleFiles, WEB_RULES_FILE, WriteOutcome};
pub use server::{UiError, bind, route, serve};
