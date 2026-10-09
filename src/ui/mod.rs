//! The embedded web UI: assets, authentication, rule editing, and the JSON API.

mod api;
mod assets;
pub mod auth;
pub mod rules_doc;
mod server;
mod web_rules;

pub use api::{Api, ApiError, InternalError};
pub use server::{UiError, bind, route, serve};
pub use web_rules::{WEB_RULES_FILE, WebRulesFile, WriteOutcome};
