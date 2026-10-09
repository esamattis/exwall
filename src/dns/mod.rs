//! DNS filtering: pure message decisions, an upstream relay, and UDP/TCP servers.

mod pktinfo;
mod relay;
mod server;

pub use relay::{DnsUpstream, SocketUpstream, Transport, error_response, validate_reply};
pub use server::{DnsError, DnsService, decide_message};
