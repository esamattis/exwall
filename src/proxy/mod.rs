//! The HTTP(S) proxy: pure authorization, shared upstream clients, connection handling,
//! and HTTP/1.1 WebSocket relaying.

mod authorize;
mod metered;
mod original_dst;
mod server;
mod upstream;
mod websocket;

pub use authorize::{
    ConnectPlan, ForwardPlan, Rejection, Target, apply_plan, authorize, authorize_connect,
    initial_event, record_plan,
};
pub use server::{Proxy, ProxyError};
pub use upstream::{HttpUpstream, Upstream};
