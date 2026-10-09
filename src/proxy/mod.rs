//! The HTTP(S) proxy: pure authorization, a shared upstream client, and connection handling.

mod authorize;
mod original_dst;
mod server;
mod upstream;

pub use authorize::{
    ConnectPlan, ForwardPlan, Rejection, Target, apply_plan, authorize, authorize_connect,
    initial_event, record_plan,
};
pub use server::{Proxy, ProxyError};
pub use upstream::{HttpUpstream, Upstream};
