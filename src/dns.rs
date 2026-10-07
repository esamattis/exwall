//! UDP/TCP DNS filtering. DNS authorization uses hostname rules, ignoring HTTP method/path.
use crate::error::{Context, Result};
use crate::{rules::normalize_host, state::SharedPolicy};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};

/// DNS policy and upstream settings shared by UDP and TCP sessions.
#[derive(Clone)]
pub struct Dns {
    policy: SharedPolicy,
    upstream: SocketAddr,
    hostname: String,
}
impl Dns {
    /// Build the DNS service and capture the host-local DNS exception.
    pub fn new(policy: SharedPolicy, upstream: SocketAddr) -> Self {
        let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|s| normalize_host(&s))
            .unwrap_or_default();
        Self {
            policy,
            upstream,
            hostname,
        }
    }

    /// Authorize every question and reject missing or unsupported query messages.
    fn allowed(&self, message: &Message) -> bool {
        let policy = self.policy.load();
        !message.queries().is_empty()
            && message.message_type() == MessageType::Query
            && message.op_code() == OpCode::Query
            && message.queries().iter().all(|q| {
                !policy.config.block_dns
                    || policy.rules.dns(&q.name().to_utf8())
                    || normalize_host(&q.name().to_utf8()) == self.hostname
            })
    }

    /// Filter a DNS request and relay it or return a protocol error response.
    async fn answer(&self, wire: &[u8], tcp: bool) -> Result<Vec<u8>> {
        let request = Message::from_vec(wire).context("malformed DNS request")?;
        if !self.allowed(&request) {
            tracing::warn!(questions = ?request.queries(), "blocked DNS request");
            return error_response(&request, ResponseCode::Refused);
        }
        match timeout(Duration::from_secs(10), self.forward(wire, tcp)).await {
            Ok(Ok(response)) => {
                let valid = Message::from_vec(&response).is_ok_and(|parsed| {
                    parsed.id() == request.id()
                        && parsed.message_type() == MessageType::Response
                        && parsed.op_code() == request.op_code()
                        && parsed.queries() == request.queries()
                });

                if !valid {
                    tracing::warn!("DNS upstream returned a malformed or mismatched response");
                    return error_response(&request, ResponseCode::ServFail);
                }

                Ok(response)
            }
            result => {
                tracing::warn!(error = ?result, "DNS upstream failed");
                error_response(&request, ResponseCode::ServFail)
            }
        }
    }

    /// Process framed queries on one TCP connection until EOF or an inactivity timeout.
    async fn tcp_session(&self, mut stream: TcpStream) -> Result<()> {
        loop {
            let length = timeout(Duration::from_secs(30), stream.read_u16()).await??;
            let mut bytes = vec![0; usize::from(length)];
            timeout(Duration::from_secs(10), stream.read_exact(&mut bytes)).await??;
            let response = self.answer(&bytes, true).await?;

            timeout(Duration::from_secs(10), async {
                stream.write_u16(response.len().try_into()?).await?;
                stream.write_all(&response).await?;
                Ok::<_, crate::error::Error>(())
            })
            .await??;
        }
    }

    /// Exchange one DNS packet with the connected UDP or framed TCP upstream.
    async fn forward(&self, wire: &[u8], tcp: bool) -> Result<Vec<u8>> {
        if tcp {
            let mut stream = TcpStream::connect(self.upstream).await?;
            stream.write_u16(wire.len().try_into()?).await?;
            stream.write_all(wire).await?;
            let length = stream.read_u16().await?;
            let mut response = vec![0; length as usize];
            stream.read_exact(&mut response).await?;
            Ok(response)
        } else {
            let bind = if self.upstream.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = UdpSocket::bind(bind).await?;
            socket.connect(self.upstream).await?;
            socket.send(wire).await?;
            let mut response = vec![0; 65535];
            let length = socket.recv(&mut response).await?;
            response.truncate(length);
            Ok(response)
        }
    }

    /// Handle bounded concurrent UDP requests and TCP DNS sessions.
    pub async fn serve(self, udp: UdpSocket, tcp: TcpListener) -> Result<()> {
        let udp = Arc::new(udp);
        let limit = Arc::new(Semaphore::new(256));
        let mut tasks = JoinSet::new();
        let mut buffer = vec![0; 65535];
        loop {
            tokio::select! {
                result = udp.recv_from(&mut buffer) => {
                    let (length, peer) = result?;
                    let Ok(permit) = limit.clone().try_acquire_owned() else {
                        continue;
                    };
                    let bytes = buffer[..length].to_vec();
                    let socket = udp.clone();
                    let dns = self.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        match dns.answer(&bytes, false).await {
                            Ok(response) => {
                                let _ = socket.send_to(&response, peer).await;
                            }
                            Err(error) => tracing::debug!(%error, "DNS UDP request failed"),
                        }
                    });
                }
                result = tcp.accept() => {
                    let (stream, _) = result?;
                    let Ok(permit) = limit.clone().try_acquire_owned() else {
                        continue;
                    };
                    let dns = self.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = dns.tcp_session(stream).await {
                            tracing::debug!(%error, "DNS TCP session ended");
                        }
                    });
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    }
}

/// Build a DNS error preserving the transaction ID and question section.
fn error_response(request: &Message, code: ResponseCode) -> Result<Vec<u8>> {
    let mut response = Message::new();
    response
        .set_id(request.id())
        .set_message_type(MessageType::Response)
        .set_op_code(request.op_code())
        .set_recursion_desired(request.recursion_desired())
        .set_recursion_available(true)
        .set_response_code(code);
    for query in request.queries() {
        response.add_query(query.clone());
    }
    Ok(response.to_vec()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, rules::RuleSet, state::Policy};
    use hickory_proto::{
        op::Query,
        rr::{Name, RecordType},
    };
    /// Verify refusal, hostname-only rules, multi-question checks, and DNS bypass.
    #[tokio::test]
    async fn refuses_unmatched_names_and_all_questions_are_checked() {
        let policy = Arc::new(arc_swap::ArcSwap::from_pointee(Policy {
            config: Config::default(),
            rules: RuleSet::parse(
                "[[allow]]\ndomain='allowed.test'\nmethods=['POST']\npathname_pattern='/only'",
                "test",
            )
            .unwrap(),
        }));
        let dns = Dns::new(policy.clone(), "127.0.0.1:1".parse().unwrap());
        let mut query = Message::new();
        query
            .set_id(42)
            .add_query(Query::query(Name::from_ascii("denied.test").unwrap(), RecordType::A));
        let answer =
            Message::from_vec(&dns.answer(&query.to_vec().unwrap(), false).await.unwrap()).unwrap();
        assert_eq!(answer.response_code(), ResponseCode::Refused);
        assert_eq!(answer.id(), 42);
        query.queries_mut().clear();
        query.add_query(Query::query(Name::from_ascii("allowed.test").unwrap(), RecordType::AAAA));
        assert!(dns.allowed(&query));
        query.add_query(Query::query(Name::from_ascii("denied.test").unwrap(), RecordType::A));
        assert!(!dns.allowed(&query));
        policy.store(Arc::new(Policy {
            config: Config {
                block_dns: false,
                ..Config::default()
            },
            rules: RuleSet::default(),
        }));
        assert!(dns.allowed(&query));
    }
}
