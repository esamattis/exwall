//! UDP/TCP DNS filtering. DNS authorization uses hostname rules, ignoring HTTP method/path.
use crate::error::{Context, Result};
use crate::{
    access_log::{AccessLog, Entry, Failure, PendingEntry, Protocol},
    rules::normalize_host,
    state::SharedPolicy,
};
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
    access_log: AccessLog,
    policy: SharedPolicy,
    upstream: SocketAddr,
    hostname: String,
}
impl Dns {
    /// Build the DNS service and capture the host-local DNS exception.
    pub fn new(policy: SharedPolicy, upstream: SocketAddr, access_log: AccessLog) -> Self {
        let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|s| normalize_host(&s))
            .unwrap_or_default();
        Self {
            access_log,
            policy,
            upstream,
            hostname,
        }
    }

    /// Authorize every question and reject missing or unsupported query messages.
    fn decision(&self, message: &Message) -> (bool, String) {
        let policy = self.policy.load();
        if message.queries().is_empty()
            || message.message_type() != MessageType::Query
            || message.op_code() != OpCode::Query
        {
            return (false, "-".into());
        }
        let mut allowed = true;
        let rules = message
            .queries()
            .iter()
            .map(|query| {
                let name = query.name().to_utf8();
                if !policy.config.block_dns {
                    "@dns-bypass".to_owned()
                } else if let Some(rule) = policy.rules.dns_rule(&name) {
                    rule.name.clone()
                } else if normalize_host(&name) == self.hostname {
                    "@local-hostname".to_owned()
                } else {
                    allowed = false;
                    "-".to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        (allowed, rules)
    }

    /// Capture the policy decision and keep a log guard for every received DNS message.
    fn inspect(&self, wire: &[u8]) -> Result<(Message, bool, PendingEntry)> {
        let mut access = self.access_log.track(Entry::new(Protocol::Dns, "-", "-"));
        let request = match Message::from_vec(wire) {
            Ok(request) => request,
            Err(error) => {
                access.entry().fail(Failure::MalformedDns);
                return Err(error).context("malformed DNS request");
            }
        };
        access.entry().url = request
            .queries()
            .iter()
            .map(|query| {
                format!("dns://{}/{}", normalize_host(&query.name().to_utf8()), query.query_type())
            })
            .collect::<Vec<_>>()
            .join(",");
        let (allowed, rule) = self.decision(&request);
        access.entry().decision(allowed);
        access.entry().rule = rule;
        Ok((request, allowed, access))
    }

    /// Inspect one framed TCP request and relay it or return a protocol error response.
    async fn answer(&self, wire: &[u8], tcp: bool) -> Result<Vec<u8>> {
        self.relay(wire, tcp, self.inspect(wire)?).await
    }

    /// Relay an inspected request, keeping its log guard alive until completion or cancellation.
    async fn relay(
        &self,
        wire: &[u8],
        tcp: bool,
        inspected: (Message, bool, PendingEntry),
    ) -> Result<Vec<u8>> {
        let (request, allowed, mut access) = inspected;
        if !allowed {
            access.entry().dns_response("REFUSED");
            return error_response(&request, ResponseCode::Refused);
        }
        match timeout(Duration::from_secs(10), self.forward(wire, tcp)).await {
            Ok(Ok(response)) => {
                let parsed = Message::from_vec(&response).ok().filter(|parsed| {
                    parsed.id() == request.id()
                        && parsed.message_type() == MessageType::Response
                        && parsed.op_code() == request.op_code()
                        && parsed.queries() == request.queries()
                });

                let Some(parsed) = parsed else {
                    access.entry().dns_response("SERVFAIL");
                    access.entry().fail(Failure::InvalidDnsReply);
                    tracing::warn!("DNS upstream returned a malformed or mismatched response");
                    return error_response(&request, ResponseCode::ServFail);
                };

                access.entry().dns_response(dns_code(parsed.response_code()));
                Ok(response)
            }
            result => {
                tracing::warn!(error = ?result, "DNS upstream failed");
                access.entry().dns_response("SERVFAIL");
                access.entry().fail(if result.is_err() {
                    Failure::UpstreamTimeout
                } else {
                    Failure::Upstream
                });
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
        crate::udp::enable_packet_info(&udp)?;
        let udp = Arc::new(udp);
        let limit = Arc::new(Semaphore::new(256));
        let mut tasks = JoinSet::new();
        let mut buffer = vec![0; 65535];
        loop {
            tokio::select! {
                result = crate::udp::receive(&udp, &mut buffer) => {
                    let packet = result?;
                    let mut inspected = match self.inspect(&buffer[..packet.length]) {
                        Ok(inspected) => inspected,
                        Err(error) => {
                            tracing::debug!(%error, "DNS UDP request failed");
                            continue;
                        }
                    };
                    let Ok(permit) = limit.clone().try_acquire_owned() else {
                        inspected.2.entry().fail(Failure::Overloaded);
                        continue;
                    };
                    let bytes = buffer[..packet.length].to_vec();
                    let socket = udp.clone();
                    let dns = self.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        match dns.relay(&bytes, false, inspected).await {
                            Ok(response) => {
                                if let Err(error) = crate::udp::reply(&socket, &response, &packet).await {
                                    tracing::debug!(%error, "DNS UDP reply failed");
                                }
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

/// Render DNS response codes as stable, uppercase access-log result tokens.
fn dns_code(code: ResponseCode) -> String {
    match code {
        ResponseCode::NoError => "NOERROR".into(),
        ResponseCode::FormErr => "FORMERR".into(),
        ResponseCode::ServFail => "SERVFAIL".into(),
        ResponseCode::NXDomain => "NXDOMAIN".into(),
        ResponseCode::NotImp => "NOTIMP".into(),
        ResponseCode::Refused => "REFUSED".into(),
        other => u16::from(other).to_string(),
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
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("access.log");
        let (access_log, task) = AccessLog::start(crate::config::AccessLogConfig {
            path: path.clone(),
            ..crate::config::AccessLogConfig::default()
        })
        .await
        .unwrap();
        let dns = Dns::new(policy.clone(), "127.0.0.1:1".parse().unwrap(), access_log.clone());
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
        assert_eq!(dns.decision(&query), (true, "test:allow#1".into()));
        query.add_query(Query::query(Name::from_ascii("denied.test").unwrap(), RecordType::A));
        assert_eq!(dns.decision(&query), (false, "test:allow#1,-".into()));
        policy.store(Arc::new(Policy {
            config: Config {
                block_dns: false,
                ..Config::default()
            },
            rules: RuleSet::default(),
        }));
        assert_eq!(dns.decision(&query), (true, "@dns-bypass,@dns-bypass".into()));
        assert!(dns.answer(&[0], false).await.is_err());
        drop(dns);
        drop(access_log);
        task.await.unwrap().unwrap();
        let contents = std::fs::read_to_string(path).unwrap();
        assert!(contents.contains(" dns DENY - - dns://denied.test/A - REFUSED -\n"));
        assert!(contents.contains(" dns - - - - - - MALFORMED_DNS\n"));
    }
}
