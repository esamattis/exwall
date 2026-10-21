//! UDP/TCP DNS filtering. DNS authorization uses hostname rules, ignoring HTTP method/path.

use super::{
    pktinfo::{self, ReceiveError},
    relay::{DnsUpstream, Transport, error_response, validate_reply},
};
use crate::{
    error::ErrorChain,
    policy::{Decision, DnsDecision, Enforcement, Host, LocalHostname, Policy},
    runtime::PolicyStore,
    telemetry::{EventSink, Failure, PendingEvent, RequestEvent},
};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use std::{io, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};

/// Concurrent UDP requests and TCP sessions.
const CONCURRENCY: usize = 256;
/// The deadline for an upstream exchange.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(10);
/// How long an idle TCP session may wait for its next query.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a TCP message body or reply may take.
const TCP_IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Receive buffer size, the largest possible DNS message.
const MAX_MESSAGE: usize = 65_535;

/// DNS listener and session failures.
#[derive(Debug, Error)]
pub enum DnsError {
    /// A client message could not be parsed.
    #[error("malformed DNS request")]
    Malformed(#[source] hickory_proto::ProtoError),
    /// A local error response could not be encoded.
    #[error("encode DNS response")]
    Encode(#[from] hickory_proto::ProtoError),
    /// A TCP session failed.
    #[error("DNS TCP session I/O")]
    Session(#[source] io::Error),
    /// A TCP session exceeded a deadline.
    #[error("DNS TCP session timed out")]
    SessionTimeout,
    /// A response is too long for TCP framing.
    #[error("DNS response exceeds TCP framing")]
    TooLong,
    /// UDP destination metadata could not be enabled.
    #[error("enable UDP destination metadata")]
    PacketInfo(#[source] io::Error),
    /// The UDP socket failed.
    #[error("DNS UDP listener failed")]
    Receive(#[source] ReceiveError),
    /// The TCP listener failed.
    #[error("accept DNS TCP connection")]
    Accept(#[source] io::Error),
}

/// A parsed and authorized message with its pending access-log event.
struct Inspected {
    /// The parsed request.
    request: Message,
    /// Whether every question is authorized.
    allowed: bool,
    /// The event submitted when relaying completes or is cancelled.
    event: PendingEvent,
}

/// Decide a parsed message: only standard queries with questions can be authorized.
///
/// A blocking pause lifts rule denials but never authorizes non-query messages.
pub fn decide_message(
    message: &Message,
    policy: &Policy,
    local: &LocalHostname,
    enforcement: Enforcement,
) -> DnsDecision {
    let is_query =
        message.message_type() == MessageType::Query && message.op_code() == OpCode::Query;
    if message.queries().is_empty() || !is_query {
        return DnsDecision {
            matches: Vec::new(),
        };
    }
    let hosts: Vec<Host> =
        message.queries().iter().map(|query| Host::new(&query.name().to_utf8())).collect();
    policy.dns_decision(&hosts, local, enforcement)
}

/// DNS policy and upstream settings shared by UDP and TCP sessions.
#[derive(Clone)]
pub struct DnsService {
    /// Access-log and statistics mailbox.
    sink: EventSink,
    /// The active policy.
    policy: Arc<PolicyStore>,
    /// Where authorized queries are sent.
    upstream: Arc<dyn DnsUpstream>,
    /// The always-resolvable local hostname.
    local: LocalHostname,
    /// The deadline for an upstream exchange.
    upstream_timeout: Duration,
}

impl DnsService {
    /// Build the DNS service with the host-local DNS exception.
    pub fn new(
        policy: Arc<PolicyStore>,
        upstream: Arc<dyn DnsUpstream>,
        sink: EventSink,
        local: LocalHostname,
    ) -> Self {
        Self {
            sink,
            policy,
            upstream,
            local,
            upstream_timeout: UPSTREAM_TIMEOUT,
        }
    }

    /// Capture the policy decision and keep a log guard for every received DNS message.
    fn inspect(&self, wire: &[u8]) -> Result<Inspected, DnsError> {
        let mut event = self.sink.track(RequestEvent::dns());
        let request = match Message::from_vec(wire) {
            Ok(request) => request,
            Err(error) => {
                event.event().fail(Failure::MalformedDns);
                return Err(DnsError::Malformed(error));
            }
        };
        let questions: Vec<(Host, String)> = request
            .queries()
            .iter()
            .map(|query| (Host::new(&query.name().to_utf8()), query.query_type().to_string()))
            .collect();
        let urls: Vec<String> =
            questions.iter().map(|(host, kind)| format!("dns://{host}/{kind}")).collect();
        let decision =
            decide_message(&request, &self.policy.load(), &self.local, self.policy.enforcement());
        let allowed = decision.allowed();
        let pending = event.event();
        pending.url = urls.join(",");
        pending.subjects = questions.into_iter().map(|(host, _)| host).collect();
        pending.decide(Decision::from_allowed(allowed));
        pending.matches = decision.matches;
        Ok(Inspected {
            request,
            allowed,
            event,
        })
    }

    /// Inspect and answer one message, returning the wire reply.
    pub async fn answer(&self, wire: &[u8], transport: Transport) -> Result<Vec<u8>, DnsError> {
        let inspected = self.inspect(wire)?;
        self.relay(wire, transport, inspected).await
    }

    /// Relay an inspected request, keeping its log guard alive until completion or cancellation.
    async fn relay(
        &self,
        wire: &[u8],
        transport: Transport,
        inspected: Inspected,
    ) -> Result<Vec<u8>, DnsError> {
        let Inspected {
            request,
            allowed,
            mut event,
        } = inspected;
        if !allowed {
            event.event().respond_dns(ResponseCode::Refused);
            return Ok(error_response(&request, ResponseCode::Refused)?);
        }
        let exchange =
            timeout(self.upstream_timeout, self.upstream.exchange(wire, transport)).await;
        let failure = match exchange {
            Ok(Ok(reply)) => match validate_reply(&request, &reply) {
                Some(parsed) => {
                    event.event().respond_dns(parsed.response_code());
                    return Ok(reply);
                }
                None => {
                    tracing::warn!("DNS upstream returned a malformed or mismatched response");
                    Failure::InvalidDnsReply
                }
            },
            Ok(Err(error)) => {
                tracing::warn!(%error, "DNS upstream failed");
                Failure::Upstream
            }
            Err(_) => {
                tracing::warn!("DNS upstream timed out");
                Failure::UpstreamTimeout
            }
        };
        event.event().respond_dns(ResponseCode::ServFail);
        event.event().fail(failure);
        Ok(error_response(&request, ResponseCode::ServFail)?)
    }

    /// Process framed queries on one TCP connection until EOF or an inactivity timeout.
    async fn tcp_session(&self, mut stream: TcpStream) -> Result<(), DnsError> {
        loop {
            let length = timeout(TCP_IDLE_TIMEOUT, stream.read_u16())
                .await
                .map_err(|_| DnsError::SessionTimeout)?
                .map_err(DnsError::Session)?;
            let mut bytes = vec![0; usize::from(length)];
            timeout(TCP_IO_TIMEOUT, stream.read_exact(&mut bytes))
                .await
                .map_err(|_| DnsError::SessionTimeout)?
                .map_err(DnsError::Session)?;
            let response = self.answer(&bytes, Transport::Tcp).await?;
            let length = u16::try_from(response.len()).map_err(|_| DnsError::TooLong)?;
            let write = async {
                stream.write_u16(length).await?;
                stream.write_all(&response).await
            };
            timeout(TCP_IO_TIMEOUT, write)
                .await
                .map_err(|_| DnsError::SessionTimeout)?
                .map_err(DnsError::Session)?;
        }
    }

    /// Handle bounded concurrent UDP requests and TCP DNS sessions.
    pub async fn serve(self, udp: UdpSocket, tcp: TcpListener) -> Result<(), DnsError> {
        pktinfo::enable_packet_info(&udp).map_err(DnsError::PacketInfo)?;
        let udp = Arc::new(udp);
        let limit = Arc::new(Semaphore::new(CONCURRENCY));
        let mut tasks = JoinSet::new();
        let mut buffer = vec![0; MAX_MESSAGE];
        loop {
            tokio::select! {
                received = pktinfo::receive(&udp, &mut buffer) => {
                    let packet = match received {
                        Ok(packet) => packet,
                        Err(ReceiveError::Datagram(reason)) => {
                            tracing::debug!(reason, "DNS UDP datagram ignored");
                            continue;
                        }
                        Err(error) => return Err(DnsError::Receive(error)),
                    };
                    let bytes = buffer[..packet.length].to_vec();
                    let mut inspected = match self.inspect(&bytes) {
                        Ok(inspected) => inspected,
                        Err(error) => {
                            tracing::debug!(error = %ErrorChain(&error), "DNS UDP request failed");
                            continue;
                        }
                    };
                    let Ok(permit) = limit.clone().try_acquire_owned() else {
                        inspected.event.event().fail(Failure::Overloaded);
                        continue;
                    };
                    let socket = udp.clone();
                    let dns = self.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        match dns.relay(&bytes, Transport::Udp, inspected).await {
                            Ok(response) => {
                                if let Err(error) = pktinfo::reply(&socket, &response, &packet).await {
                                    tracing::debug!(%error, "DNS UDP reply failed");
                                }
                            }
                            Err(error) => {
                                tracing::debug!(error = %ErrorChain(&error), "DNS UDP request failed");
                            }
                        }
                    });
                }
                accepted = tcp.accept() => {
                    let (stream, _) = accepted.map_err(DnsError::Accept)?;
                    let Ok(permit) = limit.clone().try_acquire_owned() else {
                        continue;
                    };
                    let dns = self.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = dns.tcp_session(stream).await {
                            tracing::debug!(error = %ErrorChain(&error), "DNS TCP session ended");
                        }
                    });
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BoxFuture,
        config::RuntimeSettings,
        policy::{MatchSource, RuleId, RuleSet},
        telemetry::{EventReceiver, format},
    };
    use hickory_proto::{
        op::Query,
        rr::{Name, RecordType},
    };

    /// How the fake upstream answers.
    #[derive(Clone, Copy)]
    enum Behaviour {
        /// Echo a NOERROR response for the query.
        Answer,
        /// Return bytes that are not a DNS message.
        Garbage,
        /// Never answer.
        Hang,
    }

    /// An in-memory upstream resolver.
    struct FakeUpstream(Behaviour);

    impl DnsUpstream for FakeUpstream {
        /// Answer according to the configured behaviour.
        fn exchange<'a>(
            &'a self,
            wire: &'a [u8],
            _transport: Transport,
        ) -> BoxFuture<'a, io::Result<Vec<u8>>> {
            Box::pin(async move {
                match self.0 {
                    Behaviour::Answer => {
                        let request = Message::from_vec(wire).unwrap();
                        Ok(error_response(&request, ResponseCode::NoError).unwrap())
                    }
                    Behaviour::Garbage => Ok(b"garbage".to_vec()),
                    Behaviour::Hang => std::future::pending().await,
                }
            })
        }
    }

    /// Build a DNS service over rule text with a fake upstream and an inspectable sink.
    fn service(
        rules: &str,
        block_dns: bool,
        behaviour: Behaviour,
    ) -> (DnsService, EventReceiver, Arc<PolicyStore>) {
        let runtime = RuntimeSettings {
            block_dns,
            ..RuntimeSettings::default()
        };
        let policy = Policy::new(runtime, RuleSet::parse(rules, "test").unwrap());
        let store = Arc::new(PolicyStore::new(policy));
        let (sink, receiver) = EventSink::channel(16);
        let mut dns = DnsService::new(
            store.clone(),
            Arc::new(FakeUpstream(behaviour)),
            sink,
            LocalHostname::new(Host::new("box")),
        );
        dns.upstream_timeout = Duration::from_millis(50);
        (dns, receiver, store)
    }

    /// Encode a query with the given questions.
    fn query(names: &[(&str, RecordType)]) -> Vec<u8> {
        let mut message = Message::new();
        message.set_id(42);
        for (name, kind) in names {
            message.add_query(Query::query(Name::from_ascii(name).unwrap(), *kind));
        }
        message.to_vec().unwrap()
    }

    /// Answer a query and return the parsed reply.
    async fn answer(dns: &DnsService, wire: &[u8]) -> Message {
        Message::from_vec(&dns.answer(wire, Transport::Udp).await.unwrap()).unwrap()
    }

    /// Render the next submitted event without its timestamp.
    async fn next_row(receiver: &mut EventReceiver) -> String {
        format::message(&receiver.events.recv().await.unwrap())
    }

    /// Verify refusal, hostname-only rules, multi-question checks, and DNS bypass.
    #[tokio::test]
    async fn refuses_unmatched_names_and_all_questions_are_checked() {
        let rules = "[[allow]]\ndomain='allowed.test'\nmethods=['POST']\npathname_pattern='/only'";
        let (dns, mut events, store) = service(rules, true, Behaviour::Answer);
        let denied = answer(&dns, &query(&[("denied.test", RecordType::A)])).await;
        assert_eq!(denied.response_code(), ResponseCode::Refused);
        assert_eq!(denied.id(), 42);
        assert_eq!(next_row(&mut events).await, "dns DENY - - dns://denied.test/A - REFUSED -");

        let allowed = answer(&dns, &query(&[("Allowed.TEST.", RecordType::AAAA)])).await;
        assert_eq!(allowed.response_code(), ResponseCode::NoError);
        assert_eq!(
            next_row(&mut events).await,
            "dns ALLOW test:allow#1 - dns://allowed.test/AAAA - NOERROR -"
        );

        let mixed = query(&[("allowed.test", RecordType::AAAA), ("denied.test", RecordType::A)]);
        assert_eq!(answer(&dns, &mixed).await.response_code(), ResponseCode::Refused);
        assert_eq!(
            next_row(&mut events).await,
            "dns DENY test:allow#1,- - dns://allowed.test/AAAA,dns://denied.test/A - REFUSED -"
        );

        store.replace(Policy::new(
            RuntimeSettings {
                block_dns: false,
                ..RuntimeSettings::default()
            },
            RuleSet::default(),
        ));
        assert_eq!(answer(&dns, &mixed).await.response_code(), ResponseCode::NoError);
        assert!(next_row(&mut events).await.starts_with("dns ALLOW @dns-bypass,@dns-bypass "));

        assert!(matches!(dns.answer(&[0], Transport::Udp).await, Err(DnsError::Malformed(_))));
        assert_eq!(next_row(&mut events).await, "dns - - - - - - MALFORMED_DNS");
    }

    /// While blocking is paused, unmatched names are relayed and logged as `@paused`.
    #[tokio::test]
    async fn relays_unmatched_names_while_paused() {
        let (dns, mut events, store) = service("", true, Behaviour::Answer);
        store.pause().pause(Duration::from_secs(60));
        let reply = answer(&dns, &query(&[("denied.test", RecordType::A)])).await;
        assert_eq!(reply.response_code(), ResponseCode::NoError);
        assert_eq!(
            next_row(&mut events).await,
            "dns ALLOW @paused - dns://denied.test/A - NOERROR -"
        );
        store.pause().resume();
        let reply = answer(&dns, &query(&[("denied.test", RecordType::A)])).await;
        assert_eq!(reply.response_code(), ResponseCode::Refused);
    }

    /// The local hostname resolves without a rule; non-query messages are denied.
    #[tokio::test]
    async fn applies_local_hostname_and_rejects_non_queries() {
        let (dns, mut events, store) = service("", true, Behaviour::Answer);
        let local = answer(&dns, &query(&[("BOX.", RecordType::A)])).await;
        assert_eq!(local.response_code(), ResponseCode::NoError);
        assert!(next_row(&mut events).await.starts_with("dns ALLOW @local-hostname "));

        let mut response = Message::from_vec(&query(&[("box", RecordType::A)])).unwrap();
        response.set_message_type(MessageType::Response);
        let policy = store.snapshot();
        assert!(!decide_message(&response, &policy, &dns.local, Enforcement::Paused).allowed());
        let refused = answer(&dns, &response.to_vec().unwrap()).await;
        assert_eq!(refused.response_code(), ResponseCode::Refused);
        assert_eq!(next_row(&mut events).await, "dns DENY - - dns://box/A - REFUSED -");
        let empty = Message::new();
        assert!(
            decide_message(&empty, &policy, &dns.local, Enforcement::Paused).matches.is_empty()
        );
    }

    /// Invalid or missing upstream replies fail closed with SERVFAIL and a failure category.
    #[tokio::test]
    async fn upstream_failures_return_servfail() {
        for (behaviour, failure) in
            [(Behaviour::Garbage, "INVALID_DNS_REPLY"), (Behaviour::Hang, "UPSTREAM_TIMEOUT")]
        {
            let (dns, mut events, _store) = service("", false, behaviour);
            let reply = answer(&dns, &query(&[("x.test", RecordType::A)])).await;
            assert_eq!(reply.response_code(), ResponseCode::ServFail);
            let row = next_row(&mut events).await;
            assert!(row.ends_with(&format!(" SERVFAIL {failure}")), "{row}");
        }
    }

    /// Statistics record each question host with the message-level decision.
    #[tokio::test]
    async fn statistics_use_question_hosts() {
        let (dns, _events, _store) = service("[[allow]]\ndomain='a.test'", true, Behaviour::Answer);
        answer(&dns, &query(&[("a.test", RecordType::A), ("b.test", RecordType::A)])).await;
        let summaries = dns.sink.stats().snapshot();
        assert_eq!(summaries.len(), 2);
        assert!(summaries.iter().all(|summary| summary.dns.block == 1));
        let rule = MatchSource::Rule(RuleId::new("test", 1));
        assert_eq!(rule.to_string(), "test:allow#1");
    }

    /// TCP sessions answer framed queries until the client disconnects.
    #[tokio::test]
    async fn serves_framed_tcp_queries() {
        let (dns, _events, _store) = service("", false, Behaviour::Answer);
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap();
        let server = tokio::spawn(dns.serve(udp, tcp));
        let mut stream = TcpStream::connect(address).await.unwrap();
        let wire = query(&[("x.test", RecordType::A)]);
        stream.write_u16(wire.len() as u16).await.unwrap();
        stream.write_all(&wire).await.unwrap();
        let length = stream.read_u16().await.unwrap();
        let mut reply = vec![0; usize::from(length)];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(Message::from_vec(&reply).unwrap().response_code(), ResponseCode::NoError);
        server.abort();
    }
}
