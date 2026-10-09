//! Forwarding authorized DNS messages to the upstream resolver and validating replies.

use crate::BoxFuture;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use std::{io, net::SocketAddr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

/// The largest DNS message accepted from an upstream over UDP.
const MAX_UDP_MESSAGE: usize = 65_535;

/// The transport a DNS message arrived on, which the upstream exchange mirrors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// Unframed UDP datagrams.
    Udp,
    /// Length-prefixed TCP messages.
    Tcp,
}

/// A resolver that answers raw DNS messages.
pub trait DnsUpstream: Send + Sync {
    /// Exchange one wire-format query for one wire-format reply.
    fn exchange<'a>(
        &'a self,
        wire: &'a [u8],
        transport: Transport,
    ) -> BoxFuture<'a, io::Result<Vec<u8>>>;
}

/// The configured upstream resolver address.
pub struct SocketUpstream {
    /// Where queries are sent.
    address: SocketAddr,
}

impl SocketUpstream {
    /// Forward queries to `address`.
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
        }
    }

    /// Exchange one length-prefixed message over a new TCP connection.
    async fn exchange_tcp(&self, wire: &[u8]) -> io::Result<Vec<u8>> {
        let length = u16::try_from(wire.len()).map_err(io::Error::other)?;
        let mut stream = TcpStream::connect(self.address).await?;
        stream.write_u16(length).await?;
        stream.write_all(wire).await?;
        let length = stream.read_u16().await?;
        let mut response = vec![0; usize::from(length)];
        stream.read_exact(&mut response).await?;
        Ok(response)
    }

    /// Exchange one datagram over a new connected UDP socket.
    async fn exchange_udp(&self, wire: &[u8]) -> io::Result<Vec<u8>> {
        let bind = if self.address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(self.address).await?;
        socket.send(wire).await?;
        let mut response = vec![0; MAX_UDP_MESSAGE];
        let length = socket.recv(&mut response).await?;
        response.truncate(length);
        Ok(response)
    }
}

impl DnsUpstream for SocketUpstream {
    /// Use the same transport as the client so truncation semantics are preserved.
    fn exchange<'a>(
        &'a self,
        wire: &'a [u8],
        transport: Transport,
    ) -> BoxFuture<'a, io::Result<Vec<u8>>> {
        Box::pin(async move {
            match transport {
                Transport::Tcp => self.exchange_tcp(wire).await,
                Transport::Udp => self.exchange_udp(wire).await,
            }
        })
    }
}

/// Accept an upstream reply only if it answers exactly this request.
pub fn validate_reply(request: &Message, reply: &[u8]) -> Option<Message> {
    let parsed = Message::from_vec(reply).ok()?;
    let matches = parsed.id() == request.id()
        && parsed.message_type() == MessageType::Response
        && parsed.op_code() == request.op_code()
        && parsed.queries() == request.queries();
    matches.then_some(parsed)
}

/// Build a DNS error preserving the transaction ID and question section.
pub fn error_response(
    request: &Message,
    code: ResponseCode,
) -> Result<Vec<u8>, hickory_proto::ProtoError> {
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
    response.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::Query,
        rr::{Name, RecordType},
    };

    /// Build a query message for `name`.
    fn query(id: u16, name: &str) -> Message {
        let mut message = Message::new();
        message.set_id(id).add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        message
    }

    /// Replies must match the request's ID, type, opcode, and questions.
    #[test]
    fn validates_reply_identity() {
        let request = query(7, "a.test.");
        let good = error_response(&request, ResponseCode::NoError).unwrap();
        assert!(validate_reply(&request, &good).is_some());
        let wrong_id = error_response(&query(8, "a.test."), ResponseCode::NoError).unwrap();
        assert!(validate_reply(&request, &wrong_id).is_none());
        let wrong_name = error_response(&query(7, "b.test."), ResponseCode::NoError).unwrap();
        assert!(validate_reply(&request, &wrong_name).is_none());
        assert!(validate_reply(&request, &request.to_vec().unwrap()).is_none());
        assert!(validate_reply(&request, b"junk").is_none());
    }

    /// Error responses keep the request identity and carry the requested code.
    #[test]
    fn error_responses_preserve_questions() {
        let request = query(42, "denied.test.");
        let response =
            Message::from_vec(&error_response(&request, ResponseCode::Refused).unwrap()).unwrap();
        assert_eq!(response.id(), 42);
        assert_eq!(response.response_code(), ResponseCode::Refused);
        assert_eq!(response.queries(), request.queries());
        assert_eq!(response.message_type(), MessageType::Response);
    }
}
