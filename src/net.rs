//! Socket binding with explicit IPv4/IPv6 dual-stack behaviour.

use socket2::{Domain, Protocol, Socket, Type};
use std::{io, net::SocketAddr};
use tokio::net::{TcpListener, UdpSocket};

/// Whether an IPv6 socket also accepts IPv4-mapped traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stack {
    /// IPv6 wildcard sockets also receive IPv4 traffic.
    Dual,
    /// Each address family needs its own socket.
    Separate,
}

/// Create a socket of the address's family with the requested dual-stack mode.
fn socket(address: SocketAddr, kind: Type, protocol: Protocol, stack: Stack) -> io::Result<Socket> {
    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, kind, Some(protocol))?;
    if address.is_ipv6() {
        socket.set_only_v6(stack == Stack::Separate)?;
    }
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Bind a reusable TCP listener with the given dual-stack mode and backlog.
pub fn tcp_listener(address: SocketAddr, stack: Stack, backlog: i32) -> io::Result<TcpListener> {
    let socket = socket(address, Type::STREAM, Protocol::TCP, stack)?;
    socket.set_reuse_address(true)?;
    socket.bind(&address.into())?;
    socket.listen(backlog)?;
    TcpListener::from_std(socket.into())
}

/// Bind a UDP socket with the given dual-stack mode.
pub fn udp_socket(address: SocketAddr, stack: Stack) -> io::Result<UdpSocket> {
    let socket = socket(address, Type::DGRAM, Protocol::UDP, stack)?;
    socket.bind(&address.into())?;
    UdpSocket::from_std(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dual-stack wildcard listeners accept IPv4 clients; occupied ports fail.
    #[tokio::test]
    async fn binds_dual_stack_and_reports_conflicts() {
        let listener = tcp_listener("[::]:0".parse().unwrap(), Stack::Dual, 16).unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = tokio::net::TcpStream::connect(("127.0.0.1", port));
        let (accepted, connected) = tokio::join!(listener.accept(), client);
        accepted.unwrap();
        connected.unwrap();
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = occupied.local_addr().unwrap();
        assert!(tcp_listener(address, Stack::Separate, 16).is_err());
    }
}
