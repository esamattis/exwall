//! Preserve UDP destination addresses so transparent DNS replies reverse NAT correctly.

use socket2::{SockAddr, SockAddrStorage};
use std::{io, mem, os::fd::AsRawFd, ptr};
use tokio::{io::Interest, net::UdpSocket};

/// A datagram's size, peer, and aligned source-address metadata for its reply.
pub struct Packet {
    pub length: usize,
    peer: SockAddr,
    control: [usize; 8],
    control_length: usize,
}

/// Ask Linux to report the local destination of each IPv4 or dual-stack datagram.
pub fn enable_packet_info(socket: &UdpSocket) -> io::Result<()> {
    let (level, option) = if socket.local_addr()?.is_ipv4() {
        (libc::IPPROTO_IP, libc::IP_PKTINFO)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
    };
    let enabled: libc::c_int = 1;
    // SAFETY: the live socket and initialized integer remain valid for this call.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            ptr::from_ref(&enabled).cast(),
            mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Receive a datagram and retain its destination while respecting Tokio readiness.
pub async fn receive(socket: &UdpSocket, buffer: &mut [u8]) -> io::Result<Packet> {
    socket.async_io(Interest::READABLE, || receive_ready(socket, buffer)).await
}

/// Read one ready datagram and select its original local address for the reply.
fn receive_ready(socket: &UdpSocket, buffer: &mut [u8]) -> io::Result<Packet> {
    let mut address = SockAddrStorage::zeroed();
    let mut control = [0usize; 8];
    let mut data = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    // SAFETY: all-zero msghdr has null pointers and zero lengths, replaced below.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_name = ptr::from_mut(&mut address).cast();
    message.msg_namelen = mem::size_of_val(&address) as libc::socklen_t;
    message.msg_iov = ptr::from_mut(&mut data);
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = mem::size_of_val(&control);
    // SAFETY: every output buffer is writable and lives until recvmsg returns.
    let length = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, 0) };
    if length == -1 {
        return Err(io::Error::last_os_error());
    }
    if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(io::Error::other("truncated UDP packet or destination metadata"));
    }
    // SAFETY: recvmsg filled the aligned control buffer and reported its valid length.
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null() {
        return Err(io::Error::other("UDP packet is missing destination metadata"));
    }
    // SAFETY: CMSG_FIRSTHDR returned a header within the initialized control buffer.
    let (level, kind, header_length) =
        unsafe { ((*header).cmsg_level, (*header).cmsg_type, (*header).cmsg_len) };
    match (level, kind) {
        (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
            // SAFETY: CMSG_LEN only computes the storage length of this fixed type.
            let required = unsafe { libc::CMSG_LEN(mem::size_of::<libc::in_pktinfo>() as u32) };
            if header_length < required as usize || header_length > message.msg_controllen {
                return Err(io::Error::other("invalid IPv4 UDP destination metadata"));
            }
            // SAFETY: the checked header covers a complete in_pktinfo inside control.
            unsafe {
                let info = libc::CMSG_DATA(header).cast::<libc::in_pktinfo>();
                (*info).ipi_spec_dst = (*info).ipi_addr;
                (*info).ipi_ifindex = 0;
            }
        }
        (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
            // SAFETY: CMSG_LEN only computes the storage length of this fixed type.
            let required = unsafe { libc::CMSG_LEN(mem::size_of::<libc::in6_pktinfo>() as u32) };
            if header_length < required as usize || header_length > message.msg_controllen {
                return Err(io::Error::other("invalid IPv6 UDP destination metadata"));
            }
            // SAFETY: the checked header covers a complete in6_pktinfo inside control.
            unsafe {
                let info = libc::CMSG_DATA(header).cast::<libc::in6_pktinfo>();
                (*info).ipi6_ifindex = 0;
            }
        }
        _ => return Err(io::Error::other("unexpected UDP destination metadata")),
    }
    // SAFETY: recvmsg initialized the address and returned its actual length.
    let peer = unsafe { SockAddr::new(address, message.msg_namelen) };
    Ok(Packet {
        length: length as usize,
        peer,
        control,
        control_length: message.msg_controllen,
    })
}

/// Send a DNS reply from the exact address that received the request.
pub async fn reply(socket: &UdpSocket, bytes: &[u8], packet: &Packet) -> io::Result<()> {
    socket.async_io(Interest::WRITABLE, || reply_ready(socket, bytes, packet)).await
}

/// Write one ready UDP reply with IPv4 or IPv6 source-address ancillary data.
fn reply_ready(socket: &UdpSocket, bytes: &[u8], packet: &Packet) -> io::Result<()> {
    let mut data = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: all-zero msghdr has null pointers and zero lengths, replaced below.
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_name = packet.peer.as_ptr().cast_mut().cast();
    message.msg_namelen = packet.peer.len();
    message.msg_iov = ptr::from_mut(&mut data);
    message.msg_iovlen = 1;
    message.msg_control = packet.control.as_ptr().cast_mut().cast();
    message.msg_controllen = packet.control_length;
    // SAFETY: sendmsg only reads the valid address, bytes, and aligned control data.
    let sent = unsafe { libc::sendmsg(socket.as_raw_fd(), &message, 0) };
    if sent == -1 {
        return Err(io::Error::last_os_error());
    }
    if sent as usize != bytes.len() {
        return Err(io::Error::other("incomplete UDP reply"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    /// Verify wildcard listeners reply from each requested address, including mapped IPv4.
    #[tokio::test]
    async fn replies_from_received_destination() {
        for (listen, host) in [
            ("0.0.0.0:0", "127.0.0.1"),
            ("0.0.0.0:0", "127.0.0.2"),
            ("[::]:0", "127.0.0.2"),
            ("[::]:0", "::1"),
        ] {
            let server = crate::udp_listener(listen.parse().unwrap()).unwrap();
            enable_packet_info(&server).unwrap();
            let local = if host.contains(':') {
                "[::1]:0"
            } else {
                "127.0.0.1:0"
            };
            let client = UdpSocket::bind(local).await.unwrap();
            let target = std::net::SocketAddr::new(
                host.parse().unwrap(),
                server.local_addr().unwrap().port(),
            );
            client.connect(target).await.unwrap();
            client.send(b"query").await.unwrap();
            let mut buffer = [0; 64];
            let packet = timeout(Duration::from_secs(3), receive(&server, &mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buffer[..packet.length], b"query");
            reply(&server, b"answer", &packet).await.unwrap();
            let (length, peer) = timeout(Duration::from_secs(3), client.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(peer, target);
            assert_eq!(&buffer[..length], b"answer");
        }
    }
}
