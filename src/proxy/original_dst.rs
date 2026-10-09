//! Linux netfilter REDIRECT preserves the original destination in conntrack.
//!
//! This is the only module reading `SO_ORIGINAL_DST` through raw `getsockopt`.

use std::{
    io, mem,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    os::fd::AsRawFd,
};
use tokio::net::TcpStream;

/// The netfilter socket option returning a redirected connection's destination.
const SO_ORIGINAL_DST: libc::c_int = 80;

/// Return the original destination of a redirected connection, if it differs from the listener.
///
/// Connections made directly to the proxy (explicit proxy mode) report the
/// listener's own address and yield `None`.
pub fn redirected_destination(stream: &TcpStream) -> Option<SocketAddr> {
    let original = original_destination(stream).ok().map(normalize)?;
    let local = stream.local_addr().ok().map(normalize);
    (local != Some(original)).then_some(original)
}

/// Read the conntrack original destination, trying both address families.
fn original_destination(stream: &TcpStream) -> io::Result<SocketAddr> {
    // A dual-stack socket can carry an IPv4 REDIRECT connection. Try both
    // conntrack families rather than inferring them from the listener's family.
    let levels = if stream.local_addr()?.is_ipv6() {
        [libc::SOL_IPV6, libc::SOL_IP]
    } else {
        [libc::SOL_IP, libc::SOL_IPV6]
    };
    read_original_destination(stream, levels[0])
        .or_else(|_| read_original_destination(stream, levels[1]))
}

/// Read and decode one family's netfilter original-destination socket option.
fn read_original_destination(stream: &TcpStream, level: libc::c_int) -> io::Result<SocketAddr> {
    // SAFETY: zeroed sockaddr_storage is a valid getsockopt output buffer.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut length = mem::size_of_val(&storage) as libc::socklen_t;
    // SAFETY: storage is valid and writable for `length`; the live socket fd is borrowed.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            level,
            SO_ORIGINAL_DST,
            (&mut storage as *mut libc::sockaddr_storage).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    match libc::c_int::from(storage.ss_family) {
        libc::AF_INET if length as usize >= mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: the kernel returned AF_INET with enough bytes, and storage is suitably aligned.
            let address =
                unsafe { *(&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
            Ok(SocketAddr::new(
                Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()).into(),
                u16::from_be(address.sin_port),
            ))
        }
        libc::AF_INET6 if length as usize >= mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: the kernel returned AF_INET6 with enough bytes, and storage is suitably aligned.
            let address = unsafe {
                *(&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
            };
            Ok(SocketAddrV6::new(
                Ipv6Addr::from(address.sin6_addr.s6_addr),
                u16::from_be(address.sin6_port),
                address.sin6_flowinfo,
                address.sin6_scope_id,
            )
            .into())
        }
        _ => Err(io::Error::other("invalid original destination address")),
    }
}

/// Normalize IPv4-mapped IPv6 addresses before comparing local and original destinations.
fn normalize(address: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(ipv6) = address
        && let Some(ipv4) = ipv6.ip().to_ipv4_mapped()
    {
        return SocketAddr::new(ipv4.into(), address.port());
    }
    address
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mapped IPv4 addresses compare equal to their IPv4 form.
    #[test]
    fn normalizes_mapped_addresses() {
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:80".parse().unwrap();
        assert_eq!(normalize(mapped), "127.0.0.1:80".parse::<SocketAddr>().unwrap());
        let native: SocketAddr = "[::1]:80".parse().unwrap();
        assert_eq!(normalize(native), native);
    }

    /// Direct (non-redirected) connections report no original destination.
    #[tokio::test]
    async fn direct_connections_have_no_redirect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        let _client = client.unwrap();
        let (server, _) = accepted.unwrap();
        assert_eq!(redirected_destination(&server), None);
    }
}
