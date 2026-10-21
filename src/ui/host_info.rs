//! Identify the firewall host in the web UI by its name and network addresses.

use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    ffi::CStr,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
};

/// The kernel's record of this host's name.
const KERNEL_HOSTNAME: &str = "/proc/sys/kernel/hostname";

/// Documentation-only destinations used to ask the kernel which source
/// addresses it would pick for traffic leaving through the default routes.
///
/// Connecting a UDP socket only performs a route lookup; nothing is sent.
const ROUTE_PROBES: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
];

/// The host the UI is managing, as shown in its header.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct HostInfo {
    /// The kernel hostname, or `None` when it cannot be read.
    pub hostname: Option<String>,
    /// Addresses of local interfaces that other hosts can reach, those on
    /// default-route interfaces first, then IPv4 before IPv6.
    pub addresses: Vec<InterfaceAddress>,
}

/// One address assigned to a local network interface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InterfaceAddress {
    /// Whether the interface carries a default route, which makes this the
    /// address other hosts most likely know the host by.
    pub default_route: bool,
    /// The assigned address.
    pub address: IpAddr,
    /// The interface name, such as `eth0` or `docker0`.
    pub interface: String,
}

impl HostInfo {
    /// Read the current hostname and interface addresses.
    ///
    /// Either part degrades to empty with a warning, so the header never fails
    /// to render because of a host lookup.
    pub fn read() -> Self {
        let hostname = match std::fs::read_to_string(KERNEL_HOSTNAME) {
            Ok(name) => Some(name.trim().to_owned()).filter(|name| !name.is_empty()),
            Err(error) => {
                tracing::warn!(%error, "cannot read the hostname for the web UI");
                None
            }
        };
        let addresses = interface_addresses().unwrap_or_else(|error| {
            tracing::warn!(%error, "cannot list interface addresses for the web UI");
            Vec::new()
        });
        let sources = ROUTE_PROBES.into_iter().filter_map(route_source);
        Self {
            hostname,
            addresses: reachable_addresses(addresses, sources),
        }
    }
}

/// Keep only distinct addresses other hosts can reach and mark those on
/// interfaces that own one of the default-route source addresses.
///
/// The result lists default-route interfaces first, then IPv4 before IPv6.
fn reachable_addresses(
    addresses: Vec<(String, IpAddr)>,
    route_sources: impl IntoIterator<Item = IpAddr>,
) -> Vec<InterfaceAddress> {
    let route_sources: BTreeSet<IpAddr> = route_sources.into_iter().collect();
    let default_interfaces: BTreeSet<&str> = addresses
        .iter()
        .filter(|(_, address)| route_sources.contains(address))
        .map(|(interface, _)| interface.as_str())
        .collect();
    let mut reachable: Vec<InterfaceAddress> = addresses
        .iter()
        .filter(|(_, address)| is_reachable(address))
        .map(|(interface, address)| InterfaceAddress {
            default_route: default_interfaces.contains(interface.as_str()),
            address: *address,
            interface: interface.clone(),
        })
        .collect();
    reachable.sort_by(|left, right| {
        right
            .default_route
            .cmp(&left.default_route)
            .then(left.address.cmp(&right.address))
            .then(left.interface.cmp(&right.interface))
    });
    reachable.dedup_by(|right, left| left.address == right.address);
    reachable
}

/// Find the source address the kernel would use to reach `destination`, or
/// `None` when no route covers it.
fn route_source(destination: IpAddr) -> Option<IpAddr> {
    let unspecified = match destination {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let socket = UdpSocket::bind(SocketAddr::new(unspecified, 0)).ok()?;
    socket.connect(SocketAddr::new(destination, 9)).ok()?;
    Some(socket.local_addr().ok()?.ip())
}

/// Report whether an address identifies this host to other hosts.
///
/// Private LAN addresses count, since a host behind NAT has no other address
/// of its own; loopback, link-local, and multicast addresses do not.
fn is_reachable(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !(address.is_loopback()
                || address.is_link_local()
                || address.is_unspecified()
                || address.is_broadcast()
                || address.is_multicast())
        }
        IpAddr::V6(address) => {
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || address.is_unicast_link_local())
        }
    }
}

/// List every IP address assigned to a local interface with the interface's name.
fn interface_addresses() -> io::Result<Vec<(String, IpAddr)>> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `list` is a valid out pointer; on success it receives a list that
    // is freed exactly once below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut addresses = Vec::new();
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: `entry` is a node of the list returned above, which is not yet freed.
        let interface = unsafe { &*entry };
        // SAFETY: `ifa_addr` is null or points to a socket address of its stated family.
        if let Some(address) = unsafe { ip_address(interface.ifa_addr) } {
            // SAFETY: `ifa_name` points to a NUL-terminated name owned by the list.
            let name = unsafe { CStr::from_ptr(interface.ifa_name) };
            addresses.push((name.to_string_lossy().into_owned(), address));
        }
        entry = interface.ifa_next;
    }
    // SAFETY: `list` came from a successful getifaddrs and no references to it remain.
    unsafe { libc::freeifaddrs(list) };
    Ok(addresses)
}

/// Convert an IPv4 or IPv6 socket address to its IP address.
///
/// # Safety
///
/// `address` must be null or point to a socket address whose storage matches
/// its `sa_family`.
unsafe fn ip_address(address: *const libc::sockaddr) -> Option<IpAddr> {
    if address.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees a valid socket address.
    let family = i32::from(unsafe { (*address).sa_family });
    match family {
        libc::AF_INET => {
            // SAFETY: the family says the storage is a `sockaddr_in`.
            let socket = unsafe { address.cast::<libc::sockaddr_in>().read_unaligned() };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(socket.sin_addr.s_addr))))
        }
        libc::AF_INET6 => {
            // SAFETY: the family says the storage is a `sockaddr_in6`.
            let socket = unsafe { address.cast::<libc::sockaddr_in6>().read_unaligned() };
            Some(IpAddr::V6(Ipv6Addr::from(socket.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse `(interface, address)` pairs for test input.
    fn assigned(pairs: &[(&str, &str)]) -> Vec<(String, IpAddr)> {
        pairs
            .iter()
            .map(|(interface, address)| ((*interface).to_owned(), address.parse().unwrap()))
            .collect()
    }

    /// Summarize addresses as `(interface, address, default_route)` for comparison.
    fn summary(addresses: &[InterfaceAddress]) -> Vec<(&str, String, bool)> {
        addresses
            .iter()
            .map(|entry| (entry.interface.as_str(), entry.address.to_string(), entry.default_route))
            .collect()
    }

    /// LAN and public addresses remain, deduplicated with IPv4 first; local-only ones are dropped.
    #[test]
    fn filters_and_orders_reachable_addresses() {
        let addresses = assigned(&[
            ("eth0", "2a00:1450::1"),
            ("eth1", "93.184.216.34"),
            ("lo", "127.0.0.1"),
            ("eth0", "10.87.1.54"),
            ("eth0", "169.254.0.1"),
            ("eth0", "224.0.0.1"),
            ("lo", "::1"),
            ("eth0", "fe80::1"),
            ("eth0", "fd00::1"),
            ("eth0", "10.87.1.54"),
        ]);
        let expected = [
            ("eth0", "10.87.1.54".to_owned(), false),
            ("eth1", "93.184.216.34".to_owned(), false),
            ("eth0", "2a00:1450::1".to_owned(), false),
            ("eth0", "fd00::1".to_owned(), false),
        ];
        assert_eq!(summary(&reachable_addresses(addresses, [])), expected);
    }

    /// Every address on the interface owning a route source is marked and listed first.
    #[test]
    fn lists_default_route_interfaces_first() {
        let addresses = assigned(&[
            ("docker0", "172.17.0.1"),
            ("eth0", "10.87.1.23"),
            ("eth0", "2a00:1450::1"),
            ("br-1", "172.18.0.1"),
            ("eth0", "fe80::1"),
        ]);
        let sources = ["10.87.1.23".parse().unwrap()];
        let expected = [
            ("eth0", "10.87.1.23".to_owned(), true),
            ("eth0", "2a00:1450::1".to_owned(), true),
            ("docker0", "172.17.0.1".to_owned(), false),
            ("br-1", "172.18.0.1".to_owned(), false),
        ];
        assert_eq!(summary(&reachable_addresses(addresses, sources)), expected);
    }

    /// Enumerating interfaces works and includes the loopback address.
    #[test]
    fn lists_interface_addresses() {
        let addresses = interface_addresses().unwrap();
        assert!(addresses.iter().any(|(_, address)| address.is_loopback()));
    }
}
