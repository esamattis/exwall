//! Identify the firewall host in the web UI by its name and network addresses.

use serde::{Deserialize, Serialize};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// The kernel's record of this host's name.
const KERNEL_HOSTNAME: &str = "/proc/sys/kernel/hostname";

/// The host the UI is managing, as shown in its header.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct HostInfo {
    /// The kernel hostname, or `None` when it cannot be read.
    pub hostname: Option<String>,
    /// Addresses of local interfaces that other hosts can reach, IPv4 first.
    pub addresses: Vec<IpAddr>,
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
        Self {
            hostname,
            addresses: reachable_addresses(addresses),
        }
    }
}

/// Keep only distinct addresses other hosts can reach, sorted with IPv4 first.
fn reachable_addresses(addresses: impl IntoIterator<Item = IpAddr>) -> Vec<IpAddr> {
    let mut reachable: Vec<IpAddr> = addresses.into_iter().filter(is_reachable).collect();
    reachable.sort();
    reachable.dedup();
    reachable
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

/// List every IP address assigned to a local interface.
fn interface_addresses() -> io::Result<Vec<IpAddr>> {
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
            addresses.push(address);
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

    /// LAN and public addresses remain, deduplicated with IPv4 first; local-only ones are dropped.
    #[test]
    fn filters_and_orders_reachable_addresses() {
        let addresses = [
            "2a00:1450::1",
            "93.184.216.34",
            "127.0.0.1",
            "10.87.1.54",
            "169.254.0.1",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "10.87.1.54",
        ]
        .map(|address| address.parse().unwrap());
        let expected: [IpAddr; 4] = ["10.87.1.54", "93.184.216.34", "2a00:1450::1", "fd00::1"]
            .map(|address| address.parse().unwrap());
        assert_eq!(reachable_addresses(addresses), expected);
    }

    /// Enumerating interfaces works and includes the loopback address.
    #[test]
    fn lists_interface_addresses() {
        let addresses = interface_addresses().unwrap();
        assert!(addresses.iter().any(IpAddr::is_loopback));
    }
}
