//! Typed iptables vocabulary rendered to argument vectors.

use ipnet::IpNet;
use std::fmt;

/// The filter chain holding installed egress policy.
pub const OUTPUT_CHAIN: &str = "EXWALL_OUTPUT";
/// The NAT chain holding redirects and their bypasses.
pub const NAT_CHAIN: &str = "EXWALL_NAT";
/// The configuration-independent bootstrap deny chain.
pub const GUARD_CHAIN: &str = "EXWALL_GUARD";
/// The built-in output chain.
pub const BUILTIN_OUTPUT: &str = "OUTPUT";
/// The built-in forward chain.
pub const BUILTIN_FORWARD: &str = "FORWARD";
/// Comment identifying the temporary rebuild guard.
pub const SETUP_COMMENT: &str = "exwall-setup-guard";
/// Comment identifying the guard against newly enabled forwarding.
pub const FORWARD_COMMENT: &str = "exwall-forwarding-guard";
/// iptables' message for a missing rule.
pub const ABSENT_RULE: &str = "Bad rule (does a matching rule exist in that chain?).";
/// iptables' message for a missing chain.
pub const ABSENT_CHAIN: &str = "No chain/target/match by that name.";

/// An IP address family and its iptables front end.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Family {
    /// IPv4 via `iptables`.
    V4,
    /// IPv6 via `ip6tables`.
    V6,
}

impl Family {
    /// Both families, IPv4 first.
    pub const ALL: [Family; 2] = [Family::V4, Family::V6];

    /// The iptables program for this family.
    pub fn program(self) -> &'static str {
        match self {
            Self::V4 => "iptables",
            Self::V6 => "ip6tables",
        }
    }

    /// Report whether a network belongs to this family.
    pub fn contains(self, network: &IpNet) -> bool {
        matches!((self, network), (Self::V4, IpNet::V4(_)) | (Self::V6, IpNet::V6(_)))
    }
}

/// An iptables table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Table {
    /// Packet filtering.
    Filter,
    /// Address translation.
    Nat,
}

impl Table {
    /// The table name passed to `-t`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Filter => "filter",
            Self::Nat => "nat",
        }
    }
}

/// A protocol matched with `-p`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMPv6, required for IPv6 neighbour discovery.
    Ipv6Icmp,
}

impl Protocol {
    /// The protocol name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Ipv6Icmp => "ipv6-icmp",
        }
    }
}

/// A conntrack packet direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Packets in the connection initiator's direction.
    Original,
    /// Packets in the reply direction.
    Reply,
}

/// What happens to a matching packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Let the packet through.
    Accept,
    /// Discard the packet.
    Drop,
    /// Continue in another chain.
    Jump(&'static str),
    /// Redirect to a local port (NAT only).
    Redirect(u16),
}

/// One rule's match and verdict arguments, built in iptables argument order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleSpec {
    /// Rendered arguments.
    args: Vec<String>,
}

impl RuleSpec {
    /// Start an empty rule.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append raw arguments.
    fn push(mut self, args: &[&str]) -> Self {
        self.args.extend(args.iter().map(|arg| (*arg).to_owned()));
        self
    }

    /// Match a protocol.
    pub fn protocol(self, protocol: Protocol) -> Self {
        self.push(&["-p", protocol.name()])
    }

    /// Match packets leaving through an interface.
    pub fn out_interface(self, interface: &str) -> Self {
        self.push(&["-o", interface])
    }

    /// Match packets not leaving through an interface.
    pub fn not_out_interface(self, interface: &str) -> Self {
        self.push(&["!", "-o", interface])
    }

    /// Match a destination network.
    pub fn destination(self, network: &IpNet) -> Self {
        self.push(&["-d", &network.to_string()])
    }

    /// Match a destination port (requires a protocol).
    pub fn destination_port(self, port: u16) -> Self {
        self.push(&["--dport", &port.to_string()])
    }

    /// Match packets created by a local user.
    pub fn owner(self, user: &str) -> Self {
        self.push(&["-m", "owner", "--uid-owner", user])
    }

    /// Match a conntrack direction, optionally restricted to connection states.
    pub fn conntrack(self, states: Option<&str>, direction: Direction) -> Self {
        let direction = match direction {
            Direction::Original => "ORIGINAL",
            Direction::Reply => "REPLY",
        };
        let rule = self.push(&["-m", "conntrack"]);
        let rule = match states {
            Some(states) => rule.push(&["--ctstate", states]),
            None => rule,
        };
        rule.push(&["--ctdir", direction])
    }

    /// Match packets addressed to this host.
    pub fn local_destination(self) -> Self {
        self.push(&["-m", "addrtype", "--dst-type", "LOCAL"])
    }

    /// Attach an identifying comment.
    pub fn comment(self, text: &str) -> Self {
        self.push(&["-m", "comment", "--comment", text])
    }

    /// Finish the rule with its verdict.
    pub fn verdict(self, verdict: Verdict) -> Self {
        match verdict {
            Verdict::Accept => self.push(&["-j", "ACCEPT"]),
            Verdict::Drop => self.push(&["-j", "DROP"]),
            Verdict::Jump(chain) => self.push(&["-j", chain]),
            Verdict::Redirect(port) => {
                self.push(&["-j", "REDIRECT", "--to-ports", &port.to_string()])
            }
        }
    }

    /// The rendered arguments.
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Report whether any argument equals `value`.
    pub fn mentions(&self, value: &str) -> bool {
        self.args.iter().any(|arg| arg == value)
    }
}

impl fmt::Display for RuleSpec {
    /// Render the rule as space-separated arguments.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.args.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builders render the exact argument order used by iptables-save.
    #[test]
    fn renders_rules_in_argument_order() {
        let rule = RuleSpec::new()
            .protocol(Protocol::Udp)
            .destination_port(123)
            .owner("_chrony")
            .verdict(Verdict::Accept);
        assert_eq!(rule.to_string(), "-p udp --dport 123 -m owner --uid-owner _chrony -j ACCEPT");
        let redirect = RuleSpec::new()
            .protocol(Protocol::Tcp)
            .not_out_interface("lo")
            .destination_port(80)
            .verdict(Verdict::Redirect(58080));
        assert_eq!(redirect.to_string(), "-p tcp ! -o lo --dport 80 -j REDIRECT --to-ports 58080");
        let established = RuleSpec::new()
            .conntrack(Some("ESTABLISHED,RELATED"), Direction::Reply)
            .verdict(Verdict::Accept);
        assert_eq!(
            established.to_string(),
            "-m conntrack --ctstate ESTABLISHED,RELATED --ctdir REPLY -j ACCEPT"
        );
        let setup = RuleSpec::new()
            .conntrack(None, Direction::Original)
            .comment(SETUP_COMMENT)
            .verdict(Verdict::Drop);
        assert_eq!(
            setup.to_string(),
            "-m conntrack --ctdir ORIGINAL -m comment --comment exwall-setup-guard -j DROP"
        );
        assert!(Family::V6.contains(&"2001:db8::/32".parse().unwrap()));
        assert!(!Family::V4.contains(&"2001:db8::/32".parse().unwrap()));
    }
}
