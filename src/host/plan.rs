//! Pure firewall plans: ordered, idempotent steps derived only from their inputs.

use super::iptables::{
    BUILTIN_FORWARD, BUILTIN_OUTPUT, Direction, FORWARD_COMMENT, Family, GUARD_CHAIN, NAT_CHAIN,
    OUTPUT_CHAIN, Protocol, RuleSpec, SETUP_COMMENT, Table, Verdict,
};
use crate::config::Bypass;
use std::collections::HashSet;

/// Accounts allowed only NTP and DNS traffic, when they exist.
pub const NTP_USERS: [&str; 3] = ["systemd-timesync", "_chrony", "ntp"];
/// The system resolver's account, always exempt.
pub const RESOLVER_USER: &str = "systemd-resolve";
/// The ports NTP accounts may use: NTP and DNS.
const NTP_PORTS: [(Protocol, u16); 3] =
    [(Protocol::Udp, 123), (Protocol::Udp, 53), (Protocol::Tcp, 53)];

/// One idempotent firewall operation for a single address family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Create the chain if absent, then flush it.
    Rebuild {
        /// The table.
        table: Table,
        /// The managed chain.
        chain: &'static str,
    },
    /// Append a rule.
    Append {
        /// The table.
        table: Table,
        /// The chain.
        chain: &'static str,
        /// The rule.
        rule: RuleSpec,
    },
    /// Insert a rule at the chain head, even if a copy exists.
    Insert {
        /// The table.
        table: Table,
        /// The chain.
        chain: &'static str,
        /// The rule.
        rule: RuleSpec,
    },
    /// Remove every copy of a rule, then insert exactly one at the chain head.
    InsertOnce {
        /// The table.
        table: Table,
        /// The chain.
        chain: &'static str,
        /// The rule.
        rule: RuleSpec,
    },
    /// Remove every copy of a rule.
    RemoveAll {
        /// The table.
        table: Table,
        /// The chain.
        chain: &'static str,
        /// The rule.
        rule: RuleSpec,
    },
    /// If the chain exists, remove its OUTPUT jumps, flush it, and delete it.
    DeleteChain {
        /// The table.
        table: Table,
        /// The managed chain.
        chain: &'static str,
    },
}

/// Inputs to the installed egress policy.
#[derive(Clone, Copy, Debug)]
pub struct EgressPolicy<'a> {
    /// Configured accounts exempt from enforcement.
    pub bypass_users: &'a [String],
    /// Configured destination bypasses.
    pub bypasses: &'a [Bypass],
    /// The proxy's account.
    pub proxy_user: &'a str,
    /// Existing NTP accounts.
    pub ntp_users: &'a [String],
    /// The local proxy port.
    pub proxy_port: u16,
    /// The local DNS port.
    pub dns_port: u16,
}

/// Accounts present on the host when the bootstrap guard is built.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GuardUsers {
    /// Present proxy and resolver accounts, fully exempt.
    pub exempt: Vec<String>,
    /// Present NTP accounts, allowed NTP and DNS only.
    pub ntp: Vec<String>,
}

/// Accept rule for an account.
fn owner_accept(user: &str) -> RuleSpec {
    RuleSpec::new().owner(user).verdict(Verdict::Accept)
}

/// NTP and DNS accept rules for an NTP account.
fn ntp_rules(user: &str) -> Vec<RuleSpec> {
    NTP_PORTS
        .iter()
        .map(|(protocol, port)| {
            RuleSpec::new()
                .protocol(*protocol)
                .destination_port(*port)
                .owner(user)
                .verdict(Verdict::Accept)
        })
        .collect()
}

/// TCP destination bypass rules for this family.
fn bypass_rules(bypasses: &[Bypass], family: Family) -> Vec<RuleSpec> {
    bypasses
        .iter()
        .filter(|bypass| family.contains(&bypass.network))
        .map(|bypass| {
            RuleSpec::new()
                .protocol(Protocol::Tcp)
                .destination(&bypass.network)
                .destination_port(bypass.port)
                .verdict(Verdict::Accept)
        })
        .collect()
}

/// Ordered fail-closed output policy, including required service exemptions.
pub fn output_rules(policy: &EgressPolicy<'_>, family: Family) -> Vec<RuleSpec> {
    let mut rules = vec![
        RuleSpec::new()
            .conntrack(Some("ESTABLISHED,RELATED"), Direction::Reply)
            .verdict(Verdict::Accept),
    ];
    let mut seen = HashSet::new();
    let exempt =
        policy.bypass_users.iter().map(String::as_str).chain([policy.proxy_user, RESOLVER_USER]);
    for user in exempt {
        if seen.insert(user) {
            rules.push(owner_accept(user));
        }
    }
    for user in policy.ntp_users {
        rules.extend(ntp_rules(user));
    }
    if family == Family::V6 {
        rules.push(RuleSpec::new().protocol(Protocol::Ipv6Icmp).verdict(Verdict::Accept));
    }
    rules.push(RuleSpec::new().out_interface("lo").verdict(Verdict::Accept));
    let listeners = [
        (Protocol::Tcp, policy.proxy_port),
        (Protocol::Tcp, policy.dns_port),
        (Protocol::Udp, policy.dns_port),
    ];
    for (protocol, port) in listeners {
        rules.push(
            RuleSpec::new()
                .protocol(protocol)
                .destination_port(port)
                .local_destination()
                .verdict(Verdict::Accept),
        );
    }
    rules.extend(bypass_rules(policy.bypasses, family));
    rules.push(RuleSpec::new().verdict(Verdict::Drop));
    rules
}

/// NAT bypasses before DNS and HTTP(S) redirects.
pub fn nat_rules(policy: &EgressPolicy<'_>, family: Family) -> Vec<RuleSpec> {
    let mut rules = Vec::new();
    for user in policy.bypass_users.iter().map(String::as_str).chain([policy.proxy_user]) {
        rules.push(owner_accept(user));
    }
    for user in policy.ntp_users.iter().map(String::as_str).chain([RESOLVER_USER]) {
        for protocol in [Protocol::Udp, Protocol::Tcp] {
            rules.push(
                RuleSpec::new()
                    .protocol(protocol)
                    .destination_port(53)
                    .owner(user)
                    .verdict(Verdict::Accept),
            );
        }
    }
    rules.extend(bypass_rules(policy.bypasses, family));
    for protocol in [Protocol::Udp, Protocol::Tcp] {
        rules.push(
            RuleSpec::new()
                .protocol(protocol)
                .destination_port(53)
                .verdict(Verdict::Redirect(policy.dns_port)),
        );
    }
    for port in [80, 443] {
        rules.push(
            RuleSpec::new()
                .protocol(Protocol::Tcp)
                .not_out_interface("lo")
                .destination_port(port)
                .verdict(Verdict::Redirect(policy.proxy_port)),
        );
    }
    rules
}

/// Rebuild the filter and NAT chains and attach them before other OUTPUT rules.
pub fn install_steps(policy: &EgressPolicy<'_>, family: Family) -> Vec<Step> {
    let mut steps = vec![Step::Rebuild {
        table: Table::Filter,
        chain: OUTPUT_CHAIN,
    }];
    steps.extend(output_rules(policy, family).into_iter().map(|rule| Step::Append {
        table: Table::Filter,
        chain: OUTPUT_CHAIN,
        rule,
    }));
    steps.push(Step::InsertOnce {
        table: Table::Filter,
        chain: BUILTIN_OUTPUT,
        rule: RuleSpec::new().verdict(Verdict::Jump(OUTPUT_CHAIN)),
    });
    steps.push(Step::Rebuild {
        table: Table::Nat,
        chain: NAT_CHAIN,
    });
    steps.extend(nat_rules(policy, family).into_iter().map(|rule| Step::Append {
        table: Table::Nat,
        chain: NAT_CHAIN,
        rule,
    }));
    steps.push(Step::InsertOnce {
        table: Table::Nat,
        chain: BUILTIN_OUTPUT,
        rule: RuleSpec::new().verdict(Verdict::Jump(NAT_CHAIN)),
    });
    steps
}

/// The OUTPUT jump to the bootstrap guard.
pub fn guard_jump() -> RuleSpec {
    RuleSpec::new().verdict(Verdict::Jump(GUARD_CHAIN))
}

/// Configuration-independent deny policy exempting root, present service accounts, and loopback.
pub fn guard_rules(users: &GuardUsers, family: Family) -> Vec<RuleSpec> {
    let mut rules = vec![
        RuleSpec::new().conntrack(None, Direction::Reply).verdict(Verdict::Accept),
        owner_accept("0"),
    ];
    rules.extend(users.exempt.iter().map(|user| owner_accept(user)));
    for user in &users.ntp {
        rules.extend(ntp_rules(user));
    }
    rules.push(RuleSpec::new().out_interface("lo").verdict(Verdict::Accept));
    if family == Family::V6 {
        rules.push(RuleSpec::new().protocol(Protocol::Ipv6Icmp).verdict(Verdict::Accept));
    }
    rules.push(RuleSpec::new().verdict(Verdict::Drop));
    rules
}

/// Build the guard chain and jump to it first.
pub fn guard_steps(users: &GuardUsers, family: Family) -> Vec<Step> {
    let mut steps = vec![Step::Rebuild {
        table: Table::Filter,
        chain: GUARD_CHAIN,
    }];
    steps.extend(guard_rules(users, family).into_iter().map(|rule| Step::Append {
        table: Table::Filter,
        chain: GUARD_CHAIN,
        rule,
    }));
    steps.push(Step::Insert {
        table: Table::Filter,
        chain: BUILTIN_OUTPUT,
        rule: guard_jump(),
    });
    steps
}

/// Remove the bootstrap guard once replacement enforcement is installed.
pub fn clear_guard_steps() -> Vec<Step> {
    vec![Step::DeleteChain {
        table: Table::Filter,
        chain: GUARD_CHAIN,
    }]
}

/// The temporary rule blocking new outbound connections while rebuilding.
fn setup_guard_rule() -> RuleSpec {
    RuleSpec::new()
        .conntrack(None, Direction::Original)
        .comment(SETUP_COMMENT)
        .verdict(Verdict::Drop)
}

/// Block new outbound connections while chains are rebuilt.
pub fn setup_guard_steps() -> Vec<Step> {
    vec![Step::InsertOnce {
        table: Table::Filter,
        chain: BUILTIN_OUTPUT,
        rule: setup_guard_rule(),
    }]
}

/// Remove the temporary rebuild guard.
pub fn clear_setup_guard_steps() -> Vec<Step> {
    vec![Step::RemoveAll {
        table: Table::Filter,
        chain: BUILTIN_OUTPUT,
        rule: setup_guard_rule(),
    }]
}

/// Install or remove the guard dropping forwarding that exwall newly enabled.
pub fn forward_guard_steps(install: bool) -> Vec<Step> {
    let rule = RuleSpec::new().comment(FORWARD_COMMENT).verdict(Verdict::Drop);
    let step = if install {
        Step::InsertOnce {
            table: Table::Filter,
            chain: BUILTIN_FORWARD,
            rule,
        }
    } else {
        Step::RemoveAll {
            table: Table::Filter,
            chain: BUILTIN_FORWARD,
            rule,
        }
    };
    vec![step]
}

/// Remove every managed chain and guard without reading configuration.
pub fn clear_steps() -> Vec<Step> {
    let mut steps = vec![
        Step::DeleteChain {
            table: Table::Nat,
            chain: NAT_CHAIN,
        },
        Step::DeleteChain {
            table: Table::Filter,
            chain: OUTPUT_CHAIN,
        },
    ];
    steps.extend(clear_setup_guard_steps());
    steps.extend(clear_guard_steps());
    steps
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    /// Build a policy from a parsed configuration.
    fn policy<'a>(config: &'a Config, ntp: &'a [String]) -> EgressPolicy<'a> {
        EgressPolicy {
            bypass_users: &config.startup.bypass_users,
            bypasses: &config.startup.iptables.bypass,
            proxy_user: "exwall",
            ntp_users: ntp,
            proxy_port: 58080,
            dns_port: 58053,
        }
    }

    /// Verify bypass precedence, family selection, and local-only listener access.
    #[test]
    fn ordering_and_fail_closed_policy() {
        let config = Config::parse(
            "bypass_users = ['root']\n[[iptables.bypass]]\nnetwork = '192.168.1.19/24'\nport = 443\n[[iptables.bypass]]\nnetwork = '2001:db8::/32'\nport = 22\n",
        )
        .unwrap();
        let ntp = vec!["_chrony".to_owned()];
        let nat = nat_rules(&policy(&config, &ntp), Family::V4);
        let custom = nat.iter().position(|rule| rule.mentions("192.168.1.0/24")).unwrap();
        let redirect = nat.iter().position(|rule| rule.mentions("REDIRECT")).unwrap();
        assert!(custom < redirect);
        assert!(nat[..redirect].iter().any(|rule| rule.mentions(RESOLVER_USER)));
        assert!(!nat.iter().any(|rule| rule.mentions("2001:db8::/32")));
        let output = output_rules(&policy(&config, &[]), Family::V6);
        assert_eq!(output.last().unwrap(), &RuleSpec::new().verdict(Verdict::Drop));
        assert!(output[0].mentions("REPLY"));
        for rule in output.iter().filter(|rule| rule.mentions("58080") || rule.mentions("58053")) {
            assert!(rule.mentions("LOCAL"));
        }
        assert!(output.iter().any(|rule| rule.mentions("ipv6-icmp")));
        assert!(
            !output_rules(&policy(&config, &[]), Family::V4)
                .iter()
                .any(|rule| rule.mentions("ipv6-icmp"))
        );
    }

    /// Bypass users are deduplicated in the filter chain but listed in NAT order.
    #[test]
    fn deduplicates_filter_exemptions() {
        let config = Config::parse("bypass_users = ['exwall', 'root', 'root']").unwrap();
        let output = output_rules(&policy(&config, &[]), Family::V4);
        let owners: Vec<_> = output
            .iter()
            .filter(|rule| rule.mentions("--uid-owner"))
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            owners,
            [
                "-m owner --uid-owner exwall -j ACCEPT",
                "-m owner --uid-owner root -j ACCEPT",
                "-m owner --uid-owner systemd-resolve -j ACCEPT",
            ]
        );
    }

    /// The guard admits replies, root, present accounts, NTP, loopback, and ICMPv6, then drops.
    #[test]
    fn guard_policy_is_configuration_independent() {
        let users = GuardUsers {
            exempt: vec!["exwall".into()],
            ntp: vec!["_chrony".into()],
        };
        let rules: Vec<String> =
            guard_rules(&users, Family::V6).iter().map(ToString::to_string).collect();
        assert_eq!(
            rules,
            [
                "-m conntrack --ctdir REPLY -j ACCEPT",
                "-m owner --uid-owner 0 -j ACCEPT",
                "-m owner --uid-owner exwall -j ACCEPT",
                "-p udp --dport 123 -m owner --uid-owner _chrony -j ACCEPT",
                "-p udp --dport 53 -m owner --uid-owner _chrony -j ACCEPT",
                "-p tcp --dport 53 -m owner --uid-owner _chrony -j ACCEPT",
                "-o lo -j ACCEPT",
                "-p ipv6-icmp -j ACCEPT",
                "-j DROP",
            ]
        );
        let steps = guard_steps(&users, Family::V4);
        assert!(matches!(
            steps.first(),
            Some(Step::Rebuild {
                chain: GUARD_CHAIN,
                ..
            })
        ));
        assert!(matches!(
            steps.last(),
            Some(Step::Insert {
                chain: BUILTIN_OUTPUT,
                ..
            })
        ));
    }

    /// Installation attaches each chain after filling it, NAT after filter.
    #[test]
    fn install_attaches_chains_after_filling_them() {
        let config = Config::default();
        let steps = install_steps(&policy(&config, &[]), Family::V4);
        let jumps: Vec<_> = steps
            .iter()
            .enumerate()
            .filter(|(_, step)| matches!(step, Step::InsertOnce { .. }))
            .map(|(index, _)| index)
            .collect();
        assert_eq!(jumps.len(), 2);
        assert_eq!(
            jumps[0] + 1,
            steps
                .iter()
                .position(|step| matches!(
                    step,
                    Step::Rebuild {
                        table: Table::Nat,
                        ..
                    }
                ))
                .unwrap()
        );
        assert_eq!(jumps[1], steps.len() - 1);
        assert_eq!(clear_steps().len(), 4);
    }
}
