//! Privileged, idempotent iptables hooks. All commands use argv, never a shell.
use crate::config::Config;
use crate::error::{Context, Result, bail, ensure};
use std::{
    collections::HashSet,
    process::{Command, Output},
};

pub const OUTPUT: &str = "RAMAWALL_OUTPUT";
pub const NAT: &str = "RAMAWALL_NAT";
const GUARD: &str = "RAMAWALL_GUARD";
const SETUP: &str = "ramawall-setup-guard";
const FORWARD: &str = "ramawall-forwarding-guard";
const ABSENT_RULE: &str = "Bad rule (does a matching rule exist in that chain?).";
const ABSENT_CHAIN: &str = "No chain/target/match by that name.";

/// An iptables address-family client with optional command-only dry runs.
pub struct Firewall {
    pub command: &'static str,
    pub dry_run: bool,
}

/// Copy fixed command arguments into owned strings.
fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).into()).collect()
}
impl Firewall {
    /// Execute an argv-only iptables operation with the shared xtables lock.
    fn run(&self, args: &[String]) -> Result<Option<Output>> {
        if self.dry_run {
            println!("{} -w 10 {}", self.command, args.join(" "));
            return Ok(None);
        }
        let mut command = Command::new(self.command);
        command.args(["-w", "10"]).args(args).env("LC_ALL", "C");
        tracing::debug!(command = ?command, "executing command");
        Ok(Some(command.output().with_context(|| self.command.to_owned())?))
    }

    /// Require a mutating firewall command to complete successfully.
    fn checked(&self, args: &[String]) -> Result<()> {
        if let Some(output) = self.run(args)? {
            ensure!(
                output.status.success(),
                "{} {}: {}",
                self.command,
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    /// Distinguish expected absence from permission, syntax, and backend errors.
    fn probe(&self, args: &[String], absent: &str) -> Result<bool> {
        let Some(output) = self.run(args)? else {
            return Ok(false);
        };
        if output.status.success() {
            return Ok(true);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let absent_nft_chain = absent == ABSENT_CHAIN
            && stderr
                .lines()
                .any(|line| line.contains("Chain '") && line.ends_with("' does not exist"));
        if output.status.code() == Some(1)
            && (stderr.trim_end().ends_with(absent) || absent_nft_chain)
        {
            return Ok(false);
        }
        bail!("{} probe failed: {}", self.command, String::from_utf8_lossy(&output.stderr))
    }

    /// Build an exact rule operation for the requested table and chain.
    fn rule_args(table: &str, op: &str, chain: &str, rule: &[String]) -> Vec<String> {
        let mut args = strings(&["-t", table, op, chain]);
        args.extend_from_slice(rule);
        args
    }

    /// Append one rule to a managed chain.
    fn append(&self, table: &str, chain: &str, rule: &[String]) -> Result<()> {
        self.checked(&Self::rule_args(table, "-A", chain, rule))
    }

    /// Delete every exact duplicate of one rule.
    fn remove(&self, table: &str, chain: &str, rule: &[String]) -> Result<()> {
        while self.probe(&Self::rule_args(table, "-C", chain, rule), ABSENT_RULE)? {
            self.checked(&Self::rule_args(table, "-D", chain, rule))?;
        }
        Ok(())
    }

    /// Place exactly one copy of a rule at the chain head.
    fn first(&self, table: &str, chain: &str, rule: &[String]) -> Result<()> {
        self.remove(table, chain, rule)?;
        self.checked(&Self::rule_args(table, "-I", chain, rule))
    }

    /// Check for a chain, treating only the known absence message as absent.
    fn chain(&self, table: &str, chain: &str) -> Result<bool> {
        self.probe(&strings(&["-t", table, "-S", chain]), ABSENT_CHAIN)
    }

    /// Create a managed chain if necessary and clear its previous rules.
    fn rebuild(&self, table: &str, chain: &str) -> Result<()> {
        if !self.chain(table, chain)? {
            self.checked(&strings(&["-t", table, "-N", chain]))?;
        }
        self.checked(&strings(&["-t", table, "-F", chain]))
    }

    /// Keep existing enforcement, or attach a configuration-independent deny policy.
    pub fn guard(&self, proxy_user: &str) -> Result<()> {
        if self.chain("filter", OUTPUT)? {
            // A restart must retain the complete previous policy and its exceptions.
            return Ok(());
        }
        let jump = Self::rule_args("filter", "-C", "OUTPUT", &strings(&["-j", GUARD]));
        if self.chain("filter", GUARD)? && self.probe(&jump, ABSENT_RULE)? {
            return Ok(());
        }
        self.rebuild("filter", GUARD)?;
        self.append(
            "filter",
            GUARD,
            &strings(&["-m", "conntrack", "--ctdir", "REPLY", "-j", "ACCEPT"]),
        )?;
        self.append(
            "filter",
            GUARD,
            &strings(&["-m", "owner", "--uid-owner", "0", "-j", "ACCEPT"]),
        )?;
        for user in [proxy_user, "systemd-resolve", "systemd-timesync", "_chrony", "ntp"] {
            if user_exists(user)? {
                let protocols: &[(&str, &str)] =
                    if matches!(user, "systemd-timesync" | "_chrony" | "ntp") {
                        &[("udp", "123"), ("udp", "53"), ("tcp", "53")]
                    } else {
                        &[]
                    };
                if protocols.is_empty() {
                    self.append(
                        "filter",
                        GUARD,
                        &strings(&["-m", "owner", "--uid-owner", user, "-j", "ACCEPT"]),
                    )?;
                } else {
                    for (protocol, port) in protocols {
                        self.append(
                            "filter",
                            GUARD,
                            &strings(&[
                                "-p",
                                protocol,
                                "--dport",
                                port,
                                "-m",
                                "owner",
                                "--uid-owner",
                                user,
                                "-j",
                                "ACCEPT",
                            ]),
                        )?;
                    }
                }
            }
        }
        self.append("filter", GUARD, &strings(&["-o", "lo", "-j", "ACCEPT"]))?;
        if self.command == "ip6tables" {
            self.append("filter", GUARD, &strings(&["-p", "ipv6-icmp", "-j", "ACCEPT"]))?;
        }
        self.append("filter", GUARD, &strings(&["-j", "DROP"]))?;
        self.checked(&Self::rule_args("filter", "-I", "OUTPUT", &strings(&["-j", GUARD])))?;
        Ok(())
    }

    /// Remove the bootstrap policy only after replacement enforcement is installed.
    pub fn clear_guard(&self) -> Result<()> {
        if self.chain("filter", GUARD)? {
            self.remove("filter", "OUTPUT", &strings(&["-j", GUARD]))?;
            self.checked(&strings(&["-t", "filter", "-F", GUARD]))?;
            self.checked(&strings(&["-t", "filter", "-X", GUARD]))?;
        }
        Ok(())
    }

    /// Temporarily block outbound original-direction packets while rebuilding.
    pub fn setup_guard(&self) -> Result<()> {
        self.first(
            "filter",
            "OUTPUT",
            &strings(&[
                "-m",
                "conntrack",
                "--ctdir",
                "ORIGINAL",
                "-m",
                "comment",
                "--comment",
                SETUP,
                "-j",
                "DROP",
            ]),
        )
    }

    /// Remove only the temporary guard owned by ramawall.
    pub fn clear_setup_guard(&self) -> Result<()> {
        self.remove(
            "filter",
            "OUTPUT",
            &strings(&[
                "-m",
                "conntrack",
                "--ctdir",
                "ORIGINAL",
                "-m",
                "comment",
                "--comment",
                SETUP,
                "-j",
                "DROP",
            ]),
        )
    }

    /// Install or remove the guard for forwarding newly enabled by ramawall.
    pub fn forward_guard(&self, install: bool) -> Result<()> {
        let rule = strings(&["-m", "comment", "--comment", FORWARD, "-j", "DROP"]);
        if install {
            self.first("filter", "FORWARD", &rule)
        } else {
            self.remove("filter", "FORWARD", &rule)
        }
    }

    /// Rebuild complete filter/NAT policy and attach it before other OUTPUT rules.
    pub fn install(
        &self,
        config: &Config,
        proxy_user: &str,
        ntp_users: &[String],
        proxy_port: u16,
        dns_port: u16,
    ) -> Result<()> {
        self.rebuild("filter", OUTPUT)?;
        for rule in output_rules(
            config,
            proxy_user,
            ntp_users,
            proxy_port,
            dns_port,
            self.command == "ip6tables",
        ) {
            self.append("filter", OUTPUT, &rule)?;
        }
        self.first("filter", "OUTPUT", &strings(&["-j", OUTPUT]))?;
        self.rebuild("nat", NAT)?;
        for rule in nat_rules(
            config,
            proxy_user,
            ntp_users,
            proxy_port,
            dns_port,
            self.command == "ip6tables",
        ) {
            self.append("nat", NAT, &rule)?;
        }
        self.first("nat", "OUTPUT", &strings(&["-j", NAT]))?;
        Ok(())
    }

    /// Remove managed jumps and chains without reading current configuration.
    pub fn clear(&self) -> Result<()> {
        for (table, chain) in [("nat", NAT), ("filter", OUTPUT)] {
            if self.chain(table, chain)? {
                self.remove(table, "OUTPUT", &strings(&["-j", chain]))?;
                self.checked(&strings(&["-t", table, "-F", chain]))?;
                self.checked(&strings(&["-t", table, "-X", chain]))?;
            }
        }
        self.clear_setup_guard()?;
        self.clear_guard()
    }
}

/// Select custom destination exceptions for one IP address family.
fn family_bypasses(config: &Config, ipv6: bool) -> impl Iterator<Item = &crate::config::Bypass> {
    config.iptables.bypass.iter().filter(move |b| matches!(b.network, ipnet::IpNet::V6(_)) == ipv6)
}

/// Build ordered fail-closed output policy, including required service exemptions.
fn output_rules(
    config: &Config,
    proxy_user: &str,
    ntp: &[String],
    proxy_port: u16,
    dns_port: u16,
    ipv6: bool,
) -> Vec<Vec<String>> {
    let mut rules = vec![strings(&[
        "-m",
        "conntrack",
        "--ctstate",
        "ESTABLISHED,RELATED",
        "--ctdir",
        "REPLY",
        "-j",
        "ACCEPT",
    ])];
    let mut seen = HashSet::new();
    for user in
        config.bypass_users.iter().map(String::as_str).chain([proxy_user, "systemd-resolve"])
    {
        if seen.insert(user) {
            rules.push(strings(&["-m", "owner", "--uid-owner", user, "-j", "ACCEPT"]));
        }
    }
    for user in ntp {
        for (protocol, port) in [("udp", "123"), ("udp", "53"), ("tcp", "53")] {
            rules.push(strings(&[
                "-p",
                protocol,
                "--dport",
                port,
                "-m",
                "owner",
                "--uid-owner",
                user,
                "-j",
                "ACCEPT",
            ]));
        }
    }
    if ipv6 {
        rules.push(strings(&["-p", "ipv6-icmp", "-j", "ACCEPT"]));
    }
    rules.push(strings(&["-o", "lo", "-j", "ACCEPT"]));
    for (protocol, port) in [("tcp", proxy_port), ("tcp", dns_port), ("udp", dns_port)] {
        rules.push(strings(&[
            "-p",
            protocol,
            "--dport",
            &port.to_string(),
            "-m",
            "addrtype",
            "--dst-type",
            "LOCAL",
            "-j",
            "ACCEPT",
        ]));
    }
    for b in family_bypasses(config, ipv6) {
        rules.push(strings(&[
            "-p",
            "tcp",
            "-d",
            &b.network.to_string(),
            "--dport",
            &b.port.to_string(),
            "-j",
            "ACCEPT",
        ]));
    }
    rules.push(strings(&["-j", "DROP"]));
    rules
}

/// Build NAT bypasses before HTTP(S) and DNS redirect rules.
fn nat_rules(
    config: &Config,
    proxy_user: &str,
    ntp: &[String],
    proxy_port: u16,
    dns_port: u16,
    ipv6: bool,
) -> Vec<Vec<String>> {
    let mut rules = Vec::new();
    for user in config.bypass_users.iter().map(String::as_str).chain([proxy_user]) {
        rules.push(strings(&["-m", "owner", "--uid-owner", user, "-j", "ACCEPT"]));
    }
    for user in ntp.iter().map(String::as_str).chain(["systemd-resolve"]) {
        for protocol in ["udp", "tcp"] {
            rules.push(strings(&[
                "-p",
                protocol,
                "--dport",
                "53",
                "-m",
                "owner",
                "--uid-owner",
                user,
                "-j",
                "ACCEPT",
            ]));
        }
    }
    for b in family_bypasses(config, ipv6) {
        rules.push(strings(&[
            "-p",
            "tcp",
            "-d",
            &b.network.to_string(),
            "--dport",
            &b.port.to_string(),
            "-j",
            "ACCEPT",
        ]));
    }
    for protocol in ["udp", "tcp"] {
        rules.push(strings(&[
            "-p",
            protocol,
            "--dport",
            "53",
            "-j",
            "REDIRECT",
            "--to-ports",
            &dns_port.to_string(),
        ]));
    }
    for port in ["80", "443"] {
        rules.push(strings(&[
            "-p",
            "tcp",
            "!",
            "-o",
            "lo",
            "--dport",
            port,
            "-j",
            "REDIRECT",
            "--to-ports",
            &proxy_port.to_string(),
        ]));
    }
    rules
}

/// Check an account using id without interpolating its name into a shell.
pub fn user_exists(user: &str) -> Result<bool> {
    let mut command = Command::new("id");
    command.args(["-u", "--", user]).env("LC_ALL", "C");
    tracing::debug!(command = ?command, "executing command");
    let output = command.output()?;
    if output.status.success() {
        return Ok(true);
    }
    ensure!(output.status.code() == Some(1), "failed to look up user {user}");
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Verify bypass precedence, family selection, and local-only listener access.
    #[test]
    fn ordering_and_fail_closed_policy() {
        let config = Config::parse(
            r#"
bypass_users = ['root']
[[iptables.bypass]]
network = '192.168.1.19/24'
port = 443
[[iptables.bypass]]
network = '2001:db8::/32'
port = 22
"#,
        )
        .unwrap();
        let nat = nat_rules(&config, "ramawall", &["_chrony".into()], 58080, 58053, false);
        let custom = nat.iter().position(|r| r.contains(&"192.168.1.0/24".into())).unwrap();
        let redirect = nat.iter().position(|r| r.contains(&"REDIRECT".into())).unwrap();
        assert!(custom < redirect);
        assert!(nat[..redirect].iter().any(|r| r.contains(&"systemd-resolve".into())));
        assert!(!nat.iter().any(|r| r.contains(&"2001:db8::/32".into())));
        let output = output_rules(&config, "ramawall", &[], 58080, 58053, true);
        assert_eq!(output.last().unwrap(), &strings(&["-j", "DROP"]));
        assert!(output[0].contains(&"REPLY".into()));
        for rule in
            output.iter().filter(|r| r.contains(&"58080".into()) || r.contains(&"58053".into()))
        {
            assert!(rule.contains(&"LOCAL".into()));
        }
        assert!(output.iter().any(|r| r.contains(&"ipv6-icmp".into())));
    }
}
