//! Executes firewall plan steps for one address family through a [`System`].

use super::{
    command::CommandSpec,
    error::HookError,
    iptables::{ABSENT_CHAIN, ABSENT_RULE, BUILTIN_OUTPUT, Family, RuleSpec, Table, Verdict},
    plan::Step,
    system::System,
};

/// An iptables client for one address family.
pub struct Firewall<'a> {
    /// Where commands run.
    system: &'a dyn System,
    /// The address family.
    family: Family,
}

impl<'a> Firewall<'a> {
    /// Manage `family`'s firewall through `system`.
    pub fn new(system: &'a dyn System, family: Family) -> Self {
        Self {
            system,
            family,
        }
    }

    /// The address family.
    pub fn family(&self) -> Family {
        self.family
    }

    /// Build an argv-only iptables command with the shared xtables lock and a stable locale.
    fn command(&self, args: &[String]) -> CommandSpec {
        CommandSpec::new(self.family.program())
            .args(["-w", "10"])
            .args(args.iter().cloned())
            .env("LC_ALL", "C")
    }

    /// Require a mutating command to complete successfully.
    fn checked(&self, args: &[String]) -> Result<(), HookError> {
        let output = self.system.execute(&self.command(args))?;
        if output.success() {
            return Ok(());
        }
        Err(HookError::CommandFailed {
            command: format!("{} {}", self.family.program(), args.join(" ")),
            stderr: output.stderr_text(),
        })
    }

    /// Distinguish expected absence from permission, syntax, and backend errors.
    fn probe(&self, args: &[String], absent: &str) -> Result<bool, HookError> {
        let output = self.system.execute(&self.command(args))?;
        if output.success() {
            return Ok(true);
        }
        let stderr = output.stderr_text();
        let absent_nft_chain = absent == ABSENT_CHAIN
            && stderr
                .lines()
                .any(|line| line.contains("Chain '") && line.ends_with("' does not exist"));
        if output.code == Some(1) && (stderr.trim_end().ends_with(absent) || absent_nft_chain) {
            return Ok(false);
        }
        Err(HookError::ProbeFailed {
            program: self.family.program(),
            stderr,
        })
    }

    /// Build `-t table OP chain rule...`.
    fn rule_args(table: Table, operation: &str, chain: &str, rule: &RuleSpec) -> Vec<String> {
        let mut args =
            vec!["-t".to_owned(), table.name().to_owned(), operation.to_owned(), chain.to_owned()];
        args.extend(rule.args().iter().cloned());
        args
    }

    /// Build `-t table OP chain`.
    fn chain_args(table: Table, operation: &str, chain: &str) -> Vec<String> {
        vec!["-t".to_owned(), table.name().to_owned(), operation.to_owned(), chain.to_owned()]
    }

    /// Check for a chain, treating only the known absence message as absent.
    pub fn chain_exists(&self, table: Table, chain: &str) -> Result<bool, HookError> {
        self.probe(&Self::chain_args(table, "-S", chain), ABSENT_CHAIN)
    }

    /// Check for an exact rule.
    pub fn rule_exists(
        &self,
        table: Table,
        chain: &str,
        rule: &RuleSpec,
    ) -> Result<bool, HookError> {
        self.probe(&Self::rule_args(table, "-C", chain, rule), ABSENT_RULE)
    }

    /// Delete every exact duplicate of one rule.
    fn remove_all(&self, table: Table, chain: &str, rule: &RuleSpec) -> Result<(), HookError> {
        while self.rule_exists(table, chain, rule)? {
            self.checked(&Self::rule_args(table, "-D", chain, rule))?;
        }
        Ok(())
    }

    /// Apply one plan step.
    pub fn apply(&self, step: &Step) -> Result<(), HookError> {
        match step {
            Step::Rebuild {
                table,
                chain,
            } => {
                if !self.chain_exists(*table, chain)? {
                    self.checked(&Self::chain_args(*table, "-N", chain))?;
                }
                self.checked(&Self::chain_args(*table, "-F", chain))
            }
            Step::Append {
                table,
                chain,
                rule,
            } => self.checked(&Self::rule_args(*table, "-A", chain, rule)),
            Step::Insert {
                table,
                chain,
                rule,
            } => self.checked(&Self::rule_args(*table, "-I", chain, rule)),
            Step::InsertOnce {
                table,
                chain,
                rule,
            } => {
                self.remove_all(*table, chain, rule)?;
                self.checked(&Self::rule_args(*table, "-I", chain, rule))
            }
            Step::RemoveAll {
                table,
                chain,
                rule,
            } => self.remove_all(*table, chain, rule),
            Step::DeleteChain {
                table,
                chain,
            } => {
                if self.chain_exists(*table, chain)? {
                    let jump = RuleSpec::new().verdict(Verdict::Jump(chain));
                    self.remove_all(*table, BUILTIN_OUTPUT, &jump)?;
                    self.checked(&Self::chain_args(*table, "-F", chain))?;
                    self.checked(&Self::chain_args(*table, "-X", chain))?;
                }
                Ok(())
            }
        }
    }

    /// Apply steps in order, stopping at the first failure.
    pub fn apply_all(&self, steps: &[Step]) -> Result<(), HookError> {
        steps.iter().try_for_each(|step| self.apply(step))
    }
}
