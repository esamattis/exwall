//! An in-memory model of iptables used by dry runs and tests.
//!
//! It interprets the argument vectors exwall issues (`-S`, `-C`, `-A`, `-I`,
//! `-D`, `-N`, `-F`, `-X`) with iptables' exit codes and absence messages, so
//! probes stay consistent with earlier simulated changes.

use super::{
    command::CommandOutput,
    iptables::{ABSENT_CHAIN, ABSENT_RULE, Family, Table},
};
use std::collections::BTreeMap;

/// Chains that exist in every table without being created.
const BUILTIN_CHAINS: [&str; 5] = ["INPUT", "FORWARD", "OUTPUT", "PREROUTING", "POSTROUTING"];

/// Targets that are not user chains.
const BUILTIN_TARGETS: [&str; 4] = ["ACCEPT", "DROP", "REDIRECT", "RETURN"];

/// One family's simulated tables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulatedTables {
    /// Rules of every chain, keyed by table and chain name.
    chains: BTreeMap<(String, String), Vec<Vec<String>>>,
}

impl Default for SimulatedTables {
    /// Start with empty built-in chains.
    fn default() -> Self {
        let mut chains = BTreeMap::new();
        for (table, names) in [
            ("filter", &["INPUT", "FORWARD", "OUTPUT"][..]),
            ("nat", &["PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"][..]),
        ] {
            for name in names {
                chains.insert((table.to_owned(), (*name).to_owned()), Vec::new());
            }
        }
        Self {
            chains,
        }
    }
}

/// A parsed iptables operation.
enum Operation {
    /// `-S [chain]`.
    List(Option<String>),
    /// `-C chain rule`.
    Check(String, Vec<String>),
    /// `-A chain rule`.
    Append(String, Vec<String>),
    /// `-I chain rule`.
    Insert(String, Vec<String>),
    /// `-D chain rule`.
    Delete(String, Vec<String>),
    /// `-N chain`.
    Create(String),
    /// `-F chain`.
    Flush(String),
    /// `-X chain`.
    Remove(String),
}

impl SimulatedTables {
    /// Return the rules of a chain, if it exists.
    pub fn rules(&self, table: Table, chain: &str) -> Option<&[Vec<String>]> {
        self.chains.get(&(table.name().to_owned(), chain.to_owned())).map(Vec::as_slice)
    }

    /// Report whether a chain exists.
    pub fn has_chain(&self, table: Table, chain: &str) -> bool {
        self.rules(table, chain).is_some()
    }

    /// Execute one iptables argument vector (without the program name).
    pub fn execute(&mut self, family: Family, args: &[String]) -> CommandOutput {
        let program = family.program();
        let (table, operation) = match parse(args) {
            Ok(parsed) => parsed,
            Err(message) => return CommandOutput::failed(2, format!("{program}: {message}\n")),
        };
        let absent_chain = || CommandOutput::failed(1, format!("{program}: {ABSENT_CHAIN}\n"));
        let absent_rule = || CommandOutput::failed(1, format!("{program}: {ABSENT_RULE}\n"));
        let key = |chain: &str| (table.clone(), chain.to_owned());
        if let Operation::Append(_, rule) | Operation::Insert(_, rule) = &operation
            && !self.target_exists(&table, rule)
        {
            return absent_chain();
        }
        match operation {
            Operation::List(chain) => {
                self.list(&table, chain.as_deref()).unwrap_or_else(absent_chain)
            }
            Operation::Check(chain, rule) => match self.chains.get(&key(&chain)) {
                Some(rules) if rules.contains(&rule) => CommandOutput::ok(""),
                _ => absent_rule(),
            },
            Operation::Append(chain, rule) => match self.chains.get_mut(&key(&chain)) {
                Some(rules) => {
                    rules.push(rule);
                    CommandOutput::ok("")
                }
                None => absent_chain(),
            },
            Operation::Insert(chain, rule) => match self.chains.get_mut(&key(&chain)) {
                Some(rules) => {
                    rules.insert(0, rule);
                    CommandOutput::ok("")
                }
                None => absent_chain(),
            },
            Operation::Delete(chain, rule) => match self.chains.get_mut(&key(&chain)) {
                Some(rules) => match rules.iter().position(|existing| *existing == rule) {
                    Some(index) => {
                        rules.remove(index);
                        CommandOutput::ok("")
                    }
                    None => absent_rule(),
                },
                None => absent_chain(),
            },
            Operation::Create(chain) => {
                if self.chains.contains_key(&key(&chain)) {
                    return CommandOutput::failed(1, format!("{program}: Chain already exists.\n"));
                }
                self.chains.insert(key(&chain), Vec::new());
                CommandOutput::ok("")
            }
            Operation::Flush(chain) => match self.chains.get_mut(&key(&chain)) {
                Some(rules) => {
                    rules.clear();
                    CommandOutput::ok("")
                }
                None => absent_chain(),
            },
            Operation::Remove(chain) => {
                self.remove_chain(&table, &chain).unwrap_or_else(absent_chain)
            }
        }
    }

    /// Render `-S` output for one chain or the whole table.
    fn list(&self, table: &str, chain: Option<&str>) -> Option<CommandOutput> {
        let mut output = String::new();
        let mut found = false;
        for ((chain_table, name), rules) in &self.chains {
            if chain_table != table || chain.is_some_and(|wanted| wanted != name) {
                continue;
            }
            found = true;
            if BUILTIN_CHAINS.contains(&name.as_str()) {
                output.push_str(&format!("-P {name} ACCEPT\n"));
            } else {
                output.push_str(&format!("-N {name}\n"));
            }
            for rule in rules {
                output.push_str(&format!("-A {name} {}\n", rule.join(" ")));
            }
        }
        found.then(|| CommandOutput::ok(output))
    }

    /// Report whether a rule's jump target exists in the table.
    fn target_exists(&self, table: &str, rule: &[String]) -> bool {
        let Some(position) = rule.iter().position(|arg| arg == "-j") else {
            return true;
        };
        let Some(target) = rule.get(position + 1) else {
            return false;
        };
        BUILTIN_TARGETS.contains(&target.as_str())
            || self.chains.contains_key(&(table.to_owned(), target.clone()))
    }

    /// Delete an empty, unreferenced user chain.
    fn remove_chain(&mut self, table: &str, chain: &str) -> Option<CommandOutput> {
        let key = (table.to_owned(), chain.to_owned());
        let rules = self.chains.get(&key)?;
        if !rules.is_empty() {
            return Some(CommandOutput::failed(1, "Directory not empty\n"));
        }
        let referenced = self.chains.iter().any(|((other, _), rules)| {
            other == table
                && rules.iter().any(|rule| rule.windows(2).any(|w| w[0] == "-j" && w[1] == chain))
        });
        if referenced {
            return Some(CommandOutput::failed(1, "Too many links\n"));
        }
        self.chains.remove(&key);
        Some(CommandOutput::ok(""))
    }
}

/// Parse the table and operation from an iptables argument vector.
fn parse(args: &[String]) -> Result<(String, Operation), &'static str> {
    let mut table = "filter".to_owned();
    let mut rest = args;
    loop {
        match rest {
            [flag, _, tail @ ..] if flag == "-w" => rest = tail,
            [flag, name, tail @ ..] if flag == "-t" => {
                table = name.clone();
                rest = tail;
            }
            _ => break,
        }
    }
    let [operation, tail @ ..] = rest else {
        return Err("missing operation");
    };
    let chain = || tail.first().cloned().ok_or("missing chain");
    let rule = || tail.get(1..).map(<[String]>::to_vec).unwrap_or_default();
    let operation = match operation.as_str() {
        "-S" => Operation::List(tail.first().cloned()),
        "-C" => Operation::Check(chain()?, rule()),
        "-A" => Operation::Append(chain()?, rule()),
        "-I" => Operation::Insert(chain()?, rule()),
        "-D" => Operation::Delete(chain()?, rule()),
        "-N" => Operation::Create(chain()?),
        "-F" => Operation::Flush(chain()?),
        "-X" => Operation::Remove(chain()?),
        _ => return Err("unsupported operation"),
    };
    Ok((table, operation))
}

/// Report whether an iptables argument vector changes state.
pub fn is_mutation(args: &[String]) -> bool {
    args.iter().any(|arg| matches!(arg.as_str(), "-A" | "-I" | "-D" | "-N" | "-F" | "-X"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Convert string slices to owned arguments.
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    /// The simulator reproduces iptables' success and absence semantics.
    #[test]
    fn models_chain_and_rule_lifecycle() {
        let mut tables = SimulatedTables::default();
        let v4 = Family::V4;
        assert_eq!(
            tables.execute(v4, &args(&["-w", "10", "-t", "filter", "-S", "X"])).code,
            Some(1)
        );
        assert!(tables.execute(v4, &args(&["-t", "filter", "-N", "X"])).success());
        assert!(!tables.execute(v4, &args(&["-t", "filter", "-N", "X"])).success());
        let jump = args(&["-t", "filter", "-I", "OUTPUT", "-j", "X"]);
        assert!(tables.execute(v4, &jump).success());
        assert!(
            !tables
                .execute(v4, &args(&["-t", "filter", "-I", "OUTPUT", "-j", "MISSING"]))
                .success()
        );
        assert!(tables.execute(v4, &args(&["-t", "filter", "-A", "X", "-j", "DROP"])).success());
        assert!(tables.execute(v4, &args(&["-t", "filter", "-C", "X", "-j", "DROP"])).success());
        let missing = tables.execute(v4, &args(&["-t", "filter", "-C", "X", "-j", "ACCEPT"]));
        assert!(missing.stderr_text().trim_end().ends_with(ABSENT_RULE));
        assert_eq!(tables.execute(v4, &args(&["-t", "filter", "-X", "X"])).code, Some(1));
        assert!(tables.execute(v4, &args(&["-t", "filter", "-F", "X"])).success());
        assert_eq!(tables.execute(v4, &args(&["-t", "filter", "-X", "X"])).code, Some(1));
        assert!(tables.execute(v4, &args(&["-t", "filter", "-D", "OUTPUT", "-j", "X"])).success());
        assert!(tables.execute(v4, &args(&["-t", "filter", "-X", "X"])).success());
        assert!(!tables.has_chain(Table::Filter, "X"));
        assert!(is_mutation(&args(&["-t", "nat", "-A", "X"])));
        assert!(!is_mutation(&args(&["-t", "nat", "-S", "X"])));
    }
}
