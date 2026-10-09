//! The `hook` command: guard, start, or stop enforcement under one lifecycle lock.

use super::init_logging;
use crate::{
    cli::{Cli, HookAction, HookArgs},
    config::{Config, LogLevel},
    error::Error,
    host::{
        DryRunSystem, HookSettings, Hooks, Mode, RealSystem, System,
        files::ResolverPaths,
        iptables::{BUILTIN_OUTPUT, Family, NAT_CHAIN, OUTPUT_CHAIN, Table},
        simulate::SimulatedTables,
    },
    policy::{MissingDirectory, load_rules},
};
use std::collections::BTreeMap;

/// Run one lifecycle hook.
///
/// Configuration failures never prevent guarding or stopping: logging falls
/// back to `info`, the guard is installed before configuration is required,
/// and stop never reads it.
pub fn run(cli: &Cli, args: &HookArgs) -> Result<(), Error> {
    let config = Config::load(&cli.config);
    let level = config.as_ref().map_or(LogLevel::Info, |config| config.startup.log_level);
    init_logging(level);
    let settings = HookSettings {
        rules_dir: cli.rules_dir.clone(),
        state_dir: args.state_dir.clone(),
        resolver: ResolverPaths::default(),
        proxy_user: args.proxy_user.clone(),
        proxy_port: args.proxy_port,
        dns_port: args.dns_port,
    };
    if args.dry_run {
        let tables = if args.action == HookAction::Stop {
            installed_tables()
        } else {
            BTreeMap::new()
        };
        let system = DryRunSystem::new(tables, Box::new(std::io::stdout()));
        let note = |text: &str| system.note(text);
        let hooks = Hooks::new(settings, &system, Mode::DryRun, &note);
        return execute(&hooks, args.action, cli, config);
    }
    let system = RealSystem;
    let silent = |_: &str| {};
    let hooks = Hooks::new(settings, &system as &dyn System, Mode::Live, &silent);
    // One lock covers the guard and the start that follows it.
    let _lock = hooks.lock()?;
    execute(&hooks, args.action, cli, config)
}

/// Perform the hook action; start requires valid configuration and rules after guarding.
fn execute(
    hooks: &Hooks<'_>,
    action: HookAction,
    cli: &Cli,
    config: Result<Config, crate::config::ConfigError>,
) -> Result<(), Error> {
    match action {
        HookAction::Guard => hooks.guard()?,
        HookAction::Start => {
            hooks.guard()?;
            let config = config?;
            load_rules(&cli.rules_dir, MissingDirectory::Empty)?;
            hooks.start(&config.startup)?;
        }
        HookAction::Stop => hooks.stop()?,
    }
    Ok(())
}

/// Simulated tables with installed exwall chains, so a dry-run stop shows their removal.
fn installed_tables() -> BTreeMap<Family, SimulatedTables> {
    let mut tables = BTreeMap::new();
    for family in Family::ALL {
        let mut simulated = SimulatedTables::default();
        for (table, chain) in [(Table::Filter, OUTPUT_CHAIN), (Table::Nat, NAT_CHAIN)] {
            for operation in [vec!["-N", chain], vec!["-I", BUILTIN_OUTPUT, "-j", chain]] {
                let mut args = vec!["-t".to_owned(), table.name().to_owned()];
                args.extend(operation.into_iter().map(str::to_owned));
                simulated.execute(family, &args);
            }
        }
        tables.insert(family, simulated);
    }
    tables
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dry-run stop model contains both installed chains and their jumps.
    #[test]
    fn dry_run_stop_starts_from_installed_chains() {
        let tables = installed_tables();
        for family in Family::ALL {
            assert!(tables[&family].has_chain(Table::Filter, OUTPUT_CHAIN));
            assert!(tables[&family].has_chain(Table::Nat, NAT_CHAIN));
            assert_eq!(tables[&family].rules(Table::Nat, BUILTIN_OUTPUT).unwrap().len(), 1);
        }
    }
}
