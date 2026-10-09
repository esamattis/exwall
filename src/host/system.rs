//! The host operations hooks depend on, with real, dry-run, and test implementations.

use super::{
    command::{CommandOutput, CommandSpec, format_command},
    error::HookError,
    iptables::Family,
    simulate::{SimulatedTables, is_mutation},
};
use std::{
    collections::BTreeMap,
    ffi::CString,
    io::{self, Write},
    sync::Mutex,
};

/// Host operations used by lifecycle hooks.
///
/// User, sysctl, and service queries have default implementations that run
/// the standard utilities through [`System::run`], so real executions are
/// logged uniformly.
pub trait System {
    /// Run a command to completion, capturing its output.
    fn run(&self, command: &CommandSpec) -> io::Result<CommandOutput>;

    /// The effective user ID of this process.
    fn effective_uid(&self) -> u32;

    /// Run a command, attributing spawn failures to its program.
    fn execute(&self, command: &CommandSpec) -> Result<CommandOutput, HookError> {
        self.run(command).map_err(|source| HookError::Spawn {
            program: command.program.clone(),
            source,
        })
    }

    /// Check whether an account exists using `id`, never a shell.
    fn user_exists(&self, user: &str) -> Result<bool, HookError> {
        let output = self.execute(&id_command("-u", user))?;
        match output.code {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(HookError::UserLookup {
                user: user.to_owned(),
            }),
        }
    }

    /// Resolve an account's numeric user and group IDs.
    fn user_ids(&self, user: &str) -> Result<(u32, u32), HookError> {
        let mut ids = Vec::new();
        for flag in ["-u", "-g"] {
            let output = self.execute(&id_command(flag, user))?;
            let id = output.success().then(|| output.stdout_text().parse::<u32>().ok()).flatten();
            ids.push(id.ok_or_else(|| HookError::ServiceAccount {
                user: user.to_owned(),
            })?);
        }
        Ok((ids[0], ids[1]))
    }

    /// Read a boolean-valued sysctl.
    fn read_sysctl(&self, name: &str) -> Result<u8, HookError> {
        let output = self.execute(&CommandSpec::new("sysctl").args(["-n", name]))?;
        if !output.success() {
            return Err(HookError::Sysctl {
                name: name.to_owned(),
                stderr: output.stderr_text(),
            });
        }
        match output.stdout_text().parse::<u8>() {
            Ok(value) if value <= 1 => Ok(value),
            _ => Err(HookError::SysctlValue {
                name: name.to_owned(),
            }),
        }
    }

    /// Write a boolean-valued sysctl.
    fn write_sysctl(&self, name: &str, value: u8) -> Result<(), HookError> {
        let assignment = format!("{name}={value}");
        let output = self.execute(&CommandSpec::new("sysctl").args(["-w", &assignment]))?;
        if !output.success() {
            return Err(HookError::Sysctl {
                name: name.to_owned(),
                stderr: output.stderr_text(),
            });
        }
        Ok(())
    }

    /// Report whether systemd-resolved is running.
    fn resolver_active(&self) -> Result<bool, HookError> {
        let command = CommandSpec::new("systemctl").args([
            "is-active",
            "--quiet",
            "systemd-resolved.service",
        ]);
        Ok(self.execute(&command)?.success())
    }
}

/// Build an `id` query with a stable locale.
fn id_command(flag: &str, user: &str) -> CommandSpec {
    CommandSpec::new("id").args([flag, "--", user]).env("LC_ALL", "C")
}

/// The live host: commands are logged at debug level and executed.
pub struct RealSystem;

impl System for RealSystem {
    /// Log the command, then run it with captured output.
    fn run(&self, command: &CommandSpec) -> io::Result<CommandOutput> {
        tracing::debug!(command = %format_command(command), "executing command");
        let output = std::process::Command::new(&command.program)
            .args(&command.args)
            .envs(command.env.iter().map(|(name, value)| (name, value)))
            .output()?;
        Ok(CommandOutput {
            code: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    /// Return the process's effective UID.
    fn effective_uid(&self) -> u32 {
        // SAFETY: geteuid has no pointer arguments or preconditions.
        unsafe { libc::geteuid() }
    }
}

/// A preview that prints firewall changes against a simulated firewall.
///
/// Probes are answered by the simulation, so later steps see earlier ones,
/// and nothing is executed: user lookups read the account database directly.
pub struct DryRunSystem {
    /// Simulated tables per family.
    tables: Mutex<BTreeMap<Family, SimulatedTables>>,
    /// Where planned commands are printed.
    output: Mutex<Box<dyn Write + Send>>,
}

impl DryRunSystem {
    /// Preview against `tables`, printing planned commands to `output`.
    pub fn new(tables: BTreeMap<Family, SimulatedTables>, output: Box<dyn Write + Send>) -> Self {
        Self {
            tables: Mutex::new(tables),
            output: Mutex::new(output),
        }
    }

    /// Print an explanatory comment line.
    pub fn note(&self, text: &str) {
        let mut output = self.output.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = writeln!(output, "# {text}");
    }
}

impl System for DryRunSystem {
    /// Simulate iptables commands, printing those that would change state.
    fn run(&self, command: &CommandSpec) -> io::Result<CommandOutput> {
        let family = match command.program.as_str() {
            "iptables" => Family::V4,
            "ip6tables" => Family::V6,
            other => {
                return Err(io::Error::other(format!("{other} is not executed in a dry run")));
            }
        };
        if is_mutation(&command.args) {
            let mut output = self.output.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            writeln!(output, "{} {}", command.program, command.args.join(" "))?;
        }
        let mut tables = self.tables.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(tables.entry(family).or_default().execute(family, &command.args))
    }

    /// Report the real effective UID; dry runs never take the root-only lock.
    fn effective_uid(&self) -> u32 {
        RealSystem.effective_uid()
    }

    /// Look up the account database without spawning `id`.
    fn user_exists(&self, user: &str) -> Result<bool, HookError> {
        Ok(lookup_user(user)?.is_some())
    }

    /// Look up the account database without spawning `id`.
    fn user_ids(&self, user: &str) -> Result<(u32, u32), HookError> {
        lookup_user(user)?.ok_or_else(|| HookError::ServiceAccount {
            user: user.to_owned(),
        })
    }
}

/// Resolve an account's IDs through the C library's account database.
fn lookup_user(user: &str) -> Result<Option<(u32, u32)>, HookError> {
    let lookup_error = || HookError::UserLookup {
        user: user.to_owned(),
    };
    let name = CString::new(user).map_err(|_| lookup_error())?;
    let mut buffer = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: all-zero passwd is a valid output buffer for getpwnam_r.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer refers to live, writable storage of the stated size.
    let status = unsafe {
        libc::getpwnam_r(name.as_ptr(), &mut entry, buffer.as_mut_ptr(), buffer.len(), &mut result)
    };
    if status != 0 {
        return Err(lookup_error());
    }
    if result.is_null() {
        return Ok(None);
    }
    Ok(Some((entry.pw_uid, entry.pw_gid)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A writer whose contents can be inspected after use.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Write for Captured {
        /// Append to the shared buffer.
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        /// Nothing is buffered.
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Dry runs print only mutations, answer probes consistently, and refuse other programs.
    #[test]
    fn dry_runs_print_mutations_and_simulate_probes() {
        let captured = Captured::default();
        let system = DryRunSystem::new(BTreeMap::new(), Box::new(captured.clone()));
        let probe = CommandSpec::new("iptables").args(["-w", "10", "-t", "filter", "-S", "X"]);
        assert_eq!(system.run(&probe).unwrap().code, Some(1));
        let create = CommandSpec::new("iptables").args(["-w", "10", "-t", "filter", "-N", "X"]);
        assert!(system.run(&create).unwrap().success());
        assert!(system.run(&probe).unwrap().success());
        assert!(system.run(&CommandSpec::new("sysctl")).is_err());
        assert!(system.user_exists("root").unwrap());
        assert_eq!(system.user_ids("root").unwrap(), (0, 0));
        assert!(!system.user_exists("exwall-no-such-user").unwrap());
        system.note("comment");
        let printed = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert_eq!(printed, "iptables -w 10 -t filter -N X\n# comment\n");
    }
}
