//! Argument-vector commands, never shell strings, and their readable rendering.

/// A program invocation with explicit arguments and environment overrides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandSpec {
    /// The executable name or path.
    pub program: String,
    /// Arguments, passed without shell interpretation.
    pub args: Vec<String>,
    /// Environment variables set for the child.
    pub env: Vec<(String, String)>,
}

impl CommandSpec {
    /// Start describing an invocation of `program`.
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
        }
    }

    /// Append arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set an environment variable for the child.
    pub fn env(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((name.into(), value.into()));
        self
    }
}

/// The exit status and captured output of a finished command.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommandOutput {
    /// The exit code, or `None` if the child was killed by a signal.
    pub code: Option<i32>,
    /// Captured standard output.
    pub stdout: Vec<u8>,
    /// Captured standard error.
    pub stderr: Vec<u8>,
}

impl CommandOutput {
    /// A successful exit with the given standard output.
    pub fn ok(stdout: impl Into<Vec<u8>>) -> Self {
        Self {
            code: Some(0),
            stdout: stdout.into(),
            stderr: Vec::new(),
        }
    }

    /// A failed exit with the given code and standard error.
    pub fn failed(code: i32, stderr: impl Into<Vec<u8>>) -> Self {
        Self {
            code: Some(code),
            stdout: Vec::new(),
            stderr: stderr.into(),
        }
    }

    /// Report whether the command exited with status zero.
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// Standard output as trimmed text.
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).trim().to_owned()
    }

    /// Standard error as text.
    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

/// Render a command with quotes only around empty arguments or arguments containing whitespace.
pub fn format_command(command: &CommandSpec) -> String {
    let environment = command.env.iter().map(|(name, value)| format!("{name}={value}"));
    let arguments = std::iter::once(command.program.clone()).chain(command.args.iter().cloned());
    environment
        .chain(arguments)
        .map(|argument| {
            if argument.is_empty() || argument.chars().any(char::is_whitespace) {
                format!("{argument:?}")
            } else {
                argument
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keep ordinary firewall arguments unquoted and show environment overrides.
    #[test]
    fn ordinary_arguments_are_unquoted() {
        let command = CommandSpec::new("iptables")
            .env("LC_ALL", "C")
            .args(["-w", "10", "-t", "filter", "-S", "OUTPUT"]);
        assert_eq!(format_command(&command), "LC_ALL=C iptables -w 10 -t filter -S OUTPUT");
    }

    /// Preserve argument boundaries and escape embedded quotes when whitespace requires quoting.
    #[test]
    fn whitespace_and_empty_arguments_are_quoted() {
        let command = CommandSpec::new("a program").args([
            "--comment",
            "a \"quoted\" comment",
            "two\twords",
            "",
        ]);
        assert_eq!(
            format_command(&command),
            "\"a program\" --comment \"a \\\"quoted\\\" comment\" \"two\\twords\" \"\""
        );
    }
}
