//! Readable debug logging for commands executed by the firewall hooks.

use std::process::Command;

/// Render a command with quotes only around empty arguments or arguments containing whitespace.
fn format_command(command: &Command) -> String {
    let environment = command.get_envs().filter_map(|(name, value)| {
        value.map(|value| format!("{}={}", name.to_string_lossy(), value.to_string_lossy()))
    });
    let arguments = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|argument| argument.to_string_lossy().into_owned());
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

/// Log the executable, environment overrides, and arguments before attempting execution.
pub fn log_command(command: &Command) {
    tracing::debug!(command = %format_command(command), "executing command");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keep ordinary firewall arguments unquoted and show environment overrides.
    #[test]
    fn ordinary_arguments_are_unquoted() {
        let mut command = Command::new("iptables");
        command.env("LC_ALL", "C").args(["-w", "10", "-t", "filter", "-S", "OUTPUT"]);
        assert_eq!(format_command(&command), "LC_ALL=C iptables -w 10 -t filter -S OUTPUT");
    }

    /// Preserve argument boundaries and escape embedded quotes when whitespace requires quoting.
    #[test]
    fn whitespace_and_empty_arguments_are_quoted() {
        let mut command = Command::new("a program");
        command.args(["--comment", "a \"quoted\" comment", "two\twords", ""]);
        assert_eq!(
            format_command(&command),
            "\"a program\" --comment \"a \\\"quoted\\\" comment\" \"two\\twords\" \"\""
        );
    }
}
