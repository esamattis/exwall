//! Command-line entry point for the exwall egress firewall.

use std::process::ExitCode;

/// Parse the command line and run the selected operation.
fn main() -> ExitCode {
    exwall::app::main()
}
