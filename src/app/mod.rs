//! Command dispatch: each CLI operation wires adapters together and reports failures.

mod hook;
mod serve;

pub use serve::{ServeError, TaskFailure};

use crate::{
    ca,
    cli::{Cli, Command},
    config::{Config, LogLevel},
    error::{Error, ErrorChain},
    policy::{MissingDirectory, load_rules},
};
use clap::Parser;
use std::process::ExitCode;

/// Parse the command line, run the operation, and print any failure with its causes.
pub fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {}", ErrorChain(&error));
            ExitCode::FAILURE
        }
    }
}

/// Run the selected command.
pub fn run(cli: &Cli) -> Result<(), Error> {
    match cli.command_or_default() {
        Command::Hook(args) => hook::run(cli, &args),
        Command::InitCa(args) => {
            ca::init(&args.ca_dir)?;
            println!("CA certificate: {}", args.ca_dir.join(ca::CERT_FILE).display());
            Ok(())
        }
        Command::Check => {
            Config::load(&cli.config)?;
            let rules = load_rules(&cli.rules_dir, MissingDirectory::Empty)?;
            println!("Configuration valid; {} allow rules", rules.len());
            Ok(())
        }
        Command::Serve(args) => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(Error::Runtime)?;
            runtime.block_on(serve::run(cli, args))?;
            Ok(())
        }
    }
}

/// Initialize application logging at the configured level; `RUST_LOG` is deliberately ignored.
pub fn init_logging(level: LogLevel) {
    let filter = tracing_subscriber::EnvFilter::new(level.tracing_directive());
    let _ = tracing_subscriber::fmt().with_env_filter(filter).with_target(false).try_init();
}
