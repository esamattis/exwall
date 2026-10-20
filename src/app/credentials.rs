//! The `ui-credentials` command: store web UI credentials and print how to log in.

use crate::{
    cli::{Cli, UiCredentialsArgs},
    credentials::{self, Outcome, Rotation, UiUrl},
    error::Error,
};
use std::{fs::File, io::BufReader, path::Path};

/// Kernel source of cryptographically secure random bytes.
const RANDOM_SOURCE: &str = "/dev/urandom";

/// Generate or keep credentials, then print the UI URLs and the login.
pub fn run(cli: &Cli, args: &UiCredentialsArgs) -> Result<(), Error> {
    let rotation = if args.if_missing {
        Rotation::IfMissing
    } else {
        Rotation::Replace
    };
    let random = File::open(RANDOM_SOURCE).map_err(credentials::CredentialsError::Random)?;
    let outcome = credentials::update(
        &cli.config,
        args.username.as_deref(),
        rotation,
        &mut BufReader::new(random),
    )?;
    let urls = credentials::ui_urls(&outcome.ui, credentials::machine_address());
    print!("{}", render(&cli.config, &outcome, &urls));
    if outcome.changed && rotation == Rotation::Replace {
        eprintln!("Restart exwall to apply: sudo systemctl restart exwall");
    }
    Ok(())
}

/// Format the UI URLs, listener hints, and login for the operator.
fn render(config: &Path, outcome: &Outcome, urls: &[UiUrl]) -> String {
    let mut text = String::from("Web UI:\n");
    if outcome.ui.hosts.is_empty() {
        text.push_str(&format!("  disabled; set ui.hosts in {}\n", config.display()));
    } else {
        for url in urls {
            if url.listening {
                text.push_str(&format!("  {}\n", url.url));
            } else {
                text.push_str(&format!(
                    "  {}  (not listening; add \"{}\" to ui.hosts in {})\n",
                    url.url,
                    url.address,
                    config.display()
                ));
            }
        }
    }
    text.push_str(&format!("  username: {}\n", outcome.credentials.username));
    text.push_str(&format!("  password: {}\n", outcome.credentials.password));
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::UiConfig, credentials::UiCredentials};

    /// Unreachable URLs name the address to add, and a disabled UI says so.
    #[test]
    fn renders_urls_and_login() {
        let ui = UiConfig {
            hosts: vec!["127.0.0.1".parse().unwrap()],
            ..UiConfig::default()
        };
        let urls = credentials::ui_urls(&ui, Some("10.0.0.2".parse().unwrap()));
        let mut outcome = Outcome {
            credentials: UiCredentials {
                username: "admin".into(),
                password: "secret".into(),
            },
            changed: true,
            ui,
        };
        let config = Path::new("/etc/exwall/config.toml");
        assert_eq!(
            render(config, &outcome, &urls),
            "Web UI:\n  http://localhost:58000\n  http://10.0.0.2:58000  \
             (not listening; add \"10.0.0.2\" to ui.hosts in /etc/exwall/config.toml)\n  \
             username: admin\n  password: secret\n"
        );
        outcome.ui.hosts.clear();
        assert!(render(config, &outcome, &urls).starts_with(
            "Web UI:\n  disabled; set ui.hosts in /etc/exwall/config.toml\n  username: admin\n"
        ));
    }
}
