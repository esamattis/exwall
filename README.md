<img src="assets/icon.svg" width="64" height="64" alt="">

# exwall

A Rust port of [mitmwall](https://github.com/esamattis/mitmwall): a transparent
outbound HTTP(S) and DNS firewall for Linux, driven by mitmwall-compatible TOML
allow rules.

## Install

```sh
bash -c "$(curl -fsSL https://raw.githubusercontent.com/esamattis/exwall/refs/heads/main/install.sh)"
```

Start the systemd service

```sh
sudo systemctl enable --now exwall
```

See [docs/usage.md](docs/usage.md) for configuration and operation, and
[CONTRIBUTING.md](CONTRIBUTING.md) for development.
