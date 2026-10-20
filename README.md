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


<img width="1163" height="603" alt="image" src="https://github.com/user-attachments/assets/6a929331-0e6a-44b0-b2c8-4975c3dc37a3" />

<img width="1165" height="248" alt="image" src="https://github.com/user-attachments/assets/a7894cb7-5c67-45ff-bd77-38d7c04f4dfa" />



<img width="1163" height="919" alt="image" src="https://github.com/user-attachments/assets/b11d5610-3e21-48cb-bfb8-b35976b27297" />
