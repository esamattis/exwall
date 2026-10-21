Write readable Rust with normal multiline formatting and clear control flow.
Document every struct, enum, enum variant, function, and method with a meaningful
doc comment, including private items and test helpers. Apply this to existing
code whenever changing it and to all new code.

Use thiserror for application error types and preserve useful error sources.
Run cargo fmt, cargo clippy --all-targets -- -D warnings, cargo test, and
./integration_tests.sh after functional changes. Never run the privileged
installer or live firewall hooks on the development host as a test; use dry runs,
fake tools, or an explicitly chosen disposable network namespace instead.

The web UI's HTTP API under /api is private to the bundled UI and may change
without notice. Do not document its endpoints, requests, or responses in the
README, docs/, or other user-facing documentation.

Commit directly to main; there is no need to create a branch first.
