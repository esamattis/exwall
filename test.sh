#!/bin/sh
# Check Rust formatting, lint all targets, and run policy/host-state unit tests.
set -eu
scriptdir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$scriptdir"
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
