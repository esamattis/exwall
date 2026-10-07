#!/bin/sh
# Run local protocol tests and isolated Linux firewall lifecycle tests.
set -eu
scriptdir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$scriptdir"
mise exec -- pnpm build:ui
cargo build --locked
python3 tests/run_integration.py "$scriptdir/target/debug/exwall"
