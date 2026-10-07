#!/bin/sh
# Run the TypeScript namespace harness with the project's pinned Node runtime.
set -eu
scriptdir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$scriptdir"
exec mise exec -- node tests/playwright_helpers/run_e2e.mts "$@"
