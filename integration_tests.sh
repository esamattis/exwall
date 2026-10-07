#!/bin/sh
# Run protocol, firewall, lifecycle, and browser coverage through Playwright.
set -eu
scriptdir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$scriptdir"
exec ./e2e_tests.sh "$@"
