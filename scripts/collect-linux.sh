#!/usr/bin/env bash
# Jason Stys: quoted wrapper for explicitly authorized, read-only Linux file collection.
# Arguments: --root PATH, --host-id ID, --ack-authorized-host. Output is JSON; no shell evaluation.
# Variables: none; all arguments are passed unchanged to the Python CLI.
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# END CODE MAP
set -euo pipefail
exec python -m hardening collect-linux "$@"
