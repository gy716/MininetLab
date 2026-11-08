#!/usr/bin/env bash
# Start the topology-aware Ryu application in the foreground.
# Keep this terminal open while running run_topology.sh in another terminal.
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec ryu-manager --observe-links --ofp-tcp-listen-port 6653 "$SCRIPT_DIR/mesh_controller.py" "$@"
