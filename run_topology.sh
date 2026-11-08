#!/usr/bin/env bash
# Launch the supplied mesh topology. Extra arguments are passed to Mininet.
# Examples:
#   ./run_topology.sh
#   ./run_topology.sh --test build --twait 1
# The lab's Ryu controller listens separately on 127.0.0.1:6653.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TOPO_PATH="$SCRIPT_DIR/../ceg5101Lab/reference/ceg_mesh_topo.py"

if [[ ! -r "$TOPO_PATH" ]]; then
    printf 'Cannot read topology file: %s\n' "$TOPO_PATH" >&2
    exit 1
fi

if ! command -v mn >/dev/null 2>&1; then
    printf 'Mininet is required. The mn command was not found.\n' >&2
    exit 1
fi

exec sudo mn \
    --custom "$TOPO_PATH" \
    --topo meshTopo \
    --switch ovsk,protocols=OpenFlow13 \
    --controller remote,ip=127.0.0.1,port=6653 \
    --link tc \
    "$@"
