#!/bin/bash
set -euo pipefail
node="$1"
cd /opt/worldland-testnet
test "$node" -ge 1 && test "$node" -le 6
peers=$(jq -c --argjson node "$node" 'to_entries | map(select(.key != ($node-1)) | .value)' /home/infonet/enodes.json)
printf '[Node.P2P]\nMaxPeers = 8\nNoDiscovery = true\nBootstrapNodes = []\nStaticNodes = %s\nListenAddr = "10.79.0.%d:30303"\n' "$peers" "$((node+1))" > node.toml
# First connect all nodes without mining; mining is started separately.
systemctl restart worldland-node
