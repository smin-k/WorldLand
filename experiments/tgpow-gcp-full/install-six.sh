#!/bin/bash
set -euo pipefail
node="$1"
cd /opt/worldland-testnet
printf '[Node.P2P]\nMaxPeers = 8\nNoDiscovery = true\nBootstrapNodes = []\nStaticNodes = []\nListenAddr = "10.79.0.%d:30303"\n' "$((node+1))" > node.toml
bash /home/infonet/install-node.sh "$node"
