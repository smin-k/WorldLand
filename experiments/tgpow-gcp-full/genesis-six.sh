#!/bin/bash
set -euo pipefail
cd /opt/worldland-testnet
./bin/setup -chain-id 103994 -nodes 6 -bootstrap 3 -threshold 6 genesis /opt/worldland-testnet /home/infonet/n{1,2,3,4,5,6}-identity.json
jq '. + {observerEndpoints: [range(2;8) | "http://10.79.0.\(.):8081/api/node"]}' manifest.json > /home/infonet/manifest.json
install -m 644 /home/infonet/manifest.json manifest.json
install -m 644 genesis.json /home/infonet/genesis.json
sha256sum genesis.json manifest.json bin/*
