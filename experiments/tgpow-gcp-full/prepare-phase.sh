#!/bin/bash
set -euo pipefail
phase="$1"
eligibility="$2"
[[ "$phase" =~ ^(p256|p128|p64|reorg|attack|p(256|128|64)-r[23])$ ]]
[[ "$eligibility" =~ ^(256|128|64)$ ]]
out="/opt/worldland-testnet/phase-$phase"
test ! -e "$out"
install -d "$out"
/opt/worldland-testnet/bin/setup -chain-id 103994 -nodes 6 -bootstrap 3 -threshold 6 -eligibility "$eligibility" genesis "$out" /home/infonet/n{1,2,3,4,5,6}-identity.json
jq '. + {observerEndpoints: [range(2;8) | "http://10.79.0.\(.):8081/api/node"]}' "$out/manifest.json" > "$out/observer-manifest.json"
mv "$out/observer-manifest.json" "$out/manifest.json"
tar -czf "/home/infonet/phase-$phase.tgz" -C "$out" genesis.json manifest.json
chmod 644 "/home/infonet/phase-$phase.tgz"
sha256sum "/home/infonet/phase-$phase.tgz"
