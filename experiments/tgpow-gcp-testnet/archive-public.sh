#!/bin/bash
set -euo pipefail
cd /opt/worldland-testnet
test -d archive-65536/data/worldland/chaindata
# Explicit allowlist: no keystore, account key, node key or TPM private state.
tar -czf /home/infonet/archive-public-65536.tgz -C archive-65536 genesis.json manifest.json services.log data/worldland/chaindata
chmod 644 /home/infonet/archive-public-65536.tgz
