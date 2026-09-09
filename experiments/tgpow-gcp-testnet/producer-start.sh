#!/bin/bash
set -euo pipefail
cd /opt/worldland-testnet
exec ./bin/tpmproducer -rpc http://127.0.0.1:8545 -chain-id "$(jq -r .chainId manifest.json)" -producer-key account.key -certificate-profile gcp-cas-v1 -profile-hash 0x9fb154f8ac10cbf63e5826821d4eb633b79589c3a1c3d60c5397f25d433c722e -poll "${WORLDLAND_PRODUCER_POLL:-500ms}"
