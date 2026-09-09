#!/bin/bash
set -euo pipefail
cd /opt/worldland-testnet
export WORLDLAND_TPM_EK_CERT=/opt/worldland-testnet/ek.pem
./bin/tpmenroll -action register-producer -rpc http://127.0.0.1:8545 -chain-id "$(jq -r .chainId manifest.json)" -controller-key account.key -work-key WorldLand-TPM-Work-Test -attestation-key WorldLand-TPM-AIK-Test -vrf-public-key vrf.pub -profile profile.bin -ek-intermediate intermediate.pem -wait-activation -timeout 60m
# Mining and the producer agent start only after confirmed on-chain activation.
touch mining.enabled
systemctl restart worldland-node
systemctl enable --now worldland-producer
echo WORLDLAND_DYNAMIC_ENROLLMENT_SUCCESS
