#!/bin/bash
set -euo pipefail
umask 077
cd /opt/worldland-testnet
test "$(pwd -P)" = /opt/worldland-testnet
systemctl stop worldland-producer worldland-node
test "$(systemctl is-active worldland-node || true)" = inactive
mkdir -p final-baseline
journalctl -u worldland-node -u worldland-producer -u worldland-enrollment --no-pager > final-baseline/services.log
sha256sum bin/worldland bin/tpmenroll bin/tpmproducer bin/tpmvalidator genesis.json > final-baseline/build-sha256.txt
date -u --iso-8601=seconds > final-baseline/stopped-at.txt
# Only public chain data, public evidence and reproducibility configuration.
# Never archive account.key, password, keystore, P2P nodekey or TPM private state.
tar -czf /home/infonet/final-baseline-4096.tgz genesis.json manifest.json node.toml node-start.sh producer-start.sh enroll.sh identity.json ek.pem intermediate.pem final-baseline data/worldland/chaindata
chmod 644 /home/infonet/final-baseline-4096.tgz
sha256sum /home/infonet/final-baseline-4096.tgz
