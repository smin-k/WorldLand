#!/bin/bash
set -euo pipefail
umask 077
cd /opt/worldland-testnet
test "$(pwd -P)" = /opt/worldland-testnet
test "$(jq -r .chainId manifest.json)" = 103994
systemctl stop worldland-enroll worldland-enroll-retry1 2>/dev/null || true
systemctl stop worldland-producer worldland-node
test "$(systemctl is-active worldland-node || true)" = inactive
mkdir -p final-six
journalctl -u worldland-node -u worldland-producer -u worldland-enroll -u worldland-enroll-retry1 --no-pager > final-six/services.log
sha256sum bin/* genesis.json manifest.json > final-six/build-sha256.txt
date -u --iso-8601=seconds > final-six/stopped-at.txt
systemctl cat worldland-node worldland-producer > final-six/service-config.txt
# Explicit public-data allowlist: exclude account.key/password/keystore/nodekey.
integrated=()
if [ -d data-integrated/worldland/chaindata ]; then
  integrated=(data-integrated/worldland/chaindata integrated.json node-integrated.sh)
fi
if [ -d data-research12/worldland/chaindata ]; then
  integrated+=(data-research12/worldland/chaindata node-research.sh)
  journalctl -u worldland-restart-pending --no-pager > final-six/restart-pending.log
  journalctl -u worldland-withhold-watch --no-pager > final-six/withhold-watch.log
fi
tar -czf /home/infonet/final-six.tgz genesis.json manifest.json node.toml node-start.sh producer-start.sh enroll.sh identity.json ek.pem intermediate.pem preflight.json final-six data/worldland/chaindata "${integrated[@]}"
chmod 644 /home/infonet/final-six.tgz
sha256sum /home/infonet/final-six.tgz
