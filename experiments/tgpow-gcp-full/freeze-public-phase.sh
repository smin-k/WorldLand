#!/bin/bash
set -euo pipefail
umask 077
label="$1"
[[ "$label" =~ ^(research12|p256|p128|p64|reorg|attack|p(256|128|64)-r[23])$ ]]
cd /opt/worldland-testnet
test "$(pwd -P)" = /opt/worldland-testnet
test -d "data-$label/worldland/chaindata"
test ! -e "/home/infonet/frozen-$label.tgz"
if [ "$label" != research12 ]; then test "$(cat phase-active)" = "$label"; fi
systemctl stop worldland-node
test "$(systemctl is-active worldland-node || true)" = inactive
out="frozen-$label"
mkdir "$out"
journalctl -u worldland-node -u worldland-historical-replay -u worldland-approval-replay --no-pager > "$out/services.log"
date -u --iso-8601=seconds > "$out/stopped-at.txt"
sha256sum bin/worldland-* > "$out/binaries.sha256"
# Only public chain DB and configuration; no keystore, passwords or node keys.
config=(genesis.json manifest.json)
if [ "$label" != research12 ]; then config=("phase-$label/genesis.json" "phase-$label/manifest.json"); fi
tar -czf "/home/infonet/frozen-$label.tgz" "$out" "data-$label/worldland/chaindata" "${config[@]}"
chmod 644 "/home/infonet/frozen-$label.tgz"
sha256sum "/home/infonet/frozen-$label.tgz"
