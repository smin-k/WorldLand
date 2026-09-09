#!/bin/bash
set -euo pipefail
cd /opt/worldland-testnet
label="$1"
[[ "$label" =~ ^[a-zA-Z0-9_-]+$ ]]
out="/home/infonet/public-$label"
mkdir -p "$out"
rpc() { bash /home/infonet/rpc.sh "$@"; }
head=$(rpc eth_blockNumber | jq -er .result)
rpc eth_getBlockByNumber "[\"$head\",false]" > "$out/head.json"
rpc eth_getLogs "[{\"fromBlock\":\"0x0\",\"toBlock\":\"$head\",\"address\":\"0x0000000000000000000000000000000000000801\"}]" > "$out/registry-logs.json"
jq -e 'has("result") and (has("error") | not)' "$out/registry-logs.json" > /dev/null
journalctl -u worldland-node -u worldland-producer -u worldland-enroll -u worldland-enroll-retry1 --no-pager > "$out/services.log"
install -m 644 genesis.json manifest.json preflight.json identity.json "$out/"
if [ -f integrated.json ]; then
  install -m 644 integrated.json node-integrated.sh "$out/"
fi
if [ -f node-research.sh ]; then
  install -m 644 node-research.sh "$out/"
  journalctl -u worldland-restart-pending --no-pager > "$out/restart-pending.log"
  journalctl -u worldland-withhold-watch --no-pager > "$out/withhold-watch.log"
  if ! /home/infonet/registry-probe > "$out/registration-probe.jsonl" 2> "$out/probe-errors.txt"; then
    printf 'probe incomplete; inspect probe-errors.txt\n' > "$out/probe-status.txt"
  fi
  if [ -f research-withhold.enabled ]; then
    printf 'enabled\n' > "$out/withholding-state.txt"
  else
    printf 'disabled\n' > "$out/withholding-state.txt"
  fi
fi
sha256sum bin/* > "$out/binary-sha256.txt"
date -u --iso-8601=seconds > "$out/collected-at.txt"
tar -czf "/home/infonet/public-$label.tgz" -C /home/infonet "public-$label"
chmod 644 "/home/infonet/public-$label.tgz"
sha256sum "/home/infonet/public-$label.tgz"
