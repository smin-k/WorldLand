#!/bin/bash
set -euo pipefail
label="$1"
[[ "$label" =~ ^[a-zA-Z0-9_-]+$ ]]
out="/home/infonet/resume-public-$label"
test ! -e "$out"
mkdir "$out"
cd /opt/worldland-testnet
head=$(bash /home/infonet/rpc.sh eth_blockNumber | jq -er .result)
bash /home/infonet/rpc.sh eth_getBlockByNumber "[\"$head\",false]" > "$out/head.json"
bash /home/infonet/rpc.sh eth_getLogs "[{\"fromBlock\":\"0x0\",\"toBlock\":\"$head\",\"address\":\"0x0000000000000000000000000000000000000801\"}]" > "$out/registry-logs.json"
jq -e 'has("result") and (has("error")|not)' "$out/registry-logs.json" >/dev/null
journalctl -u worldland-node -u worldland-open-replay-1 -u worldland-open-replay-6 -u worldland-open-replay-6-rpc-ready -u worldland-valid-verifier-load -n 20000 --no-pager > "$out/services.log"
sha256sum bin/worldland-response-fault > "$out/build-sha256.txt"
date -u --iso-8601=seconds > "$out/collected-at.txt"
printf '%s\n' "$head" > "$out/captured-head.txt"
if [ "${2:-}" = tail128 ]; then
 start=$((head-127)); if [ "$start" -lt 0 ]; then start=0; fi
 for ((n=start;n<=head;n++)); do
  hex=$(printf '0x%x' "$n")
  bash /home/infonet/rpc.sh eth_getBlockByNumber "[\"$hex\",false]" | jq -ce '.result | select(. != null)' >> "$out/blocks.jsonl"
 done
fi
tar -czf "$out.tgz" -C /home/infonet "resume-public-$label"
chmod 644 "$out.tgz"
sha256sum "$out.tgz"
