#!/bin/bash
set -euo pipefail
cd /opt/worldland-testnet
phase=$(<phase-active)
[[ "$phase" =~ ^(p256|p128|p64|reorg|attack|p(256|128|64)-r[23])$ ]]
label="$1"
[[ "$label" =~ ^[a-zA-Z0-9_-]+$ ]]
out="/home/infonet/phase-public-$label"
test ! -e "$out"
mkdir "$out"
head=$(bash /home/infonet/rpc.sh eth_blockNumber | jq -er .result)
observedHead="$head"
if [ -n "${2:-}" ]; then
 [[ "$2" =~ ^[0-9]+$ ]]
 test "$((head))" -ge "$2"
 head=$(printf '0x%x' "$2")
fi
bash /home/infonet/rpc.sh eth_getLogs "[{\"fromBlock\":\"0x0\",\"toBlock\":\"$observedHead\",\"address\":\"0x0000000000000000000000000000000000000801\"}]" > "$out/registry-logs.json"
jq -e 'has("result") and (has("error")|not)' "$out/registry-logs.json" >/dev/null
bash /home/infonet/rpc.sh eth_getBlockByNumber "[\"$head\",false]" > "$out/head.json"
bash /home/infonet/rpc.sh eth_getBlockByNumber "[\"$observedHead\",false]" > "$out/observed-head.json"
height=$((head))
test "$height" -le 10000
for ((n=0;n<=height;n++)); do
  hex=$(printf '0x%x' "$n")
  bash /home/infonet/rpc.sh eth_getBlockByNumber "[\"$hex\",false]" | jq -ce '.result | select(. != null)' >> "$out/blocks.jsonl"
done
journalctl -u worldland-node -u worldland-adversary3 -u worldland-load1 -u worldland-load4 -u worldland-load8 --no-pager > "$out/services.log"
install -m 644 "phase-$phase/genesis.json" "phase-$phase/manifest.json" node-phase.sh integrated.json "$out/"
sha256sum bin/worldland-measured > "$out/build-sha256.txt"
if [ "$phase" = attack ]; then sha256sum bin/worldland-response-fault >> "$out/build-sha256.txt"; fi
date -u --iso-8601=seconds > "$out/collected-at.txt"
tar -czf "/home/infonet/phase-public-$label.tgz" -C /home/infonet "phase-public-$label"
chmod 644 "/home/infonet/phase-public-$label.tgz"
sha256sum "/home/infonet/phase-public-$label.tgz"
