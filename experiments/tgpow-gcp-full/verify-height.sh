#!/bin/bash
set -euo pipefail
height="$1"
[[ "$height" =~ ^[0-9]+$ ]]
hex=$(printf '0x%x' "$height")
bash /home/infonet/rpc.sh eth_getBlockByNumber "[\"$hex\",false]" | jq -e '.result | select(. != null) | {number,hash,stateRoot,miner}'
