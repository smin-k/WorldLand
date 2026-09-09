#!/bin/bash
set -euo pipefail
method="$1"
params="${2:-[]}"
jq -cn --arg method "$method" --argjson params "$params" '{jsonrpc:"2.0",id:1,method:$method,params:$params}' | curl -fsS --max-time 15 -H 'Content-Type: application/json' --data-binary @- http://127.0.0.1:8545
