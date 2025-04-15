#!/bin/sh

# 기본값 설정
NETWORK_ID=${NETWORK_ID:-250407}

# Use a random datadir with shuf
DATADIR="/workspace/worldland-bcai-$(shuf -i 1000-9999 -n 1)-$(date +%s)"

# Create the datadir directory
mkdir -p "$DATADIR"

# Initialize blockchain state if not already initialized
if [ ! -d "$DATADIR/geth" ]; then
    echo "Initializing blockchain with genesis file"
    /usr/local/bin/worldland --datadir "$DATADIR" init /workspace/BCAIgensis.json
fi

# Start the WorldLand node
exec /usr/local/bin/worldland \
    --networkid "$NETWORK_ID" \
    --datadir "$DATADIR" \
    --port 30303 \
    --http \
    --http.addr 0.0.0.0 \
    --http.corsdomain "*" \
    --http.vhosts "*" \
    --http.api "eth,net,web3" \
    -nodiscover \
    -verbosity 3 \
    -allow-insecure-unlock \
    console
