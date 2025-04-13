#!/bin/sh

# 기본값 설정
NETWORK_ID=${NETWORK_ID:-250407}

exec /usr/local/bin/worldland \
    --networkid "$NETWORK_ID" \
    --datadir /workspace/BCAInetwork \
    --port 30303 \
    --addr 0.0.0.0 \ 
    --http \
    --http.addr 0.0.0.0 \
    --http.corsdomain "*" \
    --http.vhosts "*" \
    --http.api "eth,net,web3" \
    -nodiscover \
    -verbosity 3 \
    -allow-insecure-unlock \
    console
