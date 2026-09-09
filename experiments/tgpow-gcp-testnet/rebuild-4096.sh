#!/bin/bash
set -euo pipefail
cd /opt/worldland-testnet/source
tar -xzf /home/infonet/patch-4096.tgz
export GOPATH=/opt/worldland-testnet/go-cache GOCACHE=/opt/worldland-testnet/build-cache GOMAXPROCS=2
go test -p 2 ./consensus/VCT ./params ./experiments/tgpow-gcp-testnet/setup
mkdir -p /home/infonet/demo-4096
go build -p 2 -o /home/infonet/demo-4096/ ./cmd/worldland ./cmd/tpmenroll ./cmd/tpmproducer ./cmd/tpmvalidator ./experiments/tgpow-gcp-testnet/setup
mkdir -p /home/infonet/genesis-4096
/home/infonet/demo-4096/setup genesis /home/infonet/genesis-4096 /home/infonet/n1-identity.json /home/infonet/n2-identity.json /home/infonet/n3-identity.json /home/infonet/n4-identity.json /home/infonet/n5-identity.json
cp /home/infonet/genesis-4096/*.json /home/infonet/demo-4096/
tar -czf /home/infonet/demo-4096.tgz -C /home/infonet/demo-4096 .
chmod 644 /home/infonet/demo-4096.tgz
