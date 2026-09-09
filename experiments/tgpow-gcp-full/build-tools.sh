#!/bin/bash
set -euo pipefail
cd /opt/worldland-testnet
install -d source bin
tar -xzf /home/infonet/source.tgz -C source
tar -xzf /home/infonet/tools-source.tgz -C source
cd source
export GOMAXPROCS=2 GOPATH=/opt/worldland-testnet/go-cache GOCACHE=/opt/worldland-testnet/build-cache
go build -o ../bin/setup ./experiments/tgpow-gcp-testnet/setup
go build -o /home/infonet/explorer ./experiments/tgpow-gcp-testnet/explorer
cp ../bin/setup /home/infonet/setup
chmod 755 /home/infonet/explorer /home/infonet/setup
echo WORLDLAND_TOOLS_BUILT
