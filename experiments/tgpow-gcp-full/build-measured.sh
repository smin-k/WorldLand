#!/bin/bash
set -euo pipefail
cd /opt/worldland-integrated-build/source
tar -xzf /home/infonet/measured-overlay.tgz
export CGO_ENABLED=1 GOMAXPROCS=2 GOPATH=/opt/worldland-testnet/go-cache GOCACHE=/opt/worldland-testnet/build-cache
go test -p 2 ./miner ./internal/tpmproducer -count=1 -timeout 4m
go build -p 2 -o /home/infonet/worldland-measured ./cmd/worldland
chmod 755 /home/infonet/worldland-measured
sha256sum /home/infonet/worldland-measured
echo MEASURED_BUILD_VERIFIED
