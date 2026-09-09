#!/bin/bash
set -euo pipefail
cd /opt/worldland-integrated-build/source
tar -xzf /home/infonet/research-overlay.tgz
export CGO_ENABLED=1 GOMAXPROCS=2 GOPATH=/opt/worldland-testnet/go-cache GOCACHE=/opt/worldland-testnet/build-cache
go test -p 2 -tags enrollmentresearch ./internal/tpmproducer ./internal/tpmenroll ./miner -count=1 -timeout 4m
go build -p 2 -tags enrollmentresearch -o /home/infonet/worldland-research ./cmd/worldland
chmod 755 /home/infonet/worldland-research
sha256sum /home/infonet/worldland-research
echo RESEARCH_BUILD_VERIFIED
