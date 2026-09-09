#!/bin/bash
set -euo pipefail
cd /opt/worldland-integrated-build/source
tar -xzf /home/infonet/response-fault-overlay.tgz
export CGO_ENABLED=1 GOMAXPROCS=2 GOPATH=/opt/worldland-testnet/go-cache GOCACHE=/opt/worldland-testnet/build-cache
go test -p 2 ./internal/tpmenroll ./internal/tpmproducer -count=1 -timeout 3m
go test -p 2 -tags enrollmentresearch ./internal/tpmenroll ./internal/tpmproducer -count=1 -timeout 3m
go build -p 2 -tags enrollmentresearch -o /home/infonet/worldland-response-fault ./cmd/worldland
chmod 755 /home/infonet/worldland-response-fault
sha256sum /home/infonet/worldland-response-fault
