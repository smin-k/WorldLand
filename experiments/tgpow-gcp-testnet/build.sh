#!/bin/bash
set -euo pipefail
exec > >(tee -a /opt/worldland-testnet/build.log) 2>&1
cd /opt/worldland-testnet
mkdir -p source bin
tar -xzf "$1" -C source
cd source
export GOPATH=/opt/worldland-testnet/go-cache
export GOCACHE=/opt/worldland-testnet/build-cache
export CGO_ENABLED=1
export GOMAXPROCS=2
go version
gcc --version | head -n 1
go build -p 2 -o ../bin/ ./cmd/worldland ./cmd/tpmenroll ./cmd/tpmproducer ./cmd/tpmvalidator ./cmd/tpmpreflight ./cmd/tpmregistrygenesis
go test -p 2 ./crypto/tpmwork ./contracts/tpmregistry ./cmd/tpmenroll ./cmd/tpmproducer
sha256sum ../bin/*
echo WORLDLAND_LINUX_BUILD_SUCCESS
