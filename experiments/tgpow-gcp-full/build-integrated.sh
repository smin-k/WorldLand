#!/bin/bash
set -euo pipefail
umask 077
base=/opt/worldland-integrated-build
test ! -e "$base"
install -d "$base/source" "$base/bin"
tar -xzf /home/infonet/integrated-base.tgz -C "$base/source"
tar -xzf /home/infonet/integrated-overlay.tgz -C "$base/source"
# Tests moved to shared internal packages; remove only their old archive copies.
rm "$base/source/cmd/tpmenroll/main_test.go" "$base/source/cmd/tpmproducer/main_test.go"
cd "$base/source"
export CGO_ENABLED=1 GOMAXPROCS=2 GOPATH=/opt/worldland-testnet/go-cache GOCACHE=/opt/worldland-testnet/build-cache
go test -p 2 ./params ./contracts/tpmregistry/... ./crypto/tpmwork ./internal/tpmenroll ./internal/tpmproducer ./internal/tpmservice ./consensus/VCT ./miner ./cmd/worldland -count=1 -timeout 4m
go build -p 2 -o "$base/bin/" ./cmd/worldland ./cmd/tpmenroll ./cmd/tpmproducer
sha256sum "$base/bin/"*
tar -czf /home/infonet/integrated-binaries.tgz -C "$base" bin
chmod 644 /home/infonet/integrated-binaries.tgz
sha256sum /home/infonet/integrated-binaries.tgz
echo INTEGRATED_LINUX_VERIFIED
