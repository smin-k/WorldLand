#!/bin/bash
set -euo pipefail
cd /opt/worldland-testnet/source
install -m 644 /home/infonet/block.go core/types/block.go
install -m 644 /home/infonet/eligibility_json.go core/types/eligibility_json.go
install -m 644 /home/infonet/eligibility_json_test.go core/types/eligibility_json_test.go
install -m 644 /home/infonet/gen_header_json.go core/types/gen_header_json.go
export GOPATH=/opt/worldland-testnet/go-cache GOCACHE=/opt/worldland-testnet/build-cache GOMAXPROCS=2
# Regenerate only Header with the compatible Linux Go 1.18 toolchain.
(cd core/types && go run github.com/fjl/gencodec -type Header -field-override headerMarshaling -out gen_header_json.go)
go test -p 2 ./core/types ./ethclient ./cmd/tpmenroll ./cmd/tpmproducer ./contracts/tpmregistry
mkdir -p /home/infonet/rpc-fix
go build -p 2 -o /home/infonet/rpc-fix/ ./cmd/worldland ./cmd/tpmenroll ./cmd/tpmproducer ./cmd/tpmvalidator
sha256sum /home/infonet/rpc-fix/*
tar -czf /home/infonet/rpc-fix.tgz -C /home/infonet/rpc-fix worldland tpmenroll tpmproducer tpmvalidator
chmod 644 /home/infonet/rpc-fix.tgz
echo WORLDLAND_RPC_FIX_BUILT
