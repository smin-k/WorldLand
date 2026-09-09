#!/bin/bash
set -euo pipefail
cd /opt/worldland-testnet/source
GOPATH=/opt/worldland-testnet/go-cache GOCACHE=/opt/worldland-testnet/build-cache go build -o /home/infonet/explorer ./explorer
chmod 755 /home/infonet/explorer
