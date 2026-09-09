#!/bin/bash
set -euo pipefail
umask 077
cd /opt/worldland-testnet
if [ ! -x bin/setup ]; then
  (cd source && GOPATH=/opt/worldland-testnet/go-cache GOCACHE=/opt/worldland-testnet/build-cache go build -o ../bin/setup /home/infonet/main.go)
fi
install -m 600 "$1" ek.pem
install -m 600 /home/infonet/intermediate.pem intermediate.pem
export WORLDLAND_TPM_EK_CERT=/opt/worldland-testnet/ek.pem
./bin/tpmpreflight -create | tee preflight.log
sed -n 's/^WORLDLAND_TPM_PREFLIGHT_JSON=//p' preflight.log > preflight.json
jq -e '.success == true' preflight.json
./bin/setup prepare /opt/worldland-testnet
echo WORLDLAND_NODE_PREPARED
