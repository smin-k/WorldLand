#!/bin/bash
set -euo pipefail
umask 077
cd /opt/worldland-testnet
install -d bin
tar -xzf /home/infonet/binaries.tgz bin/tpmpreflight
tar -xzf /home/infonet/demo-4096.tgz -C bin ./worldland ./tpmenroll ./tpmproducer ./tpmvalidator
install -m 755 /home/infonet/setup bin/setup
install -m 600 "/home/infonet/n$1-ek.pem" ek.pem
install -m 600 /home/infonet/intermediate.pem intermediate.pem
export WORLDLAND_TPM_EK_CERT=/opt/worldland-testnet/ek.pem
./bin/tpmpreflight -create | tee preflight.log
sed -n 's/^WORLDLAND_TPM_PREFLIGHT_JSON=//p' preflight.log > preflight.json
jq -e '.success == true' preflight.json
./bin/setup -chain-id 103994 -nodes 6 -bootstrap 3 -threshold 6 prepare /opt/worldland-testnet
install -m 644 identity.json /home/infonet/identity.json
sha256sum bin/worldland
echo WORLDLAND_NODE_PREPARED
