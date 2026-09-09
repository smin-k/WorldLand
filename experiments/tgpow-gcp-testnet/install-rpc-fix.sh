#!/bin/bash
set -euo pipefail
cd /opt/worldland-testnet
mkdir -p rpc-fix original-tools
tar -xzf /home/infonet/rpc-fix.tgz -C rpc-fix
systemctl stop worldland-producer
systemctl stop worldland-node
cp -n bin/worldland bin/tpmenroll bin/tpmproducer bin/tpmvalidator original-tools/
install -m 755 rpc-fix/worldland bin/worldland
install -m 755 rpc-fix/tpmenroll bin/tpmenroll
install -m 755 rpc-fix/tpmproducer bin/tpmproducer
install -m 755 rpc-fix/tpmvalidator bin/tpmvalidator
systemctl start worldland-node
for attempt in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8545 > /dev/null; then break; fi
  sleep 1
done
if [ -f mining.enabled ]; then
  systemctl start worldland-producer
else
  # reset-failed can unload a transient unit; recreate it explicitly.
  systemctl reset-failed worldland-enrollment || true
  systemd-run --unit=worldland-enrollment /bin/bash /opt/worldland-testnet/enroll.sh
fi
echo WORLDLAND_RPC_FIX_INSTALLED
