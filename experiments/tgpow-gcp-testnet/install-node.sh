#!/bin/bash
set -euo pipefail
umask 077
node="$1"
test "$node" -ge 1 && test "$node" -le "$(jq '.identities | length' /home/infonet/manifest.json)"
cd /opt/worldland-testnet
install -m 600 /home/infonet/genesis.json genesis.json
install -m 644 /home/infonet/manifest.json manifest.json
install -m 700 /home/infonet/node-start.sh node-start.sh
install -m 700 /home/infonet/producer-start.sh producer-start.sh
install -m 700 /home/infonet/enroll.sh enroll.sh
./bin/worldland --datadir /opt/worldland-testnet/data init genesis.json
./bin/worldland --datadir /opt/worldland-testnet/data --password password account import account.key
cat > /etc/systemd/system/worldland-node.service <<'UNIT'
[Unit]
Description=WorldLand isolated real-TPM research node
After=network-online.target
[Service]
ExecStart=/bin/bash /opt/worldland-testnet/node-start.sh
Restart=on-failure
RestartSec=5
TimeoutStopSec=45
UMask=0077
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=full
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/worldland-producer.service <<'UNIT'
[Unit]
Description=WorldLand enrollment producer
After=worldland-node.service
[Service]
ExecStart=/bin/bash /opt/worldland-testnet/producer-start.sh
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=full
[Install]
WantedBy=multi-user.target
UNIT
# The observer has no need to read TPM/account secrets or access the TPM device.
public_flag=""
if [ "$node" -eq 1 ]; then public_flag="-public"; fi
install -d -m 755 /opt/worldland-observer
install -m 755 /home/infonet/explorer /opt/worldland-observer/explorer
install -m 644 manifest.json /opt/worldland-observer/manifest.json
cat > /etc/systemd/system/worldland-observer.service <<UNIT
[Unit]
Description=WorldLand read-only explorer observations
After=worldland-node.service
[Service]
DynamicUser=true
ExecStart=/opt/worldland-observer/explorer -node $node -manifest /opt/worldland-observer/manifest.json $public_flag
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now worldland-node worldland-observer
echo WORLDLAND_NODE_INSTALLED
