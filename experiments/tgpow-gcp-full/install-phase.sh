#!/bin/bash
set -euo pipefail
umask 077
phase="$1"
[[ "$phase" =~ ^(p256|p128|p64|reorg|attack|p(256|128|64)-r[23])$ ]]
cd /opt/worldland-testnet
test "$(pwd -P)" = /opt/worldland-testnet
test "$(systemctl is-active worldland-node || true)" = inactive
test ! -e "data-$phase"
if [ "$phase" = attack ]; then
  test -s /home/infonet/worldland-response-fault
  test "$(sha256sum /home/infonet/worldland-response-fault | cut -d ' ' -f1)" = 7d35dd45a9311ea436a616d8b24167eacd0568ac5795d85ca8a0456191dac637
  install -m 755 /home/infonet/worldland-response-fault bin/worldland-response-fault
fi
install -d "phase-$phase"
tar -xzf "/home/infonet/phase-$phase.tgz" -C "phase-$phase"
if [ ! -f bin/worldland-measured ]; then install -m 755 /home/infonet/worldland-measured bin/worldland-measured; fi
install -m 700 /home/infonet/node-phase.sh node-phase.sh
./bin/worldland-measured --datadir "/opt/worldland-testnet/data-$phase" init "phase-$phase/genesis.json" 2>&1
cp -a data/keystore/. "data-$phase/keystore/"
cp -a data/worldland/nodekey "data-$phase/worldland/nodekey"
printf '%s\n' "$phase" > phase-active
install -m 644 "phase-$phase/manifest.json" /opt/worldland-observer/manifest.json
printf '[Service]\nExecStart=\nExecStart=/bin/bash /opt/worldland-testnet/node-phase.sh\n' > /etc/systemd/system/worldland-node.service.d/integrated.conf
systemctl daemon-reload
systemctl restart worldland-observer
systemctl start worldland-node
sha256sum bin/worldland-measured "phase-$phase/genesis.json"
echo PHASE_READY_NOT_MINING
