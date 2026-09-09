#!/bin/bash
set -euo pipefail
umask 077
cd /opt/worldland-testnet
test "$(pwd -P)" = /opt/worldland-testnet
test "$(jq -r .chainId manifest.json)" = 103994
test "$(systemctl is-active worldland-node || true)" = inactive
test -s /home/infonet/final-six.tgz
test ! -e data-research12
install -m 755 /home/infonet/worldland-research bin/worldland-research
install -m 700 /home/infonet/node-research.sh node-research.sh
chmod 755 /home/infonet/registry-probe
./bin/worldland-research --datadir /opt/worldland-testnet/data-research12 init genesis.json
cp -a data/keystore/. data-research12/keystore/
cp -a data/worldland/nodekey data-research12/worldland/nodekey
touch research-withhold.enabled
printf '[Service]\nExecStart=\nExecStart=/bin/bash /opt/worldland-testnet/node-research.sh\n' > /etc/systemd/system/worldland-node.service.d/integrated.conf
systemctl daemon-reload
systemctl start worldland-node
sha256sum bin/worldland-research
echo RESEARCH_READY_NOT_MINING
