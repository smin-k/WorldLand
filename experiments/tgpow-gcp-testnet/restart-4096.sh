#!/bin/bash
set -euo pipefail
umask 077
n="$1"
test "$n" -ge 1 && test "$n" -le 5
cd /opt/worldland-testnet
test "$(pwd -P)" = /opt/worldland-testnet
systemctl stop worldland-node worldland-producer
systemctl stop worldland-enrollment || true
test ! -e archive-65536
mkdir archive-65536
journalctl -u worldland-node -u worldland-producer -u worldland-enrollment --no-pager > archive-65536/services.log
cp genesis.json manifest.json identity.json node-start.sh producer-start.sh enroll.sh archive-65536/
mv data archive-65536/data
if [ -f mining.enabled ]; then mv mining.enabled archive-65536/; fi
mkdir -p release-4096
tar -xzf /home/infonet/demo-4096.tgz -C release-4096
for tool in worldland tpmenroll tpmproducer tpmvalidator; do install -m 755 "release-4096/$tool" "bin/$tool"; done
install -m 600 release-4096/genesis.json genesis.json
install -m 644 release-4096/manifest.json manifest.json
jq --argjson idx "$((n-1))" '.identities[$idx]' manifest.json > identity.json
install -m 644 manifest.json /opt/worldland-observer/manifest.json
sed -i s/103992/103993/g node-start.sh producer-start.sh enroll.sh
./bin/worldland --datadir /opt/worldland-testnet/data init genesis.json
./bin/worldland --datadir /opt/worldland-testnet/data --password password account import account.key
# Preserve the P2P identity referenced by the static peer configurations.
install -m 600 archive-65536/data/worldland/nodekey data/worldland/nodekey
if [ "$n" -le 2 ]; then touch mining.enabled; fi
systemctl reset-failed worldland-enrollment || true
systemctl enable --now worldland-node
systemctl restart worldland-observer
if [ "$n" -le 2 ]; then systemctl enable --now worldland-producer; fi
sha256sum bin/worldland genesis.json
