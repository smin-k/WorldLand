#!/bin/bash
set -euo pipefail
test "$(hostname)" = wl-tgpow6-0908-n4
cd /opt/worldland-testnet
test ! -e research-restart-completed
since=$(date -u '+%Y-%m-%d %H:%M:%S')
touch research-mining.enabled
systemctl restart worldland-node
# Bounded observation; restart only when an actual response was submitted.
for ((i=0;i<600;i++)); do
  if journalctl -u worldland-node --since "$since" --no-pager | grep -q 'producer response slot'; then
    date -u --iso-8601=ns
    journalctl -u worldland-node --since "$since" --no-pager
    bash /home/infonet/rpc.sh eth_blockNumber
    /home/infonet/registry-probe
    echo RESEARCH_PENDING_RESTART_BEGIN
    systemctl restart worldland-node
    touch research-restart-completed
    echo RESEARCH_PENDING_RESTART_COMPLETE
    exit 0
  fi
  sleep 0.5
done
echo RESEARCH_RESTART_TRIGGER_NOT_OBSERVED
exit 1
