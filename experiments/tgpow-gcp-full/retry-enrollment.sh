#!/bin/bash
set -euo pipefail
cd /opt/worldland-testnet
height=$(bash /home/infonet/rpc.sh eth_blockNumber | jq -er .result)
test "$((height))" -gt 83
test "$(systemctl is-active worldland-enroll || true)" != active
test ! -f mining.enabled
systemd-run --unit=worldland-enroll-retry1 --property=Type=exec /bin/bash /opt/worldland-testnet/enroll.sh
