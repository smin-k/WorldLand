#!/bin/bash
set -euo pipefail
test "$(jq -r .chainId /opt/worldland-testnet/manifest.json)" = 103994
systemd-run --unit=worldland-enroll --property=Type=exec --property=TimeoutStartSec=3700 /bin/bash /opt/worldland-testnet/enroll.sh
