#!/bin/bash
set -euo pipefail
install -m 700 /home/infonet/producer-start.sh /opt/worldland-testnet/producer-start.sh
install -d /etc/systemd/system/worldland-producer.service.d
printf '[Service]\nEnvironment=WORLDLAND_PRODUCER_POLL=50ms\n' > /etc/systemd/system/worldland-producer.service.d/poll.conf
systemctl daemon-reload
if systemctl is-active --quiet worldland-producer; then systemctl restart worldland-producer; fi
date -u --iso-8601=seconds
