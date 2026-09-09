#!/bin/bash
set -euo pipefail
exec > >(tee -a /var/log/worldland-setup.log) 2>&1
export DEBIAN_FRONTEND=noninteractive
apt-get -q update
apt-get -y -q install golang-go build-essential ca-certificates curl jq
install -d -m 700 /opt/worldland-testnet
echo WORLDLAND_SETUP_READY
