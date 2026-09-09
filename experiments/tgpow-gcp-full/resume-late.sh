#!/bin/bash
set -euo pipefail
mode="$1"
label="$2"
[[ "$mode" =~ ^(fault|recover)$ ]]
[[ "$label" =~ ^[a-zA-Z0-9_-]+$ ]]
[[ "$(hostname)" =~ ^wl-tgpow6-0908-n[456]$ ]]
cd /opt/worldland-testnet
test "$(cat phase-active)" = attack
test "$(systemctl is-active worldland-node)" = active
test -f response-fault.enabled
out="/home/infonet/resume-$label"
test ! -e "$out"
mkdir "$out"
date -u --iso-8601=seconds > "$out/before-time.txt"
bash /home/infonet/rpc.sh eth_blockNumber > "$out/before-head.json"
bash /home/infonet/rpc.sh eth_getLogs '[{"fromBlock":"0x0","toBlock":"latest","address":"0x0000000000000000000000000000000000000801"}]' > "$out/before-registry.json"
jq -e 'has("result") and (has("error")|not)' "$out/before-registry.json" >/dev/null
journalctl -u worldland-node --no-pager > "$out/before-services.log"
if [ "$mode" = recover ]; then
  disabled="response-fault.disabled-$label"
  test ! -e "$disabled"
  mv -n response-fault.enabled "$disabled"
  test ! -e response-fault.enabled
fi
systemctl restart worldland-node
systemctl is-active worldland-node
date -u --iso-8601=seconds > "$out/restarted-at.txt"
# Preserve public evidence only. Node keys/keystore/TPM objects are untouched.
tar -czf "$out.tgz" -C /home/infonet "resume-$label"
chmod 644 "$out.tgz"
sha256sum "$out.tgz"
