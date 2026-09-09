#!/bin/bash
set -euo pipefail
umask 077
rate="$1"
[[ "$rate" =~ ^(1|4|8)$ ]]
cd /opt/worldland-testnet
test "$(jq -r .chainId manifest.json)" = 103994
test "$(systemctl is-active worldland-node)" = active
out="/home/infonet/bounded-load-$rate"
test ! -e "$out"
mkdir "$out"
cleanup() { if [ -n "${loadpid:-}" ]; then kill "$loadpid" 2>/dev/null || true; wait "$loadpid" 2>/dev/null || true; fi; }
trap cleanup EXIT
date -u --iso-8601=seconds > "$out/start.txt"
sha256sum /home/infonet/adversary bin/worldland-research > "$out/build-sha256.txt"
# A 40 second quiet control, then at most 24 malformed starts at a bounded rate.
# The source has its own five-minute context; timeout is an independent bound.
for i in $(seq 1 20); do
  printf '%s control ' "$(date -u +%FT%TZ)" >> "$out/resources.txt"
  systemctl show worldland-node -p CPUUsageNSec -p MemoryCurrent -p TasksCurrent | tr '\n' ' ' >> "$out/resources.txt"
  bash /home/infonet/rpc.sh eth_blockNumber >> "$out/resources.txt"
  sleep 2
done
timeout --kill-after=5s 310s /home/infonet/adversary -count 24 -rate "$rate" > "$out/requests.jsonl" 2> "$out/errors.txt" &
loadpid=$!
for i in $(seq 1 170); do
  printf '%s load ' "$(date -u +%FT%TZ)" >> "$out/resources.txt"
  systemctl show worldland-node -p CPUUsageNSec -p MemoryCurrent -p TasksCurrent | tr '\n' ' ' >> "$out/resources.txt"
  bash /home/infonet/rpc.sh eth_blockNumber >> "$out/resources.txt"
  mem=$(systemctl show worldland-node -p MemoryCurrent --value)
  if [[ "$mem" =~ ^[0-9]+$ ]] && [ "$mem" -gt 6442450944 ]; then
    echo MEMORY_STOP_6GIB > "$out/safety-stop.txt"
    kill "$loadpid" 2>/dev/null || true
    break
  fi
  if ! kill -0 "$loadpid" 2>/dev/null; then break; fi
  sleep 2
done
set +e
wait "$loadpid"
result=$?
set -e
loadpid=''
printf '%s\n' "$result" > "$out/exit-code.txt"
date -u --iso-8601=seconds > "$out/end.txt"
tar -czf "$out.tgz" -C /home/infonet "bounded-load-$rate"
chmod 644 "$out.tgz"
sha256sum "$out.tgz"
exit "$result"
