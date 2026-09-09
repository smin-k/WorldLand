#!/bin/bash
set -euo pipefail
umask 077
test "$(hostname)" = wl-tgpow6-0908-n2
cd /opt/worldland-testnet
test "$(cat phase-active)" = attack
out=/home/infonet/valid-verifier-load-r1
test ! -e "$out"
mkdir "$out"
finish() {
 if [ -n "${pid:-}" ]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
 date -u --iso-8601=seconds > "$out/finished-at.txt"
 tar -czf "$out.tgz" -C /home/infonet valid-verifier-load-r1
 chmod 644 "$out.tgz"
 sha256sum "$out.tgz"
}
trap finish EXIT
sha256sum /home/infonet/verify-load-linux bin/worldland-response-fault > "$out/build-sha256.txt"
sample() {
 printf '%s %s ' "$(date -u +%FT%TZ)" "$1" >> "$out/resources.txt"
 for unit in worldland-node worldland-valid-verifier-load; do
  printf '%s ' "$unit" >> "$out/resources.txt"
  systemctl show "$unit" -p CPUUsageNSec -p MemoryCurrent -p TasksCurrent | tr '\n' ' ' >> "$out/resources.txt"
 done
 bash /home/infonet/rpc.sh eth_blockNumber >> "$out/resources.txt"
 test "$(systemctl is-active worldland-node)" = active
}
for repeat in 1 2 3; do
 for mode in response admission; do
  for workers in 1 2 4 8; do
   name="$mode-w$workers-r$repeat"
   for i in $(seq 1 8); do sample "$name-control"; sleep 2; done
   timeout --kill-after=5s 180s /home/infonet/verify-load-linux -workers "$workers" -seconds 30 -mode "$mode" > "$out/$name.json" 2> "$out/$name.err" &
   pid=$!
   while kill -0 "$pid" 2>/dev/null; do sample "$name-load"; sleep 2; done
   wait "$pid"
   pid=''
   jq -e '.failures == 0 and .operations > 0' "$out/$name.json" >/dev/null
  done
 done
done
echo complete > "$out/status.txt"
