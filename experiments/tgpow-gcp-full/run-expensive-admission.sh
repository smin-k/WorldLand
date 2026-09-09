#!/bin/bash
set -euo pipefail
umask 077
test "$(hostname)" = wl-tgpow6-0908-n6
cd /opt/worldland-testnet
test "$(cat phase-active)" = attack
out=/home/infonet/expensive-admission-r1
test ! -e "$out"
mkdir "$out"
finish() {
 if [ -n "${pid:-}" ]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
 date -u --iso-8601=seconds > "$out/finished-at.txt"
 tar -czf "$out.tgz" -C /home/infonet expensive-admission-r1
 chmod 644 "$out.tgz"
 sha256sum "$out.tgz"
}
trap finish EXIT
sha256sum /home/infonet/adversary-valid-linux bin/worldland-response-fault > "$out/build-sha256.txt"
sample() {
 printf '%s %s ' "$(date -u +%FT%TZ)" "$1" >> "$out/resources.txt"
 systemctl show worldland-node -p CPUUsageNSec -p MemoryCurrent -p TasksCurrent | tr '\n' ' ' >> "$out/resources.txt"
 bash /home/infonet/rpc.sh eth_blockNumber >> "$out/resources.txt"
 test "$(systemctl is-active worldland-node)" = active
}
for repeat in 1 2 3; do
 for rate in 1 4 8; do
  name="rate$rate-r$repeat"
  for i in $(seq 1 8); do sample "$name-control"; sleep 2; done
  timeout --kill-after=5s 310s /home/infonet/adversary-valid-linux -valid-evidence -count 24 -rate "$rate" > "$out/$name.jsonl" 2> "$out/$name.err" &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
   sample "$name-load"
   mem=$(systemctl show worldland-node -p MemoryCurrent --value)
   if [[ "$mem" =~ ^[0-9]+$ ]] && [ "$mem" -gt 6442450944 ]; then echo MEMORY_STOP > "$out/safety-stop.txt"; exit 1; fi
   sleep 2
  done
  wait "$pid"
  pid=''
 done
done
echo complete > "$out/status.txt"
