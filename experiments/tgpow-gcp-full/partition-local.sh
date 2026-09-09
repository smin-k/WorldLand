#!/bin/bash
set -euo pipefail
# Dedicated experiment-only P2P partition. IAP, SSH and observer traffic unaffected.
action="$1"
node="$2"
[[ "$action" =~ ^(split|heal)$ ]]
[[ "$node" =~ ^[1-6]$ ]]
cd /opt/worldland-testnet
test "$(jq -r .chainId manifest.json)" = 103994
chain=WL_RESEARCH_SPLIT
heal() {
  for parent in INPUT OUTPUT; do
    while iptables -w -C "$parent" -j "$chain" 2>/dev/null; do iptables -w -D "$parent" -j "$chain"; done
  done
  if iptables -w -L "$chain" >/dev/null 2>&1; then iptables -w -F "$chain"; iptables -w -X "$chain"; fi
  echo P2P_PARTITION_HEALED
}
if [ "$action" = heal ]; then heal; exit; fi
# Refuse duplicate experiments rather than losing an existing recovery timer.
! iptables -w -L "$chain" >/dev/null 2>&1
# Install independent recovery BEFORE adding any packet-drop rule.
systemd-run --unit=worldland-partition-autoheal --on-active=180s --timer-property=AccuracySec=1s /bin/bash /home/infonet/partition-local.sh heal "$node"
iptables -w -N "$chain"
trap heal ERR
# Groups {1,4,5} and {2,3,6}, with 1 versus 2 genesis producers.
case "$node" in 1|4|5) other=(3 4 7);; *) other=(2 5 6);; esac
for last in "${other[@]}"; do
  ip="10.79.0.$last"
  for port in --sport --dport; do
    iptables -w -A "$chain" -s "$ip" -p tcp "$port" 30303 -j DROP
    iptables -w -A "$chain" -d "$ip" -p tcp "$port" 30303 -j DROP
  done
done
iptables -w -I INPUT 1 -j "$chain"
iptables -w -I OUTPUT 1 -j "$chain"
date -u --iso-8601=seconds
echo P2P_PARTITION_APPLIED_AUTOHEAL_180S
