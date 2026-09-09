#!/bin/bash
set -euo pipefail
test "$(hostname)" = wl-tgpow6-0908-n5
cd /opt/worldland-testnet
test -f research-withhold.enabled
target=$(jq -r .did identity.json)
touch research-mining.enabled
systemctl restart worldland-node
observed=0
for ((i=0;i<900;i++)); do
  if ! snapshot=$(/home/infonet/registry-probe); then
    sleep 1
    continue
  fi
  match=$(printf '%s\n' "$snapshot" | jq -c --arg did "$target" 'select(.identity == $did)')
  if [ -n "$match" ]; then
    if printf '%s\n' "$match" | jq -e '.finalized or .active' >/dev/null; then
      echo RESEARCH_UNEXPECTED_FINALIZATION
      printf '%s\n' "$match"
      exit 1
    fi
    if [ "$observed" = 0 ] && printf '%s\n' "$match" | jq -e '.producerRequest.Approvals == 5 and .producerRequest.Threshold == 6 and .head <= .producerRequest.ResponseDeadline' >/dev/null; then
      echo RESEARCH_FIVE_OF_SIX_OBSERVED
      printf '%s\n' "$match"
      observed=1
    fi
    if printf '%s\n' "$match" | jq -e '.head > .producerRequest.ResponseDeadline' >/dev/null; then
      echo RESEARCH_DEADLINE_PASSED
      printf '%s\n' "$match"
      test "$observed" = 1
      exit 0
    fi
  fi
  sleep 1
done
echo RESEARCH_WITHHOLD_OBSERVATION_TIMEOUT
exit 1
