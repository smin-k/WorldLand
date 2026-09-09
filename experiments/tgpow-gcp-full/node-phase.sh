#!/bin/bash
set -euo pipefail
cd /opt/worldland-testnet
phase=$(<phase-active)
[[ "$phase" =~ ^(p256|p128|p64|reorg|attack|p(256|128|64)-r[23])$ ]]
binary=./bin/worldland-measured
if [ "$phase" = attack ]; then
  binary=./bin/worldland-response-fault
  export WORLDLAND_RESEARCH_RESPONSE_MARKER=/opt/worldland-testnet/response-fault.enabled
  case "$(hostname)" in
    wl-tgpow6-0908-n4) export WORLDLAND_RESEARCH_RESPONSE=wrong-request;;
    wl-tgpow6-0908-n5) export WORLDLAND_RESEARCH_RESPONSE=wrong-chain;;
    wl-tgpow6-0908-n6) export WORLDLAND_RESEARCH_RESPONSE=bad-signature;;
  esac
fi
export WORLDLAND_TPM_EK_CERT=/opt/worldland-testnet/ek.pem
controller=$(jq -r .controller identity.json)
did=$(jq -r .did identity.json)
args=(--config /opt/worldland-testnet/node.toml)
if [ -f "phase-$phase/mining.enabled" ]; then args+=(--mine --tpm.integrated /opt/worldland-testnet/integrated.json); fi
exec "$binary" --datadir "/opt/worldland-testnet/data-$phase" --networkid 103994 --nodiscover --nat none --port 30303 --maxpeers 8 --ipcdisable --http --http.addr 127.0.0.1 --http.port 8545 --http.api eth,net,web3,admin,miner --http.vhosts localhost --authrpc.addr 127.0.0.1 --cache 256 --syncmode full --allow-insecure-unlock --unlock "$controller" --password /opt/worldland-testnet/password --miner.etherbase "$controller" --miner.threads 1 --miner.tpmkey WorldLand-TPM-Work-Test --miner.tpmdid "$did" --verbosity 3 "${args[@]}"
