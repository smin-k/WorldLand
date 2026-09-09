#!/bin/bash
set -euo pipefail
cd /opt/worldland-testnet
export WORLDLAND_TPM_EK_CERT=/opt/worldland-testnet/ek.pem
export WORLDLAND_RESEARCH_WITHHOLD_DID=$(jq -r '.identities[4].did' manifest.json)
export WORLDLAND_RESEARCH_WITHHOLD_MARKER=/opt/worldland-testnet/research-withhold.enabled
controller=$(jq -r .controller identity.json)
did=$(jq -r .did identity.json)
chain=$(jq -r .chainId manifest.json)
args=(--config /opt/worldland-testnet/node.toml)
if [ -f research-mining.enabled ]; then args+=(--mine --tpm.integrated /opt/worldland-testnet/integrated.json); fi
exec ./bin/worldland-research --datadir /opt/worldland-testnet/data-research12 --networkid "$chain" --nodiscover --nat none --port 30303 --maxpeers 8 --ipcdisable --http --http.addr 127.0.0.1 --http.port 8545 --http.api eth,net,web3,admin,miner --http.vhosts localhost --authrpc.addr 127.0.0.1 --cache 256 --syncmode full --allow-insecure-unlock --unlock "$controller" --password /opt/worldland-testnet/password --miner.etherbase "$controller" --miner.threads 1 --miner.tpmkey WorldLand-TPM-Work-Test --miner.tpmdid "$did" --verbosity 3 "${args[@]}"
