#!/bin/bash
set -euo pipefail
umask 077
node="$1"
test "$node" -ge 1 && test "$node" -le 6
cd /opt/worldland-testnet
test "$(pwd -P)" = /opt/worldland-testnet
test "$(jq -r .chainId manifest.json)" = 103994
test "$(systemctl is-active worldland-node || true)" = inactive
test -s /home/infonet/final-six.tgz
test ! -e data-integrated
test ! -e integrated-mining.enabled
install -d /opt/worldland-integrated-release
tar -xzf /home/infonet/integrated-binaries.tgz -C /opt/worldland-integrated-release
install -m 755 /opt/worldland-integrated-release/bin/worldland bin/worldland-integrated
install -m 700 /home/infonet/node-integrated.sh node-integrated.sh
enroll=false
if [ "$node" -gt 3 ]; then enroll=true; fi
jq -n --argjson enroll "$enroll" --arg hash "$(jq -r .profileHash manifest.json)" '{Producer:{KeyFile:"/opt/worldland-testnet/account.key",CertificateProfile:"gcp-cas-v1",ProfileHashes:[$hash],Lookback:512,MaxPerSlot:4,GasLimit:1200000},Enrollment:{AttestationKey:"WorldLand-TPM-AIK-Test",VRFPublicKey:"/opt/worldland-testnet/vrf.pub",Profile:"/opt/worldland-testnet/profile.bin",EKIntermediates:["/opt/worldland-testnet/intermediate.pem"]},Enroll:$enroll,PreparationTimeoutSeconds:5}' > integrated.json
./bin/worldland-integrated --datadir /opt/worldland-testnet/data-integrated init genesis.json
cp -a data/keystore/. data-integrated/keystore/
cp -a data/worldland/nodekey data-integrated/worldland/nodekey
# Keep original data intact, including secrets, only on this VM.
systemctl disable worldland-producer
install -d /etc/systemd/system/worldland-node.service.d
printf '[Service]\nExecStart=\nExecStart=/bin/bash /opt/worldland-testnet/node-integrated.sh\n' > /etc/systemd/system/worldland-node.service.d/integrated.conf
systemctl daemon-reload
systemctl start worldland-node
sha256sum bin/worldland-integrated genesis.json integrated.json
echo INTEGRATED_INSTALLED_NOT_MINING
