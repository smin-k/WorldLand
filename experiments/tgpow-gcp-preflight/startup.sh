#!/bin/bash
set -euo pipefail
exec > >(tee -a /var/log/worldland-tpm-preflight.log) 2>&1
trap 'rc=$?; echo "WORLDLAND_TPM_PREFLIGHT_EXIT=$rc"' EXIT
shutdown -h +20
echo WORLDLAND_TPM_PREFLIGHT_STAGE=install
export DEBIAN_FRONTEND=noninteractive
apt-get -q update
apt-get -y -q install golang-go ca-certificates curl
mkdir -p /opt/worldland-tpm/crypto/tpmwork /opt/worldland-tpm/cmd/tpmpreflight
cd /opt/worldland-tpm
export GOPATH=/opt/worldland-tpm/go-cache
export GOCACHE=/opt/worldland-tpm/build-cache
meta() { curl --fail --silent --show-error --max-time 15 -H 'Metadata-Flavor: Google' "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$1"; }
meta src-mod > go.mod
meta src-signer > crypto/tpmwork/signer.go
meta src-certification > crypto/tpmwork/certification.go
meta src-backend > crypto/tpmwork/device_backend.go
meta src-linux > crypto/tpmwork/signer_linux.go
meta src-main > cmd/tpmpreflight/main.go
echo WORLDLAND_TPM_PREFLIGHT_STAGE=build
# Pin transitive dependencies for the Ubuntu 22.04 Go toolchain.
go mod edit -require=golang.org/x/sys@v0.0.0-20210615035016-665e8c7367d1
go mod tidy
CGO_ENABLED=0 go build -o /opt/worldland-tpm/tpmpreflight ./cmd/tpmpreflight
echo WORLDLAND_TPM_PREFLIGHT_STAGE=certificate
for attempt in $(seq 1 24); do
  if meta ek-cert > /opt/worldland-tpm/ek.pem; then
    export WORLDLAND_TPM_EK_CERT=/opt/worldland-tpm/ek.pem
    break
  fi
  sleep 5
done
echo WORLDLAND_TPM_PREFLIGHT_STAGE=test
timeout 240 /opt/worldland-tpm/tpmpreflight -create
