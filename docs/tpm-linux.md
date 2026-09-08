# Linux TPM 2.0 backend

Linux now implements the same `Signer`, `KeyCertifier`, and
`CredentialActivator` interfaces as the Windows backend. Consensus, enrollment
waiting periods, lottery probabilities, and certificate policy are unchanged.
The backend was subsequently tested on a real GCP Confidential VM vTPM; see
`../experiments/tgpow-gcp-preflight/README.md` for results and trust-policy limits.

## Device and keys

The default device is `/dev/tpmrm0` (kernel resource manager). Override with
`WORLDLAND_TPM_DEVICE` only for another TPM character device. No automatic
software signer, socket simulator, or certificate-validation bypass is used.
Grant access only to the node's trusted service user; do not make the device
world-writable. Prefer the resource manager for concurrent client processes.

Linux key names map to persistent TPM handles:

| Alias | Handle |
| --- | --- |
| WorldLand-TPM-Work | 0x81010020 |
| WorldLand-TPM-AIK | 0x81010021 |
| WorldLand-TPM-Work-Test | 0x81010022 |
| WorldLand-TPM-AIK-Test | 0x81010023 |

An explicit owner-range hexadecimal persistent handle may be used instead.
Arbitrary Windows KSP names are not automatically hashed or silently aliased.
Inspect handle usage before provisioning. An existing compatible key is reused;
an incompatible key is rejected, never replaced. Creation requires `-create`
(or the relevant client's existing creation flag), uses random child keys under
a transient storage primary, and leaves only persistent work/AK objects. TPM
clear, hierarchy changes, NV writes and eviction of existing keys are not used.
Transient objects and policy sessions opened by the backend are flushed.

This initial profile uses empty owner/endorsement and key authorization values.
Devices with nonempty hierarchy authorization fail closed; they are not reset.
Access control relies on OS device permissions. TPM possession and nonexportable
keys do not imply that another process with TPM access cannot request signatures.

Example on an authorized, dedicated Linux TPM test machine:

```sh
go run ./cmd/tpmworkbench -key WorldLand-TPM-Work-Test -create \
  -n 5 -certify -aik WorldLand-TPM-AIK-Test -aikcreate
```

This creates two persistent test keys. Subsequent runs should omit creation
flags. Keys survive process restart; closing the signer does not remove them.
Windows KSP export/evidence probes are not reported as Linux measurements.

## EK and enrollment

The default RSA EK handle is `0x81010001`. If absent, Linux derives the standard
RSA-2048 EK transiently from the endorsement hierarchy. It is not persisted or
replaced. Explicit non-default EK handles must already exist. Unsupported EK
templates are rejected. Existing devices with vendor-specific templates or
non-default derivation requirements need an explicitly reviewed profile.

By default, the EK leaf certificate is read from NV index `0x01c00002`.
For a provider-delivered certificate, set:

```sh
export WORLDLAND_TPM_EK_CERT=/secure/config/ek.pem
```

Accepts one PEM certificate or DER, at most 64 KiB. The backend checks that its
RSA public key matches the actual TPM EK. This is NOT certificate trust:
`tpmregistry` still verifies the configured root/intermediate chain, validity,
EK usage, canonical EK template and approved profile. Supply intermediate
certificates with `tpmenroll -ek-intermediate`. No Google root is automatically
trusted, and no external URL or metadata API is contacted by the backend.

GCP deployment still requires obtaining a nonempty **EK** certificate (not an AK
or CPU VCEK certificate), reviewing the Google trust profile, and testing the
complete enrollment flow. A vTPM experiment does not demonstrate physical-device
scarcity. No cloud VM is created by this change.

## Verification boundary

Host-independent unit tests exercise TPM wire responses, failure handling,
certificate/key matching, signature normalization, and the existing Certify
verifier. They are regression fixtures, not a simulated testnet or hardware
evidence. Real Linux validation must additionally cover key creation/reopen,
EK retrieval, successful and tampered ActivateCredential challenges, Certify,
concurrent access and restart, then end-to-end registry enrollment.

Initial implementation checks performed on 2026-09-08, before the GCP run:

- Windows host: `go test ./crypto/tpmwork ./contracts/tpmregistry
  ./cmd/tpmenroll ./cmd/tpmworkbench ./cmd/tpmdelegatebench` passed.
- Windows host: `go test -race ./crypto/tpmwork` passed.
- Windows host: `go build ./cmd/worldland` passed.
- Linux/amd64 cross-build with CGO disabled: `go build ./crypto/tpmwork
  ./cmd/tpmworkbench` passed.
- A wider Linux cross-build including enrollment/delegation tools is blocked
  by the existing VCT/ECCPoW CGO dependency (`ECC` and associated symbols are
  absent with CGO disabled). This does not establish a full Linux node build.
  Validate that separately on Linux with a C/C++ toolchain and CGO enabled.
- No live Linux TPM, GCP VM, or testnet was used in these checks.

Subsequent GCP preflight on the same date passed signing, reopen, Certify,
EK certificate/public-key matching, credential activation and tamper rejection.
It exposed and fixed an EK derivation bug: the standard RSA EK creation template
requires a 256-byte zero unique field. The cloud run did not validate a trusted
Google registry policy or start a consensus network.

The subsequent client update adds the explicit pinned-root `gcp-cas-v1`
policy and offline verification of that captured evidence. See
[Google Cloud certificate policy](tpm-gcp.md) for configuration and trust limits.
