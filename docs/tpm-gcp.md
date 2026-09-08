# Explicit Google Cloud EK certificate policy

The client repository includes an opt-in `gcp-cas-v1` certificate policy for
`tpmvalidator` and `tpmproducer`. The default `manufacturer` policy and its
digest encoding are unchanged. This is not an automatic relaxation of TPM
certificate verification and does not change block difficulty or mining rules.

## Configuration

Select `-certificate-profile gcp-cas-v1` on every enrollment validator and
producer that uses this policy. Do not supply `-ek-root`: this mode pins the
embedded Google EK/AK CAS root and rejects caller-supplied roots.
No `-require-ek-oid=false` workaround is needed.

Obtain the configured digest without a running chain:

```sh
go run ./cmd/tpmvalidator -certificate-profile gcp-cas-v1 -print-policy-digest
```

Other policy inputs, including `-profile-hash` and `-max-evidence-bytes`,
must match across services. Commit this new digest in the testnet genesis or
an authorized policy epoch before registration. Changing only a local flag
does not update an existing on-chain policy.

The Linux claimant still needs its own EK certificate, read from TPM NV or
supplied as `WORLDLAND_TPM_EK_CERT`, and the appropriate intermediate supplied
to `tpmenroll -ek-intermediate /path/to/intermediate.pem`. The existing
`-profile` document is a separate input; it cannot choose the validator's
certificate policy. Never reuse the captured test fixture certificate as a
different VM's identity.

## Verification and trust boundary

After ordinary X.509 signature, chain and validity verification to the pinned
root, the policy requires a non-CA RSA2048/65537 EK certificate with exactly
key-encipherment usage. Signing/AK certificates from the same CA are rejected.
It checks the signed GCE instance identity extension
`1.3.6.1.4.1.11129.2.1.21`, production issuance, positive project/instance
numbers, nonempty identifiers, and consistency with the certificate subject.
Malformed, duplicate and unsupported security-property encodings fail closed.
Existing EK/public-area binding, canonical EK identity, AK attributes, work-key
and VRF-key checks remain in effect. Credential activation and certification
remain necessary in the enrollment flow; a public certificate alone cannot enroll.

Verification performs no AIA downloads, implicit OS-root trust, or automatic CA
discovery. Revocation checking is not implemented. Root rotation or support for
another Google CA needs a reviewed policy update. This profile intentionally
does not accept every historical or future GCP certificate format.

A Google-issued vTPM identity is not proof of one scarce physical TPM per VM.
The issuance extension is not a fresh proof that a VM is running, and this policy
does not verify a current SEV/TDX attestation report. It accepts eligible Google
instances across projects, not only the experimenter's project. Research using
this profile must state that cloud-resource trust model explicitly.

## Root provenance

Embedded certificate: `contracts/tpmregistry/roots/gcp_ek_ak_ca_root.pem`.
DER SHA-256:
`594759594b9b61524f6c8ef668f7177f7b9066bc0674f2f49fe9e052be78beb2`.

Source: Google's [go-tpm-tools root certificate](https://github.com/google/go-tpm-tools/blob/ce0b546e0e6a7a836e10915c3ffdd67b6f855d1c/server/ca-certs/gcp_ek_ak_ca_root.crt),
pinned at commit `ce0b546e0e6a7a836e10915c3ffdd67b6f855d1c`.
The signed instance identity schema is documented in Google's
[verification implementation](https://github.com/google/go-tpm-tools/blob/ce0b546e0e6a7a836e10915c3ffdd67b6f855d1c/server/verify.go).
Only the public certificate is embedded; no upstream implementation code is copied.

## Verification performed (2026-09-08)

The earlier live, non-mining GCP preflight passed TPM signing, persistent reopen,
Certify, EK/key matching and ActivateCredential including tampered-input rejection.
Its public result is retained unchanged, including its historical
`certificateChainTrusted: false` field: chain validation was not performed
by that probe.

The new offline `TestGCPCapturedEvidence` verifies that captured certificate
and TPM public areas through this policy using the actual intermediate and
embedded Google root. The certificate clock is fixed to 2026-09-09 UTC for
reproducibility. A fresh local VRF test key and profile document complete the
static evidence; this is not a recorded on-chain registration.

Negative tests cover missing intermediates, tampering, expiry, wrong/nil roots,
unknown policies, usage/CA mismatches, missing/duplicate/malformed identities,
nonproduction issuance, invalid project numbers and subject mismatches.
Policy digest separation and default/explicit manufacturer compatibility are tested.

Windows-host package and race tests passed. Full Linux CGO-enabled node build,
live end-to-end enrollment and a multi-node consensus run remain separate checks.
No VM was provisioned by this policy change; the previous probe VM was deleted.
