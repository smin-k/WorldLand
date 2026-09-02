# TPM work-key certification prototype

This package separates two questions that are easy to conflate:

1. Did the registered work key exist inside the same TPM as an attestation key?
2. Does that attestation key belong to an accepted, unique physical TPM?

`TPM2_Certify` answers the first question. EK certificate validation and
`TPM2_ActivateCredential` answer the second.

## Implemented path

On Windows, `OpenPlatformSigner` keeps the P-256 work key in the Microsoft
Platform Crypto Provider. `CertifyWorkKey` then:

1. creates or opens a restricted RSA Attestation Identity Key (AIK);
2. obtains the live TPM handles from the Platform Crypto Provider;
3. reads both TPM public areas with `TPM2_ReadPublic`;
4. sends `TPM2_Certify(workKey, AIK, challenge)` through TPM Base Services;
5. verifies the challenge, the work-key TPM Name, both public-key bindings,
   and the AIK's RSA-SHA256 signature.

The returned `KeyCertification` is portable JSON. A registrar can call
`VerifyKeyCertification` without access to the prover's TPM.

The implementation uses TPM Base Services because Windows NCrypt does not
provide a complete one-call certification path for restricted AIKs. Chromium
uses the same Platform Provider plus `TPM2_Certify` design.

## Local experiment

The following command creates the named AIK only when it is missing. It never
clears the TPM or deletes a key:

```powershell
go run .\cmd\tpmworkbench `
  -key WorldLand-TPM-Work-Test `
  -n 1 `
  -certify `
  -aik WorldLand-TPM-AIK-Test `
  -aikcreate
```

The AMD fTPM used for this prototype returned and locally verified:

- a 118-byte work-key `TPMT_PUBLIC`;
- a 312-byte AIK `TPMT_PUBLIC`;
- a 173-byte `TPMS_ATTEST` statement;
- a 262-byte `TPMT_SIGNATURE`.

`-certjson` prints the portable proof. A production enrollment request must
use a fresh unpredictable challenge supplied by the registrar, not the fixed
diagnostic challenge in `tpmworkbench`.

## Credential activation

`EnrollmentIdentity` reads the standard RSA EK, its certificate NV index and
the persisted AIK public area. `ActivateCredential` uses a policy session with
the endorsement hierarchy and executes `TPM2_ActivateCredential` on the same
Platform Provider TBS context that owns the NCrypt AIK handle. The default TCG
Windows locations are:

- RSA EK persistent handle: `0x81010001`
- RSA EK certificate NV index: `0x01c00002`

Both are configurable by the enrollment CLI. The validator-side credential
creation, certificate-chain policy and canonical device nullifier are
implemented in `contracts/tpmregistry`. Certificate revocation feeds and
vendor root/profile selection remain deployment policy rather than TPM backend
logic.
