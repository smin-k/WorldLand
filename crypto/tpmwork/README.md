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

## Remaining enrollment boundary

Successful `VerifyKeyCertification` proves that the work key and AIK were
co-resident in one TPM at certification time. It does not make an arbitrary
AIK trustworthy. The registrar must additionally:

1. validate an EK certificate against an accepted manufacturer root and
   revocation policy;
2. run credential activation so that the AIK is proven to reside with that EK;
3. derive one canonical device nullifier from the accepted EK and reject a
   previously used nullifier;
4. authorize the work-key hash, VRF-key hash and controller for the registry
   contract.

The tested AIK exposes an 834-byte `PCP_TPM12_IDBINDING` blob, so the Windows
side provides the material needed for the next enrollment stage. Parsing that
provider-specific blob, certificate-chain policy and credential activation are
not yet implemented. Until they are, this is a work-key certification
prototype, not a complete proof of `1 physical TPM = 1 DID`.
