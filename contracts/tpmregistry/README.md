# TPM DID registry prototype

The contract at `contract/registry.sol` specifies the parent-state layout read
by `consensus/VCT/tpm_registry.go`. It is intended for predeployment at
`0x0000000000000000000000000000000000000801` when the TPM-gated fork is
activated.

This first implementation deliberately exposes the registrar as a trust
boundary. The registrar validates EK/AK manufacturer evidence, work-key
certification and the canonical device nullifier off chain. Moving certificate
verification on chain or replacing the registrar with threshold governance is
separate work.

The client now implements nonce-bound work-key certification in
`crypto/tpmwork`: a restricted AIK signs `TPM2_Certify` evidence and
`VerifyKeyCertification` checks the public areas, TPM Name, challenge and AIK
signature. This closes the AIK-to-work-key link. EK certificate validation and
credential activation are still registrar responsibilities and must be
completed before the registrar signs a production `register` authorization.

The fixed collateral is not a VRF weight. Every active registration receives
one VRF trial; the collateral only raises registration and misbehavior cost.
