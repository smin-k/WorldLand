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

The fixed collateral is not a VRF weight. Every active registration receives
one VRF trial; the collateral only raises registration and misbehavior cost.

