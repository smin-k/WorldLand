# TGPoW TPM-bound consensus identity registry

The preferred protocol is now the dynamic `t`-of-`n` block-producer slot path
implemented by `beginProducerRegistration`, `publishProducerChallenge`,
`submitProducerResponse`, `approveProducerSlot`, and
`finalizeProducerRegistration`. See `docs/tpm-gated-mining.md` for the flow,
trust boundary, and candidate-block integration constraint.

`cmd/tpmproducer` and the miner's private enrollment queue implement automatic
challenge publication and producer approval. `cmd/tpmenroll -action
register-producer` implements automatic activation, Certify response,
threshold waiting, and finalization. The private miner RPC is intended only for
a trusted local/admin endpoint.

The older epoch-validator flow documented below remains implemented for
backward compatibility. ABI/storage identifiers containing `DID` are legacy
names for a chain-scoped TPM-bound consensus identity; they do not implement a
W3C DID method.

`contract/registry.sol` implements the enrollment boundary for TPM-gated VCT.
It is intended for predeployment at
`0x0000000000000000000000000000000000000801` when the TPM-gated fork is
activated.

## Registration flow

Registration uses two on-chain transactions and off-chain TPM verification:

1. The controller computes the canonical device nullifier from the EK Name,
   derives the chain-specific DID, commits to the evidence bundle, and calls
   `beginRegistration`. The contract escrows the fixed collateral and freezes
   the validator epoch, policy digest and block deadline in a request.
2. Each validator independently validates the manufacturer EK certificate,
   performs a fresh `MakeCredential`-`ActivateCredential` exchange to bind the
   AK to that EK, verifies `TPM2_Certify` for the TPM work key, and checks all
   hashes against the evidence commitment. A successful validator signs the
   request's EIP-712 enrollment statement.
3. Before the deadline, the controller calls `finalizeRegistration` with at
   least `threshold` distinct validator signatures. The contract verifies the
   signatures, permanently consumes the nullifier and DID, and writes the
   consensus-visible registration.
4. Anyone may call `activate` after the configured confirmation delay. With a
   zero delay, finalization activates the DID immediately.

Only steps 1 and 3 are controller transactions. `evidenceHash` commits to the
non-interactive certificate and public-area bundle known when the request is
opened. Each validator's later random challenge and response remain private to
that session; the validator approval attests that the fresh exchange succeeded.
This keeps enrollment cost bounded while making the resulting authorization
publicly attributable to a validator quorum.

## Trust and failure model

The threshold is an enrollment trust assumption, not a consequence of PoW or
a 51% boundary. A false enrollment is possible if `threshold` validators sign
without performing the required checks. One uncooperative validator cannot
block enrollment when enough other validators remain available. Epoch-scoped
sets permit validator rotation without invalidating signatures already being
collected for a live request.

`policyDigest` must identify the complete validation policy: accepted root
certificates and profiles, EK Name canonicalization, freshness requirements,
the evidence encoding, and work/VRF key binding rules. Implementations must
reject approvals made under a different digest.

The nullifier is consumed permanently, including after revocation. This is the
one-TPM/one-consensus-DID rule. It does not prevent a platform owner from
changing EPS and obtaining a genuinely new manufacturer-recognized identity;
the validator policy must reject uncertified replacement EKs or require a
manufacturer migration record linking them to the already-consumed device.

## Consensus-critical storage

WorldLand reads `registrations` directly from parent state in
`consensus/VCT/tpm_registry.go`. The mapping must remain at slot 0 and the
`Registration` fields must retain their current order. Slots 0 through 4 have
also been retained from the first registrar-based prototype so an upgrade does
not reinterpret existing state.

Genesis allocation installs runtime bytecode, so the Solidity constructor does
not execute. `cmd/tpmregistrygenesis` writes the embedded runtime and the exact
constructor-equivalent storage. Existing chains use the consensus
`tpmRegistryBlock` migration; it must precede `tpmGatedBlock` so registrations
can be finalized before TPM-gated mining begins.

An existing-chain configuration has the following shape (addresses and values
are examples only):

```json
{
  "tpmRegistryBlock": 100000,
  "tpmRegistry": {
    "address": "0x0000000000000000000000000000000000000801",
    "fixedCollateral": 1000000000000000000,
    "governor": "0x0000000000000000000000000000000000001001",
    "registrationTTL": 90,
    "activationDelay": 6,
    "validators": [
      "0x0000000000000000000000000000000000002001",
      "0x0000000000000000000000000000000000002002"
    ],
    "threshold": 2,
    "policyDigest": "0x<64-hex-digit-policy-digest>"
  },
  "tpmGatedBlock": 101000
}
```

All nodes must use the same values. Invalid thresholds, duplicate or zero
validators, missing policy fields, and a migration that does not precede the
TPM-gated fork are rejected during chain configuration validation.

Regenerate the pinned ABI, runtime and storage-layout artifacts with:

```powershell
go generate ./contracts/tpmregistry
```

Pinning 0.8.17 avoids Shanghai's `PUSH0`, which is not available under every
WorldLand fork configuration. The Go helpers in this directory mirror DID,
request, EIP-712 statement and signer recovery calculations.

## Operational commands

Compute the policy digest before creating the chain configuration:

```powershell
go run ./cmd/tpmvalidator -print-policy-digest `
  -ek-root manufacturer-root.pem `
  -profile-hash 0x<keccak256-profile>
```

Create a new genesis file without overwriting its input:

```powershell
go run ./cmd/tpmregistrygenesis -in genesis.json -out genesis-tpm.json `
  -governor 0x<governor> -collateral 1000000000000000000 `
  -registration-ttl 90 -activation-delay 6 -threshold 2 `
  -policy-digest 0x<digest> `
  -validator 0x<validator-1> -validator 0x<validator-2>
```

Start each validator with its own signing key and TLS endpoint:

```powershell
go run ./cmd/tpmvalidator -chain-id 10399 -rpc http://127.0.0.1:8545 `
  -signing-key validator.key -ek-root manufacturer-root.pem `
  -profile-hash 0x<profile-hash> -tls-cert validator.pem -tls-key validator-key.pem
```

The controller performs the full two-transaction enrollment with:

```powershell
go run ./cmd/tpmenroll -action register -chain-id 10399 `
  -controller-key controller.key -vrf-public-key vrf.pub -profile profile.json `
  -work-key WorldLand-TPM-Work -attestation-key WorldLand-TPM-AIK -create `
  -validator https://validator-1:8741 -validator https://validator-2:8741
```

Failed requests can be refunded after their deadline with
`-action cancel -request-id 0x...`. Delayed DIDs can be enabled with
`-action activate -did 0x...`, or registration can use `-wait-activation`.
