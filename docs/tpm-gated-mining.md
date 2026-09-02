# TGPoW: TPM-Gated Proof of Work with Verifiable Coin Tosses

TGPoW binds both consensus identity and work-input generation to one TPM trust
root. WorldLand uses ECCPoW as its reference work puzzle: a VRF selects an
eligible round, a non-exportable P-256 TPM work key signs the round context,
and the signature-derived value becomes the ECCPoW input. Any independent
search nonce or puzzle parameter must be included in that TPM-signed context;
otherwise a miner could grind many work inputs behind one eligible VRF result.

The Solidity ABI and block header retain names such as `did`, `TPMDID`, and
`deriveDID` for storage and wire compatibility. They mean a chain-scoped
TPM-bound consensus identity, not a W3C DID document or DID method. New Go code
uses `DeriveConsensusIdentity`; `DeriveDID` is a compatibility alias.

## Components

- `crypto/tpmwork`: TPM signing, MakeCredential/ActivateCredential, and
  TPM2_Certify support.
- `consensus/VCT`: the WorldLand ECCPoW instantiation of TGPoW.
- `contracts/tpmregistry`: registry contract, dynamic producer-slot hashes,
  Go client, evidence validation, and consensus-visible storage layout.
- `cmd/tpmworkbench`: local TPM signing-throughput benchmark.
- `cmd/tpmdelegatebench`: actual TPM-to-HTTP-worker ECCVCC pipeline benchmark.
- `cmd/networkexperiment`: fixed-seed partially synchronous mother-tree emulator.
- `cmd/tpmregistrygenesis`: registry predeploy generator, including dynamic
  producer committee parameters.

The delegated benchmark opens an existing non-exportable key and never creates
or deletes TPM objects:

```powershell
go run .\cmd\tpmdelegatebench `
  -key WorldLand-TPM-Work-Test -n 300 -workers 4 -worker-delay 20ms
```

Each HTTP worker verifies the canonical TPM signature and invokes the same
ECCVCC decoder and decision code as the local VCT miner. Increasing workers
can drain the bounded signed-input queue faster, but cannot create another
canonical input without another completed TPM signature.

## Dynamic t-of-n producer-slot enrollment

The preferred registration path reuses the next `n` block-production slots as
a hashpower-weighted committee. It does not claim that the slots are `n`
independent people.

```text
controller             slot producer P_j                 registry
    | beginProducerRegistration(E)                           |
    |------------------------------------------------------->|
    |                    MakeCredential(EK, AK, z_j)          |
    |                    pre-mine challenge transaction      |
    |                    publish(B_j,S_j,c_j,sig_Pj)          |
    |<-------------------------------------------------------|
    | ActivateCredential -> z_j                              |
    | TPM2_Certify -> evidence_j                             |
    | submitResponse(z_j,H(evidence_j))                      |
    |------------------------------------------------------->| verify c_j
    |                    verify evidence_j off chain          |
    |                    approveSlot(sig_Pj)                  |
    |<-------------------------------------------------------|
    | finalizeProducerRegistration after t approved slots    |
    |------------------------------------------------------->|
```

The canonical public enrollment evidence is supplied as calldata and emitted
with the request after the contract checks its hash. Producers therefore have
the EK/AK material required by MakeCredential. For slot `j`, the contract
stores the block producer, MakeCredential material hash, commitment, response
evidence hash, and approval flags. The full credential blob and encrypted
secret are emitted in the canonical-chain event log. The commitment binds the
chain ID, registry, request statement,
exact block slot, producer, credential material, and secret:

```text
c_j = H(domain || chainId || registry || requestId || H(E) ||
        slot_j || P_j || H(B_j,S_j) || z_j)
```

The producer signs the challenge payload, and the contract requires the
recovered signer to equal that block's `block.coinbase`. This makes a relayed
transaction possible while preventing a non-producer from filling the slot.
After the controller reveals `z_j`, the contract recomputes `c_j` directly.
The producer then signs a second digest binding the request, slot, commitment,
`H(evidence_j)`, consensus identity, and deadline. Registration succeeds once
at least `t` unique slots are approved. A single producer may own multiple
slots, exactly as implied by hashpower weighting.

`z_j` consistency is trustless. Correct interpretation of manufacturer EK
certificates and TPM2_Certify evidence remains an off-chain producer decision.
Therefore bribable/compromised producer slots are a separate threat variable;
they are not automatically equivalent to a 51% reorganization attack.

## Candidate-block integration constraint

A producer cannot append a challenge transaction after finding PoW because
that would change the transaction root and invalidate the block. It must:

1. observe active requests for its target height;
2. create MakeCredential material and sign the challenge before searching;
3. insert that transaction into its candidate block template; and
4. mine the resulting template.

This integration is implemented with a private miner queue. The
`miner_submitEnrollmentTransaction` RPC accepts only a transaction signed by
the configured coinbase, addressed to the registry, calling either
`publishProducerChallenge` or `approveProducerSlot`, and targeting exactly the
next canonical height. It never enters or gossips through the public txpool.
Staging a transaction immediately discards the old candidate template, and
the worker executes private enrollment transactions before public-pool
transactions. If another producer wins the height, the stale private entries
are discarded and the agent builds new transactions for the next slot.

`cmd/tpmproducer` performs the producer workflow: it discovers request events,
validates the manufacturer/TPM evidence under its local policy, constructs
MakeCredential and commitments, stages private challenges, verifies disclosed
TPM2_Certify responses, and stages producer approvals. `cmd/tpmenroll
-action register-producer` performs the controller workflow: it publishes the
canonical evidence, watches canonical challenge events, runs
ActivateCredential and TPM2_Certify, submits responses, waits for `t`
approvals, finalizes, and optionally activates the identity.

The producer coinbase account must have no ordinary pending transactions while
the agent allocates private nonces. The agent refuses to stage work otherwise.
The private `miner` RPC must only be exposed on a trusted local/admin endpoint.
The older epoch-validator path remains available as a deployment fallback.

## Registry configuration

The predeploy keeps consensus-critical legacy storage slots 0--4 unchanged.
Dynamic settings are appended at slots 15--16:

- `producerSlotCount` (`n`)
- `producerThreshold` (`t`)
- `producerSlotDelay`
- `producerResponseWindow`
- `producerPolicyDigest`

Example genesis flags:

```text
go run ./cmd/tpmregistrygenesis \
  -in genesis.json -out genesis-tgpow.json \
  -governor 0x... -registration-ttl 90 \
  -producer-slots 6 -producer-threshold 4 \
  -producer-slot-delay 2 -producer-response-window 12 \
  -producer-policy-digest 0x...
```

Legacy validator fields are optional. A deployment may enable the dynamic
producer path alone, the legacy epoch-validator fallback alone, or both.
The controller can publish the canonical evidence bundle and open a dynamic
request with:

```text
go run ./cmd/tpmenroll -action register-producer \
  -rpc http://127.0.0.1:8545 -chain-id 103 \
  -controller-key controller.key -vrf-public-key vrf.pub \
  -profile profile.bin -wait-activation
```

Each mining node runs its producer agent against a local RPC endpoint with the
private `miner` namespace enabled:

```text
go run ./cmd/tpmproducer \
  -rpc http://127.0.0.1:8545 -chain-id 103 \
  -producer-key coinbase.key -ek-root root.pem \
  -profile-hash 0x...
```

The producer key must match `eth_coinbase`. Use a dedicated local RPC listener;
do not expose `miner_submitEnrollmentTransaction` publicly.

## Mining and TPM performance

Start the ECCPoW reference miner with the registered identity and TPM key:

```text
worldland --mine --unlock <coinbase> \
  --miner.tpmkey WorldLand-TPM-Work-Test \
  --miner.tpmdid 0x<32-byte-consensus-identity>
```

The header flag remains `--miner.tpmdid` for CLI compatibility. A local AMD
fTPM 2.0 (`3.56.0.5`) measurement on 2026-08-14 produced 200 sequential P-256
signatures at 72.133 signatures/s, with p50 13.8308 ms, p95 14.5962 ms, and
p99 15.1082 ms. This is an engineering datapoint, not a protocol constant;
Intel PTT, discrete TPMs, concurrent handles, and dictionary-lockout behavior
require separate measurements.
