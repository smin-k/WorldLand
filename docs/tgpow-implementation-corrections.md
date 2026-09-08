# TGPoW implementation corrections (2026-09-07)

This change implements the existing paper's protocol invariants; it does not
change the paper to accommodate client bugs. The source of the protocol is
`hardware-bound-coin-toss-paper/sections/{system-model,methodology}.tex`.

| Paper rule | Implementation correction | Regression evidence |
| --- | --- | --- |
| `eq:canonical-device-nullifier`: fixed EK profile and `Name(EK_can)` | Authenticate the EK certificate/key, require one fixed RSA-2048 public template, normalize equivalent exponent encodings, and derive the canonical Name. Reject altered policy/attributes. | `contracts/tpmregistry/evidence_test.go`, `canonical_keys_test.go` |
| One committed VRF key per identity | Hash the canonical compressed secp256k1 key for both 33- and 65-byte enrollment inputs. Require the CLI controller key to match the mining key. | Canonical-key tests; controller CLI tests; dynamic-registration/VCT integration |
| Only canonical registration slots count; orphaned responses are invalid | Recover private queue reservations from the exact parent hash, make identical submissions idempotent, and recheck canonical challenge/commitment before and after TPM calls. | Producer restart/lost-ACK/reorg tests; miner queue reorg tests; controller response replacement tests |
| `eq:first-eligible-height`: activation delay is at least seed delay; use parent state | Reject inconsistent migration/genesis settings before allocation changes. Keep activation idempotent at the controller. | `params/tpm_activation_delay_test.go`; genesis tests; 3-of-3 registration/activation integration |
| Branch-local delayed seed and chain-separated round input | Resolve prior headers from the incoming batch by exact hash and height. Bind fresh verifier engines to a copied chain ID before VRF checks; reject cross-chain engine reuse. | `consensus/VCT/batch_headers_test.go` |
| `eq:objective-timeout-stage`, `eq:tpm-work-signature`: timestamp and executed template are committed | Select timestamp, threshold, difficulty and identity fields before EVM execution. Seal waits asynchronously without changing the executed template. Match returned blocks only by exact seal hash and validate state/receipts before local persistence. | `miner/vct_template_test.go`, `enrollment_queue_test.go` |

## What the integration tests establish

`TestVCTTimeoutTemplateExecutesBeforeSealAndImports` uses the real VCT engine
behind the client's beacon wrapper, real VRF and P-256 cryptography, real
ECCPoW sealing, the miner worker and EVM, and an independent chain database.
A transaction stores `TIMESTAMP` and `DIFFICULTY`; the independent receiver
must reconstruct the same state. A competing empty template must not be chosen
for the transaction-bearing block. Future work must return promptly and remain
cancellable.

`producer_vct_integration_test.go` executes the actual registry bytecode through
three producer slots, rejects an incomplete quorum and premature activation,
and checks the production VCT parent-state gate before and after activation.
It also checks the controller/key binding and delayed VRF proof context.

These are client integration tests, **not physical-TPM or network experiments**.
The miner test uses a software P-256 fixture and temporarily lowers the test
process's ECCPoW difficulty floor to the existing Seoul minimum (1023).
The registration test uses fake PoW to advance its transaction chain and signed
approval fixtures, not a real manufacturer/TPM enrollment transcript. Production
difficulty, timeout defaults and signature backend selection are unchanged.

## Compatibility and deployment

- Enrollment policy digests now commit to the canonicalization rule revision.
  For the planned demo, generate a **fresh genesis and registry**. Updating a
  policy digest does not repair old registry entries or merge old nullifiers.
  No accept-old-nullifiers fallback or automatic state rewrite is provided.
- The supported EK profile is the fixed RSA-2048/SHA-256/AES-128-CFB profile
  documented in `contracts/tpmregistry/README.md`. Other vendor profiles require
  explicit specification and validation; they must not be accepted by relaxing
  the template checks.
- `miner_submitEnrollmentTransaction(target, raw, parentHash)` adds an optional
  parent-hash argument. The updated agent always sends it. The new private
  `miner_enrollmentQueue(target, parentHash)` returns queued raw transactions so
  an agent can recover after a lost reply or restart. Keep miner RPC local/admin.
- The default producer challenge cap remains four per block. Five simultaneous
  requests with `n=t` need a cap of at least five **and sufficient block gas**,
  or staggered request windows. The agent logs capacity exhaustion rather than
  reporting those requests as successfully handled.
- Linux platform TPM support and AWS NitroTPM EK-certificate compatibility are
  not implemented/established by these corrections. No AWS resources are created.
- Per the user's instruction, the TPM ten-node run and any AWS provisioning
  require a separate discussion after these tests. They are not automatic next
  steps of this correction work.

## Verification commands

```text
go test ./consensus/... ./core/... ./miner ./eth/... ./contracts/tpmregistry/... ./crypto/tpmwork ./params ./cmd/tpmenroll ./cmd/tpmproducer ./cmd/tpmregistrygenesis ./cmd/tgpowtestnetgenesis -count=1 -timeout 3m
go test ./... -run '^$' -timeout 3m
```

The second command compiles the whole repository and its tests; it deliberately
does not execute unrelated test suites. Protocol tests require CGO.

## Recorded outcome

All listed test packages passed. The first broad run overlapped an in-progress
test-file edit and reported a VCT syntax error; after that edit was completed,
the full VCT package was rerun successfully (22.577 s). The other broad-run
packages, including core, downloader, miner and registration, passed.
The complete repository compile-only command finished with exit code zero.

The selected concurrency regressions also passed:

```text
go test -race ./miner ./consensus/VCT -run 'Test(VCTTimeout|EnrollmentQueue|SealingResult|VCTChainContextConcurrent)' -count=1 -timeout 2m
```

Both race-tested packages passed (miner 7.552 s; VCT 1.477 s), and `git diff
--check` plus the touched Go files' formatting checks were clean. Changes are
left in the working tree for review; no commit or deployment was performed.
