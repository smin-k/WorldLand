# Direct resumed campaign — 2026-09-09 UTC

The human explicitly requested execution of all remaining tests. This direct
interactive campaign is distinct from the paused, read-only heartbeat. Existing
six VMs only; provider DELETE 2026-09-09 10:50 UTC unchanged. No chain deletion,
new VM, private-key export or remote git push.

## Active-window duplicate response and approval: actual transactions

Late3 restarted with outbound first-slot faults retained; public pre-restart
logs/events preserved in resume-open-replay-r1.tgz on each late node.
For request
`0x91c8233b107aa5ba97e3e7e303cb840a7af06b2d189f661e48276da41b0d3d64`,
slots5401..5406, deadline5466, threshold6:

- Response tx `0xc85b5f6a985222b83cef246f5f37132dcfdaf59d0150659fbb70615bed4670c3`.
- Approval tx `0x4ce72e64f7a666c05d221a098c9fb0e7567a023ad99fb07c1a27bc609cea6749`.

Both included at block5415 with receipt status0. Request remained unfinalized;
approval state before/after both5. This is before deadline, not closed-request
coverage. Read-only probes separately report `invalid slot response` and `slot
not approvable`. Fresh nonce and identical prior successful call data used.

Harness failure: node6 watcher started before its client restart and exited on
RPC connection refusal without submitting a replay. Retested after RPC was ready
under worldland-open-replay-6-rpc-ready; both successful experiment units exit0.

## Recovery status

UPDATE: recovery completed. Following expiry, all late clients restarted again
at04:34:56 UTC. All three new requests slots5485..5490/deadline5550 completed6/6,
finalized and activated. Live audit at5582 confirms it. Canonical heights5503..5582
contain node4/5/6 blocks9/10/14 respectively; all six identities produced blocks.
The copied128-header snapshot has consistent parent links. Evidence archive
n1-normal-recovery.tgz SHA256
687175a5b3f4dbb7ab35dcf2a6d6dc6cfe5dfa0e70a015e70af2189cb3372778.
This is manual restart recovery, not automatic retry after expiry.

Historical intermediate state at04:26 UTC: first-slot fault markers on nodes4..6 renamed to unique disabled
files, services restarted, public snapshots preserved in
resume-normal-recovery-r1.tgz. At head5443/5444 the previous requests were still
open, so enrollment resumed them rather than creating fresh requests. Recovery
was not complete at that point; the later restart after deadline5466 completed
recovery as recorded above. The marker rename alone did not restore six miners.

## Valid verification load: completed

UPDATE: all24 runs completed at04:44:06 UTC, service exit0, all verification
failure counts0. Archive valid-verifier-load-r1.tgz remote/local SHA256 both
8aaabfddc0387b5f4ba6609593d291722b74a106621af9dde3bde3702d2e0cdc.

| Component | Workers | Repeats | Mean ops/s | Mean of per-run p95 ms |
| --- | ---: | ---: | ---: | ---: |
| Admission static evidence | 1 | 3 | 1215.23 | 1.30 |
| Admission static evidence | 2 | 3 | 1230.73 | 3.64 |
| Admission static evidence | 4 | 3 | 1172.34 | 14.89 |
| Admission static evidence | 8 | 3 | 1081.23 | 41.47 |
| Slot response | 1 | 3 | 21212.49 | 0.07 |
| Slot response | 2 | 3 | 22607.21 | 0.09 |
| Slot response | 4 | 3 | 23600.84 | 0.09 |
| Slot response | 8 | 3 | 21351.59 | 0.09 |

These are arithmetic means across three runs, not pooled percentiles. Admission
throughput plateaus while latency rises with workers: component saturation in
this co-hosted bounded configuration, not end-to-end fresh-registration capacity.
Historical preparation/context below remains important for scope.

Node2 worldland-valid-verifier-load: 24 bounded closed-loop measurements,
response/admission verification, workers1/2/4/8, three repeats, 30s each with
16s quiet lead-ins; process GOMAXPROCS2, service MemoryMax2GiB/RuntimeMax2400s.
Real canonical initial evidence and valid TPM Certify responses are used with
their real request/slot commitment domains. Verifier functions are the client's
actual Policy.ValidateEvidence / VerifyProducerResponseEvidence.
Each run reuses15valid slot fixtures from3TPM identities. The8,415,940operations
are repeated verification calls, not independent identities or attack trials.

This is a co-hosted verification-component stress test, NOT a stream of fresh
accepted enrollment transactions or an end-to-end admission queue benchmark.
The first repeat overlaps late-client recovery and must not be presented as a
quiet six-active-node steady state. CPU/memory/client height sampled separately.
Latency samples are capped at the first200000 per worker, so reported quantiles
describe that bounded sample, not necessarily all operations during30seconds.
End-to-end saturation cannot be inferred from the component throughput alone.

Local replay/verify-load packages compile (no automated tests in those command
packages). Windows shared build cache permission errors were resolved by using
a workspace-specific cache, not by suppressing failing tests.

## Actual expensive-admission network load: completed

worldland-expensive-admission ran04:45:01--05:03:22 UTC on node6, service exit0.
The unmodified static TPM evidence passes Policy.ValidateEvidence before any
submission. A fresh funded test controller claims different DID/nullifier values;
the real integrated producers run static crypto checks then reject statement
binding. Producer logs explicitly show `statement mismatch`. These are NOT
legitimate new TPM identities, nor a successful-registration throughput test.

All216 submitted starts (24 per rate1/4/8, three sequential repeats) have actual
receipt status1. All216 verdicts have0challenges/0approvals/inactive. Complete
archive downloaded and verified: expensive-admission-r1.tgz SHA256
c3a3052b6af1058ee35df662e61d09bc067086ad1fc0730d7b41bb0c27283768.
Reproduce analysis with summarize-expensive-admission.ps1; it asserts all counts,
receipt statuses and zero progression.

| Trial | Observed load seconds | Blocks advanced | Node6 client CPU cores | Peak MiB |
| --- | ---: | ---: | ---: | ---: |
| rate1-r1 | 90 | 21 | 0.53 | 159.55 |
| rate4-r1 | 67 | 14 | 0.44 | 174.49 |
| rate8-r1 | 119 | 11 | 0.21 | 181.39 |
| rate1-r2 | 128 | 18 | 0.48 | 186.81 |
| rate4-r2 | 144 | 17 | 0.62 | 189.93 |
| rate8-r2 | 45 | 14 | 0.49 | 197.04 |
| rate1-r3 | 166 | 14 | 0.14 | 210.79 |
| rate4-r3 | 59 | 15 | 0.40 | 223.63 |
| rate8-r3 | 115 | 13 | 0.31 | 223.34 |

Resource windows include submission and waiting for receipts/slot end, not a
sustained injection at the nominal rate. Earlier requests can still be open in
later trials; 16s control is no-new-injection, not an empty pending queue. The
three sequential repeats are not independent fresh-chain trials. Do not infer a
causal rate-vs-throughput curve, leak or full-network saturation knee from this
table. All segments advanced, but this is not proof of uninterrupted liveness.

## Additional fresh-chain eligibility repetitions

At05:04 UTC, launched run-repeat-phase.ps1 Previous=attack Phase=p256-r2 after
all above network workload artifacts were downloaded/checked. First preserves
all6 public attack DBs. All p256/p128/p64-r2/-r3 executions subsequently completed
and passed copied-header, exact six-slot event and all-node hash/root64 audits.
See RESULTS-eligibility-repeats.md for per-run intervals and activation waits.
All18additional late registrations completed; with original R1, total27/27.
The final25%run reached the observation criterion without changing parameters;
its maximum non-genesis header interval was101s (mean11.159s).
