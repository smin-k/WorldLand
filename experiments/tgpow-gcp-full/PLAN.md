# Real-vTPM ten-node experiment: first campaign

Authorization: ten independent GCP vTPM nodes, paid usage permitted, maximum
24 hours of VM execution. No automatic paid-account conversion, extra projects,
or quota circumvention. Do not start the VM clock until prerequisites pass.
Use an absolute provider-side DELETE deadline for all VMs and auto-delete disks.
Preserve results before deletion. Do not extend without user approval.

## Prerequisites

- CPUS_ALL_REGIONS >=20; us-central1 N2D_CPUS >=20; regional external IPs >=10.
- Read effective quotas; a pending preference is not granted capacity.
- Pin source commit, binary hashes, genesis hash, configuration and clock source.
- Ten VMs, each n2d-standard-2 with its own TPM. Five bootstrap and five late.
- IAP-only management, subnet-only P2P, loopback privileged RPC, read-only explorer.
- Validate each fresh EK certificate and TPM key binding; never reuse old VM identities.
- Offline regression tests are a prerequisite, not substitutes for live experiments.

## Conditions and acceptance criteria

Run separately named fresh chains per condition; preserve all evidence, including failures.
Initial/minimum difficulty 4096; seed delay 1; activation delay 6; six producer
slots, threshold six. Set producer challenge capacity >=5 for five concurrent requests
and check measured gas consumption. Keep EK policy and cryptographic checks unchanged.

1. Normal registration: five late identities independently complete challenge,
   ActivateCredential, Certify, all six canonical-slot approvals, finalization,
   activation delay, and at least one accepted block from every late identity.
   Require all nodes to agree on a common finalized observation height/state root.
2. Missing approval: deliberately withhold one designated slot approval. The request
   must not finalize; record expiry and a fresh-request retry. Do not count timeout as pass
   unless the on-chain rejection/expiry and eventual retry outcome are observed.
3. Eligibility: separate initial thresholds 256,128,64 (100%,50%,25%). Record actual
   per-header adaptive threshold, eligibility outcomes, timeout stages, attempts, blocks,
   stale blocks and wall-clock intervals. These are not fixed-probability runs unless
   a separately reviewed consensus variant disables adaptation; do not silently do so.
4. Invalid registration: individually test duplicate identity, corrupted certificate,
   altered key attributes/Certify signature, wrong challenge, wrong request, wrong chain
   and duplicate response/approval. Observe explicit rejection and unchanged registry.
5. Recovery/reorg: process restart, bounded subnet partition and recovery. Record both
   branch hashes and which challenge/response/approval left the canonical chain. Require
   canonical-state convergence; a partition without an actual reorg does not test reorg.
6. Bounded load: step registration/candidate arrival rates, with a hard request/time cap.
   Measure verification service time, queue wait, p50/p95/p99, throughput, CPU/memory,
   head propagation and error counts. Stop the load source on sustained saturation;
   retain the failed point. No traffic outside the dedicated experiment subnet.

Repeat completed conditions with independent seeds/runs when the 24-hour window permits.
Report unfinished conditions as NOT RUN, not passes. Retain a no-injection control.
Record all producer queue head-race errors and subsequent successful polling/recovery.

## Claims excluded

Physical TPM scarcity/anti-cloning, measured wall-plug energy savings and universal
adversarial security are not established by this cloud experiment. Resource consumption
is not electrical energy. GCP EK trust profile remains explicit.

## Current infrastructure status

No campaign VM exists. Quota preferences requested for global CPUs 20, regional N2D
CPUs 20 and regional in-use addresses 10. Effective grant must be checked before launch.
The earlier five-node baseline and its real identities are archived and terminated.

GCP subsequently returned `Quota request denied` for all three preferences:
`wl-research-global-cpu20` (grant 12), `wl-research-n2d-cpu20` (grant 16),
and `wl-research-ip10` (grant 8). No reason beyond denial was returned. The campaign
is blocked on external quota approval; do not resubmit duplicates or split projects
to evade the limit. No VM was created, and paid-account conversion was not attempted.

Preflight regression command passed on the Windows host on 2026-09-08:
`go test ./params ./contracts/tpmregistry/... ./crypto/tpmwork ./cmd/tpmenroll ./cmd/tpmproducer ./consensus/VCT ./miner -count=1 -timeout 3m`.
This is software regression evidence only. Live ten-node conditions above are NOT RUN.
