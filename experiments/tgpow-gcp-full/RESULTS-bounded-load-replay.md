# Bounded invalid-admission load and historical replay — 2026-09-08 UTC

Subsequent direct tests are in RESULTS-resumed-campaign.md: open-request duplicate
transactions, valid-verification component repetitions, and216 real expensive-
rejection admissions. Keep those distinct from this earlier early-rejection load.

Six existing GCP vTPM nodes, research12 chain 103994, threshold 6/6. These tests
were resumed by explicit interactive user instruction, not by the read-only heartbeat.

## Load sweep

Each condition has a 40-second quiet lead-in, then 24 invalid registration starts
at the configured rate. The source waits for all request slot windows to end.
All three conditions terminated with exit 0 and 24 submissions, 24 successful
begin receipts, 24 zero-challenge/zero-approval/inactive verdicts. Total: 72 requests.

| Requests/s | Control seconds / blocks | Observed load seconds / blocks | Node 6 load CPU cores averaged | Node 6 peak memory MiB |
| --- | --- | --- | --- | --- |
| 1 | 38 / 11 | 74 / 18 | 0.239 | 146.68 |
| 4 | 39 / 9 | 112 / 16 | 0.167 | 156.07 |
| 8 | 39 / 7 | 67 / 16 | 0.370 | 160.91 |

These are sampled client-cgroup counters from node 6, not total network CPU or
energy. The load interval includes post-submission observation, not sustained
arrival at that rate for the entire interval. No saturation knee was established.
The workload fails static evidence checks; it is NOT valid TPM verification load.
Sequential receipt observation is NOT service time or trustworthy p95 latency.
No claim of throughput superiority follows from different block counts/intervals.

Archives in ignored artifacts/tgpow-gcp-full; remote/local SHA-256 matched:

- bounded-load-1.tgz: 6b4f5913c552b3d909bbe7dafd09e0bc67fa3d0f1ee84329b43719b29134a76c
- bounded-load-4.tgz: ff43b9caefd58d99bea006e009dd0c00e13b527b076b8fa3faddef88aeed1719
- bounded-load-8.tgz: 218f5caf0bc2cfca63befb1f93c5aefb98bd5b3e861c3af4b45a362f03acd63c

Reproduce analysis by extracting archives into load-audit and running
`experiments/tgpow-gcp-full/summarize-load.ps1`. No live injection is performed by
the analysis script. Load1 resource order was independently checked; later files
include property names.

## Historical duplicate calldata

Original calldata was signed into a fresh-nonce transaction by its original sender.
This avoids confusing transaction-pool duplicate rejection with contract execution.

- Node6 response replay, height1135, status0:
  0x2ed0cfd29025a0fb3b42d0ea01fc898a044c350b7935c717cc59e55522ed4893
- Node1 approval replay, height1155, status0:
  0x4a33a1371d7e0b7f41529f5854df522f22db1d551890ce49a527b6be8adee3a9

Both request approval records were unchanged at 6/6. Read-only execution gave
`TPMRegistry: request closed`. This is closed-request replay coverage, NOT active
window duplicate response/approval, wrong-request, or orphan-branch evidence reuse.
Node6's first combined tool run failed after the response case because it owned
no historical approval transaction. That missing fixture is retained as a harness
failure, not a successful approval test; node1 subsequently supplied the approval.
Logs are included in n1/n6-frozen-research12.tgz public backups.

## Transition

All six research12 client DBs cleanly stopped and archived as new files; each
downloaded hash matched. Original DBs and local secrets remain on their own VMs.
Fresh p256 measured client started with three genesis miners at14:19:38–40;
three late integrated enrollments started14:20:20–21 after block1 was observed.
No completed p256/p128/p64 or partition result yet at this writing.
