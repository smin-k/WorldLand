# Fresh-chain repetitions (2026-09-09 UTC)

Same six GCP vTPM identities/VMs,3bootstrap+3late,6/6slots,difficulty4096,
normal measured binary3d37b7b17bc5d27a84fe7dcaf038353611acf0cb3cddfab35ebeee8cfa85089e.
Fresh datadir for each execution, old public DBs retained and downloaded. These
are repeated executions on the same devices, not independent device samples.
Initial thresholds adapt afterwards. R2/R3 performance snapshots fix heights1..64
(63intervals after excluding genesis-to-first). Registry events are separately
collected through observed-head.json, which may be later than64.
The actual client has progressive eligibility relaxation at effective70..100s;
EffectiveDeltaT subtracts5s from raw parent/header time difference (vct_secp256k1.go).
This is another reason these are not fixed-q trials. In p64-r2, long gaps around
height17 were observed while all3late requests already had6/6approval; the chain
subsequently advanced without changing parameters. Quantify gaps from final
captured headers, not from coarse observer polling alone.

| Phase | Headers | Mean interval s | Max s | Base range | Producers | Late finalized | Hash/root64 all6 |
| --- | ---: | ---: | ---: | --- | ---: | ---: | --- |
| p256-r2 | 64 | 4.301587 | 25 | 0.954234..1 | 6 | 3 | yes |
| p128-r2 | 64 | 3.920635 | 20 | 0.5..1 | 6 | 3 | yes |
| p64-r2 | 64 | 16.126984 | 96 | 0.25..0.536612 | 6 | 3 | yes |
| p256-r3 | 64 | 4.285714 | 26 | 0.954234..1 | 6 | 3 | yes |
| p128-r3 | 64 | 3.650794 | 15 | 0.5..1 | 6 | 3 | yes |
| p64-r3 | 64 | 11.158730 | 101 | 0.25..0.512952 | 6 | 3 | yes |

p256-r2 hash64 ff23abc773df3735e4cda15940c01b56daa26caa6fcd163617a12b666bf96393,
root64 99d3c7fb313ef80e44dc2c5cc3fab37f9cd62b5a20e002e8995fccd4937cf7c4.
All6 observed-head78. Node4/5 requests slots9..14, node6 slots10..15; all six
challenges/responses/approvals and finalized in copied logs. Node4/5/6 each won
four of the first64blocks. audit-repeat-phase.ps1 validates header parent links,
counts, all6slot events and common hash/root; summarize-phase.ps1 derives timing.

Archive hashes n1..n6 p256-r2-fixed64:
7ad15346b5a2553dc55f0cefce1fdb4e724424ffd92b5d96a6cc9c4319f30313,
70dd83449b1e307f633138308fe2665d3af4bca98e1975a9e8433fe88a4b69b5,
81ede16b8bfb321d06f656be576f90281b3265d99cca47e4ded32876c697f5c6,
a59488546c5f1e9fa8143dd9e0711d175a159f96a71bd6794d118c0d9d1e6128,
2f702173a80b5cd5491f32c783f184b8d4a570c97b4a7f09bb2c888467b9bf87,
3997bc14c0c8c6145054680c9b9500d7f8bfbeaec9e3fe3e2149c9f14847cd93.
All match the remote collector hashes. Frozen attack DB hashes checked as well.

Harness incident: first orchestrator exited when normal init stderr was treated
as an error by the PowerShell parallel pipeline. Read-only audit found all6new
services already correctly installed, not mining. Resumed without reinitializing
or deleting data. init stderr now merged to stdout in install-phase.sh. Two
management-API upload timeouts were retried; they did not alter running nodes.

p128-r2 hash64 0be7a61e30cd48a96bf4135d40abed680b34033dd9d686f585cfccd2e6b98593,
root64 1dc55dc20722266239379e41f1c476139c08b08c54933daae15d4d72364ca4a1.
All6 observed-head75. All six copied snapshot hashes match collector output;
previous p256-r2 clean public DB backups also downloaded and hash checked.

p64-r2 hash64 20050fcdc05984014d5787ab619748248d5cf94e60012b929104762858149f57,
root64 2e9eb81e90b05ce0fc7f0c832539dbcdf9ceaec4c2a7619e4bd68337c3b449a1.
All6 observed-head70. All three late requests completed all6slots; all6identities
produced accepted blocks within the fixed64window. Local snapshot hashes matched
the remote collector output, as did all6clean frozen p128-r2 DB archives.

p256-r3 hash64 eb5eaecb0e36324dac9519c32663051a7f7b98f5e60c02d72829ace8ee8a60c2,
root64 726509d4f27bca44ae51cd5aa8080b048a906639a0d6f3f068472aec6d37e794.
All6 observed-head69. The orchestrator verified both the six fixed64archive
hashes and six preceding frozen p64-r2 archive hashes against the remote output.

p128-r3 hash64 db2e0ee57e444968fcf4ffd56745c7e828daaae72d18709e01c10ff32165bacd,
root64 885ff5a4a222435f697f619eb0512c26906e7c2b6c74af5096fe70c6132719a3.
All6 observed-head78. The six fixed64archives and six preceding frozen p256-r3
archives matched remote digests. All late requests have6unique events of each
kind within their exact slot intervals; the audit rejects extra/out-of-range events.

Registration timing from summarize-registration-wait.ps1 (three concurrent
requests, correlated; canonical begin inclusion to activation-height header time,
NOT submission wall-clock latency):

| Phase | Begin-to-activation blocks, min..max | Header seconds, min..max |
| --- | ---: | ---: |
| p256-r2 | 25..26 | 142..143 |
| p128-r2 | 23 | 137 |
| p64-r2 | 20..21 | 563..579 |
| p256-r3 | 24 | 156 |
| p128-r3 | 29 | 131 |
| p64-r3 | 23 | 356 |

p64-r3 hash64 11e57da1d5449bbde14fc0232c7078707856a6fc7d0d6fe12bbcf579bae6971f,
root64 0200cb7f34dfe689125b3d2e2696355bf6e3399cd0f475513074f36b7de8c483.
All6 observed-head72. All six fixed64archives and preceding frozen p128-r3 DBs
downloaded and matched remote digests. Final requests begin2, finalize19,
activation25, all3complete6/6. All6identities won within64headers.

All six additional repetitions are complete and audited. Together with the
three original R1 chains, nine executions have27/27successful late registrations.
R2/R3 each have3/3late successes and all6accepted producers in64headers, with
identical hash/root64 across all6nodes. The three R1 windows are shorter/unequal;
do not pool all nine as equal steady-state observations.
No claim of causal energy or
fixed-probability steady-state throughput from these short adaptive episodes.
