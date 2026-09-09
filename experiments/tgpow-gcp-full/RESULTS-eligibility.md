# Initial eligibility sweep — actual six-node GCP vTPM runs

Additional fresh-chain repetitions with fixed64-header windows are recorded in
RESULTS-eligibility-repeats.md. The variable-length initial runs below remain
unchanged; do not silently pool them as equal-length steady-state samples.

Three fresh chains with separate datadirs, same six identities, three bootstrap
and three late registrants, six of six approvals, difficulty4096. Binary SHA256:
3d37b7b17bc5d27a84fe7dcaf038353611acf0cb3cddfab35ebeee8cfa85089e.
Original chain data preserved; public phase archives and clean stopped DBs copied
locally. Initial thresholds are adaptive, NOT fixed probabilities throughout.

| Phase | Node1 captured blocks | Header intervals (excluding genesis-to-first) | Mean seconds | Maximum seconds | Observed base threshold range | Late finalized | Distinct block producers |
| --- | --- | --- | --- | --- | --- | --- | --- |
| p256 (100%) | 1–51 | 50 | 4.960 | 32 | 0.9645–1.0000 | 3/3 | 6/6 |
| p128 (50%) | 1–64 | 63 | 3.476 | 18 | 0.5000–1.0000 | 3/3 | 5/6 |
| p64 (25%) | 1–43 | 42 | 11.071 | 93 | 0.2500–0.5079 | 3/3 | 5/6 |

All six active and mining in each final live observation. Node6 had no accepted
block in the captured p128/p64 windows; do not equate a mining flag with winning.
The different sample lengths, single run each and adaptive thresholds prevent
causal claims about relative throughput or energy. These windows include the
bootstrap-only and enrollment periods, not steady-state six-producer performance.
The first interval is excluded because genesis files were prepared before launch.

All three late requests have six challenges, six responses and six approvals:

- p256: all slots7..12.
- p128: node5 slots20..25; nodes4/6 slots22..27.
- p64: all slots9..14.

All6 agree on block hash AND state root at height40, per downloaded block records:

| Phase | Hash | State root |
| --- | --- | --- |
| p256 | 0x10621361fca5cca3544b976a64027804a8012205f890d8e8014ae6fa290e63ae | 0x8471b8c44ac61950403834732391344f06c32ffa6dea6c59662d5730d846c6d9 |
| p128 | 0xd3dcc553daa8b0500a243db0971c92c5725c5b381efa6d0f0bde6eca7b17c64a | 0xc3ea13af6d94aca033ea595b5a5b612ffa32d25466a7b9ffbcf6490ae0e5859b |
| p64 | 0xefd2206098239b605615e828ab3c567a2191fc7129452dca0bed23e420a21444 | 0x8314d5782e90e4f7d1d75128e7a171a220847d9e3c299404e0b8de3e090f8061 |

Local files: artifacts/tgpow-gcp-full/nN-p256-normal.tgz (and p128/p64),
nN-frozen-p256.tgz (and p128/p64). Each frozen DB's local hash checked against
remote before phase transition. Summarize with summarize-phase.ps1; validate
registration events using `go run ./experiments/tgpow-gcp-full/audit registry-logs.json`.
Service logs include earlier phases: filter the process/time window before using
eligibility or preparation-latency lines. Per-attempt log counts can repeat within
a height and must not be treated as independent VRF trials.
