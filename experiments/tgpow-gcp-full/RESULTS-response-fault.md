# Actual TPM Certify response faults — 2026-09-08 UTC

Superseded live-state note: on2026-09-09 the direct campaign completed active-window
duplicate transactions and fault-disabled fresh-request recovery (all3six approvals,
active and actual blocks). See RESULTS-resumed-campaign.md. The pending recovery
instructions below describe the earlier snapshot, not a remaining task.

Independent data-attack chain, real GCP TPMs. Client SHA256:
7d35dd45a9311ea436a616d8b24167eacd0568ac5795d85ca8a0456191dac637.
Linux tests passed for tpmenroll/tpmproducer in normal and research builds.
Production builds have no-op hooks; research build only changes outbound first
slot evidence with an explicit marker, isolated chain103994, and selected mode.
The normal producer verifier, contract and 6/6 threshold are unchanged.

Bootstrap3 mining15:01:38–41. Late3 enabled15:03:12–14 after block9.
Each request has slots19..24, deadline84. Node4's first Certify qualifying data
uses a different request ID, node5's uses chain103995, node6's returned signature
has its last byte flipped. EK/AK/work/VRF identity evidence stays genuine.
Other five response slots are not modified.

Node2 producer log rejects slot19 of node4/node5 with
`producer certification challenge mismatch`, and node6 with
`invalid TPM certification signature: crypto/rsa: verification error`.
This demonstrates the actual response verifier, not only malformed admission.

At15:22:08/head206, read-only live registry audit gives for ALL THREE:
approvals5, threshold6, finalized=false, active=false, deadline84;
finalize eth_call returns `TPMRegistry: request closed`.
Actual response/event counts are audited separately from eth_call. Do not call
the read-only finalize probe a broadcast failed finalization transaction.

Public snapshots: artifacts/tgpow-gcp-full/nN-attack-expired.tgz.
The current attack chain still runs with only bootstrap3 mining; fault markers
remain enabled on late nodes4–6 and their requests expired. Recovery retry has
NOT run. Active-window duplicates also NOT run: the observation window passed;
earlier duplicate results cover closed requests only.

Next interactive recovery, after evidence review: exact targets
wl-tgpow6-0908-n4..n6 in the existing project/zone. Preserve the expired snapshots,
rename only /opt/worldland-testnet/response-fault.enabled to a new disabled name
(do not overwrite existing files), then restart worldland-node on those3 to submit
fresh requests. Observe6/6, activation and actual blocks. No data deletion or
quorum change is needed. The read-only heartbeat must not execute this recovery.
