# Live pending-restart / missing-approval experiments

Date: 2026-09-08 UTC. Six existing GCP SEV/vTPM VMs, chain103994,
fresh data-research12 with the same genesis as the preserved integrated control.
Three bootstrap identities. Consensus threshold remains6/6; difficulty4096.
No extra VM or quota changes. Original deletion deadline remains2026-09-09T10:50Z.

## Build and controls

Research client SHA256:
`ecc3744229b13e7fd1fb93014e77e5f72498e1db2391363afa00717e29b5cb0c`.
Built with `enrollmentresearch`; ordinary builds compile a no-op fault hook.
The hook checks chain103994, exact node5 identity, first request slot, and a local
marker. It withholds an approval AFTER verifying the evidence. It does not alter
contract code, signature validation, approval count, or deadline requirements.
The marker is disabled for recovery. This tests an intentionally uncooperative
producer, not a cryptographic forgery or general network attack.

Normal integrated control DBs were cleanly stopped, downloaded and remote/local
SHA256 matched for all6: `artifacts/tgpow-gcp-full/nN-integrated-control-db.tgz`.
Original `data` and `data-integrated` remain intact on every VM.

## 1. Restart while registration is pending

PASS for the observed approval-wait state (not every possible interruption point).
Node4 request:
`0x5be262c32f2998fef753571c0235273c3c3a21b24b5dbd8b1a608754fa222a9d`.
Slots11..16, response deadline76.

At12:39:56Z, a read-only live registry probe reported head18,
approvals4/6, finalized=false, active=false. Finalize eth_call returned
`TPMRegistry: insufficient producer approvals`. Node4 was then restarted.
After restart the SAME request obtained6/6 approvals, finalized at block20,
and activation block26. Later observation at head39 showed active=true;
the node returned to mining. No extra begin request was observed for node4.

Deviation: the automatic first-response trigger could not parse an ISO timestamp
on the VM's journalctl. It was stopped; the actual restart was manually triggered
after verifying4/6 on-chain. Thus this is an approval-wait restart, NOT evidence
of an exactly-first-response restart. The script timestamp format was corrected.
Retain the failed trigger logs rather than counting it as a successful trigger.

Public evidence archives (local hashes must match remote):

* n1-pending-restart-pass.tgz: dea40b6e998dcf55f9b59510e5c8f3b3900062663f1dcab1e67387f634eb034c
* n4-pending-restart-pass.tgz: ef8c7852a346223b44dc3faa833d1ffc54188cc2f0362d304edf874720b039e9

## 2. Deliberately missing approval

PASS for withholding, expiry, and fresh-request recovery in this run.
Node5 starts after experiment1; all producers run the research binary with the
first-slot omission enabled for node5 only. Request a351e8925e4894e11f07f1ad4bf60e4cb39f0c4f6a515e7ecfb0261744839d63
has challenges/responses for ALL slots48..53; approvals49..53 only (48 omitted).
At12:43:33Z/head60, approvals5/6, finalized=false, active=false, and finalize call
returns `TPMRegistry: insufficient producer approvals`.
Deadline113 passed at12:47:03Z/head114 with the same5/6, still unfinalized/inactive;
finalize call now returns `TPMRegistry: request closed`. At12:47:04Z the integrated
service reports expiry with5of6 and does not start mining. Network keeps advancing.
All six withholding markers renamed to disabled after preserving expiry evidence;
node5 restarted for a fresh request and node6 enabled for normal registration.

Public node5 evidence: n5-withhold-five.tgz SHA256
86b415bac9c59d0fd76a8dd282e0ac77da172119604c232ca60e822cbe21ef88;
n5-withhold-expired.tgz SHA256
fadf2d491f0832eaf49a1fcca08907e37d64a96b3903ee6d49505efa7b1c39a7.
The probe uses actual chain state via eth_call; it does not broadcast a failed
finalization transaction and must not be described as one.
`active` in probe output is the identity's current state, not a property of an
individual request. After a successful retry, an expired request can still show
active=true for that identity while its own finalized field remains false.

Recovery request `0x738d6ad5f7d2a3497bbdece87d1050718571a9ebf5d92621b4f6161de53357e4`
has all6 challenges/responses/approvals at slots131..136 and finalized=true.
Node5 activated and produced canonical blocks. The original failed request remains
unfinalized at5/6. Node6's normal enrollment also completed6/6 and mining.
Final observer sample: heads187..189, all6 mining, latest20 canonical blocks include
every controller. See status-research12-complete.json in the local artifacts.
Separate RPC checks on all6 at height150 agree:
hash `0x8deb2a1f61d107590e9c8b647e12c363cd4740ef40f52fda13193c40fe9a0542`,
stateRoot `0xcb7f129955c1095ad09d856eb2c0c0e9655acc06ca52bc3f07076ce45946c3ca`.

All6 nN-research12-complete.tgz downloaded, remote/local SHA256 matched. Node5:
58d739ec1f9f99ed01bca26e83d2d0c848d25193ba2fbfa5559b7d80b46d6dd3.
Fault markers disabled on all6; research binary remains identifiable and running
without withholding. No chain quorum or verifier bypass was enabled.

These are individual live runs, not repeated statistical trials, pending-request
reorg tests, malicious evidence tests, or proof of all possible restart points.
