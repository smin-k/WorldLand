# Six-node quota-constrained campaign — 2026-09-08

## ACTIVE EXPERIMENTS 3–6 — 2026-09-08 13:01Z

User authorized remaining invalid/replay, partition/reorg, eligibility256/128/64,
and bounded load experiments. Main task owns mutations. Heartbeat must only observe
and preserve evidence; do not restart experiment nodes/helpers or change conditions.
Deadline2026-09-09T10:50Z remains mandatory. No new infrastructure/quota changes.
Invalid registration admission is not successful registration: audit zero challenges,
approvals and activation after miner evidence validation, not just receipt status.
Historical eth_call checks are distinctly labeled, never called broadcast attacks.
No experiment is complete until its measured outcome is recorded.

## ACTIVE EXPERIMENTS 1/2 — 2026-09-08 12:34Z

User authorized pending-registration restart and deliberate one-approval withholding.
Main task owns mutations; heartbeat should observe/backup only, not restart helpers
or restore old binaries. Preserve integrated control before fresh data-research12.
Research binary (enrollmentresearch build tag) only withholds node5 DID first-slot
approval when research-withhold.enabled exists. Crypto verification/quorum unchanged.
Node4 pending response triggers one restart; node5 later tests5/6 rejection/expiry
and retry after marker removal. Do not infer success until audit is recorded.
Original VM deletion deadline unchanged. No quota changes or extra nodes.

12:48Z progress: experiment1 passed approval-wait restart at4/6, resumed same
request to6/6/active. Original automatic trigger had journalctl timestamp parsing
failure; manual on-chain-verified restart substituted. See RESULTS-restart-withhold.md.
Experiment2 node5 had all6 challenges/responses but only5approvals, slot48 omitted;
head60 eth_call rejected insufficient approvals. Athead114 pastdeadline113 still
5/6 andinactive; client explicitly expired. All6 withholding markers now disabled.
Node5 fresh request retry and node6 normal enrollment started about12:48Z.
Recovery IN PROGRESS; do not re-enable withholding or external helpers.
Current active chain directory is data-research12, not data-integrated.
Use newest finish-six.sh for final backup (all three public chain DBs).

### Experiments1/2 COMPLETE — about12:53Z

Node5 retry738d6ad5... obtained6/6 for slots131..136, finalized, activated and
mined. Original a351e892... remains unfinalized5/6 afterdeadline113. Node6 also
activated/mined. All6 observed mining at heads187..189; latest20 include all6.
All6 height150 hash8deb2a1f61d107590e9c8b647e12c363cd4740ef40f52fda13193c40fe9a0542
and stateRootcb7f129955c1095ad09d856eb2c0c0e9655acc06ca52bc3f07076ce45946c3ca match.
All6 final public archives downloaded and SHA256 matched; detailed evidence and
limitations in RESULTS-restart-withhold.md. No remaining retry action required.
Keep network running with withholding DISABLED; do not rerun fault helpers.
The tagged research binary remains deployed with all markers disabled. Preserve
the precise binary hash and never describe it as the ordinary release binary.
Heartbeat may observe/back up; further fault injections require a new user request.
Deletion deadline unchanged; all6 have latest finish-six.sh covering three DBs.

## ACTIVE HANDOFF — integrated-client rollout 2026-09-08 12:15Z

User authorized Linux validation and integrated testnet deployment. Main task is
building in /opt/worldland-integrated-build, then preserving all six control DBs
before installing a fresh data-integrated chain (same genesis/network ID, separate
run). Do not start external producer/enrollment helpers or inject attacks during
this rollout. Check worldland-node logs for integration failures. The original
data directory stays intact. New node entrypoint is node-integrated.sh; automatic
mining/enrollment is gated by integrated-mining.enabled. Deadline unchanged.
No new experiment outcome should be inferred from the older control results below.

Linux full selected regression suite and CGO build passed 12:16Z. Integrated binary
SHA256 9fdb4c97219fe3c08701cfa30a3b29b670ef201dc4761a3d6d7bdffa4968a0ed.
All six old clean DB backups downloaded as n1..n6-control-final.tgz and matched
remote SHA256 before rollout. Original data remains untouched on each VM.
Fresh chain (same genesis) started about12:21Z; all six deployed same binary.
Bootstrap3 started first; late3 enabled about12:22Z after observed height5.
External producer disabled on all six, no external enrollment helper started.
Initial deployment key copy nested the keystore directory and caused startup
failures; corrected to copy directory contents before starting mining. Preserve
those logs; this was a deployment failure, not a successful first startup.
Integrated registration subsequently passed the checks recorded below.
finish-six.sh now archives both old data and data-integrated public chaindata.
Always upload its current version before final backup. Never include keystore,
nodekey, account.key, password or JWT secret in downloadable archives.

### Integrated run acceptance — 2026-09-08 about12:28Z

All six observed at height124, mining=true, no observer RPC errors. The latest20
canonical blocks include all six controller addresses. Three late requests only:

* 5be262c32f2998fef753571c0235273c3c3a21b24b5dbd8b1a608754fa222a9d:
  all challenges/responses/approvals for slots16..21, finalized.
* a351e8925e4894e11f07f1ad4bf60e4cb39f0c4f6a515e7ecfb0261744839d63:
  all challenges/responses/approvals for slots20..25, finalized.
* ab49c5699ee8edca77d2db60c10c4cb3c97a5e30514e8d6e18d9fdf5d5c92712:
  all challenges/responses/approvals for slots20..25, finalized.

Separate RPC calls on all six agree at height50:
hash 0xdefd73748bd58b7871489630ebe6b5a18beb48e7faa0d6be2fb76a78c93f80b2,
stateRoot 0xc56f4d1d2b474e6d0d16ef83598018d675ca45e5e685ebacb4dfd7cd75a1571c.
All six external worldland-producer services inactive. n4 restarted12:25:52Z,
recognized active identity12:25:53.285Z, resumed mining with no extra registration
request in collected canonical events. This tests active-state resumption, not
restart during a pending request or a forced reorg.

All six nN-integrated-final.tgz public archives downloaded with matching remote
SHA256; n1 hash611280395e58448623a797e10a8f067449ed0aa48cb66433c208d723bd8ce5d4.
Local status-integrated-active.json and status-integrated-postrestart.json preserve
observations. Earlier public-integrated-progress snapshot had all approvals but
preceded finalization; do not use its Finalized:false as current state.
Node1 integrated-window collected logs contain no matching enrollment preparation
warnings/errors; this is not a universal absence-of-errors or overload guarantee.

Keep this integrated control running under existing15min heartbeat and original
2026-09-09T10:50Z DELETE deadline. Use current finish-six.sh on every node before
deletion and verify downloads; it includes BOTH chain directories without secrets.
No deliberate attack/load/eligibility sweep was performed in this integration run.

User approved proceeding within current quotas. This supersedes the ten-node
capacity prerequisite in PLAN.md, not its evidence requirements or exclusions.
Six independent SEV/vTPM VMs, each n2d-standard-2: 12 vCPUs total.
Three genesis identities and three late registrants. Six of six slot approvals.
Chain 103994; initial/minimum difficulty 4096; activation six blocks;
initial eligibility 256/256, adaptive thereafter. This is NOT a ten-node result.

Project project-b705fc06-c245-4131-9fb, account smin8030@gmail.com.
VMs wl-tgpow6-0908-n1 through n6, zone us-central1-b.
VPC/subnet wl-tgpow6-0908 (10.79.0.0/28), internal IPs .2 through .7.
Firewall rules wl-tgpow6-0908-iap, wl-tgpow6-0908-internal,
wl-tgpow6-0908-explorer. No service accounts or public privileged RPC.
All VMs requested with absolute DELETE deadline 2026-09-09T10:50:00Z
(2026-09-09 19:50 KST), boot disks auto-delete. Do not extend.
Archive public chain data, configuration and service logs before deletion.
Then verify VM/disks gone and delete the dedicated firewall/subnet/VPC.
Never publish account keys, keystores, P2P private keys or SSH keys.

Current phase: live control experiment; observer http://35.253.126.26:8080/ verified HTTP200.
All six TPM preflights and separate GCP certificate policy validations passed.
All six nodes connected to five peers; initial three mining, late three not yet active.
Genesis block 0x002f152cb30a1d1e7f4682efbdf83184f2099d2eef030e9c39ccbe2d5cd8e8e2.
First concurrent enrollment (500ms producer polling) opened at block15, slots18..23,
response deadline83. Canonical event audit found exactly five challenges, responses
and approvals for EACH request: slots18,19,21,22,23. Slot20 missing; none finalized.
All three producer logs skip staging slot20. Timing/polling race is a hypothesis,
not yet a proven root cause. This is NOT a successful normal registration result.
First-attempt public logs/events preserved locally as n1/n4/n5/n6-public-first-attempt.tgz;
all four remote/local SHA256 values matched. audit/main.go summarizes event evidence.
Next bounded condition: change producer polling only to50ms, leave consensus/6-of-6
unchanged, retry after first requests expire (>83). Never silently count the retry
as success of the original500ms condition. A shorter poll is not a guaranteed fix.
50ms service override applied to all6 at11:22:25..31Z; only bootstrap3 agents running.
retry-enrollment.sh is uploaded on late nodes; run once per node after height>83
and original worldland-enroll is inactive/failed. It uses separate retry1 unit.
No cancellation is necessary for zero-collateral new requests; contract nonce
gives a new request ID. Do not cancelExpired: zero collateral refund rejects.
Node1 service log shows block19 sealed11:15:11.817, block20 sealed11:15:11.914,
about97ms later: substantially shorter than the500ms polling period.
This supports the polling/fast-sealing explanation;50ms remains an experimental mitigation.
Other adversarial/eligibility/load conditions remain NOT RUN.
First requests all expired explicitly with5of6 approvals at11:23:37..38Z.
This confirms incomplete quorum was not finalized in this observed case; it is
not a substitute for the planned deliberate malicious-approval experiment.
Retry1 started11:25:05..07Z on all late nodes; opened block102, slots105..110,
response deadline170. n4 request81dece21aeb50535126f7338723faee47e550d02fd966163dc926c3dd0458c05;
n5 request738d6ad5f7d2a3497bbdece87d1050718571a9ebf5d92621b4f6161de53357e4;
n6 request91c8233b107aa5ba97e3e7e303cb840a7af06b2d189f661e48276da41b0d3d64.
Do not start retry1 again: it is already running underworldland-enroll-retry1.
Retry1 logs: all three finalized. n5 activation block123, active/mining at11:27:06Z.
n4 andn6 activation block133, waiting as of11:27:10Z.
Pending acceptance: audit six canonical approvals each and actual accepted blocks
from all late identities, then a common-height/state convergence observation.

## Latest verified result (supersedes pending status above)

All six active and mining; common observed height178. The latest20 blocks include
every one of the six controller addresses, including all three late registrants.
status-six-active.json preserves that observation. Six separate RPC proofs at
height140 match hash0x3572b4a916d729cb8980830dadcb5421ed59399314fa79ccadaf27d3725db869
and stateRoot0xbd2df6ab577082515047ca7b3f78adb1903df56817407359238cfd739303da23.
n1..n6-height140.json preserve proofs. Audit of n1-public-retry1-finalized.tgz
confirms EACH retry request has challenges,responses,andapprovals for all six
slots105..110 and RegistrationFinalized. SHA256 verified:
54e51cd2249186fc7c3705287f3f411da6d2856b2b9b0d9d49c87099509a7d51.
The 50ms retry control passed these registration/convergence checks once.
The original500ms control failed5of6; shorter polling is NOT a proven robust fix.
Keep both results. Do not attribute success solely to polling: block intervals
also differed and controlled repeated trials are needed.
Before destructive subsequent conditions, cleanly archive the whole baseline chain
from all6 via finish-six.sh and verify downloaded hashes, then restart as needed.
Other planned deliberate adversarial, eligibility and load tests are still NOT RUN.
Binary worldland reused from preserved research build, expected SHA256:
b63538ad5268e9a8a1f9c524823c98930bbe20179163ab6f32ea3d6d7af7b959
Setup and observer rebuilt from updated local sources on node 1.
Local results directory: artifacts/tgpow-gcp-full/ (ignored).
Management: experiments/tgpow-gcp-full/cloud.ps1.
Old worldland-4096 heartbeat remains paused; old baseline VMs are deleted.
New heartbeat worldland-6 checks every15minutes and preserves evidence before deletion.
Provider-side DELETE deadline and disk autoDelete verified on all six instances.
Final clean public chain backup: upload and run finish-six.sh (stops services),
download /home/infonet/final-six.tgz separately for eachnode and verify SHA256.
This backup script refuses other chain IDs; adapt and review if later phases use a new chain.

## Heartbeat 2026-09-08 11:46Z

Read-only check: observed heads443..445, all6active/mining, latest20blocks include
all6controllers. Separate height430 proofs match on all6:
hash0x926c6642c61d3df7760f37aa0712224b314e42c5d5d3bfe540b9c0539b368529,
stateRoot0x4dd42112f1c92f86aec98f7a0a41fb36fa0fe9b2b5ad6db137d11384833b1498.
Public snapshot status-20260908-1146Z.json and all6 public-monitor-1146Z archives
downloaded and integrity checked; each remote/local SHA256 matched. Canonical
registry-logs.json SHA256 identical across all6:
55f5f3a0215eea3f5bc41d101f143764a1e23fe2318dba0e655ca196eafb6092.
This is a public observation/log backup, NOT a clean complete chain DB backup.

Known producer head-race errors continue under50ms: in each node's collected
11:31..11:48Z log window, error-line counts n1..n6 =42,49,42,44,44,44.
Examples are 'enrollment queue requires the next canonical parent and height'.
These are not new registration failures (no fresh requests in this interval),
nor proof of corrupt consensus. Do not suppress or call the timing defect fixed.
Code inspection: worker.go starts sealing when private enrollment queue is empty;
submitPrivateEnrollmentForParent signals a template rebuild only AFTER a tx arrives.
producerAgent independently polls and stages approvals before challenges. Thus
the existing rebuild mechanism does not synchronize mining with challenge readiness.
This motivates a bounded readiness/reproduction test, not blindly lowering quorum
or declaring50ms a robust solution. No code/consensus/runtime changes this heartbeat.

No attack/load injection: reviewed executable injection+recovery harnesses and clean
baseline DB backups are not yet prepared. Planned deliberate conditions remain NOT RUN.
Keep the control network running, preserve baseline before destructive scenarios,
and prioritize the enrollment timing issue as explained to the user.
