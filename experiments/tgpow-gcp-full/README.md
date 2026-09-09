# Six-node real-vTPM campaign

최종 한국어 요약: [`RESULTS-summary-ko.md`](RESULTS-summary-ko.md).
Public archive inventory: `PUBLIC-RESUMED.sha256` (80 selected evidence archives).

Start with `DIRECT_CAMPAIGN.md` for the latest state; historical `PLAN.md` describes
the ten-node quota request and is not the deployed topology. Existing six-node
project/zone and management allowlist are pinned in `cloud.ps1`.

2026-09-09 direct continuation: see `RESULTS-resumed-campaign.md` for actual
active-window replay results, successful manual recovery,24valid-verifier runs
and216expensive-admission transactions. `RESULTS-eligibility-repeats.md` records
the fresh-chain repetitions and their exact observation windows.

Results and explicit scope:

1. `RESULTS-restart-withhold.md`: pending restart, deliberate omitted approval,
   expiry and fresh-request recovery.
2. `RESULTS-bounded-load-replay.md`: invalid-admission rate sweep, closed-request
   duplicate response and approval transactions.
3. `RESULTS-eligibility.md`: adaptive initial100/50/25% registrations and headers.
4. `RESULTS-reorg.md`: actual partition, orphan branch audit and recovery.
5. `RESULTS-response-fault.md`: genuine TPM response context/signature faults.
6. `RESULTS-resumed-campaign.md`: open-window replay, fault recovery, actual
   valid-verifier component stress and expensive-rejection network load.
7. `RESULTS-eligibility-repeats.md`: fixed64window repetitions and registration
   activation delay, separated from initial variable-window observations.

Analysis only: `audit`, `fork-audit`, `summarize-load.ps1`, `summarize-phase.ps1`,
`assert-reorg.ps1`, `audit-repeat-phase.ps1`, `summarize-registration-wait.ps1`,
`summarize-verifier-load.ps1`, `summarize-expensive-admission.ps1`.
`verify-campaign-results.ps1` combines the copied-artifact checks and has no cloud
calls. Missing evidence is an error, not an implied pass.
Experiment commands compile but have no automated tests;
client package regression tests are distinct from network evidence.

Operational scripts are NOT a turnkey rerunnable suite. They intentionally refuse
existing phase data/output paths. `install-phase.sh` and freeze scripts change
service state; `partition-local.sh` temporarily changes only P2P packet filtering;
adversary/replay programs broadcast bounded test transactions. Review exact phase,
targets, backups and recovery before execution. Do not run these from a read-only
heartbeat. No instruction here authorizes cloud resource creation/deletion.

Raw public artifacts live under ignored `artifacts/tgpow-gcp-full/`. Never add
account keys, password files, keystores, TPM private material, nodekeys or SSH keys.
Paper source: sibling hardware-bound-coin-toss-paper, section gcp-testnet-evaluation.
The experiment-time handoffs record their original no-push status. Repository
organization subsequently publishes source, result documents and hash inventories;
raw DB archives remain local and have not been publicly released.
