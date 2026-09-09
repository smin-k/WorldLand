# Read-only verification of preserved public results. No cloud calls or service changes.
$ErrorActionPreference='Stop'
Set-Location (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$repetitions=@(foreach($phase in @('p256-r2','p128-r2','p64-r2','p256-r3','p128-r3','p64-r3')) {
 $audit=& "$PSScriptRoot/audit-repeat-phase.ps1" -Phase $phase | ConvertFrom-Json
 $wait=& "$PSScriptRoot/summarize-registration-wait.ps1" -Phase $phase | ConvertFrom-Json
 [pscustomobject]@{Phase=$phase;Nodes=$audit.Nodes;LateFinalized=$audit.LateFinalized;Hash64=$audit.Hash64;Root64=$audit.Root64;Headers=$audit.Stats.Headers;MeanIntervalSeconds=$audit.Stats.MeanSeconds;MaximumIntervalSeconds=$audit.Stats.MaxSeconds;ProducerCount=$audit.Stats.Producers.Count;InitialBase=$audit.Stats.InitialBase;MinimumBase=$audit.Stats.MinimumBase;MaximumBase=$audit.Stats.MaximumBase;ActivationWait=$wait.Requests}
})
$reorg=& "$PSScriptRoot/assert-reorg.ps1"|ConvertFrom-Json
$openReplay=& "$PSScriptRoot/assert-open-replay.ps1"|ConvertFrom-Json
$component=& "$PSScriptRoot/summarize-verifier-load.ps1"|ConvertFrom-Json
$network=@(& "$PSScriptRoot/summarize-expensive-admission.ps1" -Directory 'artifacts/tgpow-gcp-full/resumed-analysis/expensive-admission-r1'|ConvertFrom-Json)
[pscustomobject]@{
 Repetitions=$repetitions
 Reorg=$reorg
 OpenReplay=$openReplay
 ValidVerifierRuns=$component.Runs
 ValidVerifierOperations=$component.TotalOperations
 ValidVerifierFailures=$component.Failures
 ExpensiveAdmissionTrials=$network.Count
 ExpensiveAdmissionStarts=($network.Submissions|Measure-Object -Sum).Sum
 ExpensiveAdmissionNoProgress=($network.NoProgressVerdicts|Measure-Object -Sum).Sum
 Scope='Checks copied artifacts; does not execute attacks or establish untested security/capacity claims. Original R1 eligibility and closed-request replay receipts are documented separately.'
}|ConvertTo-Json -Depth 7
