param(
 [Parameter(Mandatory=$true)][ValidatePattern('^(attack|p(256|128|64)-r[23])$')][string]$Previous,
 [Parameter(Mandatory=$true)][ValidatePattern('^p(256|128|64)-r[23]$')][string]$Phase,
 [switch]$ResumeInstalled
)
$ErrorActionPreference='Stop'
$campaignRoot=Split-Path -Parent $PSScriptRoot
$repoRoot=Split-Path -Parent $campaignRoot
$cloud=Join-Path $PSScriptRoot 'cloud.ps1'
Set-Location $repoRoot
if ($Previous -eq $Phase) {throw 'phase must change'}
function RunAll([string]$Command) {
 $results=1..6 | ForEach-Object -Parallel {
  Set-Location $using:repoRoot
  & $using:cloud -Operation run -NodeNumber $_ -RemoteCommand $using:Command
  if ($LASTEXITCODE -ne 0) {throw "node $_ failed"}
 } -ThrottleLimit 6
 $results | Write-Output
}
function AssertArchiveSet($RemoteLines,[string]$Suffix) {
 $remote=@($RemoteLines|ForEach-Object {if($_ -match '^([a-f0-9]{64})\s+/home/infonet/'){ $Matches[1].ToLowerInvariant() }}|Sort-Object)
 $local=@(1..6|ForEach-Object {(Get-FileHash "artifacts/tgpow-gcp-full/n$_-$Suffix.tgz" -Algorithm SHA256).Hash.ToLowerInvariant()}|Sort-Object)
 if($remote.Count -ne 6 -or @(Compare-Object $remote $local).Count){throw "archive digest mismatch: $Suffix"}
 Write-Output "HASH_VERIFIED all6 $Suffix"
}
# This script advances exactly ONE explicitly selected phase, preserving the old
# public chain DB. The caller reviews results before another phase is allowed.
if ($ResumeInstalled) {
 # Only after a read-only audit confirms all six already run this exact phase.
 RunAll "sudo test -d /opt/worldland-testnet/data-$Phase/worldland/chaindata && sudo systemctl is-active worldland-node"
} else {
 Write-Output "Preserving $Previous before $Phase"
 $frozenDigestLines=@(RunAll "sudo test -d /opt/worldland-testnet/data-$Previous && sudo bash /home/infonet/freeze-public-phase.sh $Previous")
 $frozenDigestLines | Write-Output
 RunAll "sudo bash /home/infonet/install-phase.sh $Phase"
}
1..3 | ForEach-Object -Parallel {
 Set-Location $using:repoRoot
 & $using:cloud -Operation run -NodeNumber $_ -RemoteCommand "sudo touch /opt/worldland-testnet/phase-$using:Phase/mining.enabled && sudo systemctl restart worldland-node"
} -ThrottleLimit 3
$phaseLimit=[DateTime]::UtcNow.AddMinutes(20)
do {
 Start-Sleep -Seconds 10
 $snapshot=Invoke-RestMethod 'http://35.253.126.26:8080/api/status' -TimeoutSec 20
 $heights=@($snapshot.nodes | ForEach-Object height)
 Write-Output "$Phase bootstrap heights: $($heights -join ',')"
 if ([DateTime]::UtcNow -gt $phaseLimit) {throw 'bootstrap deadline reached; preserve state and inspect'}
} until ($snapshot.nodes.Count -eq 6 -and ($heights | Measure-Object -Minimum).Minimum -ge 1)
4..6 | ForEach-Object -Parallel {
 Set-Location $using:repoRoot
 & $using:cloud -Operation run -NodeNumber $_ -RemoteCommand "sudo touch /opt/worldland-testnet/phase-$using:Phase/mining.enabled && sudo systemctl restart worldland-node"
} -ThrottleLimit 3
do {
 Start-Sleep -Seconds 15
 $snapshot=Invoke-RestMethod 'http://35.253.126.26:8080/api/status' -TimeoutSec 20
 $heights=@($snapshot.nodes | ForEach-Object height)
 $active=@($snapshot.nodes | ForEach-Object {@($_.registrations | Where-Object active).Count})
 Write-Output "$Phase heights=$($heights -join ',') active=$($active -join ',')"
 if ([DateTime]::UtcNow -gt $phaseLimit) {throw 'phase observation deadline reached; preserve state and inspect'}
} until ($snapshot.nodes.Count -eq 6 -and ($heights|Measure-Object -Minimum).Minimum -ge 64 -and ($active|Measure-Object -Minimum).Minimum -eq 6)
RunAll 'sudo bash /home/infonet/verify-height.sh 64'
$publicDigestLines=@(RunAll "sudo bash /home/infonet/collect-phase.sh $Phase-fixed64 64")
$publicDigestLines | Write-Output
1..6 | ForEach-Object -Parallel {
 Set-Location $using:repoRoot
 & $using:cloud -Operation download -NodeNumber $_ -Files "/home/infonet/phase-public-$using:Phase-fixed64.tgz" -Destination "artifacts/tgpow-gcp-full/n$_-$using:Phase-fixed64.tgz"
 & $using:cloud -Operation download -NodeNumber $_ -Files "/home/infonet/frozen-$using:Previous.tgz" -Destination "artifacts/tgpow-gcp-full/n$_-frozen-$using:Previous.tgz"
} -ThrottleLimit 6
AssertArchiveSet $publicDigestLines "$Phase-fixed64"
if (!$ResumeInstalled) {AssertArchiveSet $frozenDigestLines "frozen-$Previous"}
Write-Output "PHASE_OBSERVED $Phase; old DB and fixed64 public snapshots downloaded; verify hashes and audit before next phase."
