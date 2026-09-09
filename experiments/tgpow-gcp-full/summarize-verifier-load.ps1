param([string]$Directory='artifacts/tgpow-gcp-full/resumed-analysis/valid-verifier-load-r1')
$ErrorActionPreference='Stop'
if ((Get-Content (Join-Path $Directory 'status.txt')).Trim() -ne 'complete') {throw 'run incomplete'}
$runs=@(Get-ChildItem $Directory -Filter '*.json' | ForEach-Object {Get-Content $_.FullName|ConvertFrom-Json})
if ($runs.Count -ne 24 -or @($runs|Where-Object {$_.failures -ne 0 -or $_.operations -le 0 -or $_.seconds -lt 30}).Count) {throw 'unexpected run count or failures'}
$samples=@(foreach($line in Get-Content (Join-Path $Directory 'resources.txt')) {
 if ($line -notmatch '^(\S+) (\S+) worldland-node MemoryCurrent=(\d+) CPUUsageNSec=(\d+) TasksCurrent=(\d+) worldland-valid-verifier-load MemoryCurrent=(\d+) CPUUsageNSec=(\d+) TasksCurrent=(\d+) (\{.*\})$') {throw "unparsed resource sample: $line"}
 [pscustomobject]@{Time=[DateTimeOffset]::Parse($Matches[1]);Segment=$Matches[2];ClientMemory=[double]$Matches[3];ClientCPU=[double]$Matches[4];LoadMemory=[double]$Matches[6];LoadCPU=[double]$Matches[7];Head=[Convert]::ToInt64(($Matches[9]|ConvertFrom-Json).result.Substring(2),16)}
})
$resources=@(foreach($group in $samples|Group-Object Segment) {
 $s=@($group.Group); $seconds=($s[-1].Time-$s[0].Time).TotalSeconds
 if ($seconds -le 0) {throw 'zero-duration resource segment'}
 [pscustomobject]@{Segment=$group.Name;Seconds=$seconds;Blocks=$s[-1].Head-$s[0].Head;ClientCores=($s[-1].ClientCPU-$s[0].ClientCPU)/1e9/$seconds;VerifierCores=($s[-1].LoadCPU-$s[0].LoadCPU)/1e9/$seconds;ClientPeakMiB=($s.ClientMemory|Measure-Object -Maximum).Maximum/1MB;VerifierPeakMiB=($s.LoadMemory|Measure-Object -Maximum).Maximum/1MB}
})
$cases=@(foreach($group in $runs|Group-Object mode,workers) {
 if ($group.Count -ne 3) {throw 'expected three repeats per case'}
 [pscustomobject]@{Case=$group.Name;Repeats=$group.Count;OpsPerSecondMean=($group.Group.opsPerSecond|Measure-Object -Average).Average;OpsPerSecondMin=($group.Group.opsPerSecond|Measure-Object -Minimum).Minimum;OpsPerSecondMax=($group.Group.opsPerSecond|Measure-Object -Maximum).Maximum;MeanOfRunP95ms=($group.Group.p95ms|Measure-Object -Average).Average}
})
[pscustomobject]@{Runs=$runs.Count;TotalOperations=($runs.operations|Measure-Object -Sum).Sum;Failures=($runs.failures|Measure-Object -Sum).Sum;Cases=$cases;Resources=$resources;Note='Component closed-loop test. Quantiles use first200000 latency samples per worker; averages of per-run percentiles, not pooled. Resources include process setup and collection. First repeat overlaps enrollment recovery.'}|ConvertTo-Json -Depth 5
