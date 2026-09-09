param([string]$Root='artifacts/tgpow-gcp-full/load-audit')
$ErrorActionPreference='Stop'
foreach ($rate in 1,4,8) {
 $dir=Join-Path $Root "bounded-load-$rate"
 $events=Get-Content (Join-Path $dir 'requests.jsonl') | ConvertFrom-Json
 $samples=@(foreach($line in Get-Content (Join-Path $dir 'resources.txt')) {
  if($line -match '^(\S+) (control|load) (?:MemoryCurrent=)?(\d+) (?:CPUUsageNSec=)?(\d+) (?:TasksCurrent=)?(\d+) (\{.*\})$') {
   [pscustomobject]@{Time=[DateTimeOffset]::Parse($Matches[1]);Phase=$Matches[2];Memory=[double]$Matches[3];CPU=[double]$Matches[4];Head=[Convert]::ToInt64(($Matches[6]|ConvertFrom-Json).result.Substring(2),16)}
  } else { throw "Unrecognized resource line: $line" }
 })
 $segments=@(foreach($phase in 'control','load') {
  $s=@($samples|Where-Object Phase -eq $phase)
  $seconds=($s[-1].Time-$s[0].Time).TotalSeconds
  [pscustomobject]@{Phase=$phase;Seconds=$seconds;Blocks=$s[-1].Head-$s[0].Head;CPUCoreEquivalent=($s[-1].CPU-$s[0].CPU)/1e9/$seconds;PeakMiB=($s.Memory|Measure-Object -Maximum).Maximum/1MB}
 })
 [pscustomobject]@{Rate=$rate;Requests=@($events|Where-Object event -eq submitted).Count;Receipts=@($events|Where-Object event -eq receipt).Count;Verdicts=@($events|Where-Object event -eq verdict).Count;UnexpectedProgress=@($events|Where-Object {$_.event -eq 'verdict' -and ($_.active -or $_.approvals -ne 0 -or $_.challenges -ne 0)}).Count;Segments=$segments} | ConvertTo-Json -Depth 4 -Compress
}
