param([Parameter(Mandatory=$true)][string]$Directory)
$ErrorActionPreference='Stop'
if ((Get-Content (Join-Path $Directory 'status.txt')).Trim() -ne 'complete') {throw 'run incomplete'}
$samples=@(foreach($line in Get-Content (Join-Path $Directory 'resources.txt')) {
 if ($line -notmatch '^(\S+) (\S+) MemoryCurrent=(\d+) CPUUsageNSec=(\d+) TasksCurrent=(\d+) (\{.*\})$') {throw "bad sample: $line"}
 [pscustomobject]@{Time=[DateTimeOffset]::Parse($Matches[1]);Segment=$Matches[2];Memory=[double]$Matches[3];CPU=[double]$Matches[4];Head=[Convert]::ToInt64(($Matches[6]|ConvertFrom-Json).result.Substring(2),16)}
})
$files=@(Get-ChildItem $Directory -Filter '*.jsonl')
if ($files.Count -ne 9) {throw 'expected nine measured trials'}
foreach($file in $files) {
 $events=@(Get-Content $file.FullName|ConvertFrom-Json)
 $submitted=@($events|Where-Object event -eq submitted)
 $receipts=@($events|Where-Object event -eq receipt)
 $verdicts=@($events|Where-Object event -eq verdict)
 if ($submitted.Count -ne 24 -or $receipts.Count -ne 24 -or $verdicts.Count -ne 24) {throw "incomplete events in $($file.Name)"}
 if (@($receipts|Where-Object status -ne 1).Count) {throw 'begin did not execute successfully'}
 if (@($verdicts|Where-Object {$_.active -or $_.approvals -ne 0 -or $_.challenges -ne 0}).Count) {throw 'invalid identity progressed'}
 $segments=@(foreach($kind in 'control','load') {
  $s=@($samples|Where-Object Segment -eq "$($file.BaseName)-$kind")
  $seconds=($s[-1].Time-$s[0].Time).TotalSeconds
  [pscustomobject]@{Segment=$kind;Seconds=$seconds;Blocks=$s[-1].Head-$s[0].Head;CPUCoreEquivalent=($s[-1].CPU-$s[0].CPU)/1e9/$seconds;PeakMiB=($s.Memory|Measure-Object -Maximum).Maximum/1MB}
 })
 [pscustomobject]@{Trial=$file.BaseName;Submissions=24;SuccessfulBegins=24;NoProgressVerdicts=24;Segments=$segments;Note='Valid static crypto evidence, false claimed identity; not valid new identities. Sequential repeated load with overlapping open-request lifetimes; control means no new injection, not empty pending queue.'}|ConvertTo-Json -Depth 4 -Compress
}
