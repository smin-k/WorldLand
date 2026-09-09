param([Parameter(Mandatory=$true)][ValidatePattern('^p(256|128|64)-r[23]$')][string]$Phase)
$ErrorActionPreference='Stop'
$env:GOCACHE='C:/Users/infonet/Desktop/git/02_worldland/WorldLand/artifacts/go-cache-windows'
$root="artifacts/tgpow-gcp-full/repeat-analysis/$Phase"
$summaries=@(foreach($n in 1..6) {
 $out="$root/n$n"
 if (!(Test-Path $out)) {
  New-Item -ItemType Directory -Path $out | Out-Null
  tar -xzf "artifacts/tgpow-gcp-full/n$n-$Phase-fixed64.tgz" -C $out
  if ($LASTEXITCODE -ne 0) {throw 'archive extraction failed'}
 }
 $dir="$out/phase-public-$Phase-fixed64"
 $blocks=@(Get-Content "$dir/blocks.jsonl"|ConvertFrom-Json)
 if ($blocks.Count -ne 65) {throw 'expected genesis plus64headers'}
 for($i=0;$i -lt $blocks.Count;$i++) {
  if([Convert]::ToInt64($blocks[$i].number.Substring(2),16) -ne $i){throw 'wrong block number'}
  if($i -gt 0 -and $blocks[$i].parentHash -ne $blocks[$i-1].hash){throw 'mixed fork snapshot'}
 }
 $requests=@(go run ./experiments/tgpow-gcp-full/audit "$dir/registry-logs.json"|ConvertFrom-Json)
 if($LASTEXITCODE -ne 0){throw 'event audit failed'}
 if($requests.Count -ne 3){throw 'expected exactly3late requests in fresh chain'}
 foreach($r in $requests){
  if(!$r.Finalized -or $r.First -lt 1 -or @($r.Challenges|Sort-Object -Unique).Count -ne 6 -or @($r.Responses|Sort-Object -Unique).Count -ne 6 -or @($r.Approvals|Sort-Object -Unique).Count -ne 6){throw 'late request did not complete all6slots'}
  if($r.Last-$r.First -ne 5){throw 'unexpected slot interval'}
  foreach($events in @($r.Challenges,$r.Responses,$r.Approvals)){
   if($events.Count -ne 6 -or @($events|Where-Object {$_ -lt $r.First -or $_ -gt $r.Last}).Count){throw 'duplicate or out-of-range slot event'}
  }
 }
 $stats=.\experiments\tgpow-gcp-full\summarize-phase.ps1 -Directory $dir | ConvertFrom-Json
 [pscustomobject]@{Node=$n;Hash64=$blocks[64].hash;Root64=$blocks[64].stateRoot;Finalized=$requests.Count;Stats=$stats;ObservedHead=([Convert]::ToInt64((Get-Content "$dir/observed-head.json"|ConvertFrom-Json).result.number.Substring(2),16))}
})
if(@($summaries.Hash64|Sort-Object -Unique).Count -ne 1 -or @($summaries.Root64|Sort-Object -Unique).Count -ne 1){throw 'six-node disagreement at64'}
[pscustomobject]@{Phase=$Phase;Nodes=$summaries.Count;LateFinalized=3;Hash64=$summaries[0].Hash64;Root64=$summaries[0].Root64;Stats=$summaries[0].Stats;ObservedHeads=$summaries.ObservedHead;Assertions='65 parent-consistent headers per node;6/6late challenge/response/approval events;hash+root64agree all6. Finalization can be after fixed64performance window.'}|ConvertTo-Json -Depth 5
