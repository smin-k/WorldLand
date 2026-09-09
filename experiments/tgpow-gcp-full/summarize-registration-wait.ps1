param([Parameter(Mandatory=$true)][ValidatePattern('^p(256|128|64)-r[23]$')][string]$Phase)
$ErrorActionPreference='Stop'
$env:GOCACHE='C:/Users/infonet/Desktop/git/02_worldland/WorldLand/artifacts/go-cache-windows'
$dir="artifacts/tgpow-gcp-full/repeat-analysis/$Phase/n1/phase-public-$Phase-fixed64"
$blocks=@(Get-Content "$dir/blocks.jsonl"|ConvertFrom-Json)
$requests=@(go run ./experiments/tgpow-gcp-full/audit "$dir/registry-logs.json"|ConvertFrom-Json)
if($LASTEXITCODE -ne 0 -or $requests.Count -ne 3){throw 'expected three audited late requests'}
$rows=@(foreach($r in $requests){
 if(!$r.Finalized -or $r.FinalizedBlock -lt $r.BeginBlock -or $r.ActivationBlock -ne $r.FinalizedBlock+6){throw 'invalid registration timing'}
 $seconds=$null
 # Header timestamp difference, not client submission wall-clock latency.
 # Never extrapolate when activation is beyond the copied performance window.
 if($r.ActivationBlock -lt $blocks.Count){
  $seconds=[Convert]::ToInt64($blocks[$r.ActivationBlock].timestamp.Substring(2),16)-[Convert]::ToInt64($blocks[$r.BeginBlock].timestamp.Substring(2),16)
 }
 [pscustomobject]@{Request=$r.ID;Begin=$r.BeginBlock;Finalized=$r.FinalizedBlock;Activation=$r.ActivationBlock;BeginToActivationBlocks=$r.ActivationBlock-$r.BeginBlock;BeginToActivationHeaderSeconds=$seconds}
})
[pscustomobject]@{Phase=$Phase;Requests=$rows;Note='Canonical begin-inclusion to activation-height interval, not submission wall-clock latency; three concurrent requests are correlated. Null seconds means missing activation header.'}|ConvertTo-Json -Depth 4
