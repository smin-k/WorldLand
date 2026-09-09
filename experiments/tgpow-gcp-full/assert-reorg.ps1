$ErrorActionPreference='Stop'
$root='artifacts/tgpow-gcp-full'
$forks=@(go run ./experiments/tgpow-gcp-full/fork-audit -db "$root/reorg-db-audit/data-reorg/worldland/chaindata" -first 16 -last 25 | ForEach-Object { $_ | ConvertFrom-Json })
if ($LASTEXITCODE -ne 0 -or $forks.Count -ne 10) { throw 'Expected ten orphan blocks' }
$canonical=(Get-Content "$root/reorg-audit/n1/phase-public-reorg-healed/registry-logs.json"|ConvertFrom-Json).result
$approval='0x070590207d76d329d7fd71ffbca5c9a65418e9ce218b8fb7ff1a3fdfe1785d94'
$old=@($forks.registryEvents|Where-Object {$_.topics[0] -eq $approval})
if($old.Count -eq 0) { throw 'No orphan approval evidence' }
$reused=@($old|Where-Object {$_.tx -in $canonical.transactionHash})
if($reused.Count -ne 0) { throw 'Orphan approval transaction emitted canonical registry event' }
foreach($n in 1..6) {
 foreach($label in 'reorg-split','reorg-healed') {
  $blocks=@(Get-Content "$root/reorg-audit/n$n/phase-public-$label/blocks.jsonl"|ConvertFrom-Json)
  for($i=1;$i -lt $blocks.Count;$i++) { if($blocks[$i].parentHash -ne $blocks[$i-1].hash) { throw "Inconsistent snapshot n$n $label" } }
 }
}
[pscustomobject]@{OrphanBlocks=$forks.Count;OrphanApprovals=$old.Count;OrphanApprovalEventsOnCanonical=$reused.Count;SnapshotParentLinks='passed';Scope='Observed branch replacement and event non-reuse; not universal adversarial proof'} | ConvertTo-Json
