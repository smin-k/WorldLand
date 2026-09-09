$ErrorActionPreference='Stop'
$rows=@(foreach($n in @(1,6)){
 $dir="artifacts/tgpow-gcp-full/resumed-analysis/open-replay-n$n"
 if(!(Test-Path $dir)){
  New-Item -ItemType Directory -Path $dir|Out-Null
  tar -xzf "artifacts/tgpow-gcp-full/n$n-open-replay-expired.tgz" -C $dir
  if($LASTEXITCODE -ne 0){throw 'public replay extraction failed'}
 }
 $events=@(foreach($line in Get-Content "$dir/resume-public-open-replay-expired/services.log"){
  if($line -match 'replay-open-linux\[\d+\]: (\{.*\})$'){$Matches[1]|ConvertFrom-Json}
 })
 if($events.Count -ne 1){throw 'expected exactly one successful replay observation per node'}
 $e=$events[0]
 if($e.status -ne 0 -or $e.block -ne 5415 -or $e.block -ge $e.before.ResponseDeadline -or $e.before.Approvals -ne 5 -or $e.after.Approvals -ne 5 -or $e.before.Threshold -ne 6 -or $e.before.FirstSlot -ne $e.after.FirstSlot -or $e.before.LastSlot -ne $e.after.LastSlot -or $e.before.ResponseDeadline -ne $e.after.ResponseDeadline -or $e.before.Threshold -ne $e.after.Threshold){throw 'replay receipt/state assertion failed'}
 $e
})
if(@($rows.case|Sort-Object -Unique).Count -ne 2 -or @($rows.request|Sort-Object -Unique).Count -ne 1){throw 'expected two distinct cases against same open request'}
[pscustomobject]@{Cases=$rows.Count;ReceiptStatus=0;Block=5415;Deadline=5466;ApprovalsBeforeAfter=5;Source='Preserved public journals of actual receipt-waiting harness, not a new network execution.'}|ConvertTo-Json
