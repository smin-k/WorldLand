# Read-only public evidence inventory. Never includes deployment/key bundles.
$ErrorActionPreference='Stop'
Set-Location (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$names=@(foreach($phase in @('p256-r2','p128-r2','p64-r2','p256-r3','p128-r3','p64-r3')) {
 foreach($n in 1..6){"n$n-$phase-fixed64.tgz";"n$n-frozen-$phase.tgz"}
})
$names+=@('bounded-load-1.tgz','bounded-load-4.tgz','bounded-load-8.tgz',
 'valid-verifier-load-r1.tgz','expensive-admission-r1.tgz',
 'n1-normal-recovery.tgz','n1-open-replay-expired.tgz','n6-open-replay-expired.tgz')
foreach($name in $names|Sort-Object){
 $path="artifacts/tgpow-gcp-full/$name"
 $entries=@(tar -tzf $path)
 if($LASTEXITCODE -ne 0 -or !$entries.Count){throw "unreadable public archive: $name"}
 if(@($entries|Where-Object {$_ -match '(^/|(^|/)\.\.(/|$)|(^|/)(keystore|nodekey|password|ssh-key)([./]|$))'}).Count){throw "unexpected private/unsafe path in: $name"}
 "{0}  {1}" -f (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant(),$name
}
