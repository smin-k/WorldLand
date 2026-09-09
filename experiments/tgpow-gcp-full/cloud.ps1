param(
 [ValidateSet('run','upload','download')][string]$Operation,
 [ValidateRange(1,6)][int]$NodeNumber,
 [string[]]$Files,
 [string]$RemoteCommand,
 [string]$Destination = 'artifacts/tgpow-gcp-full/'
)
$ErrorActionPreference = 'Stop'
$gc = 'C:/Users/infonet/AppData/Local/Google/Cloud SDK/google-cloud-sdk/bin/gcloud.cmd'
# ED25519 fingerprints verified through authenticated GCP serial output on 2026-09-08.
$fingerprints = @{
 1='SHA256:YgPSqUX73zKEZaTV9BcjleUI5ShBrWfqp4ineSn2q/I'
 2='SHA256:A02xwIcJ5hJVQYGwllOPr5wO4dRVwDBWjgWSEaoG6Pc'
 3='SHA256:HXCkw9rJLcLVCSzYXeurvXk7cbIzmMdMzeSTCpEBKxM'
 4='SHA256:Ye/2sHMbq0XzUbyrCS53GdlVot6K/RvNfltxT7/Ci3U'
 5='SHA256:XHEk29CLrOCqU/a7HEctA7W6HlE5uq7MiBoSXrp0fbY'
 6='SHA256:CmTgaqW0LIVdNvHBkZMLaadGGKaCFyCybiSHMwmtuDs'
}
$nodeName = "wl-tgpow6-0908-n$NodeNumber"
$commonArgs = @('--zone=us-central1-b','--tunnel-through-iap',
 '--ssh-key-file=C:/Users/infonet/Desktop/git/02_worldland/WorldLand/artifacts/tgpow-gcp-testnet/ssh-key',
 '--project=project-b705fc06-c245-4131-9fb','--account=smin8030@gmail.com','--quiet')
switch ($Operation) {
 'run' { & $gc compute ssh $nodeName @commonArgs --ssh-flag=-batch --ssh-flag=-hostkey "--ssh-flag=$($fingerprints[$NodeNumber])" "--command=$RemoteCommand" }
 'upload' { & $gc compute scp @Files "${nodeName}:" @commonArgs --scp-flag=-batch --scp-flag=-hostkey "--scp-flag=$($fingerprints[$NodeNumber])" }
 'download' {
  if ($Files.Count -ne 1) { throw 'Exactly one remote source required' }
  & $gc compute scp "${nodeName}:$($Files[0])" $Destination @commonArgs --scp-flag=-batch --scp-flag=-hostkey "--scp-flag=$($fingerprints[$NodeNumber])"
 }
}
if ($LASTEXITCODE -ne 0) { throw "GCP $Operation failed for $nodeName ($LASTEXITCODE)" }
