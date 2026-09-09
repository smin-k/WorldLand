param(
  [ValidateSet('run','upload','download')][string]$Operation,
  [ValidateRange(1,5)][int]$NodeNumber,
  [string[]]$Files,
  [string]$RemoteCommand,
  [string]$Destination = 'artifacts/tgpow-gcp-testnet/'
)
$ErrorActionPreference = 'Stop'
$cloudExe = 'C:\Users\infonet\AppData\Local\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd'
$fingerprints = @{
  1='SHA256:5NeKSJcN4E5CyEdB7qvw8wMe22S5YIO+aDadoHjlfzI'
  2='SHA256:mmu5GWeMsjhM3PHPMLL3mNfsq431A4TKJxSlsUsRYpY'
  3='SHA256:MYOSHkVre05mnt+05+w9UWUdKnFHgPRALNmCnvXb0g4'
  4='SHA256:Jo5PZkKIjeULzNnh20HCPhsXxbR/VdLKD4mrtzU0Ev4'
  5='SHA256:uYHflOqUBl6ahu0XYDOe3pCwZI8Y9WTSawW/oqjJIg4'
}
# Fingerprints verified against the authenticated GCP serial console, not TOFU.
$nodeName = "wl-tgpow-0908-n$NodeNumber"
$commonArgs = @('--zone=us-central1-b','--tunnel-through-iap',
 '--ssh-key-file=C:/Users/infonet/Desktop/git/02_worldland/WorldLand/artifacts/tgpow-gcp-testnet/ssh-key',
 '--project=project-b705fc06-c245-4131-9fb','--account=smin8030@gmail.com','--quiet')
switch ($Operation) {
 'run' {
  & $cloudExe compute ssh $nodeName @commonArgs --ssh-flag=-batch --ssh-flag=-hostkey "--ssh-flag=$($fingerprints[$NodeNumber])" "--command=$RemoteCommand"
 }
 'upload' {
  & $cloudExe compute scp @Files "${nodeName}:" @commonArgs --scp-flag=-batch --scp-flag=-hostkey "--scp-flag=$($fingerprints[$NodeNumber])"
 }
 'download' {
  if ($Files.Count -ne 1) { throw 'PuTTY requires exactly one remote source' }
  & $cloudExe compute scp "${nodeName}:$($Files[0])" $Destination @commonArgs --scp-flag=-batch --scp-flag=-hostkey "--scp-flag=$($fingerprints[$NodeNumber])"
 }
}
if ($LASTEXITCODE -ne 0) { throw "GCP $Operation failed for $nodeName ($LASTEXITCODE)" }
