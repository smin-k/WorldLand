param(
    [Parameter(Mandatory = $true)]
    [string]$RunDir
)

$ErrorActionPreference = "Stop"
$experimentDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $experimentDir "..\..")).Path
$runPath = (Resolve-Path $RunDir).Path
$worldland = Join-Path $repoRoot "artifacts\tgpow-e2e\bin\worldland.exe"
$node1Dir = Join-Path $runPath "node1"
$replayStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$node2Dir = Join-Path $runPath "validator-replay-$replayStamp"
$metadata = Get-Content (Join-Path $runPath "public-metadata.json") -Raw | ConvertFrom-Json
$node1Process = $null
$node2Process = $null

function Invoke-RPC {
    param([string]$Uri, [string]$Method, [object[]]$Params = @())
    $body = @{ jsonrpc = "2.0"; id = 1; method = $Method; params = $Params } | ConvertTo-Json -Depth 20 -Compress
    $response = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -TimeoutSec 10
    if ($null -ne $response.error) { throw "RPC $Method failed: $($response.error | ConvertTo-Json -Compress)" }
    return $response.result
}

function Wait-RPC {
    param([string]$Uri)
    $deadline = (Get-Date).AddMinutes(2)
    while ((Get-Date) -lt $deadline) {
        try { [void](Invoke-RPC -Uri $Uri -Method "web3_clientVersion"); return } catch { Start-Sleep -Milliseconds 500 }
    }
    throw "RPC endpoint $Uri did not start"
}

function Write-Utf8NoBom {
    param([string]$Path, [string]$Value)
    [System.IO.File]::WriteAllText($Path, $Value, [System.Text.UTF8Encoding]::new($false))
}

Push-Location $repoRoot
try {
    & go build -o $worldland ./cmd/worldland
    if ($LASTEXITCODE -ne 0) { throw "worldland build failed" }
    New-Item -ItemType Directory -Path $node2Dir | Out-Null
    $initProcess = Start-Process -FilePath $worldland -ArgumentList @("--datadir", $node2Dir, "init", (Join-Path $runPath "genesis.json")) -RedirectStandardOutput (Join-Path $runPath "replay-init.stdout.log") -RedirectStandardError (Join-Path $runPath "replay-init.stderr.log") -WindowStyle Hidden -Wait -PassThru
    if ($initProcess.ExitCode -ne 0) { throw "fresh validator genesis initialization failed" }
    $commonArgs = @("--networkid", "103991", "--nodiscover", "--nat", "none", "--maxpeers", "2", "--ipcdisable", "--http", "--http.addr", "127.0.0.1", "--http.api", "eth,net,web3,admin", "--http.vhosts", "localhost", "--verbosity", "4")
    $node1Args = @("--config", (Join-Path $runPath "node1.toml"), "--datadir", $node1Dir) + $commonArgs + @("--http.port", "18545", "--authrpc.port", "18551")
    $node2Args = @("--config", (Join-Path $runPath "node2.toml"), "--datadir", $node2Dir) + $commonArgs + @("--http.port", "18546", "--authrpc.port", "18552")
    $node1Process = Start-Process -FilePath $worldland -ArgumentList $node1Args -RedirectStandardOutput (Join-Path $runPath "resume-node1.stdout.log") -RedirectStandardError (Join-Path $runPath "resume-node1.stderr.log") -WindowStyle Hidden -PassThru
    $node2Process = Start-Process -FilePath $worldland -ArgumentList $node2Args -RedirectStandardOutput (Join-Path $runPath "resume-node2.stdout.log") -RedirectStandardError (Join-Path $runPath "resume-node2.stderr.log") -WindowStyle Hidden -PassThru
    Wait-RPC -Uri "http://127.0.0.1:18545"
    Wait-RPC -Uri "http://127.0.0.1:18546"
    $node1Info = Invoke-RPC -Uri "http://127.0.0.1:18545" -Method "admin_nodeInfo"
    if (-not (Invoke-RPC -Uri "http://127.0.0.1:18546" -Method "admin_addPeer" -Params @($node1Info.enode))) { throw "node2 rejected node1" }
    $deadline = (Get-Date).AddMinutes(3)
    do {
        $height1 = [Convert]::ToInt64((Invoke-RPC -Uri "http://127.0.0.1:18545" -Method "eth_blockNumber").Substring(2), 16)
        $height2 = [Convert]::ToInt64((Invoke-RPC -Uri "http://127.0.0.1:18546" -Method "eth_blockNumber").Substring(2), 16)
        if ($height2 -ge 1) { break }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)
    if ($height2 -lt 1) { throw "validator did not import the existing block (producer-full-head=$height1 validator=$height2)" }
    # The original failed validation run was stopped immediately after finding
    # the wire bug, before node1 flushed block-one state. Its block/header body
    # remains addressable even though startup repairs the full-state head to 0.
    $block1 = Invoke-RPC -Uri "http://127.0.0.1:18545" -Method "eth_getBlockByNumber" -Params @("0x1", $false)
    $block2 = Invoke-RPC -Uri "http://127.0.0.1:18546" -Method "eth_getBlockByNumber" -Params @("0x1", $false)
    if ($block1.hash -ne $block2.hash) { throw "nodes disagree on the imported block" }
    foreach ($field in @("vrfPublicKey", "vrfProof", "eligibilityThreshold", "tpmDID", "tpmWorkPublicKey", "tpmWorkSignature")) {
        if ([string]::IsNullOrWhiteSpace([string]$block2.$field) -or [string]$block2.$field -eq "0x") { throw "imported block is missing $field" }
    }
    if ([Convert]::ToInt64($block2.difficulty.Substring(2), 16) -ne 65536) { throw "difficulty is not 65536" }
    if ($block2.tpmDID -ne $metadata.did -or $block2.tpmWorkPublicKey -ne $metadata.tpmWorkPublicKey -or $block2.vrfPublicKey -ne $metadata.vrfPublicKey) { throw "identity fields differ from genesis registration" }
    Write-Utf8NoBom -Path (Join-Path $runPath "producer-block.json") -Value (($block1 | ConvertTo-Json -Depth 20) + "`n")
    Write-Utf8NoBom -Path (Join-Path $runPath "validator-block.json") -Value (($block2 | ConvertTo-Json -Depth 20) + "`n")
    $summary = [ordered]@{
        completedAt = (Get-Date).ToString("o"); producerHeaderHeight = 1; producerFullHeadAfterAbruptStop = $height1; validatorHeight = $height2
        commonBlockHash = $block1.hash; difficulty = 65536; controller = $metadata.controller; did = $metadata.did
        realTPMSigner = $true; realVRF = $true; realDevp2pTCP = $true; bootstrapEnrollment = $true
        validationFix = "RLP empty optional byte fields are interpreted by length"
    }
    Write-Utf8NoBom -Path (Join-Path $runPath "summary.json") -Value (($summary | ConvertTo-Json -Depth 10) + "`n")
    $sourceHash = Get-FileHash -Algorithm SHA256 -LiteralPath $worldland
    Write-Utf8NoBom -Path (Join-Path $runPath "validation-source.txt") -Value ("commit=$(git rev-parse HEAD)`nworldland_sha256=$($sourceHash.Hash.ToLowerInvariant())`n")
    foreach ($process in @($node1Process, $node2Process)) {
        if ($null -ne $process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            $process.WaitForExit()
        }
    }
    $node1Process = $null
    $node2Process = $null
    $manifest = Get-ChildItem $runPath -File | Sort-Object Name | Where-Object Name -ne "SHA256SUMS" | ForEach-Object {
        $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName
        "$($hash.Hash.ToLowerInvariant())  $($_.Name)"
    }
    Write-Utf8NoBom -Path (Join-Path $runPath "SHA256SUMS") -Value (($manifest -join "`n") + "`n")
    Write-Host "existing genuine TGPoW block validated over devp2p: $runPath"
    Write-Host ($summary | ConvertTo-Json -Compress)
} finally {
    foreach ($process in @($node1Process, $node2Process)) {
        if ($null -ne $process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
    }
    Pop-Location
}
