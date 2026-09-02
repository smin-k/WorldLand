param(
    [string]$TPMKeyName = "WorldLand-TPM-Work-Test",
    [int]$TimeoutMinutes = 90,
    [switch]$SetupOnly
)

$ErrorActionPreference = "Stop"
$experimentDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $experimentDir "..\..")).Path
$artifactRoot = Join-Path $repoRoot "artifacts\tgpow-e2e"
$binaryDir = Join-Path $artifactRoot "bin"
$runStamp = Get-Date -Format "yyyyMMdd-HHmmss"
$runDir = Join-Path $artifactRoot "runs\$runStamp"
$node1Dir = Join-Path $runDir "node1"
$node2Dir = Join-Path $runDir "node2"
$worldland = Join-Path $binaryDir "worldland.exe"
$workbench = Join-Path $binaryDir "tpmworkbench.exe"
$genesisTool = Join-Path $binaryDir "tgpowtestnetgenesis.exe"
$privateKeyFile = Join-Path $experimentDir "test-miner.key"
$passwordFile = Join-Path $experimentDir "test-miner.password"
$chainID = "103991"
$node1RPC = "http://127.0.0.1:18545"
$node2RPC = "http://127.0.0.1:18546"
$node1Process = $null
$node2Process = $null

function Invoke-RPC {
    param([string]$Uri, [string]$Method, [object[]]$Params = @())
    $body = @{ jsonrpc = "2.0"; id = 1; method = $Method; params = $Params } | ConvertTo-Json -Depth 20 -Compress
    $response = Invoke-RestMethod -Uri $Uri -Method Post -ContentType "application/json" -Body $body -TimeoutSec 10
    if ($null -ne $response.error) {
        throw "RPC $Method failed: $($response.error | ConvertTo-Json -Compress)"
    }
    return $response.result
}

function Wait-RPC {
    param([string]$Uri, [datetime]$Deadline)
    while ((Get-Date) -lt $Deadline) {
        try {
            [void](Invoke-RPC -Uri $Uri -Method "web3_clientVersion")
            return
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    throw "RPC endpoint $Uri did not start"
}

function Write-Utf8NoBom {
    param([string]$Path, [string]$Value)
    [System.IO.File]::WriteAllText($Path, $Value, [System.Text.UTF8Encoding]::new($false))
}

function Invoke-LoggedProcess {
    param([string]$FilePath, [object[]]$Arguments, [string]$LogStem)
    $stdoutPath = "$LogStem.stdout.log"
    $stderrPath = "$LogStem.stderr.log"
    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -WindowStyle Hidden -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        $stderrText = Get-Content $stderrPath -Raw -ErrorAction SilentlyContinue
        throw "$FilePath exited with code $($process.ExitCode): $stderrText"
    }
}

New-Item -ItemType Directory -Force -Path $binaryDir | Out-Null
New-Item -ItemType Directory -Path $runDir, $node1Dir, $node2Dir | Out-Null

Push-Location $repoRoot
try {
    & go build -o $worldland ./cmd/worldland
    if ($LASTEXITCODE -ne 0) { throw "worldland build failed" }
    & go build -o $workbench ./cmd/tpmworkbench
    if ($LASTEXITCODE -ne 0) { throw "tpmworkbench build failed" }
    & go build -o $genesisTool ./cmd/tgpowtestnetgenesis
    if ($LASTEXITCODE -ne 0) { throw "genesis tool build failed" }

    $sourceFiles = @(
        "consensus/VCT/algorithm.go", "consensus/VCT/consensus.go", "consensus/VCT/sealer.go",
        "consensus/VCT/tpm_registry.go", "contracts/tpmregistry/predeploy.go",
        "core/types/block.go", "eth/backend.go", "miner/worker.go", "params/config.go",
        "cmd/tgpowtestnetgenesis/main.go", "experiments/tgpow-client-e2e/run-two-node.ps1"
    )
    $sourceState = @("commit=$(git rev-parse HEAD)", "go=$(go version)", "status:") + (git status --short) + @("sha256:")
    foreach ($relativePath in $sourceFiles) {
        $sourceHash = Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $repoRoot $relativePath)
        $sourceState += "$($sourceHash.Hash.ToLowerInvariant())  $relativePath"
    }
    foreach ($binaryPath in @($worldland, $workbench, $genesisTool)) {
        $binaryHash = Get-FileHash -Algorithm SHA256 -LiteralPath $binaryPath
        $sourceState += "$($binaryHash.Hash.ToLowerInvariant())  artifacts/tgpow-e2e/bin/$([IO.Path]::GetFileName($binaryPath))"
    }
    Write-Utf8NoBom -Path (Join-Path $runDir "source-state.txt") -Value (($sourceState -join "`n") + "`n")

    $probePath = Join-Path $runDir "tpm-probe.txt"
    $probeLines = & $workbench -key $TPMKeyName -n 1 -clients 1 2>&1
    if ($LASTEXITCODE -ne 0) { throw "read-only TPM work-key probe failed: $probeLines" }
    Write-Utf8NoBom -Path $probePath -Value (($probeLines -join "`n") + "`n")
    $publicKeyLine = $probeLines | Where-Object { $_ -match '^publicKey=([0-9a-fA-F]{130})$' } | Select-Object -First 1
    if ($null -eq $publicKeyLine) { throw "TPM probe did not return a 65-byte public key" }
    $tpmPublicKey = [regex]::Match([string]$publicKeyLine, '^publicKey=(.+)$').Groups[1].Value

    $genesisPath = Join-Path $runDir "genesis.json"
    $metadataPath = Join-Path $runDir "public-metadata.json"
    & $genesisTool -out $genesisPath -metadata $metadataPath -private-key-file $privateKeyFile -tpm-public-key $tpmPublicKey -chain-id $chainID
    if ($LASTEXITCODE -ne 0) { throw "test genesis generation failed" }
    $metadata = Get-Content $metadataPath -Raw | ConvertFrom-Json

    Invoke-LoggedProcess -FilePath $worldland -Arguments @("--datadir", $node1Dir, "init", $genesisPath) -LogStem (Join-Path $runDir "node1-init")
    Invoke-LoggedProcess -FilePath $worldland -Arguments @("--datadir", $node2Dir, "init", $genesisPath) -LogStem (Join-Path $runDir "node2-init")
    Invoke-LoggedProcess -FilePath $worldland -Arguments @("--datadir", $node1Dir, "--password", $passwordFile, "account", "import", $privateKeyFile) -LogStem (Join-Path $runDir "account-import")

    $node1Config = @"
[Node.P2P]
MaxPeers = 2
NoDiscovery = true
BootstrapNodes = []
StaticNodes = []
TrustedNodes = []
ListenAddr = "127.0.0.1:31303"
"@
    $node2Config = $node1Config.Replace("31303", "31304")
    $node1ConfigPath = Join-Path $runDir "node1.toml"
    $node2ConfigPath = Join-Path $runDir "node2.toml"
    Write-Utf8NoBom -Path $node1ConfigPath -Value $node1Config
    Write-Utf8NoBom -Path $node2ConfigPath -Value $node2Config

    if ($SetupOnly) {
        Write-Host "setup-only validation complete: $runDir"
        exit 0
    }

    $commonArgs = @("--networkid", $chainID, "--nodiscover", "--nat", "none", "--maxpeers", "2", "--ipcdisable", "--http", "--http.addr", "127.0.0.1", "--http.api", "eth,net,web3,admin,miner", "--http.vhosts", "localhost", "--verbosity", "4")
    $node1Args = @("--config", $node1ConfigPath, "--datadir", $node1Dir) + $commonArgs + @("--http.port", "18545", "--authrpc.port", "18551", "--allow-insecure-unlock", "--unlock", $metadata.controller, "--password", $passwordFile, "--mine", "--miner.threads", "1", "--miner.etherbase", $metadata.controller, "--miner.tpmkey", $TPMKeyName, "--miner.tpmdid", $metadata.did)
    $node2Args = @("--config", $node2ConfigPath, "--datadir", $node2Dir) + $commonArgs + @("--http.port", "18546", "--authrpc.port", "18552")

    $node1Process = Start-Process -FilePath $worldland -ArgumentList $node1Args -RedirectStandardOutput (Join-Path $runDir "node1.stdout.log") -RedirectStandardError (Join-Path $runDir "node1.stderr.log") -WindowStyle Hidden -PassThru
    $node2Process = Start-Process -FilePath $worldland -ArgumentList $node2Args -RedirectStandardOutput (Join-Path $runDir "node2.stdout.log") -RedirectStandardError (Join-Path $runDir "node2.stderr.log") -WindowStyle Hidden -PassThru

    $startupDeadline = (Get-Date).AddMinutes(2)
    Wait-RPC -Uri $node1RPC -Deadline $startupDeadline
    Wait-RPC -Uri $node2RPC -Deadline $startupDeadline
    $node1Info = Invoke-RPC -Uri $node1RPC -Method "admin_nodeInfo"
    if (-not (Invoke-RPC -Uri $node2RPC -Method "admin_addPeer" -Params @($node1Info.enode))) {
        throw "node2 rejected node1 as a static test peer"
    }

    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    $startedAt = Get-Date
    $peerCount = 0
    while ((Get-Date) -lt $deadline) {
        if ($node1Process.HasExited) { throw "node1 exited with code $($node1Process.ExitCode)" }
        if ($node2Process.HasExited) { throw "node2 exited with code $($node2Process.ExitCode)" }
        $peerCount = [Convert]::ToInt32((Invoke-RPC -Uri $node2RPC -Method "net_peerCount").Substring(2), 16)
        $height1 = [Convert]::ToInt64((Invoke-RPC -Uri $node1RPC -Method "eth_blockNumber").Substring(2), 16)
        $height2 = [Convert]::ToInt64((Invoke-RPC -Uri $node2RPC -Method "eth_blockNumber").Substring(2), 16)
        if ($height1 -ge 1 -and $height2 -ge $height1) { break }
        Start-Sleep -Seconds 2
    }
    $height1 = [Convert]::ToInt64((Invoke-RPC -Uri $node1RPC -Method "eth_blockNumber").Substring(2), 16)
    $height2 = [Convert]::ToInt64((Invoke-RPC -Uri $node2RPC -Method "eth_blockNumber").Substring(2), 16)
    if ($height1 -lt 1 -or $height2 -lt 1) { throw "timed out waiting for a mined and imported block (node1=$height1 node2=$height2)" }
    [void](Invoke-RPC -Uri $node1RPC -Method "miner_stop")
    $block1 = Invoke-RPC -Uri $node1RPC -Method "eth_getBlockByNumber" -Params @("latest", $false)
    $block2 = Invoke-RPC -Uri $node2RPC -Method "eth_getBlockByNumber" -Params @("latest", $false)
    if ($block1.hash -ne $block2.hash) { throw "nodes disagree on the latest block hash" }
    foreach ($field in @("vrfPublicKey", "vrfProof", "eligibilityThreshold", "tpmDID", "tpmWorkPublicKey", "tpmWorkSignature")) {
        if ([string]::IsNullOrWhiteSpace([string]$block2.$field) -or [string]$block2.$field -eq "0x") {
            throw "imported block is missing TGPoW field $field"
        }
    }
    if ([Convert]::ToInt64($block2.difficulty.Substring(2), 16) -ne 65536) {
        throw "imported block did not retain the production VCT minimum difficulty"
    }
    if ($block2.tpmDID -ne $metadata.did -or $block2.tpmWorkPublicKey -ne $metadata.tpmWorkPublicKey -or $block2.vrfPublicKey -ne $metadata.vrfPublicKey) {
        throw "imported block identity fields differ from the registered genesis identity"
    }
    Write-Utf8NoBom -Path (Join-Path $runDir "node1-latest-block.json") -Value (($block1 | ConvertTo-Json -Depth 20) + "`n")
    Write-Utf8NoBom -Path (Join-Path $runDir "node2-latest-block.json") -Value (($block2 | ConvertTo-Json -Depth 20) + "`n")

    $summary = [ordered]@{
        completedAt = (Get-Date).ToString("o")
        elapsedSeconds = [math]::Round(((Get-Date) - $startedAt).TotalSeconds, 3)
        chainId = $chainID
        peerCount = $peerCount
        producerHeight = $height1
        validatorHeight = $height2
        commonBlockHash = $block1.hash
        controller = $metadata.controller
        did = $metadata.did
        realTPMSigner = $true
        realVRF = $true
        realDevp2pTCP = $true
        bootstrapEnrollment = $true
        productionMinimumDifficulty = $true
    }
    Write-Utf8NoBom -Path (Join-Path $runDir "summary.json") -Value (($summary | ConvertTo-Json -Depth 10) + "`n")
    $manifest = Get-ChildItem $runDir -File | Sort-Object Name | ForEach-Object {
        $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName
        "$($hash.Hash.ToLowerInvariant())  $($_.Name)"
    }
    Write-Utf8NoBom -Path (Join-Path $runDir "SHA256SUMS") -Value (($manifest -join "`n") + "`n")
    Write-Host "TGPoW two-node E2E passed: $runDir"
    Write-Host ($summary | ConvertTo-Json -Compress)
} finally {
    foreach ($process in @($node1Process, $node2Process)) {
        if ($null -ne $process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Pop-Location
}
