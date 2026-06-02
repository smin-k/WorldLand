param(
    [int]$TargetBlock = 130,
    [int]$InitialSortitionThreshold = 256,
    [string]$OutRoot = "",
    [switch]$KeepRunning
)

$ErrorActionPreference = "Stop"

function Invoke-Rpc {
    param(
        [int]$Port,
        [string]$Method,
        [object[]]$Params = @()
    )
    $body = @{
        jsonrpc = "2.0"
        id      = 1
        method  = $Method
        params  = $Params
    } | ConvertTo-Json -Depth 20 -Compress
    $resp = Invoke-RestMethod -Uri "http://127.0.0.1:$Port" -Method Post -ContentType "application/json" -Body $body
    if ($resp.error) {
        throw "RPC $Method failed on port ${Port}: $($resp.error.message)"
    }
    return $resp.result
}

function Wait-Rpc {
    param([int]$Port)
    for ($i = 0; $i -lt 120; $i++) {
        try {
            [void](Invoke-Rpc -Port $Port -Method "web3_clientVersion")
            return
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    throw "RPC on port $Port did not become ready"
}

function Convert-HexToUInt64 {
    param([string]$Hex)
    if ([string]::IsNullOrWhiteSpace($Hex)) { return 0 }
    return [Convert]::ToUInt64($Hex.Replace("0x", ""), 16)
}

function Convert-HexToBigDecimal {
    param([string]$Hex)
    if ([string]::IsNullOrWhiteSpace($Hex)) { return "0" }
    $value = [System.Numerics.BigInteger]::Zero
    $digits = $Hex.Replace("0x", "")
    foreach ($ch in $digits.ToCharArray()) {
        $value = ($value * 16) + [Convert]::ToInt32($ch.ToString(), 16)
    }
    return $value.ToString()
}

function New-Account {
    param(
        [string]$Worldland,
        [string]$DataDir,
        [string]$PasswordFile
    )
    $stdout = Join-Path $DataDir "account-new.stdout.log"
    $stderr = Join-Path $DataDir "account-new.stderr.log"
    $p = Start-Process -FilePath $Worldland -ArgumentList @("--datadir", $DataDir, "--password", $PasswordFile, "account", "new") -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru -Wait
    $out = ((Get-Content -Raw $stdout -ErrorAction SilentlyContinue) + "`n" + (Get-Content -Raw $stderr -ErrorAction SilentlyContinue))
    if ($p.ExitCode -ne 0) {
        throw "account new failed: $out"
    }
    $match = [regex]::Match($out, "0x[a-fA-F0-9]{40}")
    if (!$match.Success) {
        throw "Could not parse account address from: $out"
    }
    return $match.Value.ToLowerInvariant()
}

function Get-VrfOutput {
    param(
        [string]$HelperExe,
        [string]$Proof
    )
    if ([string]::IsNullOrWhiteSpace($Proof) -or $Proof -eq "0x") {
        return @{ firstByte = $null; output = $null }
    }
    $out = & $HelperExe $Proof 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "VRF helper failed: $out"
    }
    return $out | ConvertFrom-Json
}

$repo = Split-Path $PSScriptRoot -Parent
if ([string]::IsNullOrWhiteSpace($OutRoot)) {
    $OutRoot = Join-Path $env:TEMP "worldland-rokis-runs"
}
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$runDir = Join-Path $OutRoot "rokis-2node-$stamp"
$nodeADir = Join-Path $runDir "node-a"
$nodeBDir = Join-Path $runDir "node-b"
$headersDir = Join-Path $runDir "headers"
$binDir = Join-Path $runDir "bin"
New-Item -ItemType Directory -Force -Path $nodeADir, $nodeBDir, $headersDir, $binDir | Out-Null

$worldland = Join-Path $binDir "worldland.exe"
$passwordFile = Join-Path $runDir "password.txt"
Set-Content -Path $passwordFile -Value "foobar" -NoNewline

Write-Host "Building worldland..."
Push-Location $repo
try {
    go build -o $worldland .\cmd\worldland
} finally {
    Pop-Location
}

Write-Host "Creating local miner accounts..."
$addrA = New-Account -Worldland $worldland -DataDir $nodeADir -PasswordFile $passwordFile
$addrB = New-Account -Worldland $worldland -DataDir $nodeBDir -PasswordFile $passwordFile

$allocA = $addrA.Replace("0x", "")
$allocB = $addrB.Replace("0x", "")
$genesisPath = Join-Path $runDir "rokis-genesis.json"
$genesis = @"
{
  "config": {
    "chainId": 10399,
    "homesteadBlock": 0,
    "daoForkSupport": true,
    "eip150Block": 0,
    "eip150Hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "eip155Block": 0,
    "eip158Block": 0,
    "byzantiumBlock": 0,
    "constantinopleBlock": 0,
    "petersburgBlock": 0,
    "istanbulBlock": 0,
    "berlinBlock": 0,
    "londonBlock": 0,
    "worldlandBlock": 0,
    "HalvingEndTime": 25228800,
    "seoulBlock": 0,
    "AnnapurnaBlock": 0,
    "vctBlock": 100,
    "vct": {
      "minEligibleBalance": 100000000000000000000,
      "initialSortitionThreshold": $InitialSortitionThreshold
    }
  },
  "nonce": "0x289f",
  "timestamp": "0x6821f0d0",
  "extraData": "0x576f726c646c616e6420526f6b6973206c6f63616c",
  "gasLimit": "0x1c9c380",
  "difficulty": "0x3ff",
  "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "coinbase": "0x0000000000000000000000000000000000000000",
  "alloc": {
    "$allocA": { "balance": "0x3635c9adc5dea00000" },
    "$allocB": { "balance": "0x3635c9adc5dea00000" }
  },
  "number": "0x0",
  "gasUsed": "0x0",
  "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "baseFeePerGas": null
}
"@
Set-Content -Path $genesisPath -Value $genesis

Write-Host "Initialising nodes..."
& $worldland --datadir $nodeADir init $genesisPath | Tee-Object -FilePath (Join-Path $runDir "init-a.log") | Out-Null
& $worldland --datadir $nodeBDir init $genesisPath | Tee-Object -FilePath (Join-Path $runDir "init-b.log") | Out-Null

$helperPath = Join-Path $runDir "vrfproofhash.go"
$helper = @"
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/cryptoecc/WorldLand/consensus/vct"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: vrfproofhash <hex-proof>")
	}
	raw := strings.TrimPrefix(os.Args[1], "0x")
	proof, err := hex.DecodeString(raw)
	if err != nil {
		panic(err)
	}
	out, err := vct.VRFOutputFromProof(proof)
	if err != nil {
		panic(err)
	}
	result := map[string]interface{}{
		"firstByte": int(out[0]),
		"output": "0x" + hex.EncodeToString(out[:]),
	}
	enc, _ := json.Marshal(result)
	fmt.Println(string(enc))
}
"@
Set-Content -Path $helperPath -Value $helper
$helperExe = Join-Path $runDir "vrfproofhash.exe"
Push-Location $repo
try {
    go build -o $helperExe $helperPath
} finally {
    Pop-Location
}

$nodeAOut = Join-Path $runDir "node-a.stdout.log"
$nodeAErr = Join-Path $runDir "node-a.stderr.log"
$nodeBOut = Join-Path $runDir "node-b.stdout.log"
$nodeBErr = Join-Path $runDir "node-b.stderr.log"

$commonArgs = @(
    "--networkid", "10399",
    "--syncmode", "full",
    "--gcmode", "archive",
    "--nodiscover",
    "--ipcdisable",
    "--maxpeers", "10",
    "--mine",
    "--miner.threads", "1",
    "--miner.recommit", "1s",
    "--password", $passwordFile,
    "--allow-insecure-unlock",
    "--http",
    "--http.addr", "127.0.0.1",
    "--http.api", "eth,net,web3,admin,miner,personal",
    "--http.vhosts", "*",
    "--verbosity", "3"
)

Write-Host "Starting node A ($addrA) and node B ($addrB)..."
$procA = Start-Process -FilePath $worldland -ArgumentList (@("--datadir", $nodeADir, "--port", "30313", "--http.port", "8545", "--authrpc.port", "8551", "--unlock", $addrA, "--miner.etherbase", $addrA) + $commonArgs) -RedirectStandardOutput $nodeAOut -RedirectStandardError $nodeAErr -WindowStyle Hidden -PassThru
$procB = Start-Process -FilePath $worldland -ArgumentList (@("--datadir", $nodeBDir, "--port", "30314", "--http.port", "8546", "--authrpc.port", "8552", "--unlock", $addrB, "--miner.etherbase", $addrB) + $commonArgs) -RedirectStandardOutput $nodeBOut -RedirectStandardError $nodeBErr -WindowStyle Hidden -PassThru

$headersJsonl = Join-Path $runDir "headers.jsonl"
$summaryCsv = Join-Path $runDir "summary.csv"
$metaPath = Join-Path $runDir "run-meta.json"
$rows = New-Object System.Collections.Generic.List[object]
$seen = @{}
$lastTimes = @{}

try {
    Wait-Rpc -Port 8545
    Wait-Rpc -Port 8546

    $nodeBInfo = Invoke-Rpc -Port 8546 -Method "admin_nodeInfo"
    [void](Invoke-Rpc -Port 8545 -Method "admin_addPeer" -Params @($nodeBInfo.enode))
    Write-Host "Peer added: $($nodeBInfo.enode)"

    $meta = [ordered]@{
        runDir      = $runDir
        targetBlock = $TargetBlock
        nodeA       = @{ address = $addrA; rpc = 8545; p2p = 30313 }
        nodeB       = @{ address = $addrB; rpc = 8546; p2p = 30314 }
        genesis     = $genesisPath
    }
    $meta | ConvertTo-Json -Depth 10 | Set-Content -Path $metaPath

    while ($true) {
        $headA = Convert-HexToUInt64 (Invoke-Rpc -Port 8545 -Method "eth_blockNumber")
        $headB = Convert-HexToUInt64 (Invoke-Rpc -Port 8546 -Method "eth_blockNumber")
        $head = [Math]::Min($headA, $headB)
        Write-Host ("head A={0} B={1}, dumping through {2}" -f $headA, $headB, $head)

        for ($n = 0; $n -le $head; $n++) {
            if ($seen.ContainsKey($n)) { continue }
            $hexNum = "0x{0:x}" -f $n
            $block = Invoke-Rpc -Port 8545 -Method "eth_getBlockByNumber" -Params @($hexNum, $false)
            if ($null -eq $block) { continue }

            $rawPath = Join-Path $headersDir ("block-{0:D6}.json" -f $n)
            $block | ConvertTo-Json -Depth 30 | Set-Content -Path $rawPath

            $timestamp = Convert-HexToUInt64 $block.timestamp
            $parentTime = $null
            $deltaT = $null
            if ($n -gt 0 -and $lastTimes.ContainsKey($n - 1)) {
                $parentTime = $lastTimes[$n - 1]
                $deltaT = $timestamp - $parentTime
            }
            $lastTimes[$n] = $timestamp

            $miner = [string]$block.miner
            $winner = "unknown"
            if ($miner.ToLowerInvariant() -eq $addrA) { $winner = "nodeA" }
            if ($miner.ToLowerInvariant() -eq $addrB) { $winner = "nodeB" }

            $vrf = @{ firstByte = $null; output = $null }
            if ($block.PSObject.Properties.Name -contains "vrfProof") {
                $vrf = Get-VrfOutput -HelperExe $helperExe -Proof $block.vrfProof
            }

            $threshold = 0
            if ($block.PSObject.Properties.Name -contains "sortitionThreshold") {
                $threshold = Convert-HexToBigDecimal $block.sortitionThreshold
            }

            $row = [ordered]@{
                number              = $n
                hash                = $block.hash
                parentHash          = $block.parentHash
                phase               = $(if ($n -ge 100) { "VCT" } else { "pre-VCT" })
                miner               = $miner
                winner              = $winner
                timestamp           = $timestamp
                deltaT              = $deltaT
                difficultyHex       = $block.difficulty
                difficulty          = Convert-HexToBigDecimal $block.difficulty
                sortitionThreshold  = $threshold
                vrfOutputFirstByte  = $vrf.firstByte
                vrfOutput           = $vrf.output
                hasVRFProof         = -not [string]::IsNullOrWhiteSpace($block.vrfProof) -and $block.vrfProof -ne "0x"
                hasVRFSignature     = -not [string]::IsNullOrWhiteSpace($block.vrfSignature) -and $block.vrfSignature -ne "0x"
                rawHeaderFile       = $rawPath
            }
            ($row | ConvertTo-Json -Depth 10 -Compress) | Add-Content -Path $headersJsonl
            $rows.Add([pscustomobject]$row) | Out-Null
            $seen[$n] = $true
        }

        if ($head -ge $TargetBlock) { break }
        Start-Sleep -Seconds 5
    }

    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $summaryCsv
    Write-Host "Done."
    Write-Host "Run dir: $runDir"
    Write-Host "Headers JSONL: $headersJsonl"
    Write-Host "Summary CSV: $summaryCsv"
} finally {
    if (!$KeepRunning) {
        foreach ($p in @($procA, $procB)) {
            if ($p -and !$p.HasExited) {
                Stop-Process -Id $p.Id -Force
            }
        }
    } else {
        Write-Host "Nodes left running: A pid=$($procA.Id), B pid=$($procB.Id)"
    }
}
