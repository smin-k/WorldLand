param(
    [int]$NodeCount = 4,
    [int]$TargetBlock = 180,
    [int]$InitialSortitionThreshold = 256,
    [int]$MinerThreads = 1,
    [string]$OutRoot = "",
    [switch]$KeepRunning
)

$ErrorActionPreference = "Stop"

function Invoke-Rpc {
    param([int]$Port, [string]$Method, [object[]]$Params = @())
    $body = @{ jsonrpc = "2.0"; id = 1; method = $Method; params = $Params } | ConvertTo-Json -Depth 20 -Compress
    $resp = Invoke-RestMethod -Uri "http://127.0.0.1:$Port" -Method Post -ContentType "application/json" -Body $body
    if ($resp.error) { throw "RPC $Method failed on port ${Port}: $($resp.error.message)" }
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
    foreach ($ch in $Hex.Replace("0x", "").ToCharArray()) {
        $value = ($value * 16) + [Convert]::ToInt32($ch.ToString(), 16)
    }
    return $value.ToString()
}

function New-Account {
    param([string]$Worldland, [string]$DataDir, [string]$PasswordFile)
    $stdout = Join-Path $DataDir "account-new.stdout.log"
    $stderr = Join-Path $DataDir "account-new.stderr.log"
    $p = Start-Process -FilePath $Worldland -ArgumentList @("--datadir", $DataDir, "--password", $PasswordFile, "account", "new") -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru -Wait
    $out = ((Get-Content -Raw $stdout -ErrorAction SilentlyContinue) + "`n" + (Get-Content -Raw $stderr -ErrorAction SilentlyContinue))
    if ($p.ExitCode -ne 0) { throw "account new failed: $out" }
    $match = [regex]::Match($out, "0x[a-fA-F0-9]{40}")
    if (!$match.Success) { throw "Could not parse account address from: $out" }
    return $match.Value.ToLowerInvariant()
}

function Get-VrfOutput {
    param([string]$HelperExe, [string]$Proof)
    if ([string]::IsNullOrWhiteSpace($Proof) -or $Proof -eq "0x") {
        return @{ firstByte = $null; output = $null }
    }
    $out = & $HelperExe $Proof 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "VRF helper failed: $out" }
    return $out | ConvertFrom-Json
}

if ($NodeCount -lt 1) { throw "NodeCount must be >= 1" }

$repo = Split-Path $PSScriptRoot -Parent
if ([string]::IsNullOrWhiteSpace($OutRoot)) {
    $OutRoot = Join-Path $env:TEMP "worldland-rokis-runs"
}
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$runDir = Join-Path $OutRoot "rokis-${NodeCount}node-$stamp"
$headersDir = Join-Path $runDir "headers"
$binDir = Join-Path $runDir "bin"
New-Item -ItemType Directory -Force -Path $headersDir, $binDir | Out-Null

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

$nodes = @()
Write-Host "Creating $NodeCount local miner accounts..."
for ($i = 0; $i -lt $NodeCount; $i++) {
    $nodeDir = Join-Path $runDir ("node-{0:D2}" -f $i)
    New-Item -ItemType Directory -Force -Path $nodeDir | Out-Null
    $addr = New-Account -Worldland $worldland -DataDir $nodeDir -PasswordFile $passwordFile
    $nodes += [pscustomobject]@{
        Index = $i
        Name = "node$($i + 1)"
        Dir = $nodeDir
        Address = $addr
        HttpPort = 8545 + $i
        AuthPort = 8551 + $i
        P2PPort = 30313 + $i
        Stdout = Join-Path $runDir ("node-{0:D2}.stdout.log" -f $i)
        Stderr = Join-Path $runDir ("node-{0:D2}.stderr.log" -f $i)
        Process = $null
    }
}

$allocEntries = @()
foreach ($n in $nodes) {
    $allocEntries += ('    "{0}": {{ "balance": "0x3635c9adc5dea00000" }}' -f $n.Address.Replace("0x", ""))
}
$allocJson = $allocEntries -join ",`n"
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
  "extraData": "0x576f726c646c616e6420526f6b6973206e6e6f6465",
  "gasLimit": "0x1c9c380",
  "difficulty": "0x3ff",
  "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "coinbase": "0x0000000000000000000000000000000000000000",
  "alloc": {
$allocJson
  },
  "number": "0x0",
  "gasUsed": "0x0",
  "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "baseFeePerGas": null
}
"@
Set-Content -Path $genesisPath -Value $genesis

Write-Host "Initialising nodes..."
foreach ($n in $nodes) {
    & $worldland --datadir $n.Dir init $genesisPath | Tee-Object -FilePath (Join-Path $runDir ("init-{0:D2}.log" -f $n.Index)) | Out-Null
}

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
	raw := strings.TrimPrefix(os.Args[1], "0x")
	proof, err := hex.DecodeString(raw)
	if err != nil { panic(err) }
	out, err := vct.VRFOutputFromProof(proof)
	if err != nil { panic(err) }
	enc, _ := json.Marshal(map[string]interface{}{"firstByte": int(out[0]), "output": "0x" + hex.EncodeToString(out[:])})
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

$commonArgs = @(
    "--networkid", "10399",
    "--syncmode", "full",
    "--gcmode", "archive",
    "--nodiscover",
    "--ipcdisable",
    "--maxpeers", ([Math]::Max(10, $NodeCount * 2)).ToString(),
    "--mine",
    "--miner.threads", $MinerThreads.ToString(),
    "--miner.recommit", "1s",
    "--password", $passwordFile,
    "--allow-insecure-unlock",
    "--http",
    "--http.addr", "127.0.0.1",
    "--http.api", "eth,net,web3,admin,miner,personal",
    "--http.vhosts", "*",
    "--verbosity", "3"
)

Write-Host "Starting $NodeCount nodes..."
foreach ($n in $nodes) {
    $args = @(
        "--datadir", $n.Dir,
        "--port", $n.P2PPort.ToString(),
        "--http.port", $n.HttpPort.ToString(),
        "--authrpc.port", $n.AuthPort.ToString(),
        "--unlock", $n.Address,
        "--miner.etherbase", $n.Address
    ) + $commonArgs
    $n.Process = Start-Process -FilePath $worldland -ArgumentList $args -RedirectStandardOutput $n.Stdout -RedirectStandardError $n.Stderr -WindowStyle Hidden -PassThru
}

$headersJsonl = Join-Path $runDir "headers.jsonl"
$summaryCsv = Join-Path $runDir "summary.csv"
$metaPath = Join-Path $runDir "run-meta.json"
$rows = New-Object System.Collections.Generic.List[object]
$seen = @{}
$lastTimes = @{}
$addressToName = @{}
foreach ($n in $nodes) { $addressToName[$n.Address] = $n.Name }

try {
    foreach ($n in $nodes) { Wait-Rpc -Port $n.HttpPort }
    $basePort = $nodes[0].HttpPort
    for ($i = 1; $i -lt $nodes.Count; $i++) {
        $info = Invoke-Rpc -Port $nodes[$i].HttpPort -Method "admin_nodeInfo"
        [void](Invoke-Rpc -Port $basePort -Method "admin_addPeer" -Params @($info.enode))
    }
    Write-Host "Peers added to $($nodes[0].Name)."

    $meta = [ordered]@{
        runDir = $runDir
        nodeCount = $NodeCount
        targetBlock = $TargetBlock
        initialSortitionThreshold = $InitialSortitionThreshold
        minerThreads = $MinerThreads
        nodes = @($nodes | ForEach-Object { @{ name = $_.Name; address = $_.Address; rpc = $_.HttpPort; p2p = $_.P2PPort } })
        genesis = $genesisPath
    }
    $meta | ConvertTo-Json -Depth 10 | Set-Content -Path $metaPath

    while ($true) {
        $heads = @()
        foreach ($n in $nodes) {
            $heads += Convert-HexToUInt64 (Invoke-Rpc -Port $n.HttpPort -Method "eth_blockNumber")
        }
        $head = ($heads | Measure-Object -Minimum).Minimum
        Write-Host ("heads [{0}], dumping through {1}" -f (($heads -join ",")), $head)

        for ($blockNum = 0; $blockNum -le $head; $blockNum++) {
            if ($seen.ContainsKey($blockNum)) { continue }
            $hexNum = "0x{0:x}" -f $blockNum
            $block = Invoke-Rpc -Port $basePort -Method "eth_getBlockByNumber" -Params @($hexNum, $false)
            if ($null -eq $block) { continue }

            $rawPath = Join-Path $headersDir ("block-{0:D6}.json" -f $blockNum)
            $block | ConvertTo-Json -Depth 30 | Set-Content -Path $rawPath

            $timestamp = Convert-HexToUInt64 $block.timestamp
            $deltaT = $null
            if ($blockNum -gt 0 -and $lastTimes.ContainsKey($blockNum - 1)) {
                $deltaT = $timestamp - $lastTimes[$blockNum - 1]
            }
            $lastTimes[$blockNum] = $timestamp

            $miner = ([string]$block.miner).ToLowerInvariant()
            $winner = "unknown"
            if ($addressToName.ContainsKey($miner)) { $winner = $addressToName[$miner] }

            $vrf = @{ firstByte = $null; output = $null }
            if ($block.PSObject.Properties.Name -contains "vrfProof") {
                $vrf = Get-VrfOutput -HelperExe $helperExe -Proof $block.vrfProof
            }
            $threshold = 0
            if ($block.PSObject.Properties.Name -contains "sortitionThreshold") {
                $threshold = Convert-HexToBigDecimal $block.sortitionThreshold
            }

            $row = [ordered]@{
                number = $blockNum
                hash = $block.hash
                parentHash = $block.parentHash
                phase = $(if ($blockNum -ge 100) { "VCT" } else { "pre-VCT" })
                miner = $miner
                winner = $winner
                timestamp = $timestamp
                deltaT = $deltaT
                difficultyHex = $block.difficulty
                difficulty = Convert-HexToBigDecimal $block.difficulty
                sortitionThreshold = $threshold
                vrfOutputFirstByte = $vrf.firstByte
                vrfOutput = $vrf.output
                hasVRFProof = -not [string]::IsNullOrWhiteSpace($block.vrfProof) -and $block.vrfProof -ne "0x"
                hasVRFSignature = -not [string]::IsNullOrWhiteSpace($block.vrfSignature) -and $block.vrfSignature -ne "0x"
                rawHeaderFile = $rawPath
            }
            ($row | ConvertTo-Json -Depth 10 -Compress) | Add-Content -Path $headersJsonl
            $rows.Add([pscustomobject]$row) | Out-Null
            $seen[$blockNum] = $true
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
        foreach ($n in $nodes) {
            if ($n.Process -and !$n.Process.HasExited) {
                Stop-Process -Id $n.Process.Id -Force
            }
        }
    } else {
        foreach ($n in $nodes) {
            Write-Host "$($n.Name) left running: pid=$($n.Process.Id)"
        }
    }
}
