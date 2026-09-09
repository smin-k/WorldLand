param([Parameter(Mandatory=$true)][string]$Directory)
$ErrorActionPreference='Stop'
$blocks=@(Get-Content (Join-Path $Directory 'blocks.jsonl') | ConvertFrom-Json)
function Hex64([string]$value) { [Convert]::ToInt64($value.Substring(2),16) }
$intervals=@(for($i=2;$i -lt $blocks.Count;$i++) { (Hex64 $blocks[$i].timestamp)-(Hex64 $blocks[$i-1].timestamp) })
$q=@(foreach($block in $blocks|Select-Object -Skip 1) {
 $raw=[System.Numerics.BigInteger]::Parse('0'+$block.eligibilityThreshold.Substring(2),[System.Globalization.NumberStyles]::AllowHexSpecifier)
 [double]$raw/[math]::Pow(2,256)
})
[pscustomobject]@{
 Headers=$blocks.Count-1
 IntervalCount=$intervals.Count
 MeanSeconds=($intervals|Measure-Object -Average).Average
 MaxSeconds=($intervals|Measure-Object -Maximum).Maximum
 InitialBase=$q[0]
 MinimumBase=($q|Measure-Object -Minimum).Minimum
 MaximumBase=($q|Measure-Object -Maximum).Maximum
 Producers=@($blocks|Select-Object -Skip 1|Group-Object miner|ForEach-Object { [pscustomobject]@{Address=$_.Name;Blocks=$_.Count} })
 Note='One observed run. Genesis-to-first interval excluded. Base threshold is adaptive, not realized eligibility probability or wall-clock throughput.'
} | ConvertTo-Json -Depth 4
