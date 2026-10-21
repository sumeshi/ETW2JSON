[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $OutputDirectory,
    [string] $DotNetPath,
    [string] $ApplicationDll,
    [string] $VerifierDll
)

$ErrorActionPreference = 'Stop'
if (-not $DotNetPath) { $DotNetPath = (Get-Command dotnet -ErrorAction Stop).Source }
if (-not $ApplicationDll) { $ApplicationDll = Join-Path $PSScriptRoot '../../bin/Release/net10.0-windows/etw2json.dll' }
if (-not $VerifierDll) { $VerifierDll = Join-Path $PSScriptRoot '../ETW2JSON.NativeValidation/bin/Release/net10.0-windows/ETW2JSON.NativeValidation.dll' }
$ApplicationDll = [IO.Path]::GetFullPath($ApplicationDll)
$VerifierDll = [IO.Path]::GetFullPath($VerifierDll)
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path $OutputDirectory) { throw "Use a new output directory: $OutputDirectory" }
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$downloads = Join-Path $OutputDirectory 'downloads'
New-Item -ItemType Directory -Path $downloads | Out-Null

# MIT-licensed TraceEvent test inputs, pinned independently of repository HEAD.
$commit = '29b21620a6c295979e83dc99008262ad2f3c6a2d'
$base = "https://raw.githubusercontent.com/microsoft/perfview/$commit"
$inputs = 'src/TraceEvent/TraceEvent.Tests/inputs'
$files = @(
    @{ Name = 'primitive-types.etl.zip'; Path = "$inputs/primitive-types.etl.zip"; SHA256 = '7e1f6e04e23ba0fefa555cffa4142777b9f8c160c3ccd62cd8287b99c87838b7' }
    @{ Name = 'gcevents.etl.zip'; Path = "$inputs/gcevents.etl.zip"; SHA256 = 'f6edadb2aebc6ed2fc7a2adae4e6fc3f322c89df7acde97c626a95d8ff4dc6a9' }
    @{ Name = 'SelfDescribingSingleEvent.etl'; Path = "$inputs/Regression/SelfDescribingSingleEvent.etl"; SHA256 = '4c312c63c7d366e12b908c49769943886c017497183733bc2c93b8d80e932c7c' }
    @{ Name = 'net.4.5.x64.etl.zip'; Path = "$inputs/net.4.5.x64.etl.zip"; SHA256 = '71310652b20ec1b05e3ec183996dfe077b2bc66a83d14b310d28f74b3d56ed2d' }
    @{ Name = 'ClrEtwAll.man'; Path = 'src/TraceEvent/Parsers/ClrEtwAll.man'; SHA256 = '54a1895602e0a7d8c352ba5734c677bf7873c902c2463ffe89d1e8e6c4e45524' }
)
foreach ($file in $files) {
    $path = Join-Path $downloads $file.Name
    Invoke-WebRequest -Uri "$base/$($file.Path)" -OutFile $path
    if ((Get-FileHash -Algorithm SHA256 $path).Hash.ToLowerInvariant() -ne $file.SHA256) {
        throw "SHA-256 mismatch: $($file.Name)"
    }
    if ($file.Name.EndsWith('.zip')) {
        Expand-Archive -LiteralPath $path -DestinationPath (Join-Path $downloads $file.Name.Replace('.zip', ''))
    }
}
@{ repository = 'microsoft/perfview'; commit = $commit; license = "$base/LICENSE.TXT"; downloads = $files } |
    ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 (Join-Path $OutputDirectory 'corpus-provenance.json')

$gc = (Get-ChildItem -LiteralPath (Join-Path $downloads 'gcevents.etl') -Recurse -Filter '*.etl' | Select-Object -First 1).FullName
$primitive = (Get-ChildItem -LiteralPath (Join-Path $downloads 'primitive-types.etl') -Recurse -Filter '*.etl' | Select-Object -First 1).FullName
# The upstream x64 archive contains a file named net.4.5.x86.etl; use its actual name.
$large = (Get-ChildItem -LiteralPath (Join-Path $downloads 'net.4.5.x64.etl') -Recurse -Filter '*.etl' | Select-Object -First 1).FullName
$manifest = Join-Path $downloads 'ClrEtwAll.man'
$cases = @(
    @{ Name = 'primitive-types'; Input = $primitive; Options = @(); AllowRawOnly = $false }
    @{ Name = 'gcevents-without-metadata'; Input = $gc; Options = @(); AllowRawOnly = $true }
    @{ Name = 'gcevents-with-manifest'; Input = $gc; Options = @('--manifest', $manifest); AllowRawOnly = $false }
    @{ Name = 'self-describing'; Input = (Join-Path $downloads 'SelfDescribingSingleEvent.etl'); Options = @(); AllowRawOnly = $false }
    @{ Name = 'kernel-clr-with-manifest'; Input = $large; Options = @('--manifest', $manifest); AllowRawOnly = $false }
)
$results = @()
$failed = $false
foreach ($case in $cases) {
    $caseOutput = Join-Path $OutputDirectory $case.Name
    $arguments = @($VerifierDll, $ApplicationDll, $case.Input, $caseOutput)
    if ($case.Options.Count -gt 0) { $arguments += @('--') + $case.Options }
    & $DotNetPath @arguments
    $code = $LASTEXITCODE
    $acceptable = $code -eq 0 -or ($code -eq 4 -and $case.AllowRawOnly)
    if (-not $acceptable) { $failed = $true }
    $reportPath = Join-Path $caseOutput 'comparison.json'
    $report = if (Test-Path $reportPath) { Get-Content -Raw $reportPath | ConvertFrom-Json } else { $null }
    $results += @{ case = $case.Name; exit_code = $code; accepted_for_this_case = $acceptable; comparison = $report }
    if (-not $acceptable -and $env:GITHUB_ACTIONS) {
        # Surface the actual failure in the check annotations as well as the
        # artifact. Keep raw integrity failures and semantic coverage explicit.
        $diagnostic = if ($report) { $report | ConvertTo-Json -Depth 12 -Compress } else { 'No comparison.json was produced.' }
        if ($diagnostic.Length -gt 16000) { $diagnostic = $diagnostic.Substring(0, 16000) + ' [see full artifact]' }
        $diagnostic = $diagnostic.Replace('%', '%25').Replace("`r", '%0D').Replace("`n", '%0A')
        Write-Output "::error title=External ETL $($case.Name)::exit_code=$code $diagnostic"
    }
}
$results | ConvertTo-Json -Depth 20 | Set-Content -Encoding utf8 (Join-Path $OutputDirectory 'corpus-results.json')
if ($env:GITHUB_STEP_SUMMARY) {
    Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value '## External ETL validation'
    Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value 'Raw integrity and semantic coverage are reported separately. A raw-only case does not validate decoded values.'
    Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value '```json'
    Get-Content -Raw (Join-Path $OutputDirectory 'corpus-results.json') | Add-Content -Path $env:GITHUB_STEP_SUMMARY
    Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value '```'
}
if ($failed) { throw 'One or more external ETL checks failed; inspect corpus-results.json and each comparison report.' }
