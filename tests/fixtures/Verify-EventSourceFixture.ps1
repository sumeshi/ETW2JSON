[CmdletBinding()]
param(
    [string] $OutputDirectory,
    [string] $DotNetPath,
    [string] $EmitterDll,
    [string] $ResourceDll,
    [string] $ApplicationDll,
    [switch] $SkipEmitterBuild,
    [ValidateRange(1, 10000)]
    [int] $Count = 4
)

$ErrorActionPreference = "Stop"
if (-not $OutputDirectory) { $OutputDirectory = Join-Path (Join-Path $PSScriptRoot "generated") ([Guid]::NewGuid().ToString("N")) }
if (-not $ApplicationDll) { $ApplicationDll = Join-Path $PSScriptRoot "../../bin/Release/net10.0-windows/etw2json.dll" }
if (-not $DotNetPath) { $DotNetPath = (Get-Command dotnet -ErrorAction Stop).Source }
$dotnet = [IO.Path]::GetFullPath($DotNetPath)
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$ApplicationDll = [IO.Path]::GetFullPath($ApplicationDll)
if (-not (Test-Path $ApplicationDll)) { throw "Build the CLI first; assembly not found: $ApplicationDll" }

$etl = Join-Path $OutputDirectory "etw2json-eventsource.etl"
$eventSourceGuid = "e41f4c57-9a82-4e2d-8b31-c7fb7b930001"
$eventWriteGuid = "9ab0e68d-70c1-4e5a-938c-1390a31a0002"
$traceLoggingGuid = "4c5b5fd0-7bb4-457a-ad3f-6da89e7f0003"
$eventWriteManifest = Join-Path $OutputDirectory "etw2json-eventwrite.man"
$generatorProject = Join-Path $PSScriptRoot "EventSourceFixture/ETW2JSON.FixtureEmitter.csproj"
$logman = Join-Path $env:SystemRoot "System32/logman.exe"
if (-not (Test-Path $logman)) { throw "logman.exe was not found at $logman" }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
if (Test-Path $etl) { throw "Refusing to overwrite an existing generated ETL. Use a new output directory: $etl" }
if (-not $SkipEmitterBuild) {
    & $dotnet build $generatorProject -c Release
    if ($LASTEXITCODE -ne 0) { throw "Fixture emitter build failed with exit code $LASTEXITCODE" }
}
if (-not $EmitterDll) { $EmitterDll = Join-Path (Split-Path $generatorProject) "bin/Release/net10.0-windows/ETW2JSON.FixtureEmitter.dll" }
$EmitterDll = [IO.Path]::GetFullPath($EmitterDll)
if (-not (Test-Path $EmitterDll)) { throw "Fixture emitter was not found: $EmitterDll" }
$eventSourceManifest = Join-Path $OutputDirectory "etw2json-eventsource.man"
$eventWriteManifestSource = Join-Path $PSScriptRoot "eventwrite-provider.man"
& $dotnet $EmitterDll --manifest-only $eventSourceManifest $eventWriteManifestSource $eventWriteManifest
if ($LASTEXITCODE -ne 0) { throw "Manifest generation failed with exit code $LASTEXITCODE" }
$eventWritePe = $ResourceDll
if (-not $eventWritePe) {
    $eventWritePe = Join-Path $OutputDirectory "etw2json-synthetic-provider.dll"
    & $dotnet $EmitterDll --generate-pe $eventWritePe
    if ($LASTEXITCODE -ne 0) { throw "Synthetic PE generation failed with exit code $LASTEXITCODE" }
}
$eventWritePe = [IO.Path]::GetFullPath($eventWritePe)
$providerListPath = Join-Path $OutputDirectory "providers.txt"
@(
    "{e41f4c57-9a82-4e2d-8b31-c7fb7b930001} 0xffffffffffffffff 5"
    "{9ab0e68d-70c1-4e5a-938c-1390a31a0002} 0xffffffffffffffff 5"
    "{4c5b5fd0-7bb4-457a-ad3f-6da89e7f0003} 0xffffffffffffffff 5"
) | Set-Content -Encoding ascii $providerListPath
$sessionName = "ETW2JSONFixture_$([Guid]::NewGuid().ToString('N'))"
$sessionStarted = $false
try {
    & $logman create trace $sessionName -o $etl -pf $providerListPath -ets
    if ($LASTEXITCODE -ne 0) { throw "logman could not start the ETW fixture session (exit code $LASTEXITCODE). Run in an elevated PowerShell." }
    $sessionStarted = $true
    & $dotnet $EmitterDll --emit --count $Count
    if ($LASTEXITCODE -ne 0) { throw "Fixture event emission failed with exit code $LASTEXITCODE" }
    & $logman stop $sessionName -ets
    if ($LASTEXITCODE -ne 0) { throw "logman could not stop the ETW fixture session (exit code $LASTEXITCODE)" }
    $sessionStarted = $false
}
finally {
    if ($sessionStarted) { & $logman stop $sessionName -ets | Out-Null }
}
$beforeHash = (Get-FileHash -Algorithm SHA256 $etl).Hash
$records = @(1..$Count | ForEach-Object {
    @{ sequence = $_; correlation = ("00000000-0000-0000-0000-{0:x12}" -f $_) }
})
$expected = @{
    providers = @(
        @{
            provider_guid = $eventSourceGuid; event_id = 1; expected_event_count = $Count
            properties = @(@{ name = "sequence"; type = "Int32" }, @{ name = "message"; type = "UnicodeString" }, @{ name = "correlation"; type = "GUID" })
            records = @($records | ForEach-Object { @{ sequence = $_.sequence; message = "fixture-record-$($_.sequence)"; correlation = $_.correlation } })
            manifest = "etw2json-eventsource.man"
        }
        @{
            provider_guid = $eventWriteGuid; event_id = 1; version = 1; expected_event_count = $Count
            properties = @(@{ name = "sequence"; type = "Int32" }, @{ name = "message"; type = "UnicodeString" }, @{ name = "correlation"; type = "GUID" })
            records = @($records | ForEach-Object { @{ sequence = $_.sequence; message = "manifest-record-$($_.sequence)"; correlation = ("10000000-0000-0000-0000-{0:x12}" -f $_.sequence) } })
            manifest = "etw2json-eventwrite.man"
        }
        @{
            provider_guid = $traceLoggingGuid; expected_event_count = ($Count * 2); event_names = @("TLAlpha", "TLBeta")
            event_schemas = @(
                @{ name = "TLAlpha"; properties = @(@{ name = "sequence"; type = "Int32" }, @{ name = "message"; type = "UnicodeString" }) }
                @{ name = "TLBeta"; properties = @(@{ name = "sequence"; type = "Int32" }, @{ name = "correlation"; type = "GUID" }) }
            )
            manifest = $null
        }
    )
    note = "EventSource may emit provider/control records; count each provider's event id 1 separately."
}
$expected | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 (Join-Path $OutputDirectory "etw2json-eventsource.expected.json")
$sdkList = (& $dotnet --list-sdks 2>$null | Out-String).Trim()
if (-not $sdkList) { $sdkList = "No .NET SDK installed on the ETL collection host." }
$runtimeList = (& $dotnet --list-runtimes 2>$null | Out-String).Trim()
$generation = @{
    generated_utc = [DateTime]::UtcNow.ToString("o")
    provider_guid = $eventSourceGuid
    manifest_provider_guid = $eventWriteGuid
    tracelogging_provider_guid = $traceLoggingGuid
    os_version = [Environment]::OSVersion.VersionString
    dotnet_sdks = $sdkList
    dotnet_runtimes = $runtimeList
    emitter_source = "tests/fixtures/EventSourceFixture/Program.cs"
    event_count = $Count
    etl_sha256 = $beforeHash.ToLowerInvariant()
    manifest_sha256 = (Get-FileHash -Algorithm SHA256 $eventSourceManifest).Hash.ToLowerInvariant()
    eventwrite_manifest_sha256 = (Get-FileHash -Algorithm SHA256 $eventWriteManifest).Hash.ToLowerInvariant()
    provider_list_sha256 = (Get-FileHash -Algorithm SHA256 $providerListPath).Hash.ToLowerInvariant()
    license = "MIT; generated by repository-owned source; no third-party evidence binaries"
}
$generation | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 (Join-Path $OutputDirectory "generation.json")

function Assert-True([bool] $condition, [string] $message) {
    if (-not $condition) { throw "Smoke validation failed: $message" }
}

function Invoke-Cli([string[]] $arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $dotnet
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $allArguments = @($ApplicationDll) + $arguments
    $start.Arguments = (($allArguments | ForEach-Object { '"' + $_ + '"' }) -join ' ')
    $process = [Diagnostics.Process]::Start($start)
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    return [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = $stdout; Stderr = $stderr }
}

function Read-JsonLines([string] $path) {
    $result = [Collections.Generic.List[object]]::new()
    foreach ($line in [IO.File]::ReadLines($path)) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            $result.Add(($line | ConvertFrom-Json))
        }
    }
    return ,$result.ToArray()
}

function Assert-ProviderCount($events, [string] $guid, [int] $eventId, [int] $version, [int] $expected) {
    $matches = @($events | Where-Object {
        $_.provider_guid -eq $guid -and $_.event_id -eq $eventId -and $_.version -eq $version
    })
    Assert-True ($matches.Count -eq $expected) "provider $guid event $eventId/$version count $($matches.Count), expected $expected"
    return ,$matches
}

$defaultPath = Join-Path $OutputDirectory "default.jsonl"
$manifestPath = Join-Path $OutputDirectory "with-manifest.jsonl"
$legacyPath = Join-Path $OutputDirectory "legacy.json"
$scanDefaultPath = Join-Path $OutputDirectory "scan-default.json"
$scanManifestPath = Join-Path $OutputDirectory "scan-manifest.json"
$reportPath = Join-Path $OutputDirectory "missing-report.json"
$reportManifestPath = Join-Path $OutputDirectory "resolved-report.json"

$run = Invoke-Cli @($etl, "--output", $defaultPath)
Assert-True ($run.ExitCode -eq 0) "default JSONL conversion failed: $($run.Stderr)"
$defaultEvents = Read-JsonLines $defaultPath
$eventSourceEvents = Assert-ProviderCount $defaultEvents $eventSourceGuid 1 0 $Count
$eventWriteMissing = Assert-ProviderCount $defaultEvents $eventWriteGuid 1 1 $Count
$traceLoggingEvents = @($defaultEvents | Where-Object { $_.provider_guid -eq $traceLoggingGuid })
Assert-True ($traceLoggingEvents.Count -eq ($Count * 2)) "TraceLogging record count was $($traceLoggingEvents.Count), expected $($Count * 2)"
$traceAlpha = @($traceLoggingEvents | Where-Object { $_.event_name -match "(^|/)TLAlpha(/|$)" })
$traceBeta = @($traceLoggingEvents | Where-Object { $_.event_name -match "(^|/)TLBeta(/|$)" })
Assert-True ($traceAlpha.Count -eq $Count -and $traceBeta.Count -eq $Count) "TraceLogging schema cache did not distinguish TLAlpha and TLBeta"
foreach ($event in $traceAlpha) {
    $sequence = [int]$event.properties.sequence
    Assert-True ($event.properties.message -eq "trace-alpha-$sequence") "TraceLogging TLAlpha schema/value mismatch"
    Assert-True ($event.metadata_source -eq "trace_logging" -and $event.decode_status -eq "decoded") "TraceLogging TLAlpha provenance/status mismatch"
    Assert-True ($event.source_file -eq $etl -and -not [string]::IsNullOrWhiteSpace($event.raw_payload)) "TraceLogging TLAlpha source/raw fields missing"
}
foreach ($event in $traceBeta) {
    $sequence = [int]$event.properties.sequence
    Assert-True ($event.properties.correlation -eq ("20000000-0000-0000-0000-{0:x12}" -f $sequence)) "TraceLogging TLBeta schema/value mismatch"
    Assert-True ($event.metadata_source -eq "trace_logging" -and $event.decode_status -eq "decoded") "TraceLogging TLBeta provenance/status mismatch"
    Assert-True ($event.source_file -eq $etl -and -not [string]::IsNullOrWhiteSpace($event.raw_payload)) "TraceLogging TLBeta source/raw fields missing"
}
$alphaSequences = @($traceAlpha | ForEach-Object { [int]$_.properties.sequence } | Sort-Object)
$betaSequences = @($traceBeta | ForEach-Object { [int]$_.properties.sequence } | Sort-Object)
Assert-True (($alphaSequences -join ",") -eq ((1..$Count) -join ",")) "TraceLogging TLAlpha sequence set mismatch"
Assert-True (($betaSequences -join ",") -eq ((1..$Count) -join ",")) "TraceLogging TLBeta sequence set mismatch"

foreach ($event in $eventSourceEvents) {
    $sequence = [int]$event.properties.sequence
    Assert-True ($sequence -ge 1 -and $sequence -le $Count) "EventSource sequence out of range"
    Assert-True ($event.properties.message -eq "fixture-record-$sequence") "EventSource message mismatch"
    Assert-True ($event.decode_status -eq "decoded" -and $event.metadata_source -eq "embedded") "EventSource metadata provenance/status mismatch"
    Assert-True ($event.source_file -eq $etl) "EventSource source_file mismatch"
    Assert-True (-not [string]::IsNullOrWhiteSpace($event.raw_payload)) "EventSource raw payload missing"
}
Assert-True ((@($eventSourceEvents | ForEach-Object { [int]$_.properties.sequence } | Sort-Object) -join ",") -eq ((1..$Count) -join ",")) "EventSource sequence set mismatch"
foreach ($event in $eventWriteMissing) {
    Assert-True ($event.decode_status -eq "metadata_missing") "EventWrite event unexpectedly decoded without schema"
    Assert-True (-not [string]::IsNullOrWhiteSpace($event.raw_payload)) "Missing-schema EventWrite payload was dropped"
}

$run = Invoke-Cli @($etl, "--manifest", $eventWriteManifest, "--output", $manifestPath)
Assert-True ($run.ExitCode -eq 0) "manifest-backed conversion failed: $($run.Stderr)"
$manifestEvents = Read-JsonLines $manifestPath
$eventWriteDecoded = Assert-ProviderCount $manifestEvents $eventWriteGuid 1 1 $Count
$missingPayloadBySequence = @{}
foreach ($event in $eventWriteMissing) {
    $bytes = [Convert]::FromBase64String($event.raw_payload)
    $missingPayloadBySequence[[BitConverter]::ToInt32($bytes, 0)] = $event.raw_payload
}
foreach ($event in $eventWriteDecoded) {
    $sequence = [int]$event.properties.sequence
    Assert-True ($event.decode_status -eq "decoded") "EventWrite metadata status was $($event.decode_status)"
    Assert-True ($event.metadata_source -eq "external_manifest") "EventWrite metadata source was $($event.metadata_source)"
    Assert-True ($event.properties.message -eq "manifest-record-$sequence") "EventWrite message mismatch"
    Assert-True ($event.properties.correlation -eq ("10000000-0000-0000-0000-{0:x12}" -f $sequence)) "EventWrite GUID mismatch"
    Assert-True ($event.source_file -eq $etl) "EventWrite source_file mismatch"
    Assert-True (-not [string]::IsNullOrWhiteSpace($event.raw_payload)) "Decoded EventWrite raw payload missing"
}
Assert-True ((@($eventWriteDecoded | ForEach-Object { [int]$_.properties.sequence } | Sort-Object) -join ",") -eq ((1..$Count) -join ",")) "manifest EventWrite sequence set mismatch"
Assert-True ((@($eventWriteMissing | ForEach-Object { $_.raw_payload }) -join "|") -eq (@($eventWriteDecoded | ForEach-Object { $_.raw_payload }) -join "|")) "raw EventWrite bytes changed when a manifest was supplied"

$resourcePath = Join-Path $OutputDirectory "with-resource.jsonl"
$run = Invoke-Cli @($etl, "--resource", $eventWritePe, "--output", $resourcePath)
Assert-True ($run.ExitCode -eq 0) "PE-resource conversion failed: $($run.Stderr)"
$resourceEvents = Read-JsonLines $resourcePath
$eventWriteResource = Assert-ProviderCount $resourceEvents $eventWriteGuid 1 1 $Count
foreach ($event in $eventWriteResource) {
    $sequence = [int]$event.properties.sequence
    Assert-True ($event.decode_status -eq "decoded" -and $event.metadata_source -eq "external_pe_resource") "PE metadata provenance/status mismatch"
    Assert-True ($event.properties.message -eq "manifest-record-$sequence") "PE decoded message mismatch"
    Assert-True ($event.properties.correlation -eq ("10000000-0000-0000-0000-{0:x12}" -f $sequence)) "PE decoded GUID mismatch"
    Assert-True ($event.raw_payload -eq $missingPayloadBySequence[$sequence]) "raw EventWrite data changed during PE decode"
}
Assert-True ((@($eventWriteResource | ForEach-Object { [int]$_.properties.sequence } | Sort-Object) -join ",") -eq ((1..$Count) -join ",")) "PE EventWrite sequence set mismatch"

$run = Invoke-Cli @($etl, "--manifest", $eventWriteManifest, "--format", "json", "--output", $legacyPath)
Assert-True ($run.ExitCode -eq 0) "legacy JSON conversion failed: $($run.Stderr)"
$legacyEvents = (Get-Content -Raw $legacyPath | ConvertFrom-Json).Events
$legacyManifestEvents = @($legacyEvents | ForEach-Object { $_.Event } | Where-Object { $_.ProviderGuid -eq $eventWriteGuid })
Assert-True ($legacyManifestEvents.Count -eq $Count) "legacy JSON EventWrite count mismatch"
Assert-True ($legacyManifestEvents[0].metadata_source -eq "external_manifest") "legacy metadata_source missing"
Assert-True ($legacyManifestEvents[0].source_file -eq $etl) "legacy source_file missing"
Assert-True (-not [string]::IsNullOrWhiteSpace($legacyManifestEvents[0].raw_payload)) "legacy raw_payload missing"
Assert-True ($legacyManifestEvents[0].metadata_provenance -like "man:*") "legacy metadata provenance missing"

$run = Invoke-Cli @($etl, "--scan", "--format", "json", "--output", $scanDefaultPath)
Assert-True ($run.ExitCode -eq 0) "scan without manifest failed: $($run.Stderr)"
$scanDefault = Get-Content -Raw $scanDefaultPath | ConvertFrom-Json
$scanUnresolved = @($scanDefault.Providers | Where-Object { $_.provider_guid -eq $eventWriteGuid } | ForEach-Object { $_.events } | Where-Object { $_.event_id -eq 1 -and $_.version -eq 1 })
Assert-True ($scanUnresolved.Count -eq 1 -and $scanUnresolved[0].count -eq $Count -and $scanUnresolved[0].metadata_status -eq "Missing") "scan did not report missing EventWrite metadata/count"
$scanTraceEvents = @($scanDefault.Providers | Where-Object { $_.provider_guid -eq $traceLoggingGuid } | ForEach-Object { $_.events })
foreach ($event in @($traceAlpha[0], $traceBeta[0])) {
    $scanTrace = @($scanTraceEvents | Where-Object { $_.event_id -eq $event.event_id -and $_.version -eq $event.version })
    Assert-True ($scanTrace.Count -eq 1 -and $scanTrace[0].count -eq $Count -and $scanTrace[0].metadata_status -eq "Resolved") "scan TraceLogging count/status mismatch for $($event.event_name)"
}

$run = Invoke-Cli @($etl, "--scan", "--format", "json", "--manifest", $eventWriteManifest, "--output", $scanManifestPath)
Assert-True ($run.ExitCode -eq 0) "scan with manifest failed: $($run.Stderr)"
$scanManifest = Get-Content -Raw $scanManifestPath | ConvertFrom-Json
$scanResolved = @($scanManifest.Providers | Where-Object { $_.provider_guid -eq $eventWriteGuid } | ForEach-Object { $_.events } | Where-Object { $_.event_id -eq 1 -and $_.version -eq 1 })
Assert-True ($scanResolved.Count -eq 1 -and $scanResolved[0].count -eq $Count -and $scanResolved[0].metadata_status -eq "Resolved") "scan did not report manifest-backed EventWrite resolution/count"

$scanResourcePath = Join-Path $OutputDirectory "scan-resource.json"
$run = Invoke-Cli @($etl, "--scan", "--format", "json", "--resource", $eventWritePe, "--output", $scanResourcePath)
Assert-True ($run.ExitCode -eq 0) "resource scan failed: $($run.Stderr)"
$scanResource = Get-Content -Raw $scanResourcePath | ConvertFrom-Json
$scanResourceEvents = @($scanResource.Providers | Where-Object { $_.provider_guid -eq $eventWriteGuid } | ForEach-Object { $_.events } | Where-Object { $_.event_id -eq 1 -and $_.version -eq 1 })
Assert-True ($scanResourceEvents.Count -eq 1 -and $scanResourceEvents[0].count -eq $Count -and $scanResourceEvents[0].metadata_status -eq "Resolved") "scan did not report PE-backed EventWrite resolution/count"

$run = Invoke-Cli @($etl, "--report-missing", "--format", "json", "--output", $reportPath)
Assert-True ($run.ExitCode -eq 0) "missing metadata report failed: $($run.Stderr)"
$missing = Get-Content -Raw $reportPath | ConvertFrom-Json
Assert-True (@($missing.Missing | Where-Object { $_.provider_guid -eq $eventWriteGuid -and $_.event_id -eq 1 -and $_.version -eq 1 -and $_.count -eq $Count }).Count -eq 1) "missing report lacks EventWrite GUID/event/version/count"

$run = Invoke-Cli @($etl, "--report-missing", "--format", "json", "--manifest", $eventWriteManifest, "--output", $reportManifestPath)
Assert-True ($run.ExitCode -eq 0) "resolved metadata report failed: $($run.Stderr)"
$resolved = Get-Content -Raw $reportManifestPath | ConvertFrom-Json
Assert-True (@($resolved.Missing | Where-Object { $_.provider_guid -eq $eventWriteGuid -and $_.event_id -eq 1 -and $_.version -eq 1 }).Count -eq 0) "resolved report still contains the EventWrite record"

$resourceReportPath = Join-Path $OutputDirectory "resource-report.json"
$run = Invoke-Cli @($etl, "--report-missing", "--format", "json", "--resource", $eventWritePe, "--output", $resourceReportPath)
Assert-True ($run.ExitCode -eq 0) "PE-backed missing metadata report failed: $($run.Stderr)"
$resourceReport = Get-Content -Raw $resourceReportPath | ConvertFrom-Json
Assert-True (@($resourceReport.Missing | Where-Object { $_.provider_guid -eq $eventWriteGuid -and $_.event_id -eq 1 -and $_.version -eq 1 }).Count -eq 0) "PE-backed report still lists the EventWrite record as missing"

$run = Invoke-Cli @($etl, "--output", $etl)
Assert-True ($run.ExitCode -eq 2) "same-input output overwrite was not rejected (exit $($run.ExitCode))"
$afterHash = (Get-FileHash -Algorithm SHA256 $etl).Hash
Assert-True ($afterHash -eq $beforeHash) "the source ETL hash changed during the smoke run"

Write-Host "ETW2JSON Windows smoke passed for $Count records per manifest/EventSource provider and $($Count * 2) TraceLogging records."
