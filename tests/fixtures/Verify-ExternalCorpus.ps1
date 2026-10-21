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
$missingReason = 'No matching metadata source was found.'
$structReason = 'TDH struct properties are retained as raw payload because nested layouts are not supported safely.'
$cases = @(
    @{ Name = 'primitive-types'; Input = $primitive; Options = @(); Mode = 'semantic_comparison_subset'; MinimumComparedRecords = 5; MinimumComparedFields = 55 }
    @{
        Name = 'gcevents-without-metadata'; Input = $gc; Options = @(); Mode = 'expected_metadata_missing'
        ExpectedInputSha256 = '5c10150fc9a321542135625b94dace3d4c33c1b47ea0a2f9e1a517927fd08f29'
        ExpectedRecords = 71
        ExpectedTuples = @(
            @{ Provider = '68fdd900-4a3e-11d1-84f4-0000f80464e3'; Status = 'metadata_missing'; Source = 'unknown'; Reason = $missingReason; Count = 2 }
            @{ Provider = 'e13c0d23-ccbc-4e12-931b-d9cc2eee27e4'; Status = 'metadata_missing'; Source = 'unknown'; Reason = $missingReason; Count = 69 }
        )
    }
    @{ Name = 'gcevents-with-manifest'; Input = $gc; Options = @('--manifest', $manifest); Mode = 'semantic_comparison_subset'; MinimumComparedRecords = 22; MinimumComparedFields = 49 }
    @{
        Name = 'self-describing'; Input = (Join-Path $downloads 'SelfDescribingSingleEvent.etl'); Options = @(); Mode = 'expected_unsupported_fallback'
        ExpectedInputSha256 = '4c312c63c7d366e12b908c49769943886c017497183733bc2c93b8d80e932c7c'
        ExpectedRecords = 23
        ExpectedTuples = @(
            @{ Provider = '68fdd900-4a3e-11d1-84f4-0000f80464e3'; Status = 'metadata_missing'; Source = 'unknown'; Reason = $missingReason; Count = 4 }
            @{ Provider = '9b79ee91-b5fd-41c0-a243-4248e266e9d0'; Status = 'metadata_missing'; Source = 'unknown'; Reason = $missingReason; Count = 15 }
            @{ Provider = 'ed54dff8-c409-4cf6-bf83-05e1e61a09c4'; Status = 'metadata_missing'; Source = 'unknown'; Reason = $missingReason; Count = 3 }
            @{ Provider = 'a61ea624-4944-55fc-c2a8-37838829438d'; Status = 'unsupported'; Source = 'trace_logging'; Reason = $structReason; Count = 1 }
        )
    }
    @{ Name = 'kernel-clr-with-manifest'; Input = $large; Options = @('--manifest', $manifest); Mode = 'semantic_comparison_subset'; MinimumComparedRecords = 17212; MinimumComparedFields = 50967 }
)

function Test-CaseOutcome([hashtable] $Case, [int] $Code, $Report, [string] $CaseOutput) {
    $errors = [Collections.Generic.List[string]]::new()
    function Assert-Contract([bool] $Condition, [string] $Message) {
        if (-not $Condition -and $errors.Count -lt 24) { $errors.Add($Message) }
    }
    $semanticCase = $Case.Mode -ceq 'semantic_comparison_subset'
    $result = [pscustomobject]@{
        Accepted = $false
        ValidationClass = $Case.Mode
        SemanticValidationCompleted = $false
        Errors = $errors
    }
    if ($null -eq $Report) {
        $errors.Add('No comparison report was produced.')
        return $result
    }
    Assert-Contract ($Report.exit_code -eq $Code) 'Report and process exit codes differ.'
    Assert-Contract ($Report.cli_exit_code -eq 0) 'The CLI did not finish successfully.'
    Assert-Contract ([string]::IsNullOrEmpty($Report.execution_error)) 'The harness reported an execution failure.'
    Assert-Contract ($null -ne $Report.raw.native_records -and $Report.raw.native_records -gt 0) 'No native records were validated.'
    Assert-Contract ($Report.raw.cli_records -eq $Report.raw.native_records) 'Native and CLI record counts differ.'
    Assert-Contract ($Report.raw.mismatched_records -eq 0) 'Native-to-CLI raw comparison failed.'
    Assert-Contract ($Report.semantic.mismatching_fields -eq 0) 'Semantic field mismatches were reported.'
    Assert-Contract ($Report.etl_sha256_before -ceq $Case.InputSha256) 'Report does not describe the selected input hash.'
    Assert-Contract ($Report.etl_sha256_after -ceq $Case.InputSha256) 'Input ETL changed during validation.'
    if ($semanticCase) {
        Assert-Contract ($Code -eq 0 -and $Report.outcome -ceq 'passed_with_limits') 'The semantic comparison case did not complete.'
        Assert-Contract ($Case.MinimumComparedRecords -gt 0 -and $Case.MinimumComparedFields -gt 0) 'Positive-case minimum coverage is not configured.'
        Assert-Contract ($null -ne $Report.semantic.compared_records -and $Report.semantic.compared_records -ge $Case.MinimumComparedRecords) "Compared-record coverage regressed: minimum $($Case.MinimumComparedRecords), observed $($Report.semantic.compared_records)."
        Assert-Contract ($null -ne $Report.semantic.compared_fields -and $Report.semantic.compared_fields -ge $Case.MinimumComparedFields) "Compared-field coverage regressed: minimum $($Case.MinimumComparedFields), observed $($Report.semantic.compared_fields)."
        $result.Accepted = $errors.Count -eq 0
        $result.SemanticValidationCompleted = $result.Accepted
        return $result
    }

    # These are explicit negative tests for known gaps, not permission to accept
    # any raw-only outcome. New providers/reasons/counts or an improvement to
    # decoded output require reviewing and updating this outcome contract.
    Assert-Contract ($Case.Mode -cin @('expected_metadata_missing', 'expected_unsupported_fallback')) 'Unknown expected-outcome mode.'
    Assert-Contract ($Code -eq 4 -and $Report.outcome -ceq 'raw_match_semantic_comparison_incomplete') 'Expected fallback was not an incomplete semantic comparison.'
    Assert-Contract ($Case.InputSha256 -ceq $Case.ExpectedInputSha256) 'Negative-test ETL differs from the pinned sample.'
    Assert-Contract ($Report.raw.native_records -eq $Case.ExpectedRecords) 'Negative-test native record count changed.'
    Assert-Contract ($Report.semantic.compared_fields -eq 0) 'Negative-test semantics changed; review it as a positive case.'
    $path = Join-Path $CaseOutput 'application.jsonl'
    Assert-Contract (Test-Path -LiteralPath $path) 'Negative-test application JSONL is missing.'
    if ($errors.Count -ne 0) { return $result }

    $tuples = @($Case.ExpectedTuples)
    $observed = @{}
    $expectedProviders = @{}
    for ($i = 0; $i -lt $tuples.Count; $i++) {
        $observed[$i] = 0L
        $tuple = $tuples[$i]
        if (-not $expectedProviders.ContainsKey($tuple.Provider)) {
            $expectedProviders[$tuple.Provider] = @{ Count = 0L; Statuses = @{}; Reasons = @{} }
        }
        $provider = $expectedProviders[$tuple.Provider]
        $provider.Count += $tuple.Count
        $provider.Statuses[$tuple.Status] += $tuple.Count
        $provider.Reasons[$tuple.Status + ': ' + $tuple.Reason] += $tuple.Count
    }
    $lineNumber = 0L
    $reader = $null
    try {
        $reader = [IO.File]::OpenText($path)
        while ($null -ne ($line = $reader.ReadLine())) {
            $lineNumber++
            if ($lineNumber -gt $Case.ExpectedRecords) {
                Assert-Contract $false 'Negative-test JSONL contains extra records.'
                break
            }
            $event = $line | ConvertFrom-Json
            $providerGuid = ([Guid] $event.event_header.provider_guid).ToString('D')
            $matched = $false
            for ($i = 0; $i -lt $tuples.Count; $i++) {
                $tuple = $tuples[$i]
                if ($providerGuid -ceq $tuple.Provider -and $event.decode_status -ceq $tuple.Status -and
                    $event.metadata_source -ceq $tuple.Source -and $event.decode_note -ceq $tuple.Reason) {
                    $observed[$i]++
                    $matched = $true
                    break
                }
            }
            Assert-Contract $matched "Unexpected fallback tuple at record ${lineNumber}: provider=$providerGuid; status=$($event.decode_status); source=$($event.metadata_source); reason=$($event.decode_note)"
        }
    } catch {
        Assert-Contract $false "Cannot validate negative-test JSONL: $($_.Exception.Message)"
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
    }
    Assert-Contract ($lineNumber -eq $Case.ExpectedRecords) 'Negative-test JSONL record count changed.'
    for ($i = 0; $i -lt $tuples.Count; $i++) {
        $tuple = $tuples[$i]
        Assert-Contract ($observed[$i] -eq $tuple.Count) "Fallback count changed for $($tuple.Provider)/$($tuple.Status): expected $($tuple.Count), observed $($observed[$i])."
    }
    Assert-Contract (@($Report.providers.PSObject.Properties).Count -eq $expectedProviders.Count) 'Report provider set changed.'
    foreach ($guid in $expectedProviders.Keys) {
        $expected = $expectedProviders[$guid]
        $actual = $Report.providers.PSObject.Properties[$guid].Value
        Assert-Contract ($null -ne $actual -and $actual.native_records -eq $expected.Count) "Report native count changed for $guid."
        foreach ($group in @(@{ Property = 'application_statuses'; Values = $expected.Statuses }, @{ Property = 'application_not_decoded_reasons'; Values = $expected.Reasons })) {
            $actualGroup = $actual.($group.Property)
            Assert-Contract (@($actualGroup.PSObject.Properties).Count -eq $group.Values.Count) "Report $($group.Property) set changed for $guid."
            foreach ($key in $group.Values.Keys) {
                Assert-Contract ($actualGroup.PSObject.Properties[$key].Value -eq $group.Values[$key]) "Report $($group.Property) count changed for ${guid}: $key."
            }
        }
    }
    $result.Accepted = $errors.Count -eq 0
    return $result
}

$results = @()
$failed = $false
foreach ($case in $cases) {
    $caseOutput = Join-Path $OutputDirectory $case.Name
    $arguments = @($VerifierDll, $ApplicationDll, $case.Input, $caseOutput)
    if ($case.Options.Count -gt 0) { $arguments += @('--') + $case.Options }
    $case.InputSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $case.Input).Hash.ToLowerInvariant()
    & $DotNetPath @arguments
    $code = $LASTEXITCODE
    $reportPath = Join-Path $caseOutput 'comparison.json'
    $report = if (Test-Path $reportPath) { Get-Content -Raw $reportPath | ConvertFrom-Json } else { $null }
    $contract = Test-CaseOutcome $case $code $report $caseOutput
    $acceptable = $contract.Accepted
    if (-not $acceptable) { $failed = $true }
    $results += @{
        case = $case.Name; exit_code = $code; validation_class = $contract.ValidationClass
        accepted_for_this_case = $acceptable; semantic_validation_completed = $contract.SemanticValidationCompleted
        contract_errors = @($contract.Errors); comparison = $report
    }
    if ($env:GITHUB_ACTIONS) {
        # Keep integrity, semantic coverage and failure details visible in the
        # check summary as well as in the complete validation artifact.
        $diagnostic = if ($report) {
            [ordered]@{
                outcome = $report.outcome
                validation_class = $contract.ValidationClass
                semantic_validation_completed = $contract.SemanticValidationCompleted
                contract_errors = @($contract.Errors)
                cli_exit_code = $report.cli_exit_code
                execution_error = $report.execution_error
                raw = $report.raw
                semantic = $report.semantic
                diagnostics = @($report.diagnostics | Where-Object phase -eq 'semantic' | Select-Object -First 8) + @($report.diagnostics | Where-Object phase -ne 'semantic' | Select-Object -First 4)
            } | ConvertTo-Json -Depth 12 -Compress
        } else { 'No comparison.json was produced.' }
        if ($diagnostic.Length -gt 16000) { $diagnostic = $diagnostic.Substring(0, 16000) + ' [see full artifact]' }
        $diagnostic = $diagnostic.Replace('%', '%25').Replace("`r", '%0D').Replace("`n", '%0A')
        $annotationType = if ($acceptable) { 'notice' } else { 'error' }
        Write-Output "::$annotationType title=External ETL $($case.Name)::exit_code=$code $diagnostic"
    }
}
$results | ConvertTo-Json -Depth 20 | Set-Content -Encoding utf8 (Join-Path $OutputDirectory 'corpus-results.json')
if ($env:GITHUB_STEP_SUMMARY) {
    Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value '## External ETL validation'
    Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value 'Raw integrity and semantic coverage are reported separately. Expected metadata-missing/unsupported cases assert exact provider/status/source/reason counts and raw preservation; they do not validate decoded values. Semantic cases compare only matched supported fields.'
    Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value '```json'
    Get-Content -Raw (Join-Path $OutputDirectory 'corpus-results.json') | Add-Content -Path $env:GITHUB_STEP_SUMMARY
    Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value '```'
}
if ($failed) { throw 'One or more external ETL checks failed; inspect corpus-results.json and each comparison report.' }
