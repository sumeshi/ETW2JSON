[CmdletBinding()]
param()

# Exercise the production outcome assertions without downloading fixtures,
# launching the CLI, or invoking Windows ETW APIs. All generated data is local
# to this invocation's temporary directory and is removed even after failure.
$ErrorActionPreference = 'Stop'
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('ETW2JSON-CorpusContracts-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temporaryRoot) > $null
try {
    $path = Join-Path $PSScriptRoot 'Verify-ExternalCorpus.ps1'
    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref] $tokens, [ref] $parseErrors)
    if ($parseErrors.Count) { throw ($parseErrors.Message -join '; ') }
    $function = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-CaseOutcome' }, $true)
    if ($null -eq $function) { throw 'Test-CaseOutcome was not found in the corpus wrapper.' }
    Invoke-Expression $function.Extent.Text
    # Import only the literal case configuration and the assertion function. The
    # wrapper's downloads, CLI invocation and native comparison body are never run.
    foreach ($name in @('$missingReason', '$structReason')) {
        $constant = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq $name }, $true)
        if ($null -eq $constant) { throw "Corpus configuration constant not found: $name" }
        Invoke-Expression $constant.Extent.Text
    }
    $gc = Join-Path $temporaryRoot 'gcevents.etl'
    $primitive = Join-Path $temporaryRoot 'primitive.etl'
    $manifest = Join-Path $temporaryRoot 'provider.man'
    $downloads = $temporaryRoot
    $large = Join-Path $temporaryRoot 'large.etl'
    $assignment = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$cases' }, $true)
    if ($null -eq $assignment) { throw 'The corpus case definitions were not found.' }
    Invoke-Expression $assignment.Extent.Text
    $checks = 0

    function New-SyntheticCase([hashtable] $Case) {
        $Case.InputSha256 = $Case.ExpectedInputSha256
        $directory = Join-Path $temporaryRoot ([Guid]::NewGuid().ToString('N'))
        [IO.Directory]::CreateDirectory($directory) > $null
        $lines = [Collections.Generic.List[string]]::new()
        $providers = @{}
        foreach ($tuple in $Case.ExpectedTuples) {
            if (-not $providers.ContainsKey($tuple.Provider)) {
                $providers[$tuple.Provider] = @{ native_records = 0L; application_statuses = @{}; application_not_decoded_reasons = @{} }
            }
            $provider = $providers[$tuple.Provider]
            $provider.native_records += $tuple.Count
            $provider.application_statuses[$tuple.Status] += $tuple.Count
            $provider.application_not_decoded_reasons[$tuple.Status + ': ' + $tuple.Reason] += $tuple.Count
            for ($i = 0; $i -lt $tuple.Count; $i++) {
                $lines.Add((@{ event_header = @{ provider_guid = $tuple.Provider }; decode_status = $tuple.Status; metadata_source = $tuple.Source; decode_note = $tuple.Reason } | ConvertTo-Json -Depth 5 -Compress))
            }
        }
        $report = @{
            exit_code = 4; cli_exit_code = 0; execution_error = $null
            outcome = 'raw_match_semantic_comparison_incomplete'
            etl_sha256_before = $Case.InputSha256; etl_sha256_after = $Case.InputSha256
            raw = @{ native_records = $Case.ExpectedRecords; cli_records = $Case.ExpectedRecords; mismatched_records = 0 }
            semantic = @{ compared_fields = 0; mismatching_fields = 0 }; providers = $providers
        } | ConvertTo-Json -Depth 12 | ConvertFrom-Json
        return [pscustomobject]@{ Case = $Case; Directory = $directory; Report = $report; Lines = $lines }
    }

    function Invoke-Synthetic($Sample, [int] $Code = 4) {
        [IO.File]::WriteAllLines((Join-Path $Sample.Directory 'application.jsonl'), $Sample.Lines)
        return Test-CaseOutcome $Sample.Case $Code $Sample.Report $Sample.Directory
    }

    foreach ($case in @($cases[1], $cases[3])) {
        $sample = New-SyntheticCase $case
        $result = Invoke-Synthetic $sample
        if (-not $result.Accepted -or $result.SemanticValidationCompleted) { throw "Expected negative contract was not accepted with semantic=false: $($result.Errors -join '; ')" }
        $checks++
    }

    function Assert-Rejected([scriptblock] $Mutate, [int] $Code = 4) {
        $sample = New-SyntheticCase $cases[3]
        & $Mutate $sample
        $result = Invoke-Synthetic $sample $Code
        if ($result.Accepted -or $result.Errors.Count -eq 0) { throw 'A changed fallback contract was accepted.' }
        $script:checks++
    }

    Assert-Rejected { param($s) $s.Report.raw.mismatched_records = 1 }
    Assert-Rejected { param($s) $s.Report.raw.native_records = 22; $s.Report.raw.cli_records = 22 }
    Assert-Rejected { param($s) $s.Report.cli_exit_code = 3 }
    Assert-Rejected { param($s) $s.Report.etl_sha256_after = 'changed' }
    Assert-Rejected { param($s) $s.Report.etl_sha256_before = 'wrong input' }
    Assert-Rejected { param($s) $s.Report.execution_error = 'callback failure' }
    Assert-Rejected { param($s) $s.Report.semantic.compared_fields = 1 }
    Assert-Rejected { param($s) $s.Report.semantic.mismatching_fields = 1 }
    Assert-Rejected { param($s) $s.Report.exit_code = 0; $s.Report.outcome = 'passed_with_limits' } 0
    Assert-Rejected { param($s) $s.Lines.RemoveAt($s.Lines.Count - 1) }
    Assert-Rejected { param($s) $s.Lines.Add($s.Lines[0]) }
    Assert-Rejected { param($s) $e=$s.Lines[-1]|ConvertFrom-Json; $e.decode_note='A different unsupported reason'; $s.Lines[$s.Lines.Count-1]=$e|ConvertTo-Json -Depth 5 -Compress }
    Assert-Rejected { param($s) $e=$s.Lines[-1]|ConvertFrom-Json; $e.metadata_source='unknown'; $s.Lines[$s.Lines.Count-1]=$e|ConvertTo-Json -Depth 5 -Compress }
    Assert-Rejected { param($s) $e=$s.Lines[-1]|ConvertFrom-Json; $e.event_header.provider_guid='00000000-0000-0000-0000-000000000001'; $s.Lines[$s.Lines.Count-1]=$e|ConvertTo-Json -Depth 5 -Compress }
    Assert-Rejected { param($s) $e=$s.Lines[-1]|ConvertFrom-Json; $e.decode_status='metadata_missing'; $s.Lines[$s.Lines.Count-1]=$e|ConvertTo-Json -Depth 5 -Compress }
    Assert-Rejected { param($s) $s.Lines[$s.Lines.Count-1]='not JSON' }
    Assert-Rejected { param($s) $s.Report.providers.'a61ea624-4944-55fc-c2a8-37838829438d'.application_statuses.unsupported = 2 }
    Assert-Rejected { param($s) $s.Report.providers.'a61ea624-4944-55fc-c2a8-37838829438d'.application_not_decoded_reasons | Add-Member -NotePropertyName '{other reason variants}' -NotePropertyValue 1 }
    Assert-Rejected { param($s) $s.Report.providers | Add-Member -NotePropertyName '00000000-0000-0000-0000-000000000001' -NotePropertyValue ([pscustomobject]@{}) }

    $positive = $cases[0]
    $positive.InputSha256 = 'selected hash'
    $report = @{ exit_code=0; cli_exit_code=0; execution_error=$null; outcome='passed_with_limits'; etl_sha256_before=$positive.InputSha256; etl_sha256_after=$positive.InputSha256; raw=@{native_records=7;cli_records=7;mismatched_records=0}; semantic=@{compared_records=$positive.MinimumComparedRecords;compared_fields=$positive.MinimumComparedFields;mismatching_fields=0} } | ConvertTo-Json -Depth 6 | ConvertFrom-Json
    $result = Test-CaseOutcome $positive 0 $report $temporaryRoot
    if (-not $result.Accepted -or -not $result.SemanticValidationCompleted) { throw "Positive semantic case rejected: $($result.Errors -join '; ')" }; $checks++
    $report.semantic.compared_records = $positive.MinimumComparedRecords - 1
    if ((Test-CaseOutcome $positive 0 $report $temporaryRoot).Accepted) { throw 'Compared-record coverage regression was accepted.' }; $checks++
    $report.semantic.compared_records = $positive.MinimumComparedRecords
    $report.semantic.compared_fields = $positive.MinimumComparedFields - 1
    if ((Test-CaseOutcome $positive 0 $report $temporaryRoot).Accepted) { throw 'Compared-field coverage regression was accepted.' }; $checks++
    $report.semantic.compared_fields = $positive.MinimumComparedFields
    $report.semantic.mismatching_fields = 15082
    if ((Test-CaseOutcome $positive 0 $report $temporaryRoot).Accepted) { throw 'Semantic mismatches were accepted.' }; $checks++
    $report.semantic.mismatching_fields=0; $report.semantic.compared_fields=0
    if ((Test-CaseOutcome $positive 0 $report $temporaryRoot).Accepted) { throw 'A zero-field positive case was accepted.' }; $checks++
    if ((Test-CaseOutcome $cases[3] 4 $null $temporaryRoot).Accepted) { throw 'A missing report was accepted.' }; $checks++
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) { [IO.Directory]::Delete($temporaryRoot, $true) }
}
Write-Output "$checks corpus contract checks passed; no downloads or native ETL processing were performed."
