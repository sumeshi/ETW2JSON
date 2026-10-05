# ETW2JSON

ETW2JSON converts Windows ETL files to JSONL or legacy JSON. This forensic
extension continues Microsoft's C# implementation, reusing `OpenTrace`, `ProcessTrace`, and TDH on Windows with .NET 10.

## Changes from Microsoft ETW2JSON

Compared with the [original implementation](https://github.com/microsoft/ETW2JSON/tree/4d145bf61e9daad98a58166ae8d220577eaf51bc):

An ETL acquired from another Windows installation may need provider metadata
absent from the analysis host. This fork accepts recovered schemas and records
their origin, while preserving events that cannot be decoded.

| Original behavior | Change | Result |
| --- | --- | --- |
| TDH resolution could use host registration without recording its origin. | Record schema provenance; host registration is available only through explicit `--allow-local-metadata` opt-in. | Default decoding uses ETL-embedded or explicitly supplied evidence schemas; local schemas remain a final fallback. |
| No CLI options to supply recovered manifests, PE resources, or publisher hints. | Added `--manifest`, static `--resource`, and `--provider-info`. | Recovered `.man`/PE schemas can be supplied; publisher XML guides recovery. |
| Unknown-event fallback set ID/version to 0 and omitted raw payload. | Preserve original header values, raw payload, and decode status. | Unsupported or unresolved events retain their identity and bytes for later analysis. |
| Nested JSON output only; no preflight scan/report. | Added JSONL, `--scan`, and `--report-missing`. | Events stream as lines; missing metadata can be inventoried. |
| Output opened with truncation semantics. | Existing outputs and evidence aliases are rejected. | Conversion does not overwrite an existing file or truncate its input. |

The existing reader, TDH integration, EventSource metadata, and custom parsers
remain the basis of decoding; this work adds explicit provenance and evidence
handling around them.

## Use

Publishing a GitHub Release tagged `vX.Y.Z` (or `vX.Y.Z-beta.1`) builds and
attaches a Windows x64 ZIP with `etw2json.exe`; no .NET installation is required.

```powershell
dotnet restore ETW2JSON.sln --locked-mode
dotnet build ETW2JSON.sln -c Release --no-restore

etw2json trace.etl --output trace.jsonl
etw2json trace.etl --format json --output trace.json
etw2json trace.etl --scan
etw2json trace.etl --report-missing

# Explicitly allow analysis-host provider metadata as a final fallback
etw2json trace.etl --allow-local-metadata --output trace.jsonl
```

Use `bin\Release\net10.0-windows\etw2json.exe` for `etw2json` above.
`--allow-local-metadata` is off by default. Use it when analyzing a live ETL
collected on this host; it does not detect that situation automatically or
start/consume a real-time ETW session.

JSONL is recommended. Supply recovered metadata explicitly; `--manifest`,
`--resource`, and `--provider-info` are repeatable:

```powershell
etw2json trace.etl --provider-info provider.xml `
  --manifest schema.man --resource provider.dll --output trace.jsonl
```

## Recover provider metadata

On a live evidence system, inspect the provider key and export publisher XML
as UTF-8. Substitute the GUID and registered name from the ETL or `wevtutil ep`:

```powershell
$guid = '{00000000-0000-0000-0000-000000000000}'
$key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\$guid"
Get-ItemProperty $key | Select-Object ResourceFileName, MessageFileName, ParameterFileName
wevtutil gp 'Microsoft-Windows-Example' /ge:true /gm:false /f:xml |
  Set-Content -Encoding utf8 .\provider.xml
```

Recover the referenced `ResourceFileName`, `MessageFileName`, and
`ParameterFileName` DLL/EXE/SYS files from the evidence Windows installation.
For disk images, inspect the SOFTWARE hive/filesystem with forensic tools.
Never load the hive or expand paths with the analysis host; verify files against
the evidence installation.

`--provider-info` uses `wevtutil` XML only for publisher names and candidate
paths, not as a payload schema. Use the original `.man` with `--manifest` or an
extracted provider PE with `--resource` to provide event schemas.

## Output and limits

Events retain headers, source, `metadata_source`, `decode_status`, and Base64
`raw_payload`; undecodable events remain. `timestamp` is raw ETW clock, not UTC;
`raw_timestamp` and trace-clock details are preserved.

Host provider registrations are not used by default. `--allow-local-metadata`
enables them as a final fallback after embedded and supplied evidence schemas.
Events decoded through this fallback are labeled `local_cache`. Without the
flag, events requiring only local schemas remain undecoded. The option does not
verify that host metadata matches the acquisition system.
Evidence DLL/EXE/SYS files are parsed as data, never loaded or
executed. WPP is unsupported and
classic/MOF coverage is limited. The reader supports a subset of CRIM 3.1/5.1;
map-dependent records and unsupported arrays/structures are reported. Broad
Windows compatibility and Microsoft reference equivalence remain unvalidated.

## Validate

```powershell
dotnet test ETW2JSON.sln -c Release --no-build
```

For a native ETW smoke test, run this in elevated Windows PowerShell at the
repository root:

```powershell
.\tests\fixtures\Verify-EventSourceFixture.ps1
```

The script emits repository-owned EventSource and TraceLogging events through a
temporary ETW session, checks manifest/static PE/scan/missing-report behavior,
then removes the session. Generated ETL files remain local.

Microsoft attribution and the MIT license are retained in [LICENSE](LICENSE).
