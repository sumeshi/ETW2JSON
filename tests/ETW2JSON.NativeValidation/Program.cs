using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing;

namespace ETW2JSON.NativeValidation;

internal static class Program
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = false,
    };

    private static async Task<int> Main(string[] args)
    {
        if (args is ["--self-check"]) return SelfChecks.Run();
        if (args.Length < 3 || (args.Length > 3 && args[3] != "--"))
        {
            Console.Error.WriteLine("Usage: ETW2JSON.NativeValidation <application.dll> <trace.etl> <new-output-directory> [-- <metadata-options>...]");
            return 1;
        }
        string application = Path.GetFullPath(args[0]);
        string etl = Path.GetFullPath(args[1]);
        string directory = Path.GetFullPath(args[2]);
        if (!OperatingSystem.IsWindows() || IntPtr.Size != 8)
        {
            Console.Error.WriteLine("Native validation requires Windows x64; restore/build alone does not execute validation.");
            return 3;
        }
        if (!File.Exists(application) || !File.Exists(etl) || Directory.Exists(directory) || File.Exists(directory))
        {
            Console.Error.WriteLine("Application/ETL must exist and the output directory must be new.");
            return 1;
        }

        Directory.CreateDirectory(directory);
        var report = new ComparisonReport
        {
            Application = application,
            Etl = etl,
            ReferenceAssembly = typeof(TraceEvent).Assembly.FullName ?? "TraceEvent 4.0.0",
            ApplicationArguments = args.Skip(4).ToArray(),
        };
        int exitCode = 3;
        try
        {
            report.EtlSha256Before = HashFile(etl);
            report.ApplicationSha256 = HashFile(application);
            var metadataOptions = args.Skip(4).ToArray();
            ValidateMetadataOptions(metadataOptions);
            report.CliExitCode = await RunApplication(application, etl, directory, metadataOptions);
            CompareNative(etl, directory, report);
            CompareTraceEvent(etl, directory, report);
            report.EtlSha256After = HashFile(etl);
            if (report.EtlSha256Before != report.EtlSha256After)
                throw new InvalidDataException("The input ETL changed during validation.");
            if (report.CliExitCode != 0 || report.Raw.NativeRecords == 0
                || report.Raw.MismatchedRecords != 0 || report.Semantic.MismatchingFields != 0)
            {
                report.Outcome = "failed";
                exitCode = 2;
            }
            else if (report.Semantic.ComparedFields == 0)
            {
                report.Outcome = "raw_match_semantic_comparison_incomplete";
                exitCode = 4;
            }
            else
            {
                // This intentionally does not mean that all providers or fields were decoded.
                report.Outcome = "passed_with_limits";
                exitCode = 0;
            }
        }
        catch (Exception error)
        {
            report.Outcome = "execution_failed";
            report.ExecutionError = error.ToString();
            Console.Error.WriteLine(error.Message);
        }
        finally
        {
            report.CompletedUtc = DateTimeOffset.UtcNow;
            report.ExitCode = exitCode;
            await File.WriteAllTextAsync(Path.Combine(directory, "comparison.json"),
                JsonSerializer.Serialize(report, new JsonSerializerOptions(JsonOptions) { WriteIndented = true }), new UTF8Encoding(false));
        }
        Console.WriteLine($"{report.Outcome}: native={report.Raw.NativeRecords}, CLI={report.Raw.CliRecords}, raw mismatches={report.Raw.MismatchedRecords}, compared fields={report.Semantic.ComparedFields}, semantic mismatches={report.Semantic.MismatchingFields}");
        Console.WriteLine(Path.Combine(directory, "comparison.json"));
        return exitCode;
    }

    private static void ValidateMetadataOptions(string[] args)
    {
        // Prevent an additional input, output override or scan operation from silently changing the selected comparison.
        for (int i = 0; i < args.Length; i++)
        {
            string option = args[i];
            if (option is "--manifest" or "--resource" or "--provider-info")
            {
                if (++i >= args.Length || args[i].StartsWith("--", StringComparison.Ordinal))
                    throw new ArgumentException("A metadata option requires a path.");
            }
            else if (option.StartsWith("--manifest=", StringComparison.Ordinal)
                || option.StartsWith("--resource=", StringComparison.Ordinal)
                || option.StartsWith("--provider-info=", StringComparison.Ordinal)) { }
            else if (option == "--allow-local-metadata") { }
            else if (option.StartsWith("--allow-local-metadata=", StringComparison.Ordinal)) { }
            else throw new ArgumentException("Only metadata options are accepted after --: " + option);
        }
    }

    private static async Task<int> RunApplication(string application, string etl, string directory, string[] metadataOptions)
    {
        var start = new ProcessStartInfo("dotnet")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add(application);
        start.ArgumentList.Add(etl);
        foreach (string option in metadataOptions) start.ArgumentList.Add(option);
        start.ArgumentList.Add("--output");
        start.ArgumentList.Add(Path.Combine(directory, "application.jsonl"));
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start the CLI.");
        await using var stdout = File.Create(Path.Combine(directory, "application.stdout.log"));
        await using var stderr = File.Create(Path.Combine(directory, "application.stderr.log"));
        Task copyOut = process.StandardOutput.BaseStream.CopyToAsync(stdout);
        Task copyError = process.StandardError.BaseStream.CopyToAsync(stderr);
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(15));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            await Task.WhenAll(copyOut, copyError);
            throw new TimeoutException("CLI conversion exceeded fifteen minutes.");
        }
        await Task.WhenAll(copyOut, copyError);
        return process.ExitCode;
    }

    private static void CompareNative(string etl, string directory, ComparisonReport report)
    {
        using var application = OpenApplicationOutput(directory);
        using var index = new StreamWriter(Path.Combine(directory, "native-index.jsonl"), false, new UTF8Encoding(false));
        report.NativeSession = NativeRawReader.Read(etl, raw =>
        {
            long ordinal = ++report.Raw.NativeRecords;
            ProviderSummary provider = report.Provider(raw.Header.ProviderId);
            provider.NativeRecords++;
            string hash = Hash(raw.Payload);
            string? line = application.ReadLine();
            bool matched = true;
            void Check(string field, string expected, string actual)
            {
                if (expected == actual) return;
                matched = false;
                report.Raw.MismatchFields.Increment(field);
                report.Diagnose("raw", ordinal, field, expected, actual);
            }
            if (line == null)
            {
                Check("record", "native record", "CLI record missing");
            }
            else
            {
                report.Raw.CliRecords++;
                try
                {
                    using var json = JsonDocument.Parse(line);
                    JsonElement root = json.RootElement;
                    string status = root.GetProperty("decode_status").GetString() ?? "{null}";
                    provider.ApplicationStatuses.Increment(status);
                    if (status != "decoded")
                    {
                        string? note = root.TryGetProperty("decode_note", out var noteValue) ? noteValue.GetString() : null;
                        string? source = root.TryGetProperty("metadata_source", out var sourceValue) ? sourceValue.GetString() : null;
                        report.RecordApplicationNotDecoded(raw.Header.ProviderId, ordinal, status, note, source);
                    }
                    JsonElement header = root.GetProperty("event_header");
                    Check("provider_guid", raw.Header.ProviderId.ToString("D"), header.GetProperty("provider_guid").GetGuid().ToString("D"));
                    CheckNumber("event_id", raw.Header.Id);
                    CheckNumber("version", raw.Header.Version);
                    CheckNumber("flags", raw.Header.Flags);
                    CheckNumber("channel", raw.Header.Channel);
                    CheckNumber("level", raw.Header.Level);
                    CheckNumber("opcode", raw.Header.Opcode);
                    CheckNumber("task", raw.Header.Task);
                    CheckNumber("keyword", raw.Header.Keyword);
                    Check("process_id", raw.Header.ProcessId.ToString(CultureInfo.InvariantCulture), root.GetProperty("process_id").GetUInt32().ToString(CultureInfo.InvariantCulture));
                    Check("thread_id", raw.Header.ThreadId.ToString(CultureInfo.InvariantCulture), root.GetProperty("thread_id").GetUInt32().ToString(CultureInfo.InvariantCulture));
                    Check("raw_timestamp", raw.Header.Timestamp.ToString(CultureInfo.InvariantCulture), root.GetProperty("raw_timestamp").GetInt64().ToString(CultureInfo.InvariantCulture));
                    byte[] payload = root.GetProperty("raw_payload").GetBytesFromBase64();
                    if (!raw.Payload.AsSpan().SequenceEqual(payload))
                        Check("raw_payload", "byte-for-byte match; sha256=" + hash, "bytes differ; sha256=" + Hash(payload));
                    Check("source_file", etl.ToUpperInvariant(), Path.GetFullPath(root.GetProperty("source_file").GetString()!).ToUpperInvariant());
                    void CheckNumber(string field, ulong value) => Check("event_header." + field,
                        value.ToString(CultureInfo.InvariantCulture), header.GetProperty(field).GetUInt64().ToString(CultureInfo.InvariantCulture));
                }
                catch (Exception error) when (error is JsonException or KeyNotFoundException or InvalidOperationException or FormatException or ArgumentException)
                {
                    Check("JSONL record", "complete event object", error.GetType().Name + ": " + error.Message);
                }
            }
            if (!matched) report.Raw.MismatchedRecords++;
            index.WriteLine(JsonSerializer.Serialize(new RawIndex(ordinal, raw.Header.ProviderId, raw.Header.Flags,
                raw.Header.Id, raw.Header.Version, raw.Header.Opcode, raw.TraceLogging,
                raw.Header.ProcessId, raw.Header.ThreadId, raw.Header.Timestamp, raw.Payload.Length, hash, matched, raw.ScalarTypes), JsonOptions));
        });
        while (application.ReadLine() is not null)
        {
            report.Raw.CliRecords++;
            report.Raw.MismatchedRecords++;
            report.Raw.MismatchFields.Increment("extra_cli_record");
            report.Diagnose("raw", report.Raw.CliRecords, "record", "no extra record", "extra CLI record");
        }
    }

    private static void CompareTraceEvent(string etl, string directory, ComparisonReport report)
    {
        using var source = new ETWTraceEventSource(etl, TraceEventSourceType.FileOnly);
        // Compare the stored NT path. The reference parser otherwise translates
        // kernel paths through its drive mappings before exposing FileName.
        source.Kernel.KernelPathToUserPathMapper = path => path;
        List<ReferenceField>? dynamicFields = null;
        bool comparisonPass = false;
        Exception? callbackError = null;
        source.AddDispatchHook((data, dispatch) =>
        {
            dynamicFields = null;
            dispatch(data);
        });
        source.Dynamic.All += data =>
        {
            if (!comparisonPass || callbackError != null) return;
            try { dynamicFields = SnapshotFields(data); }
            catch (Exception error)
            {
                callbackError = error;
                source.StopProcessing();
            }
        };
        source.Clr.All += _ => { };
        source.Kernel.All += _ => { };
        // Learn late embedded manifests before evaluating payloads. The supported file-source
        // API allows Process() to reset and reread while keeping parser definitions.
        if (!source.Process()) throw new InvalidOperationException("TraceEvent metadata-learning pass did not complete.");
        using var index = File.OpenText(Path.Combine(directory, "native-index.jsonl"));
        using var application = OpenApplicationOutput(directory);
        var matcher = new BoundedRecordMatcher(() =>
        {
            string? line = index.ReadLine();
            if (line == null) return null;
            var native = JsonSerializer.Deserialize<RawIndex>(line, JsonOptions)
                ?? throw new InvalidDataException("The native index contains a null record.");
            return new RecordPair(native, application.ReadLine() ?? string.Empty);
        });
        comparisonPass = true;
        source.AllEvents += data =>
        {
            if (callbackError != null) return;
            try
            {
                long ordinal = ++report.Semantic.TraceEventRecords;
                byte[] referencePayload = data.EventData();
#pragma warning disable CS0618 // Public raw clock accessor: no DateTime/relative-MS conversion or rounding.
                long rawTimestamp = data.TimeStampQPC;
#pragma warning restore CS0618
                // TaskGuid identifies the source classic provider, whereas the
                // public ProviderGuid can be the normalized parser provider.
                var identity = new ReferenceIdentity(data.IsClassicProvider ? data.TaskGuid : data.ProviderGuid,
                    data.IsClassicProvider, (int)data.ID, data.Version, (int)data.Opcode,
                    unchecked((uint)data.ProcessID), unchecked((uint)data.ThreadID), rawTimestamp,
                    referencePayload.Length, Hash(referencePayload));
                MatchResult match = matcher.Match(identity);
                if (match.Pair == null)
                {
                    report.Semantic.UnmatchedToNative++;
                    report.Semantic.SkippedRecords.Increment(match.FailureReason!);
                    report.Diagnose("reference_mapping", ordinal, "record", "unique native record in bounded window with matching source, clock, payload and version", data.EventName);
                    return;
                }
                RawIndex native = match.Pair.Native;
                ProviderSummary provider = report.Provider(native.ProviderGuid);
                if (!native.ApplicationMatched)
                {
                    report.Semantic.SkippedRecords.Increment("application_raw_record_mismatch");
                    return;
                }
                if (match.ContextFixedUp) report.Semantic.ReferencePidTidFixupMatches++;
                if (native.Ordinal != ordinal) report.Semantic.ReferenceDisplacedOrdinalMatches++;
                report.Semantic.MatchedToNative++;
                provider.ReferenceMappedRecords++;
                bool dynamicPayload = dynamicFields != null;
                List<ReferenceField> fields = dynamicFields ?? SnapshotFields(data);
                if (fields.Count == 0)
                {
                    report.Semantic.SkippedRecords.Increment("reference_has_no_decoded_fields");
                    return;
                }
                report.Semantic.ReferenceKnownPayloadRecords++;
                provider.ReferenceKnownPayloadRecords++;
                using var app = JsonDocument.Parse(match.Pair.ApplicationLine);
                JsonElement root = app.RootElement;
                if (root.GetProperty("decode_status").GetString() != "decoded")
                {
                    report.Semantic.SkippedRecords.Increment("reference_has_fields_application_not_decoded");
                    provider.ReferenceKnownApplicationNotDecoded++;
                    return;
                }
                JsonElement properties = root.GetProperty("properties");
                bool compared = false;
                foreach (ReferenceField field in fields)
                {
                    string name = field.Name;
                    if (field.Error != null)
                    {
                        report.Semantic.SkippedFields.Increment("reference_field_read_failed");
                        report.Diagnose("reference_payload", ordinal, name, "readable reference value", field.Error);
                        continue;
                    }
                    if (!properties.TryGetProperty(name, out JsonElement actual))
                    {
                        if (dynamicPayload)
                        {
                            report.Semantic.MismatchingFields++;
                            provider.MismatchingFields++;
                            report.Diagnose("semantic", ordinal, name, "reference dynamic field exists", "application field missing");
                        }
                        else report.Semantic.SkippedFields.Increment("static_parser_field_name_not_present_in_application");
                        continue;
                    }
                    object? expected = field.Value;
                    if (dynamicPayload && native.TraceLoggingScalarTypes != null
                        && native.TraceLoggingScalarTypes.TryGetValue(name, out var declaration))
                    {
                        object? normalized = TraceLoggingScalarSchema.NormalizeUnsignedReference(declaration, expected);
                        if (!Equals(expected, normalized))
                        {
                            report.Semantic.ReferenceUnsignedReinterpretations++;
                            report.Diagnose("reference_representation", ordinal, name,
                                "TraceEvent signed value=" + Convert.ToString(expected, CultureInfo.InvariantCulture),
                                "metadata declares unsigned scalar; value=" + Convert.ToString(normalized, CultureInfo.InvariantCulture));
                        }
                        expected = normalized;
                    }
                    ValueComparison value = PayloadValueComparer.Compare(expected, actual);
                    if (value.Result == ValueResult.Unsupported)
                    {
                        report.Semantic.SkippedFields.Increment(value.Reason ?? "unsupported_reference_type");
                        continue;
                    }
                    compared = true;
                    report.Semantic.ComparedFields++;
                    provider.ComparedFields++;
                    if (value.Result == ValueResult.Mismatch)
                    {
                        report.Semantic.MismatchingFields++;
                        provider.MismatchingFields++;
                        report.Diagnose("semantic", ordinal, name, Convert.ToString(expected, CultureInfo.InvariantCulture) ?? "null", actual.GetRawText());
                    }
                }
                if (compared)
                {
                    report.Semantic.ComparedRecords++;
                    provider.ComparedRecords++;
                }
                else report.Semantic.SkippedRecords.Increment("no_common_comparable_fields");
            }
            catch (Exception error)
            {
                callbackError = error;
                source.StopProcessing();
            }
        };
        bool completed = source.Process();
        report.Semantic.ReferenceReportedEventsLost = source.EventsLost;
        report.Semantic.NativeRecordsWithoutReferenceMatch = report.Raw.NativeRecords - report.Semantic.MatchedToNative;
        report.Semantic.NativeRecordsEvictedFromMatchingWindow = matcher.NativeRecordsEvicted;
        report.Semantic.PeakBufferedNativeRecords = matcher.PeakBufferedRecords;
        report.Semantic.ReferenceRecordCountDifference = report.Semantic.TraceEventRecords - report.Raw.NativeRecords;
        if (callbackError != null) throw new InvalidOperationException("TraceEvent comparison callback failed.", callbackError);
        if (!completed) throw new InvalidOperationException("TraceEvent comparison pass did not complete.");
        if (report.Semantic.TraceEventRecords != report.Raw.NativeRecords)
        {
            report.Diagnose("reference_coverage", 0, "record_count", report.Raw.NativeRecords.ToString(CultureInfo.InvariantCulture),
                report.Semantic.TraceEventRecords.ToString(CultureInfo.InvariantCulture));
        }
    }

    private static List<ReferenceField> SnapshotFields(TraceEvent data)
    {
        string[] names = data.PayloadNames;
        var values = new List<ReferenceField>(names.Length);
        for (int i = 0; i < names.Length; i++)
        {
            try
            {
                object? value = data.PayloadValue(i);
                string? error = PayloadValueComparer.ReferenceFailure(value);
                values.Add(new ReferenceField(names[i], value, error));
            }
            catch (Exception error) { values.Add(new ReferenceField(names[i], null, error.GetType().Name + ": " + error.Message)); }
        }
        return values;
    }

    private static TextReader OpenApplicationOutput(string directory)
    {
        string path = Path.Combine(directory, "application.jsonl");
        return File.Exists(path) ? File.OpenText(path) : new StringReader(string.Empty);
    }

    private static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    private static string HashFile(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }
}

internal sealed record ReferenceField(string Name, object? Value, string? Error);

internal sealed record RawIndex(long Ordinal, Guid ProviderGuid, ushort Flags, ushort EventId, byte Version, byte Opcode,
    bool TraceLogging, uint ProcessId, uint ThreadId,
    long RawTimestamp, int PayloadLength, string PayloadSha256, bool ApplicationMatched,
    Dictionary<string, TraceLoggingScalarDeclaration>? TraceLoggingScalarTypes = null);

internal sealed class ComparisonReport
{
    private readonly Dictionary<string, int> diagnosticCounts = new();
    public string Outcome { get; set; } = "not_completed";
    public int ExitCode { get; set; }
    public int? CliExitCode { get; set; }
    public string Application { get; set; } = "";
    public string ApplicationSha256 { get; set; } = "";
    public string Etl { get; set; } = "";
    public string? EtlSha256Before { get; set; }
    public string? EtlSha256After { get; set; }
    public string[] ApplicationArguments { get; set; } = [];
    public string ReferenceAssembly { get; set; } = "";
    public DateTimeOffset CompletedUtc { get; set; }
    public NativeSession? NativeSession { get; set; }
    public string? ExecutionError { get; set; }
    public RawComparison Raw { get; } = new();
    public SemanticComparison Semantic { get; } = new();
    public Dictionary<string, ProviderSummary> Providers { get; } = new();
    public List<Diagnostic> Diagnostics { get; } = [];
    public string[] Limitations { get; } =
    [
        "Windows x64 only. Compilation is not native execution evidence.",
        "Native raw comparison and TraceEvent both use the Windows ETW reader; this does not independently validate the OS ETL container parser.",
        "TraceEvent normalizes classic/TraceLogging identities and can fix up data; original headers are compared only with the independent native pass.",
        "Raw comparison covers the nine documented event_header fields, PID/TID, raw timestamp, payload bytes, source and counts. Activity/related-activity IDs, stack extensions and other extended-data items are not compared.",
        "Semantic comparison covers mapped records and supported values only; skipped fields/providers and reference-decodable application gaps are reported separately.",
        "Semantic matching uses at most 128 native/application record pairs (8 Mi characters plus one pending record), with timestamp-guided forward resynchronization. Ambiguous, outside-window or fixed-up payloads remain unmatched; reference callback counts are coverage, not a native/application raw mismatch.",
        "TraceEvent Dynamic can consult the analysis host's registered TDH metadata; agreement does not authenticate a schema against the evidence installation.",
        "The reference kernel path mapper is the identity function so FileName comparisons use stored NT paths rather than translated drive paths.",
        "TraceEvent signed representations are reinterpreted as unsigned only for independently parsed flat TraceLogging UInt16/UInt32/UInt64 declarations with default output format. Reinterpretations are counted separately; field names do not select a type.",
        "Scalar and recursively supported array/structure values are compared. Static-parser property aliases are not guessed.",
        "At most 20 diagnostics per phase and 100 overall are retained. Counters cover the complete run.",
    ];

    public ProviderSummary Provider(Guid guid)
    {
        string key = guid.ToString("D");
        if (!Providers.TryGetValue(key, out var provider)) Providers[key] = provider = new();
        return provider;
    }

    public void RecordApplicationNotDecoded(Guid providerGuid, long ordinal, string status, string? note, string? source)
    {
        string reason = string.IsNullOrWhiteSpace(note) ? "No decode_note was emitted." : note;
        string key = status + ": " + (reason.Length <= 512 ? reason : reason[..512] + "…");
        bool firstProviderReason = Provider(providerGuid).ApplicationNotDecodedReasons.IncrementBounded(key, 16);
        Semantic.ApplicationNotDecodedReasons.IncrementBounded(key, 32);
        if (firstProviderReason)
            Diagnose("application_coverage", ordinal, "provider=" + providerGuid.ToString("D") + "; decode_note",
                "application decode_status=decoded",
                "decode_status=" + status + "; metadata_source=" + (source ?? "{absent}") + "; decode_note=" + reason);
    }

    public void Diagnose(string phase, long ordinal, string field, string reference, string actual)
    {
        int phaseCount = diagnosticCounts.GetValueOrDefault(phase);
        if (phaseCount < 20 && Diagnostics.Count < 100)
        {
            Diagnostics.Add(new Diagnostic(phase, ordinal, field, Clip(reference), Clip(actual)));
            diagnosticCounts[phase] = phaseCount + 1;
        }
        static string Clip(string text) => text.Length <= 300 ? text : text[..300] + "…";
    }
}

internal sealed class RawComparison
{
    public long NativeRecords { get; set; }
    public long CliRecords { get; set; }
    public long MismatchedRecords { get; set; }
    public Dictionary<string, long> MismatchFields { get; } = new();
}

internal sealed class SemanticComparison
{
    public long TraceEventRecords { get; set; }
    public long MatchedToNative { get; set; }
    public long UnmatchedToNative { get; set; }
    public long NativeRecordsWithoutReferenceMatch { get; set; }
    public long NativeRecordsEvictedFromMatchingWindow { get; set; }
    public int PeakBufferedNativeRecords { get; set; }
    public long ReferenceRecordCountDifference { get; set; }
    public long ReferencePidTidFixupMatches { get; set; }
    public long ReferenceDisplacedOrdinalMatches { get; set; }
    public long ReferenceKnownPayloadRecords { get; set; }
    public long ComparedRecords { get; set; }
    public long ComparedFields { get; set; }
    public long MismatchingFields { get; set; }
    public long ReferenceUnsignedReinterpretations { get; set; }
    public int ReferenceReportedEventsLost { get; set; }
    public Dictionary<string, long> SkippedRecords { get; } = new();
    public Dictionary<string, long> SkippedFields { get; } = new();
    public Dictionary<string, long> ApplicationNotDecodedReasons { get; } = new();
}

internal sealed class ProviderSummary
{
    public long NativeRecords { get; set; }
    public long ReferenceMappedRecords { get; set; }
    public long ReferenceKnownPayloadRecords { get; set; }
    public long ReferenceKnownApplicationNotDecoded { get; set; }
    public long ComparedRecords { get; set; }
    public long ComparedFields { get; set; }
    public long MismatchingFields { get; set; }
    public Dictionary<string, long> ApplicationStatuses { get; } = new();
    public Dictionary<string, long> ApplicationNotDecodedReasons { get; } = new();
}

internal sealed record Diagnostic(string Phase, long Ordinal, string Field, string Reference, string Actual);

internal static class Counters
{
    public static void Increment(this Dictionary<string, long> values, string name) => values[name] = values.GetValueOrDefault(name) + 1;

    public static bool IncrementBounded(this Dictionary<string, long> values, string name, int maximumReasons)
    {
        bool firstReason = !values.ContainsKey(name);
        if (firstReason && values.Count >= maximumReasons)
        {
            values.Increment("{other reason variants}");
            return false;
        }
        values.Increment(name);
        return firstReason;
    }
}
