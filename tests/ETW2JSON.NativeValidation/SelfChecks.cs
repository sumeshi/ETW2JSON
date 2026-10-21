using System.Text.Json;

namespace ETW2JSON.NativeValidation;

internal static class SelfChecks
{
    internal static int Run()
    {
        int checks = 0;
        try
        {
            NativeRawReader.ValidateLayout();
            checks++;
            Check(ulong.MaxValue, "18446744073709551615", ValueResult.Match);
            Check(ulong.MaxValue, "18446744073709551614", ValueResult.Mismatch);
            Check(0.1f, "0.1", ValueResult.Match);
            Check(0.1d, "0.1000000001", ValueResult.Mismatch);
            Check(float.NaN, "null", ValueResult.Unsupported);
            Check(true, "true", ValueResult.Match);
            Check(false, "0", ValueResult.Mismatch);
            Check('A', "65", ValueResult.Match);
            Check(new byte[] { 1, 2, 3 }, "\"AQID\"", ValueResult.Match);
            Check(new byte[] { 1, 2, 3 }, "\"AQIE\"", ValueResult.Mismatch);
            Check(new int[] { 1, 2 }, "[1,2]", ValueResult.Match);
            Check(new int[] { 1, 2 }, "[1,3]", ValueResult.Mismatch);
            Check(new Dictionary<string, object> { ["items"] = new[] { 1, 2 } }, "{\"items\":[1,2]}", ValueResult.Match);
            Check(new Dictionary<string, object> { ["items"] = new[] { 1, 2 } }, "{\"items\":[1,2],\"extra\":0}", ValueResult.Mismatch);
            Check(Guid.Parse("11111111-2222-3333-4444-555555555555"), "\"11111111-2222-3333-4444-555555555555\"", ValueResult.Match);
            Check(DateTimeOffset.Parse("2026-01-01T00:00:00+00:00"), "\"2026-01-01T01:00:00+01:00\"", ValueResult.Match);
            Check("<<<EXCEPTION_DURING_VALUE_LOOKUP ArgumentException>>>", "\"anything\"", ValueResult.Unsupported);
            Check("[UNSUPPORTED TYPE]", "\"[UNSUPPORTED TYPE]\"", ValueResult.Unsupported);
            Check(new object(), "{}", ValueResult.Unsupported);
            var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };
            var original = new RawIndex(7, Guid.NewGuid(), 0x100, 0, 1, 32, false, uint.MaxValue, 10, long.MaxValue, 3, "payload-hash", true);
            var restored = JsonSerializer.Deserialize<RawIndex>(JsonSerializer.Serialize(original, options), options);
            if (original != restored) throw new InvalidOperationException("The streaming native-index record did not round-trip.");
            checks++;
            checks += MatcherSelfChecks.Run();
            checks += TraceLoggingSchemaSelfChecks.Run();
            checks += ReferenceScalarTypes.RunSelfChecks();
            var withSchema = original with { TraceLoggingScalarTypes = new()
            {
                ["int64_type"] = new TraceLoggingScalarDeclaration(10),
            } };
            var restoredSchema = JsonSerializer.Deserialize<RawIndex>(JsonSerializer.Serialize(withSchema, options), options);
            if (restoredSchema?.TraceLoggingScalarTypes?["int64_type"] != new TraceLoggingScalarDeclaration(10))
                throw new InvalidOperationException("The native-index scalar declarations did not round-trip.");
            checks++;
            var coverage = new ComparisonReport();
            Guid provider = Guid.Parse("11111111-2222-3333-4444-555555555555");
            coverage.RecordApplicationNotDecoded(provider, 1, "metadata_missing", "Schema absent", "unknown");
            coverage.RecordApplicationNotDecoded(provider, 2, "metadata_missing", "Schema absent", "unknown");
            if (coverage.Diagnostics.Count != 1 || coverage.Semantic.ApplicationNotDecodedReasons["metadata_missing: Schema absent"] != 2)
                throw new InvalidOperationException("Repeated application coverage reasons were not aggregated.");
            checks++;
            coverage.RecordApplicationNotDecoded(provider, 3, "unsupported", "Self-describing schema is unsupported", "trace_logging");
            if (coverage.Diagnostics.Count != 2 || !coverage.Diagnostics[1].Actual.Contains("Self-describing schema is unsupported", StringComparison.Ordinal)
                || coverage.Raw.MismatchedRecords != 0 || coverage.Semantic.MismatchingFields != 0)
                throw new InvalidOperationException("An unsupported coverage note was hidden or counted as a mismatch.");
            checks++;
            for (int i = 0; i < 100; i++) coverage.RecordApplicationNotDecoded(provider, i + 4, "decode_error", "Variant " + i, "embedded");
            if (coverage.Semantic.ApplicationNotDecodedReasons.Count > 33 || coverage.Provider(provider).ApplicationNotDecodedReasons.Count > 17
                || !coverage.Semantic.ApplicationNotDecodedReasons.ContainsKey("{other reason variants}"))
                throw new InvalidOperationException("Application reason counters were not bounded.");
            checks++;
            for (int i = 0; i < 200; i++) coverage.Diagnose("reference_mapping", i, "record", "reference", "unmatched");
            coverage.Diagnose("semantic", 1, "value", "1", "2");
            if (coverage.Diagnostics.Count > 100 || coverage.Diagnostics.Count(d => d.Phase == "reference_mapping") != 20
                || !coverage.Diagnostics.Any(d => d.Phase == "semantic"))
                throw new InvalidOperationException("One diagnostic phase hid a later semantic mismatch.");
            checks++;
            Console.WriteLine($"{checks} portable harness self-checks passed. Native ETL comparison was not executed.");
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("Harness self-check failed: " + error);
            return 2;
        }

        void Check(object? value, string json, ValueResult expected)
        {
            using var document = JsonDocument.Parse(json);
            var actual = PayloadValueComparer.Compare(value, document.RootElement);
            if (actual.Result != expected)
                throw new InvalidOperationException($"Value comparison returned {actual.Result}; expected {expected} for {value} against {json}.");
            checks++;
        }
    }
}
