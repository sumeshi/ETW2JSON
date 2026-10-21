using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using ETW2JSON;
using ETWDeserializer;

namespace ETW2JSON.CorpusReplay;

internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            var inputs = new List<string>();
            var manifests = new List<string>();
            string? output = null, summaryPath = null;
            for (int i = 0; i < args.Length; i++)
            {
                if (i + 1 >= args.Length) throw new ArgumentException("Every option requires a value.");
                switch (args[i])
                {
                    case "--input": inputs.Add(args[++i]); break;
                    case "--manifest": manifests.Add(args[++i]); break;
                    case "--output": output = args[++i]; break;
                    case "--summary": summaryPath = args[++i]; break;
                    default: throw new ArgumentException("Unknown option: " + args[i]);
                }
            }
            if (inputs.Count == 0 || output == null || summaryPath == null)
                throw new ArgumentException("Usage: --input records.jsonl [--input more.jsonl] [--manifest schema.man] --output new.jsonl --summary new.json");
            if (File.Exists(output) || File.Exists(summaryPath)) throw new IOException("Output and summary paths must be new files.");

            var inputHashes = inputs.ToDictionary(Path.GetFullPath, HashFile);
            var metadata = new MetadataResolver();
            var manifestResolver = new ManifestFileResolver();
            foreach (string manifest in manifests) manifestResolver.AddFile(manifest);
            if (manifests.Count > 0) metadata.Add(manifestResolver);
            var preflight = new PreflightMetadata(metadata);
            var clocks = new Dictionary<string, TraceClockMetadata>(StringComparer.OrdinalIgnoreCase);

            using (var ignored = new JsonlEventWriter(Stream.Null))
            {
                var reader = Reader(ignored, preflight, clocks);
                reader.SchemaOnly = true;
                foreach (var record in Read(inputs))
                {
                    if (record.HasTraceLogging) continue;
                    Bind(reader, record, clocks);
                    Replay(reader, record);
                }
            }

            long inputCount = 0, skippedTraceLogging = 0;
            long replayed = 0;
            using (var stream = new FileStream(output, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
            using (var writer = new JsonlEventWriter(stream))
            {
                var reader = Reader(writer, preflight, clocks);
                foreach (var record in Read(inputs))
                {
                    inputCount++;
                    if (record.HasTraceLogging) { skippedTraceLogging++; continue; }
                    replayed++;
                    Bind(reader, record, clocks);
                    Replay(reader, record);
                }
                writer.Flush();
            }

            var status = new SortedDictionary<string, long>();
            var sources = new SortedDictionary<string, long>();
            var byProvider = new SortedDictionary<string, SortedDictionary<string, long>>();
            var mismatches = new SortedDictionary<string, long>();
            var mismatchExamples = new List<string>();
            long emitted = 0;
            using var expected = Read(inputs).Where(record => !record.HasTraceLogging).GetEnumerator();
            foreach (string line in File.ReadLines(output))
            {
                using var document = JsonDocument.Parse(line);
                var evt = document.RootElement;
                string state = evt.GetProperty("decode_status").GetString()!;
                Increment(status, state);
                Increment(sources, evt.GetProperty("metadata_source").GetString()!);
                var header = evt.GetProperty("event_header");
                string providerKey = $"{evt.GetProperty("source_file").GetString()}:{header.GetProperty("provider_guid").GetString()}:{header.GetProperty("opcode").GetByte()}";
                if (!byProvider.TryGetValue(providerKey, out var outcomes)) byProvider.Add(providerKey, outcomes = new());
                Increment(outcomes, state);
                if (!expected.MoveNext()) Mismatch("extra_event", "Output has more records than replayed input.");
                else
                {
                    var record = expected.Current;
                    string location = $"{record.Source} record {record.Index}";
                    if (!record.Payload.AsSpan().SequenceEqual(evt.GetProperty("raw_payload").GetBytesFromBase64()))
                        Mismatch("raw_payload", location);
                    if (evt.GetProperty("raw_timestamp").GetInt64() != record.Timestamp) Mismatch("raw_timestamp", location);
                    if (evt.GetProperty("source_file").GetString() != record.Source) Mismatch("source_file", location);
                    if (evt.GetProperty("process_id").GetUInt32() != record.ProcessId) Mismatch("process_id", location);
                    if (evt.GetProperty("thread_id").GetUInt32() != record.ThreadId) Mismatch("thread_id", location);
                    var activity = evt.GetProperty("activity_id");
                    if ((activity.ValueKind == JsonValueKind.Null ? Guid.Empty : activity.GetGuid()) != record.Activity) Mismatch("activity_id", location);
                    bool headerMatches = header.GetProperty("provider_guid").GetGuid() == record.Provider
                        && header.GetProperty("event_id").GetUInt16() == record.Id
                        && header.GetProperty("version").GetByte() == record.Version
                        && header.GetProperty("flags").GetUInt16() == record.Flags
                        && header.GetProperty("channel").GetByte() == record.Channel
                        && header.GetProperty("level").GetByte() == record.Level
                        && header.GetProperty("opcode").GetByte() == record.Opcode
                        && header.GetProperty("task").GetUInt16() == record.Task
                        && header.GetProperty("keyword").GetUInt64() == record.Keyword;
                    if (!headerMatches) Mismatch("event_header", location);
                    var extended = evt.GetProperty("raw_extended_data");
                    bool extensionsMatch = extended.GetArrayLength() == record.Extensions.Count;
                    if (extensionsMatch)
                    {
                        for (int i = 0; i < record.Extensions.Count; i++)
                        {
                            var observed = extended[i];
                            var original = record.Extensions[i];
                            if (observed.GetProperty("ext_type").GetUInt16() != original.Type
                                || observed.GetProperty("data_size").GetUInt16() != original.Data.Length
                                || observed.GetProperty("raw_data").ValueKind == JsonValueKind.Null
                                || !original.Data.AsSpan().SequenceEqual(observed.GetProperty("raw_data").GetBytesFromBase64()))
                            {
                                extensionsMatch = false;
                                break;
                            }
                        }
                    }
                    if (!extensionsMatch) Mismatch("raw_extended_data", location);
                }
                emitted++;
            }
            if (emitted < replayed) Mismatch("missing_events", (replayed - emitted).ToString());
            foreach (var input in inputHashes)
                if (HashFile(input.Key) != input.Value) Mismatch("input_export_changed", input.Key);

            var summary = new
            {
                validation_scope = "Linux replay of exported records through managed decoding; not native OpenTrace/TDH/ProcessTrace validation. Header flags were inferred from ETL markers by the exporter.",
                limitations = new[] { "TraceLogging records are explicitly skipped; no native TDH lookup is mocked.", "Raw round-trip equality does not establish decoded property correctness.", "Buffer/file order may differ from native ProcessTrace ordering." },
                input_exports_sha256 = inputHashes,
                manifest_files_sha256 = manifests.ToDictionary(Path.GetFullPath, HashFile),
                decoder_assembly_sha256 = HashFile(typeof(Deserializer<JsonlEventWriter>).Assembly.Location),
                helper_assembly_sha256 = HashFile(typeof(Program).Assembly.Location),
                runtime_version = Environment.Version.ToString(),
                runtime_os = RuntimeInformation.OSDescription,
                input_records = inputCount,
                replayed_records = replayed,
                skipped_tracelogging_records = skippedTraceLogging,
                emitted_records = emitted,
                status_counts = status,
                metadata_source_counts = sources,
                by_source_provider_opcode = byProvider,
                roundtrip_mismatch_counts = mismatches,
                roundtrip_mismatch_examples = mismatchExamples,
                output_sha256 = HashFile(output),
            };
            using var summaryStream = new FileStream(summaryPath, FileMode.CreateNew, FileAccess.Write);
            JsonSerializer.Serialize(summaryStream, summary, new JsonSerializerOptions { WriteIndented = true });
            Console.WriteLine($"Input={inputCount}; replayed={replayed}; skipped TraceLogging={skippedTraceLogging}; emitted={emitted}; round-trip mismatch categories={mismatches.Count}");
            return mismatches.Count == 0 ? 0 : 2;

            void Mismatch(string kind, string detail)
            {
                Increment(mismatches, kind);
                if (mismatchExamples.Count < 20) mismatchExamples.Add(kind + ": " + detail);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
            return 1;
        }
    }

    private static Deserializer<JsonlEventWriter> Reader(JsonlEventWriter writer, PreflightMetadata metadata,
        Dictionary<string, TraceClockMetadata> clocks) => new(writer)
    {
        ResolverChain = metadata,
        AllowLocalMetadata = false,
        TraceClockLookup = source => clocks.TryGetValue(source, out var clock) ? clock : null,
    };

    private static void Bind(Deserializer<JsonlEventWriter> reader, Record record, Dictionary<string, TraceClockMetadata> clocks)
    {
        clocks[record.Source] = record.Clock;
        reader.SetCurrentSource(record.Source);
    }

    private static unsafe void Replay(Deserializer<JsonlEventWriter> reader, Record row)
    {
        byte* payload = null;
        EVENT_HEADER_EXTENDED_DATA_ITEM* extended = null;
        try
        {
            if (row.Payload.Length > 0)
            {
                payload = (byte*)NativeMemory.Alloc((nuint)row.Payload.Length);
                row.Payload.AsSpan().CopyTo(new Span<byte>(payload, row.Payload.Length));
            }
            if (row.Extensions.Count > 0)
            {
                extended = (EVENT_HEADER_EXTENDED_DATA_ITEM*)NativeMemory.AllocZeroed((nuint)row.Extensions.Count, (nuint)sizeof(EVENT_HEADER_EXTENDED_DATA_ITEM));
                for (int i = 0; i < row.Extensions.Count; i++)
                {
                    var item = row.Extensions[i];
                    byte* data = (byte*)NativeMemory.Alloc((nuint)Math.Max(1, item.Data.Length));
                    extended[i].DataPtr = (ulong)data;
                    extended[i].ExtType = item.Type;
                    extended[i].DataSize = checked((ushort)item.Data.Length);
                    item.Data.AsSpan().CopyTo(new Span<byte>(data, item.Data.Length));
                }
            }
            EVENT_RECORD record = new()
            {
                Size = 80,
                Flags = row.Flags,
                ProviderId = row.Provider,
                Id = row.Id,
                Version = row.Version,
                Channel = row.Channel,
                Level = row.Level,
                Opcode = row.Opcode,
                Task = row.Task,
                Keyword = row.Keyword,
                ProcessId = row.ProcessId,
                ThreadId = row.ThreadId,
                TimeStamp = row.Timestamp,
                ActivityId = row.Activity,
                UserData = payload,
                UserDataLength = checked((ushort)row.Payload.Length),
                ExtendedData = extended,
                ExtendedDataCount = checked((ushort)row.Extensions.Count),
            };
            reader.Deserialize(&record);
            if (reader.LastError != null) throw new InvalidOperationException($"Fatal callback at {row.Source} record {row.Index}", reader.LastError);
        }
        finally
        {
            if (extended != null)
            {
                for (int i = 0; i < row.Extensions.Count; i++) NativeMemory.Free((void*)extended[i].DataPtr);
                NativeMemory.Free(extended);
            }
            NativeMemory.Free(payload);
        }
    }

    private static IEnumerable<Record> Read(IEnumerable<string> paths)
    {
        foreach (string path in paths)
        foreach (string line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            using var document = JsonDocument.Parse(line);
            var root = document.RootElement;
            var clock = root.GetProperty("trace_clock");
            yield return new Record(
                root.GetProperty("source_file").GetString()!, root.GetProperty("record_index").GetInt64(),
                root.GetProperty("provider_guid").GetGuid(), root.GetProperty("event_id").GetUInt16(),
                root.GetProperty("version").GetByte(), root.GetProperty("replay_flags").GetUInt16(),
                root.GetProperty("channel").GetByte(), root.GetProperty("level").GetByte(),
                root.GetProperty("opcode").GetByte(), root.GetProperty("task").GetUInt16(),
                root.GetProperty("keyword").GetUInt64(), NullableUInt(root.GetProperty("process_id")),
                NullableUInt(root.GetProperty("thread_id")), root.GetProperty("raw_timestamp").GetInt64(),
                root.GetProperty("activity_id").ValueKind == JsonValueKind.Null ? Guid.Empty : root.GetProperty("activity_id").GetGuid(),
                root.GetProperty("payload_base64").GetBytesFromBase64(),
                root.GetProperty("extended_data").EnumerateArray().Select(item => new Extension(
                    item.GetProperty("ext_type").GetUInt16(), item.GetProperty("data_base64").GetBytesFromBase64())).ToList(),
                new TraceClockMetadata(clock.GetProperty("performance_frequency").GetInt64(), clock.GetProperty("start_time").GetInt64(),
                    clock.GetProperty("boot_time").GetInt64(), clock.GetProperty("reserved_flags").GetUInt32()));
        }
    }

    private static uint NullableUInt(JsonElement item) => item.ValueKind == JsonValueKind.Null ? 0 : item.GetUInt32();
    private static string HashFile(string path) { using var stream = File.OpenRead(path); return Convert.ToHexStringLower(SHA256.HashData(stream)); }
    private static void Increment(IDictionary<string, long> counts, string key) => counts[key] = counts.TryGetValue(key, out var count) ? count + 1 : 1;
    private sealed record Extension(ushort Type, byte[] Data);
    private sealed record Record(string Source, long Index, Guid Provider, ushort Id, byte Version, ushort Flags,
        byte Channel, byte Level, byte Opcode, ushort Task, ulong Keyword, uint ProcessId, uint ThreadId, long Timestamp,
        Guid Activity, byte[] Payload, List<Extension> Extensions, TraceClockMetadata Clock)
    {
        public bool HasTraceLogging => this.Extensions.Any(item => item.Type == 0x000B);
    }
}
