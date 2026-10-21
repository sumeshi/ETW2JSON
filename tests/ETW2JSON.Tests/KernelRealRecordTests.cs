namespace ETW2JSON.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text.Json;
    using ETWDeserializer;
    using Xunit;

    public sealed unsafe class KernelRealRecordTests
    {
        public static IEnumerable<object[]> Records()
        {
            string path = Path.Combine(AppContext.BaseDirectory, "fixtures", "kernel-investigation-reference.jsonl");
            foreach (string line in File.ReadLines(path))
            {
                using var document = JsonDocument.Parse(line);
                yield return new object[] { document.RootElement.GetProperty("record_index").GetInt32(), line };
            }
        }

        [Theory]
        [MemberData(nameof(Records))]
        public void PublicKernelPayloadMatchesIndependentReferenceValues(int index, string referenceJson)
        {
            using var reference = JsonDocument.Parse(referenceJson);
            var expected = reference.RootElement;
            Assert.Equal(index, expected.GetProperty("record_index").GetInt32());
            Assert.Equal(64, expected.GetProperty("provenance").GetProperty("etl_sha256").GetString().Length);
            Assert.Empty(expected.GetProperty("extended_data").EnumerateArray());
            byte[] payload = Convert.FromBase64String(expected.GetProperty("payload_base64").GetString());
            using var stream = new MemoryStream();
            using var writer = new JsonlEventWriter(stream);
            var deserializer = new Deserializer<JsonlEventWriter>(writer) { SourceFile = expected.GetProperty("source_file").GetString() };
            fixed (byte* bytes = payload)
            {
                // These flags come from the fixture exporter's raw header marker
                // inference. This tests managed payload parsing, not OpenTrace.
                var record = new EVENT_RECORD
                {
                    ProviderId = Guid.Parse(expected.GetProperty("provider_guid").GetString()),
                    Id = expected.GetProperty("event_id").GetUInt16(),
                    Version = expected.GetProperty("version").GetByte(),
                    Opcode = expected.GetProperty("opcode").GetByte(),
                    Flags = expected.GetProperty("replay_flags").GetUInt16(),
                    // Some on-disk headers omit PID/TID. Zero is only a replay
                    // placeholder here; it does not assert OpenTrace's behavior.
                    ProcessId = OptionalHeaderId(expected.GetProperty("process_id")),
                    ThreadId = OptionalHeaderId(expected.GetProperty("thread_id")),
                    TimeStamp = expected.GetProperty("raw_timestamp").GetInt64(),
                    UserData = bytes,
                    UserDataLength = checked((ushort)payload.Length),
                };
                deserializer.Deserialize(&record);
            }

            Assert.Null(deserializer.LastError);
            using var output = JsonDocument.Parse(stream.ToArray());
            var actual = output.RootElement;
            Assert.Equal("decoded", actual.GetProperty("decode_status").GetString());
            Assert.Equal("builtin_parser", actual.GetProperty("metadata_source").GetString());
            Assert.Equal(payload, actual.GetProperty("raw_payload").GetBytesFromBase64());
            Assert.Equal(expected.GetProperty("provider_guid").GetString(), actual.GetProperty("event_header").GetProperty("provider_guid").GetString());
            Assert.Equal(expected.GetProperty("event_id").GetInt32(), actual.GetProperty("event_header").GetProperty("event_id").GetInt32());
            if (expected.GetProperty("process_id").ValueKind != JsonValueKind.Null)
                Assert.Equal(expected.GetProperty("process_id").GetUInt32(), actual.GetProperty("process_id").GetUInt32());
            foreach (var property in expected.GetProperty("expected_properties").EnumerateObject())
            {
                Assert.True(actual.GetProperty("properties").TryGetProperty(property.Name, out var value), "Missing reference property: " + property.Name);
                switch (property.Value.ValueKind)
                {
                    case JsonValueKind.Number: Assert.Equal(property.Value.GetUInt64(), value.GetUInt64()); break;
                    case JsonValueKind.String: Assert.Equal(property.Value.GetString(), value.GetString()); break;
                    case JsonValueKind.Null: Assert.Equal(JsonValueKind.Null, value.ValueKind); break;
                    default: Assert.Fail("Unsupported reference value type for " + property.Name); break;
                }
            }
        }

        private static uint OptionalHeaderId(JsonElement field) => field.ValueKind == JsonValueKind.Null ? 0U : field.GetUInt32();
    }
}
