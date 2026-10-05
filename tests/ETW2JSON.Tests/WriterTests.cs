namespace ETW2JSON.Tests
{
    using System;
    using System.IO;
    using System.Text;
    using System.Text.Json;
    using ETW2JSON;
    using ETWDeserializer;
    using Xunit;

    public sealed unsafe class WriterTests
    {
        private static EventMetadata CreateMetadata() => new EventMetadata(
            Guid.Parse("11111111-1111-1111-1111-111111111111"), 7, 1,
            "Example/Event", Array.Empty<PropertyMetadata>(), "Example",
            MetadataSource.ExternalManifest, DecodeStatus.Partial, "fixture.man;sha256:abc");

        [Fact]
        [Trait("Task", "T10")]
        public void JsonlWritesIndependentLinesWithSourceAndRawPayload()
        {
            EVENT_RECORD record = default;
            byte* payload = stackalloc byte[] { 1, 2, 3 };
            record.UserData = record.UserDataFixed = payload;
            record.UserDataLength = 3;
            record.TimeStamp = 1234;
            var runtime = new RuntimeEventMetadata(&record, "source.etl", new TraceClockMetadata(10_000_000, 456, 789, 3));
            using var stream = new MemoryStream();
            using (var writer = new JsonlEventWriter(stream))
            {
                writer.WriteEventBegin(CreateMetadata(), runtime);
                writer.WriteEventEnd();
                writer.WriteEventBegin(CreateMetadata(), runtime);
                writer.WriteEventEnd();
            }

            string output = Encoding.UTF8.GetString(stream.ToArray());
            Assert.Equal(2, output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length);
            foreach (string line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                using var json = JsonDocument.Parse(line);
                Assert.Equal("source.etl", json.RootElement.GetProperty("source_file").GetString());
                Assert.Equal(1234, json.RootElement.GetProperty("raw_timestamp").GetInt64());
                Assert.Equal(10_000_000, json.RootElement.GetProperty("trace_clock").GetProperty("performance_frequency").GetInt64());
                Assert.Equal("AQID", json.RootElement.GetProperty("raw_payload").GetString());
                Assert.Equal("external_manifest", json.RootElement.GetProperty("metadata_source").GetString());
                Assert.Equal("partial", json.RootElement.GetProperty("decode_status").GetString());
                Assert.True(json.RootElement.TryGetProperty("decode_note", out _));
            }
        }

        [Fact]
        [Trait("Task", "T11")]
        public void LegacyJsonRetainsForensicFields()
        {
            EVENT_RECORD record = default;
            byte* payload = stackalloc byte[] { 0xCA, 0xFE };
            record.UserData = record.UserDataFixed = payload;
            record.UserDataLength = 2;
            using var stream = new MemoryStream();
            using (var writer = new LegacyJsonEventWriter(stream))
            {
                writer.WriteEventBegin(CreateMetadata(), new RuntimeEventMetadata(&record, "trace.etl"));
                writer.WriteEventEnd();
                writer.Complete();
            }

            using var json = JsonDocument.Parse(stream.ToArray());
            var evt = json.RootElement.GetProperty("Events")[0].GetProperty("Event");
            Assert.Equal("trace.etl", evt.GetProperty("source_file").GetString());
            Assert.Equal("yv4=", evt.GetProperty("raw_payload").GetString());
            Assert.Equal("external_manifest", evt.GetProperty("metadata_source").GetString());
            Assert.Equal("partial", evt.GetProperty("decode_status").GetString());
            Assert.Equal("fixture.man;sha256:abc", evt.GetProperty("metadata_provenance").GetString());
            Assert.True(evt.TryGetProperty("decode_note", out _));
        }
    }
}
