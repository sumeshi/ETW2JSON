namespace ETW2JSON.Tests
{
    using System;
    using System.IO;
    using System.Text.Json;
    using ETWDeserializer;
    using Xunit;

    public sealed unsafe class EventHeaderPreservationTests
    {
        [Theory]
        [InlineData(false, false)]
        [InlineData(false, true)]
        [InlineData(true, false)]
        [InlineData(true, true)]
        public void OriginalHeaderIsPreservedAlongsideSchemaIdentity(bool legacy, bool is32Bit)
        {
            Guid originalProvider = Guid.Parse("11111111-1111-1111-1111-111111111111");
            Guid schemaProvider = Guid.Parse("22222222-2222-2222-2222-222222222222");
            ushort flags = is32Bit ? (ushort)0x20 : (ushort)0x40;
            var record = new EVENT_RECORD
            {
                ProviderId = originalProvider,
                Id = 37,
                Version = 4,
                Flags = flags,
                Channel = 17,
                Level = 5,
                Opcode = 9,
                Task = 1000,
                Keyword = 0xFEDCBA9876543210UL,
            };
            var runtime = new RuntimeEventMetadata(&record, "trace.etl");
            var metadata = new EventMetadata(schemaProvider, 999, 7, "Provider/CustomEvent",
                Array.Empty<PropertyMetadata>(), "Provider", MetadataSource.Embedded, DecodeStatus.Decoded, "custom-parser");
            // The event snapshot must remain valid after the callback's record changes.
            record = default;
            using var stream = new MemoryStream();
            if (legacy)
            {
                using var writer = new LegacyJsonEventWriter(stream);
                writer.WriteEventBegin(metadata, runtime);
                writer.WriteEventEnd();
                writer.Complete();
            }
            else
            {
                using var writer = new JsonlEventWriter(stream);
                writer.WriteEventBegin(metadata, runtime);
                writer.WriteEventEnd();
            }

            using var json = JsonDocument.Parse(stream.ToArray());
            var evt = legacy ? json.RootElement.GetProperty("Events")[0].GetProperty("Event") : json.RootElement;
            Assert.Equal(schemaProvider.ToString("D"), evt.GetProperty(legacy ? "ProviderGuid" : "provider_guid").GetString());
            Assert.Equal(999, evt.GetProperty(legacy ? "Id" : "event_id").GetInt32());
            Assert.Equal(7, evt.GetProperty(legacy ? "Version" : "version").GetInt32());

            var header = evt.GetProperty("event_header");
            Assert.Equal(originalProvider.ToString("D"), header.GetProperty("provider_guid").GetString());
            Assert.Equal(37, header.GetProperty("event_id").GetInt32());
            Assert.Equal(4, header.GetProperty("version").GetInt32());
            Assert.Equal(flags, header.GetProperty("flags").GetUInt16());
            Assert.Equal(17, header.GetProperty("channel").GetInt32());
            Assert.Equal(5, header.GetProperty("level").GetInt32());
            Assert.Equal(9, header.GetProperty("opcode").GetInt32());
            Assert.Equal(1000, header.GetProperty("task").GetInt32());
            Assert.Equal(0xFEDCBA9876543210UL, header.GetProperty("keyword").GetUInt64());
        }
    }
}
