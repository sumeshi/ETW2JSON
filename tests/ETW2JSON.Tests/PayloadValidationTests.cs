namespace ETW2JSON.Tests
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Text.Json;
    using ETWDeserializer;
    using Xunit;

    public sealed unsafe class PayloadValidationTests
    {
        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void ShortSchemaRetainsRawEventInsteadOfClaimingFullDecode(bool legacy)
        {
            byte[] payload = { 42, 0, 0, 0, 99, 0, 0, 0 };
            var events = Convert(legacy, 1, DecodeStatus.Decoded, payload);

            var evt = Assert.Single(events);
            Assert.Equal("decode_error", evt.GetProperty("decode_status").GetString());
            Assert.Equal(ConvertBase64(payload), evt.GetProperty("raw_payload").GetString());
            Assert.Contains("unconsumed", evt.GetProperty("decode_note").GetString());
            Assert.Equal("external_manifest", evt.GetProperty("metadata_source").GetString());
            Assert.Equal("test-schema", evt.GetProperty("metadata_provenance").GetString());
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void InvalidPayloadDoesNotBreakFollowingValidRecord(bool legacy)
        {
            var events = Convert(legacy, 1, DecodeStatus.Decoded,
                new byte[] { 1, 2 }, new byte[] { 42, 0, 0, 0 });

            Assert.Equal(2, events.Length);
            Assert.Equal("decode_error", events[0].GetProperty("decode_status").GetString());
            Assert.Equal("AQI=", events[0].GetProperty("raw_payload").GetString());
            Assert.Equal("decoded", events[1].GetProperty("decode_status").GetString());
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void EmptySchemaAcceptsEmptyPayloadButRejectsExtraBytes(bool legacy)
        {
            var events = Convert(legacy, 0, DecodeStatus.Decoded,
                Array.Empty<byte>(), new byte[] { 1 });

            Assert.Equal(2, events.Length);
            Assert.Equal("decoded", events[0].GetProperty("decode_status").GetString());
            Assert.Equal("decode_error", events[1].GetProperty("decode_status").GetString());
            Assert.Equal("AQ==", events[1].GetProperty("raw_payload").GetString());
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void UnsupportedSchemaKeepsItsStatusAndRawPayload(bool legacy)
        {
            var evt = Assert.Single(Convert(legacy, 0, DecodeStatus.Unsupported, new byte[] { 1, 2 }));

            Assert.Equal("unsupported", evt.GetProperty("decode_status").GetString());
            Assert.Equal("AQI=", evt.GetProperty("raw_payload").GetString());
        }

        private static JsonElement[] Convert(bool legacy, int propertyCount, DecodeStatus status, params byte[][] payloads)
        {
            var properties = Enumerable.Range(0, propertyCount)
                .Select(i => new PropertyMetadata(TDH_IN_TYPE.TDH_INTYPE_INT32, TDH_OUT_TYPE.TDH_OUTTYPE_NULL,
                    "value" + i, false, false, 0, null)).ToArray();
            var operands = properties.Select((metadata, i) => (IEventTracePropertyOperand)new EventTracePropertyOperand(
                metadata, i, false, false, false, false, false)).ToArray();
            var metadata = new EventMetadata(Guid.Parse("11111111-1111-1111-1111-111111111111"), 1, 0,
                "Example/Event", properties, "Example", MetadataSource.ExternalManifest, status, "test-schema");
            var schema = new EventTraceOperand(metadata, 0, operands);

            using var stream = new MemoryStream();
            if (legacy)
            {
                using var writer = new LegacyJsonEventWriter(stream);
                SendRecords(writer, schema, payloads);
                writer.Complete();
                using var json = JsonDocument.Parse(stream.ToArray());
                return json.RootElement.GetProperty("Events").EnumerateArray()
                    .Select(e => e.GetProperty("Event").Clone()).ToArray();
            }

            using (var writer = new JsonlEventWriter(stream)) SendRecords(writer, schema, payloads);
            return Encoding.UTF8.GetString(stream.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(line =>
                {
                    using var json = JsonDocument.Parse(line);
                    return json.RootElement.Clone();
                }).ToArray();
        }

        private static void SendRecords<TWriter>(TWriter writer, IEventTraceOperand schema, byte[][] payloads)
            where TWriter : IEtwWriter
        {
            var deserializer = new Deserializer<TWriter>(writer)
            {
                ResolverChain = new SchemaResolver(schema),
                SourceFile = "test.etl",
            };
            foreach (byte[] payload in payloads)
            {
                fixed (byte* data = payload)
                {
                    EVENT_RECORD record = default;
                    record.ProviderId = schema.Metadata.ProviderGuid;
                    record.Id = schema.Metadata.Id;
                    record.UserData = record.UserDataFixed = data;
                    record.UserDataLength = checked((ushort)payload.Length);
                    deserializer.Deserialize(&record);
                }
                Assert.Null(deserializer.LastError);
            }
        }

        private static string ConvertBase64(byte[] value) => System.Convert.ToBase64String(value);

        private sealed class SchemaResolver : IMetadataResolverChain
        {
            private readonly IEventTraceOperand operand;
            public SchemaResolver(IEventTraceOperand operand) => this.operand = operand;
            public ResolutionResult Resolve(EventKey key) => new ResolutionResult(
                this.operand, this.operand.Metadata.MetadataSource, this.operand.Metadata.Provenance);
        }
    }
}
