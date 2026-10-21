namespace ETW2JSON.Tests
{
    using System;
    using System.IO;
    using System.Text.Json;
    using ETWDeserializer;
    using Xunit;

    public sealed unsafe class TdhOutputTypeTests
    {
        [Theory]
        [InlineData(false, 0)]
        [InlineData(false, 1)]
        [InlineData(false, 255)]
        [InlineData(true, 0)]
        [InlineData(true, 1)]
        [InlineData(true, 255)]
        public void TraceLoggingByteBooleanIsRenderedAsBoolean(bool legacy, byte value)
        {
            var property = new PropertyMetadata(TDH_IN_TYPE.TDH_INTYPE_UINT8, TDH_OUT_TYPE.TDH_OUTTYPE_BOOLEAN,
                "boolean_type", false, false, 0, null);
            var field = new EventTracePropertyOperand(property, 0, false, false, false, false, false);
            var evt = Decode(legacy, new[] { field }, new byte[] { value });

            Assert.Equal("decoded", evt.GetProperty("decode_status").GetString());
            Assert.Equal(value != 0, Properties(evt, legacy).GetProperty("boolean_type").GetBoolean());
        }

        [Theory]
        [InlineData(false, -204L)]
        [InlineData(false, long.MinValue)]
        [InlineData(false, long.MaxValue)]
        [InlineData(true, -204L)]
        [InlineData(true, long.MinValue)]
        [InlineData(true, long.MaxValue)]
        public void TraceLoggingUnsignedWireWithSignedLongOutputRetainsSign(bool legacy, long value)
        {
            var property = new PropertyMetadata(TDH_IN_TYPE.TDH_INTYPE_UINT64, TDH_OUT_TYPE.TDH_OUTTYPE_LONG,
                "int64_type", false, false, 0, null);
            var field = new EventTracePropertyOperand(property, 0, false, false, false, false, false);
            byte[] payload = BitConverter.GetBytes(unchecked((ulong)value));
            var evt = Decode(legacy, new[] { field }, payload);

            Assert.Equal("decoded", evt.GetProperty("decode_status").GetString());
            Assert.Equal(value, Properties(evt, legacy).GetProperty("int64_type").GetInt64());
            Assert.Equal(payload, evt.GetProperty("raw_payload").GetBytesFromBase64());
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void OutputBooleanFormattingDoesNotChangeAnArrayCountReference(bool legacy)
        {
            var countMetadata = new PropertyMetadata(TDH_IN_TYPE.TDH_INTYPE_UINT8, TDH_OUT_TYPE.TDH_OUTTYPE_BOOLEAN,
                "count", false, false, 0, null);
            var count = new EventTracePropertyOperand(countMetadata, 0, false, false, false, false, false)
            {
                IsReferencedByOtherProperties = true,
            };
            var valuesMetadata = new PropertyMetadata(TDH_IN_TYPE.TDH_INTYPE_UINT8, TDH_OUT_TYPE.TDH_OUTTYPE_NULL,
                "values", false, false, 0, null);
            var values = new EventTracePropertyOperand(valuesMetadata, 1, true, false, false, false, false);
            values.SetVariableArraySize(count);
            var evt = Decode(legacy, new[] { count, values }, new byte[] { 2, 7, 9 });

            var properties = Properties(evt, legacy);
            Assert.Equal("decoded", evt.GetProperty("decode_status").GetString());
            Assert.True(properties.GetProperty("count").GetBoolean());
            Assert.Equal(2, properties.GetProperty("values").GetArrayLength());
            Assert.Equal(7, properties.GetProperty("values")[0].GetInt32());
            Assert.Equal(9, properties.GetProperty("values")[1].GetInt32());
        }

        private static JsonElement Properties(JsonElement evt, bool legacy) => legacy
            ? evt.GetProperty("Properties")[0] : evt.GetProperty("properties");

        private static JsonElement Decode(bool legacy, EventTracePropertyOperand[] fields, byte[] payload)
        {
            var metadata = new EventMetadata(Guid.NewGuid(), 1, 0, "Example/Event",
                Array.ConvertAll(fields, f => f.Metadata), "Example", MetadataSource.TraceLogging, DecodeStatus.Decoded, "fixture:TDH-output-type");
            var operand = new EventTraceOperand(metadata, 0, fields);
            using var stream = new MemoryStream();
            if (legacy)
            {
                using var writer = new LegacyJsonEventWriter(stream);
                Send(writer, operand, payload);
                writer.Complete();
                using var document = JsonDocument.Parse(stream.ToArray());
                return document.RootElement.GetProperty("Events")[0].GetProperty("Event").Clone();
            }
            using (var writer = new JsonlEventWriter(stream)) Send(writer, operand, payload);
            using var json = JsonDocument.Parse(stream.ToArray());
            return json.RootElement.Clone();
        }

        private static void Send<T>(T writer, IEventTraceOperand operand, byte[] payload) where T : IEtwWriter
        {
            var deserializer = new Deserializer<T>(writer) { ResolverChain = new Resolver(operand) };
            fixed (byte* data = payload)
            {
                var record = new EVENT_RECORD { ProviderId = operand.Metadata.ProviderGuid, Id = 1, UserData = data, UserDataLength = (ushort)payload.Length };
                deserializer.Deserialize(&record);
            }
            Assert.Null(deserializer.LastError);
        }

        private sealed class Resolver : IMetadataResolverChain
        {
            private readonly IEventTraceOperand operand;
            public Resolver(IEventTraceOperand operand) => this.operand = operand;
            public ResolutionResult Resolve(EventKey key) => new ResolutionResult(this.operand, MetadataSource.TraceLogging, "fixture:TDH-output-type");
        }
    }
}
