namespace ETW2JSON.Tests
{
    using System;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Text.Json;
    using ETWDeserializer;
    using Xunit;

    public sealed unsafe class TdhInt64SignTests
    {
        [Theory]
        [InlineData(false, -204L)]
        [InlineData(false, long.MinValue)]
        [InlineData(false, 0L)]
        [InlineData(false, long.MaxValue)]
        [InlineData(true, -204L)]
        [InlineData(true, long.MinValue)]
        [InlineData(true, 0L)]
        [InlineData(true, long.MaxValue)]
        public void TdhIntegerDeclarationControlsSignRegardlessOfPropertyName(bool legacy, long value)
        {
            var operand = BuildTdhOperand();
            byte[] bits = BitConverter.GetBytes(value);
            byte[] payload = new byte[3 * sizeof(long)];
            for (int i = 0; i < 3; i++) bits.CopyTo(payload, i * sizeof(long));
            using var stream = new MemoryStream();
            JsonElement evt;
            if (legacy)
            {
                using var writer = new LegacyJsonEventWriter(stream);
                Send(writer, operand, payload);
                writer.Complete();
                using var json = JsonDocument.Parse(stream.ToArray());
                evt = json.RootElement.GetProperty("Events")[0].GetProperty("Event").Clone();
            }
            else
            {
                using (var writer = new JsonlEventWriter(stream)) Send(writer, operand, payload);
                using var json = JsonDocument.Parse(stream.ToArray());
                evt = json.RootElement.Clone();
            }

            Assert.Equal("decoded", evt.GetProperty("decode_status").GetString());
            var properties = legacy ? evt.GetProperty("Properties")[0] : evt.GetProperty("properties");
            Assert.Equal(value, properties.GetProperty("Signed64").GetInt64());
            Assert.Equal(unchecked((ulong)value), properties.GetProperty("Unsigned64").GetUInt64());
            Assert.Equal(unchecked((ulong)value), properties.GetProperty("int64_type").GetUInt64());
            Assert.Equal(payload, evt.GetProperty("raw_payload").GetBytesFromBase64());
        }

        [Fact]
        public void PublicPrimitiveSampleDeclaresBoth64BitFieldsUnsigned()
        {
            // PerfView 29b21620a6c295979e83dc99008262ad2f3c6a2d,
            // src/TraceEvent/TraceEvent.Tests/inputs/primitive-types.etl.zip,
            // ETL SHA256 66df3cefc602cf91718faecb290a6dd38e7a6e494fac37f4a9176f8e581af50b,
            // record 2, EVENT_SCHEMA_TL bytes. MIT license accompanies our real-record fixtures.
            // The text baseline renders int64_type as negative, but its metadata has
            // neither the signed type 9 nor a chained signed output format.
            byte[] schema = Convert.FromBase64String("tgAAUHJpbWl0aXZlVHlwZXNUZXN0AHN0cmluZ190eXBlAAJib29sZWFuX3R5cGUAhANjaGFyX3R5cGUAhAJpbnQxNl90eXBlAAVpbnQzMl90eXBlAAd1aW50MTZfdHlwZQAGdWludDMyX3R5cGUACGludDY0X3R5cGUACnVpbnQ2NF90eXBlAApndWlkX3R5cGUAD2ZpbGVfdGltZV90eXBlABFzeXN0ZW1fdGltZV90eXBlABI=");
            Assert.Equal("int64_type\0", Encoding.UTF8.GetString(schema, 112, 11));
            Assert.Equal("uint64_type\0", Encoding.UTF8.GetString(schema, 124, 12));
            Assert.Equal(10, schema[123]);
            Assert.Equal(10, schema[136]);
            Assert.Equal((byte)TDH_IN_TYPE.TDH_INTYPE_UINT64, schema[123]);
        }

        private static IEventTraceOperand BuildTdhOperand()
        {
            string[] names = { "Signed64", "Unsigned64", "int64_type" };
            int propertyOffset = Marshal.OffsetOf<TRACE_EVENT_INFO>(nameof(TRACE_EVENT_INFO.EventPropertyInfoArray)).ToInt32();
            int nameOffset = propertyOffset + names.Length * sizeof(EVENT_PROPERTY_INFO);
            byte[] buffer = new byte[nameOffset + 128];
            fixed (byte* data = buffer)
            {
                var info = (TRACE_EVENT_INFO*)data;
                info->ProviderGuid = Guid.NewGuid();
                info->DecodingSource = DECODING_SOURCE.DecodingSourceTlg;
                info->PropertyCount = info->TopLevelPropertyCount = (uint)names.Length;
                var properties = (EVENT_PROPERTY_INFO*)(data + propertyOffset);
                for (int i = 0; i < names.Length; i++)
                {
                    byte[] name = Encoding.Unicode.GetBytes(names[i] + "\0");
                    name.CopyTo(buffer, nameOffset);
                    properties[i].NameOffset = (uint)nameOffset;
                    properties[i].NonStructType.InType = (ushort)(i == 0 ? TDH_IN_TYPE.TDH_INTYPE_INT64 : TDH_IN_TYPE.TDH_INTYPE_UINT64);
                    properties[i].count = 1;
                    nameOffset += name.Length;
                }
                Assert.True(EventTraceOperandBuilder.IsValidTraceEventInfo(info, buffer.Length, out string reason), reason);
                return EventTraceOperandBuilder.Build(info, 0, MetadataSource.TraceLogging, "fixture:TDH-Int64-declarations");
            }
        }

        private static void Send<T>(T writer, IEventTraceOperand operand, byte[] payload) where T : IEtwWriter
        {
            var deserializer = new Deserializer<T>(writer) { ResolverChain = new Resolver(operand) };
            fixed (byte* data = payload)
            {
                var record = new EVENT_RECORD { ProviderId = operand.Metadata.ProviderGuid, UserData = data, UserDataLength = (ushort)payload.Length };
                deserializer.Deserialize(&record);
            }
            Assert.Null(deserializer.LastError);
        }

        private sealed class Resolver : IMetadataResolverChain
        {
            private readonly IEventTraceOperand operand;
            public Resolver(IEventTraceOperand operand) => this.operand = operand;
            public ResolutionResult Resolve(EventKey key) => new ResolutionResult(this.operand, MetadataSource.TraceLogging, "fixture:TDH-Int64-declarations");
        }
    }
}
