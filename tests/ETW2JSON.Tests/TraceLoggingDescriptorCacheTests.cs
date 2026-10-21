namespace ETW2JSON.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Text.Json;
    using ETWDeserializer;
    using Xunit;

    public sealed unsafe class TraceLoggingDescriptorCacheTests
    {
        private static readonly byte[] Schema = { 16, 0, 0, 69, 118, 101, 110, 116, 0, 86, 97, 108, 117, 101, 0, 8 };
        private static readonly byte[] Traits = { 11, 0, 80, 114, 111, 118, 105, 100, 101, 114, 0 };
        private static readonly (byte Opcode, ushort Task, uint Value)[] Records =
        {
            (1, 7, 101), (2, 7, 102), (1, 7, 103), (1, 8, 104), (1, 263, 105), (1, 7, 106),
        };

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void OpcodeAndTaskKeepTheirOwnMetadataWhileRepeatedDescriptorsReuseCache(bool legacy)
        {
            var scenario = new TdhScenario();
            using var output = new MemoryStream();
            if (legacy)
            {
                using var writer = new LegacyJsonEventWriter(output);
                Send(writer, scenario);
                writer.Complete();
            }
            else
            {
                using var writer = new JsonlEventWriter(output);
                Send(writer, scenario);
            }

            var events = new List<JsonElement>();
            if (legacy)
            {
                using var document = JsonDocument.Parse(output.ToArray());
                foreach (var item in document.RootElement.GetProperty("Events").EnumerateArray())
                    events.Add(item.GetProperty("Event").Clone());
            }
            else
            {
                foreach (string line in Encoding.UTF8.GetString(output.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    using var document = JsonDocument.Parse(line);
                    events.Add(document.RootElement.Clone());
                }
            }

            Assert.Equal(Records.Length, events.Count);
            for (int i = 0; i < Records.Length; i++)
            {
                var record = Records[i];
                var evt = events[i];
                Assert.Equal("Provider/Task" + record.Task + "/" + OpcodeName(record.Opcode), evt.GetProperty(legacy ? "Name" : "event_name").GetString());
                Assert.Equal("decoded", evt.GetProperty("decode_status").GetString());
                Assert.Equal("trace_logging", evt.GetProperty("metadata_source").GetString());
                var header = evt.GetProperty("event_header");
                Assert.Equal(scenario.Provider, header.GetProperty("provider_guid").GetGuid());
                Assert.Equal(66, header.GetProperty("event_id").GetInt32());
                Assert.Equal(4, header.GetProperty("version").GetInt32());
                Assert.Equal(0x40, header.GetProperty("flags").GetInt32());
                Assert.Equal(record.Opcode, header.GetProperty("opcode").GetByte());
                Assert.Equal(record.Task, header.GetProperty("task").GetUInt16());
                var properties = legacy ? evt.GetProperty("Properties")[0] : evt.GetProperty("properties");
                Assert.Equal(record.Value, properties.GetProperty("Value").GetUInt32());
                Assert.Equal(BitConverter.GetBytes(record.Value), evt.GetProperty("raw_payload").GetBytesFromBase64());
                var extensions = evt.GetProperty("raw_extended_data");
                Assert.Equal(Schema, extensions[0].GetProperty("raw_data").GetBytesFromBase64());
                Assert.Equal(Traits, extensions[1].GetProperty("raw_data").GetBytesFromBase64());
            }

            // Each distinct task/opcode needs one size query and one TDH read.
            // Returning to an earlier descriptor reuses that descriptor's schema.
            Assert.Equal(8, scenario.Calls);
            Assert.Equal(4, scenario.DescriptorCalls.Count);
            foreach (int calls in scenario.DescriptorCalls.Values) Assert.Equal(2, calls);
        }

        private static void Send<T>(T writer, TdhScenario scenario) where T : IEtwWriter
        {
            var deserializer = new Deserializer<T>(writer) { TdhInformationLookup = scenario.Lookup };
            fixed (byte* schema = Schema)
            fixed (byte* traits = Traits)
            {
                EVENT_HEADER_EXTENDED_DATA_ITEM* extensions = stackalloc EVENT_HEADER_EXTENDED_DATA_ITEM[2];
                extensions[0] = new EVENT_HEADER_EXTENDED_DATA_ITEM { ExtType = 0xB, DataSize = (ushort)Schema.Length, DataPtr = (ulong)schema };
                extensions[1] = new EVENT_HEADER_EXTENDED_DATA_ITEM { ExtType = 0xC, DataSize = (ushort)Traits.Length, DataPtr = (ulong)traits };
                foreach (var item in Records)
                {
                    uint value = item.Value;
                    var record = new EVENT_RECORD
                    {
                        ProviderId = scenario.Provider, Id = 66, Version = 4, Flags = 0x40,
                        Opcode = item.Opcode, Task = item.Task, UserData = (byte*)&value, UserDataLength = sizeof(uint),
                        ExtendedData = extensions, ExtendedDataCount = 2,
                    };
                    deserializer.Deserialize(&record);
                    Assert.Null(deserializer.LastError);
                }
            }
        }

        private static string OpcodeName(byte opcode) => opcode == 1 ? "Start" : "Stop";

        private sealed class TdhScenario
        {
            public Guid Provider { get; } = Guid.NewGuid();
            public int Calls { get; private set; }
            public Dictionary<(byte Opcode, ushort Task), int> DescriptorCalls { get; } = new();

            public int Lookup(EVENT_RECORD* record, uint count, IntPtr context, byte* buffer, ref uint size)
            {
                this.Calls++;
                var descriptor = (record->Opcode, record->Task);
                this.DescriptorCalls.TryGetValue(descriptor, out int calls);
                this.DescriptorCalls[descriptor] = calls + 1;
                byte[][] names =
                {
                    Encoding.Unicode.GetBytes("Provider\0"),
                    Encoding.Unicode.GetBytes("Task" + record->Task.ToString(CultureInfo.InvariantCulture) + "\0"),
                    Encoding.Unicode.GetBytes(OpcodeName(record->Opcode) + "\0"),
                    Encoding.Unicode.GetBytes("Value\0"),
                };
                int propertyOffset = Marshal.OffsetOf<TRACE_EVENT_INFO>(nameof(TRACE_EVENT_INFO.EventPropertyInfoArray)).ToInt32();
                int offset = propertyOffset + sizeof(EVENT_PROPERTY_INFO);
                uint required = (uint)offset;
                foreach (byte[] name in names) required += (uint)name.Length;
                if (buffer == null) { size = required; return 122; }
                Assert.Equal(required, size);
                new Span<byte>(buffer, (int)size).Clear();
                var info = (TRACE_EVENT_INFO*)buffer;
                info->ProviderGuid = record->ProviderId;
                info->Id = record->Id;
                info->Version = record->Version;
                info->Opcode = record->Opcode;
                info->Task = record->Task;
                info->DecodingSource = DECODING_SOURCE.DecodingSourceTlg;
                info->PropertyCount = info->TopLevelPropertyCount = 1;
                uint[] offsets = new uint[names.Length];
                for (int i = 0; i < names.Length; i++)
                {
                    offsets[i] = (uint)offset;
                    Marshal.Copy(names[i], 0, (IntPtr)(buffer + offset), names[i].Length);
                    offset += names[i].Length;
                }
                info->ProviderNameOffset = offsets[0];
                info->TaskNameOffset = offsets[1];
                info->OpcodeNameOffset = offsets[2];
                var property = (EVENT_PROPERTY_INFO*)(buffer + propertyOffset);
                property->NameOffset = offsets[3];
                property->NonStructType.InType = (ushort)TDH_IN_TYPE.TDH_INTYPE_UINT32;
                property->count = 1;
                return 0;
            }
        }
    }
}
