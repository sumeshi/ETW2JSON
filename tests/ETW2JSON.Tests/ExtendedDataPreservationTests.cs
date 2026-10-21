namespace ETW2JSON.Tests
{
    using System;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Text.Json;
    using ETWDeserializer;
    using Xunit;

    public sealed unsafe class ExtendedDataPreservationTests
    {
        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void ExtendedMetadataIsRetainedWithoutSerializingNativeAddresses(bool legacy)
        {
            byte[] sid = { 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0 };
            byte[] session = { 42, 0, 0, 0 };
            byte[] schema = { 6, 0, (byte)'T', 0, 0, 0 };
            byte[] unknown = { 0xCA, 0xFE };
            string originalSid = Convert.ToBase64String(sid);
            fixed (byte* sidPointer = sid, sessionPointer = session, schemaPointer = schema, unknownPointer = unknown)
            {
                EVENT_HEADER_EXTENDED_DATA_ITEM* extended = stackalloc EVENT_HEADER_EXTENDED_DATA_ITEM[4];
                extended[0] = Item(2, sidPointer, sid.Length);
                extended[0].Reserved1 = 0x1234;
                extended[0].Reserved2 = 1;
                extended[1] = Item(3, sessionPointer, session.Length);
                extended[2] = Item(11, schemaPointer, schema.Length);
                extended[3] = Item(0xBEEF, unknownPointer, unknown.Length);
                var record = new EVENT_RECORD { ExtendedData = extended, ExtendedDataCount = 4 };
                var runtime = new RuntimeEventMetadata(&record, "source.etl");
                sid[0] = 9;
                using var json = WriteEvent(runtime, legacy);
                var evt = Event(json, legacy);
                var data = evt.GetProperty("raw_extended_data");
                Assert.Equal(4, data.GetArrayLength());
                Assert.Equal(2, data[0].GetProperty("ext_type").GetInt32());
                Assert.Equal(0x1234, data[0].GetProperty("reserved1").GetInt32());
                Assert.Equal(1, data[0].GetProperty("flags").GetInt32());
                Assert.True(data[0].GetProperty("linkage").GetBoolean());
                Assert.Equal(sid.Length, data[0].GetProperty("data_size").GetInt32());
                Assert.Equal(originalSid, data[0].GetProperty("raw_data").GetString());
                Assert.Equal(Convert.ToBase64String(session), data[1].GetProperty("raw_data").GetString());
                Assert.Equal(Convert.ToBase64String(schema), data[2].GetProperty("raw_data").GetString());
                Assert.Equal(Convert.ToBase64String(unknown), data[3].GetProperty("raw_data").GetString());
                foreach (JsonElement item in data.EnumerateArray())
                {
                    Assert.False(item.TryGetProperty("data_ptr", out _));
                    Assert.False(item.TryGetProperty("data_error", out _));
                }
                Assert.False(evt.TryGetProperty("extended_data_errors", out _));
            }
        }

        [Theory]
        [InlineData(false, false)]
        [InlineData(false, true)]
        [InlineData(true, false)]
        [InlineData(true, true)]
        public void TruncatedStackIsReportedAndRetainedWithoutDroppingTrailingBytes(bool legacy, bool is64Bit)
        {
            int size = is64Bit ? 17 : 13;
            byte* bytes = stackalloc byte[size];
            for (int i = 0; i < size; i++) bytes[i] = (byte)(i + 1);
            byte[] original = new byte[size];
            Marshal.Copy((IntPtr)bytes, original, 0, size);
            var extended = Item(is64Bit ? (ushort)6 : (ushort)5, bytes, size);
            var record = new EVENT_RECORD { ExtendedData = &extended, ExtendedDataCount = 1 };
            var runtime = new RuntimeEventMetadata(&record, "source.etl");

            using var json = WriteEvent(runtime, legacy);

            var evt = Event(json, legacy);
            var item = evt.GetProperty("raw_extended_data")[0];
            Assert.Equal(Convert.ToBase64String(original), item.GetProperty("raw_data").GetString());
            Assert.Contains("stack", item.GetProperty("data_error").GetString(), StringComparison.OrdinalIgnoreCase);
            Assert.True(evt.GetProperty("extended_data_errors").GetArrayLength() > 0);
            Assert.False(evt.TryGetProperty(legacy ? "Stacks" : "stacks", out _));
            Assert.False(evt.TryGetProperty(legacy ? "StackMatchId" : "stack_match_id", out _));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void MissingPointerDoesNotProduceInventedRawBytes(bool legacy)
        {
            var extended = Item(0xBEEF, null, 4);
            var record = new EVENT_RECORD { ExtendedData = &extended, ExtendedDataCount = 1 };
            var runtime = new RuntimeEventMetadata(&record, "source.etl");

            using var json = WriteEvent(runtime, legacy);

            var evt = Event(json, legacy);
            var item = evt.GetProperty("raw_extended_data")[0];
            Assert.Equal(JsonValueKind.Null, item.GetProperty("raw_data").ValueKind);
            Assert.Contains("null", item.GetProperty("data_error").GetString(), StringComparison.OrdinalIgnoreCase);
            Assert.True(evt.GetProperty("extended_data_errors").GetArrayLength() > 0);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void MissingExtendedDataArrayIsExplicit(bool legacy)
        {
            var record = new EVENT_RECORD { ExtendedData = null, ExtendedDataCount = 1 };
            var runtime = new RuntimeEventMetadata(&record, "source.etl");

            using var json = WriteEvent(runtime, legacy);

            var evt = Event(json, legacy);
            Assert.Equal(0, evt.GetProperty("raw_extended_data").GetArrayLength());
            Assert.True(evt.GetProperty("extended_data_errors").GetArrayLength() > 0);
        }

        private static EVENT_HEADER_EXTENDED_DATA_ITEM Item(ushort type, byte* data, int size)
        {
            return new EVENT_HEADER_EXTENDED_DATA_ITEM { ExtType = type, DataPtr = (ulong)data, DataSize = (ushort)size };
        }

        private static JsonDocument WriteEvent(RuntimeEventMetadata runtime, bool legacy)
        {
            var metadata = new EventMetadata(Guid.NewGuid(), 1, 0, "Provider/Event", Array.Empty<PropertyMetadata>());
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
            return JsonDocument.Parse(stream.ToArray());
        }

        private static JsonElement Event(JsonDocument json, bool legacy) =>
            legacy ? json.RootElement.GetProperty("Events")[0].GetProperty("Event") : json.RootElement;
    }
}
