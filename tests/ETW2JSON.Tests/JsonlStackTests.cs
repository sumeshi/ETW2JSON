namespace ETW2JSON.Tests
{
    using System;
    using System.IO;
    using System.Text;
    using System.Text.Json;
    using ETWDeserializer;
    using Xunit;

    public sealed unsafe class JsonlStackTests
    {
        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void JsonlRetainsStackAddressesAndMatchIdWithoutLeakingIntoNextRecord(bool is64Bit)
        {
            const ulong matchId = 42;
            ulong firstAddress = is64Bit ? 0xFEDCBA9876543210UL : 0xFEDCBA98UL;
            ulong secondAddress = is64Bit ? 0x123456789ABCDEF0UL : 0x12345678UL;
            byte* data = stackalloc byte[24];
            *(ulong*)data = matchId;
            if (is64Bit)
            {
                ((ulong*)(data + 8))[0] = firstAddress;
                ((ulong*)(data + 8))[1] = secondAddress;
            }
            else
            {
                ((uint*)(data + 8))[0] = (uint)firstAddress;
                ((uint*)(data + 8))[1] = (uint)secondAddress;
            }
            var extended = new EVENT_HEADER_EXTENDED_DATA_ITEM
            {
                ExtType = is64Bit ? (ushort)6 : (ushort)5,
                DataSize = is64Bit ? (ushort)24 : (ushort)16,
                DataPtr = (ulong)data,
            };
            EVENT_RECORD record = default;
            record.ExtendedData = &extended;
            record.ExtendedDataCount = 1;
            var runtime = new RuntimeEventMetadata(&record, "source.etl");
            var metadata = new EventMetadata(Guid.NewGuid(), 1, 0, "Provider/Event", Array.Empty<PropertyMetadata>());
            using var stream = new MemoryStream();
            using (var writer = new JsonlEventWriter(stream))
            {
                writer.WriteEventBegin(metadata, runtime);
                writer.WriteEventEnd();
                record.ExtendedData = null;
                record.ExtendedDataCount = 0;
                writer.WriteEventBegin(metadata, new RuntimeEventMetadata(&record, "source.etl"));
                writer.WriteEventEnd();
            }

            string[] lines = Encoding.UTF8.GetString(stream.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
            Assert.Equal(2, lines.Length);
            using var first = JsonDocument.Parse(lines[0]);
            Assert.Equal(matchId, first.RootElement.GetProperty("stack_match_id").GetUInt64());
            var stacks = first.RootElement.GetProperty("stacks");
            Assert.Equal(2, stacks.GetArrayLength());
            Assert.Equal(firstAddress, stacks[0].GetUInt64());
            Assert.Equal(secondAddress, stacks[1].GetUInt64());
            using var second = JsonDocument.Parse(lines[1]);
            Assert.False(second.RootElement.TryGetProperty("stack_match_id", out _));
            Assert.False(second.RootElement.TryGetProperty("stacks", out _));
        }
    }
}
