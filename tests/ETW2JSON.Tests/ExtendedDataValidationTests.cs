namespace ETW2JSON.Tests
{
    using System;
    using ETWDeserializer;
    using Xunit;

    public sealed unsafe class ExtendedDataValidationTests
    {
        [Theory]
        [InlineData(1UL)]
        [InlineData(ulong.MaxValue)]
        public void ImpossibleDataPointerIsReportedWithoutReadingOrInventingBytes(ulong pointer)
        {
            var item = new EVENT_HEADER_EXTENDED_DATA_ITEM { ExtType = 0xBEEF, DataSize = 4, DataPtr = pointer };
            var record = new EVENT_RECORD { ExtendedData = &item, ExtendedDataCount = 1 };

            var runtime = new RuntimeEventMetadata(&record, "source.etl");

            var captured = Assert.Single(runtime.GetRawExtendedData());
            Assert.False(captured.RawDataAvailable);
            Assert.Null(captured.GetRawData());
            Assert.Contains("pointer", captured.Error, StringComparison.OrdinalIgnoreCase);
            Assert.Single(runtime.GetExtendedDataErrors());
        }

        [Fact]
        public void ExcessiveItemCountIsExplicitlyRejected()
        {
            int count = ExtendedEventDataSnapshot.MaximumItems + 1;
            EVENT_HEADER_EXTENDED_DATA_ITEM* items = stackalloc EVENT_HEADER_EXTENDED_DATA_ITEM[count];
            var record = new EVENT_RECORD { ExtendedData = items, ExtendedDataCount = (ushort)count };

            var runtime = new RuntimeEventMetadata(&record, "source.etl");

            Assert.Empty(runtime.GetRawExtendedData());
            Assert.Contains("limit", Assert.Single(runtime.GetExtendedDataErrors()), StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void ByteLimitPreservesEarlierItemsAndMarksUnavailableRemainder()
        {
            byte[] data = new byte[ushort.MaxValue];
            data[0] = 0xCA;
            int count = ExtendedEventDataSnapshot.MaximumBytes / data.Length + 1;
            fixed (byte* pointer = data)
            {
                EVENT_HEADER_EXTENDED_DATA_ITEM* items = stackalloc EVENT_HEADER_EXTENDED_DATA_ITEM[count];
                for (int i = 0; i < count; i++)
                {
                    items[i] = new EVENT_HEADER_EXTENDED_DATA_ITEM { ExtType = 0xBEEF, DataPtr = (ulong)pointer, DataSize = (ushort)data.Length };
                }
                var record = new EVENT_RECORD { ExtendedData = items, ExtendedDataCount = (ushort)count };

                var runtime = new RuntimeEventMetadata(&record, "source.etl");

                var captured = runtime.GetRawExtendedData();
                Assert.Equal(count, captured.Length);
                int copied = 0;
                foreach (ExtendedEventData item in captured) if (item.RawDataAvailable) copied += item.DataSize;
                Assert.InRange(copied, 1, ExtendedEventDataSnapshot.MaximumBytes);
                Assert.Equal(0xCA, captured[0].GetRawData()[0]);
                Assert.False(captured[^1].RawDataAvailable);
                Assert.Null(captured[^1].GetRawData());
                Assert.Contains("limit", captured[^1].Error, StringComparison.OrdinalIgnoreCase);
                Assert.Single(runtime.GetExtendedDataErrors());
            }
        }

        [Fact]
        public void ZeroByteUnknownItemIsNotConfusedWithUnavailableData()
        {
            var item = new EVENT_HEADER_EXTENDED_DATA_ITEM { ExtType = 0xBEEF, DataSize = 0, DataPtr = 0 };
            var record = new EVENT_RECORD { ExtendedData = &item, ExtendedDataCount = 1 };

            var runtime = new RuntimeEventMetadata(&record, "source.etl");

            var captured = Assert.Single(runtime.GetRawExtendedData());
            Assert.True(captured.RawDataAvailable);
            Assert.Empty(captured.GetRawData());
            Assert.Null(captured.Error);
            Assert.Empty(runtime.GetExtendedDataErrors());
        }

        [Fact]
        public void RelatedActivityWithExtraBytesIsNotSilentlyShortened()
        {
            byte* data = stackalloc byte[17];
            new Guid("11111111-1111-1111-1111-111111111111").TryWriteBytes(new Span<byte>(data, 16));
            data[16] = 0xCA;
            var item = new EVENT_HEADER_EXTENDED_DATA_ITEM { ExtType = 1, DataSize = 17, DataPtr = (ulong)data };
            var record = new EVENT_RECORD { ExtendedData = &item, ExtendedDataCount = 1 };

            var runtime = new RuntimeEventMetadata(&record, "source.etl");

            Assert.Equal(Guid.Empty, runtime.RelatedActivityId);
            var captured = Assert.Single(runtime.GetRawExtendedData());
            Assert.Equal(17, captured.GetRawData().Length);
            Assert.Equal(0xCA, captured.GetRawData()[16]);
            Assert.NotNull(captured.Error);
            Assert.Single(runtime.GetExtendedDataErrors());
        }

        [Theory]
        [InlineData((ushort)1)]
        [InlineData((ushort)6)]
        public void DuplicateKnownItemsArePreservedWithoutChoosingOneInterpretation(ushort type)
        {
            ulong* data = stackalloc ulong[] { 42, 0x1234 };
            EVENT_HEADER_EXTENDED_DATA_ITEM* items = stackalloc EVENT_HEADER_EXTENDED_DATA_ITEM[2];
            items[0] = items[1] = new EVENT_HEADER_EXTENDED_DATA_ITEM { ExtType = type, DataSize = 16, DataPtr = (ulong)data };
            var record = new EVENT_RECORD { ExtendedData = items, ExtendedDataCount = 2 };

            var runtime = new RuntimeEventMetadata(&record, "source.etl");

            Assert.Equal(2, runtime.GetRawExtendedData().Length);
            Assert.Contains("Multiple", Assert.Single(runtime.GetExtendedDataErrors()), StringComparison.Ordinal);
            Assert.Equal(Guid.Empty, runtime.RelatedActivityId);
            Assert.Null(runtime.GetStacks(out ulong matchId));
            Assert.Equal(0UL, matchId);
        }
    }
}
