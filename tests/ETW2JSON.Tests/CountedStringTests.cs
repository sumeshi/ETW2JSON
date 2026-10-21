namespace ETW2JSON.Tests
{
    using System;
    using System.Buffers.Binary;
    using System.Text;
    using ETWDeserializer;
    using Xunit;

    public sealed unsafe class CountedStringTests
    {
        [Theory]
        [InlineData(false, false)]
        [InlineData(false, true)]
        [InlineData(true, false)]
        [InlineData(true, true)]
        public void CountedStringsUseTheDeclaredByteOrderAndKeepFollowingField(bool unicode, bool reversed)
        {
            string expected = new string('A', unicode ? 129 : 258);
            byte[] text = (unicode ? Encoding.Unicode : Encoding.ASCII).GetBytes(expected);
            byte[] payload = new byte[text.Length + 3];
            if (reversed) BinaryPrimitives.WriteUInt16BigEndian(payload, (ushort)text.Length);
            else BinaryPrimitives.WriteUInt16LittleEndian(payload, (ushort)text.Length);
            text.CopyTo(payload, 2);
            payload[payload.Length - 1] = 0x7F;

            fixed (byte* data = payload)
            {
                EVENT_RECORD record = default;
                record.UserData = record.UserDataFixed = data;
                record.UserDataLength = (ushort)payload.Length;
                var reader = new EventRecordReader(&record);

                Assert.Equal(expected, Read(ref reader, unicode, reversed));
                Assert.Equal(0x7F, reader.ReadUInt8());
            }
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void OddUnicodeByteCountIsRejected(bool reversed)
        {
            byte[] payload = reversed ? new byte[] { 0, 3, 65, 0, 66 } : new byte[] { 3, 0, 65, 0, 66 };
            fixed (byte* data = payload)
            {
                EVENT_RECORD record = default;
                record.UserData = record.UserDataFixed = data;
                record.UserDataLength = (ushort)payload.Length;
                var reader = new EventRecordReader(&record);

                Assert.Throws<InvalidOperationException>(() => Read(ref reader, true, reversed));
            }
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void TruncatedReversedCountedStringsAreRejected(bool unicode)
        {
            byte[] payload = { 0, 4, 65, 0 };
            fixed (byte* data = payload)
            {
                EVENT_RECORD record = default;
                record.UserData = record.UserDataFixed = data;
                record.UserDataLength = (ushort)payload.Length;
                var reader = new EventRecordReader(&record);

                Assert.Throws<InvalidOperationException>(() => Read(ref reader, unicode, true));
            }
        }

        private static string Read(ref EventRecordReader reader, bool unicode, bool reversed)
        {
            if (unicode) return reversed ? reader.ReadReversedCountedString() : reader.ReadCountedString();
            return reversed ? reader.ReadReversedCountedAnsiString() : reader.ReadCountedAnsiString();
        }
    }
}
