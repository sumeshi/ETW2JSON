namespace ETWDeserializer
{
    using System;
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;
    using System.Security.Principal;

    public struct EventRecordReader
    {
        public const ulong MaximumArrayElements = 65536;

        private readonly unsafe EVENT_RECORD* eventRecord;
        private readonly ArrayElementBudget arrayElementBudget;

        internal unsafe EventRecordReader(EVENT_RECORD* eventRecord)
        {
            this.eventRecord = eventRecord;
            this.arrayElementBudget = new ArrayElementBudget();
        }

        public void ReserveArrayElements(ulong count)
        {
            this.arrayElementBudget.Reserve(count);
        }

        /// <summary>A full decode must account for every byte in the event payload.</summary>
        public void EnsurePayloadConsumed()
        {
            int remaining = this.RemainingBytes;
            if (remaining != 0)
            {
                throw new InvalidOperationException("Event payload has " + remaining + " unconsumed bytes; the schema does not describe the complete payload.");
            }
        }

        /// <summary>
        /// Reader for TDH_INTYPE_UNICODESTRING
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe string ReadUnicodeString()
        {
            int length = 0;
            byte* ptr = this.eventRecord->UserData;
            int maxLength = this.RemainingBytes;
            while (length + 1 < maxLength && !(ptr[length] == 0 && ptr[length + 1] == 0))
            {
                length += 2;
            }

            if (length + 1 >= maxLength)
            {
                throw new InvalidOperationException("Unterminated or truncated UTF-16 payload string.");
            }

            string value = new string((char*)this.eventRecord->UserData, 0, length / 2);
            this.eventRecord->UserData += length + 2;
            return value;
        }

        /// <summary>
        /// Reader for TDH_INTYPE_UNICODESTRING
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public string ReadUnicodeString(short length)
        {
            return this.ReadUnicodeStringHelper(length);
        }

        /// <summary>
        /// Reader for TDH_INTYPE_UNICODESTRING
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public string ReadUnicodeString(ushort length)
        {
            return this.ReadUnicodeStringHelper(length);
        }

        /// <summary>
        /// Reader for TDH_INTYPE_UNICODESTRING
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public string ReadUnicodeString(int length)
        {
            return this.ReadUnicodeStringHelper(length);
        }

        /// <summary>
        /// Reader for TDH_INTYPE_UNICODESTRING
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public string ReadUnicodeString(uint length)
        {
            return this.ReadUnicodeStringHelper((int)length);
        }

        /// <summary>
        /// Reader for TDH_INTYPE_ANSISTRING
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe string ReadAnsiString()
        {
            int length = 0;
            byte* ptr = this.eventRecord->UserData;
            int maxLength = this.RemainingBytes;
            while (length < maxLength && ptr[length] != 0)
            {
                ++length;
            }

            if (length == maxLength)
            {
                throw new InvalidOperationException("Unterminated payload string.");
            }

            var arr = new char[length];
            for (int i = 0; i < length; ++i)
            {
                arr[i] = (char)*ptr++;
            }

            this.eventRecord->UserData += length + 1; // +1 for null terminator
            return new string(arr);
        }

        /// <summary>
        /// Reader for TDH_INTYPE_ANSISTRING
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public string ReadAnsiString(short length)
        {
            return this.ReadAnsiStringHelper(length);
        }

        /// <summary>
        /// Reader for TDH_INTYPE_ANSISTRING
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public string ReadAnsiString(ushort length)
        {
            return this.ReadAnsiStringHelper(length);
        }

        /// <summary>
        /// Reader for TDH_INTYPE_ANSISTRING
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public string ReadAnsiString(int length)
        {
            return this.ReadAnsiStringHelper(length);
        }

        /// <summary>
        /// Reader for TDH_INTYPE_ANSISTRING
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public string ReadAnsiString(uint length)
        {
            return this.ReadAnsiStringHelper((int)length);
        }

        /// <summary>
        /// Reader for TDH_INTYPE_INT8
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe sbyte ReadInt8()
        {
            this.EnsureAvailable(sizeof(sbyte));
            sbyte value = *(sbyte*)this.eventRecord->UserData;
            this.eventRecord->UserData += sizeof(sbyte);
            return value;
        }

        /// <summary>
        /// Reader for TDH_INTYPE_UINT8
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe byte ReadUInt8()
        {
            this.EnsureAvailable(sizeof(byte));
            byte value = *this.eventRecord->UserData;
            this.eventRecord->UserData += sizeof(byte);
            return value;
        }

        /// <summary>
        /// Reader for TDH_INTYPE_INT16
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe short ReadInt16()
        {
            this.EnsureAvailable(sizeof(short));
            short value = *(short*)this.eventRecord->UserData;
            this.eventRecord->UserData += sizeof(short);
            return value;
        }

        /// <summary>
        /// Reader for TDH_INTYPE_UINT16
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe ushort ReadUInt16()
        {
            this.EnsureAvailable(sizeof(ushort));
            ushort value = *(ushort*)this.eventRecord->UserData;
            this.eventRecord->UserData += sizeof(ushort);
            return value;
        }

        /// <summary>
        /// Reader for TDH_INTYPE_INT32
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe int ReadInt32()
        {
            this.EnsureAvailable(sizeof(int));
            int value = *(int*)this.eventRecord->UserData;
            this.eventRecord->UserData += sizeof(int);
            return value;
        }

        /// <summary>
        /// Reader for TDH_INTYPE_UINT32
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe uint ReadUInt32()
        {
            this.EnsureAvailable(sizeof(uint));
            uint value = *(uint*)this.eventRecord->UserData;
            this.eventRecord->UserData += sizeof(uint);
            return value;
        }

        /// <summary>
        /// Reader for TDH_INTYPE_INT64
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe long ReadInt64()
        {
            this.EnsureAvailable(sizeof(long));
            long value = *(long*)this.eventRecord->UserData;
            this.eventRecord->UserData += sizeof(long);
            return value;
        }

        /// <summary>
        /// Reader for TDH_INTYPE_UINT64
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe ulong ReadUInt64()
        {
            this.EnsureAvailable(sizeof(ulong));
            ulong value = *(ulong*)this.eventRecord->UserData;
            this.eventRecord->UserData += sizeof(ulong);
            return value;
        }

        /// <summary>
        /// Reader for TDH_INTYPE_FLOAT
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe float ReadFloat()
        {
            this.EnsureAvailable(sizeof(float));
            float value = *(float*)this.eventRecord->UserData;
            this.eventRecord->UserData += sizeof(float);
            return value;
        }

        /// <summary>
        /// Reader for TDH_INTYPE_DOUBLE
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe double ReadDouble()
        {
            this.EnsureAvailable(sizeof(double));
            double value = *(double*)this.eventRecord->UserData;
            this.eventRecord->UserData += sizeof(double);
            return value;
        }

        /// <summary>
        /// Reader for TDH_INTYPE_BOOLEAN
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool ReadBoolean()
        {
            this.EnsureAvailable(sizeof(int));
            bool value = *(int*)this.eventRecord->UserData != 0;
            this.eventRecord->UserData += sizeof(int);
            return value;
        }

        /// <summary>
        /// Reader for TDH_INTYPE_BINARY
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe byte[] ReadBinary(short size)
        {
            this.EnsureAvailable(size);
            var value = new byte[size];
            Marshal.Copy((IntPtr)this.eventRecord->UserData, value, 0, size);
            this.eventRecord->UserData += size;
            return value;
        }

        /// <summary>
        /// Reader for TDH_INTYPE_BINARY
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe byte[] ReadBinary(ushort size)
        {
            this.EnsureAvailable(size);
            var value = new byte[size];
            Marshal.Copy((IntPtr)this.eventRecord->UserData, value, 0, size);
            this.eventRecord->UserData += size;
            return value;
        }

        /// <summary>
        /// Reader for TDH_INTYPE_BINARY
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe byte[] ReadBinary(int size)
        {
            this.EnsureAvailable(size);
            var value = new byte[size];
            Marshal.Copy((IntPtr)this.eventRecord->UserData, value, 0, size);
            this.eventRecord->UserData += size;
            return value;
        }

        /// <summary>
        /// Reader for TDH_INTYPE_BINARY
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe byte[] ReadBinary(uint size)
        {
            if (size > int.MaxValue) throw new InvalidOperationException("Payload length exceeds supported bounds.");
            this.EnsureAvailable((int)size);
            var value = new byte[size];
            Marshal.Copy((IntPtr)this.eventRecord->UserData, value, 0, (int)size);
            this.eventRecord->UserData += size;
            return value;
        }

        /// <summary>
        /// Reader for TDH_INTYPE_GUID
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe Guid ReadGuid()
        {
            this.EnsureAvailable(sizeof(Guid));
            Guid value = *(Guid*)this.eventRecord->UserData;
            this.eventRecord->UserData += sizeof(Guid);
            return value;
        }

        /// <summary>
        /// Reader for TDH_INTYPE_POINTER
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe ulong ReadPointer()
        {
            if ((eventRecord->Flags & Etw.EVENT_HEADER_FLAG_32_BIT_HEADER) == Etw.EVENT_HEADER_FLAG_32_BIT_HEADER)
            {
                return this.ReadUInt32();
            }

            return this.ReadUInt64();
        }

        /// <summary>
        /// Reader for TDH_INTYPE_FILETIME
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public DateTime ReadFileTime()
        {
            return DateTime.FromFileTimeUtc(this.ReadInt64());
        }

        /// <summary>
        /// Reader for TDH_INTYPE_SYSTEMTIME
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public DateTime ReadSystemTime()
        {
            int year = this.ReadInt16();
            int month = this.ReadInt16();
            this.ReadInt16();
            int day = this.ReadInt16();
            int hour = this.ReadInt16();
            int minute = this.ReadInt16();
            int second = this.ReadInt16();
            int milliseconds = this.ReadInt16();
            return new DateTime(year, month, day, hour, minute, second, milliseconds);
        }

        /// <summary>
        /// Reader for TDH_INTYPE_SID
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe string ReadSid()
        {
            this.EnsureAvailable(8);
            int binaryLength = 8 + (this.eventRecord->UserData[1] * 4);
            this.EnsureAvailable(binaryLength);
            var value = new SecurityIdentifier((IntPtr)this.eventRecord->UserData);
            this.eventRecord->UserData += value.BinaryLength;
            return value.Value;
        }

        /// <summary>
        /// Reader for TDH_INTYPE_COUNTEDSTRING
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe string ReadCountedString()
        {
            ushort length = this.ReadUInt16();
            return this.ReadUnicodeStringHelper(length);
        }

        /// <summary>
        /// Reader for TDH_INTYPE_COUNTEDANSISTRING
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe string ReadCountedAnsiString()
        {
            ushort length = this.ReadUInt16();
            return this.ReadAnsiStringHelper(length);
        }

        /// <summary>
        /// Reader for TDH_INTYPE_REVERSEDCOUNTEDSTRING
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe string ReadReversedCountedString()
        {
            byte high = this.ReadUInt8();
            byte low = this.ReadUInt8();
            ushort length = (ushort)((high << 8) | low);

            return this.ReadUnicodeStringHelper(length);
        }

        /// <summary>
        /// Reader for TDH_INTYPE_REVERSEDCOUNTEDANSISTRING
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe string ReadReversedCountedAnsiString()
        {
            byte high = this.ReadUInt8();
            byte low = this.ReadUInt8();
            ushort length = (ushort)((high << 8) | low);

            return this.ReadAnsiStringHelper(length);
        }

        /// <summary>
        /// Reader for TDH_INTYPE_NONNULLTERMINATEDSTRING
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe string ReadNonNullTerminatedString()
        {
            return this.ReadUnicodeStringHelper(this.RemainingBytes);
        }

        /// <summary>
        /// Reader for TDH_INTYPE_NONNULLTERMINATEDANSISTRING
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe string ReadNonNullTerminatedAnsiString()
        {
            return this.ReadAnsiStringHelper(this.RemainingBytes);
        }

        /// <summary>
        /// Reader for TDH_INTYPE_UNICODECHAR
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe char ReadUnicodeChar()
        {
            this.EnsureAvailable(sizeof(char));
            char value = *(char*)this.eventRecord->UserData;
            this.eventRecord->UserData += sizeof(char);
            return value;
        }

        /// <summary>
        /// Reader for TDH_INTYPE_ANSICHAR
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe char ReadAnsiChar()
        {
            this.EnsureAvailable(sizeof(byte));
            char value = (char)*this.eventRecord->UserData;
            this.eventRecord->UserData += 1;
            return value;
        }

        /// <summary>
        /// Reader for TDH_INTYPE_HEXDUMP
        ///
        /// https://msdn.microsoft.com/en-us/library/windows/desktop/aa363800(v=vs.85).aspx
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public byte[] ReadHexDump()
        {
            return this.ReadBinary(this.ReadInt32());
        }

        /// <summary>Consumes and returns all remaining payload bytes.</summary>
        public unsafe byte[] ReadRemainingBytes()
        {
            return this.ReadBinary(this.RemainingBytes);
        }

        /// <summary>
        /// Reader for TDH_INTYPE_WBEMSID
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe string ReadWbemSid()
        {
            int pointerSize = (eventRecord->Flags & Etw.EVENT_HEADER_FLAG_32_BIT_HEADER) == Etw.EVENT_HEADER_FLAG_32_BIT_HEADER ? 4 : 8;
            this.EnsureAvailable(pointerSize * 2);
            this.eventRecord->UserData += pointerSize * 2;
            return this.ReadSid();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe string ReadAnsiStringHelper(int length)
        {
            this.EnsureAvailable(length);
            byte* ptr = this.eventRecord->UserData;
            var arr = new char[length];
            for (int i = 0; i < length; ++i)
            {
                arr[i] = (char)*ptr++;
            }

            this.eventRecord->UserData += length;
            return new string(arr);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe string ReadUnicodeStringHelper(int length)
        {
            if ((length & 1) != 0)
            {
                throw new InvalidOperationException("UTF-16 payload string has an odd byte length.");
            }
            this.EnsureAvailable(length);
            string value = new string((char*)this.eventRecord->UserData, 0, length / 2);
            this.eventRecord->UserData += value.Length * 2;
            return value;
        }

        private unsafe int RemainingBytes
        {
            get
            {
                if (this.eventRecord == null)
                {
                    throw new InvalidOperationException("Event payload pointer is unavailable.");
                }

                if (this.eventRecord->UserDataFixed == null || this.eventRecord->UserData == null)
                {
                    if (this.eventRecord->UserDataLength == 0 && this.eventRecord->UserDataFixed == null && this.eventRecord->UserData == null)
                    {
                        return 0;
                    }
                    throw new InvalidOperationException("Event payload pointer is unavailable.");
                }

                long consumed = this.eventRecord->UserData - this.eventRecord->UserDataFixed;
                if (consumed < 0 || consumed > this.eventRecord->UserDataLength)
                {
                    throw new InvalidOperationException("Event payload cursor is outside the payload bounds.");
                }

                return this.eventRecord->UserDataLength - (int)consumed;
            }
        }

        private unsafe void EnsureAvailable(int count)
        {
            if (count < 0 || count > this.RemainingBytes)
            {
                throw new InvalidOperationException("Event payload is truncated or has an invalid length.");
            }
        }
    }
}

namespace ETWDeserializer
{
    internal sealed class ArrayElementBudget
    {
        private ulong reserved;

        public void Reserve(ulong count)
        {
            if (count > EventRecordReader.MaximumArrayElements - this.reserved)
            {
                throw new System.InvalidOperationException("ETW array element budget exceeds the safe limit of " + EventRecordReader.MaximumArrayElements + "; event retained as raw payload.");
            }
            this.reserved += count;
        }
    }
}
