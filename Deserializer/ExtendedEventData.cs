namespace ETWDeserializer
{
    using System;
    using System.Buffers.Binary;
    using System.Collections.Generic;
    using System.Runtime.InteropServices;

    /// <summary>An owned copy of an extended-data item, excluding its process-local native address.</summary>
    public sealed class ExtendedEventData
    {
        private readonly byte[] rawData;

        internal ExtendedEventData(ushort type, ushort reserved1, ushort flags, ushort size, byte[] rawData, string error)
        {
            this.ExtType = type;
            this.Reserved1 = reserved1;
            this.Flags = flags;
            this.DataSize = size;
            this.rawData = rawData;
            this.Error = error;
        }

        public ushort ExtType { get; }

        public ushort Reserved1 { get; }

        /// <summary>The original Linkage/Reserved2 bitfield.</summary>
        public ushort Flags { get; }

        public bool Linkage => (this.Flags & 1) != 0;

        public ushort DataSize { get; }

        public bool RawDataAvailable => this.rawData != null;

        public string Error { get; }

        /// <summary>Null means bytes were unavailable; an empty array means a genuine zero-byte item.</summary>
        public byte[] GetRawData() => this.rawData == null ? null : (byte[])this.rawData.Clone();
    }

    internal sealed class ExtendedEventDataSnapshot
    {
        internal const int MaximumItems = 1024;
        internal const int MaximumBytes = 16 * 1024 * 1024;

        private ExtendedEventDataSnapshot()
        {
        }

        public ExtendedEventData[] Items { get; private set; } = Array.Empty<ExtendedEventData>();

        public string[] Errors { get; private set; } = Array.Empty<string>();

        public Guid RelatedActivityId { get; private set; }

        public ulong[] Stacks { get; private set; }

        public ulong StackMatchId { get; private set; }

        public static unsafe ExtendedEventDataSnapshot Capture(EVENT_HEADER_EXTENDED_DATA_ITEM* extended, ushort count)
        {
            var snapshot = new ExtendedEventDataSnapshot();
            if (count == 0) return snapshot;
            if (count > MaximumItems)
            {
                snapshot.Errors = new[] { "Extended-data count " + count + " exceeds the per-event snapshot limit of " + MaximumItems + "; extended data was not copied." };
                return snapshot;
            }
            if (extended == null)
            {
                snapshot.Errors = new[] { "The event declares " + count + " extended-data items but the item-array pointer is null." };
                return snapshot;
            }
            if (!IsUsablePointer((ulong)extended, (ulong)(count * sizeof(EVENT_HEADER_EXTENDED_DATA_ITEM))))
            {
                snapshot.Errors = new[] { "The extended-data item-array pointer is outside the supported user-address range; extended data was not copied." };
                return snapshot;
            }

            var items = new List<ExtendedEventData>(count);
            var errors = new List<string>();
            int copiedBytes = 0;
            int stackItems = 0;
            int relatedItems = 0;
            for (int i = 0; i < count; i++)
            {
                var item = extended[i];
                byte[] rawData = null;
                string error = null;
                if (item.DataSize == 0)
                {
                    rawData = Array.Empty<byte>();
                }
                else if (item.DataPtr == 0)
                {
                    error = "The item declares " + item.DataSize + " bytes but its data pointer is null.";
                }
                else if (!IsUsablePointer(item.DataPtr, item.DataSize))
                {
                    error = "The item data pointer is outside the supported user-address range; raw bytes are unavailable.";
                }
                else if (item.DataSize > MaximumBytes - copiedBytes)
                {
                    error = "Copying this item would exceed the per-event extended-data snapshot limit of " + MaximumBytes + " bytes; raw bytes are unavailable.";
                }
                else
                {
                    rawData = new byte[item.DataSize];
                    Marshal.Copy((IntPtr)(long)item.DataPtr, rawData, 0, rawData.Length);
                    copiedBytes += rawData.Length;
                }

                if (item.ExtType == Etw.EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID)
                {
                    relatedItems++;
                    if (relatedItems > 1)
                    {
                        snapshot.RelatedActivityId = Guid.Empty;
                        error = AppendError(error, "Multiple related-activity items are present; the parsed related activity ID has been omitted.");
                    }
                    else if (rawData != null)
                    {
                        if (rawData.Length != 16)
                        {
                            error = AppendError(error, "A related-activity item must contain exactly 16 bytes.");
                        }
                        else
                        {
                            snapshot.RelatedActivityId = new Guid(rawData);
                        }
                    }
                }
                else if (item.ExtType == Etw.EVENT_HEADER_EXT_TYPE_STACK_TRACE32 || item.ExtType == Etw.EVENT_HEADER_EXT_TYPE_STACK_TRACE64)
                {
                    stackItems++;
                    if (stackItems > 1)
                    {
                        snapshot.Stacks = null;
                        snapshot.StackMatchId = 0;
                        error = AppendError(error, "Multiple stack items are present; parsed stack fields have been omitted.");
                    }
                    else if (rawData != null)
                    {
                        int width = item.ExtType == Etw.EVENT_HEADER_EXT_TYPE_STACK_TRACE32 ? 4 : 8;
                        if (rawData.Length < 8 || (rawData.Length - 8) % width != 0)
                        {
                            error = AppendError(error, "A stack item must contain an 8-byte match ID followed by complete " + width + "-byte addresses; parsed stack fields have been omitted.");
                        }
                        else
                        {
                            snapshot.StackMatchId = BinaryPrimitives.ReadUInt64LittleEndian(rawData);
                            snapshot.Stacks = new ulong[(rawData.Length - 8) / width];
                            for (int j = 0; j < snapshot.Stacks.Length; j++)
                            {
                                var address = rawData.AsSpan(8 + j * width, width);
                                snapshot.Stacks[j] = width == 4
                                    ? BinaryPrimitives.ReadUInt32LittleEndian(address)
                                    : BinaryPrimitives.ReadUInt64LittleEndian(address);
                            }
                        }
                    }
                }
                else if (item.ExtType == Etw.EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL && rawData != null && rawData.Length == 0)
                {
                    error = AppendError(error, "The TraceLogging schema item is empty.");
                }

                items.Add(new ExtendedEventData(item.ExtType, item.Reserved1, item.Reserved2, item.DataSize, rawData, error));
                if (error != null) errors.Add("Extended-data item " + i + " (type " + item.ExtType + "): " + error);
            }

            snapshot.Items = items.ToArray();
            snapshot.Errors = errors.ToArray();
            return snapshot;
        }

        private static bool IsUsablePointer(ulong pointer, ulong size)
        {
            // Windows reserves the first 64 KiB. This also rejects truncated or
            // overflowing pointers without attempting an unsafe memory read.
            ulong maximum = IntPtr.Size == 4 ? uint.MaxValue : (ulong)long.MaxValue;
            return pointer >= 0x10000 && pointer <= maximum && (size == 0 || size - 1 <= maximum - pointer);
        }

        private static string AppendError(string previous, string next) => previous == null ? next : previous + " " + next;
    }
}
