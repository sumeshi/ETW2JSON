namespace ETWDeserializer
{
    using System;
    using System.Runtime.InteropServices;

    /// <summary>Clock parameters copied from the input ETL header.</summary>
    public sealed class TraceClockMetadata
    {
        public TraceClockMetadata(long performanceFrequency, long startTime, long bootTime, uint clockType)
        {
            this.PerformanceFrequency = performanceFrequency;
            this.StartTime = startTime;
            this.BootTime = bootTime;
            this.ClockType = clockType;
        }

        public long PerformanceFrequency { get; }

        public long StartTime { get; }

        public long BootTime { get; }

        public uint ClockType { get; }
    }

    /// <summary>Managed snapshot of the event header and payload, safe after the native callback returns.</summary>
    public struct RuntimeEventMetadata
    {
        private readonly EVENT_RECORD eventRecord;

        private readonly string sourceFile;

        private readonly byte[] rawPayload;

        private readonly Guid relatedActivityId;

        private readonly ulong[] stacks;

        private readonly ulong stackMatchId;

        private readonly ExtendedEventData[] rawExtendedData;

        private readonly string[] extendedDataErrors;

        internal unsafe RuntimeEventMetadata(EVENT_RECORD* eventRecord)
            : this(eventRecord, null, null)
        {
        }

        internal unsafe RuntimeEventMetadata(EVENT_RECORD* eventRecord, string sourceFile)
            : this(eventRecord, sourceFile, null)
        {
        }

        internal unsafe RuntimeEventMetadata(EVENT_RECORD* eventRecord, string sourceFile, TraceClockMetadata traceClock)
        {
            if (eventRecord == null)
            {
                throw new ArgumentNullException(nameof(eventRecord));
            }

            this.eventRecord = *eventRecord;
            this.sourceFile = sourceFile;
            this.TraceClock = traceClock;
            int length = eventRecord->UserDataLength;
            if (length > 0 && eventRecord->UserDataFixed != null)
            {
                this.rawPayload = new byte[length];
                Marshal.Copy((IntPtr)eventRecord->UserDataFixed, this.rawPayload, 0, length);
            }
            else
            {
                this.rawPayload = Array.Empty<byte>();
            }

            var extended = ExtendedEventDataSnapshot.Capture(eventRecord->ExtendedData, eventRecord->ExtendedDataCount);
            this.relatedActivityId = extended.RelatedActivityId;
            this.stacks = extended.Stacks;
            this.stackMatchId = extended.StackMatchId;
            this.rawExtendedData = extended.Items;
            this.extendedDataErrors = extended.Errors;
        }

        public string SourceFile => this.sourceFile;

        public TraceClockMetadata TraceClock { get; }

        public long RawTimestamp => this.Timestamp;

        public byte Level => this.eventRecord.Level;

        public byte Opcode => this.eventRecord.Opcode;

        public ushort Task => this.eventRecord.Task;

        public ulong Keyword => this.eventRecord.Keyword;

        public byte Channel => this.eventRecord.Channel;

        public byte Version => this.eventRecord.Version;

        public byte[] GetRawPayload() => (byte[])this.rawPayload.Clone();

        public ExtendedEventData[] GetRawExtendedData() => this.rawExtendedData == null
            ? Array.Empty<ExtendedEventData>() : (ExtendedEventData[])this.rawExtendedData.Clone();

        public string[] GetExtendedDataErrors() => this.extendedDataErrors == null
            ? Array.Empty<string>() : (string[])this.extendedDataErrors.Clone();

        public ushort Flags => this.eventRecord.Flags;

        public uint ThreadId => this.eventRecord.ThreadId;

        public uint ProcessId => this.eventRecord.ProcessId;

        public long Timestamp => this.eventRecord.TimeStamp;

        public Guid ProviderId => this.eventRecord.ProviderId;

        public ushort EventId => this.eventRecord.Id;

        public Guid ActivityId => this.eventRecord.ActivityId;

        public ushort UserDataLength => this.eventRecord.UserDataLength;

        public Guid RelatedActivityId => this.relatedActivityId;

        public ushort ProcessorNumber => (this.eventRecord.Flags & Etw.EVENT_HEADER_FLAG_PROCESSOR_INDEX) != 0
            ? (ushort)(this.eventRecord.ProcessorNumber | (this.eventRecord.Alignment << 8))
            : this.eventRecord.ProcessorNumber;

        public ulong[] GetStacks(out ulong matchId)
        {
            matchId = this.stackMatchId;
            return this.stacks == null ? null : (ulong[])this.stacks.Clone();
        }
    }
}
