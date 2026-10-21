namespace ETW2JSON.Tests
{
    using System;
    using System.Runtime.InteropServices;
    using ETWDeserializer;
    using Xunit;

    // Windows SDK declarations: shared/evntrace.h and um/evntcons.h.
    // These checks verify managed layout, not actual native ETL consumption.
    public sealed class NativeEtwLayoutTests
    {
        [Fact]
        public void InvalidOpenTraceHandleUsesTheProcessPointerWidth()
        {
            Assert.True(new Readers.TraceOpenResult(ulong.MaxValue, 5).IsInvalidHandle);
            Assert.Equal(IntPtr.Size == 4, new Readers.TraceOpenResult(uint.MaxValue, 5).IsInvalidHandle);
            Assert.False(new Readers.TraceOpenResult(1, 0).IsInvalidHandle);
        }

        [Fact]
        public void TraceLogfileHeaderMatchesWindowsSdkOffsets()
        {
            bool x64 = IntPtr.Size == 8;
            Assert.Equal(x64 ? 280 : 272, Marshal.SizeOf<TRACE_LOGFILE_HEADER>());
            Offset<TRACE_LOGFILE_HEADER>(nameof(TRACE_LOGFILE_HEADER.EventsLost), 48);
            Offset<TRACE_LOGFILE_HEADER>(nameof(TRACE_LOGFILE_HEADER.TimeZone), x64 ? 72 : 64);
            Offset<TRACE_LOGFILE_HEADER>(nameof(TRACE_LOGFILE_HEADER.PerfFreq), x64 ? 256 : 248);
            Offset<TRACE_LOGFILE_HEADER>(nameof(TRACE_LOGFILE_HEADER.ReservedFlags), x64 ? 272 : 264);
            Offset<TRACE_LOGFILE_HEADER>(nameof(TRACE_LOGFILE_HEADER.BuffersLost), x64 ? 276 : 268);
        }

        [Fact]
        public void EventTraceLogfileMatchesWindowsSdkOffsets()
        {
            bool x64 = IntPtr.Size == 8;
            Assert.Equal(x64 ? 448 : 416, Marshal.SizeOf<EVENT_TRACE_LOGFILEW>());
            Offset<EVENT_TRACE_LOGFILEW>(nameof(EVENT_TRACE_LOGFILEW.CurrentEvent), x64 ? 32 : 24);
            Offset<EVENT_TRACE_LOGFILEW>(nameof(EVENT_TRACE_LOGFILEW.LogfileHeader), x64 ? 120 : 112);
            Offset<EVENT_TRACE_LOGFILEW>(nameof(EVENT_TRACE_LOGFILEW.BufferCallback), x64 ? 400 : 384);
            Offset<EVENT_TRACE_LOGFILEW>(nameof(EVENT_TRACE_LOGFILEW.EventsLost), x64 ? 416 : 396);
            Offset<EVENT_TRACE_LOGFILEW>(nameof(EVENT_TRACE_LOGFILEW.EventRecordCallback), x64 ? 424 : 400);
            Offset<EVENT_TRACE_LOGFILEW>(nameof(EVENT_TRACE_LOGFILEW.Context), x64 ? 440 : 408);
        }

        [Fact]
        public void EventRecordMatchesWindowsSdkOffsets()
        {
            bool x64 = IntPtr.Size == 8;
            Assert.Equal(x64 ? 112 : 104, Marshal.SizeOf<EVENT_RECORD>());
            Offset<EVENT_RECORD>(nameof(EVENT_RECORD.Flags), 4);
            Offset<EVENT_RECORD>(nameof(EVENT_RECORD.Id), 40);
            Offset<EVENT_RECORD>(nameof(EVENT_RECORD.Keyword), 48);
            Offset<EVENT_RECORD>(nameof(EVENT_RECORD.ExtendedData), 88);
            Offset<EVENT_RECORD>(nameof(EVENT_RECORD.UserData), x64 ? 96 : 92);
            Offset<EVENT_RECORD>(nameof(EVENT_RECORD.UserDataFixed), x64 ? 104 : 96);
        }

        [Fact]
        public void CounterAndTimezoneFieldSignednessMatchesWindowsSdk()
        {
            Assert.Equal(typeof(uint), typeof(EVENT_TRACE_LOGFILEW).GetField(nameof(EVENT_TRACE_LOGFILEW.BufferSize)).FieldType);
            Assert.Equal(typeof(uint), typeof(EVENT_TRACE_LOGFILEW).GetField(nameof(EVENT_TRACE_LOGFILEW.Filled)).FieldType);
            Assert.Equal(typeof(uint), typeof(EVENT_TRACE_LOGFILEW).GetField(nameof(EVENT_TRACE_LOGFILEW.EventsLost)).FieldType);
            Assert.Equal(typeof(int), typeof(TIME_ZONE_INFORMATION).GetField(nameof(TIME_ZONE_INFORMATION.Bias)).FieldType);
            Assert.Equal(typeof(int), typeof(TIME_ZONE_INFORMATION).GetField(nameof(TIME_ZONE_INFORMATION.StandardBias)).FieldType);
            Assert.Equal(typeof(int), typeof(TIME_ZONE_INFORMATION).GetField(nameof(TIME_ZONE_INFORMATION.DaylightBias)).FieldType);
            Assert.Equal(172, Marshal.SizeOf<TIME_ZONE_INFORMATION>());
        }

        private static void Offset<T>(string field, int expected) where T : struct
        {
            Assert.Equal(expected, Marshal.OffsetOf<T>(field).ToInt32());
        }
    }
}
