using System.ComponentModel;
using System.Runtime.InteropServices;

namespace ETW2JSON.NativeValidation;

// These independent declarations follow Windows SDK evntrace.h/evntcons.h.
// They deliberately do not reference ETW2JSON's native reader or TraceEvent internals.
internal static class NativeRawReader
{
    internal static void ValidateLayout()
    {
        if (IntPtr.Size != 8 || Marshal.SizeOf<EventHeader>() != 80 || Marshal.SizeOf<EventRecord>() != 112
            || Marshal.SizeOf<LogFile>() != 448 || Marshal.OffsetOf<LogFile>(nameof(LogFile.EventCallback)).ToInt32() != 424)
            throw new InvalidOperationException("The Windows SDK interop layout does not match Windows x64.");
    }

    internal static NativeSession Read(string path, Action<RawRecord> observe)
    {
        if (!OperatingSystem.IsWindows() || IntPtr.Size != 8)
            throw new PlatformNotSupportedException("Native validation requires a Windows x64 process.");
        ValidateLayout();

        Exception? callbackError = null;
        EventCallback callback = address =>
        {
            if (callbackError != null) return;
            try
            {
                var record = Marshal.PtrToStructure<EventRecord>(address);
                var bytes = new byte[record.UserDataLength];
                if (bytes.Length != 0)
                {
                    if (record.UserData == IntPtr.Zero) throw new InvalidDataException("Native record has a null payload pointer.");
                    Marshal.Copy(record.UserData, bytes, 0, bytes.Length);
                }
                bool traceLogging = false;
                int schemaItems = 0;
                Dictionary<string, TraceLoggingScalarDeclaration>? scalarTypes = null;
                for (int i = 0; record.ExtendedData != IntPtr.Zero && i < record.ExtendedDataCount; i++)
                {
                    // EVENT_HEADER_EXTENDED_DATA_ITEM is 16 bytes; ExtType is at
                    // offset 2. This is a mapping hint, not extended-data validation.
                    if (unchecked((ushort)Marshal.ReadInt16(record.ExtendedData, i * 16 + 2)) == 0x000b)
                    {
                        traceLogging = true;
                        schemaItems++;
                        int size = unchecked((ushort)Marshal.ReadInt16(record.ExtendedData, i * 16 + 6));
                        IntPtr data = Marshal.ReadIntPtr(record.ExtendedData, i * 16 + 8);
                        if (schemaItems == 1 && size != 0 && data != IntPtr.Zero)
                        {
                            var schema = new byte[size];
                            Marshal.Copy(data, schema, 0, size);
                            if (TraceLoggingScalarSchema.TryRead(schema, out var declarations)) scalarTypes = declarations;
                        }
                        else scalarTypes = null;
                    }
                }
                observe(new RawRecord(record.Header, bytes, traceLogging, scalarTypes));
            }
            catch (Exception error)
            {
                // Never unwind a managed exception through ProcessTrace's native callback.
                callbackError = error;
            }
        };
        BufferCallback bufferCallback = _ => callbackError == null ? 1u : 0u;
        var logfile = new LogFile
        {
            LogFileName = path,
            ProcessTraceMode = 0x10000000 | 0x00001000, // EVENT_RECORD | RAW_TIMESTAMP
            EventCallback = callback,
            BufferCallback = bufferCallback,
        };
        ulong handle = OpenTrace(ref logfile);
        int openError = Marshal.GetLastWin32Error();
        if (handle == ulong.MaxValue) throw new Win32Exception(openError, "Independent OpenTraceW failed.");
        var session = new NativeSession(logfile.Header.PerformanceFrequency, logfile.Header.ReservedFlags,
            logfile.Header.EventsLost, logfile.Header.BuffersLost);
        uint result;
        try
        {
            result = ProcessTrace([handle], 1, IntPtr.Zero, IntPtr.Zero);
        }
        finally
        {
            session.CloseTraceStatus = CloseTrace(handle);
            GC.KeepAlive(callback);
            GC.KeepAlive(bufferCallback);
        }
        if (callbackError != null) throw new InvalidOperationException("Independent raw-record callback failed.", callbackError);
        if (result != 0) throw new Win32Exception(unchecked((int)result), "Independent ProcessTrace failed.");
        if (session.CloseTraceStatus != 0) throw new Win32Exception(unchecked((int)session.CloseTraceStatus), "Independent CloseTrace failed.");
        return session;
    }

    [DllImport("advapi32.dll", EntryPoint = "OpenTraceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ulong OpenTrace([In, Out] ref LogFile logfile);

    [DllImport("advapi32.dll")]
    private static extern uint ProcessTrace([In] ulong[] handles, uint count, IntPtr start, IntPtr end);

    [DllImport("advapi32.dll")]
    private static extern uint CloseTrace(ulong handle);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void EventCallback(IntPtr record);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint BufferCallback(IntPtr logfile);

    [StructLayout(LayoutKind.Sequential)]
    internal struct EventHeader
    {
        public ushort Size, HeaderType, Flags, EventProperty;
        public uint ThreadId, ProcessId;
        public long Timestamp;
        public Guid ProviderId;
        public ushort Id;
        public byte Version, Channel, Level, Opcode;
        public ushort Task;
        public ulong Keyword;
        public uint KernelTime, UserTime;
        public Guid ActivityId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EventRecord
    {
        public EventHeader Header;
        public uint BufferContext;
        public ushort ExtendedDataCount, UserDataLength;
        public IntPtr ExtendedData, UserData, UserContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LegacyEventHeader
    {
        public ushort Size, FieldTypeFlags;
        public byte Type, Level;
        public ushort Version;
        public uint ThreadId, ProcessId;
        public long Timestamp;
        public Guid Guid;
        public uint KernelTime, UserTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LegacyEvent
    {
        public LegacyEventHeader Header;
        public uint InstanceId, ParentInstanceId;
        public Guid ParentGuid;
        public IntPtr MofData;
        public uint MofLength, BufferContext;
    }

    [StructLayout(LayoutKind.Explicit, Size = 172)]
    private struct TimeZoneInformation { }

    [StructLayout(LayoutKind.Sequential)]
    private struct LogHeader
    {
        public uint BufferSize, Version, ProviderVersion, NumberOfProcessors;
        public long EndTime;
        public uint TimerResolution, MaximumFileSize, LogFileMode, BuffersWritten;
        public uint StartBuffers, PointerSize, EventsLost, CpuSpeed;
        public IntPtr LoggerName, LogFileName;
        public TimeZoneInformation TimeZone;
        public long BootTime, PerformanceFrequency, StartTime;
        public uint ReservedFlags, BuffersLost;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct LogFile
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string? LogFileName;
        [MarshalAs(UnmanagedType.LPWStr)] public string? LoggerName;
        public long CurrentTime;
        public uint BuffersRead, ProcessTraceMode;
        public LegacyEvent CurrentEvent;
        public LogHeader Header;
        public BufferCallback? BufferCallback;
        public uint BufferSize, Filled, EventsLost;
        public EventCallback? EventCallback;
        public uint IsKernelTrace;
        public IntPtr Context;
    }
}

internal sealed record RawRecord(NativeRawReader.EventHeader Header, byte[] Payload, bool TraceLogging,
    Dictionary<string, TraceLoggingScalarDeclaration>? ScalarTypes = null);
internal sealed record NativeSession(long PerformanceFrequency, uint RawClockType, uint EventsLost, uint BuffersLost)
{
    public uint CloseTraceStatus { get; set; }
}
