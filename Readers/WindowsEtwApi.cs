namespace ETW2JSON.Readers
{
    using System;
    using System.Runtime.InteropServices;

    /// <summary>Native ETW operations, separated so reader lifecycle paths can be exercised without Windows.</summary>
    internal interface IWindowsEtwApi
    {
        TraceOpenResult OpenTrace(ref EVENT_TRACE_LOGFILEW logfile);

        int ProcessTrace(ulong handle);

        int CloseTrace(ulong handle);
    }

    internal readonly struct TraceOpenResult
    {
        public TraceOpenResult(ulong handle, int error)
        {
            this.Handle = handle;
            this.Error = error;
        }

        public ulong Handle { get; }

        public int Error { get; }

        // OpenTrace uses (UINT64)UINTPTR_MAX on supported Windows versions.
        // Older implementations used UINT64_MAX regardless of pointer width.
        public bool IsInvalidHandle => this.Handle == ulong.MaxValue || (IntPtr.Size == 4 && this.Handle == uint.MaxValue);
    }

    internal sealed class WindowsEtwApi : IWindowsEtwApi
    {
        internal static readonly WindowsEtwApi Instance = new WindowsEtwApi();

        public TraceOpenResult OpenTrace(ref EVENT_TRACE_LOGFILEW logfile)
        {
            ulong handle = Etw.OpenTrace(ref logfile);
            // Capture the thread-local native error before diagnostics or another
            // interop call can replace it. No mutable shared error state is used.
            return new TraceOpenResult(handle, Marshal.GetLastPInvokeError());
        }

        public int ProcessTrace(ulong handle)
        {
            return Etw.ProcessTrace(new[] { handle }, 1, IntPtr.Zero, IntPtr.Zero);
        }

        public int CloseTrace(ulong handle)
        {
            return Etw.CloseTrace(handle);
        }
    }
}
