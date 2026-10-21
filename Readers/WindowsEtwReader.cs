namespace ETW2JSON.Readers
{
    using System;
    using System.Collections.Generic;
    using ETWDeserializer;

    /// <summary>
    /// Thin managed wrapper over OpenTrace/ProcessTrace/CloseTrace. Guarantees that
    /// every opened handle is closed, that native callbacks never leak a managed
    /// exception, and that each record carries the ETL file it came from.
    /// </summary>
    public sealed class WindowsEtwReader
    {
        private WindowsEtwReader()
        {
        }

        public static WindowsEtwReader<TWriter> Create<TWriter>(TWriter writer, Action<string> reportError, Func<ushort, string> sourceLookup)
            where TWriter : IEtwWriter
        {
            return new WindowsEtwReader<TWriter>(writer, reportError, sourceLookup);
        }
    }

    /// <summary>Typed reader over the native ETW file APIs.</summary>
    public sealed class WindowsEtwReader<TWriter>
        where TWriter : IEtwWriter
    {
        private readonly Deserializer<TWriter> deserializer;
        private readonly Action<string> reportError;
        private readonly Func<ushort, string> sourceLookup;
        private readonly IWindowsEtwApi nativeApi;

        internal WindowsEtwReader(TWriter writer, Action<string> reportError, Func<ushort, string> sourceLookup)
            : this(writer, reportError, sourceLookup, WindowsEtwApi.Instance)
        {
        }

        internal WindowsEtwReader(TWriter writer, Action<string> reportError, Func<ushort, string> sourceLookup, IWindowsEtwApi nativeApi)
        {
            this.deserializer = new Deserializer<TWriter>(writer);
            this.reportError = reportError ?? (_ => { });
            this.sourceLookup = sourceLookup;
            this.nativeApi = nativeApi ?? throw new ArgumentNullException(nameof(nativeApi));
            this.deserializer.SourceFileLookup = sourceLookup;
        }

        public Deserializer<TWriter> Deserializer => this.deserializer;

        /// <summary>
        /// Opens and processes every input file. Returns null on success, otherwise an
        /// error message suitable for stderr. All handles are released on both paths.
        /// </summary>
        public unsafe string Process(IReadOnlyList<string> inputFiles)
        {
            int count = inputFiles.Count;
            if (count == 0)
            {
                return "No input files were provided.";
            }

            var clockBySource = new Dictionary<string, TraceClockMetadata>(StringComparer.OrdinalIgnoreCase);
            this.deserializer.TraceClockLookup = source =>
                source != null && clockBySource.TryGetValue(source, out var clock) ? clock : null;
            this.deserializer.ResetErrors();

            // Process files one at a time so source path and clock metadata remain
            // unambiguous for every callback, including same-LoggerId ETLs.
            for (int i = 0; i < count; ++i)
            {
                var fileSession = new EVENT_TRACE_LOGFILEW
                {
                    LogFileName = inputFiles[i],
                    EventRecordCallback = this.deserializer.Deserialize,
                    BufferCallback = this.deserializer.BufferCallback,
                    LogFileMode = global::ETW2JSON.Etw.PROCESS_TRACE_MODE_EVENT_RECORD | global::ETW2JSON.Etw.PROCESS_TRACE_MODE_RAW_TIMESTAMP,
                };
                var opened = this.nativeApi.OpenTrace(ref fileSession);
                ulong handle = opened.Handle;
                if (opened.IsInvalidHandle)
                {
                    this.reportError("ClosedOpenTraceError");
                    return "Failed to open ETL file: " + inputFiles[i] + " (win32=" + opened.Error + ")";
                }

                try
                {
                    var header = fileSession.LogfileHeader;
                    if (header.EventsLost != 0 || header.BuffersLost != 0)
                    {
                        this.reportError(FormattableString.Invariant(
                            $"WARNING: ETL reports collection loss for '{inputFiles[i]}': events_lost={header.EventsLost}; buffers_lost={header.BuffersLost}. Records lost during collection cannot appear in the output."));
                    }
                    clockBySource[inputFiles[i]] = new TraceClockMetadata(header.PerfFreq, header.StartTime, header.BootTime, header.ReservedFlags);
                    this.deserializer.SetCurrentSource(inputFiles[i]);
                    int result = this.nativeApi.ProcessTrace(handle);
                    if (this.deserializer.LastError != null)
                    {
                        return "Event callback failed: " + this.deserializer.LastError.GetType().Name + ": " + this.deserializer.LastError.Message;
                    }
                    if (result != 0)
                    {
                        return "ProcessTrace failed for ETL file: " + inputFiles[i] + " (win32=" + result + ").";
                    }
                }
                finally
                {
                    this.nativeApi.CloseTrace(handle);
                    GC.KeepAlive(fileSession);
                }
            }

            return null;
        }
    }
}
