namespace ETW2JSON.Tests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Text.Json;
    using ETW2JSON.Readers;
    using ETWDeserializer;
    using Xunit;

    public sealed unsafe class WindowsEtwReaderTests
    {
        [Theory]
        [InlineData(7u, 0u)]
        [InlineData(0u, 3u)]
        [InlineData(uint.MaxValue, uint.MaxValue)]
        public void CollectionLossIsReportedWithSourceWithoutDiscardingRemainingEvents(uint eventsLost, uint buffersLost)
        {
            var source = new Source("loss.etl", 10_000_000, 100, 200, 1);
            source.Header.EventsLost = eventsLost;
            source.Header.BuffersLost = buffersLost;
            var api = new FakeApi(source);
            var diagnostics = new List<string>();
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);
            var reader = Reader(writer, api, diagnostics.Add);

            Assert.Null(reader.Process(new[] { source.Path }));

            string warning = Assert.Single(diagnostics);
            Assert.Contains("WARNING", warning);
            Assert.Contains(source.Path, warning);
            Assert.Contains("events_lost=" + eventsLost, warning);
            Assert.Contains("buffers_lost=" + buffersLost, warning);
            Assert.Contains("collection", warning);
            Assert.Single(api.Closed);
            using var json = JsonDocument.Parse(output.ToArray());
            Assert.Equal(source.Path, json.RootElement.GetProperty("source_file").GetString());
        }

        [Fact]
        public void ZeroHeaderLossDoesNotProduceALossWarning()
        {
            var api = new FakeApi(new Source("zero-loss.etl", 10_000_000, 100, 200, 1));
            var diagnostics = new List<string>();
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);

            Assert.Null(Reader(writer, api, diagnostics.Add).Process(new[] { "zero-loss.etl" }));

            Assert.Empty(diagnostics);
            Assert.Single(api.Closed);
        }

        [Fact]
        public void SourceAndClockRemainDistinctWhenEtlsReuseTheSameLoggerId()
        {
            var api = new FakeApi(new Source("first.etl", 10_000_000, 111, 222, 1),
                new Source("second.etl", 24_000_000, 333, 444, 3));
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);
            var reader = Reader(writer, api, _ => { });

            Assert.Null(reader.Process(new[] { "first.etl", "second.etl" }));

            string[] lines = Encoding.UTF8.GetString(output.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
            Assert.Equal(2, lines.Length);
            for (int i = 0; i < lines.Length; i++)
            {
                using var json = JsonDocument.Parse(lines[i]);
                var source = api.Sources[i];
                Assert.Equal(source.Path, json.RootElement.GetProperty("source_file").GetString());
                var clock = json.RootElement.GetProperty("trace_clock");
                Assert.Equal(source.Header.PerfFreq, clock.GetProperty("performance_frequency").GetInt64());
                Assert.Equal(source.Header.StartTime, clock.GetProperty("start_time").GetInt64());
                Assert.Equal(source.Header.BootTime, clock.GetProperty("boot_time").GetInt64());
                Assert.Equal(source.Header.ReservedFlags, clock.GetProperty("reserved_flags").GetUInt32());
            }
            Assert.Equal(new ulong[] { 1, 2 }, api.Closed);
            Assert.All(api.Modes, mode => Assert.Equal(0x10001000u, mode));
        }

        [Fact]
        public void OpenFailureRetainsNativeErrorAndDoesNotCloseAnInvalidHandle()
        {
            var api = new FakeApi(new Source("first.etl", 1, 2, 3, 1), new Source("denied.etl", 4, 5, 6, 1))
            {
                OpenFailurePath = "denied.etl",
            };
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);

            string error = Reader(writer, api, _ => { }).Process(new[] { "first.etl", "denied.etl" });

            Assert.Contains("denied.etl", error);
            Assert.Contains("win32=5", error);
            Assert.Equal(new ulong[] { 1 }, api.Closed);
            Assert.Equal(new ulong[] { 1 }, api.Processed);
        }

        [Fact]
        public void ProcessFailureClosesTheHandleAndStopsBeforeLaterSources()
        {
            var api = new FakeApi(new Source("broken.etl", 1, 2, 3, 1), new Source("later.etl", 4, 5, 6, 1))
            {
                ProcessError = 13,
            };
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);

            string error = Reader(writer, api, _ => { }).Process(new[] { "broken.etl", "later.etl" });

            Assert.Contains("ProcessTrace failed", error);
            Assert.Contains("win32=13", error);
            Assert.Equal(new ulong[] { 1 }, api.Closed);
            Assert.Single(api.Opened);
        }

        [Fact]
        public void FatalWriterCallbackErrorCancelsFurtherBuffersAndClosesTheHandle()
        {
            var api = new FakeApi(new Source("writer-error.etl", 1, 2, 3, 1));
            using var output = new FailingStream();
            using var writer = new JsonlEventWriter(output);

            string error = Reader(writer, api, _ => { }).Process(new[] { "writer-error.etl" });

            Assert.Contains("Event callback failed", error);
            Assert.Contains("IOException", error);
            Assert.False(api.ContinueBuffers);
            Assert.Single(api.Closed);
        }

        [Fact]
        public void ManagedProcessingExceptionStillClosesTheNativeHandle()
        {
            var api = new FakeApi(new Source("exception.etl", 1, 2, 3, 1)) { ThrowDuringProcess = true };
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);

            Assert.Throws<InvalidOperationException>(() => Reader(writer, api, _ => { }).Process(new[] { "exception.etl" }));

            Assert.Single(api.Closed);
        }

        [Fact]
        public void LossDiagnosticExceptionStillClosesTheNativeHandle()
        {
            var source = new Source("loss.etl", 1, 2, 3, 1);
            source.Header.EventsLost = 1;
            var api = new FakeApi(source);
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);

            Assert.Throws<IOException>(() => Reader(writer, api, _ => throw new IOException("stderr unavailable")).Process(new[] { source.Path }));

            Assert.Single(api.Closed);
            Assert.Empty(api.Processed);
        }

        private static WindowsEtwReader<JsonlEventWriter> Reader(JsonlEventWriter writer, FakeApi api, Action<string> diagnostic)
        {
            var reader = new WindowsEtwReader<JsonlEventWriter>(writer, diagnostic, _ => "wrong-logger-source.etl", api);
            reader.Deserializer.ResolverChain = new MetadataResolver();
            return reader;
        }

        private sealed class Source
        {
            public Source(string path, long frequency, long start, long boot, uint clockType)
            {
                this.Path = path;
                this.Header = new TRACE_LOGFILE_HEADER
                {
                    PerfFreq = frequency,
                    StartTime = start,
                    BootTime = boot,
                    ReservedFlags = clockType,
                };
            }

            public string Path { get; }

            public TRACE_LOGFILE_HEADER Header;
        }

        private sealed class FakeApi : IWindowsEtwApi
        {
            private readonly Dictionary<ulong, EVENT_TRACE_LOGFILEW> active = new Dictionary<ulong, EVENT_TRACE_LOGFILEW>();
            private readonly Guid provider = Guid.NewGuid();

            public FakeApi(params Source[] sources) => this.Sources = sources;

            public Source[] Sources { get; }
            public string OpenFailurePath { get; set; }
            public int ProcessError { get; set; }
            public bool ThrowDuringProcess { get; set; }
            public bool ContinueBuffers { get; private set; }
            public List<string> Opened { get; } = new List<string>();
            public List<uint> Modes { get; } = new List<uint>();
            public List<ulong> Processed { get; } = new List<ulong>();
            public List<ulong> Closed { get; } = new List<ulong>();

            public TraceOpenResult OpenTrace(ref EVENT_TRACE_LOGFILEW logfile)
            {
                this.Opened.Add(logfile.LogFileName);
                this.Modes.Add(logfile.LogFileMode);
                if (logfile.LogFileName == this.OpenFailurePath)
                {
                    return new TraceOpenResult(IntPtr.Size == 8 ? ulong.MaxValue : uint.MaxValue, 5);
                }
                string path = logfile.LogFileName;
                logfile.LogfileHeader = this.Sources.Single(source => source.Path == path).Header;
                ulong handle = (ulong)this.Opened.Count;
                this.active.Add(handle, logfile);
                return new TraceOpenResult(handle, 0);
            }

            public int ProcessTrace(ulong handle)
            {
                this.Processed.Add(handle);
                if (this.ThrowDuringProcess) throw new InvalidOperationException("native adapter exception");
                if (this.ProcessError != 0) return this.ProcessError;
                var session = this.active[handle];
                var record = new EVENT_RECORD { ProviderId = this.provider, Id = 1, LoggerId = 7, TimeStamp = (long)handle * 100 };
                session.EventRecordCallback(&record);
                this.ContinueBuffers = session.BufferCallback(IntPtr.Zero);
                return 0;
            }

            public int CloseTrace(ulong handle)
            {
                this.Closed.Add(handle);
                Assert.True(this.active.Remove(handle));
                return 0;
            }
        }

        private sealed class FailingStream : MemoryStream
        {
            public override void Write(byte[] buffer, int offset, int count) => throw new IOException("output write failed");

            public override void Write(ReadOnlySpan<byte> buffer) => throw new IOException("output write failed");
        }
    }
}
