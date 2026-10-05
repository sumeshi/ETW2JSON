namespace ETW2JSON.FixtureEmitter
{
    using System;
    using System.Diagnostics.Tracing;
    using System.IO;
    using System.Runtime.InteropServices;
    using ETW2JSON.TestFixtures;
    using System.Threading;

    internal static class Program
    {
        private const string ProviderGuid = "e41f4c57-9a82-4e2d-8b31-c7fb7b930001";
        private const string TraceLoggingProviderGuid = "4c5b5fd0-7bb4-457a-ad3f-6da89e7f0003";
        internal const string ManifestProviderGuidForInterop = "9ab0e68d-70c1-4e5a-938c-1390a31a0002";

        private static int Main(string[] args)
        {
            if (args.Length == 2 && args[0] == "--generate-pe")
            {
                try
                {
                    using (var output = new FileStream(args[1], FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        byte[] image = SyntheticProviderPeBuilder.Build();
                        output.Write(image, 0, image.Length);
                    }
                    return 0;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(ex.Message);
                    return 2;
                }
            }

            if (args.Length == 4 && args[0] == "--manifest-only")
            {
                File.WriteAllText(args[1], EventSource.GenerateManifest(typeof(FixtureEventSource), typeof(Program).Assembly.Location));
                File.Copy(args[2], args[3], overwrite: true);
                return 0;
            }

            if (args.Length != 3 || args[0] != "--emit" || args[1] != "--count" ||
                !int.TryParse(args[2], out int count) || count < 1 || count > 10000)
            {
                Console.Error.WriteLine("Usage: fixture-emitter --manifest-only PATH | --generate-pe PATH | --emit --count N");
                return 1;
            }

            using (var provider = new FixtureEventSource())
            using (var manifestProvider = new ManifestFixtureProvider())
            using (var traceLoggingProvider = new FixtureTraceLoggingSource())
            {
                // Give the ETW controller time to deliver its enable command before emission.
                Thread.Sleep(500);
                for (int i = 0; i < count; i++)
                {
                    provider.KnownPayload(i + 1, "fixture-record-" + (i + 1),
                        Guid.Parse("00000000-0000-0000-0000-" + (i + 1).ToString("x12")));
                    manifestProvider.KnownPayload(i + 1, "manifest-record-" + (i + 1),
                        Guid.Parse("10000000-0000-0000-0000-" + (i + 1).ToString("x12")));
                    traceLoggingProvider.Emit(i + 1);
                }

                Thread.Sleep(500);
            }

            return 0;
        }
    }

    [EventSource(Name = "ETW2JSON-TraceLogging-Fixture", Guid = "4c5b5fd0-7bb4-457a-ad3f-6da89e7f0003")]
    internal sealed class FixtureTraceLoggingSource : EventSource
    {
        public FixtureTraceLoggingSource()
            : base(EventSourceSettings.EtwSelfDescribingEventFormat)
        {
        }

        public void Emit(int sequence)
        {
            if (!this.IsEnabled()) return;
            this.Write("TLAlpha", new { sequence, message = "trace-alpha-" + sequence });
            this.Write("TLBeta", new
            {
                sequence,
                correlation = Guid.Parse("20000000-0000-0000-0000-" + sequence.ToString("x12")),
            });
        }
    }

    internal sealed unsafe class ManifestFixtureProvider : IDisposable
    {
        private readonly ulong registrationHandle;
        private static EventDescriptor descriptor = new EventDescriptor { Id = 1, Version = 1, Level = 4 };

        public ManifestFixtureProvider()
        {
            Guid providerGuid = Guid.Parse(Program.ManifestProviderGuidForInterop);
            int status = EventRegister(ref providerGuid, IntPtr.Zero, IntPtr.Zero, out ulong handle);
            this.registrationHandle = handle;
            if (status != 0) throw new InvalidOperationException("EventRegister failed: " + status);
        }

        public void KnownPayload(int sequence, string message, Guid correlation)
        {
            fixed (char* messagePointer = message)
            {
                EventDataDescriptor* data = stackalloc EventDataDescriptor[3];
                data[0] = new EventDataDescriptor { Pointer = (ulong)&sequence, Size = sizeof(int) };
                data[1] = new EventDataDescriptor { Pointer = (ulong)messagePointer, Size = (uint)((message.Length + 1) * sizeof(char)) };
                data[2] = new EventDataDescriptor { Pointer = (ulong)&correlation, Size = (uint)sizeof(Guid) };
                int status = EventWrite(this.registrationHandle, ref descriptor, 3, data);
                if (status != 0) throw new InvalidOperationException("EventWrite failed: " + status);
            }
        }

        public void Dispose()
        {
            if (this.registrationHandle != 0) EventUnregister(this.registrationHandle);
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EventDescriptor
        {
            public ushort Id;
            public byte Version;
            public byte Channel;
            public byte Level;
            public byte Opcode;
            public ushort Task;
            public ulong Keyword;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EventDataDescriptor
        {
            public ulong Pointer;
            public uint Size;
            public uint Reserved;
        }

        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern int EventRegister(ref Guid providerId, IntPtr callback, IntPtr context, out ulong registrationHandle);

        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern int EventWrite(ulong registrationHandle, ref EventDescriptor eventDescriptor, int userDataCount, EventDataDescriptor* userData);

        [DllImport("advapi32.dll", ExactSpelling = true)]
        private static extern int EventUnregister(ulong registrationHandle);
    }

    [EventSource(Name = "ETW2JSON-Fixture", Guid = "e41f4c57-9a82-4e2d-8b31-c7fb7b930001")]
    internal sealed class FixtureEventSource : EventSource
    {
        [Event(1, Level = EventLevel.Informational, Message = "Known fixture payload")]
        public void KnownPayload(int sequence, string message, Guid correlation)
        {
            if (this.IsEnabled()) this.WriteEvent(1, sequence, message, correlation);
        }
    }
}
