namespace ETW2JSON
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Text;
    using ETWDeserializer;
    using ETW2JSON.Analysis;
    using ETW2JSON.IO;
    using ETW2JSON.Readers;

    public static class Program
    {
        private const string Usage =
@"Usage: etw2json trace.etl [trace2.etl ...] [options]

Output:
  --output=PATH            Output file (also -output / /output). Default: stdout.
  --format=jsonl|json      Output format. Default: jsonl.

Metadata:
  --manifest=PATH          External event manifest (.man). Repeatable.
  --resource=PATH          Evidence PE (DLL/EXE/SYS) parsed statically. Repeatable.
  --provider-info=PATH     Exported provider XML from wevtutil; guides recovery only.
  --allow-local-metadata[=BOOL]
                           Opt in to analysis-host provider registrations (source: local_cache).

Analysis (no --output required):
  --scan                   Print providers, event ids/versions and metadata status.
  --report-missing         Print providers/events whose metadata is missing.

Forensic note: local provider registrations are disabled by default. When enabled,
they are used only after embedded and explicitly supplied metadata are missing.
Evidence binaries are parsed as data only; they are never loaded or executed.
Default output is JSONL (one event per line).";

        public static void Main(string[] args)
        {
            Environment.ExitCode = Run(args, Console.Out, Console.Error);
        }

        internal static int Run(string[] args, TextWriter stdout, TextWriter stderr)
        {
            try
            {
                return RunCore(args, stdout, stderr);
            }
            catch (IOException ex)
            {
                stderr.WriteLine("ERROR: I/O failure: " + ex.Message);
                return (int)ExitCode.IoError;
            }
            catch (UnauthorizedAccessException ex)
            {
                stderr.WriteLine("ERROR: access denied: " + ex.Message);
                return (int)ExitCode.IoError;
            }
        }

        private static int RunCore(string[] args, TextWriter stdout, TextWriter stderr)
        {
            var options = CliOptions.Parse(args, stderr);
            if (options == null)
            {
                return (int)ExitCode.Usage;
            }

            if (options.ShowHelp)
            {
                stdout.WriteLine(Usage);
                return (int)ExitCode.Success;
            }

            if (options.Inputs.Count == 0)
            {
                stderr.WriteLine("ERROR: at least one ETL input file is required.");
                stderr.WriteLine(Usage);
                return (int)ExitCode.Usage;
            }

            foreach (var input in options.Inputs)
            {
                if (!File.Exists(input))
                {
                    stderr.WriteLine("ERROR: input file not found: " + input);
                    return (int)ExitCode.IoError;
                }
            }

            if (!string.IsNullOrEmpty(options.Output) && options.Output != "-")
            {
                string outputPath = Path.GetFullPath(options.Output);
                if (File.Exists(outputPath) || Directory.Exists(outputPath))
                {
                    stderr.WriteLine("ERROR: output already exists; refusing to replace it: " + outputPath);
                    return (int)ExitCode.IoError;
                }
            }

            // Build the resolver chain from explicit evidence metadata.
            var chain = new MetadataResolver();
            var manifestResolver = new ManifestFileResolver();
            foreach (var manifest in options.Manifests)
            {
                if (!File.Exists(manifest))
                {
                    stderr.WriteLine("ERROR: manifest not found: " + manifest);
                    return (int)ExitCode.IoError;
                }

                try
                {
                    manifestResolver.AddFile(manifest);
                }
                catch (Exception ex)
                {
                    stderr.WriteLine("ERROR: failed to read manifest '" + manifest + "': " + ex.Message);
                    return (int)ExitCode.IoError;
                }
            }

            if (manifestResolver.LoadedFiles.Count > 0)
            {
                chain.Add(manifestResolver);
            }

            if (options.Resources.Count > 0)
            {
                var peResolver = new PeResourceResolver();
                foreach (var resource in options.Resources)
                {
                    if (!File.Exists(resource))
                    {
                        stderr.WriteLine("ERROR: resource not found: " + resource);
                        return (int)ExitCode.IoError;
                    }

                    try
                    {
                        peResolver.AddFile(resource);
                    }
                    catch (Exception ex)
                    {
                        stderr.WriteLine("ERROR: failed to parse resource '" + resource + "': " + ex.Message);
                        return (int)ExitCode.IoError;
                    }
                }

                chain.Add(peResolver);
            }

            var exportedProviders = new ExportedProviderResolver();
            foreach (var providerInfo in options.ProviderInfos)
            {
                try
                {
                    exportedProviders.AddFile(providerInfo);
                }
                catch (Exception ex)
                {
                    stderr.WriteLine("ERROR: failed to read provider-info XML '" + providerInfo + "': " + ex.Message);
                    return (int)ExitCode.IoError;
                }
            }

            // Preflight: learn every schema the trace carries, so metadata that
            // appears later can decode earlier events, and so scan/report can state
            // exactly what is missing. This pass decodes no payload.
            var preflightResolver = new PreflightMetadata(chain);
            var preflight = new ScanService(preflightResolver);
            var preflightStatus = RunPreflight(options.Inputs, preflightResolver, preflight, options.AllowLocalMetadata, stderr);
            if (preflightStatus != null)
            {
                stderr.WriteLine(preflightStatus);
                return (int)ExitCode.DecodeError;
            }

            if (options.Scan)
            {
                preflight.Refresh(preflightResolver);
                using var scanOut = OpenOutput(options.Output, stdout);
                if (options.Format == OutputFormat.Json)
                {
                    scanOut.WriteJsonTo(stream => preflight.WriteJson(stream, exportedProviders));
                }
                else
                {
                    preflight.WriteText(scanOut.Writer, exportedProviders);
                }

                return FlushAndClose(scanOut);
            }

            if (options.ReportMissing)
            {
                preflight.Refresh(preflightResolver);
                using var reportOut = OpenOutput(options.Output, stdout);
                if (options.Format == OutputFormat.Json)
                {
                    reportOut.WriteJsonTo(stream => MissingMetadataReport.WriteJson(stream, preflight.Entries.Values, exportedProviders));
                }
                else
                {
                    MissingMetadataReport.WriteText(reportOut.Writer, preflight.Entries.Values, exportedProviders);
                }

                return FlushAndClose(reportOut);
            }

            return Convert(options, preflightResolver, exportedProviders, stdout, stderr);
        }

        private static string RunPreflight(
            IReadOnlyList<string> inputs,
            PreflightMetadata chain,
            ScanService scan,
            bool allowLocalMetadata,
            TextWriter stderr)
        {
            var writer = new PreflightWriter(scan);
            var reader = WindowsEtwReader.Create<PreflightWriter>(writer, stderr.WriteLine, _ => null);
            reader.Deserializer.ResolverChain = chain;
            reader.Deserializer.AllowLocalMetadata = allowLocalMetadata;
            reader.Deserializer.SchemaOnly = true;
            reader.Deserializer.SourceObserver = (source, key, operand) => scan.Observe(source, key, operand);

            return reader.Process(inputs);
        }

        private static int Convert(CliOptions options, PreflightMetadata chain, ExportedProviderResolver providerInfo, TextWriter stdout, TextWriter stderr)
        {
            using var output = OpenOutput(options.Output, stdout);

            var watch = Stopwatch.StartNew();

            int result;
            if (options.Format == OutputFormat.Json)
            {
                var writer = new LegacyJsonEventWriter(output.Stream, providerInfo);
                var reader = WindowsEtwReader.Create(writer, stderr.WriteLine, _ => null);
                reader.Deserializer.ResolverChain = chain;
                reader.Deserializer.AllowLocalMetadata = options.AllowLocalMetadata;
                var error = reader.Process(options.Inputs);
                writer.Complete();

                writer.Dispose();
                result = error == null ? (int)ExitCode.Success : (int)ExitCode.DecodeError;
                if (error != null)
                {
                    stderr.WriteLine("ERROR: " + error);
                }
            }
            else
            {
                var writer = new JsonlEventWriter(output.Stream, providerInfo);
                var reader = WindowsEtwReader.Create(writer, stderr.WriteLine, _ => null);
                reader.Deserializer.ResolverChain = chain;
                reader.Deserializer.AllowLocalMetadata = options.AllowLocalMetadata;
                var error = reader.Process(options.Inputs);
                writer.Dispose();
                result = error == null ? (int)ExitCode.Success : (int)ExitCode.DecodeError;
                if (error != null)
                {
                    stderr.WriteLine("ERROR: " + error);
                }
            }

            watch.Stop();
            if (result == (int)ExitCode.Success)
            {
                stderr.WriteLine("Finished in " + watch.ElapsedMilliseconds + " ms");
            }

            return result;
        }

        private static OutputHandle OpenOutput(string path, TextWriter stdoutFallback)
        {
            if (string.IsNullOrEmpty(path))
            {
                // Scan/report may write to stdout.
                return new OutputHandle(stdoutFallback ?? Console.Out);
            }

            if (path == "-")
            {
                return new OutputHandle(stdoutFallback ?? Console.Out);
            }

            var directory = Path.GetDirectoryName(Path.GetFullPath(path));
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            return new OutputHandle(path);
        }

        private static int FlushAndClose(OutputHandle output)
        {
            output.Dispose();
            return (int)ExitCode.Success;
        }

        private sealed class OutputHandle : IDisposable
        {
            public OutputHandle(string path)
            {
                this.FileStream = OutputFile.OpenNew(path);
                this.Stream = this.FileStream;
                this.Writer = new StreamWriter(this.FileStream, new UTF8Encoding(false));
            }

            public OutputHandle(TextWriter stdout)
            {
                this.Writer = stdout;
                this.Stream = ReferenceEquals(stdout, Console.Out) ? Console.OpenStandardOutput() : new MemoryStream();
            }

            public OutputHandle(TextWriter stdout, Stream stream)
            {
                this.Writer = stdout;
                this.Stream = stream;
            }

            public FileStream FileStream { get; }

            public Stream Stream { get; }

            public TextWriter Writer { get; }

            private bool disposed;

            /// <summary>Renders structured JSON either to the file stream or, when writing to stdout, via a buffer.</summary>
            public void WriteJsonTo(Action<Stream> writeJson)
            {
                if (this.Stream != null)
                {
                    writeJson(this.Stream);
                    return;
                }

                using var buffer = new MemoryStream();
                writeJson(buffer);
                this.Writer.Write(Encoding.UTF8.GetString(buffer.ToArray()));
            }

            public void Dispose()
            {
                if (this.disposed) return;
                this.disposed = true;
                if (this.FileStream != null)
                {
                    this.Writer.Flush();
                    this.Writer.Dispose();
                    this.FileStream.Dispose();
                }
                else if (this.Stream is MemoryStream buffer)
                {
                    this.Writer.Write(Encoding.UTF8.GetString(buffer.ToArray()));
                    buffer.Dispose();
                    this.Writer.Flush();
                }
                else
                {
                    this.Writer.Flush();
                    this.Stream?.Flush();
                }
            }
        }

        /// <summary>Schema-only writer used by the preflight pass; discards all payload.</summary>
        private sealed class PreflightWriter : IEtwWriter
        {
            private readonly ScanService scan;

            public PreflightWriter(ScanService scan)
            {
                this.scan = scan;
            }

            public void WriteEventBegin(EventMetadata metadata, RuntimeEventMetadata runtimeMetadata)
            {
            }

            public void WriteEventEnd()
            {
            }

            public void WriteStructBegin()
            {
            }

            public void WriteStructEnd()
            {
            }

            public void WritePropertyBegin(PropertyMetadata metadata)
            {
            }

            public void WritePropertyEnd()
            {
            }

            public void WriteArrayBegin()
            {
            }

            public void WriteArrayEnd()
            {
            }

            public void WriteAnsiString(string value)
            {
            }

            public void WriteUnicodeString(string value)
            {
            }

            public void WriteInt8(sbyte value)
            {
            }

            public void WriteUInt8(byte value)
            {
            }

            public void WriteInt16(short value)
            {
            }

            public void WriteUInt16(ushort value)
            {
            }

            public void WriteInt32(int value)
            {
            }

            public void WriteUInt32(uint value)
            {
            }

            public void WriteInt64(long value)
            {
            }

            public void WriteUInt64(ulong value)
            {
            }

            public void WriteFloat(float value)
            {
            }

            public void WriteDouble(double value)
            {
            }

            public void WriteBoolean(bool value)
            {
            }

            public void WriteBinary(byte[] value)
            {
            }

            public void WriteGuid(Guid value)
            {
            }

            public void WritePointer(ulong value)
            {
            }

            public void WriteFileTime(DateTime value)
            {
            }

            public void WriteSystemTime(DateTime value)
            {
            }

            public void WriteSid(string value)
            {
            }

            public void WriteUnicodeChar(char value)
            {
            }

            public void WriteAnsiChar(char value)
            {
            }

            public void WriteHexDump(byte[] value)
            {
            }

            public void WriteWbemSid(string value)
            {
            }
        }
    }

    internal enum ExitCode
    {
        Success = 0,
        Usage = 1,
        IoError = 2,
        DecodeError = 3,
        MetadataMissing = 4,
    }

    internal enum OutputFormat
    {
        Jsonl,
        Json,
    }

    internal sealed class CliOptions
    {
        public List<string> Inputs { get; } = new List<string>();

        public List<string> Manifests { get; } = new List<string>();

        public List<string> Resources { get; } = new List<string>();

        public List<string> ProviderInfos { get; } = new List<string>();

        public string Output { get; private set; }

        public OutputFormat Format { get; private set; } = OutputFormat.Jsonl;

        public bool Scan { get; private set; }

        public bool ReportMissing { get; private set; }

        public bool AllowLocalMetadata { get; private set; }

        public bool ShowHelp { get; private set; }

        public static CliOptions Parse(string[] args, TextWriter stderr)
        {
            var options = new CliOptions();
            bool localMetadataSeen = false;
            for (int i = 0; i < args.Length; i++)
            {
                var arg = args[i];

                if (arg == "--help" || arg == "-h" || arg == "/?")
                {
                    options.ShowHelp = true;
                    continue;
                }

                if (arg == "--scan")
                {
                    options.Scan = true;
                    continue;
                }

                if (arg == "--report-missing")
                {
                    options.ReportMissing = true;
                    continue;
                }

                if (arg == "--allow-local-metadata" || arg.StartsWith("--allow-local-metadata=", StringComparison.Ordinal))
                {
                    if (localMetadataSeen)
                    {
                        stderr.WriteLine("ERROR: --allow-local-metadata specified more than once.");
                        return null;
                    }

                    localMetadataSeen = true;
                    string booleanValue = null;
                    if (arg.StartsWith("--allow-local-metadata=", StringComparison.Ordinal))
                    {
                        booleanValue = arg.Substring("--allow-local-metadata=".Length);
                    }
                    else if (i + 1 < args.Length && bool.TryParse(args[i + 1], out _))
                    {
                        booleanValue = args[++i];
                    }

                    if (booleanValue == null)
                    {
                        options.AllowLocalMetadata = true;
                    }
                    else if (bool.TryParse(booleanValue, out bool parsedBoolean))
                    {
                        options.AllowLocalMetadata = parsedBoolean;
                    }
                    else
                    {
                        stderr.WriteLine("ERROR: --allow-local-metadata requires true or false.");
                        return null;
                    }

                    continue;
                }

                if (TryNamedValue(arg, i, args, out var name, out var value, out int consumed))
                {
                    i += consumed;
                    switch (name)
                    {
                        case "--output":
                        case "-output":
                        case "/output":
                            if (value == null)
                            {
                                stderr.WriteLine("ERROR: " + name + " requires a value.");
                                return null;
                            }

                            if (options.Output != null)
                            {
                                stderr.WriteLine("ERROR: --output specified more than once.");
                                return null;
                            }

                            options.Output = value;
                            break;

                        case "--format":
                            if (value == null)
                            {
                                stderr.WriteLine("ERROR: --format requires a value.");
                                return null;
                            }

                            if (string.Equals(value, "jsonl", StringComparison.OrdinalIgnoreCase))
                            {
                                options.Format = OutputFormat.Jsonl;
                            }
                            else if (string.Equals(value, "json", StringComparison.OrdinalIgnoreCase))
                            {
                                options.Format = OutputFormat.Json;
                            }
                            else
                            {
                                stderr.WriteLine("ERROR: unknown --format value: " + value);
                                return null;
                            }

                            break;

                        case "--manifest":
                            if (value == null)
                            {
                                stderr.WriteLine("ERROR: --manifest requires a value.");
                                return null;
                            }

                            options.Manifests.Add(value);
                            break;

                        case "--resource":
                            if (value == null)
                            {
                                stderr.WriteLine("ERROR: --resource requires a value.");
                                return null;
                            }

                            options.Resources.Add(value);
                            break;

                        case "--provider-info":
                            if (value == null)
                            {
                                stderr.WriteLine("ERROR: --provider-info requires a value.");
                                return null;
                            }

                            options.ProviderInfos.Add(value);
                            break;
                    }

                    continue;
                }

                if (arg.StartsWith("-") && arg.Length > 1 && !arg.StartsWith("--", StringComparison.Ordinal))
                {
                    stderr.WriteLine("ERROR: unknown option: " + arg);
                    return null;
                }

                if (arg.StartsWith("--", StringComparison.Ordinal))
                {
                    stderr.WriteLine("ERROR: unknown option: " + arg);
                    return null;
                }

                options.Inputs.Add(arg);
            }

            if (options.Scan && options.ReportMissing)
            {
                stderr.WriteLine("ERROR: --scan and --report-missing cannot be combined.");
                return null;
            }

            return options;
        }

        /// <summary>
        /// Matches both <c>--name=value</c> and <c>--name value</c>. Returns false when
        /// the argument is not a recognized named option.
        /// </summary>
        private static bool TryNamedValue(string arg, int index, string[] args, out string name, out string value, out int consumed)
        {
            name = null;
            value = null;
            consumed = 0;

            string candidate = null;
            foreach (var known in KnownOptions)
            {
                if (arg.Equals(known, StringComparison.Ordinal))
                {
                    candidate = known;
                    break;
                }

                if (arg.StartsWith(known + "=", StringComparison.Ordinal))
                {
                    name = known;
                    value = arg.Substring(known.Length + 1);
                    return true;
                }
            }

            if (candidate == null)
            {
                return false;
            }

            name = candidate;
            if (index + 1 < args.Length && !LooksLikeOption(args[index + 1]))
            {
                value = args[index + 1];
                consumed = 1;
            }

            return true;
        }

        private static bool LooksLikeOption(string value)
        {
            return value.StartsWith("-", StringComparison.Ordinal) || value == "/?";
        }

        private static readonly string[] KnownOptions =
        {
            "--output", "-output", "/output", "--format", "--manifest", "--resource", "--provider-info",
        };
    }
}
