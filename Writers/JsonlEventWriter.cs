namespace ETW2JSON
{
    using System;
    using System.IO;
    using System.Text.Json;
    using ETWDeserializer;

    /// <summary>Writes standalone event objects as UTF-8 JSON Lines.</summary>
    public sealed class JsonlEventWriter : IEtwWriter, IAbortableEtwWriter, IDisposable
    {
        private readonly Stream stream;
        private readonly ExportedProviderResolver providerInfo;
        private Utf8JsonWriter writer;
        private MemoryStream eventBuffer;
        private readonly Utf8JsonWriter externalWriter;
        private string currentSourceFile;
        private string currentDecodeReason;
        private bool externalEventWritten;

        private DecodeStatus currentStatus = DecodeStatus.Decoded;
        private MetadataSource currentSource = MetadataSource.Unknown;
        private string currentProvenance;
        private byte[] currentRawPayload;
        private bool inEvent;

        public JsonlEventWriter(Stream stream)
            : this(stream, null)
        {
        }

        public JsonlEventWriter(Stream stream, ExportedProviderResolver providerInfo)
        {
            this.stream = stream;
            this.providerInfo = providerInfo;
            if (stream == null) throw new ArgumentNullException(nameof(stream));
        }

        /// <summary>
        /// Compatibility overload for callers that supply a preconfigured JSON writer.
        /// The caller owns JSONL framing; this overload can write one event only.
        /// Prefer the stream overload for normal CLI output.
        /// </summary>
        public JsonlEventWriter(Utf8JsonWriter writer)
        {
            this.externalWriter = writer ?? throw new ArgumentNullException(nameof(writer));
            this.writer = writer;
        }

        public void WriteEventBegin(EventMetadata metadata, RuntimeEventMetadata runtimeMetadata)
        {
            if (this.inEvent) throw new InvalidOperationException("An event is already being written.");
            if (this.externalWriter != null && this.externalEventWritten)
            {
                throw new InvalidOperationException("A caller-supplied Utf8JsonWriter can frame only one event; use the stream constructor for JSONL.");
            }
            this.eventBuffer = new MemoryStream();
            this.writer = new Utf8JsonWriter(this.eventBuffer, new JsonWriterOptions { Indented = false, SkipValidation = false });
            this.currentStatus = metadata.DecodeStatus;
            this.currentSource = metadata.MetadataSource;
            this.currentProvenance = metadata.Provenance;
            this.currentDecodeReason = metadata.DecodeReason;
            this.currentRawPayload = runtimeMetadata.GetRawPayload();
            this.currentSourceFile = runtimeMetadata.SourceFile;
            this.inEvent = true;

            var w = this.writer;
            w.WriteStartObject();

            w.WriteString("timestamp", FormatTimestamp(runtimeMetadata.Timestamp));
            w.WriteNumber("raw_timestamp", runtimeMetadata.RawTimestamp);
            WriteTraceClock(w, runtimeMetadata.TraceClock);
            w.WriteString("provider_guid", metadata.ProviderGuid.ToString("D"));
            WriteName(w, "provider_name", this.GetProviderName(metadata));
            w.WriteNumber("event_id", metadata.Id);
            w.WriteNumber("version", metadata.Version);
            w.WriteNumber("level", runtimeMetadata.Level);
            w.WriteNumber("opcode", runtimeMetadata.Opcode);
            w.WriteNumber("task", runtimeMetadata.Task);
            w.WriteNumber("keyword", runtimeMetadata.Keyword);
            w.WriteNumber("process_id", runtimeMetadata.ProcessId);
            w.WriteNumber("thread_id", runtimeMetadata.ThreadId);
            w.WriteNumber("processor_number", runtimeMetadata.ProcessorNumber);

            var activityId = runtimeMetadata.ActivityId;
            if (activityId != Guid.Empty)
            {
                w.WriteString("activity_id", activityId.ToString("D"));
            }
            else
            {
                w.WriteNull("activity_id");
            }

            var related = runtimeMetadata.RelatedActivityId;
            if (related != Guid.Empty)
            {
                w.WriteString("related_activity_id", related.ToString("D"));
            }
            else
            {
                w.WriteNull("related_activity_id");
            }

            w.WriteString("event_name", metadata.Name);

            w.WritePropertyName("properties");
            w.WriteStartObject();
        }

        public void WriteEventEnd()
        {
            var w = this.writer;
            w.WriteEndObject(); // properties

            w.WriteString("metadata_source", MetadataSourceNames.ToJson(this.currentSource));
            w.WriteString("decode_status", MetadataSourceNames.ToJson(this.currentStatus));
            if (this.currentProvenance != null)
            {
                w.WriteString("metadata_provenance", this.currentProvenance);
            }

            w.WriteBase64String("raw_payload", this.currentRawPayload ?? Array.Empty<byte>());
            w.WriteString("source_file", this.GetSourceFile());

            if (this.currentStatus != DecodeStatus.Decoded)
            {
                string reason = this.currentDecodeReason;
                w.WriteString("decode_note", reason ?? ("schema=" + MetadataSourceNames.ToJson(this.currentSource) + ";status=" + MetadataSourceNames.ToJson(this.currentStatus)));
            }

            w.WriteEndObject();
            w.Flush();
            if (this.eventBuffer != null)
            {
                this.writer.Dispose();
                this.eventBuffer.Position = 0;
                if (this.stream != null)
                {
                    this.eventBuffer.CopyTo(this.stream);
                    this.stream.WriteByte((byte)'\n');
                }
                else
                {
                    this.externalWriter.WriteRawValue(this.eventBuffer.ToArray(), skipInputValidation: false);
                    this.externalWriter.Flush();
                }
                this.eventBuffer.Dispose();
                this.eventBuffer = null;
                this.writer = null;
            }
            this.inEvent = false;
            this.externalEventWritten = this.externalWriter != null;
        }

        public void WriteStructBegin() => this.writer.WriteStartObject();

        public void WriteStructEnd() => this.writer.WriteEndObject();

        public void WritePropertyBegin(PropertyMetadata metadata) => this.writer.WritePropertyName(metadata.Name);

        public void WritePropertyEnd()
        {
        }

        public void WriteArrayBegin() => this.writer.WriteStartArray();

        public void WriteArrayEnd() => this.writer.WriteEndArray();

        public void WriteAnsiString(string value) => this.writer.WriteStringValue(value);

        public void WriteUnicodeString(string value) => this.writer.WriteStringValue(value);

        public void WriteInt8(sbyte value) => this.writer.WriteNumberValue(value);

        public void WriteUInt8(byte value) => this.writer.WriteNumberValue(value);

        public void WriteInt16(short value) => this.writer.WriteNumberValue(value);

        public void WriteUInt16(ushort value) => this.writer.WriteNumberValue(value);

        public void WriteInt32(int value) => this.writer.WriteNumberValue(value);

        public void WriteUInt32(uint value) => this.writer.WriteNumberValue(value);

        public void WriteInt64(long value) => this.writer.WriteNumberValue(value);

        public void WriteUInt64(ulong value) => this.writer.WriteNumberValue(value);

        public void WriteFloat(float value) => this.writer.WriteNumberValue(value);

        public void WriteDouble(double value) => this.writer.WriteNumberValue(value);

        public void WriteBoolean(bool value) => this.writer.WriteBooleanValue(value);

        public void WriteBinary(byte[] value) => this.writer.WriteBase64StringValue(value ?? Array.Empty<byte>());

        public void WriteGuid(Guid value) => this.writer.WriteStringValue(value.ToString("D"));

        public void WritePointer(ulong value) => this.writer.WriteNumberValue(value);

        public void WriteFileTime(DateTime value) => this.writer.WriteStringValue(value);

        public void WriteSystemTime(DateTime value) => this.writer.WriteStringValue(value);

        public void WriteSid(string value) => this.writer.WriteStringValue(value);

        public void WriteUnicodeChar(char value) => this.writer.WriteNumberValue(value);

        public void WriteAnsiChar(char value) => this.writer.WriteNumberValue(value);

        public void WriteHexDump(byte[] value) => this.writer.WriteBase64StringValue(value ?? Array.Empty<byte>());

        public void WriteWbemSid(string value) => this.writer.WriteStringValue(value);

        public void Flush()
        {
            this.writer?.Flush();
            this.stream?.Flush();
        }

        public void Dispose()
        {
            this.writer?.Dispose();
            this.eventBuffer?.Dispose();
        }

        public void AbortEvent()
        {
            this.writer?.Dispose();
            this.writer = null;
            this.eventBuffer?.Dispose();
            this.eventBuffer = null;
            this.inEvent = false;
        }

        private static void WriteName(Utf8JsonWriter w, string name, string value)
        {
            if (value != null)
            {
                w.WriteString(name, value);
            }
            else
            {
                w.WriteNull(name);
            }
        }

        internal static void WriteTraceClock(Utf8JsonWriter writer, TraceClockMetadata clock)
        {
            if (clock == null)
            {
                writer.WriteNull("trace_clock");
                return;
            }

            writer.WritePropertyName("trace_clock");
            writer.WriteStartObject();
            writer.WriteNumber("performance_frequency", clock.PerformanceFrequency);
            writer.WriteNumber("start_time", clock.StartTime);
            writer.WriteNumber("boot_time", clock.BootTime);
            writer.WriteNumber("reserved_flags", clock.ClockType);
            writer.WriteEndObject();
        }

        private string GetSourceFile()
        {
            // Runtime metadata is copied per event in WriteEventBegin.
            return this.currentSourceFile;
        }

        private string GetProviderName(EventMetadata metadata)
        {
            if (metadata.ProviderName != null) return metadata.ProviderName;
            if (this.providerInfo != null && this.providerInfo.TryGetProvider(metadata.ProviderGuid, out ExportedProviderInfo info) && info.Name != null)
            {
                return info.Name;
            }

            return ProviderNameFromDecorated(metadata.Name);
        }

        internal static string FormatTimestamp(long rawTimestamp)
        {
            // Raw timestamp (PROCESS_TRACE_MODE_RAW_TIMESTAMP) is not wall-clock.
            // Preserve it verbatim; callers that know the clock can convert it later.
            return rawTimestamp.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        private static string ProviderNameFromDecorated(string decorated)
        {
            if (string.IsNullOrEmpty(decorated) || decorated.StartsWith("UnknownProvider(", StringComparison.Ordinal))
            {
                return null;
            }

            int slash = decorated.IndexOf('/');
            return slash > 0 ? decorated.Substring(0, slash) : decorated;
        }
    }
}
