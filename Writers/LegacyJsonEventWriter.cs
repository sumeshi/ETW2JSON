namespace ETW2JSON
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text.Json;
    using ETWDeserializer;

    /// <summary>
    /// Legacy-shaped writer: an <c>Events</c> array of <c>Event</c> objects, matching the
    /// historical ETW2JSON output while carrying the new provenance/raw fields.
    /// </summary>
    public sealed class LegacyJsonEventWriter : IEtwWriter, IAbortableEtwWriter, IDisposable
    {
        private readonly Utf8JsonWriter envelopeWriter;
        private readonly ExportedProviderResolver providerInfo;
        private Utf8JsonWriter writer;
        private MemoryStream eventBuffer;
        private readonly Stream stream;
        private bool started;
        private EventMetadata currentMetadata;
        private RuntimeEventMetadata currentRuntimeMetadata;

        public LegacyJsonEventWriter(Stream stream)
            : this(stream, null)
        {
        }

        public LegacyJsonEventWriter(Stream stream, ExportedProviderResolver providerInfo)
        {
            this.stream = stream;
            this.providerInfo = providerInfo;
            this.envelopeWriter = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });
        }

        public void WriteEventBegin(EventMetadata metadata, RuntimeEventMetadata runtimeMetadata)
        {
            this.currentMetadata = metadata;
            this.currentRuntimeMetadata = runtimeMetadata;
            this.EnsureStarted();
            this.eventBuffer = new MemoryStream();
            this.writer = new Utf8JsonWriter(this.eventBuffer, new JsonWriterOptions { Indented = true });
            var w = this.writer;

            w.WriteStartObject();
            w.WritePropertyName("Event");
            w.WriteStartObject();

            w.WriteString("Timestamp", JsonlEventWriter.FormatTimestamp(runtimeMetadata.Timestamp));
            w.WriteNumber("raw_timestamp", runtimeMetadata.RawTimestamp);
            JsonlEventWriter.WriteTraceClock(w, runtimeMetadata.TraceClock);
            EventHeaderJsonWriter.Write(w, runtimeMetadata);
            ExtendedDataJsonWriter.Write(w, runtimeMetadata);
            w.WriteString("ProviderGuid", metadata.ProviderGuid.ToString("D"));
            w.WriteNumber("Id", metadata.Id);
            w.WriteNumber("Version", metadata.Version);
            w.WriteNumber("Level", runtimeMetadata.Level);
            w.WriteNumber("Opcode", runtimeMetadata.Opcode);
            w.WriteNumber("Task", runtimeMetadata.Task);
            w.WriteNumber("Keyword", runtimeMetadata.Keyword);
            w.WriteNumber("ProcessId", runtimeMetadata.ProcessId);
            w.WriteNumber("ThreadId", runtimeMetadata.ThreadId);
            w.WriteNumber("ProcessorNumber", runtimeMetadata.ProcessorNumber);

            if (runtimeMetadata.ActivityId != Guid.Empty)
            {
                w.WriteString("ActivityId", runtimeMetadata.ActivityId.ToString("D"));
            }

            if (runtimeMetadata.RelatedActivityId != Guid.Empty)
            {
                w.WriteString("RelatedActivityId", runtimeMetadata.RelatedActivityId.ToString("D"));
            }

            var stacks = runtimeMetadata.GetStacks(out var matchId);
            if (matchId != 0)
            {
                w.WriteNumber("StackMatchId", matchId);
            }

            if (stacks != null)
            {
                w.WritePropertyName("Stacks");
                w.WriteStartArray();
                foreach (var stack in stacks)
                {
                    w.WriteNumberValue(stack);
                }

                w.WriteEndArray();
            }

            w.WriteString("Name", metadata.Name);
            string providerName = metadata.ProviderName;
            if (providerName == null && this.providerInfo != null && this.providerInfo.TryGetProvider(metadata.ProviderGuid, out ExportedProviderInfo exported))
            {
                providerName = exported.Name;
            }

            if (providerName != null)
            {
                w.WriteString("ProviderName", providerName);
            }

            w.WritePropertyName("Properties");
            w.WriteStartArray();
            w.WriteStartObject();
        }

        public void WriteEventEnd()
        {
            var w = this.writer;
            w.WriteEndObject(); // property bag
            w.WriteEndArray();  // Properties
            w.WriteString("metadata_source", MetadataSourceNames.ToJson(this.currentMetadata.MetadataSource));
            w.WriteString("decode_status", MetadataSourceNames.ToJson(this.currentMetadata.DecodeStatus));
            if (this.currentMetadata.Provenance != null)
            {
                w.WriteString("metadata_provenance", this.currentMetadata.Provenance);
            }

            if (this.currentMetadata.DecodeStatus != DecodeStatus.Decoded)
            {
                string reason = this.currentMetadata.DecodeReason;
                w.WriteString("decode_note", reason ?? ("schema=" + MetadataSourceNames.ToJson(this.currentMetadata.MetadataSource) + ";status=" + MetadataSourceNames.ToJson(this.currentMetadata.DecodeStatus)));
            }

            w.WriteString("source_file", this.currentRuntimeMetadata.SourceFile);
            w.WriteBase64String("raw_payload", this.currentRuntimeMetadata.GetRawPayload() ?? Array.Empty<byte>());
            w.WriteEndObject(); // Event
            w.WriteEndObject(); // wrapper
            w.Flush();
            w.Dispose();
            this.eventBuffer.Position = 0;
            this.envelopeWriter.WriteRawValue(this.eventBuffer.ToArray(), skipInputValidation: false);
            this.envelopeWriter.Flush();
            this.eventBuffer.Dispose();
            this.eventBuffer = null;
            this.writer = null;
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
            this.envelopeWriter.Flush();
        }

        public void Dispose()
        {
            this.writer?.Dispose();
            this.eventBuffer?.Dispose();
            this.envelopeWriter.Dispose();
        }

        public void AbortEvent()
        {
            this.writer?.Dispose();
            this.writer = null;
            this.eventBuffer?.Dispose();
            this.eventBuffer = null;
        }

        private void EnsureStarted()
        {
            if (this.started)
            {
                return;
            }

            this.envelopeWriter.WriteStartObject();
            this.envelopeWriter.WritePropertyName("Events");
            this.envelopeWriter.WriteStartArray();
            this.started = true;
        }

        /// <summary>Closes the Events array and the envelope. Must be called exactly once.</summary>
        public void Complete()
        {
            this.EnsureStarted();
            this.envelopeWriter.WriteEndArray();
            this.envelopeWriter.WriteEndObject();
            this.envelopeWriter.Flush();
        }
    }
}
