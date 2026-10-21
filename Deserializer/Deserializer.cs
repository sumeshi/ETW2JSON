namespace ETWDeserializer
{
    using System;
    using System.Collections.Generic;
    using System.Linq.Expressions;
    using System.Runtime.CompilerServices;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using System.Text.RegularExpressions;
    using CustomParsers;

    public sealed class Deserializer<T>
        where T : IEtwWriter
    {
        private static readonly Type ReaderType = typeof(EventRecordReader);

        private static readonly Type EventMetadataArrayType = typeof(EventMetadata[]);

        private static readonly Type RuntimeMetadataType = typeof(RuntimeEventMetadata);

        private static readonly Regex InvalidCharacters = new Regex("[:\\/*?\"<>|\"-]");

        private static readonly Type WriterType = typeof(T);

        private readonly Dictionary<TraceEventKey, Action<EventRecordReader, T, EventMetadata[], RuntimeEventMetadata>> actionTable = new Dictionary<TraceEventKey, Action<EventRecordReader, T, EventMetadata[], RuntimeEventMetadata>>();

        private readonly Dictionary<TraceEventKey, IEventTraceOperand> operandTable = new Dictionary<TraceEventKey, IEventTraceOperand>();

        private readonly Dictionary<string, Action<EventRecordReader, T, EventMetadata[], RuntimeEventMetadata>> traceLoggingActionTable = new Dictionary<string, Action<EventRecordReader, T, EventMetadata[], RuntimeEventMetadata>>(StringComparer.Ordinal);

        private readonly Dictionary<string, IEventTraceOperand> traceLoggingOperandTable = new Dictionary<string, IEventTraceOperand>(StringComparer.Ordinal);

        private readonly Dictionary<Guid, EventSourceManifest> eventSourceManifestCache = new Dictionary<Guid, EventSourceManifest>();

        private readonly Dictionary<Guid, EventSourceManifest> publishedEventSourceManifestCache = new Dictionary<Guid, EventSourceManifest>();

        private readonly List<EventMetadata> eventMetadataTableList = new List<EventMetadata>();

        private T writer;

        private EventMetadata[] eventMetadataTable;

        /// <summary>
        /// User-supplied schema sources (explicit --manifest, --resource, offline).
        /// When null, the built-in embedded/TDH paths are used.
        /// </summary>
        public IMetadataResolverChain ResolverChain { get; set; }

        /// <summary>Source file reported for every event, when a single input is being read.</summary>
        public string SourceFile { get; set; }

        /// <summary>Maps a native logger id to its source file, for multi-file traces.</summary>
        public Func<ushort, string> SourceFileLookup { get; set; }

        /// <summary>Maps a source ETL path to its original clock parameters.</summary>
        public Func<string, TraceClockMetadata> TraceClockLookup { get; set; }

        /// <summary>
        /// Invoked for every record once its schema resolution completed. Used by the
        /// preflight scan and missing-metadata report.
        /// </summary>
        public Action<EventKey, IEventTraceOperand> Observer { get; set; }

        public Action<string, EventKey, IEventTraceOperand> SourceObserver { get; set; }

        /// <summary>Resolves and reports schemas without traversing event payloads.</summary>
        public bool SchemaOnly { get; set; }

        /// <summary>Opt in to provider metadata installed in the analysis host's TDH cache.</summary>
        public bool AllowLocalMetadata { get; set; }

        internal Func<EventKey, IEventTraceOperand> LocalMetadataTestHook { get; set; }

        internal unsafe delegate int EventInformationLookup(EVENT_RECORD* record, uint contextCount, IntPtr context, byte* buffer, ref uint bufferSize);

        internal unsafe EventInformationLookup TdhInformationLookup { get; set; } = Tdh.GetEventInformation;

        /// <summary>First fatal callback/writer error, used to stop ProcessTrace cleanly.</summary>
        public Exception LastError { get; private set; }

        private string currentSourceFile;
        private Func<ushort, string> currentSourceFileFn;

        public Deserializer(T writer)
        {
            this.writer = writer;
        }

        /// <summary>Binds the source file whose records will be processed by the next ProcessTrace call.</summary>
        public void SetCurrentSource(string sourceFile)
        {
            if (!string.Equals(this.currentSourceFile, sourceFile, StringComparison.OrdinalIgnoreCase))
            {
                this.actionTable.Clear();
                this.operandTable.Clear();
                this.traceLoggingActionTable.Clear();
                this.traceLoggingOperandTable.Clear();
                this.eventSourceManifestCache.Clear();
                this.publishedEventSourceManifestCache.Clear();
                this.eventMetadataTableList.Clear();
                this.eventMetadataTable = Array.Empty<EventMetadata>();
            }
            this.currentSourceFile = sourceFile;
            this.currentSourceFileFn = this.SourceFileLookup;
            if (this.ResolverChain is ISourceScopedMetadataResolver scopedResolver)
            {
                scopedResolver.SetCurrentSource(sourceFile);
            }
        }

        public void ResetWriter(T writer)
        {
            this.writer = writer;
        }

        internal void ResetErrors()
        {
            this.LastError = null;
        }

        [AllowReversePInvokeCalls]
        public bool BufferCallback(IntPtr logfile)
        {
            return this.LastError == null;
        }

        [AllowReversePInvokeCalls]
        public unsafe void Deserialize(EVENT_RECORD* eventRecord)
        {
            if (this.LastError != null) return;
            RuntimeEventMetadata runtimeMetadata = default;
            bool runtimeReady = false;
            IEventTraceOperand observedOperand = null;
            TraceEventKey key = default;
            string traceLoggingIdentity = null;
            try
            {
                eventRecord->UserDataFixed = eventRecord->UserData;
                var eventRecordReader = new EventRecordReader(eventRecord);
                string sourceFile = this.currentSourceFile ?? this.currentSourceFileFn?.Invoke(eventRecord->LoggerId) ?? this.SourceFile;
                runtimeMetadata = new RuntimeEventMetadata(eventRecord, sourceFile, this.TraceClockLookup?.Invoke(sourceFile));
                runtimeReady = true;
                string[] extendedErrors = runtimeMetadata.GetExtendedDataErrors();
                if (extendedErrors.Length != 0)
                {
                    bool traceLogging = Array.Exists(runtimeMetadata.GetRawExtendedData(), item => item.ExtType == Etw.EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL);
                    var metadata = new EventMetadata(runtimeMetadata.ProviderId, runtimeMetadata.EventId, runtimeMetadata.Version,
                        "InvalidExtendedData(" + runtimeMetadata.ProviderId.ToString("D") + ")", Array.Empty<PropertyMetadata>(), null,
                        traceLogging ? MetadataSource.TraceLogging : MetadataSource.Unknown, DecodeStatus.DecodeError,
                        "etl:extended-data-validation", (traceLogging ? "Invalid TraceLogging extended event metadata: " : "Invalid extended event metadata: ")
                            + string.Join("; ", extendedErrors), ResolutionStatus.Invalid);
                    observedOperand = new EventTraceOperand(metadata, 0, Array.Empty<IEventTracePropertyOperand>());
                    if (!this.SchemaOnly)
                    {
                        this.writer.WriteEventBegin(metadata, runtimeMetadata);
                        this.writer.WriteEventEnd();
                    }
                    this.ObserveSafely(GetRecordKey(eventRecord), observedOperand);
                    return;
                }
                key = new TraceEventKey(
                    eventRecord->ProviderId,
                    (eventRecord->Flags & Etw.EVENT_HEADER_FLAG_CLASSIC_HEADER) != 0 ? eventRecord->Opcode : eventRecord->Id,
                    eventRecord->Version,
                    (eventRecord->Flags & Etw.EVENT_HEADER_FLAG_CLASSIC_HEADER) != 0);

                string unsupportedHeaderReason = GetUnsupportedHeaderReason(eventRecord->Flags);
                if (unsupportedHeaderReason != null)
                {
                    var unsupported = BuildUnsupportedHeaderOperand(eventRecord, unsupportedHeaderReason);
                    observedOperand = unsupported;
                    var unsupportedKey = GetRecordKey(eventRecord);
                    if (!this.SchemaOnly)
                    {
                        this.writer.WriteEventBegin(unsupported.Metadata, runtimeMetadata);
                        this.writer.WriteEventEnd();
                    }
                    this.ObserveSafely(unsupportedKey, unsupported);
                    return;
                }

                var sourceKey = GetRecordKey(eventRecord);
                // Self-describing records resolve their own schema before any
                // external lookup, even when external definitions conflict.
                if (!HasTraceLoggingSchema(eventRecord) && !HasBuiltinParser(eventRecord)
                    && this.ResolverChain is PreflightMetadata scopedPreflight
                    && scopedPreflight.Resolve(sourceKey).Status == ResolutionStatus.Conflict)
                {
                    var conflict = BuildSchemaConflictOperand(eventRecord, scopedPreflight.Resolve(sourceKey));
                    observedOperand = conflict;
                    if (!this.SchemaOnly)
                    {
                        this.writer.WriteEventBegin(conflict.Metadata, runtimeMetadata);
                        this.writer.WriteEventEnd();
                    }
                    this.ObserveSafely(sourceKey, conflict);
                    return;
                }

                traceLoggingIdentity = GetTraceLoggingSchemaIdentity(eventRecord);
                bool eventSourceManifestRecord = IsEventSourceManifestRecord(eventRecord);
                Action<EventRecordReader, T, EventMetadata[], RuntimeEventMetadata> action;
                if (traceLoggingIdentity != null && this.traceLoggingActionTable.TryGetValue(traceLoggingIdentity, out action))
                {
                    this.traceLoggingOperandTable.TryGetValue(traceLoggingIdentity, out observedOperand);
                    if (!this.SchemaOnly)
                    {
                        eventRecord->UserData = eventRecord->UserDataFixed;
                        action(eventRecordReader, this.writer, this.eventMetadataTable, runtimeMetadata);
                    }
                }
                else if (traceLoggingIdentity == null && !eventSourceManifestRecord && this.actionTable.TryGetValue(key, out action))
                {
                    this.operandTable.TryGetValue(key, out observedOperand);
                    if (!this.SchemaOnly)
                    {
                        eventRecord->UserData = eventRecord->UserDataFixed;
                        action(eventRecordReader, this.writer, this.eventMetadataTable, runtimeMetadata);
                    }
                }
                else
                {
                    observedOperand = this.SlowLookup(eventRecord, eventRecordReader, runtimeMetadata, ref key, traceLoggingIdentity);
                }

                observedOperand ??= BuildUnknownOperand(eventRecord, 0);
                var observedKey = GetRecordKey(eventRecord);
                this.ObserveSafely(observedKey, observedOperand);
            }
            catch (Exception ex)
            {
                if (!runtimeReady || !IsRecoverableDecodeException(ex)) this.LastError = ex;
                if (observedOperand == null && traceLoggingIdentity != null) this.traceLoggingOperandTable.TryGetValue(traceLoggingIdentity, out observedOperand);
                if (observedOperand == null) this.operandTable.TryGetValue(key, out observedOperand);
                if (runtimeReady) this.EmitDecodeFailure(eventRecord, runtimeMetadata, ex, observedOperand);
            }
        }

        internal static string GetUnsupportedHeaderReason(ushort flags)
        {
            if ((flags & Etw.EVENT_HEADER_FLAG_TRACE_MESSAGE) != 0) return "WPP/TraceMessage payload decoding is unsupported; the raw payload is retained.";
            if ((flags & Etw.EVENT_HEADER_FLAG_STRING_ONLY) != 0) return "String-only ETW payload decoding is unsupported; the raw payload is retained.";
            return null;
        }

        private static unsafe EventKey GetRecordKey(EVENT_RECORD* record)
        {
            return new EventKey(record->ProviderId, record->Id, record->Version,
                (record->Flags & Etw.EVENT_HEADER_FLAG_CLASSIC_HEADER) != 0 ? record->Opcode : (byte?)null);
        }

        private static unsafe EventKey GetEmbeddedSchemaKey(TRACE_EVENT_INFO* info)
        {
            bool classic = info->EventGuid != Guid.Empty;
            return new EventKey(classic ? info->EventGuid : info->ProviderGuid, classic ? (ushort)0 : info->Id,
                info->Version, classic ? info->Opcode : (byte?)null);
        }

        private static unsafe IEventTraceOperand BuildUnsupportedHeaderOperand(EVENT_RECORD* eventRecord, string reason)
        {
            var metadata = new EventMetadata(eventRecord->ProviderId, eventRecord->Id, eventRecord->Version,
                "UnsupportedHeader(" + eventRecord->ProviderId.ToString("D") + ")", Array.Empty<PropertyMetadata>(), null,
                MetadataSource.Unknown, DecodeStatus.Unsupported, null, reason, ResolutionStatus.Unsupported);
            return new EventTraceOperand(metadata, 0, Array.Empty<IEventTracePropertyOperand>());
        }

        private static unsafe IEventTraceOperand BuildSchemaConflictOperand(EVENT_RECORD* eventRecord, ResolutionResult result)
        {
            var metadata = new EventMetadata(eventRecord->ProviderId, eventRecord->Id, eventRecord->Version,
                "ConflictingSchema(" + eventRecord->ProviderId.ToString("D") + ")", Array.Empty<PropertyMetadata>(), null,
                result.Source, DecodeStatus.DecodeError, result.Provenance,
                result.Reason ?? "Conflicting schemas are available for this source.", ResolutionStatus.Conflict);
            return new EventTraceOperand(metadata, 0, Array.Empty<IEventTracePropertyOperand>());
        }

        private static unsafe IEventTraceOperand BuildMetadataContainerOperand(EVENT_RECORD* record, int index, string name, string reason)
        {
            var metadata = new EventMetadata(record->ProviderId, record->Id, record->Version, name, Array.Empty<PropertyMetadata>(), null,
                MetadataSource.Embedded, DecodeStatus.Partial, "etl:metadata-container:" + name, reason, ResolutionStatus.Resolved);
            return new EventTraceOperand(metadata, index, Array.Empty<IEventTracePropertyOperand>());
        }

        private static bool IsRecoverableDecodeException(Exception exception)
        {
            return exception is InvalidOperationException
                || exception is ArgumentException
                || exception is OverflowException
                || exception is FormatException
                || exception is IndexOutOfRangeException
                || exception is System.Xml.XmlException;
        }

        private void ObserveSafely(EventKey key, IEventTraceOperand operand)
        {
            try
            {
                this.Observer?.Invoke(key, operand);
                this.SourceObserver?.Invoke(this.currentSourceFile ?? this.SourceFile, key, operand);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine("metadata observer failed: " + ex.Message);
                this.LastError = ex;
            }
        }

        private IEventTraceOperand CacheEmbeddedSchema(EventKey key, IEventTraceOperand operand)
        {
            if (operand == null) return null;
            string source = this.currentSourceFile ?? this.SourceFile;
            string provenance = operand.Metadata.Provenance;
            if (!string.IsNullOrEmpty(source)) provenance = "etl:" + source + ";" + provenance;
            var original = operand.Metadata;
            var metadata = new EventMetadata(original.ProviderGuid, original.Id, original.Version, original.Name, original.Properties, original.ProviderName, original.MetadataSource, original.DecodeStatus, provenance, original.DecodeReason, original.ResolutionStatus);
            var contextualOperand = new EventTraceOperand(metadata, operand.EventMetadataTableIndex, operand.EventPropertyOperands);
            var result = new ResolutionResult(contextualOperand, metadata.MetadataSource, provenance, metadata.ResolutionStatus, metadata.DecodeReason);
            if (this.ResolverChain is PreflightMetadata preflight) preflight.Store(key, result);
            else if (this.ResolverChain is MetadataResolver chain) chain.StoreEmbeddedSchema(key, result);
            return contextualOperand;
        }

        private unsafe void EmitDecodeFailure(EVENT_RECORD* eventRecord, RuntimeEventMetadata runtimeMetadata, Exception exception, IEventTraceOperand knownOperand)
        {
            try
            {
                if (!this.SchemaOnly) (this.writer as IAbortableEtwWriter)?.AbortEvent();
                var metadata = new EventMetadata(
                    eventRecord->ProviderId,
                    eventRecord->Id,
                    eventRecord->Version,
                    knownOperand?.Metadata.Name ?? "UnknownProvider(" + eventRecord->ProviderId.ToString("D") + ")",
                    Array.Empty<PropertyMetadata>(),
                    knownOperand?.Metadata.ProviderName,
                    knownOperand?.Metadata.MetadataSource ?? MetadataSource.Unknown,
                    DecodeStatus.DecodeError,
                    knownOperand?.Metadata.Provenance,
                    exception.GetType().Name + ": " + exception.Message,
                    knownOperand?.Metadata.ResolutionStatus ?? ResolutionStatus.Invalid);
                var key = GetRecordKey(eventRecord);
                this.ObserveSafely(key, new EventTraceOperand(metadata, 0, Array.Empty<IEventTracePropertyOperand>()));
                if (!this.SchemaOnly)
                {
                    this.writer.WriteEventBegin(metadata, runtimeMetadata);
                    this.writer.WriteEventEnd();
                }
            }
            catch (Exception fallbackException)
            {
                System.Diagnostics.Trace.WriteLine("failed to emit raw event fallback: " + fallbackException.Message);
                this.LastError = fallbackException;
            }
        }

        private unsafe IEventTraceOperand BuildOperandFromXml(EVENT_RECORD* eventRecord, Dictionary<Guid, EventSourceManifest> cache, EventRecordReader eventRecordReader, int metadataTableIndex)
        {
            if ((eventRecord->Flags & Etw.EVENT_HEADER_FLAG_CLASSIC_HEADER) != 0) return null;
            EventSourceManifest manifest;
            Guid providerGuid = eventRecord->ProviderId;
            if (IsEventSourceManifestRecord(eventRecord))
            {
                manifest = CreateEventSourceManifest(providerGuid, cache, eventRecord, eventRecordReader);
            }
            else if (!cache.TryGetValue(providerGuid, out manifest))
            {
                return null;
            }

            if (manifest == null)
            {
                return null;
            }

            if (manifest.IsComplete && (!this.publishedEventSourceManifestCache.TryGetValue(providerGuid, out var published) || !ReferenceEquals(published, manifest)))
            {
                var schema = manifest.Schema;
                this.publishedEventSourceManifestCache[providerGuid] = manifest;
                foreach (var key in EventTraceOperandBuilder.GetEventKeys(schema, providerGuid))
                {
                    var cachedOperand = EventTraceOperandBuilder.BuildManifest(schema, key, MetadataSource.Embedded, "eventsource manifest chunks");
                    this.CacheEmbeddedSchema(key, cachedOperand);
                }
            }

            return !manifest.IsComplete ? null : EventTraceOperandBuilder.BuildManifest(
                manifest.Schema,
                new EventKey(providerGuid, eventRecord->Id, eventRecord->Version),
                MetadataSource.Embedded,
                "eventsource manifest chunks");
        }

        private static unsafe bool IsEventSourceManifestRecord(EVENT_RECORD* eventRecord)
        {
            if (eventRecord->Id != 65534 || eventRecord->UserDataLength < 8 || eventRecord->UserData == null)
            {
                return false;
            }

            byte* payload = eventRecord->UserData;
            ushort totalChunks = *(ushort*)(payload + 4);
            ushort chunkNumber = *(ushort*)(payload + 6);
            return payload[0] == 1 && payload[3] == 0x5B && totalChunks > 0 && totalChunks <= 1024 && chunkNumber < totalChunks;
        }

        private static unsafe bool HasTraceLoggingSchema(EVENT_RECORD* eventRecord)
        {
            for (int i = 0; i < eventRecord->ExtendedDataCount; i++)
            {
                if (eventRecord->ExtendedData[i].ExtType == Etw.EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL)
                {
                    return true;
                }
            }

            return false;
        }

        private static unsafe string GetTraceLoggingSchemaError(EVENT_RECORD* eventRecord)
        {
            for (int i = 0; i < eventRecord->ExtendedDataCount; i++)
            {
                ref EVENT_HEADER_EXTENDED_DATA_ITEM item = ref eventRecord->ExtendedData[i];
                if ((item.ExtType == Etw.EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL || item.ExtType == Etw.EVENT_HEADER_EXT_TYPE_PROV_TRAITS)
                    && (item.DataSize < sizeof(ushort) || item.DataPtr == 0))
                {
                    return "TraceLogging schema or provider traits are empty, truncated, or unavailable.";
                }
            }

            return null;
        }

        private static unsafe string GetTraceLoggingSchemaIdentity(EVENT_RECORD* eventRecord)
        {
            using (var identity = new System.IO.MemoryStream())
            {
                bool foundSchema = false;
                int effectiveEventId = (eventRecord->Flags & Etw.EVENT_HEADER_FLAG_CLASSIC_HEADER) != 0
                    ? eventRecord->Opcode
                    : eventRecord->Id;
                identity.Write(eventRecord->ProviderId.ToByteArray(), 0, 16);
                identity.WriteByte((byte)effectiveEventId);
                identity.WriteByte((byte)(effectiveEventId >> 8));
                identity.WriteByte(eventRecord->Version);

                for (int i = 0; i < eventRecord->ExtendedDataCount; i++)
                {
                    ref EVENT_HEADER_EXTENDED_DATA_ITEM item = ref eventRecord->ExtendedData[i];
                    if (item.ExtType != Etw.EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL
                        && item.ExtType != Etw.EVENT_HEADER_EXT_TYPE_PROV_TRAITS) continue;
                    if (item.DataSize == 0 || item.DataPtr == 0)
                    {
                        return "invalid:" + eventRecord->ProviderId.ToString("D") + ":" + effectiveEventId + ":" + eventRecord->Version + ":" + item.ExtType + ":" + item.DataSize;
                    }

                    var bytes = new byte[item.DataSize];
                    Marshal.Copy(new IntPtr(unchecked((long)item.DataPtr)), bytes, 0, bytes.Length);
                    identity.WriteByte((byte)item.ExtType);
                    identity.WriteByte((byte)(item.ExtType >> 8));
                    identity.WriteByte((byte)item.DataSize);
                    identity.WriteByte((byte)(item.DataSize >> 8));
                    identity.Write(bytes, 0, bytes.Length);
                    foundSchema |= item.ExtType == Etw.EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL;
                }

                if (!foundSchema) return null;
                using (var sha = SHA256.Create())
                {
                    return BitConverter.ToString(sha.ComputeHash(identity.ToArray())).Replace("-", string.Empty);
                }
            }
        }

        private unsafe IEventTraceOperand BuildOperandFromTdh(EVENT_RECORD* eventRecord, int metadataTableIndex, bool allowAnalysisHostMetadata)
        {
            bool hasTraceLoggingSchema = HasTraceLoggingSchema(eventRecord);
            // Normal decoding only consults TDH when the record itself carries its
            // TraceLogging schema. Host registrations are an explicit, separate opt-in.
            if (!hasTraceLoggingSchema && !allowAnalysisHostMetadata)
            {
                return null;
            }

            string schemaError = hasTraceLoggingSchema ? GetTraceLoggingSchemaError(eventRecord) : null;
            if (schemaError != null)
            {
                return BuildTdhFailureOperand(eventRecord, metadataTableIndex, true, schemaError);
            }

            uint bufferSize = 0;
            byte* buffer = (byte*)0;

            // Not Found
            int status = this.TdhInformationLookup(eventRecord, 0, IntPtr.Zero, buffer, ref bufferSize);
            if (status != 122 && status != 0)
            {
                return hasTraceLoggingSchema
                    ? BuildTdhFailureOperand(eventRecord, metadataTableIndex, true, "TDH could not resolve the TraceLogging schema (win32=" + status + ").")
                    : null;
            }

            if (bufferSize > 16 * 1024 * 1024 || bufferSize < (uint)Marshal.OffsetOf(typeof(TRACE_EVENT_INFO), nameof(TRACE_EVENT_INFO.EventPropertyInfoArray)).ToInt32())
            {
                return BuildTdhFailureOperand(eventRecord, metadataTableIndex, hasTraceLoggingSchema, "TDH returned an invalid TRACE_EVENT_INFO buffer length.");
            }

            buffer = (byte*)Marshal.AllocHGlobal((int)bufferSize);
            uint allocatedSize = bufferSize;
            try
            {
                status = this.TdhInformationLookup(eventRecord, 0, IntPtr.Zero, buffer, ref bufferSize);
                if (status != 0)
                {
                    return hasTraceLoggingSchema
                        ? BuildTdhFailureOperand(eventRecord, metadataTableIndex, true, "TDH could not read the TraceLogging schema (win32=" + status + ").")
                        : null;
                }

                if (bufferSize > allocatedSize || bufferSize > 16 * 1024 * 1024)
                {
                    return BuildTdhFailureOperand(eventRecord, metadataTableIndex, hasTraceLoggingSchema, "TDH returned an inconsistent or oversized TRACE_EVENT_INFO size.");
                }

                var traceEventInfo = (TRACE_EVENT_INFO*)buffer;
                if (!EventTraceOperandBuilder.IsValidTraceEventInfo(traceEventInfo, (int)bufferSize, out _))
                {
                    return BuildTdhFailureOperand(eventRecord, metadataTableIndex, hasTraceLoggingSchema, "TDH returned malformed TRACE_EVENT_INFO.");
                }

                bool isTraceLogging = traceEventInfo->DecodingSource == DECODING_SOURCE.DecodingSourceTlg;
                if (isTraceLogging && !hasTraceLoggingSchema)
                {
                    return null;
                }

                if (isTraceLogging)
                {
                    if (!DoesAnalysisHostIdentityMatchRecord(eventRecord, traceEventInfo))
                    {
                        return BuildTdhFailureOperand(eventRecord, metadataTableIndex, true, "TDH TraceLogging metadata does not match this provider/event/version record.");
                    }
                    return EventTraceOperandBuilder.Build(traceEventInfo, metadataTableIndex, MetadataSource.TraceLogging, "tdh:embedded-tracelogging-schema");
                }

                if (hasTraceLoggingSchema)
                {
                    return BuildTdhFailureOperand(eventRecord, metadataTableIndex, true, "TDH did not return TraceLogging metadata for this self-describing record.");
                }

                if (!allowAnalysisHostMetadata) return null;
                if (!DoesAnalysisHostIdentityMatchRecord(eventRecord, traceEventInfo))
                {
                    return new UnknownOperandBuilder(eventRecord->ProviderId, eventRecord->Id, eventRecord->Version,
                        metadataTableIndex, DecodeStatus.DecodeError,
                        "Analysis-host TDH metadata does not match this provider/event/version record.");
                }
                return EventTraceOperandBuilder.Build(traceEventInfo, metadataTableIndex, MetadataSource.LocalCache, "tdh:analysis-host-provider-registration");
            }
            finally
            {
                Marshal.FreeHGlobal((IntPtr)buffer);
            }
        }

        private static unsafe IEventTraceOperand BuildTdhFailureOperand(EVENT_RECORD* eventRecord, int metadataTableIndex, bool hasTraceLoggingSchema, string reason)
        {
            if (!hasTraceLoggingSchema)
            {
                return new UnknownOperandBuilder(eventRecord->ProviderId, eventRecord->Id, eventRecord->Version,
                    metadataTableIndex, DecodeStatus.DecodeError, reason);
            }

            // A failed per-record TraceLogging schema must not be replaced by a
            // manifest or host registration that merely shares its header key.
            var metadata = new EventMetadata(eventRecord->ProviderId, eventRecord->Id, eventRecord->Version,
                "TraceLogging(" + eventRecord->ProviderId.ToString("D") + ")", Array.Empty<PropertyMetadata>(), null,
                MetadataSource.TraceLogging, DecodeStatus.DecodeError, "tdh:embedded-tracelogging-schema",
                "TraceLogging metadata could not be used: " + reason, ResolutionStatus.Invalid);
            return new EventTraceOperand(metadata, metadataTableIndex, Array.Empty<IEventTracePropertyOperand>());
        }

        internal static unsafe bool DoesAnalysisHostIdentityMatchRecord(EVENT_RECORD* eventRecord, TRACE_EVENT_INFO* info)
        {
            if (eventRecord == null || info == null || info->Version != eventRecord->Version) return false;
            if ((eventRecord->Flags & Etw.EVENT_HEADER_FLAG_CLASSIC_HEADER) != 0)
            {
                bool providerMatches = info->EventGuid != Guid.Empty
                    ? info->EventGuid == eventRecord->ProviderId
                    : info->ProviderGuid == eventRecord->ProviderId;
                return providerMatches && info->Opcode == eventRecord->Opcode;
            }

            return info->ProviderGuid == eventRecord->ProviderId && info->Id == eventRecord->Id;
        }

        private static unsafe IEventTraceOperand BuildUnknownOperand(EVENT_RECORD* eventRecord, int metadataTableIndex)
        {
            return new UnknownOperandBuilder(eventRecord->ProviderId, eventRecord->Id, eventRecord->Version, metadataTableIndex);
        }

        private static IEventTraceOperand RelabelLocalMetadata(IEventTraceOperand operand, int metadataTableIndex, bool forceLocal = false)
        {
            if (operand == null) return null;
            var original = operand.Metadata;
            if (!forceLocal && (original.MetadataSource == MetadataSource.TraceLogging || original.MetadataSource == MetadataSource.Embedded))
            {
                return new EventTraceOperand(original, metadataTableIndex, operand.EventPropertyOperands);
            }
            var metadata = new EventMetadata(original.ProviderGuid, original.Id, original.Version, original.Name, original.Properties,
                original.ProviderName, MetadataSource.LocalCache, original.DecodeStatus,
                "tdh:analysis-host-provider-registration", original.DecodeReason, original.ResolutionStatus);
            return new EventTraceOperand(metadata, metadataTableIndex, operand.EventPropertyOperands);
        }

        internal static unsafe IEventTraceOperand NormalizeLocalMetadataToRecordHeader(IEventTraceOperand operand, EVENT_RECORD* eventRecord, int metadataTableIndex)
        {
            if (operand == null) return null;
            var original = operand.Metadata;
            if ((eventRecord->Flags & Etw.EVENT_HEADER_FLAG_CLASSIC_HEADER) == 0) return operand;
            var metadata = new EventMetadata(eventRecord->ProviderId, eventRecord->Id, eventRecord->Version, original.Name,
                original.Properties, original.ProviderName, MetadataSource.LocalCache, original.DecodeStatus,
                original.Provenance ?? "tdh:analysis-host-provider-registration", original.DecodeReason, original.ResolutionStatus);
            return new EventTraceOperand(metadata, metadataTableIndex, operand.EventPropertyOperands);
        }

        private unsafe EventSourceManifest CreateEventSourceManifest(Guid providerGuid, Dictionary<Guid, EventSourceManifest> cache, EVENT_RECORD* eventRecord, EventRecordReader eventRecordReader)
        {
            // EventSource Schema events have the following signature:
            // { byte Format, byte MajorVersion, byte MinorVersion, byte Magic, ushort TotalChunks, ushort ChunkNumber } == 8 bytes, followed by the XML schema
            if (eventRecord->UserDataLength <= 8)
            {
                throw new InvalidOperationException("EventSource metadata manifest chunk has no schema bytes.");
            }

            var format = eventRecordReader.ReadUInt8();
            var majorVersion = eventRecordReader.ReadUInt8();
            var minorVersion = eventRecordReader.ReadUInt8();
            var magic = eventRecordReader.ReadUInt8();
            ushort totalChunks = eventRecordReader.ReadUInt16();
            ushort chunkNumber = eventRecordReader.ReadUInt16();

            if (!(format == 1 && magic == 0x5B) || totalChunks == 0 || totalChunks > 1024 || chunkNumber >= totalChunks)
            {
                return null;
            }

            EventSourceManifest manifest;
            bool exists = cache.TryGetValue(providerGuid, out manifest);
            if (!exists
                || manifest.Format != format
                || manifest.MajorVersion != majorVersion
                || manifest.MinorVersion != minorVersion
                || manifest.Magic != magic
                || manifest.TotalChunks != totalChunks
                || (chunkNumber == 0 && manifest.IsComplete))
            {
                this.InvalidateProviderCache(providerGuid);
                manifest = new EventSourceManifest(eventRecord->ProviderId, format, majorVersion, minorVersion, magic, totalChunks);
                cache[providerGuid] = manifest;
            }

            byte[] schemaChunk = eventRecordReader.ReadRemainingBytes();
            manifest.AddChunk(chunkNumber, schemaChunk);

            return manifest;
        }

        private void InvalidateProviderCache(Guid providerGuid)
        {
            var keys = new List<TraceEventKey>();
            foreach (var key in this.actionTable.Keys)
            {
                if (key.ProviderId == providerGuid) keys.Add(key);
            }

            foreach (var key in keys)
            {
                this.actionTable.Remove(key);
                this.operandTable.Remove(key);
            }

        }

        private unsafe IEventTraceOperand BuildOperand(EVENT_RECORD* eventRecord, EventRecordReader eventRecordReader, int metadataTableIndex, ref bool isSpecialKernelTraceMetaDataEvent)
        {
            if (eventRecord->ProviderId == CustomParserGuids.KernelTraceControlMetaDataGuid && eventRecord->Opcode == 32)
            {
                var embeddedInfo = (TRACE_EVENT_INFO*)eventRecord->UserData;
                if (!EventTraceOperandBuilder.IsValidTraceEventInfo(embeddedInfo, eventRecord->UserDataLength, out string validationError))
                {
                    return new UnknownOperandBuilder(eventRecord->ProviderId, eventRecord->Id, eventRecord->Version, metadataTableIndex, DecodeStatus.DecodeError, validationError);
                }

                isSpecialKernelTraceMetaDataEvent = true;
                var embeddedOperand = EventTraceOperandBuilder.Build(embeddedInfo, metadataTableIndex, MetadataSource.Embedded, "kerneltracecontrol");
                var targetKey = GetEmbeddedSchemaKey(embeddedInfo);
                return this.CacheEmbeddedSchema(targetKey, embeddedOperand);
            }

            if (IsEventSourceManifestRecord(eventRecord))
            {
                BuildOperandFromXml(eventRecord, this.eventSourceManifestCache, eventRecordReader, metadataTableIndex);
                return BuildMetadataContainerOperand(eventRecord, metadataTableIndex, "EventSource/ManifestChunk",
                    "Recognized EventSource metadata manifest chunk; original bytes are retained. The target manifest may still be incomplete.");
            }

            IEventTraceOperand operand;
            operand = BuildOperandFromXml(eventRecord, this.eventSourceManifestCache, eventRecordReader, metadataTableIndex);
            if (operand != null)
            {
                return this.CacheEmbeddedSchema(new EventKey(eventRecord->ProviderId, eventRecord->Id, eventRecord->Version), operand);
            }

            operand = BuildOperandFromTdh(eventRecord, metadataTableIndex, allowAnalysisHostMetadata: false);
            if (operand != null)
            {
                return operand;
            }

            ResolutionResult diagnostic = null;
            // User-supplied evidence sources are consulted only after event-embedded schema.
            EventKey key = GetRecordKey(eventRecord);
            if (this.ResolverChain != null)
            {
                var resolution = this.ResolverChain.Resolve(key);
                if (resolution != null && resolution.Resolved)
                {
                    return resolution.Operand;
                }

                diagnostic = resolution;
            }

            // Analysis-host metadata is a last-resort source. Explicit evidence
            // conflicts, malformed schemas, and known unsupported layouts remain
            // authoritative and must never be bypassed by the host registration.
            if (this.AllowLocalMetadata && (diagnostic == null || diagnostic.Status == ResolutionStatus.Missing))
            {
                operand = this.LocalMetadataTestHook != null
                    ? RelabelLocalMetadata(this.LocalMetadataTestHook(key), metadataTableIndex, forceLocal: true)
                    : NormalizeLocalMetadataToRecordHeader(
                        RelabelLocalMetadata(BuildOperandFromTdh(eventRecord, metadataTableIndex, allowAnalysisHostMetadata: true), metadataTableIndex),
                        eventRecord, metadataTableIndex);
                if (operand != null) return operand;
            }

            // Keep manifest records (id 65534) so metadata consumption is not silently dropped.
            if (operand == null)
            {
                var status = diagnostic == null ? DecodeStatus.MetadataMissing : ToDecodeStatus(diagnostic.Status);
                string reason = diagnostic?.Reason ?? "No embedded or trusted external schema was found.";
                operand = new UnknownOperandBuilder(eventRecord->ProviderId, eventRecord->Id, eventRecord->Version, metadataTableIndex, status, reason, diagnostic?.Status);
            }

            return operand;
        }

        private static DecodeStatus ToDecodeStatus(ResolutionStatus status)
        {
            switch (status)
            {
                case ResolutionStatus.Unsupported: return DecodeStatus.Unsupported;
                case ResolutionStatus.Invalid:
                case ResolutionStatus.Conflict: return DecodeStatus.DecodeError;
                default: return DecodeStatus.MetadataMissing;
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static unsafe bool HasBuiltinParser(EVENT_RECORD* record)
        {
            return record->ProviderId == CustomParserGuids.KernelTraceControlImageIdGuid && (record->Opcode == 0 || record->Opcode == 36 || record->Opcode == 64)
                || record->ProviderId == CustomParserGuids.KernelStackWalkGuid && record->Opcode == 32;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private unsafe bool CustomParserLookup(EVENT_RECORD* eventRecord, RuntimeEventMetadata runtimeMetadata, ref TraceEventKey key)
        {
            if (HasTraceLoggingSchema(eventRecord)) return false;
            Action<EventRecordReader, T, EventMetadata[], RuntimeEventMetadata> parser = null;
            EventMetadata template = null;
            if (eventRecord->ProviderId == CustomParserGuids.KernelTraceControlImageIdGuid)
            {
                switch (eventRecord->Opcode)
                {
                    case 0:
                        parser = new KernelTraceControlImageIdParser().Parse;
                        template = KernelTraceControlImageIdParser.SchemaMetadata;
                        break;
                    case 36:
                        parser = new KernelTraceControlDbgIdParser().Parse;
                        template = KernelTraceControlDbgIdParser.SchemaMetadata;
                        break;
                    case 64:
                        parser = new KernelTraceControlImageIdFileVersionParser().Parse;
                        template = KernelTraceControlImageIdFileVersionParser.SchemaMetadata;
                        break;
                }
            }
            else if (eventRecord->ProviderId == CustomParserGuids.KernelStackWalkGuid && eventRecord->Opcode == 32)
            {
                parser = new KernelStackWalkEventParser().Parse;
                template = KernelStackWalkEventParser.SchemaMetadata;
            }

            if (parser == null) return false;
            this.actionTable[key] = parser;
            this.operandTable[key] = new EventTraceOperand(CustomParserMetadata.Bind(template, runtimeMetadata), 0, Array.Empty<IEventTracePropertyOperand>());
            return true;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private unsafe IEventTraceOperand SlowLookup(EVENT_RECORD* eventRecord, EventRecordReader eventRecordReader, RuntimeEventMetadata runtimeMetadata, ref TraceEventKey key, string traceLoggingIdentity)
        {
            if (this.CustomParserLookup(eventRecord, runtimeMetadata, ref key))
            {
                if (!this.SchemaOnly) this.actionTable[key](eventRecordReader, this.writer, this.eventMetadataTable, runtimeMetadata);
                return this.operandTable[key];
            }

            bool isSpecialKernelTraceMetaDataEvent = false;
            var operand = this.BuildOperand(eventRecord, eventRecordReader, this.eventMetadataTableList.Count, ref isSpecialKernelTraceMetaDataEvent);

            if (operand != null)
            {
                // Resolvers may not know the table slot yet; assign it now.
                operand.EventMetadataTableIndex = this.eventMetadataTableList.Count;
                this.eventMetadataTableList.Add(operand.Metadata);
                this.eventMetadataTable = this.eventMetadataTableList.ToArray(); // TODO: Need to improve this

                var eventRecordReaderParam = Expression.Parameter(ReaderType);
                var eventWriterParam = Expression.Parameter(WriterType);
                var eventMetadataTableParam = Expression.Parameter(EventMetadataArrayType);
                var runtimeMetadataParam = Expression.Parameter(RuntimeMetadataType);

                var parameters = new[] { eventRecordReaderParam, eventWriterParam, eventMetadataTableParam, runtimeMetadataParam };
                var name = Regex.Replace(InvalidCharacters.Replace(operand.Metadata.Name, "_"), @"\s+", "_");
                var body = EventTraceOperandExpressionBuilder.Build(operand, eventRecordReaderParam, eventWriterParam, eventMetadataTableParam, runtimeMetadataParam);
                LambdaExpression expression = Expression.Lambda<Action<EventRecordReader, T, EventMetadata[], RuntimeEventMetadata>>(body, "Read_" + name, parameters);
                var action = (Action<EventRecordReader, T, EventMetadata[], RuntimeEventMetadata>)expression.Compile(false);

                if (isSpecialKernelTraceMetaDataEvent)
                {
                    var e = (TRACE_EVENT_INFO*)eventRecord->UserDataFixed;
                    var schemaKey = GetEmbeddedSchemaKey(e);
                    var metadataKey = new TraceEventKey(schemaKey.ProviderGuid, schemaKey.ClassicOpcode.HasValue ? schemaKey.ClassicOpcode.Value : schemaKey.EventId,
                        schemaKey.Version, schemaKey.ClassicOpcode.HasValue);
                    this.operandTable[metadataKey] = operand;
                    this.actionTable.AddOrUpdate(metadataKey, action);

                    var rawMetadataOperand = BuildMetadataContainerOperand(eventRecord, this.eventMetadataTableList.Count,
                        "KernelTraceControl/SchemaMetadata", "Recognized embedded KernelTraceControl schema metadata record; original bytes are retained.");
                    if (!this.SchemaOnly)
                    {
                        this.writer.WriteEventBegin(rawMetadataOperand.Metadata, runtimeMetadata);
                        this.writer.WriteEventEnd();
                    }

                    return rawMetadataOperand;
                }
                else if (traceLoggingIdentity != null)
                {
                    // TraceLogging schema content is part of the action-cache key.
                    this.traceLoggingOperandTable[traceLoggingIdentity] = operand;
                    this.traceLoggingActionTable[traceLoggingIdentity] = action;
                    eventRecord->UserData = eventRecord->UserDataFixed;
                    if (!this.SchemaOnly) action(eventRecordReader, this.writer, this.eventMetadataTable, runtimeMetadata);
                }
                else
                {
                    this.operandTable[key] = operand;
                    this.actionTable.Add(key, action);
                    if (!this.SchemaOnly)
                    {
                        eventRecord->UserData = eventRecord->UserDataFixed;
                        action(eventRecordReader, this.writer, this.eventMetadataTable, runtimeMetadata);
                    }
                }
            }

            return operand;
        }
    }
}
