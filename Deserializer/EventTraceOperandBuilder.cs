namespace ETWDeserializer
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Runtime.InteropServices;

    internal static unsafe class EventTraceOperandBuilder
    {
        public static bool IsValidTraceEventInfo(TRACE_EVENT_INFO* info, int bufferLength, out string reason)
        {
            reason = null;
            int propertyOffset = (int)Marshal.OffsetOf(typeof(TRACE_EVENT_INFO), nameof(TRACE_EVENT_INFO.EventPropertyInfoArray));
            if (info == null || bufferLength < propertyOffset)
            {
                reason = "TRACE_EVENT_INFO header is truncated.";
                return false;
            }

            if (info->PropertyCount > (uint)((bufferLength - propertyOffset) / sizeof(EVENT_PROPERTY_INFO))
                || info->TopLevelPropertyCount > info->PropertyCount)
            {
                reason = "TRACE_EVENT_INFO property table exceeds its buffer.";
                return false;
            }

            byte* bytes = (byte*)info;
            if (!ValidStringOffset(bytes, bufferLength, info->ProviderNameOffset)
                || !ValidStringOffset(bytes, bufferLength, info->LevelNameOffset)
                || !ValidStringOffset(bytes, bufferLength, info->ChannelNameOffset)
                || !ValidStringOffset(bytes, bufferLength, info->KeywordsNameOffset)
                || !ValidStringOffset(bytes, bufferLength, info->TaskNameOffset)
                || !ValidStringOffset(bytes, bufferLength, info->OpcodeNameOffset)
                || !ValidStringOffset(bytes, bufferLength, info->EventMessageOffset)
                || !ValidStringOffset(bytes, bufferLength, info->ProviderMessageOffset)
                || !ValidStringOffset(bytes, bufferLength, info->ActivityIDNameOffset)
                || !ValidStringOffset(bytes, bufferLength, info->RelatedActivityIDNameOffset))
            {
                reason = "TRACE_EVENT_INFO contains an out-of-bounds string offset.";
                return false;
            }

            var properties = (EVENT_PROPERTY_INFO*)(bytes + propertyOffset);
            for (uint i = 0; i < info->PropertyCount; i++)
            {
                ref EVENT_PROPERTY_INFO property = ref properties[i];
                if (property.NameOffset == 0 || !ValidStringOffset(bytes, bufferLength, property.NameOffset)
                    || (!IsStruct(property.Flags) && !ValidStringOffset(bytes, bufferLength, property.NonStructType.MapNameOffset)))
                {
                    reason = "TRACE_EVENT_INFO property contains an invalid name or map offset.";
                    return false;
                }

                if (IsStruct(property.Flags))
                {
                    uint start = property.StructType.StructStartIndex;
                    uint end = start + property.StructType.NumOfStructMembers;
                    if (end < start || end > info->PropertyCount)
                    {
                        reason = "TRACE_EVENT_INFO struct property exceeds the property table.";
                        return false;
                    }
                }
                else if ((property.Flags & PROPERTY_FLAGS.PropertyParamCount) != 0 && property.countPropertyIndex >= i)
                {
                    reason = "TRACE_EVENT_INFO variable array references an invalid count property.";
                    return false;
                }
                else if ((property.Flags & PROPERTY_FLAGS.PropertyParamLength) != 0 && property.lengthPropertyIndex >= i)
                {
                    reason = "TRACE_EVENT_INFO variable length references an invalid length property.";
                    return false;
                }
            }

            return true;
        }

        private static bool IsStruct(PROPERTY_FLAGS flags)
        {
            return (flags & PROPERTY_FLAGS.PropertyStruct) != 0;
        }

        private static unsafe bool ValidStringOffset(byte* buffer, int length, uint offset)
        {
            if (offset == 0) return true;
            if (offset >= length || (offset & 1) != 0) return false;
            for (uint i = offset; i + 1 < length; i += 2)
            {
                if (buffer[i] == 0 && buffer[i + 1] == 0) return true;
            }

            return false;
        }

        public static IEventTraceOperand Build(TRACE_EVENT_INFO* traceEventInfo, int metadataIndex)
        {
            return Build(traceEventInfo, metadataIndex, MetadataSource.Embedded, null);
        }

        public static IEventTraceOperand Build(TRACE_EVENT_INFO* traceEventInfo, int metadataIndex, MetadataSource source, string provenance)
        {
            return new EventTraceOperandBuilderFromTDH(traceEventInfo, source, provenance).Build(metadataIndex);
        }

        public static IEventTraceOperand Build(instrumentationManifest manifest, ushort eventId, int metadataIndex)
        {
            return Build(manifest, eventId, 0, metadataIndex, MetadataSource.Unknown, null);
        }

        /// <summary>Builds an event operand from an explicitly supplied manifest, requiring provider, id and version to match.</summary>
        public static IEventTraceOperand BuildManifest(instrumentationManifest manifest, EventKey key, MetadataSource source, string provenance)
        {
            if (manifest == null)
            {
                throw new ArgumentNullException(nameof(manifest));
            }

            if (CountMatchingDefinitions(manifest, key) > 1)
            {
                var conflictMetadata = new EventMetadata(key.ProviderGuid, key.EventId, key.Version, "ConflictingProvider(" + key.ProviderGuid.ToString("D") + ")", Array.Empty<PropertyMetadata>(), null, source, DecodeStatus.DecodeError, provenance, "The manifest defines this provider/event/version more than once.", ResolutionStatus.Conflict);
                return new EventTraceOperand(conflictMetadata, 0, Array.Empty<IEventTracePropertyOperand>());
            }

            return new TraceEventOperandBuilderFromXml(manifest, key.ProviderGuid, key.EventId, key.Version, source, provenance).Build(0);
        }

        public static IReadOnlyList<EventKey> GetEventKeys(instrumentationManifest manifest, Guid providerGuid)
        {
            var keys = new HashSet<EventKey>();
            foreach (var item in manifest.Items)
            {
                var instrumentation = item as InstrumentationType;
                if (instrumentation == null) continue;
                foreach (var eventsContainer in instrumentation.Items)
                {
                    var events = eventsContainer as EventsType;
                    if (events == null) continue;
                    foreach (var providerItem in events.Items)
                    {
                        var provider = providerItem as ProviderType;
                        if (provider == null || string.IsNullOrEmpty(provider.guid) || new Guid(provider.guid) != providerGuid) continue;
                        foreach (var providerChild in provider.Items)
                        {
                            var definitions = providerChild as DefinitionType;
                            if (definitions == null) continue;
                            foreach (EventDefinitionType definition in definitions.Items)
                            {
                                if (!ushort.TryParse(definition.value, out ushort id)) continue;
                                byte version = string.IsNullOrEmpty(definition.version) ? (byte)0 : byte.Parse(definition.version);
                                keys.Add(new EventKey(providerGuid, id, version));
                            }
                        }
                    }
                }
            }

            return new List<EventKey>(keys);
        }

        private static int CountMatchingDefinitions(instrumentationManifest manifest, EventKey key)
        {
            int count = 0;
            foreach (var item in manifest.Items)
            {
                var instrumentation = item as InstrumentationType;
                if (instrumentation == null) continue;
                foreach (var eventsContainer in instrumentation.Items)
                {
                    var events = eventsContainer as EventsType;
                    if (events == null) continue;
                    foreach (var providerItem in events.Items)
                    {
                        var provider = providerItem as ProviderType;
                        if (provider == null || string.IsNullOrEmpty(provider.guid) || new Guid(provider.guid) != key.ProviderGuid) continue;
                        foreach (var providerChild in provider.Items)
                        {
                            var definitions = providerChild as DefinitionType;
                            if (definitions == null) continue;
                            foreach (EventDefinitionType definition in definitions.Items)
                            {
                                byte version = string.IsNullOrEmpty(definition.version) ? (byte)0 : byte.Parse(definition.version);
                                if (string.Equals(definition.value, key.EventId.ToString("D"), StringComparison.Ordinal) && version == key.Version) count++;
                            }
                        }
                    }
                }
            }

            return count;
        }

        public static IEventTraceOperand Build(instrumentationManifest manifest, ushort eventId, byte version, int metadataIndex, MetadataSource source, string provenance)
        {
            return new TraceEventOperandBuilderFromXml(manifest, null, eventId, version, source, provenance).Build(metadataIndex);
        }

        private sealed class TraceEventOperandBuilderFromXml
        {
            private readonly instrumentationManifest manifest;

            private readonly ushort eventId;

            private readonly Guid? providerGuid;

            private readonly byte version;

            private readonly MetadataSource source;

            private readonly string provenance;

            public TraceEventOperandBuilderFromXml(instrumentationManifest manifest, Guid? providerGuid, ushort eventId, byte version, MetadataSource source, string provenance)
            {
                this.manifest = manifest;
                this.providerGuid = providerGuid;
                this.eventId = eventId;
                this.version = version;
                this.source = source;
                this.provenance = provenance;
            }

            public IEventTraceOperand Build(int eventMetadataTableIndex)
            {
                foreach (var instrumentationManifestTypeItem in this.manifest.Items)
                {
                    var instrumentationType = instrumentationManifestTypeItem as InstrumentationType;
                    if (instrumentationType != null)
                    {
                        foreach (var instrumentationTypeItem in instrumentationType.Items)
                        {
                            var eventTypes = instrumentationTypeItem as EventsType;
                            if (eventTypes != null)
                            {
                                foreach (var eventTypeItem in eventTypes.Items)
                                {
                                    var providerType = eventTypeItem as ProviderType;
                                    if (providerType != null)
                                    {
                                        var providerName = providerType.name;
                                        var providerGuid = new Guid(providerType.guid);

                                        if (this.providerGuid.HasValue && providerGuid != this.providerGuid.Value)
                                        {
                                            continue;
                                        }

                                        foreach (var providerTypeItem in providerType.Items)
                                        {
                                            var definitionType = providerTypeItem as DefinitionType;
                                            if (definitionType != null)
                                            {
                                                foreach (EventDefinitionType definitionTypeItem in definitionType.Items)
                                                {
                                                    if (string.Equals(definitionTypeItem.value, this.eventId.ToString("D")))
                                                    {
                                                        string version = definitionTypeItem.version;
                                                        byte definitionVersion = string.IsNullOrEmpty(version) ? (byte)0 : byte.Parse(version);

                                                        // ETW omits version when it is zero. Only accept an exact match so a
                                                        // changed payload layout is never decoded with the wrong template.
                                                        if (definitionVersion != this.version)
                                                        {
                                                            continue;
                                                        }

                                                        string task = definitionTypeItem.task == null ? string.IsNullOrEmpty(definitionTypeItem.symbol) ? "Task" : definitionTypeItem.symbol : definitionTypeItem.task.Name;
                                                        string opcode = definitionTypeItem.opcode == null ? string.Empty : definitionTypeItem.opcode.Name;
                                                        string template = definitionTypeItem.template;
                                                        bool requiresTemplate = !string.IsNullOrEmpty(template);
                                                        bool templateFound = false;
                                                        string unsupportedReason = null;

                                                        string name = providerName + "/" + task + (opcode == string.Empty ? string.Empty : "/" + opcode);
                                                        var properties = new List<IEventTracePropertyOperand>();

                                                        foreach (var item in providerType.Items)
                                                        {
                                                            var templateList = item as TemplateListType;
                                                            if (templateList != null)
                                                            {
                                                                foreach (var templateTid in templateList.template)
                                                                {
                                                                    if (string.Equals(templateTid.tid, template))
                                                                    {
                                                                        templateFound = true;
                                                                        int i = 0;
                                                                        foreach (var rawProperty in templateTid.Items)
                                                                        {
                                                                            var propertyItem = rawProperty as DataDefinitionType;
                                                                            if (propertyItem == null)
                                                                            {
                                                                                unsupportedReason = "Manifest struct or nested property is not supported; the raw payload is retained.";
                                                                                continue;
                                                                            }

                                                                            if (!string.IsNullOrEmpty(propertyItem.count)
                                                                                || !string.IsNullOrEmpty(propertyItem.length)
                                                                                || !string.IsNullOrEmpty(propertyItem.map)
                                                                                || propertyItem.outType != null)
                                                                            {
                                                                                unsupportedReason = "Manifest arrays, maps, lengths, and output formatting are not decoded; the raw payload is retained.";
                                                                                continue;
                                                                            }

                                                                            if (propertyItem.inType == null || string.IsNullOrEmpty(propertyItem.inType.Name))
                                                                            {
                                                                                unsupportedReason = "Manifest property has no supported inType; the raw payload is retained.";
                                                                                continue;
                                                                            }

                                                                            var inType = Extensions.ToTdhInType(propertyItem.inType.Name);
                                                                            var outType = TDH_OUT_TYPE.TDH_OUTTYPE_NOPRINT;
                                                                            var metadata = new PropertyMetadata(inType, outType, propertyItem.name, false, false, 0, null);
                                                                            properties.Add(new EventTracePropertyOperand(metadata, i++, false, false, false, false, false));
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }

                                                        if (requiresTemplate && !templateFound)
                                                        {
                                                            continue;
                                                        }

                                                        if (unsupportedReason != null)
                                                        {
                                                            var unsupportedMetadata = new EventMetadata(providerGuid, this.eventId, this.version, name, Array.Empty<PropertyMetadata>(), providerName, this.source, DecodeStatus.Unsupported, this.provenance, unsupportedReason);
                                                            return new EventTraceOperand(unsupportedMetadata, eventMetadataTableIndex, Array.Empty<IEventTracePropertyOperand>());
                                                        }

                                                        var operand = new EventTraceOperand(
                                                            new EventMetadata(
                                                                providerGuid,
                                                                this.eventId,
                                                                this.version,
                                                                name,
                                                                properties.Select(t => t.Metadata).ToArray(),
                                                                providerName,
                                                                this.source,
                                                                DecodeStatus.Decoded,
                                                                this.provenance), eventMetadataTableIndex,
                                                            properties);
                                                        return operand;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                return null;
            }
        }

        private sealed class EventTraceOperandBuilderFromTDH
        {
            private readonly TRACE_EVENT_INFO* traceEventInfo;

            private readonly MetadataSource source;

            private readonly string provenance;

            private readonly List<IEventTracePropertyOperand> flatPropertyList = new List<IEventTracePropertyOperand>();

            public EventTraceOperandBuilderFromTDH(TRACE_EVENT_INFO* traceEventInfo, MetadataSource source, string provenance)
            {
                this.traceEventInfo = traceEventInfo;
                this.source = source;
                this.provenance = provenance;
            }

            public IEventTraceOperand Build(int eventMetadataTableIndex)
            {
                var buffer = (byte*)this.traceEventInfo;
                EVENT_PROPERTY_INFO* eventPropertyInfoArr = (EVENT_PROPERTY_INFO*)&this.traceEventInfo->EventPropertyInfoArray;

                string provider = this.BuildName("Provider", this.traceEventInfo->ProviderGuid.ToString(), this.traceEventInfo->ProviderNameOffset);
                string task = this.BuildName("EventID", this.traceEventInfo->Id.ToString(), this.traceEventInfo->TaskNameOffset);
                string opcode = this.BuildName("Opcode", this.traceEventInfo->Opcode.ToString(), this.traceEventInfo->OpcodeNameOffset);

                bool isWpp = this.traceEventInfo->DecodingSource == DECODING_SOURCE.DecodingSourceWPP;

                string unsupportedReason = isWpp ? "WPP decoding is not supported by this decoder." : null;
                for (int i = 0; unsupportedReason == null && i < this.traceEventInfo->PropertyCount; i++)
                {
                    var property = eventPropertyInfoArr[i];
                    if ((property.Flags & PROPERTY_FLAGS.PropertyStruct) != 0)
                    {
                        unsupportedReason = "TDH struct properties are retained as raw payload because nested layouts are not supported safely.";
                    }
                    else if (property.NonStructType.MapNameOffset != 0)
                    {
                        unsupportedReason = "TDH event maps are not resolved by this decoder; the event is retained as raw payload.";
                    }
                }

                if (unsupportedReason != null)
                {
                    var unsupportedMetadata = new EventMetadata(
                        this.traceEventInfo->ProviderGuid,
                        this.traceEventInfo->Id,
                        this.traceEventInfo->Version,
                        provider + "/" + task + "/" + opcode,
                        Array.Empty<PropertyMetadata>(),
                        provider,
                        this.source,
                        DecodeStatus.Unsupported,
                        this.provenance,
                        unsupportedReason);
                    return new EventTraceOperand(unsupportedMetadata, eventMetadataTableIndex, Array.Empty<IEventTracePropertyOperand>());
                }

                int end = (int)this.traceEventInfo->TopLevelPropertyCount;
                var topLevelOperands = this.IterateProperties(buffer, 0, end, eventPropertyInfoArr);
                var metadata = new EventMetadata(
                    this.traceEventInfo->ProviderGuid,
                    this.traceEventInfo->Id,
                    this.traceEventInfo->Version,
                    provider + "/" + task + "/" + opcode,
                    this.flatPropertyList.Select(t => t.Metadata).ToArray(),
                    provider,
                    this.source,
                    isWpp ? DecodeStatus.Unsupported : DecodeStatus.Decoded,
                    this.provenance);
                return new EventTraceOperand(metadata, eventMetadataTableIndex, topLevelOperands);
            }

            private string BuildName(string prefix, string value, uint offset)
            {
                var buffer = (byte*)this.traceEventInfo;
                string item = prefix + "(" + value + ")";
                if (offset != 0)
                {
                    item = new string((char*)&buffer[offset]).Trim();
                }

                return item;
            }

            private List<EventTracePropertyOperand> IterateProperties(byte* buffer, int start, int end, EVENT_PROPERTY_INFO* eventPropertyInfoArr)
            {
                var operands = new List<EventTracePropertyOperand>();
                return this.IterateProperties(buffer, operands, start, end, eventPropertyInfoArr);
            }

            private List<EventTracePropertyOperand> IterateProperties(byte* buffer, List<EventTracePropertyOperand> operands, int start, int end, EVENT_PROPERTY_INFO* eventPropertyInfoArr)
            {
                var returnList = new List<EventTracePropertyOperand>();
                for (int i = start; i < end; ++i)
                {
                    var eventPropertyInfo = &eventPropertyInfoArr[i];
                    string propertyName = new string((char*)&buffer[eventPropertyInfo->NameOffset]);

                    int structchildren = eventPropertyInfo->StructType.NumOfStructMembers;
                    bool isStruct = (eventPropertyInfo->Flags & PROPERTY_FLAGS.PropertyStruct) == PROPERTY_FLAGS.PropertyStruct;
                    bool isVariableArray = (eventPropertyInfo->Flags & PROPERTY_FLAGS.PropertyParamCount) == PROPERTY_FLAGS.PropertyParamCount;
                    bool isFixedArray = (eventPropertyInfo->Flags & PROPERTY_FLAGS.PropertyParamFixedCount) == PROPERTY_FLAGS.PropertyParamFixedCount;
                    bool isVariableLength = (eventPropertyInfo->Flags & PROPERTY_FLAGS.PropertyParamLength) == PROPERTY_FLAGS.PropertyParamLength;
                    bool isFixedLength = (eventPropertyInfo->Flags & PROPERTY_FLAGS.PropertyParamFixedLength) == PROPERTY_FLAGS.PropertyParamFixedLength;
                    bool isWbemXmlFragment = (eventPropertyInfo->Flags & PROPERTY_FLAGS.PropertyWBEMXmlFragment) == PROPERTY_FLAGS.PropertyWBEMXmlFragment;

                    // NOTE: Do not remove this special case, there are cases like this, we just assume it's a fixed array
                    if (!isFixedArray && !isVariableArray && eventPropertyInfo->count > 1)
                    {
                        isFixedArray = true;
                    }

                    /* save important information in an object */
                    var operand = new EventTracePropertyOperand(
                        new PropertyMetadata((TDH_IN_TYPE)eventPropertyInfo->NonStructType.InType, (TDH_OUT_TYPE)eventPropertyInfo->NonStructType.OutType, propertyName, false, isStruct, isStruct ? structchildren : 0, null),
                        i,
                        isVariableArray,
                        isFixedArray,
                        isVariableLength,
                        isFixedLength,
                        isWbemXmlFragment);

                    this.flatPropertyList.Add(operand);
                    operands.Add(operand);
                    returnList.Add(operand);

                    /* if this references a previous field, we need to capture that as a local */
                    if (isVariableArray)
                    {
                        var reference = operands[eventPropertyInfo->countPropertyIndex];
                        reference.IsReferencedByOtherProperties = true;
                        operand.SetVariableArraySize(reference);
                    }
                    else if (isFixedArray)
                    {
                        operand.SetFixedArraySize(eventPropertyInfo->count);
                    }

                    /* if this references a previous field, we need to capture that as a local */
                    if (isVariableLength)
                    {
                        var reference = operands[eventPropertyInfo->lengthPropertyIndex];
                        reference.IsReferencedByOtherProperties = true;
                        operand.SetVariableLengthSize(reference);
                    }
                    else if (isFixedLength)
                    {
                        operand.SetFixedLengthSize(eventPropertyInfo->length);
                    }

                    if ((eventPropertyInfo->Flags & PROPERTY_FLAGS.PropertyStruct) == PROPERTY_FLAGS.PropertyStruct)
                    {
                        var innerProps = this.IterateProperties(
                            buffer,
                            operands,
                            eventPropertyInfo->StructType.StructStartIndex,
                            eventPropertyInfo->StructType.StructStartIndex + eventPropertyInfo->StructType.NumOfStructMembers,
                            eventPropertyInfoArr);

                        foreach (var innerProp in innerProps)
                        {
                            operand.Children.Add(innerProp);
                        }
                    }
                }

                return returnList;
            }
        }
    }

    internal sealed class UnknownOperandBuilder : IEventTraceOperand
    {
        public UnknownOperandBuilder(Guid providerGuid, ushort eventId, byte version, int metadataTableIndex)
            : this(providerGuid, eventId, version, metadataTableIndex, DecodeStatus.MetadataMissing, "No trusted event schema was available.")
        {
        }

        public UnknownOperandBuilder(Guid providerGuid, ushort eventId, byte version, int metadataTableIndex, DecodeStatus status, string reason)
            : this(providerGuid, eventId, version, metadataTableIndex, status, reason, null)
        {
        }

        public UnknownOperandBuilder(Guid providerGuid, ushort eventId, byte version, int metadataTableIndex, DecodeStatus status, string reason, ResolutionStatus? resolutionStatus)
        {
            this.EventMetadataTableIndex = metadataTableIndex;
            this.Metadata = new EventMetadata(
                providerGuid,
                eventId,
                version,
                "UnknownProvider(" + providerGuid.ToString("D") + ")",
                new PropertyMetadata[0],
                null,
                MetadataSource.Unknown,
                status,
                null,
                reason,
                resolutionStatus);
        }

        public int EventMetadataTableIndex { get; set; }

        public EventMetadata Metadata { get; set; }

        public IEnumerable<IEventTracePropertyOperand> EventPropertyOperands => Enumerable.Empty<IEventTracePropertyOperand>();
    }
}
