namespace ETWDeserializer
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Text;
    using System.Xml;

    public enum WevtTemplateStatus
    {
        NotApplicable,
        Supported,
        PartiallySupported,
        Unsupported,
        Invalid,
    }

    public sealed class WevtTemplateProviderResult
    {
        internal WevtTemplateProviderResult(Guid providerGuid, instrumentationManifest manifest, WevtTemplateStatus status, IReadOnlyList<string> reasons, IReadOnlyCollection<EventKey> unsupportedEvents = null, bool allEventsUnsupported = false, IReadOnlyCollection<EventKey> invalidEvents = null)
        {
            this.ProviderGuid = providerGuid;
            this.Manifest = manifest;
            this.Status = status;
            this.Reasons = reasons;
            this.UnsupportedEvents = unsupportedEvents ?? Array.Empty<EventKey>();
            this.AllEventsUnsupported = allEventsUnsupported;
            this.InvalidEvents = invalidEvents ?? Array.Empty<EventKey>();
        }

        public Guid ProviderGuid { get; }

        public instrumentationManifest Manifest { get; }

        public WevtTemplateStatus Status { get; }

        public IReadOnlyList<string> Reasons { get; }

        public IReadOnlyCollection<EventKey> UnsupportedEvents { get; }

        public bool AllEventsUnsupported { get; }

        public IReadOnlyCollection<EventKey> InvalidEvents { get; }
    }

    /// <summary>
    /// Bounded static reader for the documented CRIM 3.1 and 5.1 layouts.
    /// Unknown types, map-dependent fields, arrays, structures, and other
    /// versions are left unsupported instead of being guessed.
    /// </summary>
    public static class WevtTemplateReader
    {
        private const uint CrimSignature = 0x4d495243; // CRIM
        private const uint WevtSignature = 0x54564557; // WEVT
        private const uint MaxItems = 65536;
        private const uint MaxBlobSize = 512 * 1024 * 1024;
        private const int EventRecordSize = 48;
        private const int ProviderRecordSize = 20;
        private const int ElementRecordSize = 8;
        private const int TemplateItemSize = 20;

        public static bool IsWevtTemplate(byte[] data)
        {
            return data != null && data.Length >= 4
                && (ReadUInt32(data, 0) == WevtSignature || ReadUInt32(data, 0) == CrimSignature);
        }

        public static IReadOnlyList<WevtTemplateProviderResult> ReadProviders(byte[] data)
        {
            ValidateBlob(data);
            if (ReadUInt32(data, 0) != CrimSignature)
            {
                throw new InvalidDataException("A CRIM compiled-manifest container is required to enumerate providers.");
            }

            uint blobSize = ReadUInt32(data, 4);
            ushort major = ReadUInt16(data, 8);
            ushort minor = ReadUInt16(data, 10);
            if (blobSize < 16 || blobSize > data.Length || data.Length - blobSize > 7)
            {
                throw new InvalidDataException("The CRIM declared size is outside the resource bounds.");
            }

            uint providerCount = ReadUInt32(data, 12);
            if (providerCount > MaxItems)
            {
                throw new InvalidDataException("CRIM declares too many providers.");
            }

            EnsureRange(blobSize, 16, (long)providerCount * ProviderRecordSize);
            var results = new List<WevtTemplateProviderResult>((int)providerCount);
            bool supportedVersion = (major == 3 && minor == 1) || (major == 5 && minor == 1);
            for (uint i = 0; i < providerCount; i++)
            {
                int entry = checked(16 + (int)(i * ProviderRecordSize));
                var guid = new Guid(new ReadOnlySpan<byte>(data, entry, 16));
                uint providerOffset = ReadUInt32(data, entry + 16);
                if (!supportedVersion)
                {
                    results.Add(new WevtTemplateProviderResult(guid, null, WevtTemplateStatus.Unsupported,
                        new[] { "Unsupported CRIM format version " + major + "." + minor + "; supported versions are 3.1 and 5.1." },
                        allEventsUnsupported: true));
                    continue;
                }

                try
                {
                    results.Add(ReadProvider(data, blobSize, guid, providerOffset));
                }
                catch (InvalidDataException ex)
                {
                    results.Add(new WevtTemplateProviderResult(guid, null, WevtTemplateStatus.Invalid,
                        new[] { ex.Message }, allEventsUnsupported: true));
                }
            }

            return results;
        }

        public static WevtTemplateProviderResult ReadProvider(byte[] data, Guid providerGuid)
        {
            ValidateBlob(data);
            if (ReadUInt32(data, 0) == CrimSignature)
            {
                foreach (var result in ReadProviders(data))
                {
                    if (result.ProviderGuid == providerGuid)
                    {
                        return result;
                    }
                }

                return new WevtTemplateProviderResult(providerGuid, null, WevtTemplateStatus.NotApplicable,
                    new[] { "The compiled manifest does not contain the requested provider GUID." });
            }

            if (ReadUInt32(data, 0) == WevtSignature)
            {
                throw new NotSupportedException("A standalone WEVT resource has no provider GUID binding and cannot be safely associated with this provider.");
            }

            return new WevtTemplateProviderResult(providerGuid, null, WevtTemplateStatus.NotApplicable, Array.Empty<string>());
        }

        private static WevtTemplateProviderResult ReadProvider(byte[] data, uint blobSize, Guid providerGuid, uint providerOffset)
        {
            EnsureRange(blobSize, providerOffset, 20);
            if (ReadUInt32(data, providerOffset) != WevtSignature)
            {
                throw new InvalidDataException("A CRIM provider offset does not point to a WEVT record.");
            }

            uint providerSize = ReadUInt32(data, providerOffset + 4);
            uint elementCount = ReadUInt32(data, providerOffset + 12);
            if (providerSize < 20 || providerSize > blobSize - providerOffset || elementCount > MaxItems)
            {
                throw new InvalidDataException("The WEVT header declares an invalid size or element count.");
            }

            EnsureRange(providerOffset + providerSize, providerOffset + 20, (long)elementCount * ElementRecordSize);
            var elements = new Dictionary<string, uint>(StringComparer.Ordinal);
            for (uint i = 0; i < elementCount; i++)
            {
                uint entry = providerOffset + 20 + (i * ElementRecordSize);
                uint elementOffset = ReadUInt32(data, entry);
                EnsureRange(blobSize, elementOffset, 4);
                string signature = ReadSignature(data, elementOffset);
                if (IsKnownElement(signature))
                {
                    if (elements.ContainsKey(signature))
                    {
                        throw new InvalidDataException("The WEVT provider has duplicate " + signature + " elements.");
                    }

                    elements.Add(signature, elementOffset);
                }
                else
                {
                    // Unknown tables are recorded but do not invalidate unrelated scalar templates.
                    elements.Add("?" + elementOffset.ToString(CultureInfo.InvariantCulture), elementOffset);
                }
            }

            if (!elements.TryGetValue("EVNT", out uint eventOffset))
            {
                return new WevtTemplateProviderResult(providerGuid, null, WevtTemplateStatus.Unsupported,
                    new[] { "The provider has no recognized EVNT table." });
            }

            return BuildManifest(data, blobSize, providerGuid, eventOffset, elements);
        }

        private static WevtTemplateProviderResult BuildManifest(byte[] data, uint blobSize, Guid providerGuid, uint eventOffset, Dictionary<string, uint> elements)
        {
            uint eventSize = ReadUInt32(data, eventOffset + 4);
            uint eventCount = ReadUInt32(data, eventOffset + 8);
            if (eventSize < 16 || eventSize > blobSize - eventOffset || eventCount > MaxItems)
            {
                throw new InvalidDataException("The EVNT table declares an invalid size or event count.");
            }

            EnsureRange(eventOffset + eventSize, eventOffset + 16, (long)eventCount * EventRecordSize);

            var definitions = new List<EventDefinitionType>();
            var templates = new List<TemplateItemType>();
            var reasons = new List<string>();
            var seenKeys = new HashSet<string>(StringComparer.Ordinal);
            var ambiguousKeys = new HashSet<string>(StringComparer.Ordinal);
            var unsupportedEvents = new HashSet<EventKey>();
            var invalidEvents = new HashSet<EventKey>();
            for (uint i = 0; i < eventCount; i++)
            {
                uint record = eventOffset + 16 + (i * EventRecordSize);
                ushort eventId = ReadUInt16(data, record);
                byte version = data[record + 2];
                uint templateOffset = ReadUInt32(data, record + 20);
                // The value at +44 is an auxiliary metadata offset in observed
                // CRIM 5.1 resources (channel table); it is not a bit flag mask.
                // Event header values remain on the ETW record itself.
                string eventKey = eventId.ToString(CultureInfo.InvariantCulture) + ":" + version.ToString(CultureInfo.InvariantCulture);
                if (!seenKeys.Add(eventKey))
                {
                    ambiguousKeys.Add(eventKey);
                    reasons.Add("Duplicate event ID/version " + eventKey + " is ambiguous.");
                    continue;
                }

                string templateId = "T" + templateOffset.ToString(CultureInfo.InvariantCulture);
                TemplateItemType template = null;
                if (templateOffset != 0)
                {
                    try
                    {
                        template = ReadTemplate(data, blobSize, templateOffset, templateId);
                    }
                    catch (NotSupportedException ex)
                    {
                        reasons.Add("Event " + eventKey + ": " + ex.Message);
                        unsupportedEvents.Add(new EventKey(providerGuid, eventId, version));
                        continue;
                    }
                    catch (InvalidDataException ex)
                    {
                        reasons.Add("Event " + eventKey + ": invalid template data: " + ex.Message);
                        invalidEvents.Add(new EventKey(providerGuid, eventId, version));
                        continue;
                    }
                }

                definitions.Add(new EventDefinitionType
                {
                    value = eventId.ToString(CultureInfo.InvariantCulture),
                    version = version.ToString(CultureInfo.InvariantCulture),
                    template = template == null ? null : templateId,
                    symbol = "Event" + eventId.ToString(CultureInfo.InvariantCulture),
                });
                if (template != null)
                {
                    templates.Add(template);
                }
            }

            definitions.RemoveAll(definition => ambiguousKeys.Contains(definition.value + ":" + definition.version));

            var provider = new ProviderType
            {
                name = "{" + providerGuid.ToString("D") + "}",
                guid = providerGuid.ToString("D"),
                Items = new object[]
                {
                    new DefinitionType { Items = definitions.ToArray() },
                    new TemplateListType { template = templates.ToArray() },
                },
            };
            var manifest = new instrumentationManifest
            {
                Items = new object[]
                {
                    new InstrumentationType
                    {
                        Items = new object[] { new EventsType { Items = new object[] { provider } } },
                    },
                },
            };

            WevtTemplateStatus status = reasons.Count == 0
                ? WevtTemplateStatus.Supported
                : definitions.Count == 0 ? WevtTemplateStatus.Unsupported : WevtTemplateStatus.PartiallySupported;
            return new WevtTemplateProviderResult(providerGuid, manifest, status, reasons, unsupportedEvents, invalidEvents: invalidEvents);
        }

        private static TemplateItemType ReadTemplate(byte[] data, uint blobSize, uint offset, string tid)
        {
            EnsureRange(blobSize, offset, 40);
            if (ReadUInt32(data, offset) != 0x504d4554) // TEMP
            {
                throw new InvalidDataException("An EVNT template offset does not point to TEMP.");
            }

            uint size = ReadUInt32(data, offset + 4);
            uint itemCount = ReadUInt32(data, offset + 8);
            uint nameCount = ReadUInt32(data, offset + 12);
            uint itemOffset = ReadUInt32(data, offset + 16);
            uint eventType = ReadUInt32(data, offset + 20);
            if (size < 40 || size > blobSize - offset || itemCount > MaxItems || nameCount > MaxItems)
            {
                throw new InvalidDataException("The TEMP size or item/name count is invalid.");
            }

            if (eventType != 1)
            {
                throw new NotSupportedException("The template is not an EventData template (event type " + eventType.ToString(CultureInfo.InvariantCulture) + ").");
            }

            var properties = new List<object>((int)itemCount);
            if (itemCount != 0)
            {
                if (itemOffset == 0)
                {
                    throw new InvalidDataException("TEMP declares items but has no external item descriptor table.");
                }

                EnsureRange(blobSize, itemOffset, (long)itemCount * TemplateItemSize);
                for (uint i = 0; i < itemCount; i++)
                {
                    uint descriptor = itemOffset + (i * TemplateItemSize);
                    uint unknownFlags = ReadUInt32(data, descriptor);
                    byte inType = data[descriptor + 4];
                    ushort unknown16 = ReadUInt16(data, descriptor + 6);
                    uint mapOffset = ReadUInt32(data, descriptor + 8);
                    ushort count = ReadUInt16(data, descriptor + 12);
                    ushort length = ReadUInt16(data, descriptor + 14);
                    uint nameOffset = ReadUInt32(data, descriptor + 16);

                    if (unknownFlags != 0 || unknown16 != 0)
                    {
                        throw new NotSupportedException("A property has nonzero unknown flags.");
                    }

                    if (mapOffset != 0)
                    {
                        throw new NotSupportedException("A property references an unsupported MAPS table.");
                    }

                    if (count > 1 || length != 0)
                    {
                        throw new NotSupportedException("Array and fixed-length properties are not supported.");
                    }

                    string typeName = GetSupportedType(inType);
                    string propertyName = ReadName(data, blobSize, nameOffset);
                    properties.Add(new DataDefinitionType
                    {
                        name = propertyName,
                        inType = new XmlQualifiedName(typeName, "win"),
                    });
                }
            }

            return new TemplateItemType { tid = tid, Items = properties.ToArray() };
        }

        private static string GetSupportedType(byte inType)
        {
            switch (inType)
            {
                case 0x01: return "UnicodeString";
                case 0x02: return "AnsiString";
                case 0x03: return "Int8";
                case 0x04: return "UInt8";
                case 0x05: return "Int16";
                case 0x06: return "UInt16";
                case 0x07: return "Int32";
                case 0x08: return "UInt32";
                case 0x09: return "Int64";
                case 0x0a: return "UInt64";
                case 0x0b: return "Float";
                case 0x0c: return "Double";
                case 0x0d: return "Boolean";
                case 0x10: return "Pointer";
                case 0x11: return "FileTime";
                case 0x12: return "SystemTime";
                case 0x13: return "SID";
                case 0x0f: return "GUID";
                case 0x14: return "HexInt32";
                case 0x15: return "HexInt64";
                default: throw new NotSupportedException("Property input type 0x" + inType.ToString("x2", CultureInfo.InvariantCulture) + " is not supported.");
            }
        }

        private static string ReadName(byte[] data, uint blobSize, uint offset)
        {
            EnsureRange(blobSize, offset, 4);
            uint size = ReadUInt32(data, offset);
            if (size < 6 || size > 4096 || size > blobSize - offset)
            {
                throw new InvalidDataException("A TEMP property name has an invalid size.");
            }

            int chars = (int)(size - 4) / 2;
            int end = 0;
            for (; end < chars; end++)
            {
                if (ReadUInt16(data, offset + 4 + (uint)(end * 2)) == 0)
                {
                    break;
                }
            }

            if (end == chars)
            {
                throw new InvalidDataException("A TEMP property name is not null-terminated.");
            }

            return Encoding.Unicode.GetString(data, checked((int)offset + 4), end * 2);
        }

        private static string ReadSignature(byte[] data, uint offset)
        {
            return Encoding.ASCII.GetString(data, checked((int)offset), 4);
        }

        private static bool IsKnownElement(string signature)
        {
            return signature == "CHAN" || signature == "EVNT" || signature == "KEYW"
                || signature == "LEVL" || signature == "MAPS" || signature == "OPCO"
                || signature == "TASK" || signature == "TTBL" || signature == "PRVA";
        }

        private static void ValidateBlob(byte[] data)
        {
            if (data == null || data.Length < 4 || data.Length > MaxBlobSize)
            {
                throw new InvalidDataException("The compiled manifest is empty or exceeds the 512 MiB safety limit.");
            }
        }

        private static ushort ReadUInt16(byte[] data, long offset)
        {
            EnsureRange((uint)data.Length, offset, 2);
            return System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(new ReadOnlySpan<byte>(data, checked((int)offset), 2));
        }

        private static uint ReadUInt32(byte[] data, long offset)
        {
            EnsureRange((uint)data.Length, offset, 4);
            return System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(data, checked((int)offset), 4));
        }

        private static void EnsureRange(uint limit, long offset, long size)
        {
            if (offset < 0 || size < 0 || offset > limit - size)
            {
                throw new InvalidDataException("A compiled-manifest structure points outside the declared blob.");
            }
        }
    }
}
