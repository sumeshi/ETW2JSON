namespace ETWDeserializer
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Xml;
    using Microsoft.Xml.Serialization.GeneratedAssembly;

    /// <summary>
    /// Resolves schemas from evidence PE files (DLL/EXE/SYS) using only static,
    /// read-only resource parsing. Evidence binaries are never loaded into the
    /// process or executed.
    ///
    /// Supported resource forms:
    ///  - embedded XML event manifests (resource type RT_MANIFEST with an
    ///    instrumentationManifest root);
    ///  - compiled WEVT_TEMPLATE blobs are detected but reported unsupported
    ///    (raw payload is preserved by the decoder).
    /// </summary>
    public sealed class PeResourceResolver : IMetadataResolver
    {
        private readonly List<LoadedPe> images = new List<LoadedPe>();

        public MetadataSource Source => MetadataSource.ExternalPeResource;

        public void AddFile(string path)
        {
            var resourceData = PeResourceReader.Read(path);
            var image = new LoadedPe(resourceData);
            foreach (var resource in resourceData.Resources)
            {
                if (resource.TypeId == 24) // RT_MANIFEST
                {
                    image.TryAddXmlManifest(resource);
                }
                else if (WevtTemplateReader.IsWevtTemplate(resource.Data))
                {
                    image.TryAddCompiledManifest(resource);
                }
            }

            this.images.Add(image);
        }

        /// <summary>True when at least one PE contained a compiled manifest this build cannot reconstruct.</summary>
        public bool HasUnsupportedCompiledManifest
        {
            get
            {
                foreach (var image in this.images)
                {
                    foreach (var resource in image.CompiledResources)
                    {
                        if (resource.HasUnsupportedManifest)
                        {
                            return true;
                        }
                    }
                }

                return false;
            }
        }

        public ResolutionResult Resolve(EventKey key)
        {
            if (key.ClassicOpcode.HasValue)
            {
                return ResolutionResult.UnresolvedResult(ResolutionStatus.Missing, MetadataSource.ExternalPeResource, null,
                    "Manifest PE resources do not supply classic/MOF class schemas; recover embedded trace metadata or the matching MOF definitions.");
            }
            ResolutionResult diagnostic = null;
            ResolutionResult resolved = null;
            foreach (var image in this.images)
            {
                foreach (var manifest in image.Manifests)
                {
                    if (!manifest.ContainsProvider(key.ProviderGuid))
                    {
                        continue;
                    }

                    var operand = EventTraceOperandBuilder.BuildManifest(manifest.Value, key, MetadataSource.ExternalPeResource, manifest.Provenance());
                    if (operand != null)
                    {
                        var candidate = new ResolutionResult(operand, MetadataSource.ExternalPeResource, manifest.Provenance());
                        if (resolved == null)
                        {
                            resolved = candidate;
                        }
                        else if (!SchemaEquivalence.AreEquivalent(resolved.Operand, candidate.Operand))
                        {
                            return ResolutionResult.UnresolvedResult(ResolutionStatus.Conflict, MetadataSource.ExternalPeResource,
                                resolved.Provenance + ";" + candidate.Provenance,
                                "Multiple supplied PE resources define different schemas for " + key + ".");
                        }
                    }
                }

                foreach (var resource in image.CompiledResources)
                {
                    IReadOnlyList<WevtTemplateProviderResult> results = resource.ReadProviders(key.ProviderGuid);

                    foreach (var result in results)
                    {
                        if (result.ProviderGuid != key.ProviderGuid)
                        {
                            continue;
                        }

                        if (result.AllEventsUnsupported)
                        {
                            ResolutionStatus status = result.Status == WevtTemplateStatus.Invalid
                                ? ResolutionStatus.Invalid
                                : ResolutionStatus.Unsupported;
                            diagnostic = ResolutionResult.UnresolvedResult(status, MetadataSource.ExternalPeResource,
                                resource.Provenance, GetEventReason(result, key));
                            continue;
                        }

                        if (result.Manifest != null)
                        {
                            var operand = EventTraceOperandBuilder.BuildManifest(result.Manifest, key, MetadataSource.ExternalPeResource, resource.Provenance);
                            if (operand != null)
                            {
                                var candidate = new ResolutionResult(operand, MetadataSource.ExternalPeResource, resource.Provenance);
                                if (resolved == null)
                                {
                                    resolved = candidate;
                                }
                                else if (!SchemaEquivalence.AreEquivalent(resolved.Operand, candidate.Operand))
                                {
                                    return ResolutionResult.UnresolvedResult(ResolutionStatus.Conflict, MetadataSource.ExternalPeResource,
                                        resolved.Provenance + ";" + candidate.Provenance,
                                        "Multiple supplied PE resources define different schemas for " + key + ".");
                                }
                            }
                        }

                        if (result.InvalidEvents.Contains(key))
                        {
                            diagnostic = ResolutionResult.UnresolvedResult(ResolutionStatus.Invalid, MetadataSource.ExternalPeResource,
                                resource.Provenance, GetEventReason(result, key));
                        }
                        else if (result.AllEventsUnsupported || result.UnsupportedEvents.Contains(key))
                        {
                            diagnostic = ResolutionResult.UnresolvedResult(ResolutionStatus.Unsupported, MetadataSource.ExternalPeResource,
                                resource.Provenance, GetEventReason(result, key));
                        }
                    }
                }
            }

            return resolved ?? diagnostic ?? ResolutionResult.Unresolved;
        }

        private sealed class LoadedPe
        {
            private readonly PeResourceData data;

            public LoadedPe(PeResourceData data)
            {
                this.data = data;
            }

            public List<XmlManifest> Manifests { get; } = new List<XmlManifest>();

            public List<CompiledResource> CompiledResources { get; } = new List<CompiledResource>();

            public void TryAddXmlManifest(PeResourceEntry resource)
            {
                try
                {
                    var manifest = XmlManifest.TryCreate(this.data, resource);
                    if (manifest != null)
                    {
                        this.Manifests.Add(manifest);
                    }
                }
                catch (InvalidDataException)
                {
                    // Malformed manifest resource: ignore it, do not fail the whole trace.
                }
                catch (XmlException)
                {
                }
            }

            public void TryAddCompiledManifest(PeResourceEntry resource)
            {
                string provenance = "pe:" + this.data.Path + ";sha256:" + this.data.Sha256
                    + ";resource:" + FormatResourceLocation(resource);
                this.CompiledResources.Add(new CompiledResource(resource.Data, provenance));
            }
        }

        private sealed class XmlManifest
        {
            private readonly instrumentationManifest value;
            private readonly string provenance;
            private readonly HashSet<Guid> providerGuids = new HashSet<Guid>();

            private XmlManifest(instrumentationManifest value, string provenance)
            {
                this.value = value;
                this.provenance = provenance;
            }

            public static XmlManifest TryCreate(PeResourceData data, PeResourceEntry resource)
            {
                using (var stream = new MemoryStream(resource.Data))
                {
                    var settings = new XmlReaderSettings
                    {
                        DtdProcessing = DtdProcessing.Prohibit,
                        XmlResolver = null,
                    };

                    using (var reader = XmlReader.Create(stream, settings))
                    {
                        if (!reader.ReadToFollowing("instrumentationManifest"))
                        {
                            return null;
                        }

                        var serializer = new instrumentationManifestSerializer();
                        var manifest = (instrumentationManifest)serializer.Deserialize(reader);
                        if (manifest == null)
                        {
                            return null;
                        }

                        string provenance = "pe:" + data.Path + ";sha256:" + data.Sha256
                            + ";resource:" + FormatResourceLocation(resource);
                        return new XmlManifest(manifest, provenance);
                    }
                }
            }

            public string Provenance() => this.provenance;

            public instrumentationManifest Value => this.value;

            public bool ContainsProvider(Guid providerGuid)
            {
                if (this.providerGuids.Count == 0)
                {
                    this.CollectProviders();
                }

                return this.providerGuids.Contains(providerGuid);
            }

            private void CollectProviders()
            {
                foreach (var item in this.value.Items)
                {
                    var instrumentationType = item as InstrumentationType;
                    if (instrumentationType == null)
                    {
                        continue;
                    }

                    foreach (var typeItem in instrumentationType.Items)
                    {
                        var events = typeItem as EventsType;
                        if (events == null)
                        {
                            continue;
                        }

                        foreach (var eventsItem in events.Items)
                        {
                            var provider = eventsItem as ProviderType;
                            if (provider == null || string.IsNullOrEmpty(provider.guid))
                            {
                                continue;
                            }

                            try
                            {
                                this.providerGuids.Add(new Guid(provider.guid));
                            }
                            catch (FormatException)
                            {
                            }
                        }
                    }
                }
            }
        }

        private sealed class CompiledResource
        {
            private readonly byte[] data;
            private readonly IReadOnlyList<WevtTemplateProviderResult> allProviders;
            private readonly string loadError;
            private readonly WevtTemplateStatus loadStatus;
            private readonly bool standalone;

            public CompiledResource(byte[] data, string provenance)
            {
                this.data = data;
                this.Provenance = provenance;
                uint signature = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0, 4));
                if (signature == 0x54564557) // WEVT
                {
                    this.standalone = true;
                    this.loadStatus = WevtTemplateStatus.Unsupported;
                    this.loadError = "Standalone WEVT has no CRIM provider GUID binding; it is not associated with an ETL provider.";
                }
                else
                {
                    try
                    {
                        this.allProviders = WevtTemplateReader.ReadProviders(data);
                    }
                    catch (NotSupportedException ex)
                    {
                        this.loadStatus = WevtTemplateStatus.Unsupported;
                        this.loadError = ex.Message;
                    }
                    catch (InvalidDataException ex)
                    {
                        this.loadStatus = WevtTemplateStatus.Invalid;
                        this.loadError = ex.Message;
                    }
                }
            }

            public string Provenance { get; }

            public bool HasUnsupportedManifest => this.loadError != null || this.allProviders != null
                && this.allProviders.Any(provider => provider.Status != WevtTemplateStatus.Supported);

            public IReadOnlyList<WevtTemplateProviderResult> ReadProviders(Guid providerGuid)
            {
                if (this.loadError != null)
                {
                    return new[] { new WevtTemplateProviderResult(providerGuid, null, this.loadStatus,
                        new[] { this.loadError }, allEventsUnsupported: true) };
                }

                if (this.standalone)
                {
                    return new[] { new WevtTemplateProviderResult(providerGuid, null, WevtTemplateStatus.Unsupported,
                        new[] { this.loadError }, allEventsUnsupported: true) };
                }

                return this.allProviders ?? Array.Empty<WevtTemplateProviderResult>();
            }
        }


        private static string FormatResourceLocation(PeResourceEntry resource)
        {
            string type = string.IsNullOrEmpty(resource.TypeName)
                ? resource.TypeId.ToString(System.Globalization.CultureInfo.InvariantCulture)
                : resource.TypeId.ToString(System.Globalization.CultureInfo.InvariantCulture) + " (" + resource.TypeName + ")";
            return type + "/" + resource.Name + "/" + resource.Language;
        }

        private static string GetEventReason(WevtTemplateProviderResult result, EventKey key)
        {
            string prefix = "Event " + key.EventId.ToString(System.Globalization.CultureInfo.InvariantCulture)
                + ":" + key.Version.ToString(System.Globalization.CultureInfo.InvariantCulture) + ": ";
            foreach (string reason in result.Reasons)
            {
                if (reason.StartsWith(prefix, StringComparison.Ordinal))
                {
                    return reason.Substring(prefix.Length);
                }
            }

            return result.Reasons.Count > 0 ? string.Join("; ", result.Reasons) : "The compiled manifest does not provide a supported schema for this event.";
        }
    }
}
