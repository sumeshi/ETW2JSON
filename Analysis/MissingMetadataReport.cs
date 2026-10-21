namespace ETW2JSON.Analysis
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Globalization;
    using System.Text.Json;
    using ETWDeserializer;

    /// <summary>
    /// Reports provider / event id / version tuples whose metadata could not be
    /// resolved, so a silent "UnknownProvider" success is impossible.
    /// </summary>
    public static class MissingMetadataReport
    {
        private const string PublisherKey = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\";

        public static void WriteText(TextWriter writer, IEnumerable<ScanEntry> entries)
        {
            WriteText(writer, entries, null);
        }

        public static void WriteText(TextWriter writer, IEnumerable<ScanEntry> entries, ExportedProviderResolver providerInfo)
        {
            foreach (var entry in entries)
            {
                if (entry.MetadataStatus == "Resolved")
                {
                    continue;
                }

                writer.WriteLine("GUID: {" + entry.Key.ProviderGuid.ToString("D") + "}");
                writer.WriteLine("Provider: " + (GetProviderName(entry, providerInfo) ?? "{unknown}"));
                writer.WriteLine("Event ID: " + entry.Key.EventId);
                writer.WriteLine("Version: " + entry.Key.Version);
                if (entry.Key.ClassicOpcode.HasValue) writer.WriteLine("Classic/MOF opcode: " + entry.Key.ClassicOpcode.Value);
                writer.WriteLine("Count: " + entry.Count);
                writer.WriteLine("Metadata resolution: " + entry.MetadataStatus);
                writer.WriteLine("Reason: " + (entry.Reason ?? "No usable schema was resolved from the ETL or supplied metadata."));
                if (entry.Key.ClassicOpcode.HasValue)
                {
                    writer.WriteLine("Collection guidance: " + ClassicGuidance);
                }
                else WriteCollectionGuidance(writer, entry.Key.ProviderGuid, providerInfo);
                writer.WriteLine();
            }
        }

        public static void WriteJson(Stream stream, IEnumerable<ScanEntry> entries)
        {
            WriteJson(stream, entries, null);
        }

        public static void WriteJson(Stream stream, IEnumerable<ScanEntry> entries, ExportedProviderResolver providerInfo)
        {
            using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
            {
                writer.WriteStartObject();
                writer.WritePropertyName("Missing");
                writer.WriteStartArray();
                foreach (var entry in entries)
                {
                    if (entry.MetadataStatus == "Resolved")
                    {
                        continue;
                    }

                    writer.WriteStartObject();
                    writer.WriteString("provider_guid", entry.Key.ProviderGuid.ToString("D"));
                    writer.WriteString("provider_name", GetProviderName(entry, providerInfo));
                    writer.WriteNumber("event_id", entry.Key.EventId);
                    writer.WriteNumber("version", entry.Key.Version);
                    if (entry.Key.ClassicOpcode.HasValue) writer.WriteNumber("classic_opcode", entry.Key.ClassicOpcode.Value);
                    writer.WriteNumber("count", entry.Count);
                    writer.WriteString("metadata_status", entry.MetadataStatus);
                    if (!string.IsNullOrEmpty(entry.Reason))
                    {
                        writer.WriteString("metadata_reason", entry.Reason);
                    }
                    writer.WriteString("registry_key_candidate", entry.Key.ClassicOpcode.HasValue ? null : GetPublisherKey(entry.Key.ProviderGuid));
                    writer.WritePropertyName("registry_values_to_check");
                    writer.WriteStartArray();
                    if (!entry.Key.ClassicOpcode.HasValue)
                    {
                        writer.WriteStringValue("ResourceFileName");
                        writer.WriteStringValue("MessageFileName");
                        writer.WriteStringValue("ParameterFileName");
                    }
                    writer.WriteEndArray();
                    writer.WriteString("guidance", entry.Key.ClassicOpcode.HasValue ? ClassicGuidance : "On the evidence Windows host, inspect the listed publisher values, copy referenced provider binaries from the evidence, and pass them with --resource. A path shown in registry data is only a candidate until the file is recovered and parsed.");
                    if (providerInfo != null && providerInfo.TryGetProvider(entry.Key.ProviderGuid, out ExportedProviderInfo exported))
                    {
                        writer.WritePropertyName("exported_provider_info");
                        writer.WriteStartObject();
                        writer.WriteString("name", exported.Name);
                        writer.WriteString("source_file", exported.SourcePath);
                        writer.WriteString("sha256", exported.Sha256);
                        WriteOptionalString(writer, "resource_file_name_candidate", exported.ResourceFileName);
                        WriteOptionalString(writer, "message_file_name_candidate", exported.MessageFileName);
                        WriteOptionalString(writer, "parameter_file_name_candidate", exported.ParameterFileName);
                        writer.WriteBoolean("provides_payload_schema", exported.ProvidesPayloadSchema);
                        writer.WriteEndObject();
                    }
                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
                writer.WriteEndObject();
                writer.Flush();
            }
        }

        private static void WriteCollectionGuidance(TextWriter writer, Guid providerGuid, ExportedProviderResolver providerInfo)
        {
            writer.WriteLine("Collection guidance (run on the evidence Windows host):");
            writer.WriteLine("  reg query \"" + GetPublisherKey(providerGuid) + "\" /v ResourceFileName");
            writer.WriteLine("  reg query \"" + GetPublisherKey(providerGuid) + "\" /v MessageFileName");
            writer.WriteLine("  reg query \"" + GetPublisherKey(providerGuid) + "\" /v ParameterFileName");
            writer.WriteLine("  Find the publisher name from the matching registry key or `wevtutil ep`, then run:");
            if (providerInfo != null && providerInfo.TryGetProvider(providerGuid, out ExportedProviderInfo exported))
            {
                writer.WriteLine("Exported provider information (candidate paths only; source " + exported.SourcePath + "; sha256 " + exported.Sha256 + "):");
                writer.WriteLine("  Provider: " + (exported.Name ?? "{unnamed}"));
                WriteCandidate(writer, "ResourceFileName", exported.ResourceFileName);
                WriteCandidate(writer, "MessageFileName", exported.MessageFileName);
                WriteCandidate(writer, "ParameterFileName", exported.ParameterFileName);
                writer.WriteLine("  This provider-info XML does not contain a payload schema; recover candidate PE files and pass them with --resource.");
                writer.WriteLine("  To collect again in PowerShell: wevtutil gp '<PublisherName>' /ge:true /gm:false /f:xml | Set-Content -Encoding utf8 provider.xml");
            }
            else
            {
                writer.WriteLine("  PowerShell: wevtutil gp '<PublisherName>' /ge:true /gm:false /f:xml | Set-Content -Encoding utf8 provider.xml");
                writer.WriteLine("  Then pass the captured XML with --provider-info provider.xml.");
            }

            writer.WriteLine("  Recover referenced DLL/EXE/SYS files from the evidence, then supply each with --resource.");
            writer.WriteLine("  If the original provider .man is available, supply it with --manifest. Keep unresolved events as raw/best-effort output.");
            writer.WriteLine("  Registry paths are candidates only unless an evidence hive was actually read; host registry values are never used as evidence.");
        }

        private const string ClassicGuidance = "This GUID identifies a classic/MOF event class, not a WINEVT publisher. Recover a trace containing embedded KernelTraceControl schema metadata or the matching MOF definitions from the evidence system. This tool does not import MOF files directly; retain unresolved payloads as raw data. Analysis-host metadata remains an explicit --allow-local-metadata fallback and may differ from the evidence system.";

        private static void WriteCandidate(TextWriter writer, string label, string value)
        {
            writer.WriteLine("  " + label + ": " + (string.IsNullOrWhiteSpace(value) ? "{not present in export}" : value));
        }

        private static void WriteOptionalString(Utf8JsonWriter writer, string propertyName, string value)
        {
            if (value != null)
            {
                writer.WriteString(propertyName, value);
            }
        }

        private static string GetProviderName(ScanEntry entry, ExportedProviderResolver providerInfo)
        {
            if (entry.ProviderName != null)
            {
                return entry.ProviderName;
            }

            if (providerInfo != null && providerInfo.TryGetProvider(entry.Key.ProviderGuid, out ExportedProviderInfo exported))
            {
                return exported.Name;
            }

            return null;
        }

        private static string GetPublisherKey(Guid providerGuid)
        {
            return PublisherKey + "{" + providerGuid.ToString("D", CultureInfo.InvariantCulture) + "}";
        }
    }
}
