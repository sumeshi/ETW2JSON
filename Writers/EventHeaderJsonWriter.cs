namespace ETW2JSON
{
    using System.Text.Json;
    using ETWDeserializer;

    /// <summary>Preserves the original record identity separately from schema or custom-parser identity.</summary>
    internal static class EventHeaderJsonWriter
    {
        public static void Write(Utf8JsonWriter writer, RuntimeEventMetadata runtimeMetadata)
        {
            writer.WritePropertyName("event_header");
            writer.WriteStartObject();
            writer.WriteString("provider_guid", runtimeMetadata.ProviderId.ToString("D"));
            writer.WriteNumber("event_id", runtimeMetadata.EventId);
            writer.WriteNumber("version", runtimeMetadata.Version);
            writer.WriteNumber("flags", runtimeMetadata.Flags);
            writer.WriteNumber("channel", runtimeMetadata.Channel);
            writer.WriteNumber("level", runtimeMetadata.Level);
            writer.WriteNumber("opcode", runtimeMetadata.Opcode);
            writer.WriteNumber("task", runtimeMetadata.Task);
            writer.WriteNumber("keyword", runtimeMetadata.Keyword);
            writer.WriteEndObject();
        }
    }
}
