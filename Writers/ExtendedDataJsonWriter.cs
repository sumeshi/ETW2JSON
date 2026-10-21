namespace ETW2JSON
{
    using System.Text.Json;
    using ETWDeserializer;

    internal static class ExtendedDataJsonWriter
    {
        public static void Write(Utf8JsonWriter writer, RuntimeEventMetadata runtimeMetadata)
        {
            writer.WritePropertyName("raw_extended_data");
            writer.WriteStartArray();
            foreach (ExtendedEventData item in runtimeMetadata.GetRawExtendedData())
            {
                writer.WriteStartObject();
                writer.WriteNumber("ext_type", item.ExtType);
                writer.WriteNumber("reserved1", item.Reserved1);
                writer.WriteNumber("flags", item.Flags);
                writer.WriteBoolean("linkage", item.Linkage);
                writer.WriteNumber("data_size", item.DataSize);
                if (item.RawDataAvailable)
                {
                    writer.WriteBase64String("raw_data", item.GetRawData());
                }
                else
                {
                    writer.WriteNull("raw_data");
                }
                if (item.Error != null) writer.WriteString("data_error", item.Error);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();

            string[] errors = runtimeMetadata.GetExtendedDataErrors();
            if (errors.Length > 0)
            {
                writer.WritePropertyName("extended_data_errors");
                writer.WriteStartArray();
                foreach (string error in errors) writer.WriteStringValue(error);
                writer.WriteEndArray();
            }
        }
    }
}
