namespace ETWDeserializer.CustomParsers
{
    using System;

    /// <summary>Writes fixed kernel schemas while keeping raw fallback atomic.</summary>
    internal struct BuiltinEventWriter<T> where T : IEtwWriter
    {
        private readonly T writer;
        private readonly EventMetadata metadata;
        private int propertyIndex;

        public BuiltinEventWriter(T writer, EventMetadata template, RuntimeEventMetadata runtime)
        {
            this.writer = writer;
            this.metadata = CustomParserMetadata.Bind(template, runtime);
            this.propertyIndex = 0;
            this.writer.WriteEventBegin(this.metadata, runtime);
        }

        public void Pointer(ulong value)
        {
            this.BeginProperty(); this.writer.WritePointer(value); this.writer.WritePropertyEnd();
        }

        public void UInt32(uint value)
        {
            this.BeginProperty(); this.writer.WriteUInt32(value); this.writer.WritePropertyEnd();
        }

        public void Unicode(string value)
        {
            this.BeginProperty(); this.writer.WriteUnicodeString(value); this.writer.WritePropertyEnd();
        }

        public void Utf8(string value)
        {
            this.BeginProperty(); this.writer.WriteAnsiString(value); this.writer.WritePropertyEnd();
        }

        public void Sid(string value)
        {
            this.BeginProperty(); this.writer.WriteSid(value); this.writer.WritePropertyEnd();
        }

        public void Complete(EventRecordReader reader)
        {
            if (this.propertyIndex != this.metadata.Properties.Length) throw new InvalidOperationException("The built-in event schema has unassigned properties.");
            reader.EnsurePayloadConsumed();
            this.writer.WriteEventEnd();
        }

        private void BeginProperty() => this.writer.WritePropertyBegin(this.metadata.Properties[this.propertyIndex++]);
    }
}
