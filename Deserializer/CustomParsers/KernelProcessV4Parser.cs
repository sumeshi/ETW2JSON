namespace ETWDeserializer.CustomParsers
{
    /// <summary>Process v4 MOF layout; raw paths and command lines are not normalized.</summary>
    internal sealed class KernelProcessV4Parser
    {
        private static readonly PropertyMetadata[] Properties =
        {
            CustomParserMetadata.Property("UniqueProcessKey", TDH_IN_TYPE.TDH_INTYPE_POINTER),
            CustomParserMetadata.Property("ProcessId", TDH_IN_TYPE.TDH_INTYPE_UINT32),
            CustomParserMetadata.Property("ParentId", TDH_IN_TYPE.TDH_INTYPE_UINT32),
            CustomParserMetadata.Property("SessionId", TDH_IN_TYPE.TDH_INTYPE_UINT32),
            CustomParserMetadata.Property("ExitStatus", TDH_IN_TYPE.TDH_INTYPE_UINT32),
            CustomParserMetadata.Property("DirectoryTableBase", TDH_IN_TYPE.TDH_INTYPE_POINTER),
            CustomParserMetadata.Property("Flags", TDH_IN_TYPE.TDH_INTYPE_UINT32),
            CustomParserMetadata.Property("UserSID", TDH_IN_TYPE.TDH_INTYPE_SID),
            CustomParserMetadata.Property("ImageFileName", TDH_IN_TYPE.TDH_INTYPE_ANSISTRING),
            CustomParserMetadata.Property("CommandLine", TDH_IN_TYPE.TDH_INTYPE_UNICODESTRING),
            CustomParserMetadata.Property("PackageFullName", TDH_IN_TYPE.TDH_INTYPE_UNICODESTRING),
            CustomParserMetadata.Property("ApplicationId", TDH_IN_TYPE.TDH_INTYPE_UNICODESTRING),
        };

        public KernelProcessV4Parser(byte opcode)
        {
            string action = opcode switch { 1 => "Start", 2 => "Stop", 3 => "DCStart", 4 => "DCStop", _ => throw new System.ArgumentOutOfRangeException(nameof(opcode)) };
            this.SchemaMetadata = CustomParserMetadata.Create(CustomParserGuids.KernelProcessGuid, 0, "Kernel/Process/" + action,
                Properties, "process-v4:pointer,4*uint32,pointer,uint32,wbem-sid,utf8z,3*utf16z");
        }

        public EventMetadata SchemaMetadata { get; }

        public static bool Supports(byte version, byte opcode) => version == 4 && opcode is 1 or 2 or 3 or 4;

        public void Parse<T>(EventRecordReader reader, T writer, EventMetadata[] metadataArray, RuntimeEventMetadata runtime) where T : IEtwWriter
        {
            int width = CustomParserMetadata.PointerSize(runtime);
            var output = new BuiltinEventWriter<T>(writer, this.SchemaMetadata, runtime);
            output.Pointer(reader.ReadPointer());
            output.UInt32(reader.ReadUInt32());
            output.UInt32(reader.ReadUInt32());
            output.UInt32(reader.ReadUInt32());
            output.UInt32(reader.ReadUInt32());
            output.Pointer(reader.ReadPointer());
            output.UInt32(reader.ReadUInt32());
            output.Sid(CustomParserMetadata.ReadWbemSid(reader, width));
            output.Utf8(CustomParserMetadata.ReadUtf8String(reader));
            output.Unicode(reader.ReadUnicodeString());
            output.Unicode(reader.ReadUnicodeString());
            output.Unicode(reader.ReadUnicodeString());
            output.Complete(reader);
        }
    }
}
