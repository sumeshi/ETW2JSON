namespace ETW2JSON.TestFixtures
{
    using System;
    using System.Buffers.Binary;
    using System.Text;

    /// <summary>Builds a minimal inert PE resource containing a synthetic CRIM 5.1 provider.</summary>
    public static class SyntheticProviderPeBuilder
    {
        public static readonly Guid ProviderGuid = Guid.Parse("9ab0e68d-70c1-4e5a-938c-1390a31a0002");

        public static byte[] Build(string firstPropertyName = "sequence")
        {
            byte[] compiled = BuildCompiledManifest(firstPropertyName);
            return BuildPe(compiled);
        }

        public static byte[] BuildStandaloneWevtResourcePe()
        {
            byte[] compiled = BuildCompiledManifest("sequence");
            WriteUInt32(compiled, 0, 0x54564557); // WEVT without CRIM GUID binding
            return BuildPe(compiled);
        }

        private static byte[] BuildPe(byte[] compiled)
        {
            const int ResourceTreeSize = 88;
            int resourceSize = ResourceTreeSize + compiled.Length;
            int rawSize = Align(resourceSize, 0x200);
            const int RawPointer = 0x200;
            int fileSize = RawPointer + rawSize;
            byte[] pe = new byte[fileSize];

            WriteUInt16(pe, 0, 0x5a4d); // MZ
            WriteUInt32(pe, 0x3c, 0x80);
            WriteUInt32(pe, 0x80, 0x00004550); // PE\0\0
            int coff = 0x84;
            WriteUInt16(pe, coff, 0x014c); // IMAGE_FILE_MACHINE_I386
            WriteUInt16(pe, coff + 2, 1);
            WriteUInt16(pe, coff + 16, 224);
            WriteUInt16(pe, coff + 18, 0x2102);

            int optional = coff + 20;
            WriteUInt16(pe, optional, 0x010b); // PE32
            WriteUInt32(pe, optional + 28, 0x10000000);
            WriteUInt32(pe, optional + 32, 0x1000);
            WriteUInt32(pe, optional + 36, 0x200);
            WriteUInt32(pe, optional + 56, 0x2000);
            WriteUInt32(pe, optional + 60, 0x200);
            WriteUInt16(pe, optional + 68, 3);
            WriteUInt32(pe, optional + 92, 16);
            WriteUInt32(pe, optional + 96 + (2 * 8), 0x1000);
            WriteUInt32(pe, optional + 96 + (2 * 8) + 4, (uint)resourceSize);

            int section = optional + 224;
            Encoding.ASCII.GetBytes(".rsrc").CopyTo(pe, section);
            WriteUInt32(pe, section + 8, (uint)resourceSize);
            WriteUInt32(pe, section + 12, 0x1000);
            WriteUInt32(pe, section + 16, (uint)rawSize);
            WriteUInt32(pe, section + 20, RawPointer);
            WriteUInt32(pe, section + 36, 0x40000040);

            // Three levels: type ID 0, resource name ID 1, language 0x0409.
            int resource = RawPointer;
            WriteUInt16(pe, resource + 14, 1);
            WriteUInt32(pe, resource + 16, 0);
            WriteUInt32(pe, resource + 20, 0x80000000 | 24);
            WriteUInt16(pe, resource + 24 + 14, 1);
            WriteUInt32(pe, resource + 24 + 16, 1);
            WriteUInt32(pe, resource + 24 + 20, 0x80000000 | 48);
            WriteUInt16(pe, resource + 48 + 14, 1);
            WriteUInt32(pe, resource + 48 + 16, 0x0409);
            WriteUInt32(pe, resource + 48 + 20, 72);
            WriteUInt32(pe, resource + 72, 0x1000 + ResourceTreeSize);
            WriteUInt32(pe, resource + 76, (uint)compiled.Length);
            Array.Copy(compiled, 0, pe, resource + ResourceTreeSize, compiled.Length);
            return pe;
        }

        private static byte[] BuildCompiledManifest(string firstPropertyName)
        {
            const int ProviderOffset = 36;
            const int WevtSize = 28;
            const int EventOffset = ProviderOffset + WevtSize;
            const int EventSize = 92;
            const int TemplateOffset = EventOffset + EventSize;
            const int TemplateItemsOffset = TemplateOffset + 40;
            const int NamesOffset = TemplateItemsOffset + (3 * 20);

            var names = new[] { BuildName(firstPropertyName), BuildName("message"), BuildName("correlation") };
            int blobSize = NamesOffset;
            foreach (byte[] name in names) blobSize += name.Length;
            byte[] data = new byte[blobSize];

            WriteUInt32(data, 0, 0x4d495243); // CRIM
            WriteUInt32(data, 4, (uint)blobSize);
            WriteUInt16(data, 8, 5);
            WriteUInt16(data, 10, 1);
            WriteUInt32(data, 12, 1);
            Array.Copy(ProviderGuid.ToByteArray(), 0, data, 16, 16);
            WriteUInt32(data, 32, ProviderOffset);

            WriteUInt32(data, ProviderOffset, 0x54564557); // WEVT
            WriteUInt32(data, ProviderOffset + 4, WevtSize);
            WriteUInt32(data, ProviderOffset + 8, uint.MaxValue);
            WriteUInt32(data, ProviderOffset + 12, 1);
            WriteUInt32(data, ProviderOffset + 20, EventOffset);

            WriteUInt32(data, EventOffset, 0x544e5645); // EVNT
            WriteUInt32(data, EventOffset + 4, EventSize);
            WriteUInt32(data, EventOffset + 8, 1);
            WriteUInt16(data, EventOffset + 16, 1);
            data[EventOffset + 18] = 1;
            WriteUInt32(data, EventOffset + 36, TemplateOffset);

            WriteUInt32(data, TemplateOffset, 0x504d4554); // TEMP
            WriteUInt32(data, TemplateOffset + 4, 40);
            WriteUInt32(data, TemplateOffset + 8, 3);
            WriteUInt32(data, TemplateOffset + 12, 3);
            WriteUInt32(data, TemplateOffset + 16, TemplateItemsOffset);
            WriteUInt32(data, TemplateOffset + 20, 1); // EventData

            byte[] inTypes = { 0x07, 0x01, 0x0f }; // Int32, UnicodeString, GUID
            uint nameOffset = NamesOffset;
            for (int i = 0; i < inTypes.Length; i++)
            {
                int descriptor = TemplateItemsOffset + (i * 20);
                data[descriptor + 4] = inTypes[i];
                WriteUInt32(data, descriptor + 16, nameOffset);
                Array.Copy(names[i], 0, data, nameOffset, names[i].Length);
                nameOffset += (uint)names[i].Length;
            }

            return data;
        }

        private static byte[] BuildName(string value)
        {
            byte[] text = Encoding.Unicode.GetBytes(value + "\0");
            byte[] result = new byte[text.Length + 4];
            WriteUInt32(result, 0, (uint)result.Length);
            Array.Copy(text, 0, result, 4, text.Length);
            return result;
        }

        private static int Align(int value, int alignment) => (value + alignment - 1) & ~(alignment - 1);

        private static void WriteUInt16(byte[] data, int offset, ushort value) =>
            BinaryPrimitives.WriteUInt16LittleEndian(new Span<byte>(data, offset, 2), value);

        private static void WriteUInt32(byte[] data, int offset, uint value) =>
            BinaryPrimitives.WriteUInt32LittleEndian(new Span<byte>(data, offset, 4), value);
    }
}
