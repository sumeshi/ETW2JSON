namespace ETW2JSON.Tests
{
    using System;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Text;
    using ETW2JSON.IO;
    using Xunit;

    public sealed class OutputFileTests
    {
        [Fact]
        [Trait("Task", "T27")]
        public void ExistingInputOrAliasIsNeverTruncated()
        {
            string directory = Path.Combine(Path.GetTempPath(), "etw2json-output-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            string input = Path.Combine(directory, "evidence.etl");
            string alias = Path.Combine(directory, "evidence-alias.etl");
            byte[] contents = Encoding.UTF8.GetBytes("evidence bytes");
            File.WriteAllBytes(input, contents);
            try
            {
                Assert.Throws<IOException>(() => OutputFile.OpenNew(input));
                Assert.Equal(contents, File.ReadAllBytes(input));
                Assert.True(TryCreateHardLink(alias, input), "The temporary filesystem must support hardlinks for this alias safety test.");
                Assert.Throws<IOException>(() => OutputFile.OpenNew(alias));
                Assert.Equal(contents, File.ReadAllBytes(input));
                Assert.Equal(contents, File.ReadAllBytes(alias));
            }
            finally
            {
                Directory.Delete(directory, recursive: true);
            }
        }

        private static bool TryCreateHardLink(string alias, string input)
        {
            if (OperatingSystem.IsWindows())
            {
                return CreateHardLinkWindows(alias, input, IntPtr.Zero);
            }

            return CreateHardLinkUnix(input, alias) == 0;
        }

        [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateHardLinkWindows(string fileName, string existingFileName, IntPtr securityAttributes);

        [DllImport("libc", EntryPoint = "link", SetLastError = true)]
        private static extern int CreateHardLinkUnix(string existingFileName, string fileName);
    }
}
