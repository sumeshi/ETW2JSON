namespace ETW2JSON.Tests
{
    using System.IO;
    using ETW2JSON;
    using Xunit;

    public class CliParsingTests
    {
        [Fact]
        [Trait("Task", "T23")]
        public void ParsesSpaceSeparatedOutputAndFormat()
        {
            var options = CliOptions.Parse(new[] { "trace.etl", "--output", "out.jsonl", "--format", "json" }, TextWriter.Null);
            Assert.NotNull(options);
            Assert.Single(options.Inputs);
            Assert.Equal("out.jsonl", options.Output);
        }

        [Fact]
        [Trait("Task", "T23")]
        public void ParsesRepeatedManifestAndResource()
        {
            var options = CliOptions.Parse(
                new[] { "trace.etl", "--manifest", "a.man", "--manifest=b.man", "--resource", "p.dll" },
                TextWriter.Null);
            Assert.NotNull(options);
            Assert.Equal(2, options.Manifests.Count);
            Assert.Single(options.Resources);
        }

        [Fact]
        [Trait("Task", "T23")]
        public void ParsesRepeatedProviderInfoExports()
        {
            var options = CliOptions.Parse(
                new[] { "trace.etl", "--provider-info", "a.xml", "--provider-info=b.xml" },
                TextWriter.Null);
            Assert.NotNull(options);
            Assert.Equal(new[] { "a.xml", "b.xml" }, options.ProviderInfos);
        }

        [Fact]
        [Trait("Task", "T23")]
        public void LocalProviderMetadataIsDisabledByDefault()
        {
            var options = CliOptions.Parse(new[] { "trace.etl" }, TextWriter.Null);
            Assert.NotNull(options);
            Assert.False(options.AllowLocalMetadata);
        }

        [Theory]
        [Trait("Task", "T23")]
        [InlineData("--allow-local-metadata")]
        [InlineData("--allow-local-metadata=true")]
        public void ParsesLocalProviderMetadataOptIn(string option)
        {
            var options = CliOptions.Parse(new[] { "trace.etl", option }, TextWriter.Null);
            Assert.NotNull(options);
            Assert.True(options.AllowLocalMetadata);
        }

        [Fact]
        [Trait("Task", "T23")]
        public void ParsesSpaceSeparatedLocalProviderMetadataBoolean()
        {
            var options = CliOptions.Parse(new[] { "trace.etl", "--allow-local-metadata", "true" }, TextWriter.Null);
            Assert.NotNull(options);
            Assert.True(options.AllowLocalMetadata);
        }

        [Fact]
        [Trait("Task", "T23")]
        public void ParsesExplicitLocalProviderMetadataOptOut()
        {
            var options = CliOptions.Parse(new[] { "trace.etl", "--allow-local-metadata=false" }, TextWriter.Null);
            Assert.NotNull(options);
            Assert.False(options.AllowLocalMetadata);
        }

        [Theory]
        [Trait("Task", "T23")]
        [InlineData("--allow-local-metadata=maybe")]
        public void RejectsNonsensicalLocalProviderMetadataValue(string option)
        {
            Assert.Null(CliOptions.Parse(new[] { "trace.etl", option }, TextWriter.Null));
        }

        [Fact]
        [Trait("Task", "T23")]
        public void RejectsUnknownOption()
        {
            var options = CliOptions.Parse(new[] { "trace.etl", "--bogus" }, TextWriter.Null);
            Assert.Null(options);
        }

        [Fact]
        [Trait("Task", "T24")]
        public void ScanAndReportCannotCombine()
        {
            var options = CliOptions.Parse(new[] { "trace.etl", "--scan", "--report-missing" }, TextWriter.Null);
            Assert.Null(options);
        }

        [Theory]
        [Trait("Task", "T23")]
        [InlineData("--output")]
        [InlineData("--format")]
        [InlineData("--manifest")]
        [InlineData("--resource")]
        [InlineData("--provider-info")]
        public void RejectsMissingValueInsteadOfConsumingFollowingOption(string option)
        {
            var options = CliOptions.Parse(new[] { "trace.etl", option, "--scan" }, TextWriter.Null);
            Assert.Null(options);
        }
    }
}
