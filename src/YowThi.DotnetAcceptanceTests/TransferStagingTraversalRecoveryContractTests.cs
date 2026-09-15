using Xunit;
using YowThi.DevelopmentAgent3.Inspection;

namespace YowThi.DotnetAcceptanceTests;

public sealed class TransferStagingTraversalRecoveryContractTests
{
    [Fact]
    public void BootRecoveryStatus_ValidatesFullTransferAncestorTraversal()
    {
        var source = ReadProjectSource("YowThi.DevelopmentAgent3", Path.Combine("Inspection", "V4BootRecoveryStatusTools.cs"));

        Assert.Contains("private const string DevRoot", source, StringComparison.Ordinal);
        Assert.Contains("while (current is not null)", source, StringComparison.Ordinal);
        Assert.Contains("current.Attributes & FileAttributes.ReparsePoint", source, StringComparison.Ordinal);
        Assert.Contains("current.FullName.TrimEnd", source, StringComparison.Ordinal);
        Assert.Contains("unsafePath = current.FullName;", source, StringComparison.Ordinal);
        Assert.Contains("traverses a reparse point or escapes the fixed development root", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Directory.CreateDirectory", source, StringComparison.Ordinal);
    }

    [Fact]
    public void TransferDirectoryStatus_ExposesTraversalSafety()
    {
        var property = typeof(V4BootRecoveryStatusTools.TransferDirectoryStatus)
            .GetProperty(nameof(V4BootRecoveryStatusTools.TransferDirectoryStatus.TraversalSafe));

        Assert.NotNull(property);
        Assert.Equal(typeof(bool), property.PropertyType);
    }

    private static string ReadProjectSource(string projectName, string relativePath)
    {
        var path = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..",
            projectName,
            relativePath));
        Assert.True(File.Exists(path), $"Source file was not found: {path}");
        return File.ReadAllText(path);
    }
}
