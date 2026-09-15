using Xunit;
using YowThi.DevelopmentAgent3.Inspection;

namespace YowThi.DotnetAcceptanceTests;

public sealed class TransferStagingRecoveryAcceptanceContractTests
{
    [Fact]
    public void BootRecoveryStatus_VerifiesFixedTransferStagingQueuesWithoutRepairingThem()
    {
        var source = ReadProjectSource("YowThi.DevelopmentAgent3", Path.Combine("Inspection", "V4BootRecoveryStatusTools.cs"));

        Assert.Contains(@"C:\Dev\YowThi-ERP-Dev-v4\staging\transfer", source, StringComparison.Ordinal);
        Assert.Contains(@"C:\Dev\YowThi-ERP-Dev-v4\staging\transfer\inbox", source, StringComparison.Ordinal);
        Assert.Contains(@"C:\Dev\YowThi-ERP-Dev-v4\staging\transfer\outbox", source, StringComparison.Ordinal);
        Assert.Contains("var transferStaging = ReadTransferStagingStatus(failures);", source, StringComparison.Ordinal);
        Assert.Contains("Directory.Exists(full)", source, StringComparison.Ordinal);
        Assert.Contains("FileAttributes.ReparsePoint", source, StringComparison.Ordinal);
        Assert.Contains("TransferStagingStatus TransferStaging", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Directory.CreateDirectory", source, StringComparison.Ordinal);
    }

    [Fact]
    public void BootRecoveryResult_ExposesTypedTransferStagingState()
    {
        var property = typeof(V4BootRecoveryStatusResult).GetProperty(nameof(V4BootRecoveryStatusResult.TransferStaging));

        Assert.NotNull(property);
        Assert.Equal(typeof(V4BootRecoveryStatusTools.TransferStagingStatus), property.PropertyType);
    }

    [Fact]
    public void TransferBootstrap_RemainsTheOnlyQueueCreationOwner()
    {
        var bootstrap = ReadProjectSource("YowThi.DevelopmentAgent3", Path.Combine("Transfer", "TransferStagingBootstrap.cs"));
        var recovery = ReadProjectSource("YowThi.DevelopmentAgent3", Path.Combine("Inspection", "V4BootRecoveryStatusTools.cs"));

        Assert.Contains("Directory.CreateDirectory(full)", bootstrap, StringComparison.Ordinal);
        Assert.DoesNotContain("Directory.CreateDirectory", recovery, StringComparison.Ordinal);
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
