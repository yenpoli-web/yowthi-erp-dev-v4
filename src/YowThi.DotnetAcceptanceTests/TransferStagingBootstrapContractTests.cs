using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class TransferStagingBootstrapContractTests
{
    [Fact]
    public void AgentStartup_InitializesFixedTransferQueuesBeforeWebHostStarts()
    {
        var program = ReadProjectSource("YowThi.DevelopmentAgent3", "Program.cs");

        var bootstrapIndex = program.IndexOf("TransferStagingBootstrap.EnsureExists();", StringComparison.Ordinal);
        var builderIndex = program.IndexOf("var builder = WebApplication.CreateBuilder(args);", StringComparison.Ordinal);

        Assert.True(bootstrapIndex >= 0, "Program.cs must initialize the fixed transfer staging queues.");
        Assert.True(builderIndex > bootstrapIndex, "Transfer staging initialization must occur before the web host starts.");
    }

    [Fact]
    public void TransferStagingBootstrap_UsesOnlyFixedNativeDirectoryInitialization()
    {
        var source = ReadProjectSource("YowThi.DevelopmentAgent3", Path.Combine("Transfer", "TransferStagingBootstrap.cs"));

        Assert.Contains(@"C:\Dev\YowThi-ERP-Dev-v4\staging\transfer", source, StringComparison.Ordinal);
        Assert.Contains(@"C:\Dev\YowThi-ERP-Dev-v4\staging\transfer\inbox", source, StringComparison.Ordinal);
        Assert.Contains(@"C:\Dev\YowThi-ERP-Dev-v4\staging\transfer\outbox", source, StringComparison.Ordinal);
        Assert.Contains("Directory.CreateDirectory(full)", source, StringComparison.Ordinal);
        Assert.Contains("FileAttributes.ReparsePoint", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Process.Start", source, StringComparison.Ordinal);
        Assert.DoesNotContain("powershell", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("cmd.exe", source, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TransferList_RemainsReadOnlyAndDoesNotCreateQueuesOnDemand()
    {
        var source = ReadProjectSource("YowThi.DevelopmentAgent3", Path.Combine("Transfer", "TransferTools.cs"));

        Assert.Contains("TransferInboxList() => ListStaging", source, StringComparison.Ordinal);
        Assert.Contains("TransferOutboxList() => ListStaging", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Directory.CreateDirectory", source, StringComparison.Ordinal);
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
