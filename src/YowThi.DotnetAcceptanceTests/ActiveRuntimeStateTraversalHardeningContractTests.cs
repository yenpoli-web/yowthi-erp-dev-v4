using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class ActiveRuntimeStateTraversalHardeningContractTests
{
    [Fact]
    public void SupervisorPathSafety_RejectsReparseAncestorsAndRequiresBoundaryReachability()
    {
        var source = ReadProjectSource("YowThi.RuntimeSupervisor", "RuntimeSupervisorPathSafety.cs");
        Assert.Contains("RequireSafeDirectoryTraversal", source, StringComparison.Ordinal);
        Assert.Contains("FileAttributes.ReparsePoint", source, StringComparison.Ordinal);
        Assert.Contains("Fixed directory traversal did not reach its boundary", source, StringComparison.Ordinal);
        Assert.Contains("RejectReparseIfExists", source, StringComparison.Ordinal);
    }

    [Fact]
    public void RuntimeSupervisorWorker_GuardsActiveStateReadAndWritePaths()
    {
        var source = ReadProjectSource("YowThi.RuntimeSupervisor", "RuntimeSupervisorWorker.cs");
        Assert.Contains("HandoffRoot", source, StringComparison.Ordinal);
        Assert.Contains("RequireSafeDirectoryTraversal(HandoffRoot, DevRoot)", source, StringComparison.Ordinal);
        Assert.Contains("RejectReparseIfExists(ActiveStatePath)", source, StringComparison.Ordinal);
        Assert.Contains("RejectReparseIfExists(temp)", source, StringComparison.Ordinal);
    }

    [Fact]
    public void CompatibilityWorker_GuardsQueuesAndActiveStateBeforeUse()
    {
        var source = ReadProjectSource("YowThi.RuntimeSupervisor", "RuntimeHandoffActivationWorker.cs");
        Assert.Contains("RequireSafeDirectoryTraversal(HandoffRoot, DevRoot)", source, StringComparison.Ordinal);
        Assert.Contains("RequireSafeDirectoryTraversal(PendingRoot, HandoffRoot)", source, StringComparison.Ordinal);
        Assert.Contains("RequireSafeDirectoryTraversal(ReadyRoot, HandoffRoot)", source, StringComparison.Ordinal);
        Assert.Contains("RejectReparseIfExists(ActiveStatePath)", source, StringComparison.Ordinal);
    }

    [Fact]
    public void BootRecovery_ReportsAndRevalidatesActiveStateStorageTraversal()
    {
        var source = ReadProjectSource("YowThi.DevelopmentAgent3", Path.Combine("Inspection", "V4BootRecoveryStatusTools.cs"));
        Assert.Contains("ActiveStateStorageStatus", source, StringComparison.Ordinal);
        Assert.Contains("ReadActiveStateStorageStatus(failures)", source, StringComparison.Ordinal);
        Assert.Contains("ValidateFixedDirectoryTraversal(HandoffRoot, DevRoot", source, StringComparison.Ordinal);
        Assert.Contains("active-runtime state root traversal is unsafe", source, StringComparison.Ordinal);
        Assert.Contains("C41662D394C8D183991CACB66521164996955B1FA381D4C622E9813D3582BE9E", source, StringComparison.Ordinal);
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
