using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class AgentLifecycleActiveRuntimeRetentionContractTests
{
    private static string ReadSource()
    {
        var sourcePath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..",
            "YowThi.DevelopmentAgent3",
            "AgentLifecycle",
            "AgentLifecycleRetentionCleanupTools.cs"));
        Assert.True(File.Exists(sourcePath), $"Expected P38 source file was not found: {sourcePath}");
        return File.ReadAllText(sourcePath);
    }

    [Fact]
    public void ReleaseRetention_ProtectsActiveStateWhileRollbackPolicyRemainsIndependent()
    {
        var source = ReadSource();
        Assert.Contains("AgentLifecycleReleaseCleanupInventory()", source, StringComparison.Ordinal);
        Assert.Contains("protectActiveStateReferences: true", source, StringComparison.Ordinal);
        Assert.Contains("AgentLifecycleRollbackCleanupInventory()", source, StringComparison.Ordinal);
        Assert.Contains("protectActiveStateReferences: false", source, StringComparison.Ordinal);
        Assert.Contains("active-state-current-reference", source, StringComparison.Ordinal);
        Assert.Contains("active-state-previous-reference", source, StringComparison.Ordinal);
    }

    [Fact]
    public void ActiveStateReader_IsFixedSchemaTwoDirectReleaseAndExactSha()
    {
        var source = ReadSource();
        Assert.Contains(".agent3-handoff\\active-runtime.json", source, StringComparison.Ordinal);
        Assert.Contains("schema.GetInt32() != 2", source, StringComparison.Ordinal);
        Assert.Contains("must be one direct staged release", source, StringComparison.Ordinal);
        Assert.Contains("Active runtime {name} DLL SHA-256 mismatch", source, StringComparison.Ordinal);
        Assert.Contains("FileAttributes.ReparsePoint", source, StringComparison.Ordinal);
        Assert.Contains("MaxActiveStateBytes", source, StringComparison.Ordinal);
        Assert.Contains("TryGetPropertyIgnoreCase(root, \"schemaVersion\"", source, StringComparison.Ordinal);
        Assert.Contains("GetRequiredPropertyIgnoreCase(element, \"runtimeDll\"", source, StringComparison.Ordinal);
        Assert.Contains("StringComparison.OrdinalIgnoreCase", source, StringComparison.Ordinal);
    }

    [Fact]
    public void ReleaseCleanupPlan_SealsAndExecuteRevalidatesActiveStateFingerprint()
    {
        var source = ReadSource();
        Assert.Contains("[\"activeStateFingerprint\"] = active.Fingerprint", source, StringComparison.Ordinal);
        Assert.Contains("Require(plan, \"activeStateFingerprint\")", source, StringComparison.Ordinal);
        Assert.Contains("Active runtime state changed after cleanup plan preparation.", source, StringComparison.Ordinal);
        Assert.Contains("Lifecycle release became referenced by active runtime state.", source, StringComparison.Ordinal);
    }

    [Fact]
    public void RetentionCleanup_RemainsNativeDeleteWithoutShellFallback()
    {
        var source = ReadSource();
        Assert.Contains("File.Delete(entry.FullName)", source, StringComparison.Ordinal);
        Assert.Contains("Directory.Delete(root, false)", source, StringComparison.Ordinal);
        Assert.DoesNotContain("PowerShell", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("cmd.exe", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ProcessStartInfo", source, StringComparison.Ordinal);
    }
}
