using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class RuntimeSupervisorAuthorizationGateContractTests
{
    [Fact]
    public void Program_DoesNotRegisterLegacyHandoffActivationWorker()
    {
        var sourcePath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..",
            "YowThi.RuntimeSupervisor",
            "Program.cs"));
        Assert.True(File.Exists(sourcePath), $"Runtime Supervisor Program.cs was not found: {sourcePath}");

        var source = File.ReadAllText(sourcePath);
        Assert.Contains("AddHostedService<RuntimeSupervisorWorker>()", source, StringComparison.Ordinal);
        Assert.Contains("AddHostedService<BootstrapTunnelRecoveryWorker>()", source, StringComparison.Ordinal);
        Assert.DoesNotContain("RuntimeHandoffActivationWorker", source, StringComparison.Ordinal);
    }

    [Fact]
    public void SupervisorWorker_HasNoRawPendingActivationPath()
    {
        var sourcePath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..",
            "YowThi.RuntimeSupervisor",
            "RuntimeSupervisorWorker.cs"));
        Assert.True(File.Exists(sourcePath), $"RuntimeSupervisorWorker.cs was not found: {sourcePath}");

        var source = File.ReadAllText(sourcePath);
        Assert.DoesNotContain("PendingRoot", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ActivatePendingAsync", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ManifestEndpointIsHealthyAsync", source, StringComparison.Ordinal);
        Assert.DoesNotContain(".agent3-handoff\\ready", source, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("EnsureActiveRuntimeAsync", source, StringComparison.Ordinal);
        Assert.Contains("EnsureTunnelAsync", source, StringComparison.Ordinal);
    }

    [Fact]
    public void SupervisorHealthAcceptance_RequiresExactRuntimeShaIdentity()
    {
        var sourcePath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..",
            "YowThi.RuntimeSupervisor",
            "RuntimeSupervisorWorker.cs"));
        Assert.True(File.Exists(sourcePath), $"RuntimeSupervisorWorker.cs was not found: {sourcePath}");

        var source = File.ReadAllText(sourcePath);
        Assert.Contains("TryGetProperty(\"runtimeSha256\"", source, StringComparison.Ordinal);
        Assert.Contains("string.Equals(sha.GetString(), slot.RuntimeSha256", source, StringComparison.Ordinal);
        Assert.Contains("if (string.IsNullOrWhiteSpace(body)) return false;", source, StringComparison.Ordinal);
    }
}
