using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class RuntimeDeploymentRecoveryContractTests
{
    [Fact]
    public void Executor_WaitsForSupervisorPidWritebackAfterTargetHealth()
    {
        var source = ReadSource("YowThi.RuntimeDeploymentExecutor", "Program.cs");

        var healthIndex = source.IndexOf(
            "WaitForExactRuntimeShaAsync(authorization.HealthUrl, authorization.TargetRuntimeSha256",
            StringComparison.Ordinal);
        var stateWaitIndex = source.IndexOf("WaitForActiveRuntimeStateAsync(", healthIndex + 1, StringComparison.Ordinal);

        Assert.True(healthIndex >= 0, "Target runtime health validation was not found.");
        Assert.True(stateWaitIndex > healthIndex, "Active-state PID writeback wait must occur after target health validation.");
        Assert.Contains("TimeSpan.FromSeconds(15)", source, StringComparison.Ordinal);
        Assert.Contains("state.Current.ProcessId > 0", source, StringComparison.Ordinal);
        Assert.Contains("EqualsSha(state.Current.RuntimeSha256, expectedSha)", source, StringComparison.Ordinal);
        Assert.DoesNotContain("var activeAfter = ReadActiveState();", source, StringComparison.Ordinal);
    }

    [Fact]
    public void RuntimeSupervisor_AlwaysCleansOwnedChildrenWhenInitializationIsCancelled()
    {
        var source = ReadSource("YowThi.RuntimeSupervisor", "RuntimeSupervisorWorker.cs");

        var executeIndex = source.IndexOf("protected override async Task ExecuteAsync", StringComparison.Ordinal);
        var finallyIndex = source.IndexOf("finally", executeIndex, StringComparison.Ordinal);
        var stopTunnelIndex = source.IndexOf("StopOwnedTunnel();", finallyIndex, StringComparison.Ordinal);
        var stopRuntimeIndex = source.IndexOf("StopOwnedRuntime();", finallyIndex, StringComparison.Ordinal);
        var disposeIndex = source.IndexOf("_http.Dispose();", finallyIndex, StringComparison.Ordinal);

        Assert.True(executeIndex >= 0, "RuntimeSupervisorWorker.ExecuteAsync was not found.");
        Assert.True(finallyIndex > executeIndex, "ExecuteAsync cleanup must be protected by finally.");
        Assert.True(stopTunnelIndex > finallyIndex, "Owned tunnel cleanup must be inside finally.");
        Assert.True(stopRuntimeIndex > stopTunnelIndex, "Owned runtime cleanup must be inside finally after tunnel cleanup.");
        Assert.True(disposeIndex > stopRuntimeIndex, "HttpClient disposal must remain after child cleanup.");
    }

    private static string ReadSource(string projectName, string fileName)
    {
        var path = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..",
            projectName,
            fileName));
        Assert.True(File.Exists(path), $"Source file was not found: {path}");
        return File.ReadAllText(path);
    }
}
