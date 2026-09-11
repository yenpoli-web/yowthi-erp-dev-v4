using System.Text.Json;
using Xunit;
using YowThi.DevelopmentAgent3.AgentLifecycle;

namespace YowThi.DotnetAcceptanceTests;

public sealed class AgentLifecycleReleaseInventoryBehaviorTests
{
    private const string ActiveStatePath = @"C:\Dev\YowThi-ERP-Dev-v4\.agent3-handoff\active-runtime.json";

    [Fact]
    public void ReleaseInventory_ParsesLiveActiveStateAndProtectsCurrentAndPreviousReleases()
    {
        using var state = JsonDocument.Parse(File.ReadAllBytes(ActiveStatePath));
        var currentRelease = ReleaseName(state.RootElement.GetProperty("Current").GetProperty("RuntimeDll").GetString());
        var previousElement = state.RootElement.GetProperty("Previous");
        var previousRelease = previousElement.ValueKind == JsonValueKind.Null
            ? null
            : ReleaseName(previousElement.GetProperty("RuntimeDll").GetString());

        var result = AgentLifecycleRetentionCleanupTools.AgentLifecycleReleaseCleanupInventory();

        Assert.Equal("release", result.Kind);
        Assert.True(result.CandidateCount > 0);
        Assert.Equal(result.CandidateCount, result.Candidates.Count);
        Assert.Contains(result.Candidates, candidate =>
            candidate.Name == currentRelease &&
            !candidate.EligibleForCleanup &&
            candidate.Classification.Contains("active-state-current-reference", StringComparison.Ordinal));
        if (previousRelease is not null)
        {
            Assert.Contains(result.Candidates, candidate =>
                candidate.Name == previousRelease &&
                !candidate.EligibleForCleanup &&
                candidate.Classification.Contains("active-state-previous-reference", StringComparison.Ordinal));
        }
    }

    private static string ReleaseName(string? runtimeDll)
    {
        Assert.False(string.IsNullOrWhiteSpace(runtimeDll));
        var packageDirectory = Path.GetDirectoryName(Path.GetFullPath(runtimeDll!));
        Assert.False(string.IsNullOrWhiteSpace(packageDirectory));
        return Path.GetFileName(packageDirectory!);
    }
}
