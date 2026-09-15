using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class RuntimeSupervisorReusableUpdaterContractTests
{
    [Fact]
    public void UpdaterDispatch_AddsReusableCandidateBootstrapWithoutRemovingHistoricalP54Bootstrap()
    {
        var source = ReadProjectSource("YowThi.RuntimeSupervisorUpdater", "Program.cs");

        Assert.Contains("--bootstrap-p54", source, StringComparison.Ordinal);
        Assert.Contains("IndependentBootstrap.BootstrapP54()", source, StringComparison.Ordinal);
        Assert.Contains("--bootstrap-candidate", source, StringComparison.Ordinal);
        Assert.Contains("ReusableBootstrap.BootstrapCandidate(args[1])", source, StringComparison.Ordinal);
        Assert.Contains("IndependentBootstrap.RunOneShotService", source, StringComparison.Ordinal);
    }

    [Fact]
    public void ReusableBootstrap_IsFailClosedAndUsesIndependentScmOneShotService()
    {
        var source = ReadProjectSource("YowThi.RuntimeSupervisorUpdater", "ReusableBootstrap.cs");

        Assert.Contains("StagingRoot = DevRoot + @\"\\staging\"", source, StringComparison.Ordinal);
        Assert.Contains("RequireDirectDirectoryChild(candidateDirectory, StagingRoot", source, StringComparison.Ordinal);
        Assert.Contains("RequireSafeDirectoryTraversal(candidateDirectory, StagingRoot)", source, StringComparison.Ordinal);
        Assert.Contains("buildName.Contains(\"-build\"", source, StringComparison.Ordinal);
        Assert.Contains("RequireSafeDirectoryTraversal(buildDirectory, AcceptanceRoot)", source, StringComparison.Ordinal);
        Assert.Contains("FileAttributes.ReparsePoint", source, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeSupervisor.exe", source, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeSupervisor.dll", source, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeSupervisor.deps.json", source, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeSupervisor.runtimeconfig.json", source, StringComparison.Ordinal);
        Assert.Contains("CurrentManifestSha256", source, StringComparison.Ordinal);
        Assert.Contains("CandidateManifestSha256", source, StringComparison.Ordinal);
        Assert.Contains("CurrentExeSha256", source, StringComparison.Ordinal);
        Assert.Contains("CandidateExeSha256", source, StringComparison.Ordinal);
        Assert.Contains("candidate package is identical to current package", source, StringComparison.Ordinal);
        Assert.Contains("CreateServiceW", source, StringComparison.Ordinal);
        Assert.Contains("StartServiceW", source, StringComparison.Ordinal);
        Assert.Contains("DeleteService", source, StringComparison.Ordinal);
        Assert.Contains("--service", source, StringComparison.Ordinal);
        Assert.Contains("reusable-scm-one-shot-local-system", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Process.Start", source, StringComparison.Ordinal);
        Assert.DoesNotContain("powershell", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("cmd.exe", source, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void OneShotWorker_PreservesP55PinAndAcceptsReusableAcceptanceBuildIdentity()
    {
        var legacy = ReadProjectSource("YowThi.RuntimeSupervisorUpdater", "IndependentBootstrap.cs");
        var reusable = ReadProjectSource("YowThi.RuntimeSupervisorUpdater", "ReusableBootstrap.cs");

        Assert.Contains("ExpectedBootstrapExecutable", legacy, StringComparison.Ordinal);
        Assert.Contains("? RequireExactSelf()", legacy, StringComparison.Ordinal);
        Assert.Contains(": ReusableBootstrap.RequireReusableBootstrapSelf()", legacy, StringComparison.Ordinal);
        Assert.Contains("HashFile(self), expectedSelfSha", legacy, StringComparison.Ordinal);
        Assert.Contains("internal static string RequireReusableBootstrapSelf()", reusable, StringComparison.Ordinal);
        Assert.Contains("buildName.Contains(\"-build\"", reusable, StringComparison.Ordinal);
    }
    [Fact]
    public void AtomicUpdate_RevalidatesFixedRootsInsteadOfCreatingSecurityBoundariesOnDemand()
    {
        var source = ReadProjectSource("YowThi.RuntimeSupervisorUpdater", "Program.cs");

        Assert.Contains("ValidateFixedRoots();", source, StringComparison.Ordinal);
        Assert.Contains("RequireSafeDirectoryTraversal(DevRoot, DevRoot)", source, StringComparison.Ordinal);
        Assert.Contains("RequireSafeDirectoryTraversal(StagingRoot, DevRoot)", source, StringComparison.Ordinal);
        Assert.Contains("RequireSafeDirectoryTraversal(CurrentDirectory, SupervisorRoot)", source, StringComparison.Ordinal);
        Assert.Contains("RequireSafeDirectoryTraversal(PendingRoot, SupervisorRoot)", source, StringComparison.Ordinal);
        Assert.Contains("current.Attributes & FileAttributes.ReparsePoint", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Directory.CreateDirectory(PendingRoot)", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Directory.CreateDirectory(CompletedRoot)", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Directory.CreateDirectory(FailedRoot)", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Directory.CreateDirectory(RollbackRoot)", source, StringComparison.Ordinal);
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
