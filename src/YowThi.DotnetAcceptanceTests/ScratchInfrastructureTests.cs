using System.Text.Json;
using Xunit;
using YowThi.DevelopmentAgent3.Automation;
using YowThi.DevelopmentAgent3.Filesystem;
using YowThi.DevelopmentAgent3.Git;
using YowThi.DevelopmentAgent3.Scratch;

namespace YowThi.DotnetAcceptanceTests;

public sealed class ScratchInfrastructureTests
{
    private const string RepositoryRoot = @"C:\Dev\YowThi-ERP-Dev-v4";

    [Fact]
    public void GenericFileCreate_RejectsScratchScriptsAndYowThiArtifactsInsideV4Worktree()
    {
        var ps1 = Path.Combine(RepositoryRoot, "automation", "powershell", "p48-should-never-exist.ps1");
        var artifact = Path.Combine(RepositoryRoot, "src", ".sample.yowthi-deadbeef.bak");

        Assert.Throws<UnauthorizedAccessException>(() => FilesystemTools.FileCreatePlan(ps1, "Write-Output 'blocked'"));
        Assert.Throws<UnauthorizedAccessException>(() => FilesystemTools.FileCreatePlan(artifact, "blocked"));
        Assert.False(File.Exists(ps1));
        Assert.False(File.Exists(artifact));
    }

    [Fact]
    public void ScratchStore_CreatesRepoExternalOwnedTtlManifestAndDeletesByOwnership()
    {
        var planId = Guid.NewGuid().ToString("N");
        var bytes = System.Text.Encoding.UTF8.GetBytes("P48 manifest ✓\n");
        var artifact = AgentScratchStore.CreateArtifact(
            planId,
            "tests/scratch-infrastructure",
            "manifest-test",
            ".bak",
            bytes,
            DateTimeOffset.UtcNow.AddMinutes(10),
            Path.Combine(RepositoryRoot, "README.md"));

        try
        {
            Assert.StartsWith(Path.GetFullPath(AgentScratchStore.RootPath), artifact.DataPath, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(Path.GetFullPath(RepositoryRoot) + Path.DirectorySeparatorChar, artifact.DataPath, StringComparison.OrdinalIgnoreCase);
            Assert.True(File.Exists(artifact.DataPath));
            Assert.True(File.Exists(artifact.ManifestPath));
            using var doc = JsonDocument.Parse(File.ReadAllBytes(artifact.ManifestPath));
            Assert.Equal(planId, doc.RootElement.GetProperty("PlanId").GetString());
            Assert.Equal("tests/scratch-infrastructure", doc.RootElement.GetProperty("Owner").GetString());
            Assert.Equal("manifest-test", doc.RootElement.GetProperty("Purpose").GetString());
            Assert.Equal(artifact.Sha256, doc.RootElement.GetProperty("DataSha256").GetString());
            Assert.True(doc.RootElement.GetProperty("ExpiresUtc").GetDateTimeOffset() > DateTimeOffset.UtcNow);
            var reconcile = AgentScratchStore.ReconcileExpired();
            Assert.True(reconcile.ActiveCount >= 1);
            Assert.Equal(0, reconcile.InvalidManifestCount);
        }
        finally
        {
            Assert.True(AgentScratchStore.TryDeleteOwnedArtifact(artifact.DataPath));
            Assert.False(File.Exists(artifact.DataPath));
            Assert.False(File.Exists(artifact.ManifestPath));
        }
    }

    [Fact]
    public async Task ScratchScript_ExecutesOutsideRepoAndAutoDeletesArtifact()
    {
        var plan = AgentScratchScriptTools.AgentScratchScriptPlan("Write-Output 'P48-SCRATCH-OK'", timeoutSeconds: 30, scratchTtlMinutes: 10);
        Assert.Empty(Directory.Exists(AgentScratchStore.RootPath)
            ? Directory.EnumerateFiles(AgentScratchStore.RootPath, plan.PlanId + "-*.ps1", SearchOption.TopDirectoryOnly)
            : Array.Empty<string>());

        var result = await AgentScratchScriptTools.AgentScratchScriptExecute(plan.PlanId, plan.ApprovalCode);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("P48-SCRATCH-OK", result.StdOut, StringComparison.Ordinal);
        Assert.True(result.ScratchDeleted);
        Assert.Empty(Directory.EnumerateFiles(AgentScratchStore.RootPath, plan.PlanId + "-*", SearchOption.TopDirectoryOnly));
    }

    [Fact]
    public async Task FileReplace_UsesRepoExternalBackupAndLeavesNoWorktreeTempOrBackup()
    {
        var leaf = "p48-file-replace-test-" + Guid.NewGuid().ToString("N");
        var directory = Path.Combine(RepositoryRoot, "staging", leaf);
        var target = Path.Combine(directory, "target.txt");
        Directory.CreateDirectory(directory);
        File.WriteAllText(target, "before\n");
        string? backupDataPath = null;

        try
        {
            var plan = FileReplaceTools.FileReplacePlan(target, "after\n第二行\n");
            var result = await FileReplaceTools.FileReplaceExecute(
                plan.PlanId,
                plan.ApprovalCode,
                plan.Operation,
                plan.Target,
                plan.Summary,
                plan.RiskClass.ToString());

            Assert.Equal("after\n第二行\n", File.ReadAllText(target));
            Assert.DoesNotContain(
                Directory.EnumerateFiles(directory),
                path => Path.GetFileName(path).Contains(".yowthi-", StringComparison.OrdinalIgnoreCase) ||
                        Path.GetExtension(path).Equals(".tmp", StringComparison.OrdinalIgnoreCase));
            var artifactId = ExtractOutcomeValue(result.Outcome, "backupArtifact");
            backupDataPath = Path.Combine(AgentScratchStore.RootPath, artifactId);
            Assert.True(File.Exists(backupDataPath));
            Assert.True(File.Exists(backupDataPath + ".manifest.json"));
            var backup = AgentScratchStore.RequireActiveOwnedArtifact(backupDataPath, "file-replace-backup");
            Assert.Equal("before\n", File.ReadAllText(backup.DataPath));
            Assert.True(backup.ExpiresUtc > DateTimeOffset.UtcNow.AddHours(23));
        }
        finally
        {
            if (backupDataPath is not null) _ = AgentScratchStore.TryDeleteOwnedArtifact(backupDataPath);
            if (File.Exists(target)) File.Delete(target);
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: false);
        }
    }

    [Fact]
    public void PersistentPowerShellPlan_AcceptsExistingTrackedAutomationScript()
    {
        var script = Path.Combine(RepositoryRoot, "automation", "powershell", "git-init-v4.ps1");
        Assert.True(File.Exists(script));
        var plan = PowerShellTools.PowerShellScriptPlan(script, timeoutSeconds: 30);
        Assert.Equal("powershell-script", plan.Operation);
        Assert.Equal(script, plan.Target, ignoreCase: true);
    }

    [Fact]
    public async Task GitPreflight_ReturnsScratchReconciliationEvidence()
    {
        var result = await GitWorktreePreflightTools.GitWorktreeMutationPreflight(
            RepositoryRoot,
            intendedBranch: null,
            requireAllWorktreesClean: false);

        Assert.Equal(0, result.ScratchReconciliation.InvalidManifestCount);
        Assert.True(result.ScratchReconciliation.CheckedUtc <= result.CheckedUtc);
    }

    private static string ExtractOutcomeValue(string outcome, string key)
    {
        var prefix = key + ":";
        var start = outcome.IndexOf(prefix, StringComparison.Ordinal);
        Assert.True(start >= 0, $"Outcome did not contain {prefix}");
        start += prefix.Length;
        var end = outcome.IndexOf(';', start);
        return end < 0 ? outcome[start..] : outcome[start..end];
    }
}
