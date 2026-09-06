using YowThi.DevelopmentAgent3.Git;
using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class GitValidatedMainAlignmentContractTests
{
    [Fact]
    public void AlignmentTool_ExposesOneReadOnlyStatusSignature()
    {
        var type = typeof(GitValidatedMainAlignmentTools);
        var method = type.GetMethod(nameof(GitValidatedMainAlignmentTools.GitValidatedMainAlignmentStatus));
        Assert.NotNull(method);
        Assert.True(method!.IsPublic && method.IsStatic);
        Assert.Single(method.GetParameters());
        Assert.Equal(typeof(string), method.GetParameters()[0].ParameterType);
    }

    [Fact]
    public void AlignmentTool_SourceComposesOnlyExistingReadOnlyEvidenceCapabilities()
    {
        var sourcePath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..",
            "YowThi.DevelopmentAgent3",
            "Git",
            "GitValidatedMainAlignmentTools.cs"));
        Assert.True(File.Exists(sourcePath), $"Expected P24 source file was not found: {sourcePath}");

        var source = File.ReadAllText(sourcePath);
        Assert.Contains("GitValidationBranchAbsorptionStatus", source, StringComparison.Ordinal);
        Assert.Contains("GitHubWorkflowRunJobs", source, StringComparison.Ordinal);
        Assert.Contains("git_validated_main_alignment_status", source, StringComparison.Ordinal);
        Assert.Contains("ReadOnly = true", source, StringComparison.Ordinal);
        Assert.Contains("ValidationEvidenceComplete", source, StringComparison.Ordinal);
        Assert.Contains("OriginMainAlignedWithLocalMain", source, StringComparison.Ordinal);

        Assert.DoesNotContain("Process.Start", source, StringComparison.Ordinal);
        Assert.DoesNotContain("git_push", source, StringComparison.Ordinal);
        Assert.DoesNotContain("GitPush", source, StringComparison.Ordinal);
        Assert.DoesNotContain("git_fetch", source, StringComparison.Ordinal);
        Assert.DoesNotContain("GitFetch", source, StringComparison.Ordinal);
        Assert.DoesNotContain("git_merge", source, StringComparison.Ordinal);
        Assert.DoesNotContain("GitFastForwardPromotion", source, StringComparison.Ordinal);
        Assert.DoesNotContain("GitValidationBranchCleanupPlan", source, StringComparison.Ordinal);
        Assert.DoesNotContain("GitValidationBranchCleanupExecute", source, StringComparison.Ordinal);
        Assert.DoesNotContain("runtime_handoff_activate", source, StringComparison.Ordinal);
        Assert.DoesNotContain("FileMode.Create", source, StringComparison.Ordinal);
        Assert.DoesNotContain("File.Delete", source, StringComparison.Ordinal);
        Assert.DoesNotContain("File.Move", source, StringComparison.Ordinal);
        Assert.DoesNotContain("File.Replace", source, StringComparison.Ordinal);
    }
}
