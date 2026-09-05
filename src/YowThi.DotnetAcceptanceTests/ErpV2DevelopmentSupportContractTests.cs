using System.Reflection;
using ModelContextProtocol.Server;
using Xunit;
using YowThi.DevelopmentAgent3.Git;

namespace YowThi.DotnetAcceptanceTests;

public sealed class ErpV2DevelopmentSupportContractTests
{
    [Fact]
    public void P18ToolsExposeOnlyTheIntendedNarrowContracts()
    {
        var validationTools = GetToolNames(typeof(ErpV2ValidationEvidenceTools));
        Assert.Equal(
            new[]
            {
                "erp_v2_github_workflow_run_jobs",
                "erp_v2_github_workflow_run_status",
                "erp_v2_runner_validation_evidence"
            },
            validationTools);

        var repositoryTools = GetToolNames(typeof(ErpV2RepositorySupportTools));
        Assert.Equal(
            new[]
            {
                "erp_v2_file_text_patch_execute",
                "erp_v2_file_text_patch_plan",
                "erp_v2_repository_text_search"
            },
            repositoryTools);

        AssertParameterNames(
            typeof(ErpV2ValidationEvidenceTools),
            nameof(ErpV2ValidationEvidenceTools.ErpV2GitHubWorkflowRunStatus),
            "branchName");
        AssertParameterNames(
            typeof(ErpV2ValidationEvidenceTools),
            nameof(ErpV2ValidationEvidenceTools.ErpV2GitHubWorkflowRunJobs),
            "branchName");
        AssertParameterNames(
            typeof(ErpV2ValidationEvidenceTools),
            nameof(ErpV2ValidationEvidenceTools.ErpV2RunnerValidationEvidence),
            "branchName");
        AssertParameterNames(
            typeof(ErpV2RepositorySupportTools),
            nameof(ErpV2RepositorySupportTools.ErpV2RepositoryTextSearch),
            "query", "mode", "glob", "caseSensitive", "maxResults");
        AssertParameterNames(
            typeof(ErpV2RepositorySupportTools),
            nameof(ErpV2RepositorySupportTools.ErpV2FileTextPatchPlan),
            "path", "expectedFileSha256", "replacements");
        AssertParameterNames(
            typeof(ErpV2RepositorySupportTools),
            nameof(ErpV2RepositorySupportTools.ErpV2FileTextPatchExecute),
            "planId", "approvalCode");
    }

    private static string[] GetToolNames(Type type) =>
        type.GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Select(method => method.GetCustomAttribute<McpServerToolAttribute>())
            .Where(attribute => attribute is not null)
            .Select(attribute => attribute!.Name!)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

    private static void AssertParameterNames(Type type, string methodName, params string[] expected)
    {
        var method = type.GetMethod(methodName, BindingFlags.Public | BindingFlags.Static)
            ?? throw new InvalidOperationException($"Missing method {type.FullName}.{methodName}.");
        Assert.Equal(expected, method.GetParameters().Select(parameter => parameter.Name!).ToArray());
    }
}
