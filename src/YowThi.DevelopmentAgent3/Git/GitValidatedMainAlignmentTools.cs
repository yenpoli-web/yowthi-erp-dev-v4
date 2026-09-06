using System.ComponentModel;
using ModelContextProtocol.Server;

namespace YowThi.DevelopmentAgent3.Git;

[McpServerToolType]
public static class GitValidatedMainAlignmentTools
{
    [McpServerTool(Name = "git_validated_main_alignment_status", ReadOnly = true, Destructive = false, OpenWorld = true)]
    [Description("Read consolidated validation/main alignment evidence for one flat p*-validation or m*-validation branch in the fixed YowThi ERP Dev v4 repository. This tool composes only the existing read-only validation-branch absorption and exact-SHA GitHub Actions job evidence capabilities. It reports whether the validated branch matches local main, whether the same origin validation branch matches, whether exact-SHA CI is fully accepted, and whether origin/main already equals local main. It does not push, fetch, merge, create or delete refs, create pull requests, dispatch workflows, or modify repository, process, service, runtime, or filesystem state.")]
    public static async Task<GitValidatedMainAlignmentResult> GitValidatedMainAlignmentStatus(string validationBranchName)
    {
        var git = await GitValidationBranchCleanupTools.GitValidationBranchAbsorptionStatus(validationBranchName);
        var ci = await GitHubActionsTools.GitHubWorkflowRunJobs(validationBranchName);

        var localValidationMatchesMain =
            git.LocalExists &&
            !string.IsNullOrWhiteSpace(git.LocalBranchCommit) &&
            string.Equals(git.LocalBranchCommit, git.LocalMainCommit, StringComparison.OrdinalIgnoreCase);

        var originValidationMatchesMain =
            git.RemoteExists &&
            !string.IsNullOrWhiteSpace(git.RemoteBranchCommit) &&
            string.Equals(git.RemoteBranchCommit, git.LocalMainCommit, StringComparison.OrdinalIgnoreCase);

        var ciHeadMatchesValidation =
            !string.IsNullOrWhiteSpace(ci.LocalHead) &&
            !string.IsNullOrWhiteSpace(git.LocalBranchCommit) &&
            string.Equals(ci.LocalHead, git.LocalBranchCommit, StringComparison.OrdinalIgnoreCase);

        var validationEvidenceComplete =
            git.WorkingTreeClean &&
            localValidationMatchesMain &&
            originValidationMatchesMain &&
            ciHeadMatchesValidation &&
            ci.WorkflowIdentityMatches &&
            ci.RequiredRunnerLabelsPresent &&
            ci.AllJobsSucceeded &&
            ci.EligibleForMainFastForward;

        var failureReasons = new List<string>();
        if (!git.WorkingTreeClean) failureReasons.Add("working-tree-not-clean");
        if (!git.LocalExists) failureReasons.Add("local-validation-branch-missing");
        else if (!localValidationMatchesMain) failureReasons.Add("local-validation-does-not-match-local-main");
        if (!git.RemoteExists) failureReasons.Add("origin-validation-branch-missing");
        else if (!originValidationMatchesMain) failureReasons.Add("origin-validation-does-not-match-local-main");
        if (!ciHeadMatchesValidation) failureReasons.Add("ci-head-does-not-match-local-validation");
        if (!ci.WorkflowIdentityMatches) failureReasons.Add("workflow-identity-mismatch");
        if (!ci.RequiredRunnerLabelsPresent) failureReasons.Add("required-runner-labels-missing");
        if (!ci.AllJobsSucceeded) failureReasons.Add("ci-jobs-not-all-successful");
        if (!ci.EligibleForMainFastForward) failureReasons.Add("not-eligible-for-main-fast-forward");
        if (!git.LocalMainMatchesRemoteMain) failureReasons.Add("origin-main-not-aligned-with-local-main");

        return new GitValidatedMainAlignmentResult(
            git.Repository,
            validationBranchName,
            git.CurrentBranch,
            git.CurrentHead,
            git.WorkingTreeClean,
            git.LocalMainCommit,
            git.RemoteMainCommit,
            git.LocalMainMatchesRemoteMain,
            git.LocalBranchCommit,
            git.RemoteBranchCommit,
            localValidationMatchesMain,
            originValidationMatchesMain,
            ci.RunId,
            ci.RunStatus,
            ci.RunConclusion,
            ci.WorkflowIdentityMatches,
            ci.RequiredRunnerLabelsPresent,
            ci.AllJobsSucceeded,
            ci.EligibleForMainFastForward,
            ciHeadMatchesValidation,
            validationEvidenceComplete,
            validationEvidenceComplete && git.LocalMainMatchesRemoteMain,
            failureReasons,
            DateTimeOffset.UtcNow);
    }
}

public sealed record GitValidatedMainAlignmentResult(
    string Repository,
    string ValidationBranch,
    string CurrentBranch,
    string CurrentHead,
    bool WorkingTreeClean,
    string LocalMainCommit,
    string? OriginMainCommit,
    bool OriginMainAlignedWithLocalMain,
    string? LocalValidationCommit,
    string? OriginValidationCommit,
    bool LocalValidationMatchesLocalMain,
    bool OriginValidationMatchesLocalMain,
    long? CiRunId,
    string? CiRunStatus,
    string? CiRunConclusion,
    bool WorkflowIdentityMatches,
    bool RequiredRunnerLabelsPresent,
    bool AllJobsSucceeded,
    bool EligibleForMainFastForward,
    bool CiHeadMatchesValidation,
    bool ValidationEvidenceComplete,
    bool FullyAligned,
    IReadOnlyList<string> FailureReasons,
    DateTimeOffset CheckedUtc);
