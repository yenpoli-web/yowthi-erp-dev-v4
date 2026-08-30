using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;
using YowThi.DevelopmentAgent3.Security;

namespace YowThi.DevelopmentAgent3.Git;

[McpServerToolType]
public static class GitV2Tools
{
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly ProtectedPathPolicy PathPolicy = new();

    private const string GitExe = @"C:\Program Files\Git\cmd\git.exe";
    private const string GitCredentialManagerExe = @"C:\Program Files\Git\mingw64\bin\git-credential-manager.exe";

    [McpServerTool(Name = "git_branch_delete_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed plan to delete one existing local Git branch using safe non-force deletion. The branch cannot be current, must still point to the sealed commit, and must be fully merged into the sealed current HEAD. Frozen production repositories are blocked. No arbitrary Git command is accepted.")]
    public static async Task<SignedPlan> GitBranchDeletePlan(string repository, string branchName)
    {
        var repo = await ValidateRepositoryAsync(repository, requireMutable: true);
        await ValidateBranchNameAsync(repo, branchName);
        await RequireCleanWorkingTreeAsync(repo);
        if (!await LocalBranchExistsAsync(repo, branchName))
            throw new InvalidOperationException($"Local branch does not exist: {branchName}");

        var currentBranch = await GetCurrentBranchAsync(repo);
        if (string.IsNullOrWhiteSpace(currentBranch))
            throw new InvalidOperationException("Local branch deletion is not allowed from detached HEAD.");
        if (string.Equals(currentBranch, branchName, StringComparison.Ordinal))
            throw new InvalidOperationException("The currently checked-out branch cannot be deleted.");

        var currentHead = await GetHeadAsync(repo);
        var targetCommit = await GetLocalBranchCommitAsync(repo, branchName);
        await RequireAncestorAsync(repo, targetCommit, currentHead, "Branch is not fully merged into the current HEAD.");

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["repository"] = repo,
            ["branchName"] = branchName,
            ["currentBranch"] = currentBranch,
            ["currentHead"] = currentHead,
            ["targetCommit"] = targetCommit
        };
        var summary = $"Delete fully merged local Git branch {branchName} at {targetCommit[..12]} from {repo}";
        return CreatePlan("git-branch-delete", repo, parameters, RiskClass.Medium, summary);
    }

    [McpServerTool(Name = "git_branch_delete_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared git/git-branch-delete plan using fixed safe git branch --delete semantics. Current branch, HEAD, target branch commit, clean working tree, and merged ancestry are rechecked. Force deletion is not supported.")]
    public static async Task<GitExecutionResult> GitBranchDeleteExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "git-branch-delete", operation, target, summary, riskClass);
        var repo = await ValidateRepositoryAsync(RequireParameter(plan, "repository"), requireMutable: true);
        var branchName = RequireParameter(plan, "branchName");
        var expectedCurrentBranch = RequireParameter(plan, "currentBranch");
        var expectedCurrentHead = RequireParameter(plan, "currentHead");
        var expectedTargetCommit = RequireParameter(plan, "targetCommit");
        await ValidateBranchNameAsync(repo, branchName);
        await RequireCleanWorkingTreeAsync(repo);
        if (!await LocalBranchExistsAsync(repo, branchName))
            throw new InvalidOperationException($"Local branch does not exist: {branchName}");

        var actualCurrentBranch = await GetCurrentBranchAsync(repo);
        var actualCurrentHead = await GetHeadAsync(repo);
        var actualTargetCommit = await GetLocalBranchCommitAsync(repo, branchName);
        if (!string.Equals(expectedCurrentBranch, actualCurrentBranch, StringComparison.Ordinal) ||
            !string.Equals(expectedCurrentHead, actualCurrentHead, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expectedTargetCommit, actualTargetCommit, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Git branch state changed after plan creation.");
        if (string.Equals(actualCurrentBranch, branchName, StringComparison.Ordinal))
            throw new InvalidOperationException("The currently checked-out branch cannot be deleted.");
        await RequireAncestorAsync(repo, actualTargetCommit, actualCurrentHead, "Branch is no longer fully merged into the current HEAD.");

        try
        {
            var result = await RunGitAsync(repo, new[] { "branch", "--delete", branchName }, 30);
            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, branchName, actualTargetCommit, result.ExitCode }, "executed");
            return new GitExecutionResult(plan.PlanId, plan.Operation, repo, branchName, result.ExitCode, result.StdOut, result.StdErr, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, branchName, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "git_add_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed plan to stage an exact list of repository-relative paths. Absolute paths, parent traversal, .git internals, wildcard/pathspec magic, reparse-point traversal, and repository-local external filter commands are rejected. Current HEAD and the full working-tree status snapshot are sealed.")]
    public static async Task<SignedPlan> GitAddPlan(string repository, string[] paths)
    {
        var repo = await ValidateRepositoryAsync(repository, requireMutable: true);
        var normalizedPaths = NormalizeExactPaths(repo, paths);
        await EnsureNoRepositoryLocalExternalFilterConfigAsync(repo);
        await EnsureSelectedPathsHaveNoExternalFilterAsync(repo, normalizedPaths);

        var currentHead = await GetHeadAsync(repo);
        var statusSha256 = await GetStatusSnapshotSha256Async(repo);
        var pathList = string.Join("\n", normalizedPaths);

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["repository"] = repo,
            ["paths"] = pathList,
            ["currentHead"] = currentHead,
            ["statusSha256"] = statusSha256
        };
        var summary = $"Stage {normalizedPaths.Length} exact Git path(s) in {repo} at HEAD {currentHead[..12]}";
        return CreatePlan("git-add", repo, parameters, RiskClass.Medium, summary);
    }

    [McpServerTool(Name = "git_add_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared git/git-add plan using fixed git add -- path semantics. The exact path list, HEAD, full status snapshot, reparse-point checks, filter checks, and repository boundary are revalidated. Arbitrary pathspecs and commands are not accepted.")]
    public static async Task<GitExecutionResult> GitAddExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "git-add", operation, target, summary, riskClass);
        var repo = await ValidateRepositoryAsync(RequireParameter(plan, "repository"), requireMutable: true);
        var normalizedPaths = NormalizeExactPaths(repo, ParsePathList(RequireParameter(plan, "paths")));
        var expectedHead = RequireParameter(plan, "currentHead");
        var expectedStatusSha256 = RequireParameter(plan, "statusSha256");

        await EnsureNoRepositoryLocalExternalFilterConfigAsync(repo);
        await EnsureSelectedPathsHaveNoExternalFilterAsync(repo, normalizedPaths);
        var actualHead = await GetHeadAsync(repo);
        var actualStatusSha256 = await GetStatusSnapshotSha256Async(repo);
        if (!string.Equals(expectedHead, actualHead, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expectedStatusSha256, actualStatusSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Git working-tree state changed after plan creation.");

        try
        {
            var args = new List<string> { "add", "--" };
            args.AddRange(normalizedPaths);
            var result = await RunGitAsync(repo, args, 60);
            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, paths = normalizedPaths, actualHead, result.ExitCode }, "executed");
            return new GitExecutionResult(plan.PlanId, plan.Operation, repo, $"{normalizedPaths.Length} path(s)", result.ExitCode, result.StdOut, result.StdErr, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, paths = normalizedPaths, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "git_commit_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed plan to commit the repository's currently staged changes with one explicit single-line message. Current HEAD, full status snapshot, and staged binary diff SHA-256 are sealed. Hooks and GPG signing are disabled; an editor or arbitrary command is never invoked.")]
    public static async Task<SignedPlan> GitCommitPlan(string repository, string message)
    {
        var repo = await ValidateRepositoryAsync(repository, requireMutable: true);
        var normalizedMessage = ValidateCommitMessage(message);
        var currentHead = await GetHeadAsync(repo);
        var statusSha256 = await GetStatusSnapshotSha256Async(repo);
        var stagedDiffSha256 = await GetStagedDiffSha256Async(repo, requireChanges: true);

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["repository"] = repo,
            ["message"] = normalizedMessage,
            ["currentHead"] = currentHead,
            ["statusSha256"] = statusSha256,
            ["stagedDiffSha256"] = stagedDiffSha256
        };
        var summary = $"Commit sealed staged Git changes in {repo} at HEAD {currentHead[..12]}";
        return CreatePlan("git-commit", repo, parameters, RiskClass.Medium, summary);
    }

    [McpServerTool(Name = "git_commit_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared git/git-commit plan using fixed git commit --no-verify --no-gpg-sign -m semantics. HEAD, full status snapshot, staged diff SHA-256, and commit message are rechecked. Hooks, signing, editors, and arbitrary commands are disabled.")]
    public static async Task<GitExecutionResult> GitCommitExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "git-commit", operation, target, summary, riskClass);
        var repo = await ValidateRepositoryAsync(RequireParameter(plan, "repository"), requireMutable: true);
        var message = ValidateCommitMessage(RequireParameter(plan, "message"));
        var expectedHead = RequireParameter(plan, "currentHead");
        var expectedStatusSha256 = RequireParameter(plan, "statusSha256");
        var expectedStagedDiffSha256 = RequireParameter(plan, "stagedDiffSha256");

        var actualHead = await GetHeadAsync(repo);
        var actualStatusSha256 = await GetStatusSnapshotSha256Async(repo);
        var actualStagedDiffSha256 = await GetStagedDiffSha256Async(repo, requireChanges: true);
        if (!string.Equals(expectedHead, actualHead, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expectedStatusSha256, actualStatusSha256, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expectedStagedDiffSha256, actualStagedDiffSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Git staged state changed after plan creation.");

        try
        {
            var result = await RunGitAsync(repo, new[] { "commit", "--no-verify", "--no-gpg-sign", "-m", message }, 120);
            var newHead = await GetHeadAsync(repo);
            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, oldHead = actualHead, newHead, result.ExitCode }, "executed");
            return new GitExecutionResult(plan.PlanId, plan.Operation, repo, newHead, result.ExitCode, result.StdOut, result.StdErr, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "git_pull_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed plan to fast-forward the current clean local branch from its existing same-name HTTPS upstream. Current branch, HEAD, full status snapshot, upstream remote configuration, standard fetch refspec, and fixed Git Credential Manager SHA-256 are sealed. Rebase, merge commits, force, arbitrary refspecs, and arbitrary transports are not supported.")]
    public static async Task<SignedPlan> GitPullPlan(string repository)
    {
        var repo = await ValidateRepositoryAsync(repository, requireMutable: true);
        await RequireCleanWorkingTreeAsync(repo);
        await EnsureNoRepositoryLocalExternalFilterConfigAsync(repo);

        var currentBranch = await GetCurrentBranchAsync(repo);
        if (string.IsNullOrWhiteSpace(currentBranch))
            throw new InvalidOperationException("Git pull is not allowed from detached HEAD.");
        await ValidateBranchNameAsync(repo, currentBranch);
        var (remote, remoteBranch) = await GetSameNameUpstreamAsync(repo, currentBranch);
        var currentHead = await GetHeadAsync(repo);
        var statusSha256 = await GetStatusSnapshotSha256Async(repo);
        var remoteConfigSha256 = await GetSafeHttpsRemoteConfigSha256Async(repo, remote);
        var credentialManagerSha256 = GetCredentialManagerSha256();

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["repository"] = repo,
            ["currentBranch"] = currentBranch,
            ["currentHead"] = currentHead,
            ["statusSha256"] = statusSha256,
            ["remote"] = remote,
            ["remoteBranch"] = remoteBranch,
            ["remoteConfigSha256"] = remoteConfigSha256,
            ["credentialManagerSha256"] = credentialManagerSha256
        };
        var summary = $"Fast-forward pull {currentBranch} from {remote}/{remoteBranch} in {repo} at HEAD {currentHead[..12]}";
        return CreatePlan("git-pull", repo, parameters, RiskClass.Medium, summary);
    }

    [McpServerTool(Name = "git_pull_execute", ReadOnly = false, Destructive = false, OpenWorld = true)]
    [Description("Execute one previously prepared git/git-pull plan using fixed fast-forward-only, no-rebase, no-submodule-recursion semantics and the fixed Git Credential Manager only. Current branch, HEAD, clean status, upstream identity, HTTPS remote configuration, standard refspec, and Credential Manager SHA-256 are rechecked. Interactive credential prompts and arbitrary commands are disabled.")]
    public static async Task<GitExecutionResult> GitPullExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "git-pull", operation, target, summary, riskClass);
        var repo = await ValidateRepositoryAsync(RequireParameter(plan, "repository"), requireMutable: true);
        await RequireCleanWorkingTreeAsync(repo);
        await EnsureNoRepositoryLocalExternalFilterConfigAsync(repo);

        var expectedBranch = RequireParameter(plan, "currentBranch");
        var expectedHead = RequireParameter(plan, "currentHead");
        var expectedStatusSha256 = RequireParameter(plan, "statusSha256");
        var expectedRemote = RequireParameter(plan, "remote");
        var expectedRemoteBranch = RequireParameter(plan, "remoteBranch");
        var expectedRemoteConfigSha256 = RequireParameter(plan, "remoteConfigSha256");
        var expectedCredentialManagerSha256 = RequireParameter(plan, "credentialManagerSha256");

        var actualBranch = await GetCurrentBranchAsync(repo);
        var actualHead = await GetHeadAsync(repo);
        var actualStatusSha256 = await GetStatusSnapshotSha256Async(repo);
        var (actualRemote, actualRemoteBranch) = await GetSameNameUpstreamAsync(repo, actualBranch);
        var actualRemoteConfigSha256 = await GetSafeHttpsRemoteConfigSha256Async(repo, actualRemote);
        var actualCredentialManagerSha256 = GetCredentialManagerSha256();

        if (!string.Equals(expectedBranch, actualBranch, StringComparison.Ordinal) ||
            !string.Equals(expectedHead, actualHead, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expectedStatusSha256, actualStatusSha256, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expectedRemote, actualRemote, StringComparison.Ordinal) ||
            !string.Equals(expectedRemoteBranch, actualRemoteBranch, StringComparison.Ordinal) ||
            !string.Equals(expectedRemoteConfigSha256, actualRemoteConfigSha256, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expectedCredentialManagerSha256, actualCredentialManagerSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Git pull state changed after plan creation.");

        try
        {
            var result = await RunGitAsync(
                repo,
                new[] { "pull", "--ff-only", "--no-rebase", "--no-recurse-submodules", actualRemote, actualRemoteBranch },
                300,
                networkHttpsOnly: true);
            var newHead = await GetHeadAsync(repo);
            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, actualBranch, actualRemote, oldHead = actualHead, newHead, result.ExitCode }, "executed");
            return new GitExecutionResult(plan.PlanId, plan.Operation, repo, $"{actualRemote}/{actualRemoteBranch}", result.ExitCode, result.StdOut, result.StdErr, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "git_push_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed plan to push the current clean local branch to its existing same-name HTTPS upstream without force. Current branch, HEAD, full status snapshot, upstream identity, remote configuration, standard fetch refspec, and fixed Git Credential Manager SHA-256 are sealed. New upstream creation, tag following, signed pushes, force, arbitrary refspecs, and arbitrary transports are not supported.")]
    public static async Task<SignedPlan> GitPushPlan(string repository)
    {
        var repo = await ValidateRepositoryAsync(repository, requireMutable: true);
        await RequireCleanWorkingTreeAsync(repo);

        var currentBranch = await GetCurrentBranchAsync(repo);
        if (string.IsNullOrWhiteSpace(currentBranch))
            throw new InvalidOperationException("Git push is not allowed from detached HEAD.");
        await ValidateBranchNameAsync(repo, currentBranch);
        var (remote, remoteBranch) = await GetSameNameUpstreamAsync(repo, currentBranch);
        var currentHead = await GetHeadAsync(repo);
        var statusSha256 = await GetStatusSnapshotSha256Async(repo);
        var remoteConfigSha256 = await GetSafeHttpsRemoteConfigSha256Async(repo, remote);
        var credentialManagerSha256 = GetCredentialManagerSha256();

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["repository"] = repo,
            ["currentBranch"] = currentBranch,
            ["currentHead"] = currentHead,
            ["statusSha256"] = statusSha256,
            ["remote"] = remote,
            ["remoteBranch"] = remoteBranch,
            ["remoteConfigSha256"] = remoteConfigSha256,
            ["credentialManagerSha256"] = credentialManagerSha256
        };
        var summary = $"Push {currentBranch} to existing same-name upstream {remote}/{remoteBranch} from {repo} at HEAD {currentHead[..12]}";
        return CreatePlan("git-push", repo, parameters, RiskClass.Medium, summary);
    }

    [McpServerTool(Name = "git_push_execute", ReadOnly = false, Destructive = false, OpenWorld = true)]
    [Description("Execute one previously prepared git/git-push plan using one explicit non-force same-name branch refspec and the fixed Git Credential Manager only. Current branch, HEAD, clean status, upstream identity, HTTPS remote configuration, standard refspec, and Credential Manager SHA-256 are rechecked. Tag following, signed pushes, submodule recursion, interactive credential prompts, arbitrary refspecs, and arbitrary commands are disabled.")]
    public static async Task<GitExecutionResult> GitPushExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "git-push", operation, target, summary, riskClass);
        var repo = await ValidateRepositoryAsync(RequireParameter(plan, "repository"), requireMutable: true);
        await RequireCleanWorkingTreeAsync(repo);

        var expectedBranch = RequireParameter(plan, "currentBranch");
        var expectedHead = RequireParameter(plan, "currentHead");
        var expectedStatusSha256 = RequireParameter(plan, "statusSha256");
        var expectedRemote = RequireParameter(plan, "remote");
        var expectedRemoteBranch = RequireParameter(plan, "remoteBranch");
        var expectedRemoteConfigSha256 = RequireParameter(plan, "remoteConfigSha256");
        var expectedCredentialManagerSha256 = RequireParameter(plan, "credentialManagerSha256");

        var actualBranch = await GetCurrentBranchAsync(repo);
        var actualHead = await GetHeadAsync(repo);
        var actualStatusSha256 = await GetStatusSnapshotSha256Async(repo);
        var (actualRemote, actualRemoteBranch) = await GetSameNameUpstreamAsync(repo, actualBranch);
        var actualRemoteConfigSha256 = await GetSafeHttpsRemoteConfigSha256Async(repo, actualRemote);
        var actualCredentialManagerSha256 = GetCredentialManagerSha256();

        if (!string.Equals(expectedBranch, actualBranch, StringComparison.Ordinal) ||
            !string.Equals(expectedHead, actualHead, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expectedStatusSha256, actualStatusSha256, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expectedRemote, actualRemote, StringComparison.Ordinal) ||
            !string.Equals(expectedRemoteBranch, actualRemoteBranch, StringComparison.Ordinal) ||
            !string.Equals(expectedRemoteConfigSha256, actualRemoteConfigSha256, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expectedCredentialManagerSha256, actualCredentialManagerSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Git push state changed after plan creation.");

        var refspec = $"refs/heads/{actualBranch}:refs/heads/{actualRemoteBranch}";
        try
        {
            var result = await RunGitAsync(
                repo,
                new[] { "push", "--porcelain", "--no-signed", "--no-follow-tags", "--recurse-submodules=no", actualRemote, refspec },
                300,
                networkHttpsOnly: true);
            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, actualBranch, actualRemote, refspec, actualHead, result.ExitCode }, "executed");
            return new GitExecutionResult(plan.PlanId, plan.Operation, repo, $"{actualRemote}/{actualRemoteBranch}", result.ExitCode, result.StdOut, result.StdErr, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    private static SignedPlan CreatePlan(string operation, string target, Dictionary<string, string> parameters, RiskClass riskClass, string summary)
    {
        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var unsigned = new SignedPlan(1, planId, approvalCode, "git", operation, target, parameters, riskClass, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    private static async Task<string> ValidateRepositoryAsync(string repository, bool requireMutable)
    {
        EnsureGitInstalled();
        var full = requireMutable ? PathPolicy.RequireMutable(repository) : PathPolicy.Normalize(repository);
        full = full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!Directory.Exists(full))
            throw new DirectoryNotFoundException($"Git repository directory not found: {full}");
        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Reparse-point repository roots are not allowed.");

        var probe = await RunGitAsync(full, new[] { "rev-parse", "--show-toplevel" }, 30);
        var topLevelText = probe.StdOut.Trim();
        if (string.IsNullOrWhiteSpace(topLevelText))
            throw new InvalidOperationException("Git repository root could not be resolved.");
        var topLevel = Path.GetFullPath(topLevelText).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!string.Equals(full, topLevel, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"repository must be the Git working-tree root: {topLevel}");
        return full;
    }

    private static void EnsureGitInstalled()
    {
        if (!File.Exists(GitExe))
            throw new FileNotFoundException("git.exe not found.", GitExe);
    }

    private static string GetCredentialManagerSha256()
    {
        if (!File.Exists(GitCredentialManagerExe))
            throw new FileNotFoundException("Git Credential Manager executable not found.", GitCredentialManagerExe);
        return Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(GitCredentialManagerExe)));
    }

    private static void ValidateRemoteName(string remote)
    {
        if (string.IsNullOrWhiteSpace(remote) || remote.Length > 128 || remote[0] == '-')
            throw new ArgumentException("Remote name is invalid.", nameof(remote));
        foreach (var c in remote)
        {
            if (!(char.IsLetterOrDigit(c) || c is '.' or '_' or '-'))
                throw new ArgumentException("Remote name may contain only letters, digits, '.', '_' and '-'.", nameof(remote));
        }
    }

    private static async Task ValidateBranchNameAsync(string repository, string branchName)
    {
        if (string.IsNullOrWhiteSpace(branchName) || branchName.Length > 128 || branchName[0] == '-' || branchName[0] == '.' || branchName[0] == '/' || branchName.EndsWith('.') || branchName.EndsWith('/'))
            throw new ArgumentException("Branch name is invalid.", nameof(branchName));
        if (branchName.Contains("..", StringComparison.Ordinal) || branchName.Contains("//", StringComparison.Ordinal) || branchName.Contains("@{", StringComparison.Ordinal) || branchName.EndsWith(".lock", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Branch name contains a prohibited sequence.", nameof(branchName));
        foreach (var c in branchName)
        {
            if (!(char.IsLetterOrDigit(c) || c is '.' or '_' or '-' or '/'))
                throw new ArgumentException("Git branch names may contain only letters, digits, '.', '_', '-' and '/'.", nameof(branchName));
        }

        var check = await RunGitAsync(repository, new[] { "check-ref-format", "--branch", branchName }, 30, allowNonZero: true);
        if (check.ExitCode != 0)
            throw new ArgumentException("Branch name failed git check-ref-format validation.", nameof(branchName));
    }

    private static string[] NormalizeExactPaths(string repository, IReadOnlyList<string>? paths)
    {
        if (paths is null || paths.Count == 0 || paths.Count > 64)
            throw new ArgumentException("paths must contain between 1 and 64 exact repository-relative paths.", nameof(paths));

        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in paths)
        {
            if (string.IsNullOrWhiteSpace(raw) || raw.Length > 512 || raw.Any(char.IsControl))
                throw new ArgumentException("Each Git path must be a non-empty control-character-free relative path.", nameof(paths));
            if (Path.IsPathFullyQualified(raw))
                throw new ArgumentException("Absolute Git paths are not accepted.", nameof(paths));

            var slash = raw.Replace('\\', '/');
            if (slash == "." || slash.StartsWith(":", StringComparison.Ordinal) || slash.IndexOfAny(['*', '?', '[', ']']) >= 0)
                throw new ArgumentException("Wildcard, pathspec-magic, and repository-root Git paths are not accepted.", nameof(paths));

            var full = Path.GetFullPath(Path.Combine(repository, raw));
            var repoPrefix = repository.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (!full.StartsWith(repoPrefix, StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Git path escapes the repository root.");

            var relative = Path.GetRelativePath(repository, full).Replace('\\', '/');
            if (relative == "." || relative.StartsWith("../", StringComparison.Ordinal) ||
                string.Equals(relative, ".git", StringComparison.OrdinalIgnoreCase) ||
                relative.StartsWith(".git/", StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Git internal paths and repository-root paths are not accepted.");

            EnsureNoReparsePointTraversal(repository, relative);
            if (seen.Add(relative))
                result.Add(relative);
        }

        if (result.Count == 0)
            throw new ArgumentException("No unique Git paths remain after normalization.", nameof(paths));
        return result.ToArray();
    }

    private static string[] ParsePathList(string value) =>
        value.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static void EnsureNoReparsePointTraversal(string repository, string relativePath)
    {
        var current = repository;
        foreach (var segment in relativePath.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException($"Reparse-point Git path is not allowed: {relativePath}");
        }
    }

    private static string ValidateCommitMessage(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
            throw new ArgumentException("Commit message is required.", nameof(message));
        var normalized = message.Trim();
        if (normalized.Length > 500 || normalized.Any(c => c is '\r' or '\n' || char.IsControl(c)))
            throw new ArgumentException("Commit message must be one control-character-free line of at most 500 characters.", nameof(message));
        return normalized;
    }

    private static async Task<bool> LocalBranchExistsAsync(string repository, string branchName)
    {
        var result = await RunGitAsync(repository, new[] { "show-ref", "--verify", "--quiet", $"refs/heads/{branchName}" }, 30, allowNonZero: true);
        if (result.ExitCode == 0) return true;
        if (result.ExitCode == 1) return false;
        throw new InvalidOperationException("Unable to determine whether the local branch exists.");
    }

    private static async Task<string> GetCurrentBranchAsync(string repository)
    {
        var result = await RunGitAsync(repository, new[] { "branch", "--show-current" }, 30);
        return result.StdOut.Trim();
    }

    private static async Task<string> GetHeadAsync(string repository)
    {
        var result = await RunGitAsync(repository, new[] { "rev-parse", "--verify", "HEAD" }, 30);
        var head = result.StdOut.Trim();
        if (head.Length < 12)
            throw new InvalidOperationException("Unable to resolve Git HEAD commit.");
        return head;
    }

    private static async Task<string> GetLocalBranchCommitAsync(string repository, string branchName)
    {
        var result = await RunGitAsync(repository, new[] { "rev-parse", "--verify", $"refs/heads/{branchName}" }, 30);
        var commit = result.StdOut.Trim();
        if (commit.Length < 12)
            throw new InvalidOperationException("Unable to resolve local branch commit.");
        return commit;
    }

    private static async Task RequireAncestorAsync(string repository, string ancestorCommit, string descendantCommit, string errorMessage)
    {
        var result = await RunGitAsync(repository, new[] { "merge-base", "--is-ancestor", ancestorCommit, descendantCommit }, 30, allowNonZero: true);
        if (result.ExitCode == 0) return;
        if (result.ExitCode == 1)
            throw new InvalidOperationException(errorMessage);
        throw new InvalidOperationException("Unable to validate Git commit ancestry.");
    }

    private static async Task RequireCleanWorkingTreeAsync(string repository)
    {
        var result = await RunGitAsync(repository, new[] { "status", "--porcelain=v1", "--untracked-files=all" }, 30);
        if (!string.IsNullOrWhiteSpace(result.StdOut))
            throw new InvalidOperationException("This Git operation requires a clean working tree, including no untracked files.");
    }

    private static async Task<string> GetStatusSnapshotSha256Async(string repository)
    {
        var result = await RunGitAsync(repository, new[] { "status", "--porcelain=v1", "--untracked-files=all" }, 30);
        return HashText(NormalizeText(result.StdOut));
    }

    private static async Task<string> GetStagedDiffSha256Async(string repository, bool requireChanges)
    {
        var quiet = await RunGitAsync(repository, new[] { "diff", "--cached", "--quiet", "--exit-code" }, 30, allowNonZero: true);
        if (quiet.ExitCode == 0 && requireChanges)
            throw new InvalidOperationException("No staged Git changes are available to commit.");
        if (quiet.ExitCode != 0 && quiet.ExitCode != 1)
            throw new InvalidOperationException("Unable to inspect staged Git changes.");

        var diff = await RunGitAsync(repository, new[] { "diff", "--cached", "--binary", "--no-ext-diff", "--no-textconv" }, 60);
        return HashText(NormalizeText(diff.StdOut));
    }

    private static async Task EnsureNoRepositoryLocalExternalFilterConfigAsync(string repository)
    {
        var result = await RunGitAsync(repository, new[] { "config", "--local", "--get-regexp", "^filter\\..*\\.(clean|smudge|process)$" }, 30, allowNonZero: true);
        if (result.ExitCode == 1)
            return;
        if (result.ExitCode != 0)
            throw new InvalidOperationException("Unable to inspect repository-local Git filter configuration.");
        if (!string.IsNullOrWhiteSpace(result.StdOut))
            throw new InvalidOperationException("Repository-local external Git filter commands are not allowed for this operation.");
    }

    private static async Task EnsureSelectedPathsHaveNoExternalFilterAsync(string repository, IReadOnlyList<string> paths)
    {
        var args = new List<string> { "check-attr", "filter", "--" };
        args.AddRange(paths);
        var result = await RunGitAsync(repository, args, 30);
        var lines = NormalizeText(result.StdOut).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var line in lines)
        {
            if (!line.EndsWith(": filter: unspecified", StringComparison.Ordinal) &&
                !line.EndsWith(": filter: unset", StringComparison.Ordinal))
                throw new InvalidOperationException("Selected Git paths use an external filter attribute and cannot be staged by this tool.");
        }
    }

    private static async Task<(string Remote, string RemoteBranch)> GetSameNameUpstreamAsync(string repository, string currentBranch)
    {
        var result = await RunGitAsync(
            repository,
            new[] { "for-each-ref", "--format=%(upstream:remotename)%09%(upstream:remoteref)", $"refs/heads/{currentBranch}" },
            30);
        var line = NormalizeText(result.StdOut);
        if (string.IsNullOrWhiteSpace(line))
            throw new InvalidOperationException("Current Git branch has no configured upstream.");

        var parts = line.Split('\t');
        if (parts.Length != 2 || string.IsNullOrWhiteSpace(parts[0]) || string.IsNullOrWhiteSpace(parts[1]))
            throw new InvalidOperationException("Unable to resolve the configured Git upstream.");

        var remote = parts[0].Trim();
        var remoteRef = parts[1].Trim();
        ValidateRemoteName(remote);
        if (string.Equals(remote, ".", StringComparison.Ordinal))
            throw new InvalidOperationException("Local-dot Git upstreams are not supported.");

        var expectedRemoteRef = $"refs/heads/{currentBranch}";
        if (!string.Equals(remoteRef, expectedRemoteRef, StringComparison.Ordinal))
            throw new InvalidOperationException($"Git pull/push requires a same-name upstream branch: {expectedRemoteRef}");

        return (remote, currentBranch);
    }

    private static async Task<string> GetSafeHttpsRemoteConfigSha256Async(string repository, string remote)
    {
        ValidateRemoteName(remote);
        var urlResult = await RunGitAsync(repository, new[] { "remote", "get-url", "--all", remote }, 30);
        var normalizedUrls = NormalizeText(urlResult.StdOut);
        var urls = normalizedUrls.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (urls.Length == 0)
            throw new InvalidOperationException($"Configured Git remote has no fetch URL: {remote}");

        foreach (var url in urls)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
                !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                string.IsNullOrWhiteSpace(uri.Host) ||
                !string.IsNullOrEmpty(uri.UserInfo))
                throw new InvalidOperationException("Git network operations support only configured credential-free HTTPS remote URLs.");
        }

        var refspecResult = await RunGitAsync(repository, new[] { "config", "--get-all", $"remote.{remote}.fetch" }, 30);
        var normalizedRefspecs = NormalizeText(refspecResult.StdOut);
        var refspecs = normalizedRefspecs.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var expectedRefspec = $"+refs/heads/*:refs/remotes/{remote}/*";
        if (refspecs.Length != 1 || !string.Equals(refspecs[0], expectedRefspec, StringComparison.Ordinal))
            throw new InvalidOperationException($"Git network operations require exactly the standard remote-tracking refspec: {expectedRefspec}");

        return HashText($"urls\n{normalizedUrls}\nfetch\n{normalizedRefspecs}");
    }

    private static async Task<GitProcessResult> RunGitAsync(
        string repository,
        IReadOnlyList<string> arguments,
        int timeoutSeconds,
        bool allowNonZero = false,
        bool networkHttpsOnly = false)
    {
        EnsureGitInstalled();
        var psi = new ProcessStartInfo
        {
            FileName = GitExe,
            WorkingDirectory = repository,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        psi.Environment["GIT_TERMINAL_PROMPT"] = "0";
        psi.Environment["GCM_INTERACTIVE"] = "Never";
        psi.Environment["GIT_PAGER"] = "cat";
        psi.Environment.Remove("GIT_ASKPASS");
        psi.Environment.Remove("SSH_ASKPASS");

        psi.ArgumentList.Add("--no-pager");
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add("core.hooksPath=NUL");
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add("core.fsmonitor=false");
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add("submodule.recurse=false");
        if (networkHttpsOnly)
        {
            _ = GetCredentialManagerSha256();
            var systemDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            psi.Environment["PATH"] = string.Join(Path.PathSeparator,
                Path.GetDirectoryName(GitCredentialManagerExe)!,
                Path.GetDirectoryName(GitExe)!,
                systemDirectory,
                windowsDirectory);

            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("credential.helper=");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("credential.helper=manager");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("credential.interactive=false");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("protocol.allow=never");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("protocol.https.allow=always");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("protocol.http.allow=never");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("protocol.ssh.allow=never");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("protocol.git.allow=never");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("protocol.file.allow=never");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("protocol.ext.allow=never");
        }

        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add($"safe.directory={repository}");
        psi.ArgumentList.Add("-C");
        psi.ArgumentList.Add(repository);
        foreach (var argument in arguments)
            psi.ArgumentList.Add(argument);

        using var process = Process.Start(psi) ?? throw new InvalidOperationException("git.exe failed to start.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        try
        {
            await process.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"git.exe exceeded {timeoutSeconds} seconds.");
        }

        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        var result = new GitProcessResult(process.ExitCode, stdout, stderr);
        if (!allowNonZero && result.ExitCode != 0)
        {
            var detail = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
            detail = detail.Length > 2000 ? detail[..2000] : detail;
            throw new InvalidOperationException($"git.exe exited with code {result.ExitCode}: {detail.Trim()}");
        }
        return result;
    }

    private static string NormalizeText(string text) =>
        text.Replace("\r\n", "\n", StringComparison.Ordinal).Trim();

    private static string HashText(string text) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    private static string RequireParameter(SignedPlan plan, string key)
    {
        if (!plan.Parameters.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
            throw new InvalidDataException($"{key} parameter is required.");
        return value;
    }

    private static void RequireIntentMatch(
        SignedPlan plan,
        string expectedOperation,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        if (!string.Equals(plan.Tool, "git", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }

    private sealed record GitProcessResult(int ExitCode, string StdOut, string StdErr);
}
