using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;
using YowThi.DevelopmentAgent3.Security;

namespace YowThi.DevelopmentAgent3.Git;

[McpServerToolType]
public static class GitTools
{
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly ProtectedPathPolicy PathPolicy = new();

    private const string GitExe = @"C:\Program Files\Git\cmd\git.exe";
    private const string GitCredentialManagerExe = @"C:\Program Files\Git\mingw64\bin\git-credential-manager.exe";

    [McpServerTool(Name = "git_status", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read Git working-tree status for one absolute repository root using the fixed git.exe binary. Frozen production repositories may be inspected. Hooks and filesystem-monitor commands are disabled. No PowerShell, cmd, or arbitrary Git command is accepted.")]
    public static async Task<GitStatusResult> GitStatus(string repository)
    {
        var repo = await ValidateRepositoryAsync(repository, requireMutable: false);
        var branch = await GetCurrentBranchAsync(repo);
        var head = await GetHeadAsync(repo);
        var status = await RunGitAsync(repo, new[] { "status", "--short", "--branch", "--untracked-files=normal" }, 30);
        return new GitStatusResult(repo, branch, head, status.StdOut, status.StdErr, DateTimeOffset.UtcNow);
    }

    [McpServerTool(Name = "git_branch_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List local and remote-tracking Git branches for one absolute repository root using the fixed git.exe binary. Frozen production repositories may be inspected. Hooks and filesystem-monitor commands are disabled. No PowerShell, cmd, or arbitrary Git command is accepted.")]
    public static async Task<GitBranchListResult> GitBranchList(string repository)
    {
        var repo = await ValidateRepositoryAsync(repository, requireMutable: false);
        var branches = await RunGitAsync(repo, new[] { "branch", "--all", "--no-color", "--verbose", "--no-abbrev" }, 30);
        return new GitBranchListResult(repo, branches.StdOut, branches.StdErr, DateTimeOffset.UtcNow);
    }

    [McpServerTool(Name = "git_fetch_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed plan to fetch one existing configured HTTPS Git remote by remote name. The repository must be mutable. The HTTPS URL set, standard remote-tracking fetch refspec, and fixed Git Credential Manager SHA-256 are sealed into the plan. Arbitrary URLs, refspecs, credential helpers, commands, hooks, and non-HTTPS transports are not accepted.")]
    public static async Task<SignedPlan> GitFetchPlan(string repository, string remote = "origin")
    {
        var repo = await ValidateRepositoryAsync(repository, requireMutable: true);
        ValidateRemoteName(remote);
        var remoteConfigSha256 = await GetSafeHttpsRemoteConfigSha256Async(repo, remote);
        var credentialManagerSha256 = GetCredentialManagerSha256();

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["repository"] = repo,
            ["remote"] = remote,
            ["remoteConfigSha256"] = remoteConfigSha256,
            ["credentialManagerSha256"] = credentialManagerSha256
        };
        var summary = $"Fetch configured Git remote {remote} in {repo} (remote-config-sha256={remoteConfigSha256[..12]}, gcm-sha256={credentialManagerSha256[..12]})";
        return CreatePlan("git-fetch", repo, parameters, RiskClass.Medium, summary);
    }

    [McpServerTool(Name = "git_fetch_execute", ReadOnly = false, Destructive = false, OpenWorld = true)]
    [Description("Execute one previously prepared git/git-fetch plan using the fixed git.exe binary and the fixed Git Credential Manager only. The signed HTTPS remote configuration, standard remote-tracking refspec, and Credential Manager SHA-256 are rechecked. Credential prompts are disabled; only already-available stored credentials may be used. Hooks, arbitrary credential helpers, submodule recursion, arbitrary URLs, refspecs, commands, and non-HTTPS transports are disabled.")]
    public static async Task<GitExecutionResult> GitFetchExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "git-fetch", operation, target, summary, riskClass);
        var repo = await ValidateRepositoryAsync(RequireParameter(plan, "repository"), requireMutable: true);
        var remote = RequireParameter(plan, "remote");
        ValidateRemoteName(remote);
        var expectedRemoteConfigSha256 = RequireParameter(plan, "remoteConfigSha256");
        var expectedCredentialManagerSha256 = RequireParameter(plan, "credentialManagerSha256");
        var actualRemoteConfigSha256 = await GetSafeHttpsRemoteConfigSha256Async(repo, remote);
        var actualCredentialManagerSha256 = GetCredentialManagerSha256();
        if (!string.Equals(expectedRemoteConfigSha256, actualRemoteConfigSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Git remote configuration changed after plan creation.");
        if (!string.Equals(expectedCredentialManagerSha256, actualCredentialManagerSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Git Credential Manager binary changed after plan creation.");

        try
        {
            var result = await RunGitAsync(repo, new[] { "fetch", "--no-recurse-submodules", remote }, 300, networkHttpsOnly: true);
            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new
            {
                plan.PlanId,
                remote,
                remoteConfigSha256 = actualRemoteConfigSha256,
                credentialManagerSha256 = actualCredentialManagerSha256,
                result.ExitCode
            }, "executed");
            return new GitExecutionResult(plan.PlanId, plan.Operation, repo, remote, result.ExitCode, result.StdOut, result.StdErr, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, remote, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "git_branch_create_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed plan to create one local Git branch at the repository's current HEAD. The repository must be mutable. The current HEAD commit is sealed into the plan. Branch names are validated and arbitrary Git commands are not accepted.")]
    public static async Task<SignedPlan> GitBranchCreatePlan(string repository, string branchName)
    {
        var repo = await ValidateRepositoryAsync(repository, requireMutable: true);
        await ValidateBranchNameAsync(repo, branchName);
        if (await LocalBranchExistsAsync(repo, branchName))
            throw new InvalidOperationException($"Local branch already exists: {branchName}");

        var baseCommit = await GetHeadAsync(repo);
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["repository"] = repo,
            ["branchName"] = branchName,
            ["baseCommit"] = baseCommit
        };
        var summary = $"Create local Git branch {branchName} at {baseCommit[..12]} in {repo}";
        return CreatePlan("git-branch-create", repo, parameters, RiskClass.Medium, summary);
    }

    [McpServerTool(Name = "git_branch_create_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared git/git-branch-create plan using the fixed git.exe binary. The repository, validated branch name, and sealed HEAD commit are rechecked before branch creation. Hooks and arbitrary Git commands are disabled.")]
    public static async Task<GitExecutionResult> GitBranchCreateExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "git-branch-create", operation, target, summary, riskClass);
        var repo = await ValidateRepositoryAsync(RequireParameter(plan, "repository"), requireMutable: true);
        var branchName = RequireParameter(plan, "branchName");
        var baseCommit = RequireParameter(plan, "baseCommit");
        await ValidateBranchNameAsync(repo, branchName);
        if (await LocalBranchExistsAsync(repo, branchName))
            throw new InvalidOperationException($"Local branch already exists: {branchName}");
        var currentHead = await GetHeadAsync(repo);
        if (!string.Equals(baseCommit, currentHead, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Repository HEAD changed after plan creation.");

        try
        {
            var result = await RunGitAsync(repo, new[] { "branch", "--no-track", branchName, baseCommit }, 30);
            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, branchName, baseCommit, result.ExitCode }, "executed");
            return new GitExecutionResult(plan.PlanId, plan.Operation, repo, branchName, result.ExitCode, result.StdOut, result.StdErr, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, branchName, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "git_branch_switch_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed plan to switch a clean Git working tree to one existing local branch. The repository must be mutable. Current HEAD, current branch, and target branch commit are sealed into the plan. Dirty working trees and arbitrary Git commands are not accepted.")]
    public static async Task<SignedPlan> GitBranchSwitchPlan(string repository, string branchName)
    {
        var repo = await ValidateRepositoryAsync(repository, requireMutable: true);
        await ValidateBranchNameAsync(repo, branchName);
        if (!await LocalBranchExistsAsync(repo, branchName))
            throw new InvalidOperationException($"Local branch does not exist: {branchName}");
        await RequireCleanWorkingTreeAsync(repo);

        var currentBranch = await GetCurrentBranchAsync(repo);
        if (string.Equals(currentBranch, branchName, StringComparison.Ordinal))
            throw new InvalidOperationException($"Branch is already checked out: {branchName}");
        var currentHead = await GetHeadAsync(repo);
        var targetCommit = await GetLocalBranchCommitAsync(repo, branchName);

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["repository"] = repo,
            ["branchName"] = branchName,
            ["currentBranch"] = currentBranch,
            ["currentHead"] = currentHead,
            ["targetCommit"] = targetCommit
        };
        var summary = $"Switch clean Git working tree {repo} from {DisplayBranch(currentBranch)} to {branchName} at {targetCommit[..12]}";
        return CreatePlan("git-branch-switch", repo, parameters, RiskClass.Medium, summary);
    }

    [McpServerTool(Name = "git_branch_switch_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared git/git-branch-switch plan using the fixed git.exe binary. The working tree must still be clean, and the current HEAD, current branch, and target branch commit must still match the signed plan. Hooks and arbitrary Git commands are disabled.")]
    public static async Task<GitExecutionResult> GitBranchSwitchExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "git-branch-switch", operation, target, summary, riskClass);
        var repo = await ValidateRepositoryAsync(RequireParameter(plan, "repository"), requireMutable: true);
        var branchName = RequireParameter(plan, "branchName");
        var expectedCurrentBranch = RequireParameter(plan, "currentBranch");
        var expectedCurrentHead = RequireParameter(plan, "currentHead");
        var expectedTargetCommit = RequireParameter(plan, "targetCommit");
        await ValidateBranchNameAsync(repo, branchName);
        if (!await LocalBranchExistsAsync(repo, branchName))
            throw new InvalidOperationException($"Local branch does not exist: {branchName}");
        await RequireCleanWorkingTreeAsync(repo);

        var actualCurrentBranch = await GetCurrentBranchAsync(repo);
        var actualCurrentHead = await GetHeadAsync(repo);
        var actualTargetCommit = await GetLocalBranchCommitAsync(repo, branchName);
        if (!string.Equals(expectedCurrentBranch, actualCurrentBranch, StringComparison.Ordinal) ||
            !string.Equals(expectedCurrentHead, actualCurrentHead, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expectedTargetCommit, actualTargetCommit, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Git branch state changed after plan creation.");

        try
        {
            var result = await RunGitAsync(repo, new[] { "switch", branchName }, 60);
            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, branchName, expectedCurrentHead, expectedTargetCommit, result.ExitCode }, "executed");
            return new GitExecutionResult(plan.PlanId, plan.Operation, repo, branchName, result.ExitCode, result.StdOut, result.StdErr, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, branchName, error = ex.Message }, "failed");
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
                throw new ArgumentException("Git v1 branch names may contain only letters, digits, '.', '_', '-' and '/'.", nameof(branchName));
        }

        var check = await RunGitAsync(repository, new[] { "check-ref-format", "--branch", branchName }, 30, allowNonZero: true);
        if (check.ExitCode != 0)
            throw new ArgumentException("Branch name failed git check-ref-format validation.", nameof(branchName));
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
        if (head.Length < 12) throw new InvalidOperationException("Unable to resolve Git HEAD commit.");
        return head;
    }

    private static async Task<string> GetLocalBranchCommitAsync(string repository, string branchName)
    {
        var result = await RunGitAsync(repository, new[] { "rev-parse", "--verify", $"refs/heads/{branchName}" }, 30);
        var commit = result.StdOut.Trim();
        if (commit.Length < 12) throw new InvalidOperationException("Unable to resolve local branch commit.");
        return commit;
    }

    private static async Task RequireCleanWorkingTreeAsync(string repository)
    {
        var result = await RunGitAsync(repository, new[] { "status", "--porcelain=v1", "--untracked-files=all" }, 30);
        if (!string.IsNullOrWhiteSpace(result.StdOut))
            throw new InvalidOperationException("Git branch switch requires a clean working tree, including no untracked files.");
    }

    private static async Task<string> GetSafeHttpsRemoteConfigSha256Async(string repository, string remote)
    {
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
                throw new InvalidOperationException("Git v1 fetch supports only configured credential-free HTTPS remote URLs.");
        }

        var refspecResult = await RunGitAsync(repository, new[] { "config", "--get-all", $"remote.{remote}.fetch" }, 30);
        var normalizedRefspecs = NormalizeText(refspecResult.StdOut);
        var refspecs = normalizedRefspecs.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var expectedRefspec = $"+refs/heads/*:refs/remotes/{remote}/*";
        if (refspecs.Length != 1 || !string.Equals(refspecs[0], expectedRefspec, StringComparison.Ordinal))
            throw new InvalidOperationException($"Git v1 fetch requires exactly the standard remote-tracking refspec: {expectedRefspec}");

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

    private static string NormalizeText(string text) => text.Replace("\r\n", "\n", StringComparison.Ordinal).Trim();

    private static string HashText(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    private static string DisplayBranch(string branch) => string.IsNullOrWhiteSpace(branch) ? "detached-HEAD" : branch;

    private static string RequireParameter(SignedPlan plan, string key)
    {
        if (!plan.Parameters.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
            throw new InvalidDataException($"{key} parameter is required.");
        return value;
    }

    private static void RequireIntentMatch(SignedPlan plan, string expectedOperation, string operation, string target, string summary, string riskClass)
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

public sealed record GitStatusResult(
    string Repository,
    string Branch,
    string Head,
    string Status,
    string StdErr,
    DateTimeOffset CheckedUtc);

public sealed record GitBranchListResult(
    string Repository,
    string Branches,
    string StdErr,
    DateTimeOffset CheckedUtc);

public sealed record GitExecutionResult(
    string PlanId,
    string Operation,
    string Repository,
    string Subject,
    int ExitCode,
    string StdOut,
    string StdErr,
    DateTimeOffset ExecutedUtc);