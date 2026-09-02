using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;
using YowThi.DevelopmentAgent3.Security;

namespace YowThi.DevelopmentAgent3.Git;

[McpServerToolType]
public static class GitFastForwardPromotionTools
{
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly ProtectedPathPolicy PathPolicy = new();
    private const string GitExe = @"C:\Program Files\Git\cmd\git.exe";

    [McpServerTool(Name = "git_fast_forward_promotion_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed plan to promote one validated local source branch into the currently checked-out local main branch using fast-forward-only semantics. Repository-wide worktree mutation preflight, clean state, branch identities, commits, ancestry, ahead/behind counts, status fingerprint, and fixed git.exe SHA-256 are sealed. The target is fixed to main. Merge commits, rebase, force, checkout, fetch, push, hooks, arbitrary refs, and production repositories are not supported.")]
    public static async Task<SignedPlan> GitFastForwardPromotionPlan(string repository, string sourceBranch, string targetBranch = "main")
    {
        var repo = await ValidateRepositoryAsync(repository);
        ValidateBranchName(sourceBranch, nameof(sourceBranch));
        ValidateBranchName(targetBranch, nameof(targetBranch));
        if (!string.Equals(targetBranch, "main", StringComparison.Ordinal))
            throw new InvalidOperationException("targetBranch is fixed to main.");
        if (string.Equals(sourceBranch, targetBranch, StringComparison.Ordinal))
            throw new InvalidOperationException("sourceBranch must differ from main.");

        var preflight = await GitWorktreePreflightTools.GitWorktreeMutationPreflight(repo, targetBranch, true);
        if (!preflight.EligibleForMutation)
            throw new InvalidOperationException("Repository-wide mutation preflight blocked promotion: " + string.Join(" | ", preflight.BlockingReasons));
        if (!string.Equals(preflight.CurrentBranch, targetBranch, StringComparison.Ordinal))
            throw new InvalidOperationException("The requested worktree must currently have main checked out.");

        var sourceCommit = await GetBranchCommitAsync(repo, sourceBranch);
        var targetCommit = await GetBranchCommitAsync(repo, targetBranch);
        if (!string.Equals(preflight.Head, targetCommit, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Checked-out HEAD does not match local main.");
        await RequireAncestorAsync(repo, targetCommit, sourceCommit);

        var (behind, ahead) = await GetAheadBehindAsync(repo, targetCommit, sourceCommit);
        if (behind != 0 || ahead <= 0)
            throw new InvalidOperationException($"Fast-forward eligibility failed: ahead={ahead}, behind={behind}.");

        var preflightSha256 = GetPreflightSha256(preflight);
        var gitSha256 = GetFileSha256(GitExe);
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["repository"] = repo,
            ["sourceBranch"] = sourceBranch,
            ["targetBranch"] = targetBranch,
            ["sourceCommit"] = sourceCommit,
            ["targetCommit"] = targetCommit,
            ["ahead"] = ahead.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["behind"] = behind.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["preflightSha256"] = preflightSha256,
            ["gitSha256"] = gitSha256
        };
        var summary = $"Fast-forward local main {targetCommit[..12]} to validated branch {sourceBranch} at {sourceCommit[..12]} (ahead={ahead}, behind={behind}) in {repo}";
        return CreatePlan(repo, parameters, summary);
    }

    [McpServerTool(Name = "git_fast_forward_promotion_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one signed git/git-fast-forward-promotion plan using fixed git merge --ff-only --no-edit semantics. Repository-wide worktree preflight, checked-out main, commits, ancestry, ahead/behind counts, state fingerprint, and git.exe SHA-256 are revalidated immediately before mutation. No checkout, merge commit, rebase, force, fetch, push, hooks, editor, signing, arbitrary refs, or arbitrary commands are used.")]
    public static async Task<GitFastForwardPromotionResult> GitFastForwardPromotionExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, operation, target, summary, riskClass);
        var repo = Require(plan, "repository");
        var sourceBranch = Require(plan, "sourceBranch");
        var targetBranch = Require(plan, "targetBranch");
        var expectedSource = Require(plan, "sourceCommit");
        var expectedTarget = Require(plan, "targetCommit");
        var expectedAhead = Require(plan, "ahead");
        var expectedBehind = Require(plan, "behind");
        var expectedPreflight = Require(plan, "preflightSha256");
        var expectedGit = Require(plan, "gitSha256");

        _ = await ValidateRepositoryAsync(repo);
        if (!string.Equals(targetBranch, "main", StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Signed target branch is not main.");
        if (!string.Equals(GetFileSha256(GitExe), expectedGit, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("git.exe changed after plan creation.");

        var preflight = await GitWorktreePreflightTools.GitWorktreeMutationPreflight(repo, targetBranch, true);
        if (!preflight.EligibleForMutation)
            throw new InvalidOperationException("Repository-wide mutation preflight blocked execution: " + string.Join(" | ", preflight.BlockingReasons));
        if (!string.Equals(GetPreflightSha256(preflight), expectedPreflight, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Repository-wide preflight state changed after plan creation.");
        if (!string.Equals(preflight.CurrentBranch, targetBranch, StringComparison.Ordinal))
            throw new InvalidOperationException("main is no longer checked out.");

        var actualSource = await GetBranchCommitAsync(repo, sourceBranch);
        var actualTarget = await GetBranchCommitAsync(repo, targetBranch);
        if (!string.Equals(actualSource, expectedSource, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(actualTarget, expectedTarget, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(preflight.Head, expectedTarget, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Branch commits changed after plan creation.");

        await RequireAncestorAsync(repo, actualTarget, actualSource);
        var (behind, ahead) = await GetAheadBehindAsync(repo, actualTarget, actualSource);
        if (!string.Equals(ahead.ToString(System.Globalization.CultureInfo.InvariantCulture), expectedAhead, StringComparison.Ordinal) ||
            !string.Equals(behind.ToString(System.Globalization.CultureInfo.InvariantCulture), expectedBehind, StringComparison.Ordinal) ||
            behind != 0 || ahead <= 0)
            throw new InvalidOperationException("Ahead/behind evidence changed after plan creation.");

        try
        {
            var result = await RunGitAsync(repo, new[] { "merge", "--ff-only", "--no-edit", sourceBranch }, 120);
            var newHead = await GetBranchCommitAsync(repo, targetBranch);
            if (!string.Equals(newHead, actualSource, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Fast-forward completed but main does not equal the sealed source commit.");
            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, oldHead = actualTarget, newHead, sourceBranch, ahead, behind }, "executed");
            return new GitFastForwardPromotionResult(plan.PlanId, repo, sourceBranch, targetBranch, actualTarget, newHead, ahead, behind, result.ExitCode, result.StdOut, result.StdErr, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    private static SignedPlan CreatePlan(string repo, Dictionary<string, string> parameters, string summary)
    {
        var now = DateTimeOffset.UtcNow;
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "git", "git-fast-forward-promotion", repo, parameters, RiskClass.Medium, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    private static async Task<string> ValidateRepositoryAsync(string repository)
    {
        if (string.IsNullOrWhiteSpace(repository) || !Path.IsPathFullyQualified(repository))
            throw new ArgumentException("Repository must be an absolute path.", nameof(repository));
        var full = PathPolicy.RequireMutable(repository).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException(full);
        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Repository root may not be a reparse point.");
        var top = (await RunGitAsync(full, new[] { "rev-parse", "--show-toplevel" }, 30)).StdOut.Trim();
        if (!string.Equals(Path.GetFullPath(top).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), full, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("repository must be the Git worktree root.");
        return full;
    }

    private static void ValidateBranchName(string branch, string parameter)
    {
        if (string.IsNullOrWhiteSpace(branch) || branch.Length > 128 || branch[0] is '-' or '.' or '/' ||
            branch.EndsWith('.') || branch.EndsWith('/') || branch.Contains("..", StringComparison.Ordinal) ||
            branch.Contains("//", StringComparison.Ordinal) || branch.Contains("@{", StringComparison.Ordinal) ||
            branch.EndsWith(".lock", StringComparison.OrdinalIgnoreCase) ||
            branch.Any(c => !(char.IsLetterOrDigit(c) || c is '.' or '_' or '-' or '/')))
            throw new ArgumentException("Branch name is invalid.", parameter);
    }

    private static async Task<string> GetBranchCommitAsync(string repo, string branch) =>
        (await RunGitAsync(repo, new[] { "rev-parse", "--verify", $"refs/heads/{branch}" }, 30)).StdOut.Trim();

    private static async Task RequireAncestorAsync(string repo, string ancestor, string descendant)
    {
        var result = await RunGitAsync(repo, new[] { "merge-base", "--is-ancestor", ancestor, descendant }, 30, true);
        if (result.ExitCode == 1) throw new InvalidOperationException("main is not an ancestor of the validated source branch.");
        if (result.ExitCode != 0) throw new InvalidOperationException("Unable to validate commit ancestry.");
    }

    private static async Task<(int Behind, int Ahead)> GetAheadBehindAsync(string repo, string target, string source)
    {
        var text = (await RunGitAsync(repo, new[] { "rev-list", "--left-right", "--count", $"{target}...{source}" }, 30)).StdOut.Trim();
        var parts = text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 2 || !int.TryParse(parts[0], out var behind) || !int.TryParse(parts[1], out var ahead))
            throw new InvalidOperationException("Unable to parse ahead/behind counts.");
        return (behind, ahead);
    }

    private static async Task<CliResult> RunGitAsync(string repo, IReadOnlyList<string> args, int timeoutSeconds, bool allowNonZero = false)
    {
        _ = GetFileSha256(GitExe);
        var psi = new ProcessStartInfo { FileName = GitExe, WorkingDirectory = repo, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
        psi.Environment["GIT_TERMINAL_PROMPT"] = "0";
        psi.Environment["GIT_PAGER"] = "cat";
        psi.Environment["GIT_EXTERNAL_DIFF"] = string.Empty;
        psi.Environment["NO_COLOR"] = "1";
        psi.ArgumentList.Add("--no-pager");
        psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("core.hooksPath=NUL");
        psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("core.fsmonitor=false");
        psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("diff.external=");
        psi.ArgumentList.Add("-c"); psi.ArgumentList.Add($"safe.directory={repo}");
        psi.ArgumentList.Add("-C"); psi.ArgumentList.Add(repo);
        foreach (var arg in args) psi.ArgumentList.Add(arg);
        using var process = Process.Start(psi) ?? throw new InvalidOperationException("git.exe failed to start.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"git.exe exceeded {timeoutSeconds} seconds.");
        }
        var result = new CliResult(process.ExitCode, await stdout, await stderr);
        if (!allowNonZero && result.ExitCode != 0) throw new InvalidOperationException($"git.exe exited with code {result.ExitCode}: {result.StdErr.Trim()}");
        return result;
    }

    private static string Require(SignedPlan plan, string name) =>
        plan.Parameters.TryGetValue(name, out var value) ? value : throw new InvalidDataException($"{name} is required.");

    private static void RequireIntentMatch(SignedPlan plan, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "git", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, "git-fast-forward-promotion", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }

    private static string GetFileSha256(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException("git.exe not found.", path);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("git.exe may not be a reparse point.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string GetPreflightSha256(GitWorktreeMutationPreflightResult value) =>
        HashText(JsonSerializer.Serialize(new
        {
            value.Repository,
            value.CommonGitDirectory,
            value.CurrentBranch,
            value.Head,
            value.IntendedBranch,
            value.RequireAllWorktreesClean,
            value.EligibleForMutation,
            value.BlockingReasons,
            value.Worktrees,
            value.GitExeSha256
        }));

    private static string HashText(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
    private sealed record CliResult(int ExitCode, string StdOut, string StdErr);
}

public sealed record GitFastForwardPromotionResult(
    string PlanId,
    string Repository,
    string SourceBranch,
    string TargetBranch,
    string OldHead,
    string NewHead,
    int Ahead,
    int Behind,
    int ExitCode,
    string StdOut,
    string StdErr,
    DateTimeOffset ExecutedUtc);
