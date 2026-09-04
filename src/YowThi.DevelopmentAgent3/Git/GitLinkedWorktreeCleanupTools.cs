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
public static class GitLinkedWorktreeCleanupTools
{
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly ProtectedPathPolicy PathPolicy = new();
    private const string GitExe = @"C:\Program Files\Git\cmd\git.exe";
    private const string DevelopmentRoot = @"C:\Dev";

    [McpServerTool(Name = "git_linked_worktree_cleanup_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed Medium-risk plan to remove exactly one clean unlocked linked Git worktree under C:\\Dev. The caller supplies the repository root and exact linked worktree path. The linked worktree must be non-current, exist, not be a reparse point, have a p*-validation or m*-validation branch, contain no tracked or untracked changes, and its branch HEAD must already be fully merged into local main. Repository identity, common Git directory, worktree path/HEAD/branch, main HEAD, complete clean preflight state, and git.exe SHA-256 are sealed. Force removal, branch deletion, arbitrary Git arguments, production repositories, and paths outside C:\\Dev are not supported.")]
    public static async Task<SignedPlan> GitLinkedWorktreeCleanupPlan(string repository, string linkedWorktreePath)
    {
        var repo = await ValidateRepositoryAsync(repository);
        var targetPath = NormalizePath(linkedWorktreePath);
        if (!IsUnderDevelopmentRoot(targetPath) || string.Equals(targetPath, repo, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Target must be a distinct linked worktree under C:\\Dev.");

        var preflight = await GitWorktreePreflightTools.GitWorktreeMutationPreflight(repo, "main", true);
        if (!preflight.EligibleForMutation)
            throw new InvalidOperationException("Repository-wide mutation preflight blocked worktree cleanup: " + string.Join(" | ", preflight.BlockingReasons));
        if (!string.Equals(preflight.CurrentBranch, "main", StringComparison.Ordinal))
            throw new InvalidOperationException("Primary repository must currently have main checked out.");

        var target = preflight.Worktrees.SingleOrDefault(x => string.Equals(x.Path, targetPath, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("Target path is not a registered linked worktree.");
        ValidateTarget(target);

        var mainHead = await GetBranchCommitAsync(repo, "main");
        if (!string.Equals(preflight.Head, mainHead, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Primary worktree HEAD does not match local main.");
        await RequireAncestorAsync(repo, target.Head, mainHead);

        var gitSha = GetFileSha256(GitExe);
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["repository"] = repo,
            ["commonGitDirectory"] = preflight.CommonGitDirectory,
            ["linkedWorktreePath"] = target.Path,
            ["linkedBranch"] = target.Branch,
            ["linkedBranchRef"] = target.BranchRef ?? string.Empty,
            ["linkedHead"] = target.Head,
            ["mainHead"] = mainHead,
            ["preflightSha256"] = HashPreflight(preflight),
            ["gitSha256"] = gitSha
        };
        var summary = $"Remove clean merged linked worktree {target.Path} on {target.Branch} at {target.Head[..12]} from {repo}; branch is retained";
        return CreatePlan(target.Path, parameters, summary);
    }

    [McpServerTool(Name = "git_linked_worktree_cleanup_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared git/git-linked-worktree-cleanup plan using fixed git worktree remove semantics without --force. Repository-wide clean state, primary main identity, common Git directory, target linked worktree path/HEAD/branch, validation-branch naming, unlocked/non-prunable/non-reparse state, merged ancestry, and git.exe SHA-256 are revalidated immediately before removal. Post-remove read-back must prove the linked worktree is absent from git worktree list and its directory no longer exists. The branch itself is retained for separate safe branch deletion. Arbitrary Git arguments, force removal, branch deletion, and production repositories are not supported.")]
    public static async Task<GitLinkedWorktreeCleanupResult> GitLinkedWorktreeCleanupExecute(string planId, string approvalCode)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        if (!string.Equals(plan.Tool, "git", StringComparison.Ordinal) || !string.Equals(plan.Operation, "git-linked-worktree-cleanup", StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Git linked worktree cleanup plan intent mismatch.");

        var repo = Require(plan, "repository");
        var targetPath = Require(plan, "linkedWorktreePath");
        var linkedBranch = Require(plan, "linkedBranch");
        var linkedRef = Require(plan, "linkedBranchRef");
        var linkedHead = Require(plan, "linkedHead");
        var mainHead = Require(plan, "mainHead");
        var commonGit = Require(plan, "commonGitDirectory");
        var expectedPreflight = Require(plan, "preflightSha256");
        var expectedGit = Require(plan, "gitSha256");

        _ = await ValidateRepositoryAsync(repo);
        if (!string.Equals(GetFileSha256(GitExe), expectedGit, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("git.exe changed after plan creation.");

        var preflight = await GitWorktreePreflightTools.GitWorktreeMutationPreflight(repo, "main", true);
        if (!preflight.EligibleForMutation)
            throw new InvalidOperationException("Repository-wide mutation preflight blocked execution: " + string.Join(" | ", preflight.BlockingReasons));
        if (!string.Equals(HashPreflight(preflight), expectedPreflight, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(preflight.CommonGitDirectory, commonGit, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(preflight.CurrentBranch, "main", StringComparison.Ordinal))
            throw new InvalidOperationException("Repository/worktree preflight state changed after plan creation.");

        var target = preflight.Worktrees.SingleOrDefault(x => string.Equals(x.Path, targetPath, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("Linked worktree is no longer registered.");
        ValidateTarget(target);
        if (!string.Equals(target.Head, linkedHead, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(target.Branch, linkedBranch, StringComparison.Ordinal) ||
            !string.Equals(target.BranchRef ?? string.Empty, linkedRef, StringComparison.Ordinal))
            throw new InvalidOperationException("Linked worktree identity changed after plan creation.");

        var actualMain = await GetBranchCommitAsync(repo, "main");
        if (!string.Equals(actualMain, mainHead, StringComparison.OrdinalIgnoreCase) || !string.Equals(preflight.Head, mainHead, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("main changed after plan creation.");
        await RequireAncestorAsync(repo, linkedHead, actualMain);

        try
        {
            var result = await RunGitAsync(repo, new[] { "worktree", "remove", targetPath }, 120);
            if (Directory.Exists(targetPath))
                throw new IOException("Linked worktree directory still exists after git worktree remove.");
            var remaining = await GitWorktreePreflightTools.GitWorktreeMutationPreflight(repo, "main", true);
            if (remaining.Worktrees.Any(x => string.Equals(x.Path, targetPath, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException("Linked worktree remains registered after removal.");

            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, targetPath, linkedBranch, linkedHead, outcome = "removed-branch-retained" }, "executed");
            return new GitLinkedWorktreeCleanupResult(plan.PlanId, repo, targetPath, linkedBranch, linkedHead, actualMain, result.ExitCode, result.StdOut, result.StdErr, "removed-branch-retained", DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, targetPath, error = ex.Message }, "failed");
            throw;
        }
    }

    private static void ValidateTarget(GitWorktreePreflightEntry target)
    {
        if (target.IsRequestedWorktree) throw new InvalidOperationException("Primary/current worktree cannot be removed.");
        if (!target.Exists || !target.UnderDevelopmentRoot || target.ReparsePoint) throw new InvalidOperationException("Linked worktree path is unsafe.");
        if (target.Locked) throw new InvalidOperationException("Linked worktree is locked.");
        if (target.Prunable) throw new InvalidOperationException("Prunable worktrees are not accepted by this cleanup capability.");
        if (target.Dirty || target.StatusTruncated || target.StatusEntryCount != 0 || target.InspectionError is not null)
            throw new InvalidOperationException("Linked worktree must be completely clean and inspectable.");
        ValidateValidationBranch(target.Branch);
        if (string.IsNullOrWhiteSpace(target.BranchRef) || !target.BranchRef.StartsWith("refs/heads/", StringComparison.Ordinal))
            throw new InvalidOperationException("Linked worktree must have a local branch checked out.");
    }

    private static void ValidateValidationBranch(string branch)
    {
        if (!(branch.StartsWith("p", StringComparison.Ordinal) || branch.StartsWith("m", StringComparison.Ordinal)) ||
            !branch.EndsWith("-validation", StringComparison.Ordinal) || branch.Length > 128 ||
            branch.Any(c => !(char.IsLetterOrDigit(c) || c is '.' or '_' or '-' or '/')))
            throw new InvalidOperationException("Linked worktree branch must be a p*-validation or m*-validation branch.");
    }

    private static async Task<string> ValidateRepositoryAsync(string repository)
    {
        if (string.IsNullOrWhiteSpace(repository) || !Path.IsPathFullyQualified(repository)) throw new ArgumentException("Repository must be absolute.", nameof(repository));
        var full = PathPolicy.RequireMutable(repository).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!Directory.Exists(full) || (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("Repository root is unavailable or unsafe.");
        var top = NormalizePath((await RunGitAsync(full, new[] { "rev-parse", "--show-toplevel" }, 30)).StdOut.Trim());
        if (!string.Equals(top, full, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("repository must be the Git worktree root.");
        return full;
    }

    private static async Task<string> GetBranchCommitAsync(string repo, string branch) =>
        (await RunGitAsync(repo, new[] { "rev-parse", "--verify", $"refs/heads/{branch}" }, 30)).StdOut.Trim();

    private static async Task RequireAncestorAsync(string repo, string ancestor, string descendant)
    {
        var result = await RunGitAsync(repo, new[] { "merge-base", "--is-ancestor", ancestor, descendant }, 30, true);
        if (result.ExitCode == 1) throw new InvalidOperationException("Linked branch HEAD is not fully merged into main.");
        if (result.ExitCode != 0) throw new InvalidOperationException("Unable to validate merged ancestry.");
    }

    private static SignedPlan CreatePlan(string target, Dictionary<string, string> parameters, string summary)
    {
        var now = DateTimeOffset.UtcNow;
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "git", "git-linked-worktree-cleanup", target, parameters, RiskClass.Medium, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    private static string Require(SignedPlan plan, string key) => plan.Parameters.TryGetValue(key, out var value) ? value : throw new InvalidDataException($"{key} is required.");
    private static string NormalizePath(string path) => Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    private static bool IsUnderDevelopmentRoot(string path) => NormalizePath(path).StartsWith(NormalizePath(DevelopmentRoot) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    private static string HashPreflight(GitWorktreeMutationPreflightResult value) => HashText(System.Text.Json.JsonSerializer.Serialize(new { value.Repository, value.CommonGitDirectory, value.CurrentBranch, value.Head, value.IntendedBranch, value.RequireAllWorktreesClean, value.EligibleForMutation, value.BlockingReasons, value.Worktrees, value.GitExeSha256 }));
    private static string HashText(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
    private static string GetFileSha256(string path)
    {
        if (!File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new FileNotFoundException("git.exe unavailable or unsafe.", path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static async Task<CliResult> RunGitAsync(string repo, IReadOnlyList<string> args, int timeoutSeconds, bool allowNonZero = false)
    {
        _ = GetFileSha256(GitExe);
        var psi = new ProcessStartInfo { FileName = GitExe, WorkingDirectory = repo, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
        psi.Environment["GIT_TERMINAL_PROMPT"] = "0"; psi.Environment["GIT_PAGER"] = "cat"; psi.Environment["GIT_EXTERNAL_DIFF"] = string.Empty; psi.Environment["NO_COLOR"] = "1";
        psi.ArgumentList.Add("--no-pager"); psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("core.hooksPath=NUL"); psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("core.fsmonitor=false"); psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("diff.external="); psi.ArgumentList.Add("-c"); psi.ArgumentList.Add($"safe.directory={repo}"); psi.ArgumentList.Add("-C"); psi.ArgumentList.Add(repo);
        foreach (var arg in args) psi.ArgumentList.Add(arg);
        using var process = Process.Start(psi) ?? throw new InvalidOperationException("git.exe failed to start.");
        var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        try { await process.WaitForExitAsync(timeout.Token); } catch (OperationCanceledException) { try { process.Kill(true); } catch { } throw new TimeoutException($"git.exe exceeded {timeoutSeconds} seconds."); }
        var result = new CliResult(process.ExitCode, await stdout, await stderr);
        if (!allowNonZero && result.ExitCode != 0) throw new InvalidOperationException($"git.exe exited with code {result.ExitCode}: {result.StdErr.Trim()}");
        return result;
    }

    private sealed record CliResult(int ExitCode, string StdOut, string StdErr);
}

public sealed record GitLinkedWorktreeCleanupResult(string PlanId, string Repository, string LinkedWorktreePath, string LinkedBranch, string LinkedHead, string MainHead, int ExitCode, string StdOut, string StdErr, string Outcome, DateTimeOffset ExecutedUtc);
