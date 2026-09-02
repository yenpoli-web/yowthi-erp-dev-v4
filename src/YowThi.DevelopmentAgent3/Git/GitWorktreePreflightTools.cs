using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;

namespace YowThi.DevelopmentAgent3.Git;

[McpServerToolType]
public static class GitWorktreePreflightTools
{
    private const string GitExe = @"C:\Program Files\Git\cmd\git.exe";
    private const string DevelopmentRoot = @"C:\Dev";
    private const int MaximumStatusEntries = 500;

    [McpServerTool(Name = "git_worktree_mutation_preflight", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Perform a repository-wide read-only mutation preflight for one Git worktree under C:\\Dev. Enumerates every linked worktree, active branch, HEAD, locked/prunable state, and bounded tracked/untracked status using fixed git.exe commands. The result blocks eligibility when the requested worktree is dirty, the intended branch is active elsewhere, any worktree is unsafe, or—by default—any worktree is dirty. No files, refs, index, worktree metadata, branches, remotes, hooks, or processes are modified.")]
    public static async Task<GitWorktreeMutationPreflightResult> GitWorktreeMutationPreflight(
        string repository,
        string? intendedBranch = null,
        bool requireAllWorktreesClean = true)
    {
        var repositoryPath = ValidatePath(repository, requireRepositoryRoot: false);
        var gitSha256 = GetFileSha256(GitExe);
        var requestedTop = NormalizePath((await RunGitAsync(repositoryPath, new[] { "rev-parse", "--show-toplevel" }, 30)).StdOut.Trim());
        if (!string.Equals(requestedTop, repositoryPath, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Requested path must be the root of one Git worktree.");

        var commonDirectoryText = (await RunGitAsync(repositoryPath, new[] { "rev-parse", "--git-common-dir" }, 30)).StdOut.Trim();
        var commonDirectory = NormalizePath(Path.IsPathFullyQualified(commonDirectoryText)
            ? commonDirectoryText
            : Path.Combine(repositoryPath, commonDirectoryText));

        var porcelain = (await RunGitAsync(repositoryPath, new[] { "worktree", "list", "--porcelain", "-z" }, 30)).StdOut;
        var parsed = ParseWorktrees(porcelain);
        var worktrees = new List<GitWorktreePreflightEntry>();
        var reasons = new List<string>();

        foreach (var item in parsed)
        {
            var path = NormalizePath(item.Path);
            var underDevelopmentRoot = IsUnderDevelopmentRoot(path);
            var exists = Directory.Exists(path);
            var reparsePoint = exists && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
            var statusEntries = new List<string>();
            var statusTruncated = false;
            string? inspectionError = null;

            if (!underDevelopmentRoot)
            {
                inspectionError = "Worktree is outside C:\\Dev.";
            }
            else if (!exists)
            {
                inspectionError = "Worktree directory does not exist.";
            }
            else if (reparsePoint)
            {
                inspectionError = "Worktree root is a reparse point.";
            }
            else if (!item.Prunable)
            {
                try
                {
                    var status = (await RunGitAsync(path, new[] { "status", "--porcelain=v1", "-z", "--untracked-files=all" }, 30)).StdOut;
                    var allEntries = status.Split('\0', StringSplitOptions.RemoveEmptyEntries);
                    statusTruncated = allEntries.Length > MaximumStatusEntries;
                    statusEntries.AddRange(allEntries.Take(MaximumStatusEntries));
                }
                catch (Exception ex)
                {
                    inspectionError = ex.GetType().Name + ": " + ex.Message;
                }
            }

            var dirty = statusEntries.Count > 0 || statusTruncated;
            var branch = item.BranchRef is null
                ? "(detached)"
                : item.BranchRef.StartsWith("refs/heads/", StringComparison.Ordinal)
                    ? item.BranchRef["refs/heads/".Length..]
                    : item.BranchRef;

            worktrees.Add(new GitWorktreePreflightEntry(
                path,
                string.Equals(path, repositoryPath, StringComparison.OrdinalIgnoreCase),
                item.Head,
                branch,
                item.BranchRef,
                item.Locked,
                item.LockReason,
                item.Prunable,
                item.PrunableReason,
                underDevelopmentRoot,
                exists,
                reparsePoint,
                dirty,
                statusEntries.Count,
                statusTruncated,
                statusEntries,
                inspectionError));

            if (!underDevelopmentRoot) reasons.Add($"Worktree outside C:\\Dev: {path}");
            if (!exists) reasons.Add($"Worktree missing: {path}");
            if (reparsePoint) reasons.Add($"Worktree is a reparse point: {path}");
            if (item.Locked) reasons.Add($"Worktree is locked: {path}");
            if (item.Prunable) reasons.Add($"Worktree is prunable: {path}");
            if (inspectionError is not null) reasons.Add($"Worktree inspection failed: {path}");
        }

        var requested = worktrees.SingleOrDefault(x => x.IsRequestedWorktree)
            ?? throw new InvalidOperationException("Requested worktree was not returned by git worktree list.");
        if (requested.Dirty)
            reasons.Add("Requested worktree has tracked or untracked changes.");

        var targetBranch = string.IsNullOrWhiteSpace(intendedBranch) ? requested.Branch : ValidateBranchName(intendedBranch);
        if (targetBranch == "(detached)")
            reasons.Add("An explicit intendedBranch is required when the requested worktree is detached.");

        foreach (var other in worktrees.Where(x =>
                     !x.IsRequestedWorktree &&
                     string.Equals(x.Branch, targetBranch, StringComparison.Ordinal)))
            reasons.Add($"Intended branch is active in another worktree: {other.Path}");

        if (requireAllWorktreesClean)
        {
            foreach (var dirty in worktrees.Where(x => !x.IsRequestedWorktree && x.Dirty))
                reasons.Add($"Another worktree has tracked or untracked changes: {dirty.Path}");
        }

        var distinctReasons = reasons.Distinct(StringComparer.Ordinal).ToArray();
        return new GitWorktreeMutationPreflightResult(
            repositoryPath,
            commonDirectory,
            requested.Branch,
            requested.Head,
            targetBranch,
            requireAllWorktreesClean,
            distinctReasons.Length == 0,
            distinctReasons,
            worktrees,
            gitSha256,
            DateTimeOffset.UtcNow);
    }

    private static IReadOnlyList<ParsedWorktree> ParseWorktrees(string text)
    {
        var result = new List<ParsedWorktree>();
        string? path = null;
        string? head = null;
        string? branch = null;
        var locked = false;
        string? lockReason = null;
        var prunable = false;
        string? prunableReason = null;

        void Flush()
        {
            if (path is null) return;
            result.Add(new ParsedWorktree(path, head ?? string.Empty, branch, locked, lockReason, prunable, prunableReason));
            path = head = branch = lockReason = prunableReason = null;
            locked = prunable = false;
        }

        foreach (var token in text.Split('\0'))
        {
            if (token.Length == 0) { Flush(); continue; }
            if (token.StartsWith("worktree ", StringComparison.Ordinal))
            {
                Flush();
                path = token["worktree ".Length..];
            }
            else if (token.StartsWith("HEAD ", StringComparison.Ordinal)) head = token["HEAD ".Length..];
            else if (token.StartsWith("branch ", StringComparison.Ordinal)) branch = token["branch ".Length..];
            else if (token == "detached") branch = null;
            else if (token.StartsWith("locked", StringComparison.Ordinal))
            {
                locked = true;
                lockReason = token.Length > "locked".Length ? token[("locked".Length + 1)..] : null;
            }
            else if (token.StartsWith("prunable", StringComparison.Ordinal))
            {
                prunable = true;
                prunableReason = token.Length > "prunable".Length ? token[("prunable".Length + 1)..] : null;
            }
        }
        Flush();
        return result;
    }

    private static string ValidatePath(string path, bool requireRepositoryRoot)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Repository path is required.", nameof(path));
        if (!Path.IsPathFullyQualified(path)) throw new ArgumentException("Repository path must be absolute.", nameof(path));
        var resolved = NormalizePath(path);
        if (!IsUnderDevelopmentRoot(resolved)) throw new UnauthorizedAccessException("Repository must be a child of C:\\Dev.");
        if (!Directory.Exists(resolved)) throw new DirectoryNotFoundException(resolved);
        if ((File.GetAttributes(resolved) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Repository root may not be a reparse point.");
        if (requireRepositoryRoot && !Directory.Exists(Path.Combine(resolved, ".git"))) throw new InvalidOperationException("Path is not a repository root.");
        return resolved;
    }

    private static string ValidateBranchName(string branch)
    {
        var value = branch.Trim();
        if (value.StartsWith("refs/heads/", StringComparison.Ordinal)) value = value["refs/heads/".Length..];
        if (value.Length == 0 || value.Contains('\0') || value.Contains('\r') || value.Contains('\n'))
            throw new ArgumentException("intendedBranch is invalid.", nameof(branch));
        return value;
    }

    private static bool IsUnderDevelopmentRoot(string path)
    {
        var root = NormalizePath(DevelopmentRoot);
        return path.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizePath(string path) =>
        Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

    private static async Task<CliResult> RunGitAsync(string workingDirectory, IReadOnlyList<string> arguments, int timeoutSeconds)
    {
        _ = GetFileSha256(GitExe);
        var psi = new ProcessStartInfo
        {
            FileName = GitExe,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        psi.Environment["GIT_TERMINAL_PROMPT"] = "0";
        psi.Environment["GIT_PAGER"] = "cat";
        psi.Environment["GIT_EXTERNAL_DIFF"] = string.Empty;
        psi.Environment["NO_COLOR"] = "1";
        psi.ArgumentList.Add("--no-pager");
        psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("core.hooksPath=NUL");
        psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("core.fsmonitor=false");
        psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("diff.external=");
        psi.ArgumentList.Add("-c"); psi.ArgumentList.Add($"safe.directory={workingDirectory}");
        psi.ArgumentList.Add("-C"); psi.ArgumentList.Add(workingDirectory);
        foreach (var argument in arguments) psi.ArgumentList.Add(argument);

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
        if (result.ExitCode != 0) throw new InvalidOperationException($"git.exe exited with code {result.ExitCode}: {result.StdErr.Trim()}");
        return result;
    }

    private static string GetFileSha256(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException("git.exe not found.", path);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("git.exe may not be a reparse point.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private sealed record ParsedWorktree(string Path, string Head, string? BranchRef, bool Locked, string? LockReason, bool Prunable, string? PrunableReason);
    private sealed record CliResult(int ExitCode, string StdOut, string StdErr);
}

public sealed record GitWorktreePreflightEntry(
    string Path,
    bool IsRequestedWorktree,
    string Head,
    string Branch,
    string? BranchRef,
    bool Locked,
    string? LockReason,
    bool Prunable,
    string? PrunableReason,
    bool UnderDevelopmentRoot,
    bool Exists,
    bool ReparsePoint,
    bool Dirty,
    int StatusEntryCount,
    bool StatusTruncated,
    IReadOnlyList<string> StatusEntries,
    string? InspectionError);

public sealed record GitWorktreeMutationPreflightResult(
    string Repository,
    string CommonGitDirectory,
    string CurrentBranch,
    string Head,
    string IntendedBranch,
    bool RequireAllWorktreesClean,
    bool EligibleForMutation,
    IReadOnlyList<string> BlockingReasons,
    IReadOnlyList<GitWorktreePreflightEntry> Worktrees,
    string GitExeSha256,
    DateTimeOffset CheckedUtc);
