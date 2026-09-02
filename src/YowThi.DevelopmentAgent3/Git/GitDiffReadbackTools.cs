using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;

namespace YowThi.DevelopmentAgent3.Git;

[McpServerToolType]
public static class GitDiffReadbackTools
{
    private const string GitExe = @"C:\Program Files\Git\cmd\git.exe";
    private const string DevelopmentRoot = @"C:\Dev";
    private const int MaximumDiffCharacters = 200_000;

    [McpServerTool(Name = "git_diff_readback", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read staged or unstaged Git differences for one explicit repository under C:\\Dev using the fixed git.exe binary. The result includes repository identity, branch, HEAD, name/status, diff stat, a bounded unified diff, the SHA-256 of the complete normalized diff, and whether displayed output was truncated. Hooks, external diff drivers, text conversion, paging, prompts, arbitrary Git arguments, writes, staging, commits, pushes, and production repositories are not supported.")]
    public static async Task<GitDiffReadbackResult> GitDiffReadback(string repository, bool staged = false)
    {
        var repositoryPath = ValidateRepositoryPath(repository);
        var gitSha256 = GetFileSha256(GitExe, "git.exe");
        await ValidateRepositoryIdentityAsync(repositoryPath);

        var branch = (await RunGitAsync(repositoryPath, new[] { "symbolic-ref", "--quiet", "--short", "HEAD" }, 30, allowNonZero: true)).StdOut.Trim();
        if (string.IsNullOrWhiteSpace(branch))
            branch = "(detached)";
        var head = (await RunGitAsync(repositoryPath, new[] { "rev-parse", "--verify", "HEAD" }, 30)).StdOut.Trim();

        var modeArguments = staged ? new[] { "--cached" } : Array.Empty<string>();
        var nameStatus = await RunDiffAsync(repositoryPath, modeArguments.Concat(new[] { "--name-status" }).ToArray());
        var stat = await RunDiffAsync(repositoryPath, modeArguments.Concat(new[] { "--stat=120,200" }).ToArray());
        var completeDiff = NormalizeText((await RunDiffAsync(
            repositoryPath,
            modeArguments.Concat(new[] { "--no-ext-diff", "--no-textconv", "--unified=3" }).ToArray())).StdOut);

        var diffSha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(completeDiff)));
        var truncated = completeDiff.Length > MaximumDiffCharacters;
        var displayedDiff = truncated ? completeDiff[..MaximumDiffCharacters] : completeDiff;

        return new GitDiffReadbackResult(
            repositoryPath,
            branch,
            head,
            staged,
            NormalizeText(nameStatus.StdOut),
            NormalizeText(stat.StdOut),
            displayedDiff,
            diffSha256,
            completeDiff.Length,
            truncated,
            MaximumDiffCharacters,
            gitSha256,
            DateTimeOffset.UtcNow);
    }

    private static string ValidateRepositoryPath(string repository)
    {
        if (string.IsNullOrWhiteSpace(repository))
            throw new ArgumentException("Repository path is required.", nameof(repository));
        if (!Path.IsPathFullyQualified(repository))
            throw new ArgumentException("Repository path must be absolute.", nameof(repository));

        var resolved = Path.GetFullPath(repository).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var root = Path.GetFullPath(DevelopmentRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!resolved.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Repository must be a child of C:\\Dev.");
        if (!Directory.Exists(resolved))
            throw new DirectoryNotFoundException($"Repository does not exist: {resolved}");
        if ((File.GetAttributes(resolved) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Repository may not be a reparse point.");
        if (!Directory.Exists(Path.Combine(resolved, ".git")))
            throw new InvalidOperationException("Path is not a Git repository root.");
        return resolved;
    }

    private static async Task ValidateRepositoryIdentityAsync(string repositoryPath)
    {
        var top = await RunGitAsync(repositoryPath, new[] { "rev-parse", "--show-toplevel" }, 30);
        var resolvedTop = Path.GetFullPath(top.StdOut.Trim()).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!string.Equals(resolvedTop, repositoryPath, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Resolved Git repository root does not match the requested repository.");
    }

    private static Task<CliResult> RunDiffAsync(string repositoryPath, IReadOnlyList<string> arguments)
    {
        var fixedArguments = new List<string> { "diff" };
        fixedArguments.AddRange(arguments);
        fixedArguments.Add("--");
        return RunGitAsync(repositoryPath, fixedArguments, 60);
    }

    private static async Task<CliResult> RunGitAsync(
        string repositoryPath,
        IReadOnlyList<string> arguments,
        int timeoutSeconds,
        bool allowNonZero = false)
    {
        _ = GetFileSha256(GitExe, "git.exe");
        var psi = new ProcessStartInfo
        {
            FileName = GitExe,
            WorkingDirectory = repositoryPath,
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
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add("core.hooksPath=NUL");
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add("core.fsmonitor=false");
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add("diff.external=");
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add($"safe.directory={repositoryPath}");
        psi.ArgumentList.Add("-C");
        psi.ArgumentList.Add(repositoryPath);
        foreach (var argument in arguments)
            psi.ArgumentList.Add(argument);

        using var process = Process.Start(psi) ?? throw new InvalidOperationException("git.exe failed to start.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"git.exe exceeded {timeoutSeconds} seconds.");
        }

        var result = new CliResult(process.ExitCode, await stdoutTask, await stderrTask);
        if (!allowNonZero && result.ExitCode != 0)
            throw new InvalidOperationException($"git.exe exited with code {result.ExitCode}: {NormalizeText(result.StdErr)}");
        return result;
    }

    private static string GetFileSha256(string path, string label)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException($"{label} not found.", path);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException($"{label} may not be a reparse point.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string NormalizeText(string text) =>
        text.Replace("\r\n", "\n", StringComparison.Ordinal).TrimEnd();

    private sealed record CliResult(int ExitCode, string StdOut, string StdErr);
}

public sealed record GitDiffReadbackResult(
    string Repository,
    string Branch,
    string Head,
    bool Staged,
    string NameStatus,
    string Stat,
    string UnifiedDiff,
    string CompleteDiffSha256,
    int CompleteDiffCharacters,
    bool OutputTruncated,
    int MaximumDiffCharacters,
    string GitExeSha256,
    DateTimeOffset CheckedUtc);
