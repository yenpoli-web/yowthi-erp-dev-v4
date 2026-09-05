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
public static class GitOriginRepairTools
{
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly ProtectedPathPolicy PathPolicy = new();

    private const string RepositoryPath = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string GitExe = @"C:\Program Files\Git\cmd\git.exe";
    private const string ExpectedFetchRefspec = "+refs/heads/*:refs/remotes/origin/*";

    [McpServerTool(Name = "git_origin_repair_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to restore only the missing origin remote for the fixed C:\\Dev\\YowThi-ERP-Dev-v4 repository. The repository must currently have zero configured remotes and no refs/remotes/origin directory. The proposed URL must be credential-free HTTPS on github.com under the fixed yenpoli-web owner and end in .git. Current HEAD, clean status, local Git config SHA-256, git.exe SHA-256, exact origin URL, and the standard origin fetch refspec are sealed. No network access, fetch, push, branch mutation, arbitrary remote name, non-GitHub host, SSH, credentials, or production path is supported.")]
    public static async Task<SignedPlan> GitOriginRepairPlan(string repository, string originUrl)
    {
        var repo = await ValidateFixedRepositoryAsync(repository);
        await RequireCleanWorkingTreeAsync(repo);
        await RequireRemoteAbsentAsync(repo);
        var normalizedUrl = ValidateOriginUrl(originUrl);
        var head = await GetHeadAsync(repo);
        var statusSha256 = await GetStatusSha256Async(repo);
        var configPath = Path.Combine(repo, ".git", "config");
        var configSha256 = GetFileSha256(configPath, "Git config");
        var gitExeSha256 = GetFileSha256(GitExe, "git.exe");

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["repository"] = repo,
            ["originUrl"] = normalizedUrl,
            ["fetchRefspec"] = ExpectedFetchRefspec,
            ["head"] = head,
            ["statusSha256"] = statusSha256,
            ["configSha256"] = configSha256,
            ["gitExeSha256"] = gitExeSha256,
            ["remoteAbsent"] = "true"
        };
        var summary = $"Restore missing origin remote for fixed YowThi ERP Dev v4 repository at HEAD {head[..12]} to {normalizedUrl}";
        return CreatePlan("git-origin-repair", repo, parameters, RiskClass.High, summary);
    }

    [McpServerTool(Name = "git_origin_repair_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared fixed git-origin-repair plan. Only planId and approvalCode are caller-controlled. The server revalidates the fixed repository, zero-remotes state, absent refs/remotes/origin state, clean working tree, HEAD/status/config/git.exe fingerprints, sealed credential-free yenpoli-web GitHub HTTPS URL, and standard fetch refspec before running fixed 'git remote add origin <sealed-url>' semantics. Post-write read-back must prove exactly one origin URL and exactly the standard origin fetch refspec. Failed verification performs best-effort removal of only the origin created by this invocation. No network access, fetch, push, arbitrary remote name, URL, refspec, shell, or production mutation is supported.")]
    public static async Task<GitOriginRepairResult> GitOriginRepairExecute(string planId, string approvalCode)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        if (!string.Equals(plan.Tool, "git", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, "git-origin-repair", StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Signed plan is not a git-origin-repair plan.");

        var repo = await ValidateFixedRepositoryAsync(RequireParameter(plan, "repository"));
        var originUrl = ValidateOriginUrl(RequireParameter(plan, "originUrl"));
        if (!string.Equals(RequireParameter(plan, "fetchRefspec"), ExpectedFetchRefspec, StringComparison.Ordinal) ||
            !string.Equals(RequireParameter(plan, "remoteAbsent"), "true", StringComparison.Ordinal))
            throw new InvalidDataException("Signed Git origin repair shape is invalid.");

        await RequireCleanWorkingTreeAsync(repo);
        await RequireRemoteAbsentAsync(repo);
        var actualHead = await GetHeadAsync(repo);
        var actualStatusSha256 = await GetStatusSha256Async(repo);
        var configPath = Path.Combine(repo, ".git", "config");
        var actualConfigSha256 = GetFileSha256(configPath, "Git config");
        var actualGitExeSha256 = GetFileSha256(GitExe, "git.exe");

        if (!string.Equals(actualHead, RequireParameter(plan, "head"), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(actualStatusSha256, RequireParameter(plan, "statusSha256"), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(actualConfigSha256, RequireParameter(plan, "configSha256"), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(actualGitExeSha256, RequireParameter(plan, "gitExeSha256"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Git repository state changed after origin repair plan creation.");

        var created = false;
        try
        {
            var add = await RunGitAsync(repo, new[] { "remote", "add", "origin", originUrl }, 30);
            created = true;
            var (url, refspec) = await ReadOriginAsync(repo);
            if (!string.Equals(url, originUrl, StringComparison.Ordinal) ||
                !string.Equals(refspec, ExpectedFetchRefspec, StringComparison.Ordinal))
                throw new InvalidOperationException("Post-repair origin read-back did not match the sealed configuration.");

            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, originUrl, refspec, actualHead, add.ExitCode }, "executed");
            return new GitOriginRepairResult(plan.PlanId, repo, originUrl, refspec, actualHead, true, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            if (created)
            {
                try
                {
                    var remotes = await RunGitAsync(repo, new[] { "remote" }, 30, allowNonZero: true);
                    var names = NormalizeText(remotes.StdOut).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                    if (names.Length == 1 && string.Equals(names[0], "origin", StringComparison.Ordinal))
                        _ = await RunGitAsync(repo, new[] { "remote", "remove", "origin" }, 30, allowNonZero: true);
                }
                catch { }
            }
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    private static async Task<string> ValidateFixedRepositoryAsync(string repository)
    {
        if (!File.Exists(GitExe)) throw new FileNotFoundException("git.exe not found.", GitExe);
        var full = PathPolicy.RequireMutable(repository).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!string.Equals(full, RepositoryPath, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("This repair capability is fixed to C:\\Dev\\YowThi-ERP-Dev-v4.");
        if (!Directory.Exists(full) || (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Fixed repository is missing or is a reparse point.");
        var top = await RunGitAsync(full, new[] { "rev-parse", "--show-toplevel" }, 30);
        var resolved = Path.GetFullPath(top.StdOut.Trim()).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!string.Equals(resolved, RepositoryPath, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Fixed Git repository root identity mismatch.");
        return RepositoryPath;
    }

    private static string ValidateOriginUrl(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(uri.Host, "github.com", StringComparison.OrdinalIgnoreCase) ||
            uri.Port != 443 || !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            throw new ArgumentException("originUrl must be credential-free HTTPS on github.com.", nameof(value));

        var path = uri.AbsolutePath;
        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length != 2 || !string.Equals(segments[0], "yenpoli-web", StringComparison.Ordinal) ||
            !segments[1].EndsWith(".git", StringComparison.Ordinal) || segments[1].Length <= 4 ||
            segments[1][..^4].Any(c => !(char.IsLetterOrDigit(c) || c is '.' or '_' or '-')))
            throw new ArgumentException("originUrl must target one yenpoli-web GitHub repository ending in .git.", nameof(value));

        return $"https://github.com/yenpoli-web/{segments[1]}";
    }

    private static async Task RequireRemoteAbsentAsync(string repo)
    {
        var remotes = await RunGitAsync(repo, new[] { "remote" }, 30);
        if (!string.IsNullOrWhiteSpace(NormalizeText(remotes.StdOut)))
            throw new InvalidOperationException("Origin repair requires zero configured Git remotes.");
        var originRefs = Path.Combine(repo, ".git", "refs", "remotes", "origin");
        if (Directory.Exists(originRefs) || File.Exists(originRefs))
            throw new InvalidOperationException("Origin repair requires refs/remotes/origin to be absent.");
    }

    private static async Task RequireCleanWorkingTreeAsync(string repo)
    {
        var status = await RunGitAsync(repo, new[] { "status", "--porcelain=v1", "--untracked-files=all" }, 30);
        if (!string.IsNullOrWhiteSpace(status.StdOut))
            throw new InvalidOperationException("Origin repair requires a clean working tree.");
    }

    private static async Task<string> GetHeadAsync(string repo)
    {
        var result = await RunGitAsync(repo, new[] { "rev-parse", "--verify", "HEAD" }, 30);
        var head = result.StdOut.Trim();
        if (head.Length < 12 || head.Any(c => !Uri.IsHexDigit(c)))
            throw new InvalidOperationException("Unable to resolve a valid HEAD commit.");
        return head;
    }

    private static async Task<string> GetStatusSha256Async(string repo)
    {
        var result = await RunGitAsync(repo, new[] { "status", "--porcelain=v1", "--untracked-files=all" }, 30);
        return HashText(NormalizeText(result.StdOut));
    }

    private static async Task<(string Url, string Refspec)> ReadOriginAsync(string repo)
    {
        var urlResult = await RunGitAsync(repo, new[] { "remote", "get-url", "--all", "origin" }, 30);
        var urls = NormalizeText(urlResult.StdOut).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (urls.Length != 1) throw new InvalidOperationException("Origin must have exactly one URL.");
        var refResult = await RunGitAsync(repo, new[] { "config", "--get-all", "remote.origin.fetch" }, 30);
        var refs = NormalizeText(refResult.StdOut).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (refs.Length != 1) throw new InvalidOperationException("Origin must have exactly one fetch refspec.");
        return (urls[0], refs[0]);
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

    private static async Task<GitProcessResult> RunGitAsync(string repository, IReadOnlyList<string> args, int timeoutSeconds, bool allowNonZero = false)
    {
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
        psi.Environment["GIT_PAGER"] = "cat";
        psi.ArgumentList.Add("--no-pager");
        psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("core.hooksPath=NUL");
        psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("core.fsmonitor=false");
        psi.ArgumentList.Add("-c"); psi.ArgumentList.Add($"safe.directory={repository}");
        psi.ArgumentList.Add("-C"); psi.ArgumentList.Add(repository);
        foreach (var arg in args) psi.ArgumentList.Add(arg);

        using var process = Process.Start(psi) ?? throw new InvalidOperationException("git.exe failed to start.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        try { await process.WaitForExitAsync(cts.Token); }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"git.exe exceeded {timeoutSeconds} seconds.");
        }
        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        var result = new GitProcessResult(process.ExitCode, stdout, stderr);
        if (!allowNonZero && result.ExitCode != 0)
            throw new InvalidOperationException($"git.exe exited with code {result.ExitCode}: {(string.IsNullOrWhiteSpace(stderr) ? stdout : stderr).Trim()}");
        return result;
    }

    private static string RequireParameter(SignedPlan plan, string key)
    {
        if (!plan.Parameters.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
            throw new InvalidDataException($"{key} parameter is required.");
        return value;
    }

    private static string GetFileSha256(string path, string label)
    {
        if (!File.Exists(path)) throw new FileNotFoundException($"{label} not found.", path);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException($"{label} may not be a reparse point.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string NormalizeText(string text) => text.Replace("\r\n", "\n", StringComparison.Ordinal).Trim();
    private static string HashText(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
    private sealed record GitProcessResult(int ExitCode, string StdOut, string StdErr);
}

public sealed record GitOriginRepairResult(string PlanId, string Repository, string OriginUrl, string FetchRefspec, string Head, bool Verified, DateTimeOffset ExecutedUtc);
