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
    private const string LegacyOriginUrl = "https://github.com/yenpoli-web/yowthi-erp-v2.git";
    private const string DedicatedV4OriginUrl = "https://github.com/yenpoli-web/yowthi-erp-dev-v4.git";

    [McpServerTool(Name = "git_origin_repair_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan for the fixed C:\\Dev\\YowThi-ERP-Dev-v4 repository. With zero remotes it restores a missing credential-free yenpoli-web GitHub origin. With the exact legacy ERP origin it may only retarget origin to https://github.com/yenpoli-web/yowthi-erp-dev-v4.git. Retarget mode requires clean local main, seals HEAD/status/config/git.exe plus remote/upstream/ref snapshots, removes the legacy origin locally, adds the dedicated V4 origin with the standard fetch refspec, clears stale origin-tracking refs/upstreams, and configures local main to track origin/main for the later typed first push. No network, fetch, push, force, shell, or production mutation is performed.")]
    public static async Task<SignedPlan> GitOriginRepairPlan(string repository, string originUrl)
    {
        var repo = await ValidateFixedRepositoryAsync(repository);
        await RequireCleanWorkingTreeAsync(repo);

        var normalizedUrl = ValidateOriginUrl(originUrl);
        var remoteState = await ReadRemoteStateAsync(repo);
        var mode = string.Empty;
        string upstreamSnapshot = string.Empty;
        string remoteRefsSnapshot = string.Empty;

        if (remoteState.RemoteAbsent)
        {
            await RequireNoOriginRemoteRefsAsync(repo);
            mode = "repair";
        }
        else
        {
            if (!string.Equals(remoteState.RemoteName, "origin", StringComparison.Ordinal) ||
                !string.Equals(remoteState.Url, LegacyOriginUrl, StringComparison.Ordinal) ||
                !string.Equals(remoteState.FetchRefspec, ExpectedFetchRefspec, StringComparison.Ordinal) ||
                remoteState.HasPushUrl)
                throw new InvalidOperationException("Retarget mode requires exactly the legacy ERP origin with the standard fetch refspec and no push URL.");

            if (!string.Equals(normalizedUrl, DedicatedV4OriginUrl, StringComparison.Ordinal))
                throw new UnauthorizedAccessException("Legacy origin may only be retargeted to the dedicated YowThi ERP Dev v4 GitHub repository.");

            var currentBranch = await GetCurrentBranchAsync(repo);
            if (!string.Equals(currentBranch, "main", StringComparison.Ordinal))
                throw new InvalidOperationException("Origin retarget requires local main to be checked out.");

            mode = "retarget";
            upstreamSnapshot = await GetUpstreamSnapshotAsync(repo);
            remoteRefsSnapshot = await GetRemoteRefsSnapshotAsync(repo);
        }

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
            ["mode"] = mode,
            ["upstreamSnapshotBase64"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(upstreamSnapshot)),
            ["remoteRefsSnapshotBase64"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(remoteRefsSnapshot)),
            ["upstreamSnapshotSha256"] = HashText(upstreamSnapshot),
            ["remoteRefsSnapshotSha256"] = HashText(remoteRefsSnapshot)
        };

        var summary = mode == "repair"
            ? $"Restore missing origin remote for fixed YowThi ERP Dev v4 repository at HEAD {head[..12]} to {normalizedUrl}"
            : $"Retarget fixed YowThi ERP Dev v4 origin from legacy ERP remote to dedicated V4 remote at HEAD {head[..12]}";
        return CreatePlan("git-origin-repair", repo, parameters, RiskClass.High, summary);
    }

    [McpServerTool(Name = "git_origin_repair_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared fixed git-origin-repair plan. Repair mode adds a missing origin. Retarget mode is limited to the sealed legacy ERP origin -> dedicated V4 origin transition, revalidates all sealed Git state, performs only local remote/config/ref changes, removes stale legacy origin tracking state, and configures local main to track origin/main for the later typed push. On retarget verification failure it performs a best-effort local restoration of the legacy origin, upstream configuration, and remote-tracking refs. No network, fetch, push, force, shell, or production mutation is supported.")]
    public static async Task<GitOriginRepairResult> GitOriginRepairExecute(string planId, string approvalCode)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        if (!string.Equals(plan.Tool, "git", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, "git-origin-repair", StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Signed plan is not a git-origin-repair plan.");

        var repo = await ValidateFixedRepositoryAsync(RequireParameter(plan, "repository"));
        var originUrl = ValidateOriginUrl(RequireParameter(plan, "originUrl"));
        var mode = RequireParameter(plan, "mode");
        if (mode is not ("repair" or "retarget"))
            throw new InvalidDataException("Signed Git origin repair mode is invalid.");
        if (!string.Equals(RequireParameter(plan, "fetchRefspec"), ExpectedFetchRefspec, StringComparison.Ordinal))
            throw new InvalidDataException("Signed Git origin fetch refspec is invalid.");

        await RequireCleanWorkingTreeAsync(repo);
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

        if (mode == "repair")
            return await ExecuteRepairAsync(plan, repo, originUrl, actualHead);

        if (!string.Equals(originUrl, DedicatedV4OriginUrl, StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Retarget destination is not the dedicated V4 origin.");
        return await ExecuteRetargetAsync(plan, repo, originUrl, actualHead);
    }

    private static async Task<GitOriginRepairResult> ExecuteRepairAsync(SignedPlan plan, string repo, string originUrl, string head)
    {
        var state = await ReadRemoteStateAsync(repo);
        if (!state.RemoteAbsent)
            throw new InvalidOperationException("Repair mode requires zero configured Git remotes.");
        await RequireNoOriginRemoteRefsAsync(repo);

        var created = false;
        try
        {
            var add = await RunGitAsync(repo, new[] { "remote", "add", "origin", originUrl }, 30);
            created = true;
            var (url, refspec) = await ReadOriginAsync(repo);
            if (!string.Equals(url, originUrl, StringComparison.Ordinal) ||
                !string.Equals(refspec, ExpectedFetchRefspec, StringComparison.Ordinal))
                throw new InvalidOperationException("Post-repair origin read-back did not match the sealed configuration.");

            Store.Consume(plan.PlanId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, mode = "repair", originUrl, refspec, head, add.ExitCode }, "executed");
            return new GitOriginRepairResult(plan.PlanId, repo, originUrl, refspec, head, true, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            if (created)
                await BestEffortRemoveOriginAsync(repo);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, mode = "repair", error = ex.Message }, "failed");
            throw;
        }
    }

    private static async Task<GitOriginRepairResult> ExecuteRetargetAsync(SignedPlan plan, string repo, string originUrl, string head)
    {
        var currentBranch = await GetCurrentBranchAsync(repo);
        if (!string.Equals(currentBranch, "main", StringComparison.Ordinal))
            throw new InvalidOperationException("Origin retarget requires local main to remain checked out.");

        var state = await ReadRemoteStateAsync(repo);
        if (state.RemoteAbsent ||
            !string.Equals(state.RemoteName, "origin", StringComparison.Ordinal) ||
            !string.Equals(state.Url, LegacyOriginUrl, StringComparison.Ordinal) ||
            !string.Equals(state.FetchRefspec, ExpectedFetchRefspec, StringComparison.Ordinal) ||
            state.HasPushUrl)
            throw new InvalidOperationException("Legacy ERP origin state changed after retarget plan creation.");

        var upstreamSnapshot = await GetUpstreamSnapshotAsync(repo);
        var remoteRefsSnapshot = await GetRemoteRefsSnapshotAsync(repo);
        if (!string.Equals(HashText(upstreamSnapshot), RequireParameter(plan, "upstreamSnapshotSha256"), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(HashText(remoteRefsSnapshot), RequireParameter(plan, "remoteRefsSnapshotSha256"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Git upstream or remote-tracking refs changed after retarget plan creation.");

        var sealedUpstreamSnapshot = DecodeSnapshot(RequireParameter(plan, "upstreamSnapshotBase64"));
        var sealedRemoteRefsSnapshot = DecodeSnapshot(RequireParameter(plan, "remoteRefsSnapshotBase64"));
        if (!string.Equals(upstreamSnapshot, sealedUpstreamSnapshot, StringComparison.Ordinal) ||
            !string.Equals(remoteRefsSnapshot, sealedRemoteRefsSnapshot, StringComparison.Ordinal))
            throw new InvalidDataException("Signed Git retarget snapshots are inconsistent.");

        var legacyRemoved = false;
        var dedicatedAdded = false;
        try
        {
            _ = await RunGitAsync(repo, new[] { "remote", "remove", "origin" }, 30);
            legacyRemoved = true;

            _ = await RunGitAsync(repo, new[] { "remote", "add", "origin", originUrl }, 30);
            dedicatedAdded = true;

            _ = await RunGitAsync(repo, new[] { "config", "branch.main.remote", "origin" }, 30);
            _ = await RunGitAsync(repo, new[] { "config", "branch.main.merge", "refs/heads/main" }, 30);

            var (url, refspec) = await ReadOriginAsync(repo);
            if (!string.Equals(url, DedicatedV4OriginUrl, StringComparison.Ordinal) ||
                !string.Equals(refspec, ExpectedFetchRefspec, StringComparison.Ordinal))
                throw new InvalidOperationException("Post-retarget origin read-back did not match the dedicated V4 configuration.");

            await RequireNoOriginRemoteRefsAsync(repo);
            await RequireOnlyMainTracksOriginAsync(repo);

            Store.Consume(plan.PlanId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new
            {
                plan.PlanId,
                mode = "retarget",
                oldOriginUrl = LegacyOriginUrl,
                newOriginUrl = DedicatedV4OriginUrl,
                head
            }, "executed");
            return new GitOriginRepairResult(plan.PlanId, repo, DedicatedV4OriginUrl, ExpectedFetchRefspec, head, true, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            if (dedicatedAdded)
                await BestEffortRemoveOriginAsync(repo);
            if (legacyRemoved)
                await BestEffortRestoreLegacyStateAsync(repo, sealedUpstreamSnapshot, sealedRemoteRefsSnapshot);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, mode = "retarget", error = ex.Message }, "failed");
            throw;
        }
    }

    private static async Task<string> ValidateFixedRepositoryAsync(string repository)
    {
        if (!File.Exists(GitExe)) throw new FileNotFoundException("git.exe not found.", GitExe);
        var full = PathPolicy.RequireMutable(repository).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!string.Equals(full, RepositoryPath, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("This capability is fixed to C:\\Dev\\YowThi-ERP-Dev-v4.");
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

        var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length != 2 || !string.Equals(segments[0], "yenpoli-web", StringComparison.Ordinal) ||
            !segments[1].EndsWith(".git", StringComparison.Ordinal) || segments[1].Length <= 4 ||
            segments[1][..^4].Any(c => !(char.IsLetterOrDigit(c) || c is '.' or '_' or '-')))
            throw new ArgumentException("originUrl must target one yenpoli-web GitHub repository ending in .git.", nameof(value));

        return $"https://github.com/yenpoli-web/{segments[1]}";
    }

    private static async Task<RemoteState> ReadRemoteStateAsync(string repo)
    {
        var remotes = await RunGitAsync(repo, new[] { "remote" }, 30);
        var names = NormalizeText(remotes.StdOut).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (names.Length == 0)
            return new RemoteState(true, null, null, null, false);
        if (names.Length != 1 || !string.Equals(names[0], "origin", StringComparison.Ordinal))
            throw new InvalidOperationException("This capability requires zero remotes or exactly one remote named origin.");

        var (url, refspec) = await ReadOriginAsync(repo);
        var pushUrl = await RunGitAsync(repo, new[] { "config", "--get-all", "remote.origin.pushurl" }, 30, allowNonZero: true);
        if (pushUrl.ExitCode is not (0 or 1))
            throw new InvalidOperationException("Unable to inspect origin push URL configuration.");
        return new RemoteState(false, "origin", url, refspec, !string.IsNullOrWhiteSpace(NormalizeText(pushUrl.StdOut)));
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

    private static async Task RequireCleanWorkingTreeAsync(string repo)
    {
        var status = await RunGitAsync(repo, new[] { "status", "--porcelain=v1", "--untracked-files=all" }, 30);
        if (!string.IsNullOrWhiteSpace(status.StdOut))
            throw new InvalidOperationException("This Git origin operation requires a clean working tree.");
    }

    private static async Task<string> GetCurrentBranchAsync(string repo)
    {
        var result = await RunGitAsync(repo, new[] { "branch", "--show-current" }, 30);
        return result.StdOut.Trim();
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

    private static async Task<string> GetUpstreamSnapshotAsync(string repo)
    {
        var result = await RunGitAsync(repo,
            new[] { "for-each-ref", "--format=%(refname:short)%09%(upstream:remotename)%09%(upstream:remoteref)", "refs/heads" }, 30);
        return NormalizeText(result.StdOut);
    }

    private static async Task<string> GetRemoteRefsSnapshotAsync(string repo)
    {
        var result = await RunGitAsync(repo,
            new[] { "for-each-ref", "--format=%(refname)%09%(objectname)", "refs/remotes/origin" }, 30);
        return NormalizeText(result.StdOut);
    }

    private static async Task RequireNoOriginRemoteRefsAsync(string repo)
    {
        if (!string.IsNullOrWhiteSpace(await GetRemoteRefsSnapshotAsync(repo)))
            throw new InvalidOperationException("refs/remotes/origin must be empty for this operation.");
    }

    private static async Task RequireOnlyMainTracksOriginAsync(string repo)
    {
        var snapshot = await GetUpstreamSnapshotAsync(repo);
        var sawMain = false;
        foreach (var line in snapshot.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = line.Split('\t');
            if (parts.Length != 3) throw new InvalidOperationException("Unable to inspect local branch upstream configuration.");
            var branch = parts[0].Trim();
            var remote = parts[1].Trim();
            var remoteRef = parts[2].Trim();
            if (string.Equals(branch, "main", StringComparison.Ordinal))
            {
                if (!string.Equals(remote, "origin", StringComparison.Ordinal) ||
                    !string.Equals(remoteRef, "refs/heads/main", StringComparison.Ordinal))
                    throw new InvalidOperationException("Local main is not configured to track origin/main.");
                sawMain = true;
            }
            else if (string.Equals(remote, "origin", StringComparison.Ordinal))
            {
                throw new InvalidOperationException($"Non-main branch still tracks origin after retarget: {branch}");
            }
        }
        if (!sawMain) throw new InvalidOperationException("Local main upstream configuration was not established.");
    }

    private static async Task BestEffortRemoveOriginAsync(string repo)
    {
        try
        {
            var remotes = await RunGitAsync(repo, new[] { "remote" }, 30, allowNonZero: true);
            if (NormalizeText(remotes.StdOut).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Contains("origin", StringComparer.Ordinal))
                _ = await RunGitAsync(repo, new[] { "remote", "remove", "origin" }, 30, allowNonZero: true);
        }
        catch { }
    }

    private static async Task BestEffortRestoreLegacyStateAsync(string repo, string upstreamSnapshot, string remoteRefsSnapshot)
    {
        try
        {
            var remotes = await RunGitAsync(repo, new[] { "remote" }, 30, allowNonZero: true);
            var names = NormalizeText(remotes.StdOut).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (names.Length == 0)
                _ = await RunGitAsync(repo, new[] { "remote", "add", "origin", LegacyOriginUrl }, 30, allowNonZero: true);

            foreach (var line in upstreamSnapshot.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var parts = line.Split('\t');
                if (parts.Length != 3 || !string.Equals(parts[1].Trim(), "origin", StringComparison.Ordinal))
                    continue;
                var branch = parts[0].Trim();
                var remoteRef = parts[2].Trim();
                if (string.IsNullOrWhiteSpace(branch) || !remoteRef.StartsWith("refs/heads/", StringComparison.Ordinal))
                    continue;
                _ = await RunGitAsync(repo, new[] { "config", $"branch.{branch}.remote", "origin" }, 30, allowNonZero: true);
                _ = await RunGitAsync(repo, new[] { "config", $"branch.{branch}.merge", remoteRef }, 30, allowNonZero: true);
            }

            foreach (var line in remoteRefsSnapshot.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var parts = line.Split('\t');
                if (parts.Length != 2) continue;
                var reference = parts[0].Trim();
                var objectId = parts[1].Trim();
                if (!reference.StartsWith("refs/remotes/origin/", StringComparison.Ordinal) ||
                    objectId.Length < 12 || objectId.Any(c => !Uri.IsHexDigit(c)))
                    continue;
                _ = await RunGitAsync(repo, new[] { "update-ref", reference, objectId }, 30, allowNonZero: true);
            }
        }
        catch { }
    }

    private static string DecodeSnapshot(string value)
    {
        try { return Encoding.UTF8.GetString(Convert.FromBase64String(value)); }
        catch (FormatException ex) { throw new InvalidDataException("Signed Git snapshot encoding is invalid.", ex); }
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
        if (!plan.Parameters.TryGetValue(key, out var value) || value is null)
            throw new InvalidDataException($"{key} parameter is required.");
        return value;
    }

    private static string GetFileSha256(string path, string label)
    {
        if (!File.Exists(path)) throw new FileNotFoundException($"{label} not found.", path);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException($"{label} may not be a reparse point.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string NormalizeText(string text) => text.Replace("\r\n", "\n", StringComparison.Ordinal).Trim();
    private static string HashText(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
    private sealed record GitProcessResult(int ExitCode, string StdOut, string StdErr);
    private sealed record RemoteState(bool RemoteAbsent, string? RemoteName, string? Url, string? FetchRefspec, bool HasPushUrl);
}

public sealed record GitOriginRepairResult(string PlanId, string Repository, string OriginUrl, string FetchRefspec, string Head, bool Verified, DateTimeOffset ExecutedUtc);
