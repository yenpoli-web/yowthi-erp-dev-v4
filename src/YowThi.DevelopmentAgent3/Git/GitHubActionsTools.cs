using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using ModelContextProtocol.Server;

namespace YowThi.DevelopmentAgent3.Git;

[McpServerToolType]
public static class GitHubActionsTools
{
    private const string GhExe = @"C:\Program Files\GitHub CLI\gh.exe";
    private const string GitExe = @"C:\Program Files\Git\cmd\git.exe";
    private const string RepositoryPath = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string RepositorySlug = "yenpoli-web/yowthi-erp-dev-v4";
    private const string ExpectedOriginUrl = "https://github.com/yenpoli-web/yowthi-erp-dev-v4.git";
    private const string WorkflowFile = "dotnet.yml";

    [McpServerTool(Name = "github_workflow_run_status", ReadOnly = true, Destructive = false, OpenWorld = true)]
    [Description("Read the latest GitHub Actions run for the fixed yenpoli-web/yowthi-erp-dev-v4 dotnet.yml workflow whose head SHA exactly matches one local m*-validation or p*-validation branch. The fixed V4 repository identity, exact dedicated origin HTTPS URL, standard origin fetch refspec, branch name, local branch HEAD, and fixed GitHub CLI binary are validated before querying GitHub. No workflow is dispatched and no repository state is changed.")]
    public static async Task<GitHubWorkflowRunStatusResult> GitHubWorkflowRunStatus(string branchName)
    {
        ValidateValidationBranchName(branchName);
        await ValidateRepositoryIdentityAsync();
        var localHead = await GetLocalBranchHeadAsync(branchName);
        var ghSha256 = GetFileSha256(GhExe, "GitHub CLI");

        var query = await RunGhAsync(new[]
        {
            "run", "list",
            "--repo", RepositorySlug,
            "--workflow", WorkflowFile,
            "--branch", branchName,
            "--limit", "50",
            "--json", "databaseId,headSha,headBranch,event,status,conclusion,createdAt,updatedAt,url"
        }, 60, allowNonZero: true);

        if (query.ExitCode != 0)
        {
            return new GitHubWorkflowRunStatusResult(
                RepositorySlug, WorkflowFile, branchName, localHead, ghSha256,
                false, false, null, null, null, null, null, null, null, null,
                false, $"GitHub CLI query failed with exit code {query.ExitCode}.", DateTimeOffset.UtcNow);
        }

        using var document = JsonDocument.Parse(query.StdOut);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("GitHub CLI run list output was not a JSON array.");

        JsonElement? match = null;
        foreach (var item in document.RootElement.EnumerateArray())
        {
            var headSha = item.TryGetProperty("headSha", out var headShaElement) ? headShaElement.GetString() : null;
            var headBranch = item.TryGetProperty("headBranch", out var headBranchElement) ? headBranchElement.GetString() : null;
            if (string.Equals(headSha, localHead, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(headBranch, branchName, StringComparison.Ordinal))
            {
                match = item.Clone();
                break;
            }
        }

        if (match is null)
        {
            return new GitHubWorkflowRunStatusResult(
                RepositorySlug, WorkflowFile, branchName, localHead, ghSha256,
                true, false, null, null, null, null, null, null, null, null,
                false, null, DateTimeOffset.UtcNow);
        }

        var run = match.Value;
        var runId = run.TryGetProperty("databaseId", out var idElement) && idElement.TryGetInt64(out var parsedId) ? parsedId : (long?)null;
        var runHeadSha = run.TryGetProperty("headSha", out var runHeadElement) ? runHeadElement.GetString() : null;
        var eventName = run.TryGetProperty("event", out var eventElement) ? eventElement.GetString() : null;
        var status = run.TryGetProperty("status", out var statusElement) ? statusElement.GetString() : null;
        var conclusion = run.TryGetProperty("conclusion", out var conclusionElement) ? conclusionElement.GetString() : null;
        var createdAt = run.TryGetProperty("createdAt", out var createdElement) && createdElement.ValueKind == JsonValueKind.String ? createdElement.GetDateTimeOffset() : (DateTimeOffset?)null;
        var updatedAt = run.TryGetProperty("updatedAt", out var updatedElement) && updatedElement.ValueKind == JsonValueKind.String ? updatedElement.GetDateTimeOffset() : (DateTimeOffset?)null;
        var url = run.TryGetProperty("url", out var urlElement) ? urlElement.GetString() : null;
        var succeeded = string.Equals(status, "completed", StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(conclusion, "success", StringComparison.OrdinalIgnoreCase);

        return new GitHubWorkflowRunStatusResult(
            RepositorySlug, WorkflowFile, branchName, localHead, ghSha256,
            true, true, runId, runHeadSha, eventName, status, conclusion, createdAt, updatedAt, url,
            succeeded, null, DateTimeOffset.UtcNow);
    }

    [McpServerTool(Name = "github_workflow_run_jobs", ReadOnly = true, Destructive = false, OpenWorld = true)]
    [Description("Read workflow and job evidence for the fixed yenpoli-web/yowthi-erp-dev-v4 dotnet.yml run whose head SHA exactly matches one local m*-validation or p*-validation branch. The result validates workflow identity, self-hosted runner labels, job conclusions, and eligibility for local main fast-forward. This is read-only.")]
    public static async Task<GitHubWorkflowRunJobsResult> GitHubWorkflowRunJobs(string branchName)
    {
        var runStatus = await GitHubWorkflowRunStatus(branchName);
        if (!runStatus.QuerySucceeded || !runStatus.MatchingRunFound || runStatus.RunId is null)
            return new GitHubWorkflowRunJobsResult(
                RepositorySlug, WorkflowFile, null, null, branchName, runStatus.LocalHead,
                runStatus.RunId, runStatus.Status, runStatus.Conclusion, false,
                Array.Empty<GitHubWorkflowJobEvidence>(), false, false,
                false, runStatus.QueryError ?? "No same-SHA workflow run was found.", DateTimeOffset.UtcNow);

        var runId = runStatus.RunId.Value;
        var runQuery = await RunGhAsync(new[]
        {
            "api", "--method", "GET",
            "-H", "Accept: application/vnd.github+json",
            "-H", "X-GitHub-Api-Version: 2022-11-28",
            $"repos/{RepositorySlug}/actions/runs/{runId}"
        }, 60, allowNonZero: true);
        if (runQuery.ExitCode != 0)
            return new GitHubWorkflowRunJobsResult(
                RepositorySlug, WorkflowFile, null, null, branchName, runStatus.LocalHead,
                runId, runStatus.Status, runStatus.Conclusion, false,
                Array.Empty<GitHubWorkflowJobEvidence>(), false, false,
                false, $"GitHub workflow run API query failed with exit code {runQuery.ExitCode}.", DateTimeOffset.UtcNow);

        using var runDocument = JsonDocument.Parse(runQuery.StdOut);
        var runRoot = runDocument.RootElement;
        var workflowName = runRoot.TryGetProperty("name", out var nameElement) ? nameElement.GetString() : null;
        var workflowPath = runRoot.TryGetProperty("path", out var pathElement) ? pathElement.GetString() : null;
        var apiHeadSha = runRoot.TryGetProperty("head_sha", out var headElement) ? headElement.GetString() : null;
        if (!string.Equals(apiHeadSha, runStatus.LocalHead, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("GitHub workflow run API head SHA does not match the sealed local validation HEAD.");

        var workflowIdentityMatches =
            string.Equals(workflowName, "dotnet-self-hosted", StringComparison.Ordinal) &&
            string.Equals(workflowPath, ".github/workflows/dotnet.yml", StringComparison.Ordinal);

        var jobsQuery = await RunGhAsync(new[]
        {
            "api", "--method", "GET",
            "-H", "Accept: application/vnd.github+json",
            "-H", "X-GitHub-Api-Version: 2022-11-28",
            $"repos/{RepositorySlug}/actions/runs/{runId}/jobs?filter=all&per_page=100"
        }, 60, allowNonZero: true);
        if (jobsQuery.ExitCode != 0)
            return new GitHubWorkflowRunJobsResult(
                RepositorySlug, WorkflowFile, workflowName, workflowPath, branchName, runStatus.LocalHead,
                runId, runStatus.Status, runStatus.Conclusion, workflowIdentityMatches,
                Array.Empty<GitHubWorkflowJobEvidence>(), false, false,
                false, $"GitHub workflow jobs API query failed with exit code {jobsQuery.ExitCode}.", DateTimeOffset.UtcNow);

        using var jobsDocument = JsonDocument.Parse(jobsQuery.StdOut);
        if (!jobsDocument.RootElement.TryGetProperty("jobs", out var jobsElement) || jobsElement.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("GitHub workflow jobs API output did not contain a jobs array.");

        var jobs = new List<GitHubWorkflowJobEvidence>();
        foreach (var job in jobsElement.EnumerateArray())
        {
            var labels = job.TryGetProperty("labels", out var labelsElement) && labelsElement.ValueKind == JsonValueKind.Array
                ? labelsElement.EnumerateArray().Select(x => x.GetString()).Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x!).ToArray()
                : Array.Empty<string>();
            var hasSelfHosted = labels.Contains("self-hosted", StringComparer.OrdinalIgnoreCase);
            var hasYowThiRunner = labels.Contains("yowthi-erp-v2", StringComparer.OrdinalIgnoreCase);
            var jobStatus = job.TryGetProperty("status", out var jobStatusElement) ? jobStatusElement.GetString() : null;
            var jobConclusion = job.TryGetProperty("conclusion", out var jobConclusionElement) ? jobConclusionElement.GetString() : null;
            jobs.Add(new GitHubWorkflowJobEvidence(
                job.TryGetProperty("id", out var jobIdElement) && jobIdElement.TryGetInt64(out var jobId) ? jobId : 0,
                job.TryGetProperty("name", out var jobNameElement) ? jobNameElement.GetString() : null,
                jobStatus,
                jobConclusion,
                job.TryGetProperty("runner_name", out var runnerNameElement) ? runnerNameElement.GetString() : null,
                job.TryGetProperty("runner_group_name", out var runnerGroupElement) ? runnerGroupElement.GetString() : null,
                labels,
                hasSelfHosted,
                hasYowThiRunner,
                string.Equals(jobStatus, "completed", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(jobConclusion, "success", StringComparison.OrdinalIgnoreCase)));
        }

        var requiredRunnerLabelsPresent = jobs.Count > 0 && jobs.All(x => x.HasSelfHostedLabel && x.HasYowThiErpV2Label);
        var allJobsSucceeded = jobs.Count > 0 && jobs.All(x => x.Succeeded);
        var eligible = runStatus.SucceededForLocalHead && workflowIdentityMatches && requiredRunnerLabelsPresent && allJobsSucceeded;

        return new GitHubWorkflowRunJobsResult(
            RepositorySlug, WorkflowFile, workflowName, workflowPath, branchName, runStatus.LocalHead,
            runId, runStatus.Status, runStatus.Conclusion, workflowIdentityMatches,
            jobs, requiredRunnerLabelsPresent, allJobsSucceeded, eligible, null, DateTimeOffset.UtcNow);
    }

    private static void ValidateValidationBranchName(string branchName)
    {
        if (string.IsNullOrWhiteSpace(branchName) || branchName.Length > 128 || branchName.Contains('/') ||
            !(branchName.StartsWith("m", StringComparison.Ordinal) || branchName.StartsWith("p", StringComparison.Ordinal)) ||
            !branchName.EndsWith("-validation", StringComparison.Ordinal) ||
            branchName.Any(c => !(char.IsLetterOrDigit(c) || c is '.' or '_' or '-')))
            throw new ArgumentException("branchName must be a flat m*-validation or p*-validation branch name.", nameof(branchName));
    }

    private static async Task ValidateRepositoryIdentityAsync()
    {
        if (!Directory.Exists(RepositoryPath))
            throw new DirectoryNotFoundException($"Fixed repository does not exist: {RepositoryPath}");
        if ((File.GetAttributes(RepositoryPath) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Fixed repository may not be a reparse point.");
        _ = GetFileSha256(GitExe, "git.exe");

        var top = await RunGitAsync(new[] { "rev-parse", "--show-toplevel" }, 30);
        var resolved = Path.GetFullPath(top.StdOut.Trim()).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!string.Equals(resolved, RepositoryPath, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Fixed Git repository root identity does not match.");

        var urls = await RunGitAsync(new[] { "remote", "get-url", "--all", "origin" }, 30);
        var urlLines = NormalizeText(urls.StdOut).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (urlLines.Length != 1 || !string.Equals(urlLines[0], ExpectedOriginUrl, StringComparison.Ordinal))
            throw new InvalidOperationException("Fixed Git origin URL does not match yenpoli-web/yowthi-erp-dev-v4 over HTTPS.");

        var fetch = await RunGitAsync(new[] { "config", "--get-all", "remote.origin.fetch" }, 30);
        var fetchLines = NormalizeText(fetch.StdOut).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (fetchLines.Length != 1 || !string.Equals(fetchLines[0], "+refs/heads/*:refs/remotes/origin/*", StringComparison.Ordinal))
            throw new InvalidOperationException("Fixed Git origin fetch refspec is not the standard remote-tracking refspec.");
    }

    private static async Task<string> GetLocalBranchHeadAsync(string branchName)
    {
        var result = await RunGitAsync(new[] { "rev-parse", "--verify", $"refs/heads/{branchName}" }, 30);
        var head = result.StdOut.Trim();
        if (head.Length < 12 || head.Any(c => !Uri.IsHexDigit(c)))
            throw new InvalidOperationException("Unable to resolve a valid local validation branch HEAD.");
        return head;
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

    private static async Task<CliResult> RunGitAsync(IReadOnlyList<string> arguments, int timeoutSeconds)
    {
        var psi = new ProcessStartInfo
        {
            FileName = GitExe,
            WorkingDirectory = RepositoryPath,
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
        psi.ArgumentList.Add("-c"); psi.ArgumentList.Add($"safe.directory={RepositoryPath}");
        psi.ArgumentList.Add("-C"); psi.ArgumentList.Add(RepositoryPath);
        foreach (var argument in arguments)
            psi.ArgumentList.Add(argument);
        return await RunProcessAsync(psi, timeoutSeconds, allowNonZero: false, "git.exe");
    }

    private static async Task<CliResult> RunGhAsync(IReadOnlyList<string> arguments, int timeoutSeconds, bool allowNonZero)
    {
        _ = GetFileSha256(GhExe, "GitHub CLI");
        var psi = new ProcessStartInfo
        {
            FileName = GhExe,
            WorkingDirectory = RepositoryPath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        psi.Environment["GH_HOST"] = "github.com";
        psi.Environment["GH_PROMPT_DISABLED"] = "1";
        psi.Environment["GH_PAGER"] = "cat";
        psi.Environment["NO_COLOR"] = "1";
        psi.Environment["GIT_TERMINAL_PROMPT"] = "0";
        foreach (var argument in arguments)
            psi.ArgumentList.Add(argument);
        return await RunProcessAsync(psi, timeoutSeconds, allowNonZero, "gh.exe");
    }

    private static async Task<CliResult> RunProcessAsync(ProcessStartInfo psi, int timeoutSeconds, bool allowNonZero, string label)
    {
        using var process = Process.Start(psi) ?? throw new InvalidOperationException($"{label} failed to start.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        try { await process.WaitForExitAsync(cts.Token); }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"{label} exceeded {timeoutSeconds} seconds.");
        }

        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        var result = new CliResult(process.ExitCode, stdout, stderr);
        if (!allowNonZero && result.ExitCode != 0)
            throw new InvalidOperationException($"{label} exited with code {result.ExitCode}.");
        return result;
    }

    private static string NormalizeText(string text) => text.Replace("\r\n", "\n", StringComparison.Ordinal).Trim();
    private sealed record CliResult(int ExitCode, string StdOut, string StdErr);
}

public sealed record GitHubWorkflowJobEvidence(
    long JobId,
    string? Name,
    string? Status,
    string? Conclusion,
    string? RunnerName,
    string? RunnerGroupName,
    IReadOnlyList<string> Labels,
    bool HasSelfHostedLabel,
    bool HasYowThiErpV2Label,
    bool Succeeded);

public sealed record GitHubWorkflowRunJobsResult(
    string Repository,
    string Workflow,
    string? WorkflowName,
    string? WorkflowPath,
    string Branch,
    string LocalHead,
    long? RunId,
    string? RunStatus,
    string? RunConclusion,
    bool WorkflowIdentityMatches,
    IReadOnlyList<GitHubWorkflowJobEvidence> Jobs,
    bool RequiredRunnerLabelsPresent,
    bool AllJobsSucceeded,
    bool EligibleForMainFastForward,
    string? QueryError,
    DateTimeOffset CheckedUtc);

public sealed record GitHubWorkflowRunStatusResult(
    string Repository,
    string Workflow,
    string Branch,
    string LocalHead,
    string GhCliSha256,
    bool QuerySucceeded,
    bool MatchingRunFound,
    long? RunId,
    string? RunHeadSha,
    string? Event,
    string? Status,
    string? Conclusion,
    DateTimeOffset? CreatedAt,
    DateTimeOffset? UpdatedAt,
    string? Url,
    bool SucceededForLocalHead,
    string? QueryError,
    DateTimeOffset CheckedUtc);
