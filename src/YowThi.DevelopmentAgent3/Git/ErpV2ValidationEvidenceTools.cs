using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ModelContextProtocol.Server;

namespace YowThi.DevelopmentAgent3.Git;

[McpServerToolType]
public static class ErpV2ValidationEvidenceTools
{
    private const string GhExe = @"C:\Program Files\GitHub CLI\gh.exe";
    private const string GitExe = @"C:\Program Files\Git\cmd\git.exe";
    private const string RepositoryPath = @"C:\Dev\yowthi-erp-v2";
    private const string RepositorySlug = "yenpoli-web/yowthi-erp-v2";
    private const string ExpectedOriginUrl = "https://github.com/yenpoli-web/yowthi-erp-v2.git";
    private const string WorkflowFile = "dotnet.yml";
    private const string WorkflowPath = ".github/workflows/dotnet.yml";
    private const string WorkflowName = "dotnet-self-hosted";
    private const string RequiredJobName = "build-test";
    private const string RequiredRunnerName = "YowThi-ERP-V2";
    private const string RunnerRoot = @"C:\actions-runner\actions-runner";
    private const string RunnerDiag = @"C:\actions-runner\actions-runner\_diag";
    private const string RunnerConfig = @"C:\actions-runner\actions-runner\.runner";
    private const int MaxWorkerLogBytes = 2_500_000;
    private const long MaxTotalScanBytes = 32L * 1024 * 1024;
    private const int MaxWorkerLogs = 120;

    [McpServerTool(Name = "erp_v2_github_workflow_run_status", ReadOnly = true, Destructive = false, OpenWorld = true)]
    [Description("Read the latest GitHub Actions run for the fixed yenpoli-web/yowthi-erp-v2 dotnet.yml workflow whose head SHA exactly matches one local flat m*-validation or p*-validation branch in C:\\Dev\\yowthi-erp-v2. Repository root, exact HTTPS origin, standard fetch refspec, branch name, local branch HEAD, workflow, and fixed GitHub CLI identity are validated. Query failures return structured evidence instead of dispatching or mutating anything.")]
    public static async Task<ErpV2GitHubWorkflowRunStatusResult> ErpV2GitHubWorkflowRunStatus(string branchName)
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
            "--limit", "100",
            "--json", "databaseId,headSha,headBranch,event,status,conclusion,createdAt,updatedAt,url"
        }, 60, allowNonZero: true);

        if (query.ExitCode != 0)
        {
            return new ErpV2GitHubWorkflowRunStatusResult(
                RepositorySlug, WorkflowFile, branchName, localHead, ghSha256,
                false, false, null, null, null, null, null, null, null, null,
                false, $"GitHub CLI query failed with exit code {query.ExitCode}.", DateTimeOffset.UtcNow);
        }

        try
        {
            using var document = JsonDocument.Parse(query.StdOut);
            if (document.RootElement.ValueKind != JsonValueKind.Array)
                throw new InvalidDataException("GitHub CLI run list output was not a JSON array.");

            JsonElement? match = null;
            foreach (var item in document.RootElement.EnumerateArray())
            {
                var headSha = item.TryGetProperty("headSha", out var sha) ? sha.GetString() : null;
                var headBranch = item.TryGetProperty("headBranch", out var branch) ? branch.GetString() : null;
                if (string.Equals(headSha, localHead, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(headBranch, branchName, StringComparison.Ordinal))
                {
                    match = item.Clone();
                    break;
                }
            }

            if (match is null)
            {
                return new ErpV2GitHubWorkflowRunStatusResult(
                    RepositorySlug, WorkflowFile, branchName, localHead, ghSha256,
                    true, false, null, null, null, null, null, null, null, null,
                    false, null, DateTimeOffset.UtcNow);
            }

            var run = match.Value;
            var runId = run.TryGetProperty("databaseId", out var idElement) && idElement.TryGetInt64(out var id) ? id : (long?)null;
            var runHeadSha = run.TryGetProperty("headSha", out var runHead) ? runHead.GetString() : null;
            var eventName = run.TryGetProperty("event", out var eventElement) ? eventElement.GetString() : null;
            var status = run.TryGetProperty("status", out var statusElement) ? statusElement.GetString() : null;
            var conclusion = run.TryGetProperty("conclusion", out var conclusionElement) ? conclusionElement.GetString() : null;
            var createdAt = run.TryGetProperty("createdAt", out var createdElement) && createdElement.ValueKind == JsonValueKind.String ? createdElement.GetDateTimeOffset() : (DateTimeOffset?)null;
            var updatedAt = run.TryGetProperty("updatedAt", out var updatedElement) && updatedElement.ValueKind == JsonValueKind.String ? updatedElement.GetDateTimeOffset() : (DateTimeOffset?)null;
            var url = run.TryGetProperty("url", out var urlElement) ? urlElement.GetString() : null;
            var succeeded = string.Equals(status, "completed", StringComparison.OrdinalIgnoreCase) &&
                            string.Equals(conclusion, "success", StringComparison.OrdinalIgnoreCase);

            return new ErpV2GitHubWorkflowRunStatusResult(
                RepositorySlug, WorkflowFile, branchName, localHead, ghSha256,
                true, true, runId, runHeadSha, eventName, status, conclusion, createdAt, updatedAt, url,
                succeeded, null, DateTimeOffset.UtcNow);
        }
        catch (JsonException ex)
        {
            return new ErpV2GitHubWorkflowRunStatusResult(
                RepositorySlug, WorkflowFile, branchName, localHead, ghSha256,
                false, false, null, null, null, null, null, null, null, null,
                false, $"GitHub CLI returned invalid JSON: {ex.GetType().Name}.", DateTimeOffset.UtcNow);
        }
    }

    [McpServerTool(Name = "erp_v2_github_workflow_run_jobs", ReadOnly = true, Destructive = false, OpenWorld = true)]
    [Description("Read exact-SHA workflow and job evidence for the fixed yenpoli-web/yowthi-erp-v2 dotnet.yml validation run. Acceptance requires workflow name dotnet-self-hosted, path .github/workflows/dotnet.yml, exactly one build-test job, runner YowThi-ERP-V2, labels self-hosted and yowthi-erp-v2, successful job conclusion, and a completed-success run for the exact local validation branch HEAD. This is read-only and returns structured query failure evidence.")]
    public static async Task<ErpV2GitHubWorkflowRunJobsResult> ErpV2GitHubWorkflowRunJobs(string branchName)
    {
        var runStatus = await ErpV2GitHubWorkflowRunStatus(branchName);
        if (!runStatus.QuerySucceeded || !runStatus.MatchingRunFound || runStatus.RunId is null)
        {
            return new ErpV2GitHubWorkflowRunJobsResult(
                RepositorySlug, WorkflowFile, null, null, branchName, runStatus.LocalHead,
                runStatus.RunId, runStatus.Status, runStatus.Conclusion,
                false, Array.Empty<ErpV2GitHubWorkflowJobEvidence>(), false, false, false, false,
                runStatus.QueryError ?? "No same-SHA workflow run was found.", DateTimeOffset.UtcNow);
        }

        var runId = runStatus.RunId.Value;
        var runQuery = await RunGhAsync(new[]
        {
            "api", "--method", "GET",
            "-H", "Accept: application/vnd.github+json",
            "-H", "X-GitHub-Api-Version: 2022-11-28",
            $"repos/{RepositorySlug}/actions/runs/{runId}"
        }, 60, allowNonZero: true);
        if (runQuery.ExitCode != 0)
        {
            return new ErpV2GitHubWorkflowRunJobsResult(
                RepositorySlug, WorkflowFile, null, null, branchName, runStatus.LocalHead,
                runId, runStatus.Status, runStatus.Conclusion,
                false, Array.Empty<ErpV2GitHubWorkflowJobEvidence>(), false, false, false, false,
                $"GitHub workflow run API query failed with exit code {runQuery.ExitCode}.", DateTimeOffset.UtcNow);
        }

        try
        {
            using var runDocument = JsonDocument.Parse(runQuery.StdOut);
            var root = runDocument.RootElement;
            var workflowName = root.TryGetProperty("name", out var name) ? name.GetString() : null;
            var workflowPath = root.TryGetProperty("path", out var path) ? path.GetString() : null;
            var apiHeadSha = root.TryGetProperty("head_sha", out var head) ? head.GetString() : null;
            if (!string.Equals(apiHeadSha, runStatus.LocalHead, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("GitHub run API head SHA does not match the exact local validation HEAD.");

            var workflowIdentityMatches = string.Equals(workflowName, WorkflowName, StringComparison.Ordinal) &&
                                          string.Equals(workflowPath, WorkflowPath, StringComparison.Ordinal);

            var jobsQuery = await RunGhAsync(new[]
            {
                "api", "--method", "GET",
                "-H", "Accept: application/vnd.github+json",
                "-H", "X-GitHub-Api-Version: 2022-11-28",
                $"repos/{RepositorySlug}/actions/runs/{runId}/jobs?filter=all&per_page=100"
            }, 60, allowNonZero: true);
            if (jobsQuery.ExitCode != 0)
            {
                return new ErpV2GitHubWorkflowRunJobsResult(
                    RepositorySlug, WorkflowFile, workflowName, workflowPath, branchName, runStatus.LocalHead,
                    runId, runStatus.Status, runStatus.Conclusion,
                    workflowIdentityMatches, Array.Empty<ErpV2GitHubWorkflowJobEvidence>(), false, false, false, false,
                    $"GitHub workflow jobs API query failed with exit code {jobsQuery.ExitCode}.", DateTimeOffset.UtcNow);
            }

            using var jobsDocument = JsonDocument.Parse(jobsQuery.StdOut);
            if (!jobsDocument.RootElement.TryGetProperty("jobs", out var jobsElement) || jobsElement.ValueKind != JsonValueKind.Array)
                throw new InvalidDataException("GitHub workflow jobs API output did not contain a jobs array.");

            var jobs = new List<ErpV2GitHubWorkflowJobEvidence>();
            foreach (var job in jobsElement.EnumerateArray())
            {
                var labels = job.TryGetProperty("labels", out var labelsElement) && labelsElement.ValueKind == JsonValueKind.Array
                    ? labelsElement.EnumerateArray().Select(x => x.GetString()).Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x!).ToArray()
                    : Array.Empty<string>();
                var hasSelfHosted = labels.Contains("self-hosted", StringComparer.OrdinalIgnoreCase);
                var hasErpV2 = labels.Contains("yowthi-erp-v2", StringComparer.OrdinalIgnoreCase);
                var jobStatus = job.TryGetProperty("status", out var jobStatusElement) ? jobStatusElement.GetString() : null;
                var jobConclusion = job.TryGetProperty("conclusion", out var jobConclusionElement) ? jobConclusionElement.GetString() : null;
                var runnerName = job.TryGetProperty("runner_name", out var runnerNameElement) ? runnerNameElement.GetString() : null;
                var jobName = job.TryGetProperty("name", out var jobNameElement) ? jobNameElement.GetString() : null;
                jobs.Add(new ErpV2GitHubWorkflowJobEvidence(
                    job.TryGetProperty("id", out var jobIdElement) && jobIdElement.TryGetInt64(out var jobId) ? jobId : 0,
                    jobName,
                    jobStatus,
                    jobConclusion,
                    runnerName,
                    job.TryGetProperty("runner_group_name", out var runnerGroupElement) ? runnerGroupElement.GetString() : null,
                    labels,
                    hasSelfHosted,
                    hasErpV2,
                    string.Equals(runnerName, RequiredRunnerName, StringComparison.Ordinal),
                    string.Equals(jobName, RequiredJobName, StringComparison.Ordinal),
                    string.Equals(jobStatus, "completed", StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(jobConclusion, "success", StringComparison.OrdinalIgnoreCase)));
            }

            var jobIdentityMatches = jobs.Count == 1 && jobs[0].IsRequiredBuildTestJob;
            var requiredRunnerIdentityMatches = jobs.Count == 1 && jobs[0].IsRequiredRunner;
            var requiredRunnerLabelsPresent = jobs.Count == 1 && jobs[0].HasSelfHostedLabel && jobs[0].HasYowThiErpV2Label;
            var allJobsSucceeded = jobs.Count == 1 && jobs[0].Succeeded;
            var eligible = runStatus.SucceededForLocalHead && workflowIdentityMatches && jobIdentityMatches &&
                           requiredRunnerIdentityMatches && requiredRunnerLabelsPresent && allJobsSucceeded;

            return new ErpV2GitHubWorkflowRunJobsResult(
                RepositorySlug, WorkflowFile, workflowName, workflowPath, branchName, runStatus.LocalHead,
                runId, runStatus.Status, runStatus.Conclusion,
                workflowIdentityMatches, jobs, jobIdentityMatches, requiredRunnerIdentityMatches,
                requiredRunnerLabelsPresent, eligible, null, DateTimeOffset.UtcNow);
        }
        catch (Exception ex) when (ex is JsonException or InvalidDataException)
        {
            return new ErpV2GitHubWorkflowRunJobsResult(
                RepositorySlug, WorkflowFile, null, null, branchName, runStatus.LocalHead,
                runId, runStatus.Status, runStatus.Conclusion,
                false, Array.Empty<ErpV2GitHubWorkflowJobEvidence>(), false, false, false, false,
                $"GitHub workflow evidence parse failed: {ex.GetType().Name}: {ex.Message}", DateTimeOffset.UtcNow);
        }
    }

    [McpServerTool(Name = "erp_v2_runner_validation_evidence", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read a typed local fallback evidence chain for one exact local ERP V2 validation branch HEAD from the fixed self-hosted runner at C:\\actions-runner\\actions-runner. It validates the runner .runner identity without reading credentials, validates the exact branch workflow declares dotnet-self-hosted / build-test / self-hosted + yowthi-erp-v2, and scans a bounded set of Worker logs for one same-file evidence chain containing exact repository, branch ref, SHA/workflow SHA, workflow ref, build-test job identity, complete_job succeeded telemetry, final Succeeded result, and worker completion. Raw log content and secrets are never returned.")]
    public static async Task<ErpV2RunnerValidationEvidenceResult> ErpV2RunnerValidationEvidence(string branchName)
    {
        ValidateValidationBranchName(branchName);
        await ValidateRepositoryIdentityAsync();
        var localHead = await GetLocalBranchHeadAsync(branchName);
        var workflowText = await GetWorkflowTextAtBranchAsync(branchName);
        var workflowSha256 = HashText(workflowText);
        var workflowNameMatches = Regex.IsMatch(workflowText, @"(?m)^\s*name\s*:\s*dotnet-self-hosted\s*$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        var jobIdentityMatches = Regex.IsMatch(workflowText, @"(?m)^\s{2}build-test\s*:\s*$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        var requiredLabelsDeclared = WorkflowDeclaresRequiredRunnerLabels(workflowText);

        var runnerIdentity = ReadRunnerIdentity();
        var runnerIdentityMatches = string.Equals(runnerIdentity.AgentName, RequiredRunnerName, StringComparison.Ordinal) &&
                                    string.Equals(runnerIdentity.GitHubUrl, $"https://github.com/{RepositorySlug}", StringComparison.Ordinal);

        string? matchedLogName = null;
        string? matchedLogSha256 = null;
        long matchedLogBytes = 0;
        DateTimeOffset? matchedLogLastWriteUtc = null;
        var exactSha = false;
        var exactBranchRef = false;
        var exactRepository = false;
        var exactWorkflowRef = false;
        var exactWorkflowSha = false;
        var exactJob = false;
        var completeJobSucceeded = false;
        var finalResultSucceeded = false;
        var workerCompleted = false;
        long totalScannedBytes = 0;
        var scannedFileCount = 0;

        if (Directory.Exists(RunnerDiag) && (File.GetAttributes(RunnerDiag) & FileAttributes.ReparsePoint) == 0)
        {
            var candidates = Directory.EnumerateFiles(RunnerDiag, "Worker_*-utc.log", SearchOption.TopDirectoryOnly)
                .Select(path => new FileInfo(path))
                .Where(info => (info.Attributes & FileAttributes.ReparsePoint) == 0 && info.Length > 0 && info.Length <= MaxWorkerLogBytes)
                .OrderByDescending(info => info.LastWriteTimeUtc)
                .Take(MaxWorkerLogs)
                .ToArray();

            foreach (var info in candidates)
            {
                if (totalScannedBytes + info.Length > MaxTotalScanBytes)
                    break;
                totalScannedBytes += info.Length;
                scannedFileCount++;

                string text;
                try
                {
                    text = File.ReadAllText(info.FullName, new UTF8Encoding(false, true));
                }
                catch (DecoderFallbackException)
                {
                    continue;
                }

                var shaEvidence = text.Contains(localHead, StringComparison.OrdinalIgnoreCase);
                var branchEvidence = text.Contains($"refs/heads/{branchName}", StringComparison.Ordinal) &&
                                     text.Contains($"\"v\": \"{branchName}\"", StringComparison.Ordinal);
                var repositoryEvidence = text.Contains($"\"v\": \"{RepositorySlug}\"", StringComparison.Ordinal) &&
                                         text.Contains($"_PipelineMapping\\{RepositorySlug}\\PipelineFolder.json", StringComparison.OrdinalIgnoreCase);
                var workflowRefEvidence = text.Contains($"{RepositorySlug}/{WorkflowPath}@refs/heads/{branchName}", StringComparison.Ordinal);
                var workflowShaEvidence = text.Contains("\"k\": \"workflow_sha\"", StringComparison.Ordinal) &&
                                          text.Contains($"\"v\": \"{localHead}\"", StringComparison.OrdinalIgnoreCase);
                var jobEvidence = text.Contains("\"jobDisplayName\": \"build-test\"", StringComparison.Ordinal) &&
                                  text.Contains("\"lit\": \"build-test\"", StringComparison.Ordinal);
                var completeEvidence = ContainsSucceededCompleteJobTelemetry(text);
                var finalEvidence = text.Contains("Job result after all job steps finish: Succeeded", StringComparison.Ordinal);
                var workerDoneEvidence = text.Contains("[INFO Worker] Job completed.", StringComparison.Ordinal);

                if (shaEvidence && branchEvidence && repositoryEvidence && workflowRefEvidence && workflowShaEvidence &&
                    jobEvidence && completeEvidence && finalEvidence && workerDoneEvidence)
                {
                    exactSha = shaEvidence;
                    exactBranchRef = branchEvidence;
                    exactRepository = repositoryEvidence;
                    exactWorkflowRef = workflowRefEvidence;
                    exactWorkflowSha = workflowShaEvidence;
                    exactJob = jobEvidence;
                    completeJobSucceeded = completeEvidence;
                    finalResultSucceeded = finalEvidence;
                    workerCompleted = workerDoneEvidence;
                    matchedLogName = info.Name;
                    matchedLogBytes = info.Length;
                    matchedLogLastWriteUtc = new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero);
                    matchedLogSha256 = GetFileSha256(info.FullName, "Runner Worker log");
                    break;
                }
            }
        }

        var accepted = runnerIdentityMatches && workflowNameMatches && jobIdentityMatches && requiredLabelsDeclared &&
                       matchedLogName is not null && exactSha && exactBranchRef && exactRepository && exactWorkflowRef &&
                       exactWorkflowSha && exactJob && completeJobSucceeded && finalResultSucceeded && workerCompleted;

        var reasons = new List<string>();
        if (!runnerIdentityMatches) reasons.Add("runner-identity-mismatch");
        if (!workflowNameMatches) reasons.Add("workflow-name-mismatch");
        if (!jobIdentityMatches) reasons.Add("build-test-job-not-declared");
        if (!requiredLabelsDeclared) reasons.Add("required-runner-labels-not-declared");
        if (matchedLogName is null) reasons.Add("no-complete-same-file-worker-evidence-chain");

        return new ErpV2RunnerValidationEvidenceResult(
            RepositorySlug, branchName, localHead,
            runnerIdentity.AgentName, runnerIdentity.GitHubUrl, runnerIdentity.RunnerConfigSha256,
            runnerIdentityMatches, workflowSha256, workflowNameMatches, jobIdentityMatches, requiredLabelsDeclared,
            scannedFileCount, totalScannedBytes, matchedLogName, matchedLogSha256, matchedLogBytes, matchedLogLastWriteUtc,
            exactSha, exactBranchRef, exactRepository, exactWorkflowRef, exactWorkflowSha, exactJob,
            completeJobSucceeded, finalResultSucceeded, workerCompleted, accepted, reasons, DateTimeOffset.UtcNow);
    }

    private static bool ContainsSucceededCompleteJobTelemetry(string text)
    {
        const string marker = "\"action\": \"complete_job\"";
        var index = text.IndexOf(marker, StringComparison.Ordinal);
        while (index >= 0)
        {
            var length = Math.Min(1600, text.Length - index);
            var segment = text.Substring(index, length);
            if (segment.Contains("\"result\": \"succeeded\"", StringComparison.OrdinalIgnoreCase))
                return true;
            index = text.IndexOf(marker, index + marker.Length, StringComparison.Ordinal);
        }
        return false;
    }

    private static bool WorkflowDeclaresRequiredRunnerLabels(string workflowText)
    {
        var match = Regex.Match(workflowText, @"(?ms)^\s{2}build-test\s*:\s*$.*?^\s{4}runs-on\s*:\s*(?<value>[^\r\n]*(?:\r?\n\s{6,}[^\r\n]*){0,6})", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
        if (!match.Success)
            return false;
        var value = match.Groups["value"].Value;
        return value.Contains("self-hosted", StringComparison.OrdinalIgnoreCase) &&
               value.Contains("yowthi-erp-v2", StringComparison.OrdinalIgnoreCase);
    }

    private static RunnerIdentity ReadRunnerIdentity()
    {
        if (!Directory.Exists(RunnerRoot) || (File.GetAttributes(RunnerRoot) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Fixed ERP V2 runner root is missing or unsafe.");
        if (!File.Exists(RunnerConfig) || (File.GetAttributes(RunnerConfig) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Fixed ERP V2 .runner file is missing or unsafe.");
        if (new FileInfo(RunnerConfig).Length > 64 * 1024)
            throw new InvalidDataException("ERP V2 .runner file exceeds the bounded size limit.");

        using var doc = JsonDocument.Parse(File.ReadAllText(RunnerConfig, new UTF8Encoding(false, true)));
        var root = doc.RootElement;
        var agentName = root.TryGetProperty("agentName", out var agent) ? agent.GetString() : null;
        var githubUrl = root.TryGetProperty("gitHubUrl", out var url) ? url.GetString() : null;
        return new RunnerIdentity(agentName, githubUrl, GetFileSha256(RunnerConfig, "ERP V2 .runner"));
    }

    private static async Task<string> GetWorkflowTextAtBranchAsync(string branchName)
    {
        var result = await RunGitAsync(new[] { "show", $"refs/heads/{branchName}:{WorkflowPath}" }, 30);
        if (string.IsNullOrWhiteSpace(result.StdOut))
            throw new InvalidDataException("ERP V2 workflow file is empty at the requested validation branch.");
        if (Encoding.UTF8.GetByteCount(result.StdOut) > 512 * 1024)
            throw new InvalidDataException("ERP V2 workflow file exceeds the bounded size limit.");
        return result.StdOut.Replace("\r\n", "\n", StringComparison.Ordinal);
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
            throw new DirectoryNotFoundException($"Fixed ERP V2 repository does not exist: {RepositoryPath}");
        if ((File.GetAttributes(RepositoryPath) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Fixed ERP V2 repository may not be a reparse point.");
        _ = GetFileSha256(GitExe, "git.exe");

        var top = await RunGitAsync(new[] { "rev-parse", "--show-toplevel" }, 30);
        var resolved = Path.GetFullPath(top.StdOut.Trim()).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!string.Equals(resolved, RepositoryPath, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Fixed ERP V2 Git repository root identity does not match.");

        var urls = await RunGitAsync(new[] { "remote", "get-url", "--all", "origin" }, 30);
        var urlLines = NormalizeText(urls.StdOut).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (urlLines.Length != 1 || !string.Equals(urlLines[0], ExpectedOriginUrl, StringComparison.Ordinal))
            throw new InvalidOperationException("Fixed ERP V2 Git origin URL does not match the expected HTTPS repository.");

        var fetch = await RunGitAsync(new[] { "config", "--get-all", "remote.origin.fetch" }, 30);
        var fetchLines = NormalizeText(fetch.StdOut).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (fetchLines.Length != 1 || !string.Equals(fetchLines[0], "+refs/heads/*:refs/remotes/origin/*", StringComparison.Ordinal))
            throw new InvalidOperationException("Fixed ERP V2 Git origin fetch refspec is not standard.");
    }

    private static async Task<string> GetLocalBranchHeadAsync(string branchName)
    {
        var result = await RunGitAsync(new[] { "rev-parse", "--verify", $"refs/heads/{branchName}" }, 30);
        var head = result.StdOut.Trim();
        if (head.Length != 40 || head.Any(c => !Uri.IsHexDigit(c)))
            throw new InvalidOperationException("Unable to resolve a valid exact ERP V2 local validation branch HEAD.");
        return head;
    }

    private static string GetFileSha256(string path, string label)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException($"{label} not found.", path);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException($"{label} may not be a reparse point.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
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
        psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("submodule.recurse=false");
        psi.ArgumentList.Add("-c"); psi.ArgumentList.Add($"safe.directory={RepositoryPath}");
        psi.ArgumentList.Add("-C"); psi.ArgumentList.Add(RepositoryPath);
        foreach (var argument in arguments)
            psi.ArgumentList.Add(argument);
        return await RunProcessAsync(psi, timeoutSeconds, false, "git.exe");
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
        try
        {
            await process.WaitForExitAsync(cts.Token);
        }
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
    private static string HashText(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    private sealed record CliResult(int ExitCode, string StdOut, string StdErr);
    private sealed record RunnerIdentity(string? AgentName, string? GitHubUrl, string RunnerConfigSha256);
}

public sealed record ErpV2GitHubWorkflowRunStatusResult(
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

public sealed record ErpV2GitHubWorkflowJobEvidence(
    long JobId,
    string? Name,
    string? Status,
    string? Conclusion,
    string? RunnerName,
    string? RunnerGroupName,
    IReadOnlyList<string> Labels,
    bool HasSelfHostedLabel,
    bool HasYowThiErpV2Label,
    bool IsRequiredRunner,
    bool IsRequiredBuildTestJob,
    bool Succeeded);

public sealed record ErpV2GitHubWorkflowRunJobsResult(
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
    IReadOnlyList<ErpV2GitHubWorkflowJobEvidence> Jobs,
    bool JobIdentityMatches,
    bool RequiredRunnerIdentityMatches,
    bool RequiredRunnerLabelsPresent,
    bool EligibleForMainFastForward,
    string? QueryError,
    DateTimeOffset CheckedUtc);

public sealed record ErpV2RunnerValidationEvidenceResult(
    string Repository,
    string Branch,
    string LocalHead,
    string? RunnerName,
    string? RunnerRepositoryUrl,
    string RunnerConfigSha256,
    bool RunnerIdentityMatches,
    string WorkflowSha256,
    bool WorkflowNameMatches,
    bool JobIdentityMatches,
    bool RequiredRunnerLabelsDeclared,
    int ScannedWorkerLogCount,
    long ScannedWorkerLogBytes,
    string? MatchedWorkerLog,
    string? MatchedWorkerLogSha256,
    long MatchedWorkerLogBytes,
    DateTimeOffset? MatchedWorkerLogLastWriteUtc,
    bool ExactShaEvidence,
    bool ExactBranchRefEvidence,
    bool ExactRepositoryEvidence,
    bool ExactWorkflowRefEvidence,
    bool ExactWorkflowShaEvidence,
    bool ExactJobEvidence,
    bool CompleteJobSucceededEvidence,
    bool FinalResultSucceededEvidence,
    bool WorkerCompletedEvidence,
    bool Accepted,
    IReadOnlyList<string> FailureReasons,
    DateTimeOffset CheckedUtc);
