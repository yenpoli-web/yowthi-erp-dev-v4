using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Build;

[McpServerToolType]
public static class DotnetDevelopmentTools
{
    private sealed class DotnetJobEntry
    {
        public required string JobId { get; init; }
        public required string Operation { get; init; }
        public required string ProjectPath { get; init; }
        public required string WorkingDirectory { get; init; }
        public required int TimeoutSeconds { get; init; }
        public string? Configuration { get; init; }
        public required Process Process { get; init; }
        public required int ProcessId { get; init; }
        public required DateTimeOffset ProcessStartUtc { get; init; }
        public required DateTimeOffset StartedUtc { get; init; }
        public object Gate { get; } = new();
        public StringBuilder StdOut { get; } = new();
        public StringBuilder StdErr { get; } = new();
        public TaskCompletionSource<bool> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool StdOutTruncated { get; set; }
        public bool StdErrTruncated { get; set; }
        public bool TimedOut { get; set; }
        public bool Cancelled { get; set; }
        public int? ExitCode { get; set; }
        public DateTimeOffset? CompletedUtc { get; set; }
        public string? Failure { get; set; }
    }

    private sealed record FingerprintSnapshot(string Sha256, int FileCount);

    private const int MaxOutputChars = 1_000_000;
    private const int MaxRetainedJobs = 128;
    private const string DotnetExe = @"C:\Program Files\dotnet\dotnet.exe";
    private const string DevRoot = @"C:\Dev";

    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly ConcurrentDictionary<string, DotnetJobEntry> Jobs = new(StringComparer.Ordinal);
    private static readonly Regex SlnProjectPattern = new("\"(?<path>[^\"]+\\.(?:csproj|fsproj|vbproj))\"", RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
    private static readonly HashSet<string> AncestorInputNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Directory.Build.props",
        "Directory.Build.targets",
        "Directory.Packages.props",
        "Directory.Packages.targets",
        "Directory.Build.rsp",
        "NuGet.Config",
        "nuget.config",
        "global.json"
    };

    [McpServerTool(Name = "dotnet_restore_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed plan to start one managed fixed dotnet restore job for a .NET project or solution under the C:\\Dev development workspace root. The project/solution graph, static ProjectReference inputs, applicable Directory.Build/Directory.Packages/global.json/NuGet configuration, target SHA-256, fixed dotnet.exe SHA-256, working directory, and timeout are fingerprinted and sealed. The plan itself performs no network access. Arbitrary CLI arguments, package sources, runtimes, properties, paths outside C:\\Dev, and production paths are rejected.")]
    public static SignedPlan DotnetRestorePlan(string projectPath, int timeoutSeconds = 300)
        => Prepare(projectPath, "dotnet-restore", timeoutSeconds);

    [McpServerTool(Name = "dotnet_restore_execute", ReadOnly = false, Destructive = false, OpenWorld = true)]
    [Description("Execute one previously prepared build/dotnet-restore plan by starting an Agent-owned managed fixed dotnet restore --nologo --no-cache job. The sealed project/solution input fingerprint, fixed dotnet.exe SHA-256, exact working directory, timeout, and signed intent are revalidated immediately before start. Output is captured as UTF-8 with fixed en-US CLI language. The call returns after process start; use dotnet_job_status for state, stdout, stderr, exit code, timeout, and completion.")]
    public static DotnetJobStartResult DotnetRestoreExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
        => StartJob(planId, approvalCode, operation, target, summary, riskClass, "dotnet-restore");

    [McpServerTool(Name = "dotnet_test_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed plan to start one managed fixed dotnet test job for a .NET project or solution under the C:\\Dev development workspace root. The project/solution input fingerprint, fixed dotnet.exe SHA-256, exact Debug/Release build-output fingerprint, working directory, configuration, and timeout are sealed. Test execution is fixed to --no-restore --no-build so no build or dependency restore occurs after approval. Arbitrary test arguments, filters, loggers, environment variables, properties, paths outside C:\\Dev, and production paths are rejected.")]
    public static SignedPlan DotnetTestPlan(string projectPath, string configuration = "Release", int timeoutSeconds = 600)
    {
        if (configuration is not ("Debug" or "Release"))
            throw new ArgumentException("Configuration must be Debug or Release.", nameof(configuration));
        return Prepare(projectPath, "dotnet-test", timeoutSeconds, configuration);
    }

    [McpServerTool(Name = "dotnet_test_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared build/dotnet-test plan by starting an Agent-owned managed fixed dotnet test --configuration <sealed> --no-restore --no-build job. The project/solution input fingerprint, sealed build-output fingerprint, fixed dotnet.exe SHA-256, exact working directory, configuration, timeout, and signed intent are revalidated immediately before start. Output is captured as UTF-8 with fixed en-US CLI language. No build or restore is performed.")]
    public static DotnetJobStartResult DotnetTestExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
        => StartJob(planId, approvalCode, operation, target, summary, riskClass, "dotnet-test");

    [McpServerTool(Name = "dotnet_job_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List dotnet restore/test jobs started and still retained by this Agent runtime. This is read-only. It returns job identity, operation, project, process identity, state, exit code, timeout/cancel flags, and timestamps without starting, stopping, or modifying a process.")]
    public static IReadOnlyList<DotnetJobSummary> DotnetJobList()
    {
        CleanupCompletedJobs();
        return Jobs.Values.Select(ToSummary).OrderByDescending(x => x.StartedUtc).ToArray();
    }

    [McpServerTool(Name = "dotnet_job_status", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read one Agent-owned dotnet restore/test job by job ID. The result includes state, partial or final stdout/stderr, exit code when available, output truncation flags, timeout/cancel flags, process identity, and timestamps. This is read-only.")]
    public static DotnetJobStatus DotnetJobStatus(string jobId)
    {
        var entry = GetJob(jobId);
        lock (entry.Gate)
        {
            return new DotnetJobStatus(
                entry.JobId,
                entry.Operation,
                entry.ProjectPath,
                entry.Configuration,
                entry.ProcessId,
                entry.ProcessStartUtc,
                GetState(entry),
                entry.ExitCode,
                entry.TimeoutSeconds,
                entry.TimedOut,
                entry.Cancelled,
                entry.StdOut.ToString(),
                entry.StdErr.ToString(),
                entry.StdOutTruncated,
                entry.StdErrTruncated,
                entry.StartedUtc,
                entry.CompletedUtc,
                entry.Failure);
        }
    }

    [McpServerTool(Name = "dotnet_job_cancel_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed plan to cancel one active Agent-owned dotnet restore/test job by job ID. Arbitrary PIDs are not accepted. Job ID, operation, project identity, process ID, process start time, and current running state are sealed.")]
    public static SignedPlan DotnetJobCancelPlan(string jobId)
    {
        var entry = GetJob(jobId);
        lock (entry.Gate)
        {
            if (entry.CompletedUtc is not null || entry.Process.HasExited)
                throw new InvalidOperationException("Dotnet job has already completed.");

            var now = DateTimeOffset.UtcNow;
            var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["jobId"] = entry.JobId,
                ["jobOperation"] = entry.Operation,
                ["projectPath"] = entry.ProjectPath,
                ["processId"] = entry.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["processStartUtc"] = entry.ProcessStartUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture)
            };
            var summary = $"Cancel Agent-owned dotnet job {entry.JobId} ({entry.Operation}, PID {entry.ProcessId})";
            var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "build", "dotnet-job-cancel", entry.JobId, parameters, RiskClass.Medium, summary, now, now.AddMinutes(10), string.Empty);
            var signed = unsigned with { Signature = Signer.Sign(unsigned) };
            Store.Add(signed);
            Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, entry.JobId, entry.ProcessId, signed.RiskClass, signed.Summary }, "prepared");
            return signed;
        }
    }

    [McpServerTool(Name = "dotnet_job_cancel_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared build/dotnet-job-cancel plan. Only the exact active Agent-owned dotnet job sealed in the plan can be terminated. Job ID, operation, project identity, PID, and process start time are revalidated before native .NET process-tree termination. Arbitrary PID termination is not supported.")]
    public static async Task<ExecutionResult> DotnetJobCancelExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, operation, target, summary, riskClass, "dotnet-job-cancel");

        var jobId = RequireParameter(plan, "jobId");
        var expectedOperation = RequireParameter(plan, "jobOperation");
        var expectedProject = RequireParameter(plan, "projectPath");
        if (!int.TryParse(RequireParameter(plan, "processId"), out var expectedProcessId))
            throw new InvalidDataException("Signed processId is invalid.");
        if (!DateTimeOffset.TryParse(RequireParameter(plan, "processStartUtc"), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out var expectedStartUtc))
            throw new InvalidDataException("Signed processStartUtc is invalid.");

        var entry = GetJob(jobId);
        lock (entry.Gate)
        {
            if (!string.Equals(entry.Operation, expectedOperation, StringComparison.Ordinal) ||
                !string.Equals(entry.ProjectPath, expectedProject, StringComparison.OrdinalIgnoreCase) ||
                entry.ProcessId != expectedProcessId ||
                entry.ProcessStartUtc != expectedStartUtc)
                throw new UnauthorizedAccessException("Dotnet job identity no longer matches the signed cancel plan.");
            if (entry.CompletedUtc is not null || entry.Process.HasExited)
                throw new InvalidOperationException("Dotnet job has already completed.");
            entry.Cancelled = true;
        }

        try
        {
            entry.Process.Kill(entireProcessTree: true);
            await entry.Process.WaitForExitAsync();
            await entry.Completion.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Store.Consume(planId);
            var outcome = $"cancelled-dotnet-job:{jobId};pid={entry.ProcessId}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, jobId, entry.ProcessId, outcome }, "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, jobId, error = ex.Message }, "failed");
            throw;
        }
    }

    private static SignedPlan Prepare(string projectPath, string operation, int timeoutSeconds, string? configuration = null)
    {
        var project = ValidateProject(projectPath);
        if (timeoutSeconds < 30 || timeoutSeconds > 7200)
            throw new ArgumentOutOfRangeException(nameof(timeoutSeconds), "Timeout must be between 30 and 7200 seconds.");

        var workingDirectory = Path.GetDirectoryName(project) ?? throw new InvalidOperationException("Project working directory could not be resolved.");
        var inputFingerprint = ComputeInputFingerprint(project);
        FingerprintSnapshot? buildFingerprint = null;
        if (operation == "dotnet-test")
        {
            if (configuration is null) throw new InvalidDataException("Test configuration is required.");
            buildFingerprint = ComputeBuildFingerprint(project, configuration);
        }

        var now = DateTimeOffset.UtcNow;
        var jobId = Guid.NewGuid().ToString("N");
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["jobId"] = jobId,
            ["projectPath"] = project,
            ["projectSha256"] = Sha256File(project),
            ["inputFingerprintSha256"] = inputFingerprint.Sha256,
            ["inputFileCount"] = inputFingerprint.FileCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["workingDirectory"] = workingDirectory,
            ["dotnetExeSha256"] = Sha256File(DotnetExe),
            ["timeoutSeconds"] = timeoutSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };
        if (configuration is not null) parameters["configuration"] = configuration;
        if (buildFingerprint is not null)
        {
            parameters["buildFingerprintSha256"] = buildFingerprint.Sha256;
            parameters["buildFileCount"] = buildFingerprint.FileCount.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        var summary = operation == "dotnet-restore"
            ? $"Start managed .NET dependency restore job {jobId} for {project} with sealed input graph"
            : $"Start managed .NET test job {jobId} for {project} ({configuration}) from sealed build outputs";
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "build", operation, project, parameters, RiskClass.Medium, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, jobId, inputFingerprint = inputFingerprint.Sha256, buildFingerprint = buildFingerprint?.Sha256, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    private static DotnetJobStartResult StartJob(string planId, string approvalCode, string operation, string target, string summary, string riskClass, string expectedOperation)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, operation, target, summary, riskClass, expectedOperation);

        var jobId = RequireParameter(plan, "jobId");
        var project = ValidateProject(RequireParameter(plan, "projectPath"));
        var workingDirectory = Path.GetFullPath(RequireParameter(plan, "workingDirectory"));
        if (!string.Equals(workingDirectory, Path.GetDirectoryName(project), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Project working directory changed after plan preparation.");

        if (!string.Equals(RequireParameter(plan, "projectSha256"), Sha256File(project), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Project or solution file changed after plan preparation.");

        var inputFingerprint = ComputeInputFingerprint(project);
        if (!string.Equals(RequireParameter(plan, "inputFingerprintSha256"), inputFingerprint.Sha256, StringComparison.OrdinalIgnoreCase) ||
            !int.TryParse(RequireParameter(plan, "inputFileCount"), out var expectedInputCount) || expectedInputCount != inputFingerprint.FileCount)
            throw new InvalidOperationException("Project/solution dependency or configuration inputs changed after plan preparation.");

        if (!string.Equals(RequireParameter(plan, "dotnetExeSha256"), Sha256File(DotnetExe), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("dotnet.exe changed after plan preparation.");

        if (!int.TryParse(RequireParameter(plan, "timeoutSeconds"), out var timeoutSeconds) || timeoutSeconds < 30 || timeoutSeconds > 7200)
            throw new InvalidDataException("timeoutSeconds parameter is invalid.");
        if (Jobs.ContainsKey(jobId))
            throw new InvalidOperationException("Dotnet job ID already exists in this Agent runtime.");

        string? configuration = null;
        FingerprintSnapshot? buildFingerprint = null;
        if (expectedOperation == "dotnet-test")
        {
            configuration = RequireParameter(plan, "configuration");
            if (configuration is not ("Debug" or "Release"))
                throw new InvalidDataException("configuration parameter is invalid.");
            buildFingerprint = ComputeBuildFingerprint(project, configuration);
            if (!string.Equals(RequireParameter(plan, "buildFingerprintSha256"), buildFingerprint.Sha256, StringComparison.OrdinalIgnoreCase) ||
                !int.TryParse(RequireParameter(plan, "buildFileCount"), out var expectedBuildCount) || expectedBuildCount != buildFingerprint.FileCount)
                throw new InvalidOperationException("Built test artifacts changed after plan preparation.");
        }

        var psi = new ProcessStartInfo
        {
            FileName = DotnetExe,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            CreateNoWindow = true
        };
        psi.Environment["DOTNET_CLI_UI_LANGUAGE"] = "en-US";
        psi.Environment["DOTNET_NOLOGO"] = "1";
        psi.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        psi.ArgumentList.Add(expectedOperation == "dotnet-restore" ? "restore" : "test");
        psi.ArgumentList.Add(project);

        if (expectedOperation == "dotnet-restore")
        {
            psi.ArgumentList.Add("--nologo");
            psi.ArgumentList.Add("--no-cache");
        }
        else
        {
            psi.ArgumentList.Add("--configuration");
            psi.ArgumentList.Add(configuration!);
            psi.ArgumentList.Add("--no-restore");
            psi.ArgumentList.Add("--no-build");
        }

        CleanupCompletedJobs();
        var process = new Process { StartInfo = psi, EnableRaisingEvents = true };
        if (!process.Start()) throw new InvalidOperationException($"{expectedOperation} failed to start.");

        var startedUtc = DateTimeOffset.UtcNow;
        var processStartUtc = new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero);
        var entry = new DotnetJobEntry
        {
            JobId = jobId,
            Operation = expectedOperation,
            ProjectPath = project,
            WorkingDirectory = workingDirectory,
            Configuration = configuration,
            TimeoutSeconds = timeoutSeconds,
            Process = process,
            ProcessId = process.Id,
            ProcessStartUtc = processStartUtc,
            StartedUtc = startedUtc
        };

        process.OutputDataReceived += (_, e) => { if (e.Data is not null) AppendOutput(entry, entry.StdOut, e.Data, false); };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) AppendOutput(entry, entry.StdErr, e.Data, true); };

        if (!Jobs.TryAdd(jobId, entry))
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new InvalidOperationException("Dotnet job ID already exists in this Agent runtime.");
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        _ = MonitorJobAsync(entry);

        Store.Consume(planId);
        Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, jobId, processId = process.Id, timeoutSeconds, inputFingerprint = inputFingerprint.Sha256, buildFingerprint = buildFingerprint?.Sha256 }, "started");
        return new DotnetJobStartResult(plan.PlanId, jobId, expectedOperation, project, configuration, process.Id, processStartUtc, timeoutSeconds, "running", startedUtc);
    }

    private static FingerprintSnapshot ComputeInputFingerprint(string target)
    {
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var projects = CollectProjectGraph(target, files);
        AddAncestorInputs(Path.GetDirectoryName(target)!, files);
        AddFixedNuGetConfiguration(files);
        foreach (var project in projects)
        {
            AddAncestorInputs(Path.GetDirectoryName(project)!, files);
            var lockFile = Path.Combine(Path.GetDirectoryName(project)!, "packages.lock.json");
            if (File.Exists(lockFile)) files.Add(Path.GetFullPath(lockFile));
        }
        return FingerprintFiles(files);
    }

    private static FingerprintSnapshot ComputeBuildFingerprint(string target, string configuration)
    {
        var inputFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var projects = CollectProjectGraph(target, inputFiles);
        if (projects.Count == 0)
            throw new InvalidOperationException("No project files were resolved for the test target.");

        var buildFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var project in projects)
        {
            var root = Path.Combine(Path.GetDirectoryName(project)!, "bin", configuration);
            if (!Directory.Exists(root))
                throw new DirectoryNotFoundException($"Built output directory does not exist: {root}. Build the target before preparing dotnet_test_plan.");
            foreach (var file in EnumerateTreeFilesNoReparse(root)) buildFiles.Add(file);
        }
        if (buildFiles.Count == 0)
            throw new InvalidOperationException("No built test artifacts were found. Build the target before preparing dotnet_test_plan.");
        return FingerprintFiles(buildFiles);
    }

    private static HashSet<string> CollectProjectGraph(string target, HashSet<string> inputFiles)
    {
        var projects = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        inputFiles.Add(target);
        var extension = Path.GetExtension(target);
        if (string.Equals(extension, ".csproj", StringComparison.OrdinalIgnoreCase) || string.Equals(extension, ".fsproj", StringComparison.OrdinalIgnoreCase) || string.Equals(extension, ".vbproj", StringComparison.OrdinalIgnoreCase))
        {
            AddProjectRecursive(target, projects, inputFiles);
            return projects;
        }

        IEnumerable<string> referenced = string.Equals(extension, ".slnx", StringComparison.OrdinalIgnoreCase)
            ? ReadSlnxProjects(target)
            : ReadSlnProjects(target);
        foreach (var project in referenced) AddProjectRecursive(project, projects, inputFiles);
        return projects;
    }

    private static void AddProjectRecursive(string projectPath, HashSet<string> projects, HashSet<string> inputFiles)
    {
        var project = ValidateGraphProject(projectPath);
        if (!projects.Add(project)) return;
        inputFiles.Add(project);

        var document = LoadXml(project);
        var projectDirectory = Path.GetDirectoryName(project)!;
        foreach (var reference in document.Descendants().Where(x => string.Equals(x.Name.LocalName, "ProjectReference", StringComparison.OrdinalIgnoreCase)))
        {
            var include = reference.Attributes().FirstOrDefault(x => string.Equals(x.Name.LocalName, "Include", StringComparison.OrdinalIgnoreCase))?.Value;
            if (string.IsNullOrWhiteSpace(include)) continue;
            if (include.Contains("$(", StringComparison.Ordinal) || include.IndexOfAny(['*', '?']) >= 0)
                throw new InvalidOperationException($"Dynamic ProjectReference cannot be sealed by typed dotnet plans: {include}");
            var referenced = Path.GetFullPath(Path.Combine(projectDirectory, include));
            AddProjectRecursive(referenced, projects, inputFiles);
        }

        foreach (var import in document.Descendants().Where(x => string.Equals(x.Name.LocalName, "Import", StringComparison.OrdinalIgnoreCase)))
        {
            var value = import.Attributes().FirstOrDefault(x => string.Equals(x.Name.LocalName, "Project", StringComparison.OrdinalIgnoreCase))?.Value;
            if (string.IsNullOrWhiteSpace(value) || value.Contains("$(", StringComparison.Ordinal) || value.IndexOfAny(['*', '?']) >= 0) continue;
            var imported = Path.GetFullPath(Path.Combine(projectDirectory, value));
            if (File.Exists(imported) && IsUnderDevRoot(imported)) inputFiles.Add(ValidateInputFile(imported));
        }
    }

    private static IEnumerable<string> ReadSlnProjects(string solutionPath)
    {
        var directory = Path.GetDirectoryName(solutionPath)!;
        var text = File.ReadAllText(solutionPath, Encoding.UTF8);
        foreach (Match match in SlnProjectPattern.Matches(text))
        {
            var value = match.Groups["path"].Value.Replace('/', Path.DirectorySeparatorChar);
            yield return Path.GetFullPath(Path.Combine(directory, value));
        }
    }

    private static IEnumerable<string> ReadSlnxProjects(string solutionPath)
    {
        var directory = Path.GetDirectoryName(solutionPath)!;
        var document = LoadXml(solutionPath);
        foreach (var attribute in document.Descendants().Attributes())
        {
            var value = attribute.Value;
            var extension = Path.GetExtension(value);
            if (!string.Equals(extension, ".csproj", StringComparison.OrdinalIgnoreCase) && !string.Equals(extension, ".fsproj", StringComparison.OrdinalIgnoreCase) && !string.Equals(extension, ".vbproj", StringComparison.OrdinalIgnoreCase))
                continue;
            yield return Path.GetFullPath(Path.Combine(directory, value.Replace('/', Path.DirectorySeparatorChar)));
        }
    }

    private static XDocument LoadXml(string path)
    {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var reader = XmlReader.Create(stream, settings);
        return XDocument.Load(reader, LoadOptions.None);
    }

    private static void AddAncestorInputs(string startDirectory, HashSet<string> files)
    {
        var root = Path.GetFullPath(DevRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var current = new DirectoryInfo(startDirectory);
        while (current is not null && (string.Equals(current.FullName, root, StringComparison.OrdinalIgnoreCase) || current.FullName.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)))
        {
            foreach (var file in current.EnumerateFiles())
                if (AncestorInputNames.Contains(file.Name)) files.Add(ValidateInputFile(file.FullName));
            if (string.Equals(current.FullName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), root, StringComparison.OrdinalIgnoreCase)) break;
            current = current.Parent;
        }
    }

    private static void AddFixedNuGetConfiguration(HashSet<string> files)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (!string.IsNullOrWhiteSpace(appData))
        {
            var userConfig = Path.Combine(appData, "NuGet", "NuGet.Config");
            if (File.Exists(userConfig) && (File.GetAttributes(userConfig) & FileAttributes.ReparsePoint) == 0) files.Add(Path.GetFullPath(userConfig));
        }

        var machineConfigRoot = @"C:\Program Files (x86)\NuGet\Config";
        if (Directory.Exists(machineConfigRoot) && (File.GetAttributes(machineConfigRoot) & FileAttributes.ReparsePoint) == 0)
        {
            foreach (var config in Directory.EnumerateFiles(machineConfigRoot, "*.config", SearchOption.TopDirectoryOnly))
                if ((File.GetAttributes(config) & FileAttributes.ReparsePoint) == 0) files.Add(Path.GetFullPath(config));
        }
    }

    private static IEnumerable<string> EnumerateTreeFilesNoReparse(string root)
    {
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var current = stack.Pop();
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException($"Reparse-point build directory is not allowed: {current}");
            foreach (var entry in Directory.EnumerateFileSystemEntries(current))
            {
                var attributes = File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new UnauthorizedAccessException($"Reparse-point build artifact is not allowed: {entry}");
                if ((attributes & FileAttributes.Directory) != 0) stack.Push(entry);
                else yield return Path.GetFullPath(entry);
            }
        }
    }

    private static FingerprintSnapshot FingerprintFiles(IEnumerable<string> paths)
    {
        var files = paths.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var file in files)
        {
            if (!File.Exists(file)) throw new FileNotFoundException("Sealed input file disappeared.", file);
            if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException($"Reparse-point input file is not allowed: {file}");
            var normalized = file.Replace('\\', '/').ToUpperInvariant();
            hash.AppendData(Encoding.UTF8.GetBytes(normalized));
            hash.AppendData(new byte[] { 0 });
            hash.AppendData(BitConverter.GetBytes(new FileInfo(file).Length));
            using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read);
            hash.AppendData(SHA256.HashData(stream));
        }
        return new FingerprintSnapshot(Convert.ToHexString(hash.GetHashAndReset()), files.Length);
    }

    private static string ValidateGraphProject(string projectPath)
    {
        var full = ValidateInputFile(projectPath);
        var extension = Path.GetExtension(full);
        if (!string.Equals(extension, ".csproj", StringComparison.OrdinalIgnoreCase) && !string.Equals(extension, ".fsproj", StringComparison.OrdinalIgnoreCase) && !string.Equals(extension, ".vbproj", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Solution project graph contains an unsupported project type.");
        return full;
    }

    private static string ValidateInputFile(string path)
    {
        var full = Path.GetFullPath(path);
        if (!IsUnderDevRoot(full)) throw new UnauthorizedAccessException("Project graph inputs must remain under the C:\\Dev development workspace root.");
        if (!File.Exists(full)) throw new FileNotFoundException("Project graph input does not exist.", full);
        RequireNoReparseTraversal(full);
        return full;
    }

    private static bool IsUnderDevRoot(string path)
    {
        var root = Path.GetFullPath(DevRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var full = Path.GetFullPath(path);
        return full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static void RequireNoReparseTraversal(string filePath)
    {
        if ((File.GetAttributes(filePath) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Reparse-point project or input files are not allowed.");
        var root = Path.GetFullPath(DevRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var current = new DirectoryInfo(Path.GetDirectoryName(filePath)!);
        while (current is not null)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException($"Project path may not traverse a reparse-point directory: {current.FullName}");
            if (string.Equals(current.FullName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), root, StringComparison.OrdinalIgnoreCase)) return;
            current = current.Parent;
        }
        throw new UnauthorizedAccessException("Project path root validation failed.");
    }

    private static async Task MonitorJobAsync(DotnetJobEntry entry)
    {
        try
        {
            var exitTask = entry.Process.WaitForExitAsync();
            var timeoutTask = Task.Delay(TimeSpan.FromSeconds(entry.TimeoutSeconds));
            var completed = await Task.WhenAny(exitTask, timeoutTask);
            if (completed == timeoutTask)
            {
                lock (entry.Gate) entry.TimedOut = true;
                try { if (!entry.Process.HasExited) entry.Process.Kill(entireProcessTree: true); } catch { }
            }

            await entry.Process.WaitForExitAsync();
            try { entry.Process.WaitForExit(); } catch { }
            lock (entry.Gate)
            {
                entry.ExitCode = entry.Process.ExitCode;
                entry.CompletedUtc = DateTimeOffset.UtcNow;
            }
            Audit.Append("build", entry.Operation, entry.ProjectPath, new { entry.JobId, entry.ProcessId, entry.ExitCode, entry.TimedOut, entry.Cancelled }, entry.ExitCode == 0 && !entry.TimedOut && !entry.Cancelled ? "completed" : "failed");
        }
        catch (Exception ex)
        {
            lock (entry.Gate)
            {
                entry.Failure = ex.Message;
                entry.CompletedUtc = DateTimeOffset.UtcNow;
                try { if (entry.Process.HasExited) entry.ExitCode = entry.Process.ExitCode; } catch { }
            }
            Audit.Append("build", entry.Operation, entry.ProjectPath, new { entry.JobId, entry.ProcessId, error = ex.Message }, "failed");
        }
        finally
        {
            entry.Completion.TrySetResult(true);
        }
    }

    private static void AppendOutput(DotnetJobEntry entry, StringBuilder target, string value, bool isError)
    {
        lock (entry.Gate)
        {
            var remaining = MaxOutputChars - target.Length;
            if (remaining <= 0)
            {
                if (isError) entry.StdErrTruncated = true; else entry.StdOutTruncated = true;
                return;
            }
            var text = value + Environment.NewLine;
            if (text.Length <= remaining) target.Append(text);
            else
            {
                target.Append(text.AsSpan(0, remaining));
                if (isError) entry.StdErrTruncated = true; else entry.StdOutTruncated = true;
            }
        }
    }

    private static DotnetJobEntry GetJob(string jobId)
    {
        if (string.IsNullOrWhiteSpace(jobId)) throw new ArgumentException("Job ID is required.", nameof(jobId));
        if (!Jobs.TryGetValue(jobId.Trim(), out var entry)) throw new KeyNotFoundException("Dotnet job ID is not retained in this Agent runtime.");
        return entry;
    }

    private static DotnetJobSummary ToSummary(DotnetJobEntry entry)
    {
        lock (entry.Gate)
            return new DotnetJobSummary(entry.JobId, entry.Operation, entry.ProjectPath, entry.Configuration, entry.ProcessId, GetState(entry), entry.ExitCode, entry.TimeoutSeconds, entry.TimedOut, entry.Cancelled, entry.StartedUtc, entry.CompletedUtc);
    }

    private static string GetState(DotnetJobEntry entry)
    {
        if (entry.CompletedUtc is null) return "Running";
        if (entry.TimedOut) return "TimedOut";
        if (entry.Cancelled) return "Cancelled";
        if (!string.IsNullOrWhiteSpace(entry.Failure)) return "Failed";
        return entry.ExitCode == 0 ? "Succeeded" : "Failed";
    }

    private static void CleanupCompletedJobs()
    {
        if (Jobs.Count <= MaxRetainedJobs) return;
        var removable = Jobs.Values.Where(x => x.CompletedUtc is not null).OrderBy(x => x.CompletedUtc).Take(Math.Max(0, Jobs.Count - MaxRetainedJobs)).Select(x => x.JobId).ToArray();
        foreach (var jobId in removable) Jobs.TryRemove(jobId, out _);
    }

    private static string ValidateProject(string projectPath)
    {
        if (!File.Exists(DotnetExe)) throw new FileNotFoundException("dotnet.exe not found.", DotnetExe);
        if (string.IsNullOrWhiteSpace(projectPath) || !Path.IsPathFullyQualified(projectPath))
            throw new ArgumentException("Project or solution path must be absolute.", nameof(projectPath));
        var project = Path.GetFullPath(projectPath);
        if (!File.Exists(project)) throw new FileNotFoundException("Project or solution not found.", project);
        if (!IsUnderDevRoot(project)) throw new UnauthorizedAccessException("Project must be under the C:\\Dev development workspace root.");
        if (project.StartsWith(@"C:\yowthi-erp\", StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException("Production ERP paths are blocked.");
        var extension = Path.GetExtension(project);
        if (!string.Equals(extension, ".csproj", StringComparison.OrdinalIgnoreCase) && !string.Equals(extension, ".sln", StringComparison.OrdinalIgnoreCase) && !string.Equals(extension, ".slnx", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Target must be a .csproj, .sln, or .slnx file.");
        RequireNoReparseTraversal(project);
        return project;
    }

    private static string Sha256File(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string RequireParameter(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : throw new InvalidDataException($"{key} parameter is required.");

    private static void RequireIntentMatch(SignedPlan plan, string operation, string target, string summary, string riskClass, string expectedOperation)
    {
        if (!string.Equals(plan.Tool, "build", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.Ordinal) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }
}

public sealed record DotnetJobStartResult(string PlanId, string JobId, string Operation, string ProjectPath, string? Configuration, int ProcessId, DateTimeOffset ProcessStartUtc, int TimeoutSeconds, string State, DateTimeOffset StartedUtc);
public sealed record DotnetJobSummary(string JobId, string Operation, string ProjectPath, string? Configuration, int ProcessId, string State, int? ExitCode, int TimeoutSeconds, bool TimedOut, bool Cancelled, DateTimeOffset StartedUtc, DateTimeOffset? CompletedUtc);
public sealed record DotnetJobStatus(string JobId, string Operation, string ProjectPath, string? Configuration, int ProcessId, DateTimeOffset ProcessStartUtc, string State, int? ExitCode, int TimeoutSeconds, bool TimedOut, bool Cancelled, string StdOut, string StdErr, bool StdOutTruncated, bool StdErrTruncated, DateTimeOffset StartedUtc, DateTimeOffset? CompletedUtc, string? Failure);