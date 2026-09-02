using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Processes;

[McpServerToolType]
public static class ManagedProcessTools
{
    private sealed class ManagedProcessEntry
    {
        public required string JobId { get; init; }
        public required string Executable { get; init; }
        public required string Arguments { get; init; }
        public required string WorkingDirectory { get; init; }
        public required int ProcessId { get; init; }
        public required string ProcessName { get; init; }
        public required Process Process { get; init; }
        public required DateTimeOffset ProcessStartUtc { get; init; }
        public required DateTimeOffset StartedUtc { get; init; }
        public object Gate { get; } = new();
        public StringBuilder StdOut { get; } = new();
        public StringBuilder StdErr { get; } = new();
        public TaskCompletionSource<bool> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool StdOutTruncated { get; set; }
        public bool StdErrTruncated { get; set; }
        public bool Cancelled { get; set; }
        public int? ExitCode { get; set; }
        public DateTimeOffset? CompletedUtc { get; set; }
        public string? Failure { get; set; }
    }

    private const int MaxOutputChars = 1_000_000;
    private const int MaxRetainedJobs = 128;

    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly ConcurrentDictionary<string, ManagedProcessEntry> Managed = new(StringComparer.Ordinal);

    private static readonly HashSet<string> BlockedExecutableNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "git.exe", "gh.exe", "git-bash.exe", "git-cmd.exe",
        "git-credential-manager.exe", "git-credential-manager-core.exe",
        "cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "sh.exe", "wsl.exe"
    };

    private static readonly string[] BlockedIdentitySeedPaths =
    [
        @"C:\Program Files\Git\cmd\git.exe",
        @"C:\Program Files\Git\bin\git.exe",
        @"C:\Program Files\Git\git-bash.exe",
        @"C:\Program Files\Git\git-cmd.exe",
        @"C:\Program Files\GitHub CLI\gh.exe",
        @"C:\Windows\System32\cmd.exe",
        @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        @"C:\Program Files\PowerShell\7\pwsh.exe",
        @"C:\Windows\System32\wsl.exe"
    ];

    private static readonly Lazy<HashSet<string>> BlockedExecutableSha256 =
        new(BuildBlockedExecutableSha256, System.Threading.LazyThreadSafetyMode.ExecutionAndPublication);

    [McpServerTool(Name="managed_process_start_plan", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Prepare a one-time signed plan to start one Agent-owned local process using the native .NET Process API. The executable SHA-256 is sealed and revalidated at execution. Direct Git/GitHub CLI, Git credential-helper, and shell-host execution is rejected; use typed Git/GitHub or dedicated script tools instead. The process receives an Agent job ID and can later be inspected through managed_process_status or cancelled through that job ID.")]
    public static SignedPlan ManagedProcessStartPlan(string executable, string arguments = "", string? workingDirectory = null)
    {
        if (string.IsNullOrWhiteSpace(executable)) throw new ArgumentException("Executable is required.", nameof(executable));
        if (!Path.IsPathFullyQualified(executable)) throw new ArgumentException("Executable path must be absolute.", nameof(executable));
        var executableFull = Path.GetFullPath(executable);
        if (!File.Exists(executableFull)) throw new FileNotFoundException("Executable does not exist.", executableFull);
        if ((File.GetAttributes(executableFull) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Executable may not be a reparse point.");
        var executableSha256 = RequireAllowedExecutable(executableFull);

        string workingDirectoryFull;
        if (string.IsNullOrWhiteSpace(workingDirectory))
        {
            workingDirectoryFull = Path.GetDirectoryName(executableFull) ?? throw new InvalidOperationException("Executable directory could not be resolved.");
        }
        else
        {
            if (!Path.IsPathFullyQualified(workingDirectory)) throw new ArgumentException("Working directory must be absolute.", nameof(workingDirectory));
            workingDirectoryFull = Path.GetFullPath(workingDirectory);
            if (!Directory.Exists(workingDirectoryFull)) throw new DirectoryNotFoundException(workingDirectoryFull);
        }

        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var jobId = Guid.NewGuid().ToString("N");
        var parameters = new Dictionary<string,string>(StringComparer.Ordinal)
        {
            ["jobId"] = jobId,
            ["executable"] = executableFull,
            ["executableSha256"] = executableSha256,
            ["arguments"] = arguments ?? string.Empty,
            ["workingDirectory"] = workingDirectoryFull
        };
        var unsigned = new SignedPlan(1, planId, approvalCode, "managed-process", "managed-process-start", executableFull, parameters, RiskClass.Medium, $"Start Agent-owned managed process {Path.GetFileName(executableFull)} as job {jobId}", now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, jobId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    [McpServerTool(Name="managed_process_start_execute", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Execute one previously prepared managed-process start plan using the native .NET Process API, revalidate the sealed executable SHA-256 and direct-executable policy, capture bounded UTF-8 stdout/stderr, and register the process under its signed Agent job ID. Direct Git/GitHub CLI, Git credential-helper, and shell-host execution is rejected. The caller must repeat the signed operation, target, summary, and risk class. Use managed_process_status for completion state, exit code, stdout, stderr, and timestamps.")]
    public static ExecutionResult ManagedProcessStartExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "managed-process-start", operation, target, summary, riskClass);

        var jobId = RequireParameter(plan, "jobId");
        var executable = RequireParameter(plan, "executable");
        var expectedExecutableSha256 = RequireParameter(plan, "executableSha256");
        var arguments = RequireParameter(plan, "arguments");
        var workingDirectory = RequireParameter(plan, "workingDirectory");

        if (!File.Exists(executable)) throw new FileNotFoundException("Executable no longer exists.", executable);
        if ((File.GetAttributes(executable) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Executable may not be a reparse point.");
        var actualExecutableSha256 = RequireAllowedExecutable(executable);
        if (!string.Equals(actualExecutableSha256, expectedExecutableSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Executable changed after plan creation.");
        if (!Directory.Exists(workingDirectory)) throw new DirectoryNotFoundException(workingDirectory);
        CleanupCompletedJobs();
        if (Managed.ContainsKey(jobId)) throw new InvalidOperationException("Managed job ID already exists.");

        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            Arguments = arguments,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        var process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
        if (!process.Start()) throw new InvalidOperationException("Process start returned false.");

        var startedUtc = DateTimeOffset.UtcNow;
        var processStartUtc = new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero);
        var entry = new ManagedProcessEntry
        {
            JobId = jobId,
            Executable = executable,
            Arguments = arguments,
            WorkingDirectory = workingDirectory,
            ProcessId = process.Id,
            ProcessName = process.ProcessName,
            Process = process,
            ProcessStartUtc = processStartUtc,
            StartedUtc = startedUtc
        };

        process.OutputDataReceived += (_, e) => { if (e.Data is not null) AppendOutput(entry, entry.StdOut, e.Data, false); };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) AppendOutput(entry, entry.StdErr, e.Data, true); };

        if (!Managed.TryAdd(jobId, entry))
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            process.Dispose();
            throw new InvalidOperationException("Managed job ID already exists.");
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        _ = MonitorProcessAsync(entry);

        Store.Consume(planId);
        var outcome = $"started-job:{jobId};pid={process.Id};name={process.ProcessName}";
        Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, jobId, processId = process.Id, processStartUtc, outcome }, "executed");
        return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
    }

    [McpServerTool(Name="managed_process_status", ReadOnly=true, Destructive=false, OpenWorld=false)]
    [Description("Read one retained Agent-owned managed process job by job ID. The result includes running/completion state, process identity, exit code when available, bounded UTF-8 stdout/stderr, truncation flags, cancellation state, timestamps, and monitor failure if any. This is read-only and does not start, stop, or modify a process.")]
    public static ManagedProcessStatus ManagedProcessStatus(string jobId)
    {
        var entry = GetJob(jobId);
        lock (entry.Gate)
        {
            return new ManagedProcessStatus(
                entry.JobId,
                entry.ProcessId,
                entry.ProcessName,
                GetState(entry),
                entry.ExitCode,
                entry.Cancelled,
                entry.StdOut.ToString(),
                entry.StdErr.ToString(),
                entry.StdOutTruncated,
                entry.StdErrTruncated,
                entry.ProcessStartUtc,
                entry.StartedUtc,
                entry.CompletedUtc,
                entry.Failure);
        }
    }

    [McpServerTool(Name="managed_process_cancel_plan", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Prepare a one-time signed plan to cancel one active process previously started and still retained by this Agent, identified only by Agent job ID. Completed jobs remain available through managed_process_status and cannot be cancelled. Arbitrary PIDs are not accepted. No PowerShell, cmd, or generic command executor is used.")]
    public static SignedPlan ManagedProcessCancelPlan(string jobId)
    {
        var entry = GetJob(jobId);
        lock (entry.Gate)
        {
            if (entry.CompletedUtc is not null || entry.Process.HasExited)
                throw new InvalidOperationException("Managed process has already completed.");

            var now = DateTimeOffset.UtcNow;
            var planId = Guid.NewGuid().ToString("N");
            var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
            var parameters = new Dictionary<string,string>(StringComparer.Ordinal)
            {
                ["jobId"] = jobId,
                ["processId"] = entry.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture),
                ["processName"] = entry.ProcessName,
                ["processStartUtc"] = entry.ProcessStartUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture)
            };
            var unsigned = new SignedPlan(1, planId, approvalCode, "managed-process", "managed-process-cancel", jobId, parameters, RiskClass.Medium, $"Cancel Agent-owned managed job {jobId} ({entry.ProcessName}, PID {entry.ProcessId})", now, now.AddMinutes(10), string.Empty);
            var signed = unsigned with { Signature = Signer.Sign(unsigned) };
            Store.Add(signed);
            Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, jobId, entry.ProcessId, entry.ProcessStartUtc, signed.RiskClass, signed.Summary }, "prepared");
            return signed;
        }
    }

    [McpServerTool(Name="managed_process_cancel_execute", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Execute one previously prepared managed-process cancel plan. Only the exact active Agent-owned job still matching the sealed job ID, PID, process name, and process start time can be terminated. The completed cancelled job remains retained for managed_process_status read-back. Arbitrary PID termination is not supported. No PowerShell, cmd, or generic command executor is used.")]
    public static async Task<ExecutionResult> ManagedProcessCancelExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "managed-process-cancel", operation, target, summary, riskClass);

        var jobId = RequireParameter(plan, "jobId");
        var expectedProcessIdText = RequireParameter(plan, "processId");
        var expectedProcessName = RequireParameter(plan, "processName");
        var expectedProcessStartUtcText = RequireParameter(plan, "processStartUtc");
        if (!int.TryParse(expectedProcessIdText, out var expectedProcessId)) throw new InvalidDataException("Signed processId is invalid.");
        if (!DateTimeOffset.TryParse(expectedProcessStartUtcText, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out var expectedProcessStartUtc))
            throw new InvalidDataException("Signed processStartUtc is invalid.");

        var entry = GetJob(jobId);
        lock (entry.Gate)
        {
            if (entry.ProcessId != expectedProcessId ||
                !string.Equals(entry.ProcessName, expectedProcessName, StringComparison.Ordinal) ||
                entry.ProcessStartUtc != expectedProcessStartUtc)
                throw new UnauthorizedAccessException("Managed process identity no longer matches the signed plan.");
            if (entry.CompletedUtc is not null || entry.Process.HasExited)
                throw new InvalidOperationException("Managed process has already completed.");
            entry.Cancelled = true;
        }

        try
        {
            entry.Process.Kill(entireProcessTree: true);
            await entry.Process.WaitForExitAsync();
            await entry.Completion.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Store.Consume(planId);
            var outcome = $"cancelled-job:{jobId};pid={entry.ProcessId}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, jobId, entry.ProcessId, outcome }, "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, jobId, error = ex.Message }, "failed");
            throw;
        }
    }

    private static async Task MonitorProcessAsync(ManagedProcessEntry entry)
    {
        try
        {
            await entry.Process.WaitForExitAsync();
            try { entry.Process.WaitForExit(); } catch { }
            lock (entry.Gate)
            {
                entry.ExitCode = entry.Process.ExitCode;
                entry.CompletedUtc = DateTimeOffset.UtcNow;
            }
            Audit.Append("managed-process", "managed-process-complete", entry.JobId, new { entry.JobId, entry.ProcessId, entry.ExitCode, entry.Cancelled }, entry.Cancelled ? "cancelled" : entry.ExitCode == 0 ? "completed" : "failed");
        }
        catch (Exception ex)
        {
            lock (entry.Gate)
            {
                entry.Failure = ex.Message;
                entry.CompletedUtc = DateTimeOffset.UtcNow;
                try { if (entry.Process.HasExited) entry.ExitCode = entry.Process.ExitCode; } catch { }
            }
            Audit.Append("managed-process", "managed-process-complete", entry.JobId, new { entry.JobId, entry.ProcessId, error = ex.Message }, "failed");
        }
        finally
        {
            entry.Completion.TrySetResult(true);
        }
    }

    private static void AppendOutput(ManagedProcessEntry entry, StringBuilder target, string value, bool isError)
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
            if (text.Length <= remaining)
            {
                target.Append(text);
            }
            else
            {
                target.Append(text.AsSpan(0, remaining));
                if (isError) entry.StdErrTruncated = true; else entry.StdOutTruncated = true;
            }
        }
    }

    private static ManagedProcessEntry GetJob(string jobId)
    {
        if (string.IsNullOrWhiteSpace(jobId)) throw new ArgumentException("Job ID is required.", nameof(jobId));
        if (!Managed.TryGetValue(jobId.Trim(), out var entry)) throw new KeyNotFoundException("Managed job ID is not retained in this Agent instance.");
        return entry;
    }

    private static string GetState(ManagedProcessEntry entry)
    {
        if (entry.CompletedUtc is null) return "Running";
        if (entry.Cancelled) return "Cancelled";
        if (!string.IsNullOrWhiteSpace(entry.Failure)) return "Failed";
        return entry.ExitCode == 0 ? "Succeeded" : "Failed";
    }

    private static void CleanupCompletedJobs()
    {
        if (Managed.Count <= MaxRetainedJobs) return;
        var removable = Managed.Values
            .Where(x => x.CompletedUtc is not null)
            .OrderBy(x => x.CompletedUtc)
            .Take(Math.Max(0, Managed.Count - MaxRetainedJobs))
            .Select(x => x.JobId)
            .ToArray();
        foreach (var jobId in removable)
        {
            if (Managed.TryRemove(jobId, out var entry))
            {
                try { entry.Process.Dispose(); } catch { }
            }
        }
    }

    private static string RequireAllowedExecutable(string executable)
    {
        var full = Path.GetFullPath(executable);
        var fileName = Path.GetFileName(full);
        if (BlockedExecutableNames.Contains(fileName))
            throw new UnauthorizedAccessException("managed_process_start does not accept direct Git/GitHub CLI, Git credential-helper, or shell-host execution. Use typed Git/GitHub tools or dedicated script tools.");

        var sha256 = GetFileSha256(full);
        if (BlockedExecutableSha256.Value.Contains(sha256))
            throw new UnauthorizedAccessException("managed_process_start rejected an executable whose binary identity matches a blocked Git/GitHub CLI or shell host. Use typed Git/GitHub tools or dedicated script tools.");
        return sha256;
    }

    private static HashSet<string> BuildBlockedExecutableSha256()
    {
        var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in BlockedIdentitySeedPaths)
        {
            try
            {
                if (!File.Exists(path)) continue;
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) continue;
                hashes.Add(GetFileSha256(path));
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
        return hashes;
    }

    private static string GetFileSha256(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string RequireParameter(SignedPlan plan, string name)
    {
        if (!plan.Parameters.TryGetValue(name, out var value)) throw new InvalidDataException($"{name} parameter is required.");
        return value;
    }

    private static void RequireIntentMatch(SignedPlan plan, string expectedOperation, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "managed-process", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.Ordinal) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }
}

public sealed record ManagedProcessStatus(
    string JobId,
    int ProcessId,
    string ProcessName,
    string State,
    int? ExitCode,
    bool Cancelled,
    string StdOut,
    string StdErr,
    bool StdOutTruncated,
    bool StdErrTruncated,
    DateTimeOffset ProcessStartUtc,
    DateTimeOffset StartedUtc,
    DateTimeOffset? CompletedUtc,
    string? Failure);
