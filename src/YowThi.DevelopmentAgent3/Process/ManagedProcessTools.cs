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
    private sealed record ManagedProcessEntry(string JobId, int ProcessId, string ProcessName, Process Process, DateTimeOffset StartedUtc);

    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly ConcurrentDictionary<string, ManagedProcessEntry> Managed = new(StringComparer.Ordinal);

    [McpServerTool(Name="managed_process_start_plan", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Prepare a one-time signed plan to start one Agent-owned local process using the native .NET Process API. The process receives an Agent job ID and can later be cancelled only through that job ID. No PowerShell, cmd, or generic command executor is used.")]
    public static SignedPlan ManagedProcessStartPlan(string executable, string arguments = "", string? workingDirectory = null)
    {
        if (string.IsNullOrWhiteSpace(executable)) throw new ArgumentException("Executable is required.", nameof(executable));
        if (!Path.IsPathFullyQualified(executable)) throw new ArgumentException("Executable path must be absolute.", nameof(executable));
        var executableFull = Path.GetFullPath(executable);
        if (!File.Exists(executableFull)) throw new FileNotFoundException("Executable does not exist.", executableFull);

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
    [Description("Execute one previously prepared managed-process start plan using the native .NET Process API and register the started process under its signed Agent job ID. The caller must repeat the signed operation, target, summary, and risk class. No PowerShell, cmd, or generic command executor is used.")]
    public static ExecutionResult ManagedProcessStartExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "managed-process-start", operation, target, summary, riskClass);

        var jobId = RequireParameter(plan, "jobId");
        var executable = RequireParameter(plan, "executable");
        var arguments = RequireParameter(plan, "arguments");
        var workingDirectory = RequireParameter(plan, "workingDirectory");

        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            Arguments = arguments,
            WorkingDirectory = workingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Process start returned null.");
        var entry = new ManagedProcessEntry(jobId, process.Id, process.ProcessName, process, DateTimeOffset.UtcNow);
        if (!Managed.TryAdd(jobId, entry))
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new InvalidOperationException("Managed job ID already exists.");
        }

        Store.Consume(planId);
        var outcome = $"started-job:{jobId};pid={process.Id};name={process.ProcessName}";
        Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, jobId, processId = process.Id, outcome }, "executed");
        return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
    }

    [McpServerTool(Name="managed_process_cancel_plan", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Prepare a one-time signed plan to cancel one process previously started and still tracked by this Agent, identified only by Agent job ID. Arbitrary PIDs are not accepted. No PowerShell, cmd, or generic command executor is used.")]
    public static SignedPlan ManagedProcessCancelPlan(string jobId)
    {
        if (string.IsNullOrWhiteSpace(jobId)) throw new ArgumentException("Job ID is required.", nameof(jobId));
        if (!Managed.TryGetValue(jobId, out var entry)) throw new KeyNotFoundException("Managed job ID is not active in this Agent instance.");
        if (entry.Process.HasExited)
        {
            Managed.TryRemove(jobId, out _);
            throw new InvalidOperationException("Managed process has already exited.");
        }

        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var parameters = new Dictionary<string,string>(StringComparer.Ordinal)
        {
            ["jobId"] = jobId,
            ["processId"] = entry.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["processName"] = entry.ProcessName
        };
        var unsigned = new SignedPlan(1, planId, approvalCode, "managed-process", "managed-process-cancel", jobId, parameters, RiskClass.Medium, $"Cancel Agent-owned managed job {jobId} ({entry.ProcessName}, PID {entry.ProcessId})", now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, jobId, entry.ProcessId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    [McpServerTool(Name="managed_process_cancel_execute", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Execute one previously prepared managed-process cancel plan. Only the Agent-owned process currently registered under the signed job ID can be cancelled; arbitrary PID termination is not supported. The caller must repeat the signed operation, target, summary, and risk class. No PowerShell, cmd, or generic command executor is used.")]
    public static async Task<ExecutionResult> ManagedProcessCancelExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "managed-process-cancel", operation, target, summary, riskClass);

        var jobId = RequireParameter(plan, "jobId");
        var expectedProcessIdText = RequireParameter(plan, "processId");
        var expectedProcessName = RequireParameter(plan, "processName");
        if (!int.TryParse(expectedProcessIdText, out var expectedProcessId)) throw new InvalidDataException("Signed processId is invalid.");
        if (!Managed.TryGetValue(jobId, out var entry)) throw new KeyNotFoundException("Managed job ID is not active in this Agent instance.");
        if (entry.ProcessId != expectedProcessId || !string.Equals(entry.ProcessName, expectedProcessName, StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Managed process identity no longer matches the signed plan.");

        try
        {
            if (!entry.Process.HasExited)
            {
                entry.Process.Kill(entireProcessTree: true);
                await entry.Process.WaitForExitAsync();
            }
            Managed.TryRemove(jobId, out _);
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
