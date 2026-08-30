using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Processes;

[McpServerToolType]
public static class ProcessTools
{
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name="process_stop_plan", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Prepare a one-time signed plan to stop one local process by numeric PID using the native .NET Process API. No PowerShell, cmd, or generic command executor is used.")]
    public static SignedPlan ProcessStopPlan(int processId, bool force = false)
    {
        if (processId <= 0) throw new ArgumentOutOfRangeException(nameof(processId));
        var process = Process.GetProcessById(processId);
        var processName = process.ProcessName;
        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var parameters = new Dictionary<string,string>(StringComparer.Ordinal)
        {
            ["processId"] = processId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["force"] = force ? "true" : "false",
            ["processName"] = processName
        };
        var unsigned = new SignedPlan(1, planId, approvalCode, "process", "process-stop", processId.ToString(System.Globalization.CultureInfo.InvariantCulture), parameters, RiskClass.Medium, $"Stop process PID {processId} ({processName}), force={force}", now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    [McpServerTool(Name="process_stop_execute", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Execute one previously prepared process/process-stop plan using the native .NET Process API. The caller must repeat the signed operation, target, summary, and risk class so execution intent is explicit. No PowerShell, cmd, or generic command executor is used.")]
    public static async Task<ExecutionResult> ProcessStopExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, operation, target, summary, riskClass);
        if (!plan.Parameters.TryGetValue("processId", out var processIdText) || !int.TryParse(processIdText, out var processId))
            throw new InvalidDataException("processId parameter is required.");
        var force = plan.Parameters.TryGetValue("force", out var forceText) && string.Equals(forceText, "true", StringComparison.OrdinalIgnoreCase);

        var process = Process.GetProcessById(processId);
        try
        {
            if (!force)
            {
                try { process.CloseMainWindow(); } catch { }
                var exited = await Task.Run(() => process.WaitForExit(3000));
                if (!exited)
                    throw new InvalidOperationException("Process did not exit gracefully within 3 seconds. Create a force=true plan if forced termination is intended.");
            }
            else
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }

            Store.Consume(planId);
            var outcome = $"stopped:{processId};force={force}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome }, "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    private static void RequireIntentMatch(SignedPlan plan, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "process", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, "process-stop", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.Ordinal) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }
}
