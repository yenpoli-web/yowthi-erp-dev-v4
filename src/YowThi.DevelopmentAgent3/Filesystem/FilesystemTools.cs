using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;
using YowThi.DevelopmentAgent3.Scratch;
using YowThi.DevelopmentAgent3.Security;

namespace YowThi.DevelopmentAgent3.Filesystem;

[McpServerToolType]
public static class FilesystemTools
{
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly ProtectedPathPolicy Paths = new();
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly FileCreateExecutor FileCreate = new(Paths);
    private static readonly FileDeleteExecutor FileDelete = new(Paths);

    [McpServerTool(Name="file_read", ReadOnly=true, Destructive=false, OpenWorld=false)]
    [Description("Read one UTF-8 text file using the native .NET filesystem API. No shell command is generated or executed.")]
    public static async Task<string> FileRead(string path)
    {
        var target = Paths.Normalize(path);
        if (!File.Exists(target)) throw new FileNotFoundException("Target file does not exist.", target);
        return await File.ReadAllTextAsync(target, Encoding.UTF8);
    }

    [McpServerTool(Name="file_create_plan", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Prepare a one-time signed plan to create one file using the native .NET filesystem API. Generic creation of .ps1 helpers or Agent .yowthi-* scratch/backup artifacts inside the protected V4 Git worktree is rejected; use the repo-external Agent scratch capability for temporary helpers. No shell command is generated or stored.")]
    public static SignedPlan FileCreatePlan(string path, string content)
    {
        var policyTarget = AgentScratchStore.RequireGenericFileCreationAllowed(path);
        var target = Paths.RequireMutable(policyTarget);
        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var parameters = new Dictionary<string,string>(StringComparer.Ordinal)
        {
            ["contentBase64"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(content))
        };
        var unsigned = new SignedPlan(1, planId, approvalCode, "filesystem", "file-create", target, parameters, RiskClass.Medium, $"Create file {target}", now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    [McpServerTool(Name="file_create_execute", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Execute one previously prepared filesystem/file-create plan using the native .NET filesystem API. V4 worktree scratch-script and .yowthi-* artifact restrictions are revalidated immediately before write. The caller must repeat the signed operation, target, summary, and risk class. No PowerShell, cmd, or generic command executor is used.")]
    public static async Task<ExecutionResult> FileCreateExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "file-create", operation, target, summary, riskClass);
        try
        {
            var result = await FileCreate.ExecuteAsync(plan);
            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, result.Outcome }, "executed");
            return result;
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name="file_delete_plan", ReadOnly=false, Destructive=true, OpenWorld=false)]
    [Description("Prepare a one-time signed plan to delete one file using the native .NET filesystem API. Protected production paths remain blocked. No shell command is generated or stored.")]
    public static SignedPlan FileDeletePlan(string path)
    {
        var target = Paths.RequireMutable(path);
        if (!File.Exists(target)) throw new FileNotFoundException("Target file does not exist.", target);
        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var unsigned = new SignedPlan(1, planId, approvalCode, "filesystem", "file-delete", target, new Dictionary<string,string>(StringComparer.Ordinal), RiskClass.Medium, $"Delete file {target}", now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    [McpServerTool(Name="file_delete_execute", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Execute one previously prepared filesystem/file-delete plan using the native .NET filesystem API. The caller must repeat the signed operation, target, summary, and risk class so execution intent is explicit. No PowerShell, cmd, or generic command executor is used.")]
    public static async Task<ExecutionResult> FileDeleteExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "file-delete", operation, target, summary, riskClass);
        try
        {
            var result = await FileDelete.ExecuteAsync(plan);
            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, result.Outcome }, "executed");
            return result;
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    private static void RequireIntentMatch(SignedPlan plan, string expectedOperation, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "filesystem", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, operation, target, summary, riskClass }, "intent-mismatch");
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
        }
    }
}
