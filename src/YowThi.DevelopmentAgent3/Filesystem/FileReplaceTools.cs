using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;
using YowThi.DevelopmentAgent3.Security;

namespace YowThi.DevelopmentAgent3.Filesystem;

[McpServerToolType]
public static class FileReplaceTools
{
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly LifecyclePathPolicy Paths = new();
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name="file_replace_plan", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Prepare a one-time signed plan to safely replace one existing file using native .NET filesystem APIs. The plan records the original SHA-256, writes replacement content to a temporary file, and preserves a backup. Frozen paths are blocked. No shell command is generated or stored.")]
    public static SignedPlan FileReplacePlan(string path, string content)
    {
        var target = Paths.RequireMutable(path);
        if (!File.Exists(target)) throw new FileNotFoundException("Target file does not exist.", target);

        var originalSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(target)));
        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var parameters = new Dictionary<string,string>(StringComparer.Ordinal)
        {
            ["contentBase64"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(content)),
            ["originalSha256"] = originalSha256
        };
        var unsigned = new SignedPlan(1, planId, approvalCode, "filesystem", "file-replace", target, parameters, RiskClass.Medium, $"Safely replace file {target} with backup", now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary, originalSha256 }, "prepared");
        return signed;
    }

    [McpServerTool(Name="file_replace_execute", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Execute one previously prepared filesystem/file-replace plan using native .NET filesystem APIs. The caller must repeat the signed operation, target, summary, and risk class. The original SHA-256 is rechecked, replacement content is written to a same-directory temporary file, and the previous file is preserved as a backup. No PowerShell, cmd, or generic command executor is used.")]
    public static async Task<ExecutionResult> FileReplaceExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, operation, target, summary, riskClass);
        var mutableTarget = Paths.RequireMutable(plan.Target);
        if (!File.Exists(mutableTarget)) throw new FileNotFoundException("Target file does not exist.", mutableTarget);
        if (!plan.Parameters.TryGetValue("contentBase64", out var contentBase64)) throw new InvalidDataException("contentBase64 parameter is required.");
        if (!plan.Parameters.TryGetValue("originalSha256", out var expectedOriginalSha256)) throw new InvalidDataException("originalSha256 parameter is required.");

        var actualOriginalSha256 = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(mutableTarget)));
        if (!string.Equals(actualOriginalSha256, expectedOriginalSha256, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Target changed after plan creation; replacement aborted.");

        var directory = Path.GetDirectoryName(mutableTarget) ?? throw new InvalidDataException("Target has no parent directory.");
        var temp = Path.Combine(directory, $".{Path.GetFileName(mutableTarget)}.yowthi-{plan.PlanId}.tmp");
        var backup = Path.Combine(directory, $".{Path.GetFileName(mutableTarget)}.yowthi-{plan.PlanId}.bak");
        var content = Convert.FromBase64String(contentBase64);

        try
        {
            await File.WriteAllBytesAsync(temp, content);
            File.Replace(temp, mutableTarget, backup, ignoreMetadataErrors: true);
            Store.Consume(planId);
            var outcome = $"replaced:{content.Length};backup:{backup}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome, backup }, "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, mutableTarget, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            if (File.Exists(temp)) File.Delete(temp);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    private static void RequireIntentMatch(SignedPlan plan, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "filesystem", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, "file-replace", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }
}
