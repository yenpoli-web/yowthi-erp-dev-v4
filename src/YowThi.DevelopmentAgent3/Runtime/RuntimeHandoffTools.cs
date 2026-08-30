using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Runtime;

[McpServerToolType]
public static class RuntimeHandoffTools
{
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly string QueueRoot = @"C:\Dev\YowThi-ERP-Dev-v4\.agent3-handoff\pending";

    [McpServerTool(Name="runtime_handoff_plan", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Prepare a one-time signed runtime handoff staging plan. It records the next runtime DLL, loopback listen URL, and health URL. It does not start, stop, restart, or terminate any process.")]
    public static SignedPlan RuntimeHandoffPlan(string runtimeDll, string listenUrl, string healthUrl)
    {
        if (string.IsNullOrWhiteSpace(runtimeDll) || !Path.IsPathFullyQualified(runtimeDll))
            throw new ArgumentException("runtimeDll must be an absolute path.", nameof(runtimeDll));
        var runtimeFull = Path.GetFullPath(runtimeDll);
        if (!File.Exists(runtimeFull)) throw new FileNotFoundException("Runtime DLL does not exist.", runtimeFull);
        ValidateLoopbackHttpUrl(listenUrl, nameof(listenUrl));
        ValidateLoopbackHttpUrl(healthUrl, nameof(healthUrl));

        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var parameters = new Dictionary<string,string>(StringComparer.Ordinal)
        {
            ["runtimeDll"] = runtimeFull,
            ["listenUrl"] = listenUrl,
            ["healthUrl"] = healthUrl,
            ["runtimeSha256"] = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(runtimeFull)))
        };
        var unsigned = new SignedPlan(1, planId, approvalCode, "runtime-handoff", "handoff-stage", runtimeFull, parameters, RiskClass.Medium,
            $"Stage runtime handoff manifest for {runtimeFull} at {listenUrl}", now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    [McpServerTool(Name="runtime_handoff_stage_execute", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Stage one previously prepared runtime handoff manifest into the Agent-owned handoff queue. This operation only writes a manifest file; it does not start, stop, restart, or terminate any process.")]
    public static ExecutionResult RuntimeHandoffStageExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, operation, target, summary, riskClass);
        var runtimeDll = RequireParameter(plan, "runtimeDll");
        var listenUrl = RequireParameter(plan, "listenUrl");
        var healthUrl = RequireParameter(plan, "healthUrl");
        var expectedHash = RequireParameter(plan, "runtimeSha256");
        if (!File.Exists(runtimeDll)) throw new FileNotFoundException("Runtime DLL no longer exists.", runtimeDll);
        var actualHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(runtimeDll)));
        if (!string.Equals(expectedHash, actualHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Runtime DLL SHA-256 changed after plan creation.");

        Directory.CreateDirectory(QueueRoot);
        var manifestPath = Path.Combine(QueueRoot, plan.PlanId + ".json");
        var manifest = new
        {
            schemaVersion = 1,
            planId = plan.PlanId,
            runtimeDll,
            runtimeSha256 = actualHash,
            listenUrl,
            healthUrl,
            stagedUtc = DateTimeOffset.UtcNow
        };
        var json = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(manifestPath, json, new UTF8Encoding(false));
        Store.Consume(planId);
        var outcome = $"manifest-staged:{manifestPath}";
        Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, manifestPath, outcome }, "executed");
        return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
    }

    private static void ValidateLoopbackHttpUrl(string value, string name)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) || !uri.IsLoopback)
            throw new ArgumentException($"{name} must be an absolute loopback HTTP(S) URL.", name);
    }

    private static string RequireParameter(SignedPlan plan, string name)
    {
        if (!plan.Parameters.TryGetValue(name, out var value)) throw new InvalidDataException($"{name} parameter is required.");
        return value;
    }

    private static void RequireIntentMatch(SignedPlan plan, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "runtime-handoff", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, "handoff-stage", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.Ordinal) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }
}
