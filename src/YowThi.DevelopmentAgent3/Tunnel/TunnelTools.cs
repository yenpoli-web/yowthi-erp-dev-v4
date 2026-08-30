using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Tunnel;

[McpServerToolType]
public static class TunnelTools
{
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private const string RuntimeKeyPath = @"C:\Users\YowThi\AppData\Local\YowThi\TunnelClient\secrets\runtime.key";

    [McpServerTool(Name = "tunnel_start_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed plan to start one YowThi tunnel-client profile using the native .NET Process API. The runtime API key is never stored in the plan, audit record, or result. No PowerShell, cmd, or generic command executor is used.")]
    public static SignedPlan TunnelStartPlan(string executable, string profileName, string profileDirectory)
    {
        var exe = Path.GetFullPath(executable);
        var profileDir = Path.GetFullPath(profileDirectory);
        ValidateInputs(exe, profileName, profileDir);

        var profilePath = Path.Combine(profileDir, profileName + ".yaml");
        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["executable"] = exe,
            ["profileName"] = profileName,
            ["profileDirectory"] = profileDir,
            ["profilePath"] = profilePath
        };

        var summary = $"Start tunnel profile {profileName} from {profilePath}";
        var unsigned = new SignedPlan(1, planId, approvalCode, "tunnel", "tunnel-start", profilePath, parameters, RiskClass.Medium, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "tunnel_start_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared tunnel/tunnel-start plan using the native .NET Process API. The caller must repeat the signed operation, target, summary, and risk class. The runtime API key is read only at execution time and injected only into the child process environment. No PowerShell, cmd, or generic command executor is used.")]
    public static ExecutionResult TunnelStartExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, operation, target, summary, riskClass);

        var exe = RequireParameter(plan, "executable");
        var profileName = RequireParameter(plan, "profileName");
        var profileDir = RequireParameter(plan, "profileDirectory");
        var profilePath = RequireParameter(plan, "profilePath");
        ValidateInputs(exe, profileName, profileDir);

        var expectedProfilePath = Path.Combine(Path.GetFullPath(profileDir), profileName + ".yaml");
        if (!string.Equals(Path.GetFullPath(profilePath), expectedProfilePath, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Profile path no longer matches the signed profile inputs.");

        var runtimeKey = File.ReadAllText(RuntimeKeyPath, Encoding.UTF8).Trim();
        if (string.IsNullOrWhiteSpace(runtimeKey) || !runtimeKey.StartsWith("sk-", StringComparison.Ordinal))
            throw new InvalidDataException("Runtime key missing or invalid.");

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                WorkingDirectory = Path.GetDirectoryName(exe)!,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.ArgumentList.Add("run");
            psi.ArgumentList.Add("--profile");
            psi.ArgumentList.Add(profileName);
            psi.ArgumentList.Add("--profile-dir");
            psi.ArgumentList.Add(profileDir);
            psi.Environment["CONTROL_PLANE_API_KEY"] = runtimeKey;

            using var process = Process.Start(psi) ?? throw new InvalidOperationException("Tunnel process failed to start.");
            var pid = process.Id;
            Store.Consume(planId);
            var outcome = $"started:{pid};profile={profileName}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, pid, profileName }, "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
        finally
        {
            runtimeKey = string.Empty;
        }
    }

    private static void ValidateInputs(string executable, string profileName, string profileDirectory)
    {
        if (!Path.IsPathFullyQualified(executable) || !File.Exists(executable))
            throw new FileNotFoundException("Tunnel executable not found.", executable);
        if (!string.Equals(Path.GetFileName(executable), "tunnel-client.exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Executable must be tunnel-client.exe.");
        if (string.IsNullOrWhiteSpace(profileName) || profileName.IndexOfAny(['\\', '/', ':']) >= 0)
            throw new ArgumentException("Invalid profile name.", nameof(profileName));
        if (!Path.IsPathFullyQualified(profileDirectory) || !Directory.Exists(profileDirectory))
            throw new DirectoryNotFoundException(profileDirectory);

        var profilePath = Path.Combine(profileDirectory, profileName + ".yaml");
        if (!File.Exists(profilePath))
            throw new FileNotFoundException("Tunnel profile not found.", profilePath);
        if (!File.Exists(RuntimeKeyPath))
            throw new FileNotFoundException("Tunnel runtime key file not found.", RuntimeKeyPath);
    }

    private static string RequireParameter(SignedPlan plan, string key)
    {
        if (!plan.Parameters.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
            throw new InvalidDataException($"{key} parameter is required.");
        return value;
    }

    private static void RequireIntentMatch(SignedPlan plan, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "tunnel", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, "tunnel-start", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.Ordinal) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }
}
