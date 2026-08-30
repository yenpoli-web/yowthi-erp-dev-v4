using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;
using YowThi.DevelopmentAgent3.Security;

namespace YowThi.DevelopmentAgent3.Automation;

[McpServerToolType]
public static class PowerShellTools
{
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly ProtectedPathPolicy Paths = new();

    private const string PowerShellExe = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    private const string AllowedScriptRoot = @"C:\Dev\YowThi-ERP-Dev-v4\automation\powershell";
    private const string FrozenProductionRoot = @"C:\yowthi-erp";

    [McpServerTool(Name = "powershell_script_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed high-risk plan to run one existing .ps1 file from the dedicated YowThi automation script root. Inline PowerShell commands are not accepted. The script SHA-256 is sealed into the plan and rechecked at execution. Obvious elevation and policy-bypass constructs are blocked. Arguments are signed and visible; do not use them for secrets.")]
    public static SignedPlan PowerShellScriptPlan(
        string scriptPath,
        string[]? arguments = null,
        string? workingDirectory = null,
        int timeoutSeconds = 300)
    {
        var script = ValidateScriptPath(scriptPath);
        var workingDir = ValidateWorkingDirectory(workingDirectory, script);
        ValidateTimeout(timeoutSeconds);

        var bytes = File.ReadAllBytes(script);
        var sha256 = Convert.ToHexString(SHA256.HashData(bytes));
        ValidateScriptText(Encoding.UTF8.GetString(bytes));

        var args = arguments ?? Array.Empty<string>();
        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["scriptPath"] = script,
            ["scriptSha256"] = sha256,
            ["argumentsJson"] = JsonSerializer.Serialize(args),
            ["workingDirectory"] = workingDir,
            ["timeoutSeconds"] = timeoutSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };

        var summary = $"Run PowerShell script {script} (sha256={sha256[..12]}, arguments={args.Length}, timeout={timeoutSeconds}s)";
        var unsigned = new SignedPlan(1, planId, approvalCode, "powershell", "powershell-script", script, parameters, RiskClass.High, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary, scriptSha256 = sha256, argumentCount = args.Length }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "powershell_script_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared powershell/powershell-script plan. Only the sealed .ps1 file is executed; inline -Command and -EncodedCommand are not supported. The script SHA-256 and safety preflight are rechecked before execution. PowerShell runs non-interactively with no profile and RemoteSigned policy. This is a high-risk host automation capability and may modify the machine according to the reviewed script.")]
    public static async Task<PowerShellExecutionResult> PowerShellScriptExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, operation, target, summary, riskClass);

        var script = ValidateScriptPath(RequireParameter(plan, "scriptPath"));
        var expectedSha256 = RequireParameter(plan, "scriptSha256");
        var workingDir = ValidateWorkingDirectory(RequireParameter(plan, "workingDirectory"), script);
        var argsJson = RequireParameter(plan, "argumentsJson");
        var timeoutText = RequireParameter(plan, "timeoutSeconds");
        if (!int.TryParse(timeoutText, out var timeoutSeconds))
            throw new InvalidDataException("timeoutSeconds parameter is invalid.");
        ValidateTimeout(timeoutSeconds);

        var bytes = File.ReadAllBytes(script);
        var actualSha256 = Convert.ToHexString(SHA256.HashData(bytes));
        if (!string.Equals(expectedSha256, actualSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("PowerShell script SHA-256 changed after plan creation.");
        ValidateScriptText(Encoding.UTF8.GetString(bytes));

        var args = JsonSerializer.Deserialize<string[]>(argsJson) ?? Array.Empty<string>();

        var psi = new ProcessStartInfo
        {
            FileName = PowerShellExe,
            WorkingDirectory = workingDir,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("-NoLogo");
        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-NonInteractive");
        psi.ArgumentList.Add("-ExecutionPolicy");
        psi.ArgumentList.Add("RemoteSigned");
        psi.ArgumentList.Add("-File");
        psi.ArgumentList.Add(script);
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);

        try
        {
            using var process = Process.Start(psi) ?? throw new InvalidOperationException("PowerShell process failed to start.");
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
                throw new TimeoutException($"PowerShell script exceeded {timeoutSeconds} seconds.");
            }

            var stdout = await stdoutTask;
            var stderr = await stderrTask;
            Store.Consume(planId);

            var result = new PowerShellExecutionResult(
                plan.PlanId,
                plan.Tool,
                plan.Operation,
                plan.Target,
                process.ExitCode,
                stdout,
                stderr,
                actualSha256,
                DateTimeOffset.UtcNow);

            Audit.Append(plan.Tool, plan.Operation, plan.Target,
                new { plan.PlanId, process.ExitCode, scriptSha256 = actualSha256, argumentCount = args.Length },
                process.ExitCode == 0 ? "executed" : "failed");
            return result;
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    private static string ValidateScriptPath(string path)
    {
        if (!File.Exists(PowerShellExe))
            throw new FileNotFoundException("Windows PowerShell executable not found.", PowerShellExe);
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            throw new ArgumentException("Absolute script path is required.", nameof(path));

        var full = Path.GetFullPath(path);
        var root = Path.GetFullPath(AllowedScriptRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!IsSameOrChild(full, root))
            throw new UnauthorizedAccessException($"PowerShell scripts must be under {root}.");
        if (!string.Equals(Path.GetExtension(full), ".ps1", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Only .ps1 scripts are allowed.");
        if (!File.Exists(full))
            throw new FileNotFoundException("PowerShell script does not exist.", full);
        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Reparse-point PowerShell scripts are not allowed.");
        return full;
    }

    private static string ValidateWorkingDirectory(string? workingDirectory, string scriptPath)
    {
        var candidate = string.IsNullOrWhiteSpace(workingDirectory)
            ? Path.GetDirectoryName(scriptPath)!
            : workingDirectory;
        if (!Path.IsPathFullyQualified(candidate))
            throw new ArgumentException("Working directory must be absolute.", nameof(workingDirectory));
        var full = Path.GetFullPath(candidate);
        if (!Directory.Exists(full))
            throw new DirectoryNotFoundException(full);
        Paths.RequireMutable(full);
        return full;
    }

    private static void ValidateScriptText(string text)
    {
        if (text.Contains(FrozenProductionRoot, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException($"PowerShell script contains frozen production root {FrozenProductionRoot}.");

        string[] blockedTokens =
        [
            "-EncodedCommand",
            "EncodedCommand",
            "-ExecutionPolicy Bypass",
            "Invoke-Expression",
            "Start-Process -Verb RunAs",
            "Start-Process  -Verb RunAs",
            "runas.exe"
        ];

        foreach (var token in blockedTokens)
        {
            if (text.Contains(token, StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException($"PowerShell script contains blocked construct: {token}.");
        }
    }

    private static void ValidateTimeout(int timeoutSeconds)
    {
        if (timeoutSeconds < 5 || timeoutSeconds > 1800)
            throw new ArgumentOutOfRangeException(nameof(timeoutSeconds), "Timeout must be between 5 and 1800 seconds.");
    }

    private static bool IsSameOrChild(string fullPath, string root)
    {
        return fullPath.Equals(root, StringComparison.OrdinalIgnoreCase) ||
               fullPath.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static string RequireParameter(SignedPlan plan, string key)
    {
        if (!plan.Parameters.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
            throw new InvalidDataException($"{key} parameter is required.");
        return value;
    }

    private static void RequireIntentMatch(SignedPlan plan, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "powershell", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, "powershell-script", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }
}

public sealed record PowerShellExecutionResult(
    string PlanId,
    string Tool,
    string Operation,
    string Target,
    int ExitCode,
    string StdOut,
    string StdErr,
    string ScriptSha256,
    DateTimeOffset ExecutedUtc);
