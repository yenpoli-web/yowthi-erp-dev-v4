using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Build;

[McpServerToolType]
public static class DotnetDevelopmentTools
{
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private const string DotnetExe = @"C:\Program Files\dotnet\dotnet.exe";
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";

    [McpServerTool(Name = "dotnet_restore_plan", ReadOnly = false, Destructive = false, OpenWorld = true)]
    [Description("Prepare a one-time signed plan to run fixed dotnet restore for one .NET project or solution under the YowThi ERP v4 development root. Arbitrary CLI arguments, sources, runtimes, properties, and production paths are rejected.")]
    public static SignedPlan DotnetRestorePlan(string projectPath, int timeoutSeconds = 300) => Prepare(projectPath, "dotnet-restore", timeoutSeconds);

    [McpServerTool(Name = "dotnet_restore_execute", ReadOnly = false, Destructive = false, OpenWorld = true)]
    [Description("Execute one previously prepared build/dotnet-restore plan using fixed dotnet restore --nologo --no-cache. Project identity and signed intent are revalidated. Arbitrary CLI arguments and package sources are not accepted.")]
    public static Task<DotnetDevelopmentResult> DotnetRestoreExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass) => Execute(planId, approvalCode, operation, target, summary, riskClass, "dotnet-restore");

    [McpServerTool(Name = "dotnet_test_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed plan to run fixed dotnet test for one .NET project or solution under the YowThi ERP v4 development root. Arbitrary test arguments, filters, loggers, environment variables, properties, and production paths are rejected.")]
    public static SignedPlan DotnetTestPlan(string projectPath, string configuration = "Release", int timeoutSeconds = 600)
    {
        if (configuration is not ("Debug" or "Release")) throw new ArgumentException("Configuration must be Debug or Release.", nameof(configuration));
        return Prepare(projectPath, "dotnet-test", timeoutSeconds, configuration);
    }

    [McpServerTool(Name = "dotnet_test_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared build/dotnet-test plan using fixed dotnet test --no-restore --nologo with the sealed Debug or Release configuration. Arbitrary test arguments, filters, loggers, and environment variables are not accepted.")]
    public static Task<DotnetDevelopmentResult> DotnetTestExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass) => Execute(planId, approvalCode, operation, target, summary, riskClass, "dotnet-test");

    private static SignedPlan Prepare(string projectPath, string operation, int timeoutSeconds, string? configuration = null)
    {
        var project = ValidateProject(projectPath);
        if (timeoutSeconds < 30 || timeoutSeconds > 1800) throw new ArgumentOutOfRangeException(nameof(timeoutSeconds), "Timeout must be between 30 and 1800 seconds.");
        var now = DateTimeOffset.UtcNow;
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["projectPath"] = project,
            ["projectSha256"] = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(project))),
            ["timeoutSeconds"] = timeoutSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };
        if (configuration is not null) parameters["configuration"] = configuration;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var summary = operation == "dotnet-restore" ? $"Restore .NET dependencies for {project}" : $"Run .NET tests for {project} ({configuration})";
        var unsigned = new SignedPlan(1, planId, approvalCode, "build", operation, project, parameters, RiskClass.Medium, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    private static async Task<DotnetDevelopmentResult> Execute(string planId, string approvalCode, string operation, string target, string summary, string riskClass, string expectedOperation)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, operation, target, summary, riskClass, expectedOperation);
        var project = ValidateProject(RequireParameter(plan, "projectPath"));
        var sealedSha = RequireParameter(plan, "projectSha256");
        var currentSha = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(project)));
        if (!string.Equals(sealedSha, currentSha, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Project file changed after plan preparation.");
        if (!int.TryParse(RequireParameter(plan, "timeoutSeconds"), out var timeoutSeconds)) throw new InvalidDataException("timeoutSeconds parameter is invalid.");

        var psi = new ProcessStartInfo { FileName = DotnetExe, WorkingDirectory = Path.GetDirectoryName(project)!, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        psi.ArgumentList.Add(expectedOperation == "dotnet-restore" ? "restore" : "test");
        psi.ArgumentList.Add(project);
        if (expectedOperation == "dotnet-restore")
        {
            psi.ArgumentList.Add("--nologo");
            psi.ArgumentList.Add("--no-cache");
        }
        else
        {
            var configuration = RequireParameter(plan, "configuration");
            if (configuration is not ("Debug" or "Release")) throw new InvalidDataException("configuration parameter is invalid.");
            psi.ArgumentList.Add("--configuration"); psi.ArgumentList.Add(configuration);
            psi.ArgumentList.Add("--no-restore"); psi.ArgumentList.Add("--nologo");
        }

        try
        {
            using var process = Process.Start(psi) ?? throw new InvalidOperationException($"{expectedOperation} failed to start.");
            var stdoutTask = process.StandardOutput.ReadToEndAsync(); var stderrTask = process.StandardError.ReadToEndAsync();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
            try { await process.WaitForExitAsync(cts.Token); }
            catch (OperationCanceledException) { try { process.Kill(entireProcessTree: true); } catch { } throw new TimeoutException($"{expectedOperation} exceeded {timeoutSeconds} seconds."); }
            var stdout = await stdoutTask; var stderr = await stderrTask;
            Store.Consume(planId);
            var result = new DotnetDevelopmentResult(plan.PlanId, plan.Operation, plan.Target, process.ExitCode, stdout, stderr, DateTimeOffset.UtcNow);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, process.ExitCode }, process.ExitCode == 0 ? "executed" : "failed");
            return result;
        }
        catch (Exception ex) { Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed"); throw; }
    }

    private static string ValidateProject(string projectPath)
    {
        if (!File.Exists(DotnetExe)) throw new FileNotFoundException("dotnet.exe not found.", DotnetExe);
        var project = Path.GetFullPath(projectPath);
        if (!Path.IsPathFullyQualified(project) || !File.Exists(project)) throw new FileNotFoundException("Project or solution not found.", project);
        var root = Path.GetFullPath(DevRoot).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!project.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException("Project must be under the YowThi ERP v4 development root.");
        if (project.StartsWith(@"C:\yowthi-erp\", StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException("Production ERP paths are blocked.");
        var extension = Path.GetExtension(project);
        if (extension is not (".csproj" or ".sln" or ".slnx")) throw new InvalidOperationException("Target must be a .csproj, .sln, or .slnx file.");
        var attributes = File.GetAttributes(project);
        if ((attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Reparse-point project targets are not allowed.");
        return project;
    }

    private static string RequireParameter(SignedPlan plan, string key) => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : throw new InvalidDataException($"{key} parameter is required.");

    private static void RequireIntentMatch(SignedPlan plan, string operation, string target, string summary, string riskClass, string expectedOperation)
    {
        if (!string.Equals(plan.Tool, "build", StringComparison.Ordinal) || !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal) || !string.Equals(plan.Operation, operation, StringComparison.Ordinal) || !string.Equals(plan.Target, target, StringComparison.Ordinal) || !string.Equals(plan.Summary, summary, StringComparison.Ordinal) || !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }
}

public sealed record DotnetDevelopmentResult(string PlanId, string Operation, string Target, int ExitCode, string StdOut, string StdErr, DateTimeOffset ExecutedUtc);
