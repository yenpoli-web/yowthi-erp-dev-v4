using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Build;

[McpServerToolType]
public static class BuildTools
{
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private const string DotnetExe = @"C:\Program Files\dotnet\dotnet.exe";

    [McpServerTool(Name = "dotnet_build_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed plan to run dotnet build for one existing project or solution using the native .NET Process API. The executable and build action are fixed; arbitrary commands are not accepted. No PowerShell, cmd, or generic command executor is used.")]
    public static SignedPlan DotnetBuildPlan(string projectPath, string outputDirectory, string configuration = "Release", int timeoutSeconds = 300)
    {
        var project = Path.GetFullPath(projectPath);
        var output = Path.GetFullPath(outputDirectory);
        ValidateInputs(project, output, configuration, timeoutSeconds);

        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["projectPath"] = project,
            ["outputDirectory"] = output,
            ["configuration"] = configuration,
            ["timeoutSeconds"] = timeoutSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };

        var summary = $"Build {project} to {output} ({configuration})";
        var unsigned = new SignedPlan(1, planId, approvalCode, "build", "dotnet-build", project, parameters, RiskClass.Medium, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "dotnet_build_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared build/dotnet-build plan using the native .NET Process API. The executable is fixed to dotnet.exe and the action is fixed to build. The caller must repeat the signed operation, target, summary, and risk class. No PowerShell, cmd, or generic command executor is used.")]
    public static async Task<BuildExecutionResult> DotnetBuildExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, operation, target, summary, riskClass);

        var project = RequireParameter(plan, "projectPath");
        var output = RequireParameter(plan, "outputDirectory");
        var configuration = RequireParameter(plan, "configuration");
        var timeoutText = RequireParameter(plan, "timeoutSeconds");
        if (!int.TryParse(timeoutText, out var timeoutSeconds))
            throw new InvalidDataException("timeoutSeconds parameter is invalid.");
        ValidateInputs(project, output, configuration, timeoutSeconds);

        Directory.CreateDirectory(output);
        var psi = new ProcessStartInfo
        {
            FileName = DotnetExe,
            WorkingDirectory = Path.GetDirectoryName(project)!,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("build");
        psi.ArgumentList.Add(project);
        psi.ArgumentList.Add("--configuration");
        psi.ArgumentList.Add(configuration);
        psi.ArgumentList.Add("--output");
        psi.ArgumentList.Add(output);
        psi.ArgumentList.Add("--nologo");

        try
        {
            using var process = Process.Start(psi) ?? throw new InvalidOperationException("dotnet build failed to start.");
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
                throw new TimeoutException($"dotnet build exceeded {timeoutSeconds} seconds.");
            }

            var stdout = await stdoutTask;
            var stderr = await stderrTask;
            var combined = stdout + "\n" + stderr;
            var warnings = CountMarker(combined, "warning ");
            var errors = CountMarker(combined, "error ");

            Store.Consume(planId);
            var result = new BuildExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, process.ExitCode, warnings, errors, stdout, stderr, DateTimeOffset.UtcNow);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, process.ExitCode, warnings, errors }, process.ExitCode == 0 ? "executed" : "failed");
            return result;
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    private static void ValidateInputs(string projectPath, string outputDirectory, string configuration, int timeoutSeconds)
    {
        if (!File.Exists(DotnetExe))
            throw new FileNotFoundException("dotnet.exe not found.", DotnetExe);
        if (!Path.IsPathFullyQualified(projectPath) || !File.Exists(projectPath))
            throw new FileNotFoundException("Project or solution not found.", projectPath);
        var extension = Path.GetExtension(projectPath);
        if (!string.Equals(extension, ".csproj", StringComparison.OrdinalIgnoreCase) && !string.Equals(extension, ".sln", StringComparison.OrdinalIgnoreCase) && !string.Equals(extension, ".slnx", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Build target must be a .csproj, .sln, or .slnx file.");
        if (!Path.IsPathFullyQualified(outputDirectory))
            throw new ArgumentException("Output directory must be an absolute path.", nameof(outputDirectory));
        if (!string.Equals(configuration, "Debug", StringComparison.Ordinal) && !string.Equals(configuration, "Release", StringComparison.Ordinal))
            throw new ArgumentException("Configuration must be Debug or Release.", nameof(configuration));
        if (timeoutSeconds < 30 || timeoutSeconds > 1800)
            throw new ArgumentOutOfRangeException(nameof(timeoutSeconds), "Timeout must be between 30 and 1800 seconds.");
    }

    private static int CountMarker(string text, string marker)
    {
        var count = 0;
        var index = 0;
        while ((index = text.IndexOf(marker, index, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            count++;
            index += marker.Length;
        }
        return count;
    }

    private static string RequireParameter(SignedPlan plan, string key)
    {
        if (!plan.Parameters.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
            throw new InvalidDataException($"{key} parameter is required.");
        return value;
    }

    private static void RequireIntentMatch(SignedPlan plan, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "build", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, "dotnet-build", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.Ordinal) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }
}

public sealed record BuildExecutionResult(
    string PlanId,
    string Tool,
    string Operation,
    string Target,
    int ExitCode,
    int Warnings,
    int Errors,
    string StdOut,
    string StdErr,
    DateTimeOffset ExecutedUtc);
