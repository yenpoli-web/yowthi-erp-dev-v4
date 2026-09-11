using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;
using YowThi.DevelopmentAgent3.Security;

namespace YowThi.DevelopmentAgent3.Scratch;

public sealed record AgentScratchScriptExecutionResult(
    string PlanId,
    int ExitCode,
    string StdOut,
    string StdErr,
    string ScriptSha256,
    string ScratchArtifactId,
    bool ScratchDeleted,
    DateTimeOffset ExecutedUtc);

[McpServerToolType]
public static class AgentScratchScriptTools
{
    private const string PowerShellExe = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    private const string FrozenProductionRoot = @"C:\yowthi-erp";
    private const int MaxScriptUtf8Bytes = 1024 * 1024;
    private const int PlanLifetimeMinutes = 10;
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly ConcurrentDictionary<string, PendingScriptPayload> Payloads = new(StringComparer.Ordinal);

    [McpServerTool(Name = "agent_scratch_script_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed plan for an Agent-owned temporary PowerShell helper without creating any file in the Git worktree. Raw script content is retained only in expiring process memory; the signed plan and audit contain only SHA-256, byte count, argument count, timeout, owner and TTL metadata. The script will later be materialized only under the fixed repo-external Agent scratch vault.")]
    public static SignedPlan AgentScratchScriptPlan(
        string script,
        string[]? arguments = null,
        int timeoutSeconds = 300,
        int scratchTtlMinutes = 30)
    {
        SweepExpiredPayloads();
        ValidateTimeout(timeoutSeconds);
        if (scratchTtlMinutes is < 5 or > 1440)
            throw new ArgumentOutOfRangeException(nameof(scratchTtlMinutes), "Scratch TTL must be between 5 and 1440 minutes.");
        ValidateScriptText(script);
        var scriptBytes = Encoding.UTF8.GetBytes(script);
        if (scriptBytes.Length is <= 0 or > MaxScriptUtf8Bytes)
            throw new ArgumentOutOfRangeException(nameof(script), $"Scratch script must contain 1-{MaxScriptUtf8Bytes} UTF-8 bytes.");
        var args = ValidateArguments(arguments ?? Array.Empty<string>());

        var now = DateTimeOffset.UtcNow;
        var expires = now.AddMinutes(PlanLifetimeMinutes);
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var scriptSha256 = Convert.ToHexString(SHA256.HashData(scriptBytes));
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["scriptSha256"] = scriptSha256,
            ["scriptUtf8Bytes"] = scriptBytes.Length.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["argumentCount"] = args.Length.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["timeoutSeconds"] = timeoutSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["scratchTtlMinutes"] = scratchTtlMinutes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["scratchOwner"] = "automation/agent-scratch-script",
            ["scratchRoot"] = AgentScratchStore.RootPath
        };
        var summary = $"Execute Agent-owned scratch PowerShell helper (sha256={scriptSha256[..12]}, bytes={scriptBytes.Length}, arguments={args.Length}, timeout={timeoutSeconds}s, ttl={scratchTtlMinutes}m)";
        var unsigned = new SignedPlan(1, planId, approvalCode, "agent-scratch", "scratch-script", AgentScratchStore.RootPath, parameters, RiskClass.High, summary, now, expires, string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        if (!Payloads.TryAdd(planId, new PendingScriptPayload(expires, script, args, timeoutSeconds, scratchTtlMinutes, scriptSha256)))
            throw new InvalidOperationException("Scratch script payload already exists.");
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new
        {
            signed.PlanId,
            scriptSha256,
            scriptUtf8Bytes = scriptBytes.Length,
            argumentCount = args.Length,
            timeoutSeconds,
            scratchTtlMinutes,
            owner = "automation/agent-scratch-script"
        }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "agent_scratch_script_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared Agent-owned scratch PowerShell helper. The script is materialized only under the fixed repo-external scratch vault with planId/owner/purpose/TTL manifest metadata, its SHA-256 is revalidated, PowerShell runs non-interactively with fixed safety checks, and both script plus manifest are deleted after execution. A crash may leave only TTL-bounded Agent-owned scratch, which scratch reconciliation can safely remove later. Only planId and approvalCode are accepted.")]
    public static async Task<AgentScratchScriptExecutionResult> AgentScratchScriptExecute(
        string planId,
        string approvalCode,
        CancellationToken cancellationToken = default)
    {
        SweepExpiredPayloads();
        var plan = Store.GetValidated(planId, approvalCode);
        if (!string.Equals(plan.Tool, "agent-scratch", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, "scratch-script", StringComparison.Ordinal) ||
            !string.Equals(plan.Target, AgentScratchStore.RootPath, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Scratch script plan intent mismatch.");
        if (!Payloads.TryGetValue(planId, out var payload) || payload.ExpiresUtc <= DateTimeOffset.UtcNow)
            throw new InvalidOperationException("Scratch script payload expired or is unavailable.");
        if (!string.Equals(Require(plan, "scriptSha256"), payload.ScriptSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Scratch script payload does not match signed plan.");

        ValidateScriptText(payload.Script);
        var artifact = AgentScratchStore.CreateArtifact(
            plan.PlanId,
            "automation/agent-scratch-script",
            "powershell-helper",
            ".ps1",
            Encoding.UTF8.GetBytes(payload.Script),
            DateTimeOffset.UtcNow.AddMinutes(payload.ScratchTtlMinutes));
        var verified = AgentScratchStore.RequireActiveOwnedArtifact(artifact.DataPath, "powershell-helper");
        if (!string.Equals(verified.Sha256, payload.ScriptSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Materialized scratch script SHA-256 mismatch.");

        int exitCode = -1;
        string stdout = string.Empty;
        string stderr = string.Empty;
        try
        {
            if (!File.Exists(PowerShellExe)) throw new FileNotFoundException("Windows PowerShell executable not found.", PowerShellExe);
            var psi = new ProcessStartInfo
            {
                FileName = PowerShellExe,
                WorkingDirectory = AgentScratchStore.RootPath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            psi.ArgumentList.Add("-NoLogo");
            psi.ArgumentList.Add("-NoProfile");
            psi.ArgumentList.Add("-NonInteractive");
            psi.ArgumentList.Add("-ExecutionPolicy");
            psi.ArgumentList.Add("RemoteSigned");
            psi.ArgumentList.Add("-File");
            psi.ArgumentList.Add(artifact.DataPath);
            foreach (var arg in payload.Arguments) psi.ArgumentList.Add(arg);

            using var process = Process.Start(psi) ?? throw new InvalidOperationException("PowerShell process failed to start.");
            var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(payload.TimeoutSeconds));
            try
            {
                await process.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                throw new TimeoutException($"Scratch PowerShell helper exceeded {payload.TimeoutSeconds} seconds.");
            }
            exitCode = process.ExitCode;
            stdout = await stdoutTask;
            stderr = await stderrTask;
            Store.Consume(planId);
            Payloads.TryRemove(planId, out _);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new
            {
                plan.PlanId,
                exitCode,
                scriptSha256 = payload.ScriptSha256,
                scratchArtifactId = artifact.ArtifactId,
                argumentCount = payload.Arguments.Length
            }, exitCode == 0 ? "executed" : "failed");
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, errorType = ex.GetType().Name, scratchArtifactId = artifact.ArtifactId }, "failed");
            throw;
        }
        finally
        {
            _ = AgentScratchStore.TryDeleteOwnedArtifact(artifact.DataPath);
        }

        var deleted = !File.Exists(artifact.DataPath) && !File.Exists(artifact.ManifestPath);
        return new(plan.PlanId, exitCode, stdout, stderr, payload.ScriptSha256, artifact.ArtifactId, deleted, DateTimeOffset.UtcNow);
    }

    private static string[] ValidateArguments(IReadOnlyList<string> arguments)
    {
        if (arguments.Count > 32) throw new ArgumentOutOfRangeException(nameof(arguments), "Scratch helper accepts at most 32 arguments.");
        var result = new string[arguments.Count];
        for (var i = 0; i < arguments.Count; i++)
        {
            var value = arguments[i] ?? throw new ArgumentException("Scratch helper arguments may not be null.", nameof(arguments));
            if (value.Length > 4096 || value.IndexOf('\0') >= 0) throw new ArgumentException("Scratch helper argument is invalid.", nameof(arguments));
            result[i] = value;
        }
        return result;
    }

    private static void ValidateScriptText(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) throw new ArgumentException("Scratch script content is required.", nameof(text));
        if (text.IndexOf('\0') >= 0) throw new ArgumentException("Scratch script may not contain NUL.", nameof(text));
        if (text.Contains(FrozenProductionRoot, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException($"Scratch script contains frozen production root {FrozenProductionRoot}.");
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
            if (text.Contains(token, StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException($"Scratch script contains blocked construct: {token}.");
    }

    private static void ValidateTimeout(int timeoutSeconds)
    {
        if (timeoutSeconds is < 5 or > 1800)
            throw new ArgumentOutOfRangeException(nameof(timeoutSeconds), "Timeout must be between 5 and 1800 seconds.");
    }

    private static string Require(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidDataException($"Signed scratch-script parameter {key} is required.");

    private static void SweepExpiredPayloads()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var pair in Payloads)
            if (pair.Value.ExpiresUtc <= now) Payloads.TryRemove(pair.Key, out _);
        _ = AgentScratchStore.ReconcileExpired();
    }

    private sealed record PendingScriptPayload(
        DateTimeOffset ExpiresUtc,
        string Script,
        string[] Arguments,
        int TimeoutSeconds,
        int ScratchTtlMinutes,
        string ScriptSha256);
}
