using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Runtime;

[McpServerToolType]
public static class RuntimeLifecycleTools
{
    private sealed record RuntimeEntry(
        int ProcessId,
        DateTimeOffset ProcessStartTimeUtc,
        string RuntimeDll,
        string RuntimeSha256,
        string ListenUrl,
        string HealthUrl,
        DateTimeOffset StartedUtc);

    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly ConcurrentDictionary<string, RuntimeEntry> Started = new(StringComparer.OrdinalIgnoreCase);
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(2) };

    private const string DotnetExe = @"C:\Program Files\dotnet\dotnet.exe";
    private const string AllowedRuntimeRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string RuntimeFileName = "YowThi.DevelopmentAgent3.dll";

    [McpServerTool(Name = "runtime_status", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read the status of one YowThi Development Agent 3 runtime endpoint. The tool checks the sealed runtime DLL path, computes its SHA-256, queries the loopback /health endpoint, and reports whether the endpoint was started by this Agent instance. It does not start, stop, restart, or modify any process.")]
    public static async Task<RuntimeStatusResult> RuntimeStatus(string runtimeDll, string listenUrl, string healthUrl)
    {
        var runtime = ValidateRuntimeDll(runtimeDll);
        var listen = ValidateLoopbackHttpUrl(listenUrl, nameof(listenUrl));
        var health = ValidateLoopbackHttpUrl(healthUrl, nameof(healthUrl));
        RequireSameAuthorityAndHealthPath(listen, health);

        var sha256 = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(runtime)));
        var key = NormalizeUrl(listen);
        RuntimeEntry? entry = null;
        if (Started.TryGetValue(key, out var candidate))
        {
            try
            {
                using var process = Process.GetProcessById(candidate.ProcessId);
                var processStartTimeUtc = new DateTimeOffset(process.StartTime.ToUniversalTime());
                if (!process.HasExited && processStartTimeUtc == candidate.ProcessStartTimeUtc)
                    entry = candidate;
                else
                    Started.TryRemove(key, out _);
            }
            catch
            {
                Started.TryRemove(key, out _);
            }
        }

        var healthProbe = await ProbeHealthAsync(health);
        return new RuntimeStatusResult(
            runtime,
            sha256,
            NormalizeUrl(listen),
            health.ToString(),
            healthProbe.Healthy,
            healthProbe.Service,
            healthProbe.Version,
            healthProbe.Status,
            healthProbe.Machine,
            entry is not null,
            entry?.ProcessId,
            entry?.StartedUtc,
            DateTimeOffset.UtcNow);
    }

    [McpServerTool(Name = "runtime_start_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed plan to start one YowThi Development Agent 3 runtime DLL with the fixed dotnet.exe host on a loopback HTTP endpoint. The runtime DLL SHA-256 is sealed into the plan. Arbitrary executables and arbitrary commands are not accepted.")]
    public static SignedPlan RuntimeStartPlan(string runtimeDll, string listenUrl, string healthUrl)
    {
        var runtime = ValidateRuntimeDll(runtimeDll);
        var listen = ValidateLoopbackHttpUrl(listenUrl, nameof(listenUrl));
        var health = ValidateLoopbackHttpUrl(healthUrl, nameof(healthUrl));
        RequireSameAuthorityAndHealthPath(listen, health);
        if (!File.Exists(DotnetExe)) throw new FileNotFoundException("dotnet.exe not found.", DotnetExe);

        var sha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(runtime)));
        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["runtimeDll"] = runtime,
            ["runtimeSha256"] = sha256,
            ["listenUrl"] = NormalizeUrl(listen),
            ["healthUrl"] = health.ToString()
        };

        var summary = $"Start YowThi Development Agent 3 runtime {runtime} at {NormalizeUrl(listen)} (sha256={sha256[..12]})";
        var unsigned = new SignedPlan(1, planId, approvalCode, "runtime", "runtime-start", runtime, parameters, RiskClass.Medium, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary, runtimeSha256 = sha256 }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "runtime_start_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared runtime/runtime-start plan using the fixed dotnet.exe host and native .NET Process API. The runtime SHA-256 and loopback endpoint are rechecked before start. If health validation fails, only the child process started by this invocation is terminated. No PowerShell, cmd, or generic command executor is used.")]
    public static async Task<RuntimeStartResult> RuntimeStartExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "runtime-start", operation, target, summary, riskClass);

        var runtime = ValidateRuntimeDll(RequireParameter(plan, "runtimeDll"));
        var expectedSha256 = RequireParameter(plan, "runtimeSha256");
        var listen = ValidateLoopbackHttpUrl(RequireParameter(plan, "listenUrl"), "listenUrl");
        var health = ValidateLoopbackHttpUrl(RequireParameter(plan, "healthUrl"), "healthUrl");
        RequireSameAuthorityAndHealthPath(listen, health);
        if (!File.Exists(DotnetExe)) throw new FileNotFoundException("dotnet.exe not found.", DotnetExe);

        var actualSha256 = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(runtime)));
        if (!string.Equals(expectedSha256, actualSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Runtime DLL SHA-256 changed after plan creation.");

        if (await IsPortListeningAsync(listen.Host, listen.Port))
            throw new InvalidOperationException($"Loopback endpoint {NormalizeUrl(listen)} is already in use.");

        Process? process = null;
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = DotnetExe,
                WorkingDirectory = Path.GetDirectoryName(runtime)!,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.ArgumentList.Add(runtime);
            psi.Environment["YOWTHI_AGENT3_URL"] = NormalizeUrl(listen);

            process = Process.Start(psi) ?? throw new InvalidOperationException("Runtime process failed to start.");

            HealthProbeResult probe = new(false, null, null, null, null);
            for (var i = 0; i < 20; i++)
            {
                if (process.HasExited) break;
                probe = await ProbeHealthAsync(health);
                if (probe.Healthy) break;
                await Task.Delay(500);
            }

            if (!probe.Healthy)
                throw new InvalidOperationException("Started runtime failed health validation.");

            var key = NormalizeUrl(listen);
            var startedUtc = DateTimeOffset.UtcNow;
            var processStartTimeUtc = new DateTimeOffset(process.StartTime.ToUniversalTime());
            var entry = new RuntimeEntry(process.Id, processStartTimeUtc, runtime, actualSha256, key, health.ToString(), startedUtc);
            Started[key] = entry;
            Store.Consume(planId);

            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, processId = process.Id, processStartTimeUtc, listenUrl = key, runtimeSha256 = actualSha256 }, "executed");
            return new RuntimeStartResult(plan.PlanId, process.Id, runtime, actualSha256, key, health.ToString(), probe.Service, probe.Version, probe.Status, startedUtc);
        }
        catch (Exception ex)
        {
            try
            {
                if (process is { HasExited: false })
                {
                    process.Kill(entireProcessTree: true);
                    await process.WaitForExitAsync();
                }
            }
            catch { }

            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "runtime_stop_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed plan to stop one YowThi Development Agent 3 runtime that was started and is still tracked by this Agent instance. The runtime is identified only by its loopback listen URL; arbitrary PIDs and untracked processes are not accepted.")]
    public static SignedPlan RuntimeStopPlan(string listenUrl)
    {
        var listen = ValidateLoopbackHttpUrl(listenUrl, nameof(listenUrl));
        var key = NormalizeUrl(listen);
        if (!Started.TryGetValue(key, out var entry))
            throw new InvalidOperationException($"Loopback endpoint {key} is not an Agent-tracked runtime.");

        try
        {
            using var process = Process.GetProcessById(entry.ProcessId);
            if (process.HasExited)
            {
                Started.TryRemove(key, out _);
                throw new InvalidOperationException($"Tracked runtime at {key} has already exited.");
            }

            var processStartTimeUtc = new DateTimeOffset(process.StartTime.ToUniversalTime());
            if (processStartTimeUtc != entry.ProcessStartTimeUtc)
            {
                Started.TryRemove(key, out _);
                throw new InvalidOperationException($"Tracked runtime identity at {key} is stale because the PID was reused.");
            }
        }
        catch (ArgumentException)
        {
            Started.TryRemove(key, out _);
            throw new InvalidOperationException($"Tracked runtime process at {key} no longer exists.");
        }

        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["listenUrl"] = key,
            ["healthUrl"] = entry.HealthUrl,
            ["runtimeDll"] = entry.RuntimeDll,
            ["runtimeSha256"] = entry.RuntimeSha256,
            ["processId"] = entry.ProcessId.ToString(CultureInfo.InvariantCulture),
            ["processStartTimeUtc"] = entry.ProcessStartTimeUtc.ToString("O", CultureInfo.InvariantCulture),
            ["startedUtc"] = entry.StartedUtc.ToString("O", CultureInfo.InvariantCulture)
        };

        var summary = $"Stop Agent-owned YowThi Development Agent 3 runtime at {key} (pid={entry.ProcessId}, sha256={entry.RuntimeSha256[..12]})";
        var unsigned = new SignedPlan(1, planId, approvalCode, "runtime", "runtime-stop", key, parameters, RiskClass.Medium, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary, processId = entry.ProcessId, processStartTimeUtc = entry.ProcessStartTimeUtc, runtimeSha256 = entry.RuntimeSha256 }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "runtime_stop_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared runtime/runtime-stop plan. Only the exact Agent-owned runtime still tracked under the signed loopback endpoint, PID, process start time, runtime path, and runtime SHA-256 can be stopped. Arbitrary PIDs and untracked processes are not accepted. No PowerShell, cmd, or generic command executor is used.")]
    public static async Task<RuntimeStopResult> RuntimeStopExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "runtime-stop", operation, target, summary, riskClass);

        var listen = ValidateLoopbackHttpUrl(RequireParameter(plan, "listenUrl"), "listenUrl");
        var key = NormalizeUrl(listen);
        var expectedPid = int.Parse(RequireParameter(plan, "processId"), CultureInfo.InvariantCulture);
        var expectedProcessStartTimeUtc = DateTimeOffset.Parse(RequireParameter(plan, "processStartTimeUtc"), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
        var expectedRuntimeDll = RequireParameter(plan, "runtimeDll");
        var expectedRuntimeSha256 = RequireParameter(plan, "runtimeSha256");

        if (!Started.TryGetValue(key, out var entry))
            throw new InvalidOperationException($"Loopback endpoint {key} is no longer an Agent-tracked runtime.");

        if (entry.ProcessId != expectedPid ||
            entry.ProcessStartTimeUtc != expectedProcessStartTimeUtc ||
            !string.Equals(entry.RuntimeDll, expectedRuntimeDll, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(entry.RuntimeSha256, expectedRuntimeSha256, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(entry.ListenUrl, key, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Tracked runtime identity no longer matches the signed stop plan.");

        try
        {
            using var process = Process.GetProcessById(entry.ProcessId);
            if (process.HasExited)
            {
                Started.TryRemove(key, out _);
                throw new InvalidOperationException($"Tracked runtime at {key} has already exited.");
            }

            var processStartTimeUtc = new DateTimeOffset(process.StartTime.ToUniversalTime());
            if (processStartTimeUtc != entry.ProcessStartTimeUtc)
            {
                Started.TryRemove(key, out _);
                throw new InvalidOperationException($"Tracked runtime identity at {key} is stale because the PID was reused.");
            }

            process.Kill(entireProcessTree: true);
            using var stopTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await process.WaitForExitAsync(stopTimeout.Token);
        }
        catch (ArgumentException)
        {
            Started.TryRemove(key, out _);
            throw new InvalidOperationException($"Tracked runtime process at {key} no longer exists.");
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, processId = entry.ProcessId, error = ex.Message }, "failed");
            throw;
        }

        Started.TryRemove(key, out _);

        var endpointReleased = false;
        for (var i = 0; i < 20; i++)
        {
            if (!await IsPortListeningAsync(listen.Host, listen.Port))
            {
                endpointReleased = true;
                break;
            }
            await Task.Delay(250);
        }

        Store.Consume(planId);
        var stoppedUtc = DateTimeOffset.UtcNow;
        Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, processId = entry.ProcessId, processStartTimeUtc = entry.ProcessStartTimeUtc, listenUrl = key, runtimeSha256 = entry.RuntimeSha256, endpointReleased }, "executed");
        return new RuntimeStopResult(plan.PlanId, entry.ProcessId, entry.RuntimeDll, entry.RuntimeSha256, key, endpointReleased, stoppedUtc);
    }

    private static string ValidateRuntimeDll(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            throw new ArgumentException("runtimeDll must be an absolute path.", nameof(path));
        var full = Path.GetFullPath(path);
        var root = Path.GetFullPath(AllowedRuntimeRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!IsSameOrChild(full, root))
            throw new UnauthorizedAccessException($"Runtime DLL must be under {root}.");
        if (!string.Equals(Path.GetFileName(full), RuntimeFileName, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Runtime DLL must be named {RuntimeFileName}.");
        if (!File.Exists(full)) throw new FileNotFoundException("Runtime DLL does not exist.", full);
        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Reparse-point runtime DLLs are not allowed.");
        return full;
    }

    private static Uri ValidateLoopbackHttpUrl(string value, string name)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttp ||
            !IPAddress.TryParse(uri.Host, out var ip) ||
            !IPAddress.IsLoopback(ip) ||
            uri.Port <= 0)
            throw new ArgumentException($"{name} must be an absolute loopback HTTP URL using an IP literal and explicit port.", name);
        return uri;
    }

    private static void RequireSameAuthorityAndHealthPath(Uri listen, Uri health)
    {
        if (!string.Equals(listen.Host, health.Host, StringComparison.OrdinalIgnoreCase) || listen.Port != health.Port)
            throw new ArgumentException("listenUrl and healthUrl must use the same loopback host and port.");
        if (!string.Equals(health.AbsolutePath.TrimEnd('/'), "/health", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("healthUrl path must be /health.");
    }

    private static async Task<bool> IsPortListeningAsync(string host, int port)
    {
        using var client = new TcpClient();
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(400));
        try
        {
            await client.ConnectAsync(host, port, cts.Token);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<HealthProbeResult> ProbeHealthAsync(Uri healthUri)
    {
        try
        {
            using var response = await Http.GetAsync(healthUri);
            if (!response.IsSuccessStatusCode) return new(false, null, null, null, null);
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var root = doc.RootElement;
            var service = GetString(root, "service");
            var version = GetString(root, "version");
            var status = GetString(root, "status");
            var machine = GetString(root, "machine");
            var healthy = string.Equals(service, "YowThi Development Agent 3", StringComparison.Ordinal) && string.Equals(status, "ok", StringComparison.OrdinalIgnoreCase);
            return new(healthy, service, version, status, machine);
        }
        catch
        {
            return new(false, null, null, null, null);
        }
    }

    private static string? GetString(JsonElement root, string name)
        => root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static bool IsSameOrChild(string fullPath, string root)
        => fullPath.Equals(root, StringComparison.OrdinalIgnoreCase) || fullPath.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);

    private static string NormalizeUrl(Uri uri) => uri.GetLeftPart(UriPartial.Authority).TrimEnd('/');

    private static string RequireParameter(SignedPlan plan, string key)
    {
        if (!plan.Parameters.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
            throw new InvalidDataException($"{key} parameter is required.");
        return value;
    }

    private static void RequireIntentMatch(SignedPlan plan, string expectedOperation, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "runtime", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }

    private sealed record HealthProbeResult(bool Healthy, string? Service, string? Version, string? Status, string? Machine);
}

public sealed record RuntimeStatusResult(
    string RuntimeDll,
    string RuntimeSha256,
    string ListenUrl,
    string HealthUrl,
    bool Healthy,
    string? Service,
    string? Version,
    string? Status,
    string? Machine,
    bool ManagedByThisAgent,
    int? ProcessId,
    DateTimeOffset? StartedUtc,
    DateTimeOffset CheckedUtc);

public sealed record RuntimeStartResult(
    string PlanId,
    int ProcessId,
    string RuntimeDll,
    string RuntimeSha256,
    string ListenUrl,
    string HealthUrl,
    string? Service,
    string? Version,
    string? Status,
    DateTimeOffset StartedUtc);

public sealed record RuntimeStopResult(
    string PlanId,
    int ProcessId,
    string RuntimeDll,
    string RuntimeSha256,
    string ListenUrl,
    bool EndpointReleased,
    DateTimeOffset StoppedUtc);