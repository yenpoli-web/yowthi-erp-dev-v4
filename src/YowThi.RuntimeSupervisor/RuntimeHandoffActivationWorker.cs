using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace YowThi.RuntimeSupervisor;

public sealed class RuntimeHandoffActivationWorker(ILogger<RuntimeHandoffActivationWorker> logger) : BackgroundService
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string ReleaseRoot = DevRoot + @"\acceptance\agent-lifecycle\releases";
    private const string HandoffRoot = DevRoot + @"\.agent3-handoff";
    private const string PendingRoot = DevRoot + @"\.agent3-handoff\pending";
    private const string ReadyRoot = DevRoot + @"\.agent3-handoff\ready";
    private const string ActiveStatePath = DevRoot + @"\.agent3-handoff\active-runtime.json";

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(2) };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        RuntimeSupervisorPathSafety.RequireSafeDirectoryTraversal(HandoffRoot, DevRoot);
        Directory.CreateDirectory(PendingRoot);
        Directory.CreateDirectory(ReadyRoot);
        RuntimeSupervisorPathSafety.RequireSafeDirectoryTraversal(PendingRoot, HandoffRoot);
        RuntimeSupervisorPathSafety.RequireSafeDirectoryTraversal(ReadyRoot, HandoffRoot);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                RuntimeSupervisorPathSafety.RequireSafeDirectoryTraversal(HandoffRoot, DevRoot);
                RuntimeSupervisorPathSafety.RequireSafeDirectoryTraversal(PendingRoot, HandoffRoot);
                RuntimeSupervisorPathSafety.RequireSafeDirectoryTraversal(ReadyRoot, HandoffRoot);
                var authorizationPath = Directory.EnumerateFiles(ReadyRoot, "*.json", SearchOption.TopDirectoryOnly)
                    .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                    .FirstOrDefault();
                if (authorizationPath is not null)
                    await ApplyAuthorizationAsync(authorizationPath, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Runtime handoff activation authorization failed.");
            }

            try { await Task.Delay(500, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }

        _http.Dispose();
    }

    private async Task ApplyAuthorizationAsync(string authorizationPath, CancellationToken token)
    {
        var fileName = Path.GetFileNameWithoutExtension(authorizationPath);
        if (!Guid.TryParseExact(fileName, "N", out _))
            throw new InvalidDataException("Ready authorization file name must be a GUID N handoff ID.");
        RejectReparse(authorizationPath);

        var pendingPath = Path.Combine(PendingRoot, fileName + ".json");
        if (!File.Exists(pendingPath))
            throw new FileNotFoundException("Authorized pending handoff manifest does not exist.", pendingPath);
        RejectReparse(pendingPath);

        var authorization = JsonSerializer.Deserialize<ActivationAuthorization>(await File.ReadAllTextAsync(authorizationPath, token), JsonOptions)
            ?? throw new InvalidDataException("Invalid runtime handoff activation authorization.");
        if (authorization.schemaVersion != 1 ||
            string.IsNullOrWhiteSpace(authorization.activationPlanId) ||
            !string.Equals(authorization.handoffPlanId, fileName, StringComparison.Ordinal))
            throw new InvalidDataException("Runtime handoff activation authorization identity is invalid.");

        var pendingBytes = await File.ReadAllBytesAsync(pendingPath, token);
        var pendingSha = Convert.ToHexString(SHA256.HashData(pendingBytes));
        if (!string.Equals(pendingSha, authorization.pendingManifestSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Pending handoff manifest SHA-256 does not match the activation authorization.");

        var manifest = JsonSerializer.Deserialize<HandoffManifest>(pendingBytes, JsonOptions)
            ?? throw new InvalidDataException("Invalid pending handoff manifest.");
        if (manifest.schemaVersion != 1 ||
            !string.Equals(manifest.planId, fileName, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(manifest.runtimeDll) ||
            string.IsNullOrWhiteSpace(manifest.runtimeSha256) ||
            string.IsNullOrWhiteSpace(manifest.listenUrl) ||
            string.IsNullOrWhiteSpace(manifest.healthUrl))
            throw new InvalidDataException("Pending handoff manifest identity is invalid.");
        ValidateRuntime(manifest.runtimeDll, manifest.runtimeSha256);
        ValidateLoopbackHttp(manifest.listenUrl, "listenUrl");
        ValidateLoopbackHttp(manifest.healthUrl, "healthUrl");
        if (!string.Equals(manifest.runtimeSha256, authorization.candidateRuntimeSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Candidate runtime SHA-256 does not match the activation authorization.");

        RuntimeSupervisorPathSafety.RequireSafeDirectoryTraversal(HandoffRoot, DevRoot);
        if (!File.Exists(ActiveStatePath))
            throw new FileNotFoundException("Active runtime state does not exist.", ActiveStatePath);
        RuntimeSupervisorPathSafety.RejectReparseIfExists(ActiveStatePath);
        var active = JsonSerializer.Deserialize<ActiveState>(await File.ReadAllTextAsync(ActiveStatePath, token), JsonOptions)
            ?? throw new InvalidDataException("Invalid active runtime state.");
        if (active.SchemaVersion != 2 || active.Current is null)
            throw new InvalidDataException("Unsupported active runtime state.");
        ValidateRuntime(active.Current.RuntimeDll, active.Current.RuntimeSha256);
        ValidateLoopbackHttp(active.Current.ListenUrl, "active listenUrl");
        ValidateLoopbackHttp(active.Current.HealthUrl, "active healthUrl");

        if (!string.Equals(active.Current.RuntimeSha256, authorization.currentRuntimeSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Current runtime SHA-256 changed after activation authorization.");
        if (string.Equals(active.Current.RuntimeSha256, manifest.runtimeSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Candidate runtime is already active.");
        if (active.Current.ProcessId <= 0 || active.Current.ProcessId == Environment.ProcessId)
            throw new InvalidOperationException("Active runtime PID is invalid for cutover.");

        await RequireCurrentHealthIdentityAsync(active.Current, token);

        using var process = Process.GetProcessById(active.Current.ProcessId);
        if (process.HasExited)
            throw new InvalidOperationException("Active runtime process has already exited.");
        if (!string.Equals(process.ProcessName, "dotnet", StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Active runtime process is not the fixed dotnet host.");

        logger.LogInformation("Authorized handoff {HandoffPlanId}: stopping active runtime pid={Pid} sha={CurrentSha} for candidate sha={CandidateSha}.",
            fileName, active.Current.ProcessId, active.Current.RuntimeSha256, manifest.runtimeSha256);

        process.Kill(entireProcessTree: true);
        using (var cts = CancellationTokenSource.CreateLinkedTokenSource(token))
        {
            cts.CancelAfter(TimeSpan.FromSeconds(10));
            await process.WaitForExitAsync(cts.Token);
        }

        File.Delete(authorizationPath);
        logger.LogInformation("Authorized handoff {HandoffPlanId}: active runtime exited; pending manifest remains for RuntimeSupervisorWorker activation.", fileName);
    }

    private async Task RequireCurrentHealthIdentityAsync(RuntimeSlot current, CancellationToken token)
    {
        using var response = await _http.GetAsync(RequireLoopbackHttp(current.HealthUrl, "active healthUrl"), token);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException("Current runtime health endpoint is not healthy at cutover authorization time.");
        var body = await response.Content.ReadAsStringAsync(token);
        using var doc = JsonDocument.Parse(body);
        if (!TryGetString(doc.RootElement, "runtimeSha256", out var runtimeSha) ||
            !string.Equals(runtimeSha, current.RuntimeSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Current runtime health identity does not match active-runtime.json.");
    }

    private static void ValidateRuntime(string runtimeDll, string expectedSha)
    {
        var full = Path.GetFullPath(runtimeDll);
        var releaseRoot = Path.GetFullPath(ReleaseRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var package = Path.GetDirectoryName(full)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            ?? throw new InvalidDataException("Runtime package directory is missing.");
        var parent = Path.GetDirectoryName(package)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!string.Equals(parent, releaseRoot, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Runtime must be one direct release under the fixed lifecycle release root.");
        if (!string.Equals(Path.GetFileName(full), "YowThi.DevelopmentAgent3.dll", StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Unexpected runtime DLL name.");
        if (!File.Exists(full)) throw new FileNotFoundException("Runtime DLL does not exist.", full);
        RejectReparse(releaseRoot); RejectReparse(package); RejectReparse(full);
        var actualSha = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(full)));
        if (!string.Equals(actualSha, expectedSha, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Runtime DLL SHA-256 mismatch.");
    }

    private static Uri RequireLoopbackHttp(string value, string name)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttp || !uri.IsLoopback)
            throw new InvalidDataException(name + " must be an absolute loopback HTTP URL.");
        return uri;
    }
    private static void ValidateLoopbackHttp(string value, string name) => _ = RequireLoopbackHttp(value, name);
    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Reparse points are not allowed: " + path);
    }
    private static bool TryGetString(JsonElement element, string name, out string? value)
    {
        foreach (var property in element.EnumerateObject())
        {
            if (!string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase)) continue;
            if (property.Value.ValueKind == JsonValueKind.String)
            {
                value = property.Value.GetString();
                return !string.IsNullOrWhiteSpace(value);
            }
        }
        value = null;
        return false;
    }

    private sealed record ActivationAuthorization(int schemaVersion, string? activationPlanId, string? handoffPlanId,
        string? pendingManifestSha256, string? currentRuntimeSha256, string? candidateRuntimeSha256, DateTimeOffset authorizedUtc);
    private sealed record HandoffManifest(int schemaVersion, string? planId, string? runtimeDll, string? runtimeSha256,
        string? listenUrl, string? healthUrl, DateTimeOffset stagedUtc);
    private sealed record RuntimeSlot(string RuntimeDll, string RuntimeSha256, string ListenUrl, string HealthUrl, int ProcessId);
    private sealed record ActiveState(int SchemaVersion, RuntimeSlot? Current, RuntimeSlot? Previous, DateTimeOffset UpdatedUtc);
}
