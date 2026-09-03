using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace YowThi.RuntimeSupervisor;

public sealed class RuntimeSupervisorWorker(ILogger<RuntimeSupervisorWorker> logger) : BackgroundService
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string ReleaseRoot = DevRoot + @"\acceptance\agent-lifecycle\releases";
    private const string PendingRoot = DevRoot + @"\.agent3-handoff\pending";
    private const string ActivatedRoot = DevRoot + @"\.agent3-handoff\activated";
    private const string FailedRoot = DevRoot + @"\.agent3-handoff\failed";
    private const string ActiveStatePath = DevRoot + @"\.agent3-handoff\active-runtime.json";
    private const string LegacyStatePath = DevRoot + @"\.agent3-handoff\runtime-state.json";
    private const string DotnetExe = @"C:\Program Files\dotnet\dotnet.exe";

    private const string TunnelExe = @"C:\ProgramData\YowThi\TunnelClient\bin\tunnel-client.exe";
    private const string TunnelExeSha256 = "6649169733686805CA16CCCD91774594D0C017FD729C37AD4CE1CD18323D9AE8";
    private const string TunnelProfileDirectory = @"C:\ProgramData\YowThi\TunnelClient\profiles";
    private const string TunnelProfilePath = TunnelProfileDirectory + @"\yowthi-erp-dev-v4.yaml";
    private const string TunnelProfileSha256 = "8B46DC3AF0DBE713CBEF8ABC2AE864AF780F8DC713CBF011ABC3405F6D0F911F";
    private const string TunnelRuntimeKeyPath = @"C:\Users\YowThi\AppData\Local\YowThi\TunnelClient\secrets\runtime.key";
    private const int TunnelHealthPort = 8792;

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true, WriteIndented = true };

    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(2) };
    private ActiveState? _active;
    private Process? _ownedRuntime;
    private Process? _ownedTunnel;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Directory.CreateDirectory(PendingRoot);
        Directory.CreateDirectory(ActivatedRoot);
        Directory.CreateDirectory(FailedRoot);

        _active = await LoadOrImportActiveStateAsync(stoppingToken);
        if (_active is not null)
        {
            await EnsureActiveRuntimeAsync(stoppingToken);
            await EnsureTunnelAsync(stoppingToken);
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var pending = Directory.EnumerateFiles(PendingRoot, "*.json", SearchOption.TopDirectoryOnly)
                    .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                    .FirstOrDefault();

                if (pending is not null)
                {
                    if (await ManifestEndpointIsHealthyAsync(pending, stoppingToken))
                    {
                        // Never consume a handoff while the current runtime still owns the target endpoint.
                        await Task.Delay(500, stoppingToken);
                        continue;
                    }

                    await ActivatePendingAsync(pending, stoppingToken);
                    continue;
                }

                if (_active is not null)
                {
                    if (!await IsHealthyAsync(_active.Current, stoppingToken))
                        await EnsureActiveRuntimeAsync(stoppingToken);

                    if (await IsHealthyAsync(_active.Current, stoppingToken))
                        await EnsureTunnelAsync(stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Runtime supervisor iteration failed.");
            }

            try { await Task.Delay(1000, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }

        StopOwnedTunnel();
        StopOwnedRuntime();
        _http.Dispose();
    }

    private async Task<ActiveState?> LoadOrImportActiveStateAsync(CancellationToken token)
    {
        if (File.Exists(ActiveStatePath))
        {
            var active = JsonSerializer.Deserialize<ActiveState>(await File.ReadAllTextAsync(ActiveStatePath, token), JsonOptions)
                ?? throw new InvalidDataException("Invalid active runtime state.");
            ValidateSlot(active.Current);
            if (active.Previous is not null) ValidateSlot(active.Previous);
            return active;
        }

        if (!File.Exists(LegacyStatePath)) return null;
        var legacy = JsonSerializer.Deserialize<LegacyState>(await File.ReadAllTextAsync(LegacyStatePath, token), JsonOptions);
        var imported = legacy?.candidateSlot ?? legacy?.currentSlot;
        if (imported is null) return null;

        var slot = new RuntimeSlot(imported.planId, imported.runtimeDll, imported.runtimeSha256,
            NormalizeUrl(imported.listenUrl), NormalizeUrl(imported.listenUrl) + "/health", imported.processId);
        ValidateSlot(slot);
        var state = new ActiveState(2, slot, null, DateTimeOffset.UtcNow);
        WriteActiveState(state);
        logger.LogInformation("Imported legacy active runtime {RuntimeDll}.", slot.RuntimeDll);
        return state;
    }

    private async Task EnsureActiveRuntimeAsync(CancellationToken token)
    {
        if (_active is null) return;
        ValidateSlot(_active.Current);
        if (await IsHealthyAsync(_active.Current, token)) return;

        if (_ownedRuntime is { HasExited: false })
        {
            try { _ownedRuntime.Kill(entireProcessTree: true); _ownedRuntime.WaitForExit(5000); } catch { }
            _ownedRuntime.Dispose();
            _ownedRuntime = null;
        }

        _ownedRuntime = StartRuntime(_active.Current);
        if (!await WaitHealthyAsync(_active.Current, _ownedRuntime, token))
        {
            try { if (!_ownedRuntime.HasExited) _ownedRuntime.Kill(entireProcessTree: true); } catch { }
            _ownedRuntime.Dispose();
            _ownedRuntime = null;
            throw new InvalidOperationException("Active runtime failed boot/crash recovery health validation.");
        }

        var current = _active.Current with { ProcessId = _ownedRuntime.Id };
        _active = _active with { Current = current, UpdatedUtc = DateTimeOffset.UtcNow };
        WriteActiveState(_active);
        logger.LogInformation("Recovered active runtime pid={Pid} sha={Sha}.", current.ProcessId, current.RuntimeSha256);
    }

    private async Task EnsureTunnelAsync(CancellationToken token)
    {
        if (_active is null || !await IsHealthyAsync(_active.Current, token))
            return;

        if (await IsTunnelReadyAsync(token))
        {
            if (_ownedTunnel is { HasExited: true })
            {
                _ownedTunnel.Dispose();
                _ownedTunnel = null;
            }
            return;
        }

        if (_ownedTunnel is { HasExited: false })
        {
            try
            {
                _ownedTunnel.Kill(entireProcessTree: true);
                _ownedTunnel.WaitForExit(5000);
            }
            catch { }
            _ownedTunnel.Dispose();
            _ownedTunnel = null;
        }
        else if (_ownedTunnel is not null)
        {
            _ownedTunnel.Dispose();
            _ownedTunnel = null;
        }

        _ownedTunnel = StartTunnel();
        if (!await WaitTunnelReadyAsync(_ownedTunnel, token))
        {
            try { if (!_ownedTunnel.HasExited) _ownedTunnel.Kill(entireProcessTree: true); } catch { }
            _ownedTunnel.Dispose();
            _ownedTunnel = null;
            throw new InvalidOperationException("V4 tunnel failed boot/crash recovery readiness validation.");
        }

        logger.LogInformation("Recovered V4 tunnel pid={Pid}.", _ownedTunnel.Id);
    }

    private async Task ActivatePendingAsync(string manifestPath, CancellationToken token)
    {
        Process? started = null;
        var previous = _active;
        try
        {
            var manifest = JsonSerializer.Deserialize<HandoffManifest>(await File.ReadAllTextAsync(manifestPath, token), JsonOptions)
                ?? throw new InvalidDataException("Invalid handoff manifest.");
            var slot = SlotFromManifest(manifest);
            ValidateSlot(slot);

            started = StartRuntime(slot);
            if (!await WaitHealthyAsync(slot, started, token))
                throw new InvalidOperationException("Candidate runtime failed health validation.");

            var activated = slot with { ProcessId = started.Id };
            _active = new ActiveState(2, activated, previous?.Current, DateTimeOffset.UtcNow);
            WriteActiveState(_active);
            _ownedRuntime = started;
            started = null;

            MoveManifest(manifestPath, ActivatedRoot, new
            {
                status = "activated",
                pid = activated.ProcessId,
                runtimeSha256 = activated.RuntimeSha256,
                activatedUtc = DateTimeOffset.UtcNow
            });

            await EnsureTunnelAsync(token);
        }
        catch (Exception ex)
        {
            try
            {
                if (started is { HasExited: false })
                {
                    started.Kill(entireProcessTree: true);
                    await started.WaitForExitAsync(token);
                }
            }
            catch { }
            started?.Dispose();

            try { MoveManifest(manifestPath, FailedRoot, new { status = "failed", error = ex.GetType().Name + ": " + ex.Message, failedUtc = DateTimeOffset.UtcNow }); }
            catch { }

            _active = previous;
            if (_active is not null && !await IsHealthyAsync(_active.Current, token))
            {
                try { await EnsureActiveRuntimeAsync(token); }
                catch (Exception recoveryEx) { logger.LogError(recoveryEx, "Rollback recovery failed."); }
            }
        }
    }

    private async Task<bool> ManifestEndpointIsHealthyAsync(string manifestPath, CancellationToken token)
    {
        try
        {
            var manifest = JsonSerializer.Deserialize<HandoffManifest>(await File.ReadAllTextAsync(manifestPath, token), JsonOptions);
            if (manifest?.healthUrl is null) return false;
            using var response = await _http.GetAsync(RequireLoopbackHttp(manifest.healthUrl, "healthUrl"), token);
            return response.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    private async Task<bool> IsHealthyAsync(RuntimeSlot slot, CancellationToken token)
    {
        try
        {
            using var response = await _http.GetAsync(RequireLoopbackHttp(slot.HealthUrl, "healthUrl"), token);
            if (!response.IsSuccessStatusCode) return false;
            var body = await response.Content.ReadAsStringAsync(token);
            if (string.IsNullOrWhiteSpace(body)) return true;
            try
            {
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("runtimeSha256", out var sha) && sha.ValueKind == JsonValueKind.String)
                    return string.Equals(sha.GetString(), slot.RuntimeSha256, StringComparison.OrdinalIgnoreCase);
            }
            catch (JsonException) { }
            return true;
        }
        catch { return false; }
    }

    private static async Task<bool> IsTunnelReadyAsync(CancellationToken token)
    {
        try
        {
            using var tcp = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(TimeSpan.FromSeconds(1));
            await tcp.ConnectAsync(IPAddress.Loopback, TunnelHealthPort, cts.Token);
            return tcp.Connected;
        }
        catch { return false; }
    }

    private async Task<bool> WaitHealthyAsync(RuntimeSlot slot, Process process, CancellationToken token)
    {
        for (var i = 0; i < 40; i++)
        {
            if (process.HasExited) return false;
            if (await IsHealthyAsync(slot, token)) return true;
            await Task.Delay(500, token);
        }
        return false;
    }

    private static async Task<bool> WaitTunnelReadyAsync(Process process, CancellationToken token)
    {
        for (var i = 0; i < 40; i++)
        {
            if (process.HasExited) return false;
            if (await IsTunnelReadyAsync(token)) return true;
            await Task.Delay(500, token);
        }
        return false;
    }

    private static Process StartRuntime(RuntimeSlot slot)
    {
        ValidateSlot(slot);
        var psi = new ProcessStartInfo
        {
            FileName = DotnetExe,
            WorkingDirectory = Path.GetDirectoryName(slot.RuntimeDll)!,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add(slot.RuntimeDll);
        psi.Environment["YOWTHI_AGENT3_URL"] = NormalizeUrl(slot.ListenUrl);
        return Process.Start(psi) ?? throw new InvalidOperationException("Failed to start runtime.");
    }

    private static Process StartTunnel()
    {
        ValidateTunnelArtifacts();
        var runtimeKey = ReadRuntimeKey();
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = TunnelExe,
                WorkingDirectory = Path.GetDirectoryName(TunnelExe)!,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.ArgumentList.Add("run");
            psi.ArgumentList.Add("--profile");
            psi.ArgumentList.Add("yowthi-erp-dev-v4");
            psi.ArgumentList.Add("--profile-dir");
            psi.ArgumentList.Add(TunnelProfileDirectory);
            psi.Environment["CONTROL_PLANE_API_KEY"] = runtimeKey;
            return Process.Start(psi) ?? throw new InvalidOperationException("Failed to start V4 tunnel.");
        }
        finally
        {
            runtimeKey = string.Empty;
        }
    }

    private static void ValidateTunnelArtifacts()
    {
        ValidateFixedFile(TunnelExe, TunnelExeSha256, "Tunnel executable");
        ValidateFixedFile(TunnelProfilePath, TunnelProfileSha256, "Tunnel profile");

        var profileDirectory = Path.GetFullPath(TunnelProfileDirectory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var profileParent = Path.GetFullPath(@"C:\ProgramData\YowThi\TunnelClient").TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var actualParent = Path.GetDirectoryName(profileDirectory)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!string.Equals(actualParent, profileParent, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Tunnel profile directory is outside the fixed YowThi TunnelClient root.");
        RejectReparse(profileParent);
        RejectReparse(profileDirectory);
    }

    private static void ValidateFixedFile(string path, string expectedSha256, string label)
    {
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
            throw new FileNotFoundException(label + " does not exist.", fullPath);
        if ((File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException(label + " may not be a reparse point.");
        using var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var actual = Convert.ToHexString(SHA256.HashData(stream));
        if (!string.Equals(actual, expectedSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(label + " SHA-256 mismatch.");
    }

    private static string ReadRuntimeKey()
    {
        var path = Path.GetFullPath(TunnelRuntimeKeyPath);
        if (!File.Exists(path))
            throw new FileNotFoundException("Tunnel runtime key file does not exist.", path);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Tunnel runtime key file may not be a reparse point.");

        var value = File.ReadAllText(path).Trim();
        if (!value.StartsWith("sk-", StringComparison.Ordinal) ||
            value.Length < 20 ||
            value.Length > 4096 ||
            value.Any(char.IsWhiteSpace))
            throw new InvalidDataException("Tunnel runtime key file is invalid.");
        return value;
    }

    private static RuntimeSlot SlotFromManifest(HandoffManifest manifest)
    {
        var runtimeDll = Path.GetFullPath(manifest.runtimeDll ?? throw new InvalidDataException("runtimeDll is required."));
        var listen = RequireLoopbackHttp(manifest.listenUrl, "listenUrl").ToString().TrimEnd('/');
        var health = RequireLoopbackHttp(manifest.healthUrl, "healthUrl").ToString().TrimEnd('/');
        return new RuntimeSlot(manifest.planId, runtimeDll,
            manifest.runtimeSha256 ?? throw new InvalidDataException("runtimeSha256 is required."), listen, health, 0);
    }

    private static void ValidateSlot(RuntimeSlot slot)
    {
        var runtimeDll = Path.GetFullPath(slot.RuntimeDll);
        var releaseRoot = Path.GetFullPath(ReleaseRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var packageDir = Path.GetDirectoryName(runtimeDll)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            ?? throw new InvalidDataException("Runtime package directory is missing.");
        var parent = Path.GetDirectoryName(packageDir)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!string.Equals(parent, releaseRoot, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Runtime must be one direct staged release under the fixed lifecycle release root.");
        if (!string.Equals(Path.GetFileName(runtimeDll), "YowThi.DevelopmentAgent3.dll", StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Unexpected runtime DLL name.");
        if (!File.Exists(runtimeDll)) throw new FileNotFoundException("Runtime DLL does not exist.", runtimeDll);
        RejectReparse(releaseRoot);
        RejectReparse(packageDir);
        if ((File.GetAttributes(runtimeDll) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Runtime DLL may not be a reparse point.");
        var actual = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(runtimeDll)));
        if (!string.Equals(actual, slot.RuntimeSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Runtime DLL SHA-256 mismatch.");
        _ = RequireLoopbackHttp(slot.ListenUrl, "listenUrl");
        _ = RequireLoopbackHttp(slot.HealthUrl, "healthUrl");
    }

    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Fixed path may not be a reparse point: " + path);
    }

    private static void WriteActiveState(ActiveState state)
    {
        ValidateSlot(state.Current);
        var temp = ActiveStatePath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(state, JsonOptions));
        File.Move(temp, ActiveStatePath, overwrite: true);
    }

    private static Uri RequireLoopbackHttp(string? value, string name)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttp ||
            !IPAddress.TryParse(uri.Host, out var ip) || !IPAddress.IsLoopback(ip))
            throw new InvalidDataException($"{name} must be an absolute loopback HTTP URL using an IP literal.");
        return uri;
    }

    private static string NormalizeUrl(string value) => value.TrimEnd('/');

    private static void MoveManifest(string source, string destinationRoot, object result)
    {
        Directory.CreateDirectory(destinationRoot);
        var destination = Path.Combine(destinationRoot, Path.GetFileName(source));
        var resultPath = source + ".result";
        File.WriteAllText(resultPath, JsonSerializer.Serialize(result, JsonOptions));
        File.Move(source, destination, overwrite: true);
        File.Move(resultPath, destination + ".result", overwrite: true);
    }

    private void StopOwnedTunnel()
    {
        try
        {
            if (_ownedTunnel is { HasExited: false })
            {
                _ownedTunnel.Kill(entireProcessTree: true);
                _ownedTunnel.WaitForExit(5000);
            }
        }
        catch { }
        _ownedTunnel?.Dispose();
        _ownedTunnel = null;
    }

    private void StopOwnedRuntime()
    {
        try
        {
            if (_ownedRuntime is { HasExited: false })
            {
                _ownedRuntime.Kill(entireProcessTree: true);
                _ownedRuntime.WaitForExit(5000);
            }
        }
        catch { }
        _ownedRuntime?.Dispose();
        _ownedRuntime = null;
    }

    private sealed record HandoffManifest(int schemaVersion, string? planId, string? runtimeDll, string? runtimeSha256, string? listenUrl, string? healthUrl, DateTimeOffset stagedUtc);
    private sealed record LegacySlot(string? planId, string runtimeDll, string runtimeSha256, string listenUrl, int processId);
    private sealed record LegacyState(int schemaVersion, LegacySlot? currentSlot, LegacySlot? previousSlot, LegacySlot? candidateSlot, DateTimeOffset? candidateActivatedUtc, DateTimeOffset? rollbackUntilUtc, bool cutoverConfirmed, DateTimeOffset updatedUtc);
    private sealed record RuntimeSlot(string? PlanId, string RuntimeDll, string RuntimeSha256, string ListenUrl, string HealthUrl, int ProcessId);
    private sealed record ActiveState(int SchemaVersion, RuntimeSlot Current, RuntimeSlot? Previous, DateTimeOffset UpdatedUtc);
}
