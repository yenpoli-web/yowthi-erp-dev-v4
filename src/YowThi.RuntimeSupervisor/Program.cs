using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;

const string queueRoot = @"C:\Dev\YowThi-ERP-Dev-v4\.agent3-handoff\pending";
const string activatedRoot = @"C:\Dev\YowThi-ERP-Dev-v4\.agent3-handoff\activated";
const string failedRoot = @"C:\Dev\YowThi-ERP-Dev-v4\.agent3-handoff\failed";
const string statePath = @"C:\Dev\YowThi-ERP-Dev-v4\.agent3-handoff\runtime-state.json";

Directory.CreateDirectory(queueRoot);
Directory.CreateDirectory(activatedRoot);
Directory.CreateDirectory(failedRoot);

using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };

while (true)
{
    foreach (var manifestPath in Directory.EnumerateFiles(queueRoot, "*.json", SearchOption.TopDirectoryOnly))
    {
        Process? started = null;
        try
        {
            var manifest = JsonSerializer.Deserialize<HandoffManifest>(await File.ReadAllTextAsync(manifestPath), new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                ?? throw new InvalidDataException("Invalid handoff manifest.");

            var runtimeDll = Path.GetFullPath(manifest.runtimeDll ?? throw new InvalidDataException("runtimeDll is required."));
            if (!File.Exists(runtimeDll)) throw new FileNotFoundException("Runtime DLL does not exist.", runtimeDll);

            var actualHash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(runtimeDll)));
            if (!string.Equals(actualHash, manifest.runtimeSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Runtime DLL SHA-256 mismatch.");

            var listenUri = RequireLoopbackHttp(manifest.listenUrl, "listenUrl");
            var healthUri = RequireLoopbackHttp(manifest.healthUrl, "healthUrl");

            var psi = new ProcessStartInfo
            {
                FileName = @"C:\Program Files\dotnet\dotnet.exe",
                Arguments = $"\"{runtimeDll}\"",
                WorkingDirectory = Path.GetDirectoryName(runtimeDll)!,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.Environment["YOWTHI_AGENT3_URL"] = listenUri.ToString().TrimEnd('/');

            started = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start staged runtime.");

            var healthy = false;
            for (var i = 0; i < 20; i++)
            {
                if (started.HasExited) break;
                try
                {
                    using var response = await http.GetAsync(healthUri);
                    if (response.IsSuccessStatusCode) { healthy = true; break; }
                }
                catch { }
                await Task.Delay(500);
            }

            if (!healthy) throw new InvalidOperationException("New runtime failed health validation.");

            UpdateRuntimeState(statePath, manifest, runtimeDll, actualHash, listenUri, started.Id);
            MoveManifest(manifestPath, activatedRoot, new { status = "activated", pid = started.Id, activatedUtc = DateTimeOffset.UtcNow });
        }
        catch (Exception ex)
        {
            try
            {
                if (started is { HasExited: false })
                {
                    started.Kill(entireProcessTree: true);
                    await started.WaitForExitAsync();
                }
            }
            catch { }

            try { MoveManifest(manifestPath, failedRoot, new { status = "failed", error = ex.Message, failedUtc = DateTimeOffset.UtcNow }); }
            catch { }
        }
    }

    await Task.Delay(1000);
}

static Uri RequireLoopbackHttp(string? value, string name)
{
    if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
        (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) ||
        !IPAddress.TryParse(uri.Host, out var ip) || !IPAddress.IsLoopback(ip))
        throw new InvalidDataException($"{name} must be an absolute loopback HTTP(S) URL using an IP literal.");
    return uri;
}

static void UpdateRuntimeState(string path, HandoffManifest manifest, string runtimeDll, string runtimeSha256, Uri listenUri, int processId)
{
    RuntimeState? existing = null;
    if (File.Exists(path))
    {
        try { existing = JsonSerializer.Deserialize<RuntimeState>(File.ReadAllText(path), new JsonSerializerOptions { PropertyNameCaseInsensitive = true }); }
        catch { }
    }

    var now = DateTimeOffset.UtcNow;
    var state = new RuntimeState(
        schemaVersion: 1,
        currentSlot: existing?.currentSlot,
        previousSlot: existing?.previousSlot,
        candidateSlot: new RuntimeSlot(manifest.planId, runtimeDll, runtimeSha256, listenUri.ToString().TrimEnd('/'), processId),
        candidateActivatedUtc: now,
        rollbackUntilUtc: now.AddMinutes(15),
        cutoverConfirmed: false,
        updatedUtc: now);

    var json = JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true });
    var tempPath = path + ".tmp";
    File.WriteAllText(tempPath, json);
    File.Move(tempPath, path, overwrite: true);
}

static void MoveManifest(string source, string destinationRoot, object result)
{
    Directory.CreateDirectory(destinationRoot);
    var destination = Path.Combine(destinationRoot, Path.GetFileName(source));
    var json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
    File.WriteAllText(source + ".result", json);
    File.Move(source, destination, overwrite: true);
    File.Move(source + ".result", destination + ".result", overwrite: true);
}

sealed record HandoffManifest(int schemaVersion, string? planId, string? runtimeDll, string? runtimeSha256, string? listenUrl, string? healthUrl, DateTimeOffset stagedUtc);
sealed record RuntimeSlot(string? planId, string runtimeDll, string runtimeSha256, string listenUrl, int processId);
sealed record RuntimeState(int schemaVersion, RuntimeSlot? currentSlot, RuntimeSlot? previousSlot, RuntimeSlot? candidateSlot, DateTimeOffset? candidateActivatedUtc, DateTimeOffset? rollbackUntilUtc, bool cutoverConfirmed, DateTimeOffset updatedUtc);
