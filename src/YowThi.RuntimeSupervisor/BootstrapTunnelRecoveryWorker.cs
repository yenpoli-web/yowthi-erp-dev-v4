using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace YowThi.RuntimeSupervisor;

public sealed class BootstrapTunnelRecoveryWorker(ILogger<BootstrapTunnelRecoveryWorker> logger) : BackgroundService
{
    private const string BackendHealthUrl = "http://127.0.0.1:8787/health";
    private const string TunnelExe = @"C:\ProgramData\YowThi\TunnelClient\bin\tunnel-client.exe";
    private const string TunnelExeSha256 = "6649169733686805CA16CCCD91774594D0C017FD729C37AD4CE1CD18323D9AE8";
    private const string ProfileDirectory = @"C:\ProgramData\YowThi\TunnelClient\profiles";
    private const string ProfileName = "yowthi-erp-bootstrap-8787-r1";
    private const string ProfilePath = ProfileDirectory + @"\yowthi-erp-bootstrap-8787-r1.yaml";
    private const string ProfileSha256 = "303C57D927D1FAFB99D9F58A029F6DC4BF52EB430B04B571B9D339FE9FEDFAAC";
    private const string RuntimeKeyPath = @"C:\Users\YowThi\AppData\Local\YowThi\TunnelClient\secrets\runtime.key";
    private const int TunnelHealthPort = 8793;

    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(2) };
    private Process? _ownedTunnel;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (await IsBackendHealthyAsync(stoppingToken))
                    await EnsureTunnelAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Bootstrap tunnel recovery iteration failed.");
            }

            try { await Task.Delay(1000, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }

        StopOwnedTunnel();
        _http.Dispose();
    }

    private async Task<bool> IsBackendHealthyAsync(CancellationToken token)
    {
        try
        {
            using var response = await _http.GetAsync(BackendHealthUrl, token);
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    private async Task EnsureTunnelAsync(CancellationToken token)
    {
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
            throw new InvalidOperationException("Bootstrap tunnel failed boot/crash recovery readiness validation.");
        }

        logger.LogInformation("Recovered Bootstrap tunnel pid={Pid}.", _ownedTunnel.Id);
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
        catch
        {
            return false;
        }
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

    private static Process StartTunnel()
    {
        ValidateArtifacts();
        var runtimeKey = ReadRuntimeKey();
        try
        {
            var start = new ProcessStartInfo
            {
                FileName = TunnelExe,
                WorkingDirectory = Path.GetDirectoryName(TunnelExe)!,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            start.ArgumentList.Add("run");
            start.ArgumentList.Add("--profile");
            start.ArgumentList.Add(ProfileName);
            start.ArgumentList.Add("--profile-dir");
            start.ArgumentList.Add(ProfileDirectory);
            start.Environment["CONTROL_PLANE_API_KEY"] = runtimeKey;
            return Process.Start(start) ?? throw new InvalidOperationException("Failed to start Bootstrap tunnel.");
        }
        finally
        {
            runtimeKey = string.Empty;
        }
    }

    private static void ValidateArtifacts()
    {
        ValidateFixedFile(TunnelExe, TunnelExeSha256, "Tunnel executable");
        ValidateFixedFile(ProfilePath, ProfileSha256, "Bootstrap tunnel profile");

        var directory = Path.GetFullPath(ProfileDirectory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var parent = Path.GetFullPath(@"C:\ProgramData\YowThi\TunnelClient").TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var actualParent = Path.GetDirectoryName(directory)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!string.Equals(actualParent, parent, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Bootstrap tunnel profile directory is outside the fixed YowThi TunnelClient root.");
        RejectReparse(parent);
        RejectReparse(directory);
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
        var path = Path.GetFullPath(RuntimeKeyPath);
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

    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Fixed path may not be a reparse point: " + path);
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
}
