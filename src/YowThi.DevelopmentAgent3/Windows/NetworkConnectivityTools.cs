using System.ComponentModel;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Versioning;
using Microsoft.Win32;
using ModelContextProtocol.Server;

namespace YowThi.DevelopmentAgent3.Windows;

[McpServerToolType]
[SupportedOSPlatform("windows")]
public static class NetworkConnectivityTools
{
    private const int MinTimeoutMilliseconds = 250;
    private const int MaxTimeoutMilliseconds = 15000;

    [McpServerTool(Name = "network_ping", ReadOnly = true, Destructive = false, OpenWorld = true)]
    [Description("Probe one explicit hostname or IP literal with a single ICMP echo using the .NET Ping API. Timeout is bounded from 250 to 15000 ms. Caller-provided packet payloads, continuous ping, route changes, shell execution, PowerShell, cmd, and generic command execution are not supported.")]
    public static NetworkPingResult NetworkPing(string hostName, int timeoutMilliseconds = 3000)
    {
        var host = NormalizeHostName(hostName);
        var timeout = NormalizeTimeout(timeoutMilliseconds);
        var stopwatch = Stopwatch.StartNew();
        try
        {
            using var ping = new Ping();
            var reply = ping.Send(host, timeout);
            stopwatch.Stop();
            return new NetworkPingResult(
                host,
                reply.Status.ToString(),
                reply.Status == IPStatus.Success,
                reply.Address?.ToString(),
                reply.Status == IPStatus.Success ? reply.RoundtripTime : null,
                stopwatch.ElapsedMilliseconds,
                null);
        }
        catch (PingException ex)
        {
            stopwatch.Stop();
            return new NetworkPingResult(host, "PingError", false, null, null, stopwatch.ElapsedMilliseconds, ex.InnerException?.GetType().Name ?? ex.GetType().Name);
        }
    }

    [McpServerTool(Name = "tcp_connect_probe", ReadOnly = true, Destructive = false, OpenWorld = true)]
    [Description("Probe whether one explicit hostname or IP literal accepts a TCP connection on one explicit port using the .NET TcpClient API. The connection is closed immediately and no application payload is sent. Port is restricted to 1-65535 and timeout to 250-15000 ms. No shell, PowerShell, cmd, telnet, curl, arbitrary protocol payload, or generic command executor is used.")]
    public static TcpConnectProbeResult TcpConnectProbe(string hostName, int port, int timeoutMilliseconds = 3000)
    {
        var host = NormalizeHostName(hostName);
        if (port is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(port), "port must be between 1 and 65535.");
        var timeout = NormalizeTimeout(timeoutMilliseconds);

        var stopwatch = Stopwatch.StartNew();
        using var client = new TcpClient();
        using var cancellation = new CancellationTokenSource(timeout);
        try
        {
            client.ConnectAsync(host, port, cancellation.Token).AsTask().GetAwaiter().GetResult();
            stopwatch.Stop();
            return new TcpConnectProbeResult(
                host,
                port,
                client.Connected,
                client.Client.LocalEndPoint?.ToString(),
                client.Client.RemoteEndPoint?.ToString(),
                stopwatch.ElapsedMilliseconds,
                null);
        }
        catch (OperationCanceledException)
        {
            stopwatch.Stop();
            return new TcpConnectProbeResult(host, port, false, null, null, stopwatch.ElapsedMilliseconds, "Timeout");
        }
        catch (SocketException ex)
        {
            stopwatch.Stop();
            return new TcpConnectProbeResult(host, port, false, null, null, stopwatch.ElapsedMilliseconds, ex.SocketErrorCode.ToString());
        }
    }

    [McpServerTool(Name = "firewall_profile_status", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read Windows Firewall profile configuration for Domain, Private/Standard, and Public profiles from fixed local-policy and Group Policy registry paths using the native .NET Registry API. Group Policy values are reported separately and resolved ahead of local values when present. This is read-only and does not enumerate or modify firewall rules, profiles, services, registry values, ports, or network configuration. No PowerShell, cmd, netsh, WMI command execution, or generic command executor is used.")]
    public static IReadOnlyList<FirewallProfileStatusItem> FirewallProfileStatus()
    {
        return new[]
        {
            ReadFirewallProfile("Domain", "DomainProfile"),
            ReadFirewallProfile("Private", "StandardProfile"),
            ReadFirewallProfile("Public", "PublicProfile")
        };
    }

    private static FirewallProfileStatusItem ReadFirewallProfile(string profileName, string registryProfileName)
    {
        var localPath = $@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{registryProfileName}";
        var policyPath = $@"SOFTWARE\Policies\Microsoft\WindowsFirewall\{registryProfileName}";
        var local = ReadFirewallSettings(localPath);
        var policy = ReadFirewallSettings(policyPath);
        var resolved = new FirewallProfileSettings(
            policy.Enabled ?? local.Enabled,
            policy.DefaultInboundAction ?? local.DefaultInboundAction,
            policy.DefaultOutboundAction ?? local.DefaultOutboundAction,
            policy.DisableNotifications ?? local.DisableNotifications);
        return new FirewallProfileStatusItem(profileName, local, policy, resolved, HasAnySetting(policy));
    }

    private static FirewallProfileSettings ReadFirewallSettings(string keyPath)
    {
        using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
        if (key is null)
            return new FirewallProfileSettings(null, null, null, null);

        return new FirewallProfileSettings(
            ReadBooleanDword(key, "EnableFirewall"),
            ReadActionDword(key, "DefaultInboundAction"),
            ReadActionDword(key, "DefaultOutboundAction"),
            ReadBooleanDword(key, "DisableNotifications"));
    }

    private static bool? ReadBooleanDword(RegistryKey key, string name)
    {
        var value = ReadDword(key, name);
        return value switch { 0 => false, 1 => true, _ => null };
    }

    private static string? ReadActionDword(RegistryKey key, string name)
    {
        var value = ReadDword(key, name);
        return value switch { 0 => "Block", 1 => "Allow", _ => null };
    }

    private static int? ReadDword(RegistryKey key, string name)
    {
        var value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (value is null)
            return null;
        try { return Convert.ToInt32(value); }
        catch { return null; }
    }

    private static bool HasAnySetting(FirewallProfileSettings settings) =>
        settings.Enabled is not null ||
        settings.DefaultInboundAction is not null ||
        settings.DefaultOutboundAction is not null ||
        settings.DisableNotifications is not null;

    private static string NormalizeHostName(string hostName)
    {
        var value = (hostName ?? string.Empty).Trim();
        if (value.Length == 0)
            throw new ArgumentException("hostName is required.", nameof(hostName));
        if (value.Length > 253)
            throw new ArgumentOutOfRangeException(nameof(hostName), "hostName must be 253 characters or fewer.");
        if (value.Any(char.IsControl))
            throw new ArgumentException("hostName must not contain control characters.", nameof(hostName));
        return value;
    }

    private static int NormalizeTimeout(int timeoutMilliseconds)
    {
        if (timeoutMilliseconds < MinTimeoutMilliseconds || timeoutMilliseconds > MaxTimeoutMilliseconds)
            throw new ArgumentOutOfRangeException(nameof(timeoutMilliseconds), $"timeoutMilliseconds must be between {MinTimeoutMilliseconds} and {MaxTimeoutMilliseconds}.");
        return timeoutMilliseconds;
    }
}

public sealed record NetworkPingResult(
    string HostName,
    string Status,
    bool Success,
    string? Address,
    long? RoundtripTimeMilliseconds,
    long ElapsedMilliseconds,
    string? ErrorType);

public sealed record TcpConnectProbeResult(
    string HostName,
    int Port,
    bool Success,
    string? LocalEndPoint,
    string? RemoteEndPoint,
    long ElapsedMilliseconds,
    string? ErrorType);

public sealed record FirewallProfileStatusItem(
    string Profile,
    FirewallProfileSettings LocalPolicy,
    FirewallProfileSettings GroupPolicy,
    FirewallProfileSettings ResolvedSettings,
    bool GroupPolicyOverridePresent);

public sealed record FirewallProfileSettings(
    bool? Enabled,
    string? DefaultInboundAction,
    string? DefaultOutboundAction,
    bool? DisableNotifications);