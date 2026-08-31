using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Server;

namespace YowThi.DevelopmentAgent3.Windows;

[McpServerToolType]
public sealed class NetworkTools
{
    private const int AF_INET = 2;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;
    private const int TCP_TABLE_OWNER_PID_LISTENER = 3;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;
    private const string TailscaleExe = @"C:\Program Files\Tailscale\tailscale.exe";
    private static readonly TimeSpan TailscaleTimeout = TimeSpan.FromSeconds(15);

    [McpServerTool(Name = "network_interface_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List local network interfaces and their operational state, interface type, speed, DNS servers, gateways, and unicast addresses using the .NET NetworkInformation API. This is read-only and does not enable, disable, reconfigure, renew, release, or modify any interface. No PowerShell, cmd, netsh, WMI command execution, or generic command executor is used.")]
    public static IReadOnlyList<NetworkInterfaceItem> NetworkInterfaceList()
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Select(ReadNetworkInterface)
            .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.Id, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    [McpServerTool(Name = "tcp_listener_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List local IPv4 TCP listening endpoints with owning PID and local process metadata using the native Windows IP Helper API plus the .NET Process API. This is read-only and does not open, close, start, stop, or modify any socket or process. No PowerShell, cmd, netstat, WMI command execution, or generic command executor is used.")]
    public static IReadOnlyList<TcpListenerItem> TcpListenerList()
    {
        var rows = ReadTcpRows(TCP_TABLE_OWNER_PID_LISTENER);
        return rows
            .Select(row =>
            {
                var pid = checked((int)row.owningPid);
                var (name, path, startTimeUtc) = ReadProcessMetadata(pid);
                return new TcpListenerItem(
                    new IPAddress(row.localAddr).ToString(),
                    DecodePort(row.localPort),
                    pid,
                    name,
                    path,
                    startTimeUtc);
            })
            .OrderBy(x => x.Port)
            .ThenBy(x => x.LocalAddress, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.ProcessId)
            .ToArray();
    }

    [McpServerTool(Name = "tcp_connection_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List local IPv4 TCP connection rows excluding listeners, including state, local and remote endpoints, owning PID, and local process metadata, using the native Windows IP Helper API plus the .NET Process API. This is read-only and does not open, close, start, stop, or modify any socket or process. No PowerShell, cmd, netstat, WMI command execution, or generic command executor is used.")]
    public static IReadOnlyList<TcpConnectionItem> TcpConnectionList()
    {
        var rows = ReadTcpRows(TCP_TABLE_OWNER_PID_ALL);
        return rows
            .Where(row => row.state != 2)
            .Select(row =>
            {
                var pid = checked((int)row.owningPid);
                var (name, path, startTimeUtc) = ReadProcessMetadata(pid);
                return new TcpConnectionItem(
                    TcpStateName(row.state),
                    new IPAddress(row.localAddr).ToString(),
                    DecodePort(row.localPort),
                    new IPAddress(row.remoteAddr).ToString(),
                    DecodePort(row.remotePort),
                    pid,
                    name,
                    path,
                    startTimeUtc);
            })
            .OrderBy(x => x.LocalPort)
            .ThenBy(x => x.RemoteAddress, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.RemotePort)
            .ThenBy(x => x.ProcessId)
            .ToArray();
    }

    [McpServerTool(Name = "udp_listener_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List local IPv4 UDP endpoints with owning PID and local process metadata using the native Windows IP Helper API plus the .NET Process API. This is read-only and does not open, close, start, stop, or modify any socket or process. No PowerShell, cmd, netstat, WMI command execution, or generic command executor is used.")]
    public static IReadOnlyList<UdpListenerItem> UdpListenerList()
    {
        var rows = ReadUdpRows();
        return rows
            .Select(row =>
            {
                var pid = checked((int)row.owningPid);
                var (name, path, startTimeUtc) = ReadProcessMetadata(pid);
                return new UdpListenerItem(
                    new IPAddress(row.localAddr).ToString(),
                    DecodePort(row.localPort),
                    pid,
                    name,
                    path,
                    startTimeUtc);
            })
            .OrderBy(x => x.Port)
            .ThenBy(x => x.LocalAddress, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.ProcessId)
            .ToArray();
    }

    [McpServerTool(Name = "dns_resolve", ReadOnly = true, Destructive = false, OpenWorld = true)]
    [Description("Resolve one explicit hostname or IP literal through the .NET DNS API and return distinct resolved addresses. This may issue normal DNS queries but does not send application payloads, alter DNS settings, flush caches, or modify network configuration. No nslookup, PowerShell, cmd, or generic command executor is used.")]
    public static IReadOnlyList<DnsResolutionItem> DnsResolve(string hostName)
    {
        var normalized = NormalizeHostName(hostName);
        return Dns.GetHostAddresses(normalized)
            .Select(address => new DnsResolutionItem(address.AddressFamily.ToString(), address.ToString()))
            .Distinct()
            .OrderBy(x => x.AddressFamily, StringComparer.Ordinal)
            .ThenBy(x => x.Address, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    [McpServerTool(Name = "tailscale_status", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read local Tailscale status using only the fixed Tailscale CLI path and fixed 'status --json' arguments. Caller-provided arguments, login/logout, up/down, serve/funnel changes, SSH changes, shell execution, PowerShell, cmd, and generic command execution are not supported.")]
    public static object TailscaleStatus()
    {
        if (!File.Exists(TailscaleExe))
        {
            return new
            {
                tailscaleExe = TailscaleExe,
                tailscaleExeExists = false,
                exitCode = (int?)null,
                status = (object?)null,
                error = "Tailscale CLI was not found at the fixed path.",
                checkedUtc = DateTimeOffset.UtcNow
            };
        }

        var start = new ProcessStartInfo
        {
            FileName = TailscaleExe,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            CreateNoWindow = true
        };
        start.ArgumentList.Add("status");
        start.ArgumentList.Add("--json");

        using var process = Process.Start(start) ?? throw new InvalidOperationException("Unable to start the fixed Tailscale CLI process.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit((int)TailscaleTimeout.TotalMilliseconds))
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"Tailscale status query exceeded {TailscaleTimeout.TotalSeconds:0} seconds.");
        }

        Task.WaitAll(stdoutTask, stderrTask);
        var stdout = stdoutTask.Result.Trim();
        var stderr = stderrTask.Result.Trim();
        object? parsed = null;
        if (stdout.Length > 0)
        {
            try
            {
                using var document = JsonDocument.Parse(stdout);
                parsed = document.RootElement.Clone();
            }
            catch (JsonException)
            {
                parsed = stdout;
            }
        }

        return new
        {
            tailscaleExe = TailscaleExe,
            tailscaleExeExists = true,
            exitCode = process.ExitCode,
            status = parsed,
            error = stderr.Length == 0 ? null : stderr,
            checkedUtc = DateTimeOffset.UtcNow
        };
    }

    private static NetworkInterfaceItem ReadNetworkInterface(NetworkInterface networkInterface)
    {
        IPInterfaceProperties? properties = null;
        try { properties = networkInterface.GetIPProperties(); } catch { }

        var dnsServers = properties?.DnsAddresses
            .Select(address => address.ToString())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(address => address, StringComparer.OrdinalIgnoreCase)
            .ToArray() ?? Array.Empty<string>();

        var gateways = properties?.GatewayAddresses
            .Select(item => item.Address.ToString())
            .Where(address => address.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(address => address, StringComparer.OrdinalIgnoreCase)
            .ToArray() ?? Array.Empty<string>();

        var unicastAddresses = properties?.UnicastAddresses
            .Select(item => new NetworkUnicastAddressItem(
                item.Address.AddressFamily.ToString(),
                item.Address.ToString(),
                item.IPv4Mask?.ToString(),
                item.PrefixLength))
            .OrderBy(item => item.AddressFamily, StringComparer.Ordinal)
            .ThenBy(item => item.Address, StringComparer.OrdinalIgnoreCase)
            .ToArray() ?? Array.Empty<NetworkUnicastAddressItem>();

        return new NetworkInterfaceItem(
            networkInterface.Id,
            networkInterface.Name,
            networkInterface.Description,
            networkInterface.NetworkInterfaceType.ToString(),
            networkInterface.OperationalStatus.ToString(),
            networkInterface.Speed,
            networkInterface.Supports(NetworkInterfaceComponent.IPv4),
            networkInterface.Supports(NetworkInterfaceComponent.IPv6),
            properties?.DnsSuffix,
            dnsServers,
            gateways,
            unicastAddresses);
    }

    private static MIB_TCPROW_OWNER_PID[] ReadTcpRows(int tableClass)
    {
        var size = 0;
        var first = GetExtendedTcpTable(IntPtr.Zero, ref size, true, AF_INET, tableClass, 0);
        if (first != ERROR_INSUFFICIENT_BUFFER || size <= 0)
            throw new Win32Exception(first, "Unable to determine TCP table size.");

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            var resultCode = GetExtendedTcpTable(buffer, ref size, true, AF_INET, tableClass, 0);
            if (resultCode != 0)
                throw new Win32Exception(resultCode, "Unable to read TCP table.");

            var count = Marshal.ReadInt32(buffer);
            var rowPtr = IntPtr.Add(buffer, sizeof(int));
            var rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            var result = new MIB_TCPROW_OWNER_PID[count];
            for (var i = 0; i < count; i++)
                result[i] = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(IntPtr.Add(rowPtr, i * rowSize));
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static MIB_UDPROW_OWNER_PID[] ReadUdpRows()
    {
        var size = 0;
        var first = GetExtendedUdpTable(IntPtr.Zero, ref size, true, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (first != ERROR_INSUFFICIENT_BUFFER || size <= 0)
            throw new Win32Exception(first, "Unable to determine UDP table size.");

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            var resultCode = GetExtendedUdpTable(buffer, ref size, true, AF_INET, UDP_TABLE_OWNER_PID, 0);
            if (resultCode != 0)
                throw new Win32Exception(resultCode, "Unable to read UDP table.");

            var count = Marshal.ReadInt32(buffer);
            var rowPtr = IntPtr.Add(buffer, sizeof(int));
            var rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();
            var result = new MIB_UDPROW_OWNER_PID[count];
            for (var i = 0; i < count; i++)
                result[i] = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(IntPtr.Add(rowPtr, i * rowSize));
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

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

    private static int DecodePort(uint rawPort)
    {
        var bytes = BitConverter.GetBytes(rawPort);
        return (bytes[0] << 8) | bytes[1];
    }

    private static string TcpStateName(uint state) => state switch
    {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RECEIVED",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT_1",
        7 => "FIN_WAIT_2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => $"UNKNOWN_{state}"
    };

    private static (string ProcessName, string? ProcessPath, string? StartTimeUtc) ReadProcessMetadata(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            string? path = null;
            string? startTimeUtc = null;
            try { path = process.MainModule?.FileName; } catch { }
            try { startTimeUtc = process.StartTime.ToUniversalTime().ToString("O"); } catch { }
            return (process.ProcessName, path, startTimeUtc);
        }
        catch
        {
            return (string.Empty, null, null);
        }
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int dwOutBufLen,
        [MarshalAs(UnmanagedType.Bool)] bool sort,
        int ipVersion,
        int tableClass,
        uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref int dwOutBufLen,
        [MarshalAs(UnmanagedType.Bool)] bool sort,
        int ipVersion,
        int tableClass,
        uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint localAddr;
        public uint localPort;
        public uint owningPid;
    }
}

public sealed record NetworkInterfaceItem(
    string Id,
    string Name,
    string Description,
    string InterfaceType,
    string OperationalStatus,
    long SpeedBitsPerSecond,
    bool SupportsIPv4,
    bool SupportsIPv6,
    string? DnsSuffix,
    IReadOnlyList<string> DnsServers,
    IReadOnlyList<string> Gateways,
    IReadOnlyList<NetworkUnicastAddressItem> UnicastAddresses);

public sealed record NetworkUnicastAddressItem(
    string AddressFamily,
    string Address,
    string? IPv4Mask,
    int PrefixLength);

public sealed record TcpListenerItem(
    string LocalAddress,
    int Port,
    int ProcessId,
    string ProcessName,
    string? ProcessPath,
    string? StartTimeUtc);

public sealed record TcpConnectionItem(
    string State,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    int ProcessId,
    string ProcessName,
    string? ProcessPath,
    string? StartTimeUtc);

public sealed record UdpListenerItem(
    string LocalAddress,
    int Port,
    int ProcessId,
    string ProcessName,
    string? ProcessPath,
    string? StartTimeUtc);

public sealed record DnsResolutionItem(
    string AddressFamily,
    string Address);