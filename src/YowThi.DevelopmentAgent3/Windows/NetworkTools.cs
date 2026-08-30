using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using ModelContextProtocol.Server;

namespace YowThi.DevelopmentAgent3.Windows;

[McpServerToolType]
public sealed class NetworkTools
{
    private const int AF_INET = 2;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;
    private const int TCP_TABLE_OWNER_PID_LISTENER = 3;

    [McpServerTool(Name = "tcp_listener_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List local IPv4 TCP listening endpoints with owning PID and local process metadata using the native Windows IP Helper API plus the .NET Process API. This is read-only and does not open, close, start, stop, or modify any socket or process. No PowerShell, cmd, netstat, WMI command execution, or generic command executor is used.")]
    public static IReadOnlyList<TcpListenerItem> TcpListenerList()
    {
        var size = 0;
        var first = GetExtendedTcpTable(IntPtr.Zero, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
        if (first != ERROR_INSUFFICIENT_BUFFER || size <= 0)
            throw new Win32Exception(first, "Unable to determine TCP listener table size.");

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            var resultCode = GetExtendedTcpTable(buffer, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
            if (resultCode != 0)
                throw new Win32Exception(resultCode, "Unable to read TCP listener table.");

            var count = Marshal.ReadInt32(buffer);
            var rowPtr = IntPtr.Add(buffer, sizeof(int));
            var rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            var result = new List<TcpListenerItem>(count);

            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(IntPtr.Add(rowPtr, i * rowSize));
                var address = new IPAddress(row.localAddr).ToString();
                var port = DecodePort(row.localPort);
                var pid = checked((int)row.owningPid);
                var (name, path, startTimeUtc) = ReadProcessMetadata(pid);
                result.Add(new TcpListenerItem(address, port, pid, name, path, startTimeUtc));
            }

            return result
                .OrderBy(x => x.Port)
                .ThenBy(x => x.LocalAddress, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.ProcessId)
                .ToArray();
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static int DecodePort(uint rawPort)
    {
        var bytes = BitConverter.GetBytes(rawPort);
        return (bytes[0] << 8) | bytes[1];
    }

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
}

public sealed record TcpListenerItem(
    string LocalAddress,
    int Port,
    int ProcessId,
    string ProcessName,
    string? ProcessPath,
    string? StartTimeUtc);