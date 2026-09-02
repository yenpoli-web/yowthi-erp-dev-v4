using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using ModelContextProtocol.Server;

namespace YowThi.DevelopmentAgent3.Processes;

[McpServerToolType]
public static partial class ProcessOwnershipReadbackTools
{
    private const int ProcessBasicInformation = 0;
    private const int ProcessCommandLineInformation = 60;
    private const int MaxDepth = 16;

    [McpServerTool(Name = "process_ownership_readback", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read one local process ownership chain by PID using native Windows process APIs. Returns the process and bounded parent chain with executable paths, start times, and redacted command-line previews plus SHA-256 fingerprints. It does not start, stop, signal, attach to, or modify any process. Secrets in common command-line option forms are redacted.")]
    public static object ProcessOwnershipReadback(int processId)
    {
        if (processId <= 0) throw new ArgumentOutOfRangeException(nameof(processId));

        var chain = new List<object>();
        var visited = new HashSet<int>();
        var current = processId;

        for (var depth = 0; depth < MaxDepth && current > 0 && visited.Add(current); depth++)
        {
            var snapshot = ReadSnapshot(current, depth);
            chain.Add(snapshot.Payload);
            if (snapshot.ParentProcessId is null || snapshot.ParentProcessId <= 0 || snapshot.ParentProcessId == current)
                break;
            current = snapshot.ParentProcessId.Value;
        }

        return new
        {
            requestedProcessId = processId,
            chain,
            truncated = chain.Count == MaxDepth && current > 0,
            capturedUtc = DateTimeOffset.UtcNow
        };
    }

    private static Snapshot ReadSnapshot(int processId, int depth)
    {
        string? name = null;
        string? path = null;
        DateTimeOffset? startTimeUtc = null;
        int? parentProcessId = null;
        string? commandLinePreview = null;
        string? commandLineSha256 = null;
        string? error = null;

        try
        {
            using var process = Process.GetProcessById(processId);
            name = Try(() => process.ProcessName);
            path = Try(() => process.MainModule?.FileName);
            startTimeUtc = TryDate(() => process.StartTime.ToUniversalTime());
            parentProcessId = TryReadParentProcessId(process.Handle);

            var commandLine = TryReadCommandLine(process.Handle);
            if (commandLine is not null)
            {
                commandLineSha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(commandLine)));
                commandLinePreview = Redact(commandLine);
                if (commandLinePreview.Length > 4096)
                    commandLinePreview = commandLinePreview[..4096] + "…";
            }
        }
        catch (Exception ex)
        {
            error = ex.GetType().Name + ": " + ex.Message;
        }

        return new Snapshot(parentProcessId, new
        {
            depth,
            processId,
            parentProcessId,
            name,
            path,
            startTimeUtc,
            commandLinePreview,
            commandLineSha256,
            error
        });
    }

    private static int? TryReadParentProcessId(IntPtr processHandle)
    {
        var size = Marshal.SizeOf<PROCESS_BASIC_INFORMATION>();
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            var status = NtQueryInformationProcess(processHandle, ProcessBasicInformation, buffer, size, out _);
            if (status < 0) return null;
            var info = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION>(buffer);
            var value = info.InheritedFromUniqueProcessId.ToInt64();
            return value is > 0 and <= int.MaxValue ? (int)value : null;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static string? TryReadCommandLine(IntPtr processHandle)
    {
        _ = NtQueryInformationProcess(processHandle, ProcessCommandLineInformation, IntPtr.Zero, 0, out var required);
        if (required <= 0 || required > 1024 * 1024) return null;

        var buffer = Marshal.AllocHGlobal(required);
        try
        {
            var status = NtQueryInformationProcess(processHandle, ProcessCommandLineInformation, buffer, required, out _);
            if (status < 0) return null;
            var value = Marshal.PtrToStructure<UNICODE_STRING>(buffer);
            if (value.Length == 0 || value.Buffer == IntPtr.Zero) return string.Empty;
            return Marshal.PtrToStringUni(value.Buffer, value.Length / 2);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static string Redact(string value)
    {
        return SecretOptionRegex().Replace(value, match =>
        {
            var prefix = match.Groups[1].Value;
            return prefix + "<redacted>";
        });
    }

    private static string? Try(Func<string?> action)
    {
        try { return action(); } catch { return null; }
    }

    private static DateTimeOffset? TryDate(Func<DateTime> action)
    {
        try { return new DateTimeOffset(action(), TimeSpan.Zero); } catch { return null; }
    }

    [GeneratedRegex(@"(?i)((?:--?|/)(?:api[-_]?key|token|access[-_]?token|secret|password|passwd|pwd)(?:\s+|=|:))(?:""[^""]*""|'[^']*'|\S+)")]
    private static partial Regex SecretOptionRegex();

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    private sealed record Snapshot(int? ParentProcessId, object Payload);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        IntPtr processInformation,
        int processInformationLength,
        out int returnLength);
}
