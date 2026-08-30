using System.ComponentModel;
using System.Diagnostics;
using ModelContextProtocol.Server;

namespace YowThi.DevelopmentAgent3.Inspection;

[McpServerToolType]
public static class InspectionTools
{
    [McpServerTool(Name="machine_metadata", ReadOnly=true, Destructive=false, OpenWorld=false)]
    [Description("Read metadata for one absolute local filesystem path using native .NET APIs. No shell command is generated or executed.")]
    public static MachinePathMetadata MachineMetadata(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("Path is required.", nameof(path));
        if (!Path.IsPathFullyQualified(path)) throw new ArgumentException("Absolute path is required.", nameof(path));
        var full = Path.GetFullPath(path);

        if (File.Exists(full))
        {
            var file = new FileInfo(full);
            return new MachinePathMetadata(true, full, "file", file.Length, file.CreationTimeUtc, file.LastWriteTimeUtc, file.LastAccessTimeUtc, file.Attributes.ToString());
        }

        if (Directory.Exists(full))
        {
            var directory = new DirectoryInfo(full);
            return new MachinePathMetadata(true, full, "directory", null, directory.CreationTimeUtc, directory.LastWriteTimeUtc, directory.LastAccessTimeUtc, directory.Attributes.ToString());
        }

        return new MachinePathMetadata(false, full, "missing", null, null, null, null, null);
    }

    [McpServerTool(Name="process_list", ReadOnly=true, Destructive=false, OpenWorld=false)]
    [Description("List local processes using the native .NET Process API. This is read-only and does not start, stop, or modify any process. No shell command is generated or executed.")]
    public static ProcessInfo[] ProcessList()
    {
        return Process.GetProcesses()
            .OrderBy(p => p.Id)
            .Select(ToInfo)
            .ToArray();
    }

    private static ProcessInfo ToInfo(Process process)
    {
        string? path = null;
        string? name = null;
        long? workingSet = null;
        double? cpuSeconds = null;
        DateTime? startTimeUtc = null;

        try { name = process.ProcessName; } catch { }
        try { path = process.MainModule?.FileName; } catch { }
        try { workingSet = process.WorkingSet64; } catch { }
        try { cpuSeconds = process.TotalProcessorTime.TotalSeconds; } catch { }
        try { startTimeUtc = process.StartTime.ToUniversalTime(); } catch { }

        return new ProcessInfo(process.Id, name, path, workingSet, cpuSeconds, startTimeUtc);
    }
}

public sealed record MachinePathMetadata(bool Exists, string FullName, string Kind, long? Bytes, DateTime? CreationTimeUtc, DateTime? LastWriteTimeUtc, DateTime? LastAccessTimeUtc, string? Attributes);
public sealed record ProcessInfo(int Id, string? ProcessName, string? Path, long? WorkingSetBytes, double? CpuSeconds, DateTime? StartTimeUtc);
