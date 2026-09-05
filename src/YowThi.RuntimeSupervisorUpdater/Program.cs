using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace YowThi.RuntimeSupervisorUpdater;

internal static class Program
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string ServiceName = "YowThiV4RuntimeSupervisor";
    private const string SupervisorRoot = DevRoot + @"\runtime-supervisor";
    private const string CurrentDirectory = SupervisorRoot + @"\current";
    private const string RollbackRoot = SupervisorRoot + @"\rollback";
    private const string PendingRoot = SupervisorRoot + @"\updates\pending";
    private const string CompletedRoot = SupervisorRoot + @"\updates\completed";
    private const string FailedRoot = SupervisorRoot + @"\updates\failed";
    private const string StagingRoot = DevRoot + @"\staging";
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true, WriteIndented = true };

    public static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows() || args.Length != 1) return 90;
        string? requestPath = null, updateId = null, backupDirectory = null, nextDirectory = null;
        var oldMoved = false;
        var newMoved = false;
        try
        {
            Directory.CreateDirectory(PendingRoot);
            Directory.CreateDirectory(CompletedRoot);
            Directory.CreateDirectory(FailedRoot);
            Directory.CreateDirectory(RollbackRoot);

            requestPath = Path.GetFullPath(args[0]);
            RequireDirectFileChild(requestPath, PendingRoot);
            RejectReparse(requestPath);
            updateId = Path.GetFileNameWithoutExtension(requestPath);
            if (!Guid.TryParseExact(updateId, "N", out _)) throw new InvalidDataException("Update request ID is invalid.");

            var request = JsonSerializer.Deserialize<UpdateRequest>(File.ReadAllText(requestPath), JsonOptions)
                ?? throw new InvalidDataException("Invalid supervisor update request.");
            if (request.SchemaVersion != 1 || !string.Equals(request.UpdateId, updateId, StringComparison.Ordinal))
                throw new InvalidDataException("Update request identity mismatch.");
            if (!string.Equals(request.ServiceName, ServiceName, StringComparison.Ordinal) ||
                !string.Equals(Path.GetFullPath(request.CurrentDirectory), Path.GetFullPath(CurrentDirectory), StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Fixed supervisor identity mismatch.");

            var candidateDirectory = Path.GetFullPath(request.CandidateDirectory);
            RequireDirectDirectoryChild(candidateDirectory, StagingRoot);
            RejectReparseTree(candidateDirectory);
            RejectReparseTree(CurrentDirectory);

            var currentManifest = ComputeManifestSha256(CurrentDirectory);
            var candidateManifest = ComputeManifestSha256(candidateDirectory);
            if (!EqualsSha(currentManifest, request.CurrentManifestSha256) || !EqualsSha(candidateManifest, request.CandidateManifestSha256))
                throw new InvalidOperationException("Current/candidate package manifest changed after request creation.");

            var currentExe = Path.Combine(CurrentDirectory, "YowThi.RuntimeSupervisor.exe");
            var candidateExe = Path.Combine(candidateDirectory, "YowThi.RuntimeSupervisor.exe");
            if (!File.Exists(currentExe) || !File.Exists(candidateExe)) throw new FileNotFoundException("Supervisor executable missing.");
            if (!EqualsSha(FileSha256(currentExe), request.CurrentExeSha256) || !EqualsSha(FileSha256(candidateExe), request.CandidateExeSha256))
                throw new InvalidOperationException("Supervisor executable identity mismatch.");

            backupDirectory = Path.Combine(RollbackRoot, updateId);
            nextDirectory = Path.Combine(SupervisorRoot, ".next-" + updateId);
            if (Directory.Exists(backupDirectory) || Directory.Exists(nextDirectory)) throw new IOException("Rollback/temp destination exists.");

            CopyTree(candidateDirectory, nextDirectory);
            if (!EqualsSha(ComputeManifestSha256(nextDirectory), candidateManifest)) throw new InvalidOperationException("Candidate copy verification failed.");

            using var service = ServiceHandle.Open(ServiceName);
            service.StopAndWait(TimeSpan.FromSeconds(30));
            Directory.Move(CurrentDirectory, backupDirectory);
            oldMoved = true;
            Directory.Move(nextDirectory, CurrentDirectory);
            newMoved = true;
            if (!EqualsSha(ComputeManifestSha256(CurrentDirectory), candidateManifest)) throw new InvalidOperationException("Activated package verification failed.");
            service.StartAndWait(TimeSpan.FromSeconds(30));

            WriteTerminalResult(CompletedRoot, requestPath, updateId, new
            {
                schemaVersion = 1,
                updateId,
                status = "completed",
                currentManifestSha256 = candidateManifest,
                rollbackDirectory = backupDirectory,
                completedUtc = DateTimeOffset.UtcNow
            });
            return 0;
        }
        catch (Exception ex)
        {
            TryRollback(oldMoved, newMoved, backupDirectory, updateId);
            try
            {
                if (nextDirectory is not null && Directory.Exists(nextDirectory)) Directory.Delete(nextDirectory, true);
                if (requestPath is not null && File.Exists(requestPath))
                {
                    var id = updateId ?? Path.GetFileNameWithoutExtension(requestPath);
                    WriteTerminalResult(FailedRoot, requestPath, id, new
                    {
                        schemaVersion = 1,
                        updateId = id,
                        status = "failed",
                        error = ex.GetType().Name + ": " + ex.Message,
                        failedUtc = DateTimeOffset.UtcNow
                    });
                }
            }
            catch { }
            return 1;
        }
    }

    private static void TryRollback(bool oldMoved, bool newMoved, string? backupDirectory, string? updateId)
    {
        if (!oldMoved) return;
        try
        {
            using var service = ServiceHandle.Open(ServiceName);
            try { service.StopAndWait(TimeSpan.FromSeconds(20)); } catch { }
            if (newMoved && Directory.Exists(CurrentDirectory))
            {
                var failed = Path.Combine(SupervisorRoot, ".failed-current-" + (updateId ?? Guid.NewGuid().ToString("N")));
                if (!Directory.Exists(failed)) Directory.Move(CurrentDirectory, failed);
            }
            if (backupDirectory is not null && Directory.Exists(backupDirectory) && !Directory.Exists(CurrentDirectory))
                Directory.Move(backupDirectory, CurrentDirectory);
            try { service.StartAndWait(TimeSpan.FromSeconds(30)); } catch { }
        }
        catch { }
    }

    private static void WriteTerminalResult(string root, string requestPath, string updateId, object result)
    {
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, updateId + ".result.json"), JsonSerializer.Serialize(result, JsonOptions), new UTF8Encoding(false));
        File.Move(requestPath, Path.Combine(root, updateId + ".request.json"), false);
    }

    private static bool EqualsSha(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    private static void RequireDirectFileChild(string path, string root)
    {
        var parent = Path.GetDirectoryName(Path.GetFullPath(path))?.TrimEnd('\\', '/');
        var expected = Path.GetFullPath(root).TrimEnd('\\', '/');
        if (!string.Equals(parent, expected, StringComparison.OrdinalIgnoreCase) || !string.Equals(Path.GetExtension(path), ".json", StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Request is outside fixed update pending root.");
    }

    private static void RequireDirectDirectoryChild(string path, string root)
    {
        var full = Path.GetFullPath(path).TrimEnd('\\', '/');
        var parent = Path.GetDirectoryName(full)?.TrimEnd('\\', '/');
        var expected = Path.GetFullPath(root).TrimEnd('\\', '/');
        if (!string.Equals(parent, expected, StringComparison.OrdinalIgnoreCase) || !Directory.Exists(full))
            throw new UnauthorizedAccessException("Candidate must be one direct staging directory.");
    }

    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Reparse point rejected: " + path);
    }

    private static void RejectReparseTree(string root)
    {
        var full = Path.GetFullPath(root);
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException(full);
        RejectReparse(full);
        foreach (var entry in Directory.EnumerateFileSystemEntries(full, "*", SearchOption.AllDirectories)) RejectReparse(entry);
    }

    private static string FileSha256(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string ComputeManifestSha256(string root)
    {
        var full = Path.GetFullPath(root).TrimEnd('\\', '/');
        RejectReparseTree(full);
        var lines = Directory.EnumerateFiles(full, "*", SearchOption.AllDirectories)
            .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
            .Select(file =>
            {
                var rel = Path.GetRelativePath(full, file).Replace('\\', '/');
                var len = new FileInfo(file).Length.ToString(System.Globalization.CultureInfo.InvariantCulture);
                return rel + "\0" + len + "\0" + FileSha256(file);
            });
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", lines) + "\n")));
    }

    private static void CopyTree(string source, string destination)
    {
        RejectReparseTree(source);
        Directory.CreateDirectory(destination);
        foreach (var dir in Directory.EnumerateDirectories(source, "*", SearchOption.AllDirectories))
        {
            RejectReparse(dir);
            Directory.CreateDirectory(Path.Combine(destination, Path.GetRelativePath(source, dir)));
        }
        foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
        {
            RejectReparse(file);
            var target = Path.Combine(destination, Path.GetRelativePath(source, file));
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, false);
        }
    }

    private sealed record UpdateRequest(int SchemaVersion, string UpdateId, string ServiceName, string CurrentDirectory,
        string CandidateDirectory, string CurrentManifestSha256, string CandidateManifestSha256,
        string CurrentExeSha256, string CandidateExeSha256, DateTimeOffset CreatedUtc);
}

internal sealed class ServiceHandle : IDisposable
{
    private readonly nint _scm;
    private readonly nint _service;
    private ServiceHandle(nint scm, nint service) { _scm = scm; _service = service; }

    public static ServiceHandle Open(string serviceName)
    {
        var scm = Native.OpenSCManager(null, null, Native.SC_MANAGER_CONNECT);
        if (scm == 0) throw new InvalidOperationException("OpenSCManager failed: " + Marshal.GetLastWin32Error());
        var service = Native.OpenService(scm, serviceName, Native.SERVICE_QUERY_STATUS | Native.SERVICE_STOP | Native.SERVICE_START);
        if (service == 0)
        {
            var error = Marshal.GetLastWin32Error();
            Native.CloseServiceHandle(scm);
            throw new InvalidOperationException("OpenService failed: " + error);
        }
        return new ServiceHandle(scm, service);
    }

    public void StopAndWait(TimeSpan timeout)
    {
        var state = Query().dwCurrentState;
        if (state == Native.SERVICE_STOPPED) return;
        if (state != Native.SERVICE_STOP_PENDING && !Native.ControlService(_service, Native.SERVICE_CONTROL_STOP, out _))
        {
            var error = Marshal.GetLastWin32Error();
            if (error != Native.ERROR_SERVICE_NOT_ACTIVE) throw new InvalidOperationException("ControlService failed: " + error);
        }
        WaitFor(Native.SERVICE_STOPPED, timeout);
    }

    public void StartAndWait(TimeSpan timeout)
    {
        var state = Query().dwCurrentState;
        if (state == Native.SERVICE_RUNNING) return;
        if (state != Native.SERVICE_START_PENDING && !Native.StartService(_service, 0, null))
        {
            var error = Marshal.GetLastWin32Error();
            if (error != Native.ERROR_SERVICE_ALREADY_RUNNING) throw new InvalidOperationException("StartService failed: " + error);
        }
        WaitFor(Native.SERVICE_RUNNING, timeout);
    }

    private void WaitFor(uint expected, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (Query().dwCurrentState == expected) return;
            Thread.Sleep(250);
        }
        throw new TimeoutException("Timed out waiting for service state " + expected + ".");
    }

    private Native.SERVICE_STATUS_PROCESS Query()
    {
        var size = Marshal.SizeOf<Native.SERVICE_STATUS_PROCESS>();
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (!Native.QueryServiceStatusEx(_service, 0, buffer, size, out _)) throw new InvalidOperationException("QueryServiceStatusEx failed: " + Marshal.GetLastWin32Error());
            return Marshal.PtrToStructure<Native.SERVICE_STATUS_PROCESS>(buffer);
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    public void Dispose()
    {
        if (_service != 0) Native.CloseServiceHandle(_service);
        if (_scm != 0) Native.CloseServiceHandle(_scm);
    }
}

internal static class Native
{
    internal const uint SC_MANAGER_CONNECT = 0x0001, SERVICE_QUERY_STATUS = 0x0004, SERVICE_START = 0x0010, SERVICE_STOP = 0x0020;
    internal const uint SERVICE_CONTROL_STOP = 1, SERVICE_STOPPED = 1, SERVICE_START_PENDING = 2, SERVICE_STOP_PENDING = 3, SERVICE_RUNNING = 4;
    internal const int ERROR_SERVICE_ALREADY_RUNNING = 1056, ERROR_SERVICE_NOT_ACTIVE = 1062;

    [StructLayout(LayoutKind.Sequential)]
    internal struct SERVICE_STATUS_PROCESS
    {
        public uint dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint, dwProcessId, dwServiceFlags;
    }
    [StructLayout(LayoutKind.Sequential)]
    internal struct SERVICE_STATUS
    {
        public uint dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern nint OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] internal static extern nint OpenService(nint scm, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool ControlService(nint service, uint control, out SERVICE_STATUS status);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "StartServiceW")] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool StartService(nint service, int argc, string[]? argv);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool QueryServiceStatusEx(nint service, int infoLevel, nint buffer, int size, out int needed);
    [DllImport("advapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] internal static extern bool CloseServiceHandle(nint handle);
}
