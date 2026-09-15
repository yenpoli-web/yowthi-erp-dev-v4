using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace YowThi.RuntimeSupervisorUpdater;

internal static class ReusableBootstrap
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string AcceptanceRoot = DevRoot + @"\acceptance";
    private const string StagingRoot = DevRoot + @"\staging";
    private const string SupervisorServiceName = "YowThiV4RuntimeSupervisor";
    private const string SupervisorRoot = DevRoot + @"\runtime-supervisor";
    private const string CurrentDirectory = SupervisorRoot + @"\current";
    private const string PendingRoot = SupervisorRoot + @"\updates\pending";
    private const string CompletedRoot = SupervisorRoot + @"\updates\completed";
    private const string FailedRoot = SupervisorRoot + @"\updates\failed";
    private const string RollbackRoot = SupervisorRoot + @"\rollback";
    private const string SupervisorExeName = "YowThi.RuntimeSupervisor.exe";
    private const string SupervisorDllName = "YowThi.RuntimeSupervisor.dll";
    private const string SupervisorDepsName = "YowThi.RuntimeSupervisor.deps.json";
    private const string SupervisorRuntimeConfigName = "YowThi.RuntimeSupervisor.runtimeconfig.json";
    private const string UpdaterExeName = "YowThi.RuntimeSupervisorUpdater.exe";

    private const uint ScManagerConnect = 0x0001;
    private const uint ScManagerCreateService = 0x0002;
    private const uint DeleteAccess = 0x00010000;
    private const uint ServiceQueryConfig = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const uint ServiceStart = 0x0010;
    private const uint ServiceWin32OwnProcess = 0x0010;
    private const uint ServiceDemandStart = 0x00000003;
    private const uint ServiceErrorNormal = 0x00000001;
    private const uint ServiceRunning = 0x00000004;

    public static int BootstrapCandidate(string candidateDirectoryInput)
    {
        var self = RequireReusableBootstrapSelf();
        ValidateFixedRoots();
        RequireSupervisorRunningAndFixedBinary();

        var candidateDirectory = Path.GetFullPath(candidateDirectoryInput).TrimEnd('\\', '/');
        RequireDirectDirectoryChild(candidateDirectory, StagingRoot, "Supervisor candidate");
        RequireSafeDirectoryTraversal(candidateDirectory, StagingRoot);
        RejectReparseTree(candidateDirectory);
        RejectReparseTree(CurrentDirectory);
        RequireSupervisorPackageShape(CurrentDirectory, "current Supervisor");
        RequireSupervisorPackageShape(candidateDirectory, "candidate Supervisor");

        var currentManifest = ComputeManifestSha256(CurrentDirectory);
        var candidateManifest = ComputeManifestSha256(candidateDirectory);
        if (string.Equals(currentManifest, candidateManifest, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Supervisor candidate package is identical to current package.");

        var currentExe = Path.Combine(CurrentDirectory, SupervisorExeName);
        var candidateExe = Path.Combine(candidateDirectory, SupervisorExeName);
        var currentExeSha = HashFile(currentExe);
        var candidateExeSha = HashFile(candidateExe);

        var updateId = Guid.NewGuid().ToString("N");
        var requestPath = Path.Combine(PendingRoot, updateId + ".json");
        var rollbackDirectory = Path.Combine(RollbackRoot, updateId);
        var nextDirectory = Path.Combine(SupervisorRoot, ".next-" + updateId);
        if (File.Exists(requestPath) || Directory.Exists(rollbackDirectory) || Directory.Exists(nextDirectory))
            throw new IOException("Reusable Supervisor update identity collision.");

        var createdUtc = DateTimeOffset.UtcNow;
        var request = new
        {
            SchemaVersion = 1,
            UpdateId = updateId,
            ServiceName = SupervisorServiceName,
            CurrentDirectory,
            CandidateDirectory = candidateDirectory,
            CurrentManifestSha256 = currentManifest,
            CandidateManifestSha256 = candidateManifest,
            CurrentExeSha256 = currentExeSha,
            CandidateExeSha256 = candidateExeSha,
            CreatedUtc = createdUtc
        };
        var requestBytes = new UTF8Encoding(false).GetBytes(JsonSerializer.Serialize(request, new JsonSerializerOptions { WriteIndented = true }));
        using (var stream = new FileStream(requestPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            stream.Write(requestBytes, 0, requestBytes.Length);
            stream.Flush(flushToDisk: true);
        }

        var serviceName = "YowThiV4SupervisorUpdater-" + updateId[..12];
        var selfSha = HashFile(self);
        var binaryPath = Quote(self) + " --service " + Quote(serviceName) + " " + Quote(requestPath) + " " + selfSha;
        var started = false;
        nint scm = 0;
        nint service = 0;
        try
        {
            scm = Native.OpenSCManagerW(null, null, ScManagerConnect | ScManagerCreateService);
            if (scm == 0) throw new InvalidOperationException("OpenSCManagerW failed: " + Marshal.GetLastWin32Error());
            service = Native.CreateServiceW(
                scm,
                serviceName,
                serviceName,
                ServiceStart | ServiceQueryStatus | DeleteAccess,
                ServiceWin32OwnProcess,
                ServiceDemandStart,
                ServiceErrorNormal,
                binaryPath,
                null,
                IntPtr.Zero,
                null,
                null,
                null);
            if (service == 0) throw new InvalidOperationException("CreateServiceW failed: " + Marshal.GetLastWin32Error());
            if (!Native.StartServiceW(service, 0, null))
                throw new InvalidOperationException("StartServiceW failed: " + Marshal.GetLastWin32Error());
            started = true;
            if (!Native.DeleteService(service))
                throw new InvalidOperationException("DeleteService failed after reusable one-shot updater start: " + Marshal.GetLastWin32Error());
        }
        catch
        {
            if (!started)
            {
                try { if (service != 0) Native.DeleteService(service); } catch { }
                try { if (File.Exists(requestPath)) File.Delete(requestPath); } catch { }
            }
            throw;
        }
        finally
        {
            if (service != 0) Native.CloseServiceHandle(service);
            if (scm != 0) Native.CloseServiceHandle(scm);
        }

        Console.WriteLine(JsonSerializer.Serialize(new
        {
            updateId,
            requestPath,
            oneShotService = serviceName,
            launchMode = "reusable-scm-one-shot-local-system",
            selfSha256 = selfSha,
            currentManifestSha256 = currentManifest,
            candidateManifestSha256 = candidateManifest,
            currentExeSha256 = currentExeSha,
            candidateExeSha256 = candidateExeSha
        }));
        return 0;
    }

    private static string RequireReusableBootstrapSelf()
    {
        var self = Path.GetFullPath(Environment.ProcessPath ?? throw new InvalidOperationException("Updater executable path is unavailable."));
        if (!string.Equals(Path.GetFileName(self), UpdaterExeName, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Reusable Supervisor bootstrap must run through the updater apphost executable.");
        if (!File.Exists(self)) throw new FileNotFoundException("Updater executable does not exist.", self);

        var buildDirectory = Path.GetDirectoryName(self)?.TrimEnd('\\', '/')
            ?? throw new InvalidDataException("Updater build directory is unavailable.");
        var parent = Path.GetDirectoryName(buildDirectory)?.TrimEnd('\\', '/');
        var acceptanceRoot = Path.GetFullPath(AcceptanceRoot).TrimEnd('\\', '/');
        var buildName = Path.GetFileName(buildDirectory);
        if (!string.Equals(parent, acceptanceRoot, StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(buildName) ||
            !buildName.Contains("-build", StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Reusable Supervisor bootstrap updater must be one direct acceptance build output.");

        RequireSafeDirectoryTraversal(buildDirectory, AcceptanceRoot);
        RejectReparse(self);
        return self;
    }

    private static void ValidateFixedRoots()
    {
        RequireSafeDirectoryTraversal(DevRoot, DevRoot);
        RequireSafeDirectoryTraversal(AcceptanceRoot, DevRoot);
        RequireSafeDirectoryTraversal(StagingRoot, DevRoot);
        RequireSafeDirectoryTraversal(SupervisorRoot, DevRoot);
        RequireSafeDirectoryTraversal(CurrentDirectory, SupervisorRoot);
        RequireSafeDirectoryTraversal(PendingRoot, SupervisorRoot);
        RequireSafeDirectoryTraversal(CompletedRoot, SupervisorRoot);
        RequireSafeDirectoryTraversal(FailedRoot, SupervisorRoot);
        RequireSafeDirectoryTraversal(RollbackRoot, SupervisorRoot);
    }

    private static void RequireSafeDirectoryTraversal(string path, string boundary)
    {
        var full = Path.GetFullPath(path).TrimEnd('\\', '/');
        var root = Path.GetFullPath(boundary).TrimEnd('\\', '/');
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException("Required fixed directory does not exist: " + full);
        if (!string.Equals(full, root, StringComparison.OrdinalIgnoreCase) &&
            !full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Fixed directory escaped its boundary: " + full);

        var current = new DirectoryInfo(full);
        while (current is not null)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException("Reparse point rejected in fixed directory traversal: " + current.FullName);
            var currentFull = current.FullName.TrimEnd('\\', '/');
            if (string.Equals(currentFull, root, StringComparison.OrdinalIgnoreCase)) return;
            current = current.Parent;
        }
        throw new UnauthorizedAccessException("Fixed directory traversal did not reach its boundary: " + full);
    }

    private static void RequireDirectDirectoryChild(string path, string root, string label)
    {
        var full = Path.GetFullPath(path).TrimEnd('\\', '/');
        var parent = Path.GetDirectoryName(full)?.TrimEnd('\\', '/');
        var expected = Path.GetFullPath(root).TrimEnd('\\', '/');
        if (!string.Equals(parent, expected, StringComparison.OrdinalIgnoreCase) || !Directory.Exists(full))
            throw new UnauthorizedAccessException(label + " must be one existing direct child of its fixed root.");
    }

    private static void RequireSupervisorPackageShape(string directory, string label)
    {
        foreach (var leaf in new[] { SupervisorExeName, SupervisorDllName, SupervisorDepsName, SupervisorRuntimeConfigName })
        {
            var path = Path.Combine(directory, leaf);
            if (!File.Exists(path)) throw new FileNotFoundException(label + " package is missing required file " + leaf + ".", path);
            RejectReparse(path);
        }
    }

    private static void RequireSupervisorRunningAndFixedBinary()
    {
        nint scm = 0;
        nint service = 0;
        try
        {
            scm = Native.OpenSCManagerW(null, null, ScManagerConnect);
            if (scm == 0) throw new InvalidOperationException("OpenSCManagerW failed: " + Marshal.GetLastWin32Error());
            service = Native.OpenServiceW(scm, SupervisorServiceName, ServiceQueryConfig | ServiceQueryStatus);
            if (service == 0) throw new InvalidOperationException("OpenServiceW failed: " + Marshal.GetLastWin32Error());

            var size = Marshal.SizeOf<Native.ServiceStatusProcess>();
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (!Native.QueryServiceStatusEx(service, 0, buffer, size, out _))
                    throw new InvalidOperationException("QueryServiceStatusEx failed: " + Marshal.GetLastWin32Error());
                var status = Marshal.PtrToStructure<Native.ServiceStatusProcess>(buffer);
                if (status.CurrentState != ServiceRunning || status.ProcessId == 0)
                    throw new InvalidOperationException("Runtime Supervisor service must be Running before reusable update bootstrap.");
            }
            finally { Marshal.FreeHGlobal(buffer); }

            _ = Native.QueryServiceConfigW(service, IntPtr.Zero, 0, out var needed);
            if (needed <= 0) throw new InvalidOperationException("QueryServiceConfigW size probe failed: " + Marshal.GetLastWin32Error());
            var configBuffer = Marshal.AllocHGlobal(needed);
            try
            {
                if (!Native.QueryServiceConfigW(service, configBuffer, needed, out _))
                    throw new InvalidOperationException("QueryServiceConfigW failed: " + Marshal.GetLastWin32Error());
                var config = Marshal.PtrToStructure<Native.QueryServiceConfig>(configBuffer);
                var commandLine = Marshal.PtrToStringUni(config.BinaryPathName) ?? string.Empty;
                var argv = Native.CommandLineToArgvW(Environment.ExpandEnvironmentVariables(commandLine), out var argc);
                if (argv == IntPtr.Zero) throw new InvalidOperationException("CommandLineToArgvW failed: " + Marshal.GetLastWin32Error());
                try
                {
                    if (argc != 1) throw new UnauthorizedAccessException("Runtime Supervisor service must use exactly one executable and no arguments.");
                    var binary = Path.GetFullPath(Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv)) ?? string.Empty);
                    var expected = Path.GetFullPath(Path.Combine(CurrentDirectory, SupervisorExeName));
                    if (!string.Equals(binary, expected, StringComparison.OrdinalIgnoreCase))
                        throw new UnauthorizedAccessException("Runtime Supervisor service binary path does not match fixed current package.");
                    RejectReparse(binary);
                }
                finally { Native.LocalFree(argv); }
            }
            finally { Marshal.FreeHGlobal(configBuffer); }
        }
        finally
        {
            if (service != 0) Native.CloseServiceHandle(service);
            if (scm != 0) Native.CloseServiceHandle(scm);
        }
    }

    private static void RejectReparseTree(string root)
    {
        var full = Path.GetFullPath(root);
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException(full);
        RejectReparse(full);
        foreach (var entry in Directory.EnumerateFileSystemEntries(full, "*", SearchOption.AllDirectories)) RejectReparse(entry);
    }

    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Reparse point rejected: " + path);
    }

    private static string HashFile(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException("Fixed file does not exist.", path);
        RejectReparse(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string ComputeManifestSha256(string root)
    {
        var full = Path.GetFullPath(root).TrimEnd('\\', '/');
        RejectReparseTree(full);
        var lines = Directory.EnumerateFiles(full, "*", SearchOption.AllDirectories)
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .Select(file =>
            {
                var relative = Path.GetRelativePath(full, file).Replace('\\', '/');
                var length = new FileInfo(file).Length.ToString(System.Globalization.CultureInfo.InvariantCulture);
                return relative + "\0" + length + "\0" + HashFile(file);
            });
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", lines) + "\n")));
    }

    private static string Quote(string value) => "\"" + value.Replace("\"", "\\\"") + "\"";

    private static class Native
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct ServiceStatusProcess
        {
            internal uint ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint, ProcessId, ServiceFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct QueryServiceConfig
        {
            internal uint ServiceType, StartType, ErrorControl;
            internal IntPtr BinaryPathName, LoadOrderGroup;
            internal uint TagId;
            internal IntPtr Dependencies, ServiceStartName, DisplayName;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern nint OpenSCManagerW(string? machineName, string? databaseName, uint desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern nint OpenServiceW(nint scm, string serviceName, uint desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern nint CreateServiceW(nint scm, string serviceName, string displayName, uint desiredAccess,
            uint serviceType, uint startType, uint errorControl, string binaryPathName, string? loadOrderGroup,
            IntPtr tagId, string? dependencies, string? serviceStartName, string? password);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "StartServiceW")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool StartServiceW(nint service, int argc, string[]? argv);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DeleteService(nint service);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool QueryServiceStatusEx(nint service, int infoLevel, nint buffer, int size, out int needed);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool QueryServiceConfigW(nint service, IntPtr config, int bufferSize, out int bytesNeeded);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr CommandLineToArgvW(string commandLine, out int argc);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr LocalFree(IntPtr memory);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseServiceHandle(nint handle);
    }
}
