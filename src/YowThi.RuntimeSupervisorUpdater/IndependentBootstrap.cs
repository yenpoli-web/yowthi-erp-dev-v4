using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace YowThi.RuntimeSupervisorUpdater;

internal static class IndependentBootstrap
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string SupervisorServiceName = "YowThiV4RuntimeSupervisor";
    private const string SupervisorRoot = DevRoot + @"\runtime-supervisor";
    private const string CurrentDirectory = SupervisorRoot + @"\current";
    private const string CandidateDirectory = DevRoot + @"\staging\p54-supervisor";
    private const string PendingRoot = SupervisorRoot + @"\updates\pending";
    private const string CompletedRoot = SupervisorRoot + @"\updates\completed";
    private const string FailedRoot = SupervisorRoot + @"\updates\failed";
    private const string RollbackRoot = SupervisorRoot + @"\rollback";
    private const string ExpectedBootstrapExecutable = DevRoot + @"\acceptance\p55-supervisor-updater-build\YowThi.RuntimeSupervisorUpdater.exe";

    private const string ExpectedCurrentManifest = "FF9FD103A1D366F9327F6062259C613FC41C8E5A691460474E1A5B694B51AF15";
    private const string ExpectedCandidateManifest = "9242524FED42D65F8346A280CDB4EE5121381B4F779DF556B84861A514B79424";
    private const string ExpectedCurrentExeSha = "C4D47D70C9826B8E0AB48D2C7B187BE421F17FE9F66903875DC1043967A84FC4";
    private const string ExpectedCandidateExeSha = "2EDBB6C7D8BF581589683DDA02595545B89621251C6A7BC235AFD7C83D6B386D";

    private const uint ScManagerConnect = 0x0001;
    private const uint ScManagerCreateService = 0x0002;
    private const uint DeleteAccess = 0x00010000;
    private const uint ServiceQueryStatus = 0x0004;
    private const uint ServiceStart = 0x0010;
    private const uint ServiceWin32OwnProcess = 0x0010;
    private const uint ServiceDemandStart = 0x00000003;
    private const uint ServiceErrorNormal = 0x00000001;
    private const uint ServiceStopped = 0x00000001;
    private const uint ServiceStartPending = 0x00000002;
    private const uint ServiceRunning = 0x00000004;

    private static string? _serviceName;
    private static string? _requestPath;
    private static string? _expectedSelfSha;
    private static int _serviceExitCode = 1;
    private static Native.ServiceMainDelegate? _serviceMainDelegate;
    private static Native.ServiceControlHandlerDelegate? _serviceControlHandlerDelegate;
    private static nint _serviceStatusHandle;

    public static int BootstrapP54()
    {
        var self = RequireExactSelf();
        ValidateFixedPackage(CurrentDirectory, ExpectedCurrentManifest, ExpectedCurrentExeSha, "current Supervisor");
        ValidateFixedPackage(CandidateDirectory, ExpectedCandidateManifest, ExpectedCandidateExeSha, "P54 Supervisor candidate");
        RequireSupervisorRunning();

        Directory.CreateDirectory(PendingRoot);
        Directory.CreateDirectory(CompletedRoot);
        Directory.CreateDirectory(FailedRoot);
        Directory.CreateDirectory(RollbackRoot);
        RejectReparse(PendingRoot);
        RejectReparse(CompletedRoot);
        RejectReparse(FailedRoot);
        RejectReparse(RollbackRoot);

        var updateId = Guid.NewGuid().ToString("N");
        var requestPath = Path.Combine(PendingRoot, updateId + ".json");
        var rollbackDirectory = Path.Combine(RollbackRoot, updateId);
        var nextDirectory = Path.Combine(SupervisorRoot, ".next-" + updateId);
        if (File.Exists(requestPath) || Directory.Exists(rollbackDirectory) || Directory.Exists(nextDirectory))
            throw new IOException("One-shot Supervisor update identity collision.");

        var currentExe = Path.Combine(CurrentDirectory, "YowThi.RuntimeSupervisor.exe");
        var candidateExe = Path.Combine(CandidateDirectory, "YowThi.RuntimeSupervisor.exe");
        var request = new
        {
            SchemaVersion = 1,
            UpdateId = updateId,
            ServiceName = SupervisorServiceName,
            CurrentDirectory,
            CandidateDirectory,
            CurrentManifestSha256 = ExpectedCurrentManifest,
            CandidateManifestSha256 = ExpectedCandidateManifest,
            CurrentExeSha256 = HashFile(currentExe),
            CandidateExeSha256 = HashFile(candidateExe),
            CreatedUtc = DateTimeOffset.UtcNow
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
                throw new InvalidOperationException("DeleteService failed after one-shot updater start: " + Marshal.GetLastWin32Error());
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
            launchMode = "scm-one-shot-local-system",
            selfSha256 = selfSha,
            currentManifestSha256 = ExpectedCurrentManifest,
            candidateManifestSha256 = ExpectedCandidateManifest
        }));
        return 0;
    }

    public static int RunOneShotService(string serviceName, string requestPath, string expectedSelfSha)
    {
        ValidateOneShotServiceName(serviceName);
        ValidateGuidRequestPath(requestPath);
        RequireSha(expectedSelfSha, "expectedSelfSha");
        var processPath = Path.GetFullPath(Environment.ProcessPath ?? throw new InvalidOperationException("Updater executable path is unavailable."));
        var self = string.Equals(processPath, Path.GetFullPath(ExpectedBootstrapExecutable), StringComparison.OrdinalIgnoreCase)
            ? RequireExactSelf()
            : ReusableBootstrap.RequireReusableBootstrapSelf();
        if (!string.Equals(HashFile(self), expectedSelfSha, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("One-shot updater executable changed after bootstrap.");

        _serviceName = serviceName;
        _requestPath = Path.GetFullPath(requestPath);
        _expectedSelfSha = expectedSelfSha;
        _serviceExitCode = 1;
        _serviceMainDelegate = ServiceMain;
        _serviceControlHandlerDelegate = ServiceControlHandler;

        var table = new Native.ServiceTableEntry[2];
        table[0] = new Native.ServiceTableEntry { ServiceName = serviceName, ServiceMain = _serviceMainDelegate };
        table[1] = new Native.ServiceTableEntry { ServiceName = null, ServiceMain = null };
        if (!Native.StartServiceCtrlDispatcherW(table))
            throw new InvalidOperationException("StartServiceCtrlDispatcherW failed: " + Marshal.GetLastWin32Error());
        return _serviceExitCode;
    }

    private static void ServiceMain(int argc, IntPtr argv)
    {
        if (_serviceName is null || _requestPath is null || _expectedSelfSha is null)
        {
            _serviceExitCode = 90;
            return;
        }

        _serviceStatusHandle = Native.RegisterServiceCtrlHandlerW(_serviceName, _serviceControlHandlerDelegate!);
        if (_serviceStatusHandle == 0)
        {
            _serviceExitCode = 91;
            return;
        }

        ReportServiceState(ServiceStartPending, 0, 30000);
        ReportServiceState(ServiceRunning, 0, 0);
        try
        {
            _serviceExitCode = Program.RunUpdate([_requestPath]);
        }
        catch
        {
            _serviceExitCode = 1;
        }
        finally
        {
            ReportServiceState(ServiceStopped, _serviceExitCode == 0 ? 0u : 1066u, 0);
        }
    }

    private static void ServiceControlHandler(uint control)
    {
        // One-shot updater intentionally accepts no external stop/pause controls while the atomic swap is in flight.
    }

    private static void ReportServiceState(uint state, uint win32ExitCode, uint waitHint)
    {
        if (_serviceStatusHandle == 0) return;
        var status = new Native.ServiceStatus
        {
            ServiceType = ServiceWin32OwnProcess,
            CurrentState = state,
            ControlsAccepted = 0,
            Win32ExitCode = win32ExitCode,
            ServiceSpecificExitCode = 0,
            CheckPoint = 0,
            WaitHint = waitHint
        };
        _ = Native.SetServiceStatus(_serviceStatusHandle, ref status);
    }

    private static string RequireExactSelf()
    {
        var self = Path.GetFullPath(Environment.ProcessPath ?? throw new InvalidOperationException("Updater executable path is unavailable."));
        if (!string.Equals(self, Path.GetFullPath(ExpectedBootstrapExecutable), StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Independent Supervisor updater must run from the fixed P55 acceptance build path.");
        if (!File.Exists(self)) throw new FileNotFoundException("Updater executable does not exist.", self);
        RejectReparse(self);
        return self;
    }

    private static void ValidateFixedPackage(string directory, string expectedManifest, string expectedExeSha, string label)
    {
        var full = Path.GetFullPath(directory);
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException(label + " directory does not exist: " + full);
        RejectReparseTree(full);
        var actualManifest = ComputeManifestSha256(full);
        if (!string.Equals(actualManifest, expectedManifest, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(label + " manifest SHA-256 mismatch.");
        var exe = Path.Combine(full, "YowThi.RuntimeSupervisor.exe");
        if (!string.Equals(HashFile(exe), expectedExeSha, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(label + " executable SHA-256 mismatch.");
    }

    private static void RequireSupervisorRunning()
    {
        nint scm = 0;
        nint service = 0;
        try
        {
            scm = Native.OpenSCManagerW(null, null, ScManagerConnect);
            if (scm == 0) throw new InvalidOperationException("OpenSCManagerW failed: " + Marshal.GetLastWin32Error());
            service = Native.OpenServiceW(scm, SupervisorServiceName, ServiceQueryStatus);
            if (service == 0) throw new InvalidOperationException("OpenServiceW failed: " + Marshal.GetLastWin32Error());
            var size = Marshal.SizeOf<Native.ServiceStatusProcess>();
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (!Native.QueryServiceStatusEx(service, 0, buffer, size, out _))
                    throw new InvalidOperationException("QueryServiceStatusEx failed: " + Marshal.GetLastWin32Error());
                var status = Marshal.PtrToStructure<Native.ServiceStatusProcess>(buffer);
                if (status.CurrentState != ServiceRunning || status.ProcessId == 0)
                    throw new InvalidOperationException("Runtime Supervisor service must be Running before P55 bootstrap.");
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        finally
        {
            if (service != 0) Native.CloseServiceHandle(service);
            if (scm != 0) Native.CloseServiceHandle(scm);
        }
    }

    private static void ValidateOneShotServiceName(string serviceName)
    {
        if (!serviceName.StartsWith("YowThiV4SupervisorUpdater-", StringComparison.Ordinal) || serviceName.Length != 38 ||
            serviceName.Skip(26).Any(ch => !Uri.IsHexDigit(ch)))
            throw new UnauthorizedAccessException("Invalid one-shot Supervisor updater service name.");
    }

    private static void ValidateGuidRequestPath(string requestPath)
    {
        var full = Path.GetFullPath(requestPath);
        var parent = Path.GetDirectoryName(full)?.TrimEnd('\\', '/');
        var expectedParent = Path.GetFullPath(PendingRoot).TrimEnd('\\', '/');
        var leaf = Path.GetFileNameWithoutExtension(full);
        if (!string.Equals(parent, expectedParent, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetExtension(full), ".json", StringComparison.OrdinalIgnoreCase) ||
            !Guid.TryParseExact(leaf, "N", out _) || !File.Exists(full))
            throw new UnauthorizedAccessException("One-shot updater request path is outside the fixed pending queue.");
        RejectReparse(full);
    }

    private static void RequireSha(string value, string name)
    {
        if (value.Length != 64 || value.Any(ch => !Uri.IsHexDigit(ch)))
            throw new InvalidDataException(name + " must be a 64-character SHA-256 digest.");
    }

    private static string Quote(string value) => "\"" + value.Replace("\"", "\\\"") + "\"";

    private static void RejectReparseTree(string root)
    {
        RejectReparse(root);
        foreach (var entry in Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories)) RejectReparse(entry);
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

    internal static class Native
    {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        internal delegate void ServiceMainDelegate(int argc, IntPtr argv);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        internal delegate void ServiceControlHandlerDelegate(uint control);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct ServiceTableEntry
        {
            [MarshalAs(UnmanagedType.LPWStr)] public string? ServiceName;
            [MarshalAs(UnmanagedType.FunctionPtr)] public ServiceMainDelegate? ServiceMain;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ServiceStatus
        {
            public uint ServiceType;
            public uint CurrentState;
            public uint ControlsAccepted;
            public uint Win32ExitCode;
            public uint ServiceSpecificExitCode;
            public uint CheckPoint;
            public uint WaitHint;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ServiceStatusProcess
        {
            public uint ServiceType;
            public uint CurrentState;
            public uint ControlsAccepted;
            public uint Win32ExitCode;
            public uint ServiceSpecificExitCode;
            public uint CheckPoint;
            public uint WaitHint;
            public uint ProcessId;
            public uint ServiceFlags;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern nint OpenSCManagerW(string? machineName, string? databaseName, uint desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern nint OpenServiceW(nint scm, string serviceName, uint desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern nint CreateServiceW(
            nint scm,
            string serviceName,
            string displayName,
            uint desiredAccess,
            uint serviceType,
            uint startType,
            uint errorControl,
            string binaryPathName,
            string? loadOrderGroup,
            IntPtr tagId,
            string? dependencies,
            string? serviceStartName,
            string? password);

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
        internal static extern bool StartServiceCtrlDispatcherW([In] ServiceTableEntry[] serviceStartTable);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern nint RegisterServiceCtrlHandlerW(string serviceName, ServiceControlHandlerDelegate handlerProc);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetServiceStatus(nint serviceStatusHandle, ref ServiceStatus serviceStatus);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseServiceHandle(nint handle);
    }
}
