using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Windows;

[McpServerToolType]
public static class V4RuntimeSupervisorServiceTools
{
    private const string ServiceName = "YowThiV4RuntimeSupervisor";
    private const string DisplayName = "YowThi V4 Runtime Supervisor";
    private const string BinaryPath = @"C:\Dev\YowThi-ERP-Dev-v4\runtime-supervisor\current\YowThi.RuntimeSupervisor.exe";
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SC_MANAGER_CREATE_SERVICE = 0x0002;
    private const uint SERVICE_QUERY_CONFIG = 0x0001;
    private const uint SERVICE_QUERY_STATUS = 0x0004;
    private const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
    private const uint SERVICE_AUTO_START = 0x00000002;
    private const uint SERVICE_ERROR_NORMAL = 0x00000001;
    private const uint SERVICE_STOPPED = 0x00000001;
    private const int SC_STATUS_PROCESS_INFO = 0;
    private const int ERROR_SERVICE_DOES_NOT_EXIST = 1060;
    private const int ERROR_SERVICE_MARKED_FOR_DELETE = 1072;

    [McpServerTool(Name = "v4_runtime_supervisor_service_install_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to install only the fixed YowThi V4 Runtime Supervisor Windows service. Service name, display name, Automatic start type, LocalSystem account, Win32 own-process type, and executable path C:\\Dev\\YowThi-ERP-Dev-v4\\runtime-supervisor\\current\\YowThi.RuntimeSupervisor.exe are fixed server-side. The executable SHA-256 and size are sealed. Arbitrary service names, paths, arguments, accounts, dependencies, shells, production paths, and overwrite are not supported.")]
    public static SignedPlan InstallPlan()
    {
        var binary = ReadBinary();
        using var scm = OpenManager(SC_MANAGER_CONNECT);
        if (ServiceExists(scm))
            throw new InvalidOperationException($"Service {ServiceName} already exists.");

        var now = DateTimeOffset.UtcNow;
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["serviceName"] = ServiceName,
            ["displayName"] = DisplayName,
            ["binaryPath"] = binary.Path,
            ["binarySha256"] = binary.Sha256,
            ["binaryBytes"] = binary.Bytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["startType"] = "Automatic",
            ["account"] = "LocalSystem"
        };
        var summary = $"Install fixed YowThi V4 Runtime Supervisor Windows service from {binary.Path} (sha256={binary.Sha256[..12]})";
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)),
            "v4-runtime-supervisor-service", "install", ServiceName, parameters, RiskClass.High, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary, binary.Sha256 }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "v4_runtime_supervisor_service_install_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute only one previously prepared fixed YowThi V4 Runtime Supervisor service install plan. The only caller inputs are planId and approvalCode. The server revalidates the fixed service identity, exact executable path and SHA-256, service absence, Automatic start type, LocalSystem account, and Win32 own-process shape immediately before native Windows Service Control Manager CreateService. No arbitrary service, command, shell, argument, dependency, overwrite, or production mutation is supported.")]
    public static ServiceInstallResult InstallExecute(string planId, string approvalCode)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequirePlan(plan);
        var binary = ReadBinary();
        if (!string.Equals(binary.Sha256, RequireParameter(plan, "binarySha256"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Runtime supervisor executable SHA-256 changed after plan creation.");

        using var scm = OpenManager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
        if (ServiceExists(scm))
            throw new InvalidOperationException($"Service {ServiceName} already exists.");

        try
        {
            using var service = CreateServiceW(
                scm, ServiceName, DisplayName,
                SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                $"\"{BinaryPath}\"",
                null, IntPtr.Zero, null, null, null);
            if (service.IsInvalid)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to create YowThi V4 Runtime Supervisor service.");

            var snapshot = ReadSnapshot(service);
            if (snapshot.State != SERVICE_STOPPED || snapshot.StartType != SERVICE_AUTO_START ||
                !string.Equals(snapshot.DisplayName, DisplayName, StringComparison.Ordinal) ||
                !string.Equals(Path.GetFullPath(snapshot.EffectiveBinaryPath), Path.GetFullPath(BinaryPath), StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("New runtime supervisor service failed fixed-identity read-back.");

            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, binary.Sha256, snapshot.ConfigFingerprint, state = "Stopped", startType = "Automatic" }, "executed");
            return new ServiceInstallResult(plan.PlanId, ServiceName, "Stopped", "Automatic", binary.Sha256, snapshot.ConfigFingerprint, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.GetType().Name + ": " + ex.Message }, "failed");
            throw;
        }
    }

    private static void RequirePlan(SignedPlan plan)
    {
        if (!string.Equals(plan.Tool, "v4-runtime-supervisor-service", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, "install", StringComparison.Ordinal) ||
            !string.Equals(plan.Target, ServiceName, StringComparison.Ordinal) ||
            plan.RiskClass != RiskClass.High ||
            !string.Equals(RequireParameter(plan, "serviceName"), ServiceName, StringComparison.Ordinal) ||
            !string.Equals(Path.GetFullPath(RequireParameter(plan, "binaryPath")), Path.GetFullPath(BinaryPath), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(RequireParameter(plan, "startType"), "Automatic", StringComparison.Ordinal) ||
            !string.Equals(RequireParameter(plan, "account"), "LocalSystem", StringComparison.Ordinal))
            throw new UnauthorizedAccessException("V4 runtime supervisor service plan identity is invalid.");
    }

    private static BinarySnapshot ReadBinary()
    {
        var path = Path.GetFullPath(BinaryPath);
        var fixedRoot = Path.GetFullPath(@"C:\Dev\YowThi-ERP-Dev-v4\runtime-supervisor\current").TrimEnd(Path.DirectorySeparatorChar);
        if (!string.Equals(Path.GetDirectoryName(path)?.TrimEnd(Path.DirectorySeparatorChar), fixedRoot, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Runtime supervisor binary is outside the fixed current package root.");
        if (!File.Exists(path)) throw new FileNotFoundException("Runtime supervisor executable does not exist.", path);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Runtime supervisor executable may not be a reparse point.");
        var info = new FileInfo(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return new BinarySnapshot(path, Convert.ToHexString(SHA256.HashData(stream)), info.Length);
    }

    private static bool ServiceExists(SafeServiceHandle scm)
    {
        using var service = OpenServiceW(scm, ServiceName, SERVICE_QUERY_STATUS);
        if (!service.IsInvalid) return true;
        var error = Marshal.GetLastWin32Error();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) return false;
        if (error == ERROR_SERVICE_MARKED_FOR_DELETE) throw new InvalidOperationException("Runtime supervisor service is marked for deletion.");
        throw new Win32Exception(error, "Unable to determine runtime supervisor service existence.");
    }

    private static ServiceSnapshot ReadSnapshot(SafeServiceHandle service)
    {
        var status = new SERVICE_STATUS_PROCESS();
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, ref status, Marshal.SizeOf<SERVICE_STATUS_PROCESS>(), out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to query runtime supervisor service status.");
        _ = QueryServiceConfigW(service, IntPtr.Zero, 0, out var bytesNeeded);
        var buffer = Marshal.AllocHGlobal(bytesNeeded);
        try
        {
            if (!QueryServiceConfigW(service, buffer, bytesNeeded, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to query runtime supervisor service configuration.");
            var config = Marshal.PtrToStructure<QUERY_SERVICE_CONFIG>(buffer);
            var binary = Marshal.PtrToStringUni(config.lpBinaryPathName) ?? string.Empty;
            var display = Marshal.PtrToStringUni(config.lpDisplayName) ?? string.Empty;
            var account = Marshal.PtrToStringUni(config.lpServiceStartName) ?? string.Empty;
            var effective = ParseExecutable(binary);
            var fp = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", ServiceName, display, binary, config.dwStartType, account))));
            return new ServiceSnapshot(status.dwCurrentState, config.dwStartType, display, effective, fp);
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static string ParseExecutable(string commandLine)
    {
        var argv = CommandLineToArgvW(Environment.ExpandEnvironmentVariables(commandLine), out var argc);
        if (argv == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to parse service executable path.");
        try
        {
            if (argc != 1) throw new UnauthorizedAccessException("Runtime supervisor service binary path must contain exactly one executable and no arguments.");
            return Path.GetFullPath(Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv)) ?? string.Empty);
        }
        finally { LocalFree(argv); }
    }

    private static SafeServiceHandle OpenManager(uint access)
    {
        var manager = OpenSCManagerW(null, null, access);
        if (manager.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to open Service Control Manager.");
        return manager;
    }

    private static string RequireParameter(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value : throw new InvalidDataException($"Signed service plan is missing parameter: {key}");

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeServiceHandle OpenSCManagerW(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeServiceHandle OpenServiceW(SafeServiceHandle manager, string serviceName, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeServiceHandle CreateServiceW(SafeServiceHandle manager, string serviceName, string displayName, uint desiredAccess, uint serviceType, uint startType, uint errorControl, string binaryPath, string? loadOrderGroup, IntPtr tagId, string? dependencies, string? serviceStartName, string? password);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(SafeServiceHandle service, int infoLevel, ref SERVICE_STATUS_PROCESS buffer, int bufferSize, out int bytesNeeded);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfigW(SafeServiceHandle service, IntPtr config, int bufferSize, out int bytesNeeded);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr handle);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW(string commandLine, out int argc);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS_PROCESS { public uint dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint, dwProcessId, dwServiceFlags; }
    [StructLayout(LayoutKind.Sequential)]
    private struct QUERY_SERVICE_CONFIG { public uint dwServiceType, dwStartType, dwErrorControl; public IntPtr lpBinaryPathName, lpLoadOrderGroup; public uint dwTagId; public IntPtr lpDependencies, lpServiceStartName, lpDisplayName; }
    private sealed class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid { public SafeServiceHandle() : base(true) { } protected override bool ReleaseHandle() => CloseServiceHandle(handle); }
    private sealed record BinarySnapshot(string Path, string Sha256, long Bytes);
    private sealed record ServiceSnapshot(uint State, uint StartType, string DisplayName, string EffectiveBinaryPath, string ConfigFingerprint);
}

public sealed record ServiceInstallResult(string PlanId, string ServiceName, string State, string StartType, string BinarySha256, string ConfigFingerprint, DateTimeOffset ExecutedUtc);
