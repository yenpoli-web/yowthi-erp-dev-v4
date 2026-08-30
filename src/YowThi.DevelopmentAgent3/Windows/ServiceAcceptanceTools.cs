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
public static class ServiceAcceptanceTools
{
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    private const string AcceptanceServiceName = "YowThiAgent3AcceptanceService";
    private const string AcceptanceDisplayName = "YowThi Agent 3 Acceptance Service";
    private const string AcceptanceBinary = @"C:\Dev\YowThi-ERP-Dev-v4\acceptance\service-acceptance-v1-build\YowThi.ServiceAcceptance.exe";

    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SC_MANAGER_CREATE_SERVICE = 0x0002;
    private const uint SERVICE_QUERY_CONFIG = 0x0001;
    private const uint SERVICE_QUERY_STATUS = 0x0004;
    private const uint DELETE = 0x00010000;
    private const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
    private const uint SERVICE_DEMAND_START = 0x00000003;
    private const uint SERVICE_ERROR_NORMAL = 0x00000001;
    private const uint SERVICE_STOPPED = 0x00000001;
    private const int SC_STATUS_PROCESS_INFO = 0;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;
    private const int ERROR_SERVICE_DOES_NOT_EXIST = 1060;
    private const int ERROR_SERVICE_MARKED_FOR_DELETE = 1072;

    [McpServerTool(Name = "service_acceptance_install_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to install only the dedicated YowThi Agent 3 acceptance Windows service. The service name, display name, executable path, LocalSystem account, Manual start type, and Win32 own-process type are fixed server-side. The acceptance executable must exist at the fixed C:\\Dev\\YowThi-ERP-Dev-v4 acceptance path, must not be a reparse point, and its SHA-256 is sealed. Arbitrary service names, paths, arguments, accounts, dependencies, and shell commands are not accepted.")]
    public static SignedPlan ServiceAcceptanceInstallPlan()
    {
        var binary = ReadValidatedBinary();
        using var scm = OpenManager(SC_MANAGER_CONNECT);
        if (ServiceExists(scm))
            throw new InvalidOperationException($"Acceptance service {AcceptanceServiceName} already exists.");

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["serviceName"] = AcceptanceServiceName,
            ["displayName"] = AcceptanceDisplayName,
            ["binaryPath"] = binary.Path,
            ["binarySha256"] = binary.Sha256,
            ["binaryBytes"] = binary.Bytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["startType"] = "Manual",
            ["account"] = "LocalSystem"
        };
        var summary = $"Install dedicated V4 acceptance Windows service {AcceptanceServiceName} from {binary.Path} (sha256={binary.Sha256[..12]})";
        return CreatePlan("service-acceptance-install", parameters, RiskClass.High, summary);
    }

    [McpServerTool(Name = "service_acceptance_install_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared service/service-acceptance-install plan using only the native Windows Service Control Manager CreateService API. The dedicated fixed service identity and acceptance executable SHA-256 are rechecked immediately before creation. The service is created as Win32 own-process, Manual start, LocalSystem, with no dependencies and no arguments. No PowerShell, cmd, sc.exe, WMI, or generic command executor is used.")]
    public static AcceptanceServiceExecutionResult ServiceAcceptanceInstallExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "service-acceptance-install", operation, target, summary, riskClass);
        RequireFixedPlanIdentity(plan);

        var binary = ReadValidatedBinary();
        if (!string.Equals(binary.Sha256, RequireParameter(plan, "binarySha256"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Acceptance service executable SHA-256 changed after plan creation.");

        using var scm = OpenManager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
        if (ServiceExists(scm))
            throw new InvalidOperationException($"Acceptance service {AcceptanceServiceName} already exists.");

        try
        {
            using var service = CreateServiceW(
                scm,
                AcceptanceServiceName,
                AcceptanceDisplayName,
                SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                $"\"{AcceptanceBinary}\"",
                null,
                IntPtr.Zero,
                null,
                null,
                null);

            if (service.IsInvalid)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to create the dedicated acceptance Windows service.");

            var snapshot = ReadSnapshot(service);
            RequireAcceptanceIdentity(snapshot);
            if (snapshot.State != SERVICE_STOPPED)
                throw new InvalidOperationException("Newly installed acceptance service is not Stopped.");

            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, binary.Sha256, snapshot.ConfigFingerprint, state = "Stopped" }, "executed");
            return new AcceptanceServiceExecutionResult(plan.PlanId, plan.Operation, AcceptanceServiceName, "Stopped", binary.Sha256, snapshot.ConfigFingerprint, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "service_acceptance_uninstall_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to uninstall only the dedicated YowThi Agent 3 acceptance Windows service. The service must exist, be Stopped, and still resolve to the exact fixed acceptance executable. The service configuration fingerprint and executable SHA-256 are sealed. Arbitrary service deletion is not supported.")]
    public static SignedPlan ServiceAcceptanceUninstallPlan()
    {
        var binary = ReadValidatedBinary();
        using var scm = OpenManager(SC_MANAGER_CONNECT);
        using var service = OpenAcceptanceService(scm, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
        var snapshot = ReadSnapshot(service);
        RequireAcceptanceIdentity(snapshot);
        if (snapshot.State != SERVICE_STOPPED)
            throw new InvalidOperationException("Acceptance service must be Stopped before an uninstall plan can be created.");

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["serviceName"] = AcceptanceServiceName,
            ["binaryPath"] = binary.Path,
            ["binarySha256"] = binary.Sha256,
            ["configFingerprint"] = snapshot.ConfigFingerprint,
            ["expectedState"] = "Stopped"
        };
        var summary = $"Uninstall dedicated V4 acceptance Windows service {AcceptanceServiceName} at {binary.Path} (sha256={binary.Sha256[..12]})";
        return CreatePlan("service-acceptance-uninstall", parameters, RiskClass.High, summary);
    }

    [McpServerTool(Name = "service_acceptance_uninstall_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared service/service-acceptance-uninstall plan using only the native Windows Service Control Manager DeleteService API. The fixed service identity, Stopped state, exact acceptance executable, configuration fingerprint, and executable SHA-256 are rechecked before deletion. Arbitrary service deletion, PowerShell, cmd, sc.exe, WMI, and generic command execution are not supported.")]
    public static AcceptanceServiceExecutionResult ServiceAcceptanceUninstallExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "service-acceptance-uninstall", operation, target, summary, riskClass);
        RequireFixedPlanIdentity(plan);

        var binary = ReadValidatedBinary();
        if (!string.Equals(binary.Sha256, RequireParameter(plan, "binarySha256"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Acceptance service executable SHA-256 changed after plan creation.");

        using var scm = OpenManager(SC_MANAGER_CONNECT);
        using var service = OpenAcceptanceService(scm, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | DELETE);
        var snapshot = ReadSnapshot(service);
        RequireAcceptanceIdentity(snapshot);
        if (snapshot.State != SERVICE_STOPPED)
            throw new InvalidOperationException("Acceptance service state changed after plan creation; it must still be Stopped.");
        if (!string.Equals(snapshot.ConfigFingerprint, RequireParameter(plan, "configFingerprint"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Acceptance service configuration changed after plan creation.");

        try
        {
            if (!DeleteService(service))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to delete the dedicated acceptance Windows service.");

            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, binary.Sha256, snapshot.ConfigFingerprint }, "executed");
            return new AcceptanceServiceExecutionResult(plan.PlanId, plan.Operation, AcceptanceServiceName, "DeleteRequested", binary.Sha256, snapshot.ConfigFingerprint, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    private static SignedPlan CreatePlan(string operation, Dictionary<string, string> parameters, RiskClass riskClass, string summary)
    {
        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var unsigned = new SignedPlan(1, planId, approvalCode, "service", operation, AcceptanceServiceName, parameters, riskClass, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    private static void RequireIntentMatch(SignedPlan plan, string expectedOperation, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "service", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, AcceptanceServiceName, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.Ordinal) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }

    private static void RequireFixedPlanIdentity(SignedPlan plan)
    {
        if (!string.Equals(RequireParameter(plan, "serviceName"), AcceptanceServiceName, StringComparison.Ordinal) ||
            !string.Equals(Path.GetFullPath(RequireParameter(plan, "binaryPath")), Path.GetFullPath(AcceptanceBinary), StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Acceptance service identity mismatch.");
    }

    private static BinarySnapshot ReadValidatedBinary()
    {
        var path = Path.GetFullPath(AcceptanceBinary);
        if (!File.Exists(path))
            throw new FileNotFoundException("Dedicated acceptance service executable does not exist.", path);
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Dedicated acceptance service executable must not be a reparse point.");
        var info = new FileInfo(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var sha256 = Convert.ToHexString(SHA256.HashData(stream));
        return new BinarySnapshot(path, sha256, info.Length);
    }

    private static bool ServiceExists(SafeServiceHandle scm)
    {
        using var service = OpenServiceW(scm, AcceptanceServiceName, SERVICE_QUERY_STATUS);
        if (!service.IsInvalid)
            return true;
        var error = Marshal.GetLastWin32Error();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST)
            return false;
        if (error == ERROR_SERVICE_MARKED_FOR_DELETE)
            throw new InvalidOperationException("Acceptance service is still marked for deletion.");
        throw new Win32Exception(error, "Unable to determine whether the acceptance Windows service exists.");
    }

    private static SafeServiceHandle OpenAcceptanceService(SafeServiceHandle scm, uint access)
    {
        var service = OpenServiceW(scm, AcceptanceServiceName, access);
        if (service.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Unable to open acceptance Windows service {AcceptanceServiceName}.");
        return service;
    }

    private static ServiceSnapshot ReadSnapshot(SafeServiceHandle service)
    {
        var status = new SERVICE_STATUS_PROCESS();
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, ref status, Marshal.SizeOf<SERVICE_STATUS_PROCESS>(), out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to query acceptance Windows service status.");

        _ = QueryServiceConfigW(service, IntPtr.Zero, 0, out var bytesNeeded);
        var error = Marshal.GetLastWin32Error();
        if (error != ERROR_INSUFFICIENT_BUFFER || bytesNeeded <= 0)
            throw new Win32Exception(error, "Unable to query acceptance Windows service configuration size.");

        var buffer = Marshal.AllocHGlobal(bytesNeeded);
        try
        {
            if (!QueryServiceConfigW(service, buffer, bytesNeeded, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to query acceptance Windows service configuration.");
            var config = Marshal.PtrToStructure<QUERY_SERVICE_CONFIG>(buffer);
            var binaryPath = Marshal.PtrToStringUni(config.lpBinaryPathName) ?? string.Empty;
            var displayName = Marshal.PtrToStringUni(config.lpDisplayName) ?? string.Empty;
            var account = Marshal.PtrToStringUni(config.lpServiceStartName) ?? string.Empty;
            var effectiveBinary = ParseExactExecutable(binaryPath);
            var fingerprintText = string.Join("\n", AcceptanceServiceName, displayName, binaryPath, config.dwStartType.ToString(System.Globalization.CultureInfo.InvariantCulture), account);
            var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fingerprintText)));
            return new ServiceSnapshot(status.dwCurrentState, config.dwStartType, displayName, account, binaryPath, effectiveBinary, fingerprint);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void RequireAcceptanceIdentity(ServiceSnapshot snapshot)
    {
        if (!string.Equals(snapshot.DisplayName, AcceptanceDisplayName, StringComparison.Ordinal) ||
            snapshot.StartType != SERVICE_DEMAND_START ||
            !string.Equals(Path.GetFullPath(snapshot.EffectiveBinaryPath), Path.GetFullPath(AcceptanceBinary), StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Existing service does not match the dedicated V4 acceptance service identity.");
    }

    private static string ParseExactExecutable(string commandLine)
    {
        var argv = CommandLineToArgvW(Environment.ExpandEnvironmentVariables(commandLine), out var argc);
        if (argv == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to parse acceptance service binary path.");
        try
        {
            if (argc != 1)
                throw new UnauthorizedAccessException("Acceptance service binary path must contain exactly one executable and no arguments.");
            var item = Marshal.ReadIntPtr(argv, 0);
            var executable = Marshal.PtrToStringUni(item) ?? string.Empty;
            if (!Path.IsPathFullyQualified(executable))
                throw new UnauthorizedAccessException("Acceptance service executable path must be absolute.");
            return Path.GetFullPath(executable);
        }
        finally
        {
            LocalFree(argv);
        }
    }

    private static SafeServiceHandle OpenManager(uint access)
    {
        var manager = OpenSCManagerW(null, null, access);
        if (manager.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to open the Windows Service Control Manager.");
        return manager;
    }

    private static string RequireParameter(SignedPlan plan, string key)
    {
        if (!plan.Parameters.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
            throw new InvalidDataException($"{key} parameter is required.");
        return value;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeServiceHandle OpenSCManagerW(string? lpMachineName, string? lpDatabaseName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeServiceHandle OpenServiceW(SafeServiceHandle hSCManager, string lpServiceName, uint dwDesiredAccess);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeServiceHandle CreateServiceW(
        SafeServiceHandle hSCManager,
        string lpServiceName,
        string lpDisplayName,
        uint dwDesiredAccess,
        uint dwServiceType,
        uint dwStartType,
        uint dwErrorControl,
        string lpBinaryPathName,
        string? lpLoadOrderGroup,
        IntPtr lpdwTagId,
        string? lpDependencies,
        string? lpServiceStartName,
        string? lpPassword);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteService(SafeServiceHandle hService);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(SafeServiceHandle hService, int InfoLevel, ref SERVICE_STATUS_PROCESS lpBuffer, int cbBufSize, out int pcbBytesNeeded);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfigW(SafeServiceHandle hService, IntPtr lpServiceConfig, int cbBufSize, out int pcbBytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CommandLineToArgvW(string lpCmdLine, out int pNumArgs);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS_PROCESS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
        public uint dwProcessId;
        public uint dwServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct QUERY_SERVICE_CONFIG
    {
        public uint dwServiceType;
        public uint dwStartType;
        public uint dwErrorControl;
        public IntPtr lpBinaryPathName;
        public IntPtr lpLoadOrderGroup;
        public uint dwTagId;
        public IntPtr lpDependencies;
        public IntPtr lpServiceStartName;
        public IntPtr lpDisplayName;
    }

    private sealed class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeServiceHandle() : base(true) { }
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    private sealed record BinarySnapshot(string Path, string Sha256, long Bytes);
    private sealed record ServiceSnapshot(uint State, uint StartType, string DisplayName, string Account, string BinaryPath, string EffectiveBinaryPath, string ConfigFingerprint);
}

public sealed record AcceptanceServiceExecutionResult(
    string PlanId,
    string Operation,
    string ServiceName,
    string State,
    string BinarySha256,
    string ConfigFingerprint,
    DateTimeOffset ExecutedUtc);
