using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;
using YowThi.DevelopmentAgent3.Security;

namespace YowThi.DevelopmentAgent3.Windows;

[McpServerToolType]
public static class ServiceTools
{
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    private static readonly string[] AllowedMutationRoots =
    {
        @"C:\ProgramData\YowThi",
        @"C:\Dev\YowThi-ERP-Dev-v4"
    };

    private const string ProductionRoot = @"C:\yowthi-erp";
    private const string DotnetExe = @"C:\Program Files\dotnet\dotnet.exe";
    private const string AcceptanceServiceName = "YowThiAgent3AcceptanceService";
    private const string AcceptanceDisplayName = "YowThi Agent 3 Acceptance Service";
    private const string AcceptanceBinaryPath = @"C:\Dev\YowThi-ERP-Dev-v4\acceptance\windows-service-acceptance-build-v1\YowThi.ServiceAcceptance.exe";
    private const string AcceptanceBinarySha256 = "FCBDB33F6ED0DFE4A0F47A03FB24F14B1D6364CBDE79D32582C0F4180AF8052C";

    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SC_MANAGER_CREATE_SERVICE = 0x0002;
    private const uint SC_MANAGER_ENUMERATE_SERVICE = 0x0004;
    private const uint SERVICE_QUERY_CONFIG = 0x0001;
    private const uint SERVICE_QUERY_STATUS = 0x0004;
    private const uint SERVICE_START = 0x0010;
    private const uint SERVICE_STOP = 0x0020;
    private const uint DELETE = 0x00010000;
    private const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
    private const uint SERVICE_WIN32 = 0x00000030;
    private const uint SERVICE_STATE_ALL = 0x00000003;
    private const uint SERVICE_CONTROL_STOP = 0x00000001;
    private const uint SERVICE_STOPPED = 0x00000001;
    private const uint SERVICE_START_PENDING = 0x00000002;
    private const uint SERVICE_STOP_PENDING = 0x00000003;
    private const uint SERVICE_RUNNING = 0x00000004;
    private const uint SERVICE_CONTINUE_PENDING = 0x00000005;
    private const uint SERVICE_PAUSE_PENDING = 0x00000006;
    private const uint SERVICE_PAUSED = 0x00000007;
    private const uint SERVICE_DEMAND_START = 0x00000003;
    private const uint SERVICE_ERROR_NORMAL = 0x00000001;
    private const int SC_ENUM_PROCESS_INFO = 0;
    private const int SC_STATUS_PROCESS_INFO = 0;
    private const int ERROR_MORE_DATA = 234;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;
    private const int ERROR_SERVICE_DOES_NOT_EXIST = 1060;
    private const int ERROR_SERVICE_MARKED_FOR_DELETE = 1072;

    [McpServerTool(Name = "service_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List Windows Win32 services and their current states using the native Windows Service Control Manager API. This is read-only. No PowerShell, cmd, sc.exe, WMI command execution, or generic command executor is used.")]
    public static IReadOnlyList<ServiceListItem> ServiceList()
    {
        using var scm = OpenManager(SC_MANAGER_ENUMERATE_SERVICE);
        var bytesNeeded = 0;
        var servicesReturned = 0;
        if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, IntPtr.Zero, 0, out bytesNeeded, out servicesReturned, IntPtr.Zero, null))
            return Array.Empty<ServiceListItem>();

        var error = Marshal.GetLastWin32Error();
        if (error != ERROR_MORE_DATA || bytesNeeded <= 0)
            throw new Win32Exception(error, "Unable to enumerate Windows services.");

        var buffer = Marshal.AllocHGlobal(bytesNeeded);
        try
        {
            if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buffer, bytesNeeded, out bytesNeeded, out servicesReturned, IntPtr.Zero, null))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to enumerate Windows services.");

            var size = Marshal.SizeOf<ENUM_SERVICE_STATUS_PROCESS>();
            var result = new List<ServiceListItem>(servicesReturned);
            for (var i = 0; i < servicesReturned; i++)
            {
                var item = Marshal.PtrToStructure<ENUM_SERVICE_STATUS_PROCESS>(IntPtr.Add(buffer, i * size));
                var serviceName = Marshal.PtrToStringUni(item.lpServiceName) ?? string.Empty;
                var displayName = Marshal.PtrToStringUni(item.lpDisplayName) ?? serviceName;
                result.Add(new ServiceListItem(serviceName, displayName, StateName(item.ServiceStatusProcess.dwCurrentState), item.ServiceStatusProcess.dwProcessId));
            }

            return result.OrderBy(x => x.ServiceName, StringComparer.OrdinalIgnoreCase).ToArray();
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [McpServerTool(Name = "service_status", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read one Windows service status and configuration using the native Windows Service Control Manager API. The result includes binary path, start type, account, process ID, a configuration fingerprint, and whether the service is eligible for YowThi-owned mutation. This is read-only.")]
    public static ServiceStatusResult ServiceStatus(string serviceName)
    {
        serviceName = ValidateServiceName(serviceName);
        using var scm = OpenManager(SC_MANAGER_CONNECT);
        using var service = OpenServiceChecked(scm, serviceName, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
        var snapshot = ReadSnapshot(serviceName, service);
        return ToStatusResult(snapshot);
    }

    [McpServerTool(Name = "service_install_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to install only the dedicated YowThi Agent 3 acceptance Windows service. The service name, display name, Manual start type, LocalSystem account, fixed acceptance executable path, and executable SHA-256 are constrained and sealed. Arbitrary service names, binaries, accounts, start types, commands, and protected production paths are not accepted. Native Windows Service Control Manager APIs are used; no PowerShell, cmd, or sc.exe is used.")]
    public static SignedPlan ServiceInstallPlan(string serviceName)
    {
        serviceName = ValidateAcceptanceServiceName(serviceName);
        var binarySha256 = ValidateAcceptanceBinary();
        using var scm = OpenManager(SC_MANAGER_CONNECT);
        EnsureServiceAbsent(scm, serviceName);

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["serviceName"] = serviceName,
            ["displayName"] = AcceptanceDisplayName,
            ["binaryPath"] = AcceptanceBinaryPath,
            ["binarySha256"] = binarySha256,
            ["startType"] = SERVICE_DEMAND_START.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["serviceAccount"] = "LocalSystem"
        };
        var summary = $"Install dedicated V4 acceptance Windows service {serviceName} from {AcceptanceBinaryPath} (sha256={binarySha256[..12]})";
        return CreatePlan("service-install", serviceName, parameters, RiskClass.High, summary);
    }

    [McpServerTool(Name = "service_install_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared service/service-install plan for only the dedicated YowThi Agent 3 acceptance Windows service. The exact service identity, fixed executable path and SHA-256, Manual start type, LocalSystem account, service absence, and protected-path rules are rechecked before CreateServiceW is called. No arbitrary service installation, PowerShell, cmd, sc.exe, or generic command executor is supported.")]
    public static ServiceRegistrationExecutionResult ServiceInstallExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "service-install", operation, target, summary, riskClass);
        var serviceName = ValidateAcceptanceServiceName(RequireParameter(plan, "serviceName"));
        RevalidateAcceptancePlanConstants(plan);
        var actualSha256 = ValidateAcceptanceBinary();
        if (!string.Equals(actualSha256, RequireParameter(plan, "binarySha256"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Acceptance service binary SHA-256 changed after plan creation.");

        using var scm = OpenManager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
        EnsureServiceAbsent(scm, serviceName);
        using var service = CreateServiceW(
            scm,
            AcceptanceServiceName,
            AcceptanceDisplayName,
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | DELETE,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            $"\"{AcceptanceBinaryPath}\"",
            null,
            IntPtr.Zero,
            null,
            null,
            null);
        if (service.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Unable to install Windows service {serviceName}.");

        Store.Consume(planId);
        try
        {
            var snapshot = ReadSnapshot(serviceName, service);
            RequireAcceptanceRegistration(snapshot, requireStopped: true);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, snapshot.ConfigFingerprint, binarySha256 = actualSha256 }, "executed");
            return new ServiceRegistrationExecutionResult(plan.PlanId, plan.Operation, serviceName, AcceptanceBinaryPath, snapshot.ConfigFingerprint, "installed", DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            _ = DeleteService(service);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message, rollback = "DeleteService attempted" }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "service_uninstall_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to remove only the Windows Service Control Manager registration for the dedicated YowThi Agent 3 acceptance service. This cleanup removes only the fixed acceptance service registration; it does not delete the executable or any files. The service must be Stopped and must still match the fixed acceptance identity, configuration, effective executable target, and executable SHA-256. Arbitrary or production-linked services cannot be targeted.")]
    public static SignedPlan ServiceUninstallPlan(string serviceName)
    {
        serviceName = ValidateAcceptanceServiceName(serviceName);
        var binarySha256 = ValidateAcceptanceBinary();
        using var scm = OpenManager(SC_MANAGER_CONNECT);
        using var service = OpenServiceChecked(scm, serviceName, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
        var snapshot = ReadSnapshot(serviceName, service);
        RequireAcceptanceRegistration(snapshot, requireStopped: true);

        var parameters = BuildMutationParameters(snapshot);
        parameters["displayName"] = AcceptanceDisplayName;
        parameters["binaryPath"] = AcceptanceBinaryPath;
        parameters["binarySha256"] = binarySha256;
        parameters["startType"] = SERVICE_DEMAND_START.ToString(System.Globalization.CultureInfo.InvariantCulture);
        parameters["serviceAccount"] = "LocalSystem";
        var summary = $"Uninstall dedicated V4 acceptance Windows service {serviceName} ({AcceptanceBinaryPath}, sha256={binarySha256[..12]})";
        return CreatePlan("service-uninstall", serviceName, parameters, RiskClass.High, summary);
    }

    [McpServerTool(Name = "service_uninstall_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared service/service-uninstall plan to remove only the Windows Service Control Manager registration for the dedicated YowThi Agent 3 acceptance service. The executable and all files are left untouched. Exact service identity, Stopped state, configuration fingerprint, effective image target, fixed executable SHA-256, Manual start type, LocalSystem account, and protected-path rules are rechecked before the fixed service registration is removed through the native Windows Service Control Manager API. Arbitrary service removal, PowerShell, cmd, sc.exe, and generic command execution are not supported.")]
    public static async Task<ServiceRegistrationExecutionResult> ServiceUninstallExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "service-uninstall", operation, target, summary, riskClass);
        var serviceName = ValidateAcceptanceServiceName(RequireParameter(plan, "serviceName"));
        RevalidateAcceptancePlanConstants(plan);
        var actualSha256 = ValidateAcceptanceBinary();
        if (!string.Equals(actualSha256, RequireParameter(plan, "binarySha256"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Acceptance service binary SHA-256 changed after plan creation.");

        using var scm = OpenManager(SC_MANAGER_CONNECT);
        using var service = OpenServiceChecked(scm, serviceName, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | DELETE);
        var before = ReadSnapshot(serviceName, service);
        RequireAcceptanceRegistration(before, requireStopped: true);
        RevalidateMutationSnapshot(plan, before, SERVICE_STOPPED, requireSameProcessId: false);

        try
        {
            if (!DeleteService(service))
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Unable to uninstall Windows service {serviceName}.");

            Store.Consume(planId);
            service.Dispose();
            await WaitForServiceAbsentAsync(scm, serviceName, TimeSpan.FromSeconds(15));
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, before.ConfigFingerprint, binarySha256 = actualSha256 }, "executed");
            return new ServiceRegistrationExecutionResult(plan.PlanId, plan.Operation, serviceName, AcceptanceBinaryPath, before.ConfigFingerprint, "uninstalled", DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "service_start_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to start one stopped YowThi-owned Windows service using the native Windows Service Control Manager API. Mutation is allowed only when the service name is YowThi-prefixed and its effective executable or dotnet-hosted DLL is under C:\\ProgramData\\YowThi or C:\\Dev\\YowThi-ERP-Dev-v4. Services tied to C:\\yowthi-erp are blocked. Configuration fingerprint and stopped state are sealed.")]
    public static SignedPlan ServiceStartPlan(string serviceName)
    {
        serviceName = ValidateServiceName(serviceName);
        using var scm = OpenManager(SC_MANAGER_CONNECT);
        using var service = OpenServiceChecked(scm, serviceName, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
        var snapshot = ReadSnapshot(serviceName, service);
        RequireMutationEligible(snapshot);
        if (snapshot.State != SERVICE_STOPPED)
            throw new InvalidOperationException($"Service must be stopped before a start plan can be created. Current state: {StateName(snapshot.State)}");

        var parameters = BuildMutationParameters(snapshot);
        var summary = $"Start YowThi-owned Windows service {snapshot.ServiceName} ({snapshot.EffectiveImageTarget})";
        return CreatePlan("service-start", snapshot.ServiceName, parameters, RiskClass.High, summary);
    }

    [McpServerTool(Name = "service_start_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared service/service-start plan through the native Windows Service Control Manager API. Service identity, YowThi ownership, protected-production exclusion, configuration fingerprint, stopped state, effective image target, and process state are rechecked before StartService is called. No PowerShell, cmd, sc.exe, or generic command executor is used.")]
    public static async Task<ServiceExecutionResult> ServiceStartExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "service-start", operation, target, summary, riskClass);
        var serviceName = RequireParameter(plan, "serviceName");

        using var scm = OpenManager(SC_MANAGER_CONNECT);
        using var service = OpenServiceChecked(scm, serviceName, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_START);
        var before = ReadSnapshot(serviceName, service);
        RevalidateMutationSnapshot(plan, before, SERVICE_STOPPED, requireSameProcessId: false);

        try
        {
            if (!StartServiceW(service, 0, null))
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Unable to start service {serviceName}.");

            Store.Consume(planId);
            var after = await WaitForStateAsync(serviceName, service, SERVICE_RUNNING, TimeSpan.FromSeconds(45));
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, before = StateName(before.State), after = StateName(after.dwCurrentState), after.dwProcessId }, "executed");
            return new ServiceExecutionResult(plan.PlanId, plan.Operation, serviceName, StateName(before.State), StateName(after.dwCurrentState), after.dwProcessId, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "service_stop_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to stop one running YowThi-owned Windows service using the native Windows Service Control Manager API. Mutation is allowed only when the service name is YowThi-prefixed and its effective executable or dotnet-hosted DLL is under C:\\ProgramData\\YowThi or C:\\Dev\\YowThi-ERP-Dev-v4. Services tied to C:\\yowthi-erp are blocked. Configuration fingerprint, running state, and process ID are sealed.")]
    public static SignedPlan ServiceStopPlan(string serviceName)
    {
        serviceName = ValidateServiceName(serviceName);
        using var scm = OpenManager(SC_MANAGER_CONNECT);
        using var service = OpenServiceChecked(scm, serviceName, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
        var snapshot = ReadSnapshot(serviceName, service);
        RequireMutationEligible(snapshot);
        if (snapshot.State != SERVICE_RUNNING)
            throw new InvalidOperationException($"Service must be running before a stop plan can be created. Current state: {StateName(snapshot.State)}");
        if (snapshot.ProcessId == 0)
            throw new InvalidOperationException("Running service did not report a process ID.");

        var parameters = BuildMutationParameters(snapshot);
        var summary = $"Stop YowThi-owned Windows service {snapshot.ServiceName} ({snapshot.EffectiveImageTarget}, pid={snapshot.ProcessId})";
        return CreatePlan("service-stop", snapshot.ServiceName, parameters, RiskClass.High, summary);
    }

    [McpServerTool(Name = "service_stop_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared service/service-stop plan through the native Windows Service Control Manager API. Service identity, YowThi ownership, protected-production exclusion, configuration fingerprint, running state, effective image target, and process ID are rechecked before SERVICE_CONTROL_STOP is sent. No PowerShell, cmd, sc.exe, or generic command executor is used.")]
    public static async Task<ServiceExecutionResult> ServiceStopExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "service-stop", operation, target, summary, riskClass);
        var serviceName = RequireParameter(plan, "serviceName");

        using var scm = OpenManager(SC_MANAGER_CONNECT);
        using var service = OpenServiceChecked(scm, serviceName, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_STOP);
        var before = ReadSnapshot(serviceName, service);
        RevalidateMutationSnapshot(plan, before, SERVICE_RUNNING, requireSameProcessId: true);

        try
        {
            var nativeStatus = new SERVICE_STATUS();
            if (!ControlService(service, SERVICE_CONTROL_STOP, ref nativeStatus))
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Unable to stop service {serviceName}.");

            Store.Consume(planId);
            var after = await WaitForStateAsync(serviceName, service, SERVICE_STOPPED, TimeSpan.FromSeconds(45));
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, before = StateName(before.State), after = StateName(after.dwCurrentState), before.ProcessId }, "executed");
            return new ServiceExecutionResult(plan.PlanId, plan.Operation, serviceName, StateName(before.State), StateName(after.dwCurrentState), after.dwProcessId, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    private static Dictionary<string, string> BuildMutationParameters(ServiceSnapshot snapshot) => new(StringComparer.Ordinal)
    {
        ["serviceName"] = snapshot.ServiceName,
        ["configFingerprint"] = snapshot.ConfigFingerprint,
        ["expectedState"] = snapshot.State.ToString(System.Globalization.CultureInfo.InvariantCulture),
        ["effectiveImageTarget"] = snapshot.EffectiveImageTarget ?? string.Empty,
        ["processId"] = snapshot.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture)
    };

    private static SignedPlan CreatePlan(string operation, string target, Dictionary<string, string> parameters, RiskClass riskClass, string summary)
    {
        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var unsigned = new SignedPlan(1, planId, approvalCode, "service", operation, target, parameters, riskClass, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    private static void RevalidateMutationSnapshot(SignedPlan plan, ServiceSnapshot snapshot, uint requiredState, bool requireSameProcessId)
    {
        RequireMutationEligible(snapshot);
        var expectedFingerprint = RequireParameter(plan, "configFingerprint");
        var expectedState = uint.Parse(RequireParameter(plan, "expectedState"), System.Globalization.CultureInfo.InvariantCulture);
        var expectedTarget = RequireParameter(plan, "effectiveImageTarget");
        var expectedProcessId = uint.Parse(RequireParameter(plan, "processId"), System.Globalization.CultureInfo.InvariantCulture);

        if (expectedState != requiredState || snapshot.State != requiredState)
            throw new InvalidOperationException($"Service state changed after plan creation. Expected {StateName(requiredState)}, actual {StateName(snapshot.State)}.");
        if (!string.Equals(expectedFingerprint, snapshot.ConfigFingerprint, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Service configuration changed after plan creation.");
        if (!string.Equals(expectedTarget, snapshot.EffectiveImageTarget, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Service effective image target changed after plan creation.");
        if (requireSameProcessId && expectedProcessId != snapshot.ProcessId)
            throw new InvalidOperationException("Service process ID changed after plan creation.");
    }

    private static void RevalidateAcceptancePlanConstants(SignedPlan plan)
    {
        if (!string.Equals(RequireParameter(plan, "serviceName"), AcceptanceServiceName, StringComparison.Ordinal) ||
            !string.Equals(RequireParameter(plan, "displayName"), AcceptanceDisplayName, StringComparison.Ordinal) ||
            !string.Equals(NormalizeAbsolutePath(RequireParameter(plan, "binaryPath")), AcceptanceBinaryPath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(RequireParameter(plan, "binarySha256"), AcceptanceBinarySha256, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(RequireParameter(plan, "startType"), SERVICE_DEMAND_START.ToString(System.Globalization.CultureInfo.InvariantCulture), StringComparison.Ordinal) ||
            !string.Equals(RequireParameter(plan, "serviceAccount"), "LocalSystem", StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Acceptance service plan constants do not match the fixed V4 acceptance service contract.");
    }

    private static void RequireAcceptanceRegistration(ServiceSnapshot snapshot, bool requireStopped)
    {
        RequireMutationEligible(snapshot);
        if (!string.Equals(snapshot.ServiceName, AcceptanceServiceName, StringComparison.Ordinal) ||
            !string.Equals(snapshot.DisplayName, AcceptanceDisplayName, StringComparison.Ordinal) ||
            snapshot.StartType != SERVICE_DEMAND_START ||
            !string.Equals(snapshot.ServiceAccount, "LocalSystem", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(snapshot.EffectiveImageTarget, AcceptanceBinaryPath, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Windows service does not match the fixed V4 acceptance service registration contract.");
        if (requireStopped && snapshot.State != SERVICE_STOPPED)
            throw new InvalidOperationException($"Acceptance service must be Stopped. Current state: {StateName(snapshot.State)}.");
    }

    private static string ValidateAcceptanceServiceName(string serviceName)
    {
        serviceName = ValidateServiceName(serviceName);
        if (!string.Equals(serviceName, AcceptanceServiceName, StringComparison.Ordinal))
            throw new UnauthorizedAccessException($"Only the dedicated acceptance service {AcceptanceServiceName} is allowed by this registration capability.");
        return serviceName;
    }

    private static string ValidateAcceptanceBinary()
    {
        var binaryPath = NormalizeAbsolutePath(AcceptanceBinaryPath);
        if (!IsUnderAllowedMutationRoot(binaryPath))
            throw new UnauthorizedAccessException("Acceptance service binary is outside approved mutation roots.");
        if (!File.Exists(binaryPath))
            throw new FileNotFoundException("Acceptance service binary does not exist.", binaryPath);
        var attributes = File.GetAttributes(binaryPath);
        if ((attributes & FileAttributes.Directory) != 0 || (attributes & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Acceptance service binary must be a regular non-reparse-point file.");
        using var stream = new FileStream(binaryPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var actualSha256 = Convert.ToHexString(SHA256.HashData(stream));
        if (!string.Equals(actualSha256, AcceptanceBinarySha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException($"Acceptance service binary SHA-256 mismatch. Expected {AcceptanceBinarySha256}, actual {actualSha256}.");
        return actualSha256;
    }

    private static void EnsureServiceAbsent(SafeServiceHandle scm, string serviceName)
    {
        using var probe = OpenServiceW(scm, serviceName, SERVICE_QUERY_STATUS);
        if (!probe.IsInvalid)
            throw new InvalidOperationException($"Windows service {serviceName} already exists.");
        var error = Marshal.GetLastWin32Error();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST)
            return;
        if (error == ERROR_SERVICE_MARKED_FOR_DELETE)
            throw new InvalidOperationException($"Windows service {serviceName} is still marked for deletion.");
        throw new Win32Exception(error, $"Unable to verify that Windows service {serviceName} is absent.");
    }

    private static async Task WaitForServiceAbsentAsync(SafeServiceHandle scm, string serviceName, TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            using var probe = OpenServiceW(scm, serviceName, SERVICE_QUERY_STATUS);
            if (probe.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                if (error == ERROR_SERVICE_DOES_NOT_EXIST)
                    return;
                if (error != ERROR_SERVICE_MARKED_FOR_DELETE)
                    throw new Win32Exception(error, $"Unable to verify deletion of Windows service {serviceName}.");
            }
            await Task.Delay(250);
        }
        throw new TimeoutException($"Windows service {serviceName} did not disappear from the SCM database within {timeout.TotalSeconds:0} seconds.");
    }

    private static ServiceStatusResult ToStatusResult(ServiceSnapshot snapshot) => new(
        snapshot.ServiceName,
        snapshot.DisplayName,
        StateName(snapshot.State),
        snapshot.ProcessId,
        StartTypeName(snapshot.StartType),
        snapshot.BinaryPath,
        snapshot.ServiceAccount,
        snapshot.ConfigFingerprint,
        snapshot.MutationEligible,
        snapshot.EligibilityReason,
        snapshot.EffectiveImageTarget);

    private static ServiceSnapshot ReadSnapshot(string serviceName, SafeServiceHandle service)
    {
        var status = QueryStatus(service);
        var config = QueryConfig(service);
        var displayName = string.IsNullOrWhiteSpace(config.DisplayName) ? serviceName : config.DisplayName;
        var (eligible, reason, effectiveTarget) = EvaluateMutationEligibility(serviceName, config.BinaryPath);
        var fingerprintText = string.Join("\n",
            serviceName,
            displayName,
            config.BinaryPath,
            config.StartType.ToString(System.Globalization.CultureInfo.InvariantCulture),
            config.ServiceAccount);
        var fingerprint = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fingerprintText)));

        return new ServiceSnapshot(serviceName, displayName, status.dwCurrentState, status.dwProcessId, config.StartType, config.BinaryPath, config.ServiceAccount, fingerprint, eligible, reason, effectiveTarget);
    }

    private static (bool Eligible, string Reason, string? EffectiveTarget) EvaluateMutationEligibility(string serviceName, string binaryPath)
    {
        if (!serviceName.StartsWith("YowThi", StringComparison.OrdinalIgnoreCase))
            return (false, "Service name is not YowThi-prefixed.", null);
        if (string.IsNullOrWhiteSpace(binaryPath))
            return (false, "Service binary path is empty.", null);
        if (binaryPath.Contains(ProductionRoot, StringComparison.OrdinalIgnoreCase))
            return (false, "Service configuration references the protected production root C:\\yowthi-erp.", null);

        string[] argv;
        try
        {
            argv = ParseWindowsCommandLine(Environment.ExpandEnvironmentVariables(binaryPath));
        }
        catch (Exception ex)
        {
            return (false, $"Service binary path could not be parsed safely: {ex.Message}", null);
        }

        if (argv.Length == 0)
            return (false, "Service binary path contains no executable.", null);

        string executable;
        try
        {
            executable = NormalizeAbsolutePath(argv[0]);
        }
        catch
        {
            return (false, "Service executable path is not an absolute local path.", null);
        }

        if (IsUnderAllowedMutationRoot(executable))
            return (true, "YowThi-owned service executable is under an approved mutation root.", executable);

        if (string.Equals(executable, DotnetExe, StringComparison.OrdinalIgnoreCase) && argv.Length >= 2)
        {
            try
            {
                var dll = NormalizeAbsolutePath(argv[1]);
                if (dll.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && IsUnderAllowedMutationRoot(dll))
                    return (true, "YowThi-owned dotnet-hosted service DLL is under an approved mutation root.", dll);
            }
            catch
            {
            }
        }

        return (false, "Service executable is outside the approved YowThi mutation roots.", null);
    }

    private static void RequireMutationEligible(ServiceSnapshot snapshot)
    {
        if (!snapshot.MutationEligible || string.IsNullOrWhiteSpace(snapshot.EffectiveImageTarget))
            throw new UnauthorizedAccessException($"Service mutation is blocked: {snapshot.EligibilityReason}");
    }

    private static bool IsUnderAllowedMutationRoot(string path)
    {
        if (IsUnderRoot(path, ProductionRoot))
            return false;
        return AllowedMutationRoots.Any(root => IsUnderRoot(path, root));
    }

    private static bool IsUnderRoot(string path, string root)
    {
        var normalizedPath = NormalizeAbsolutePath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var normalizedRoot = NormalizeAbsolutePath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return string.Equals(normalizedPath, normalizedRoot, StringComparison.OrdinalIgnoreCase) ||
               normalizedPath.StartsWith(normalizedRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeAbsolutePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("Path is empty.", nameof(value));
        var expanded = Environment.ExpandEnvironmentVariables(value.Trim());
        if (!Path.IsPathFullyQualified(expanded))
            throw new ArgumentException("Path must be absolute.", nameof(value));
        return Path.GetFullPath(expanded);
    }

    private static string[] ParseWindowsCommandLine(string commandLine)
    {
        var argvPtr = CommandLineToArgvW(commandLine, out var argc);
        if (argvPtr == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Command line parsing failed.");
        try
        {
            var args = new string[argc];
            for (var i = 0; i < argc; i++)
            {
                var itemPtr = Marshal.ReadIntPtr(argvPtr, i * IntPtr.Size);
                args[i] = Marshal.PtrToStringUni(itemPtr) ?? string.Empty;
            }
            return args;
        }
        finally
        {
            LocalFree(argvPtr);
        }
    }

    private static async Task<SERVICE_STATUS_PROCESS> WaitForStateAsync(string serviceName, SafeServiceHandle service, uint desiredState, TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            var status = QueryStatus(service);
            if (status.dwCurrentState == desiredState)
                return status;
            if (desiredState == SERVICE_RUNNING && status.dwCurrentState == SERVICE_STOPPED)
                throw new InvalidOperationException($"Service {serviceName} returned to Stopped while waiting for Running. Win32ExitCode={status.dwWin32ExitCode}, ServiceSpecificExitCode={status.dwServiceSpecificExitCode}.");
            await Task.Delay(250);
        }
        var final = QueryStatus(service);
        throw new TimeoutException($"Service {serviceName} did not reach {StateName(desiredState)} within {timeout.TotalSeconds:0} seconds. Current state: {StateName(final.dwCurrentState)}.");
    }

    private static SERVICE_STATUS_PROCESS QueryStatus(SafeServiceHandle service)
    {
        var status = new SERVICE_STATUS_PROCESS();
        if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, ref status, Marshal.SizeOf<SERVICE_STATUS_PROCESS>(), out _))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to query Windows service status.");
        return status;
    }

    private static ServiceConfig QueryConfig(SafeServiceHandle service)
    {
        _ = QueryServiceConfigW(service, IntPtr.Zero, 0, out var bytesNeeded);
        var error = Marshal.GetLastWin32Error();
        if (error != ERROR_INSUFFICIENT_BUFFER || bytesNeeded <= 0)
            throw new Win32Exception(error, "Unable to query Windows service configuration size.");

        var buffer = Marshal.AllocHGlobal(bytesNeeded);
        try
        {
            if (!QueryServiceConfigW(service, buffer, bytesNeeded, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to query Windows service configuration.");
            var native = Marshal.PtrToStructure<QUERY_SERVICE_CONFIG>(buffer);
            return new ServiceConfig(
                native.dwStartType,
                Marshal.PtrToStringUni(native.lpBinaryPathName) ?? string.Empty,
                Marshal.PtrToStringUni(native.lpServiceStartName) ?? string.Empty,
                Marshal.PtrToStringUni(native.lpDisplayName) ?? string.Empty);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static SafeServiceHandle OpenManager(uint access)
    {
        var handle = OpenSCManagerW(null, null, access);
        if (handle.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to open the Windows Service Control Manager.");
        return handle;
    }

    private static SafeServiceHandle OpenServiceChecked(SafeServiceHandle scm, string serviceName, uint access)
    {
        var handle = OpenServiceW(scm, serviceName, access);
        if (handle.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"Unable to open Windows service {serviceName}.");
        return handle;
    }

    private static string ValidateServiceName(string serviceName)
    {
        if (string.IsNullOrWhiteSpace(serviceName) || serviceName.Length > 256 || serviceName.Any(char.IsControl) || serviceName.Contains('\0'))
            throw new ArgumentException("Service name is invalid.", nameof(serviceName));
        return serviceName.Trim();
    }

    private static string RequireParameter(SignedPlan plan, string key)
    {
        if (!plan.Parameters.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
            throw new InvalidDataException($"{key} parameter is required.");
        return value;
    }

    private static void RequireIntentMatch(SignedPlan plan, string expectedOperation, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "service", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }

    private static string StateName(uint state) => state switch
    {
        SERVICE_STOPPED => "Stopped",
        SERVICE_START_PENDING => "StartPending",
        SERVICE_STOP_PENDING => "StopPending",
        SERVICE_RUNNING => "Running",
        SERVICE_CONTINUE_PENDING => "ContinuePending",
        SERVICE_PAUSE_PENDING => "PausePending",
        SERVICE_PAUSED => "Paused",
        _ => $"Unknown({state})"
    };

    private static string StartTypeName(uint startType) => startType switch
    {
        0 => "Boot",
        1 => "System",
        2 => "Automatic",
        3 => "Manual",
        4 => "Disabled",
        _ => $"Unknown({startType})"
    };

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

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumServicesStatusExW(
        SafeServiceHandle hSCManager,
        int InfoLevel,
        uint dwServiceType,
        uint dwServiceState,
        IntPtr lpServices,
        int cbBufSize,
        out int pcbBytesNeeded,
        out int lpServicesReturned,
        IntPtr lpResumeHandle,
        string? pszGroupName);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceStatusEx(SafeServiceHandle hService, int InfoLevel, ref SERVICE_STATUS_PROCESS lpBuffer, int cbBufSize, out int pcbBytesNeeded);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryServiceConfigW(SafeServiceHandle hService, IntPtr lpServiceConfig, int cbBufSize, out int pcbBytesNeeded);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartServiceW(SafeServiceHandle hService, int dwNumServiceArgs, string[]? lpServiceArgVectors);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ControlService(SafeServiceHandle hService, uint dwControl, ref SERVICE_STATUS lpServiceStatus);

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
    private struct ENUM_SERVICE_STATUS_PROCESS
    {
        public IntPtr lpServiceName;
        public IntPtr lpDisplayName;
        public SERVICE_STATUS_PROCESS ServiceStatusProcess;
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

    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public uint dwServiceType;
        public uint dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }

    private sealed class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeServiceHandle() : base(true) { }
        protected override bool ReleaseHandle() => CloseServiceHandle(handle);
    }

    private sealed record ServiceConfig(uint StartType, string BinaryPath, string ServiceAccount, string DisplayName);
    private sealed record ServiceSnapshot(
        string ServiceName,
        string DisplayName,
        uint State,
        uint ProcessId,
        uint StartType,
        string BinaryPath,
        string ServiceAccount,
        string ConfigFingerprint,
        bool MutationEligible,
        string EligibilityReason,
        string? EffectiveImageTarget);
}

public sealed record ServiceListItem(string ServiceName, string DisplayName, string State, uint ProcessId);

public sealed record ServiceStatusResult(
    string ServiceName,
    string DisplayName,
    string State,
    uint ProcessId,
    string StartType,
    string BinaryPath,
    string ServiceAccount,
    string ConfigFingerprint,
    bool MutationEligible,
    string EligibilityReason,
    string? EffectiveImageTarget);

public sealed record ServiceExecutionResult(
    string PlanId,
    string Operation,
    string ServiceName,
    string BeforeState,
    string AfterState,
    uint ProcessId,
    DateTimeOffset ExecutedUtc);

public sealed record ServiceRegistrationExecutionResult(
    string PlanId,
    string Operation,
    string ServiceName,
    string BinaryPath,
    string ConfigFingerprint,
    string Outcome,
    DateTimeOffset ExecutedUtc);