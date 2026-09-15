using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Runtime;
using YowThi.DevelopmentAgent3.Windows;

namespace YowThi.DevelopmentAgent3.Inspection;

[McpServerToolType]
public static class V4BootRecoveryStatusTools
{
    private const string SupervisorServiceName = "YowThiV4RuntimeSupervisor";
    private const string SupervisorExe = @"C:\Dev\YowThi-ERP-Dev-v4\runtime-supervisor\current\YowThi.RuntimeSupervisor.exe";
    private const string SupervisorDll = @"C:\Dev\YowThi-ERP-Dev-v4\runtime-supervisor\current\YowThi.RuntimeSupervisor.dll";
    private const string ExpectedSupervisorDllSha256 = "5C312E8B54AC34A23A6017BE1BF8B0C25270DB79073220EA41A39322C1C1D34D";

    private const string BootstrapBackendServiceName = "YowThiDevelopmentAgent";
    private const string BootstrapBackendExe = @"C:\Program Files\YowThi\DevelopmentAgent\YowThi.DevelopmentAgent.exe";

    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string HandoffRoot = @"C:\Dev\YowThi-ERP-Dev-v4\.agent3-handoff";
    private const string ActiveStatePath = @"C:\Dev\YowThi-ERP-Dev-v4\.agent3-handoff\active-runtime.json";
    private const string TransferRoot = @"C:\Dev\YowThi-ERP-Dev-v4\staging\transfer";
    private const string TransferInboxRoot = @"C:\Dev\YowThi-ERP-Dev-v4\staging\transfer\inbox";
    private const string TransferOutboxRoot = @"C:\Dev\YowThi-ERP-Dev-v4\staging\transfer\outbox";

    private const string TunnelExe = @"C:\ProgramData\YowThi\TunnelClient\bin\tunnel-client.exe";
    private const string ExpectedTunnelExeSha256 = "6649169733686805CA16CCCD91774594D0C017FD729C37AD4CE1CD18323D9AE8";
    private const string FormalTunnelProfile = @"C:\ProgramData\YowThi\TunnelClient\profiles\yowthi-erp-dev-v4.yaml";
    private const string ExpectedFormalTunnelProfileSha256 = "8B46DC3AF0DBE713CBEF8ABC2AE864AF780F8DC713CBF011ABC3405F6D0F911F";
    private const string BootstrapTunnelProfile = @"C:\ProgramData\YowThi\TunnelClient\profiles\yowthi-erp-bootstrap-8787-r1.yaml";
    private const string ExpectedBootstrapTunnelProfileSha256 = "303C57D927D1FAFB99D9F58A029F6DC4BF52EB430B04B571B9D339FE9FEDFAAC";

    private const int BootstrapBackendPort = 8787;
    private const int FormalTunnelHealthPort = 8792;
    private const int BootstrapTunnelHealthPort = 8793;
    private const int RuntimePort = 8828;
    private const int ProcessBasicInformation = 0;

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    [McpServerTool(Name = "v4_boot_recovery_status", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read the complete YowThi ERP Dev v4 reboot-recovery acceptance state in one call. It verifies the Automatic LocalSystem Runtime Supervisor, the Automatic Bootstrap backend, active Agent runtime identity, loopback 8828 and 8787 listeners, Formal 8792 and Bootstrap 8793 tunnels with supervisor parent ownership, fixed supervisor/tunnel/profile fingerprints, fixed transfer staging queues, active-runtime state storage traversal, and reboot ownership ordering. Returns accepted plus explicit failure reasons. This is read-only and does not start, stop, restart, mutate, repair, read secrets, execute shells, or access production paths.")]
    public static V4BootRecoveryStatusResult V4BootRecoveryStatus()
    {
        var failures = new List<string>();
        var checkedUtc = DateTimeOffset.UtcNow;
        var approximateBootUtc = checkedUtc - TimeSpan.FromMilliseconds(Environment.TickCount64);

        var supervisorService = ReadAndValidateService(
            SupervisorServiceName,
            SupervisorExe,
            requireLocalSystem: true,
            failures,
            "Runtime Supervisor");

        var bootstrapBackendService = ReadAndValidateService(
            BootstrapBackendServiceName,
            BootstrapBackendExe,
            requireLocalSystem: true,
            failures,
            "Bootstrap backend");

        string? supervisorDllSha256 = null;
        try
        {
            supervisorDllSha256 = HashRegularFile(SupervisorDll);
            if (!string.Equals(supervisorDllSha256, ExpectedSupervisorDllSha256, StringComparison.OrdinalIgnoreCase))
                failures.Add("Supervisor DLL SHA-256 does not match the accepted active-runtime state traversal hardening build.");
        }
        catch (Exception ex)
        {
            failures.Add("Supervisor DLL verification failed: " + FormatError(ex));
        }

        var registry = ToolRegistryIdentity.Current;
        if (registry.ToolCount < 206)
            failures.Add($"Agent tool registry contains {registry.ToolCount} tools; expected at least 206.");
        foreach (var required in new[]
        {
            "v4_boot_recovery_status",
            "acceptance_build_quarantine_plan",
            "acceptance_build_quarantine_execute",
            "acceptance_build_quarantine_restore_plan",
            "acceptance_build_quarantine_restore_execute",
            "v4_runtime_supervisor_service_install_plan",
            "v4_runtime_supervisor_service_install_execute"
        })
        {
            if (!registry.ToolNames.Contains(required, StringComparer.Ordinal))
                failures.Add("Required Agent tool is missing from the authoritative registry: " + required);
        }

        var transferStaging = ReadTransferStagingStatus(failures);

        var activeStateStorage = ReadActiveStateStorageStatus(failures);

        ActiveState? active = null;
        try
        {
            active = ReadActiveState();
            if (active.SchemaVersion != 2)
                failures.Add($"active-runtime schemaVersion is {active.SchemaVersion}, expected 2.");
            if (!PathsEqual(active.Current.RuntimeDll, registry.RuntimeDll))
                failures.Add("active-runtime current DLL does not match the executing Agent runtime DLL.");
            if (!string.Equals(active.Current.RuntimeSha256, registry.RuntimeSha256, StringComparison.OrdinalIgnoreCase))
                failures.Add("active-runtime current SHA-256 does not match the executing Agent runtime SHA-256.");
            if (active.Current.ProcessId != registry.ProcessId)
                failures.Add($"active-runtime PID {active.Current.ProcessId} does not match executing Agent PID {registry.ProcessId}.");
            if (!string.Equals(active.Current.ListenUrl.TrimEnd('/'), "http://127.0.0.1:8828", StringComparison.OrdinalIgnoreCase))
                failures.Add("active-runtime listenUrl is not the fixed http://127.0.0.1:8828 endpoint.");
            if (!string.Equals(active.Current.HealthUrl.TrimEnd('/'), "http://127.0.0.1:8828/health", StringComparison.OrdinalIgnoreCase))
                failures.Add("active-runtime healthUrl is not the fixed http://127.0.0.1:8828/health endpoint.");
        }
        catch (Exception ex)
        {
            failures.Add("active-runtime verification failed: " + FormatError(ex));
        }

        var listeners = NetworkTools.TcpListenerList();
        var runtimeListener = FindSingleLoopbackListener(listeners, RuntimePort, failures, "Agent runtime");
        var bootstrapBackendListener = FindSingleLoopbackListener(listeners, BootstrapBackendPort, failures, "Bootstrap backend");
        var formalTunnelListener = FindSingleLoopbackListener(listeners, FormalTunnelHealthPort, failures, "Formal V4 tunnel");
        var bootstrapTunnelListener = FindSingleLoopbackListener(listeners, BootstrapTunnelHealthPort, failures, "Bootstrap tunnel");

        if (runtimeListener is not null)
        {
            if (runtimeListener.ProcessId != registry.ProcessId)
                failures.Add($"Port {RuntimePort} is owned by PID {runtimeListener.ProcessId}, expected Agent PID {registry.ProcessId}.");
            if (!string.Equals(runtimeListener.ProcessName, "dotnet", StringComparison.OrdinalIgnoreCase))
                failures.Add($"Port {RuntimePort} owner is {runtimeListener.ProcessName}, expected dotnet.");
        }

        if (bootstrapBackendListener is not null && bootstrapBackendService is not null)
        {
            if (bootstrapBackendListener.ProcessId != bootstrapBackendService.ProcessId)
                failures.Add($"Port {BootstrapBackendPort} is owned by PID {bootstrapBackendListener.ProcessId}, expected Bootstrap service PID {bootstrapBackendService.ProcessId}.");
            if (!PathsEqual(bootstrapBackendListener.ProcessPath, BootstrapBackendExe))
                failures.Add($"Port {BootstrapBackendPort} owner executable does not match the fixed Bootstrap backend path.");
        }

        var formalTunnelParentProcessId = ValidateTunnelListener(
            formalTunnelListener,
            FormalTunnelHealthPort,
            supervisorService,
            failures,
            "Formal V4 tunnel");

        var bootstrapTunnelParentProcessId = ValidateTunnelListener(
            bootstrapTunnelListener,
            BootstrapTunnelHealthPort,
            supervisorService,
            failures,
            "Bootstrap tunnel");

        string? tunnelExeSha256 = null;
        string? formalTunnelProfileSha256 = null;
        string? bootstrapTunnelProfileSha256 = null;
        try
        {
            tunnelExeSha256 = HashRegularFile(TunnelExe);
            if (!string.Equals(tunnelExeSha256, ExpectedTunnelExeSha256, StringComparison.OrdinalIgnoreCase))
                failures.Add("Tunnel executable SHA-256 mismatch.");
        }
        catch (Exception ex)
        {
            failures.Add("Tunnel executable verification failed: " + FormatError(ex));
        }
        try
        {
            formalTunnelProfileSha256 = HashRegularFile(FormalTunnelProfile);
            if (!string.Equals(formalTunnelProfileSha256, ExpectedFormalTunnelProfileSha256, StringComparison.OrdinalIgnoreCase))
                failures.Add("Formal V4 tunnel profile SHA-256 mismatch.");
        }
        catch (Exception ex)
        {
            failures.Add("Formal V4 tunnel profile verification failed: " + FormatError(ex));
        }
        try
        {
            bootstrapTunnelProfileSha256 = HashRegularFile(BootstrapTunnelProfile);
            if (!string.Equals(bootstrapTunnelProfileSha256, ExpectedBootstrapTunnelProfileSha256, StringComparison.OrdinalIgnoreCase))
                failures.Add("Bootstrap tunnel profile SHA-256 mismatch.");
        }
        catch (Exception ex)
        {
            failures.Add("Bootstrap tunnel profile verification failed: " + FormatError(ex));
        }

        var supervisorStartUtc = TryProcessStart(supervisorService?.ProcessId);
        var bootstrapBackendStartUtc = TryProcessStart(bootstrapBackendService?.ProcessId);
        var runtimeStartUtc = TryProcessStart(registry.ProcessId);
        var formalTunnelStartUtc = ParseStartTime(formalTunnelListener?.StartTimeUtc);
        var bootstrapTunnelStartUtc = ParseStartTime(bootstrapTunnelListener?.StartTimeUtc);

        if (supervisorStartUtc is not null && runtimeStartUtc is not null && runtimeStartUtc < supervisorStartUtc)
            failures.Add("Runtime started before the supervisor service, which violates reboot ownership order.");
        if (supervisorStartUtc is not null && formalTunnelStartUtc is not null && formalTunnelStartUtc < supervisorStartUtc)
            failures.Add("Formal V4 tunnel started before the supervisor service, which violates reboot ownership order.");
        if (supervisorStartUtc is not null && bootstrapTunnelStartUtc is not null && bootstrapTunnelStartUtc < supervisorStartUtc)
            failures.Add("Bootstrap tunnel started before the supervisor service, which violates reboot ownership order.");
        if (bootstrapBackendStartUtc is not null && bootstrapTunnelStartUtc is not null && bootstrapTunnelStartUtc < bootstrapBackendStartUtc)
            failures.Add("Bootstrap tunnel started before the Bootstrap backend, which violates recovery dependency order.");

        return new V4BootRecoveryStatusResult(
            failures.Count == 0,
            failures,
            approximateBootUtc,
            checkedUtc,
            supervisorService,
            bootstrapBackendService,
            supervisorDllSha256,
            registry,
            transferStaging,
            activeStateStorage,
            active,
            runtimeListener,
            bootstrapBackendListener,
            formalTunnelListener,
            formalTunnelParentProcessId,
            bootstrapTunnelListener,
            bootstrapTunnelParentProcessId,
            tunnelExeSha256,
            formalTunnelProfileSha256,
            bootstrapTunnelProfileSha256,
            supervisorStartUtc,
            bootstrapBackendStartUtc,
            runtimeStartUtc,
            formalTunnelStartUtc,
            bootstrapTunnelStartUtc);
    }

    private static TransferStagingStatus ReadTransferStagingStatus(List<string> failures)
    {
        var root = ReadTransferDirectoryStatus(TransferRoot, "Transfer staging root", failures);
        var inbox = ReadTransferDirectoryStatus(TransferInboxRoot, "Transfer inbox", failures);
        var outbox = ReadTransferDirectoryStatus(TransferOutboxRoot, "Transfer outbox", failures);
        return new TransferStagingStatus(root, inbox, outbox);
    }

    private static TransferDirectoryStatus ReadTransferDirectoryStatus(string path, string label, List<string> failures)
    {
        try
        {
            var full = Path.GetFullPath(path);
            if (!Directory.Exists(full))
            {
                failures.Add($"{label} does not exist: {full}");
                return new(full, false, false, false);
            }

            var attributes = File.GetAttributes(full);
            var isReparsePoint = (attributes & FileAttributes.ReparsePoint) != 0;
            var traversalSafe = ValidateTransferTraversal(full, out var unsafePath);
            if (isReparsePoint)
                failures.Add($"{label} may not be a reparse point: {full}");
            else if (!traversalSafe)
                failures.Add($"{label} traverses a reparse point or escapes the fixed development root: {unsafePath ?? full}");
            return new(full, true, isReparsePoint, traversalSafe);
        }
        catch (Exception ex)
        {
            failures.Add($"{label} verification failed: {FormatError(ex)}");
            return new(Path.GetFullPath(path), false, false, false);
        }
    }

    private static bool ValidateTransferTraversal(string path, out string? unsafePath)
    {
        var devRoot = Path.GetFullPath(DevRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var current = new DirectoryInfo(Path.GetFullPath(path));
        while (current is not null)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                unsafePath = current.FullName;
                return false;
            }

            if (string.Equals(current.FullName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), devRoot, StringComparison.OrdinalIgnoreCase))
            {
                unsafePath = null;
                return true;
            }

            current = current.Parent;
        }

        unsafePath = path;
        return false;
    }
    private static ActiveStateStorageStatus ReadActiveStateStorageStatus(List<string> failures)
    {
        var rootPath = Path.GetFullPath(HandoffRoot);
        var rootExists = Directory.Exists(rootPath);
        var rootIsReparsePoint = false;
        var traversalSafe = false;
        string? unsafePath = null;
        try
        {
            if (!rootExists)
            {
                failures.Add("active-runtime state root does not exist: " + rootPath);
            }
            else
            {
                rootIsReparsePoint = (File.GetAttributes(rootPath) & FileAttributes.ReparsePoint) != 0;
                traversalSafe = ValidateFixedDirectoryTraversal(rootPath, DevRoot, out unsafePath);
                if (rootIsReparsePoint)
                    failures.Add("active-runtime state root may not be a reparse point: " + rootPath);
                else if (!traversalSafe)
                    failures.Add("active-runtime state root traverses a reparse point or escapes the fixed development root: " + (unsafePath ?? rootPath));
            }
        }
        catch (Exception ex)
        {
            failures.Add("active-runtime state root verification failed: " + FormatError(ex));
        }

        var statePath = Path.GetFullPath(ActiveStatePath);
        var stateExists = File.Exists(statePath);
        var stateIsReparsePoint = false;
        try
        {
            if (!stateExists)
                failures.Add("active-runtime state file does not exist: " + statePath);
            else
            {
                stateIsReparsePoint = (File.GetAttributes(statePath) & FileAttributes.ReparsePoint) != 0;
                if (stateIsReparsePoint)
                    failures.Add("active-runtime state file may not be a reparse point: " + statePath);
            }
        }
        catch (Exception ex)
        {
            failures.Add("active-runtime state file verification failed: " + FormatError(ex));
        }

        return new(rootPath, rootExists, rootIsReparsePoint, traversalSafe, statePath, stateExists, stateIsReparsePoint);
    }

    private static bool ValidateFixedDirectoryTraversal(string path, string boundary, out string? unsafePath)
    {
        var root = Path.GetFullPath(boundary).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var current = new DirectoryInfo(Path.GetFullPath(path));
        while (current is not null)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                unsafePath = current.FullName;
                return false;
            }

            if (string.Equals(current.FullName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), root, StringComparison.OrdinalIgnoreCase))
            {
                unsafePath = null;
                return true;
            }
            current = current.Parent;
        }
        unsafePath = path;
        return false;
    }
    private static ServiceStatusResult? ReadAndValidateService(
        string serviceName,
        string expectedExecutable,
        bool requireLocalSystem,
        List<string> failures,
        string label)
    {
        try
        {
            var service = ServiceTools.ServiceStatus(serviceName);
            if (!string.Equals(service.State, "Running", StringComparison.Ordinal))
                failures.Add($"{label} service state is {service.State}, expected Running.");
            if (!string.Equals(service.StartType, "Automatic", StringComparison.Ordinal))
                failures.Add($"{label} service start type is {service.StartType}, expected Automatic.");
            if (requireLocalSystem && !string.Equals(service.ServiceAccount, "LocalSystem", StringComparison.OrdinalIgnoreCase))
                failures.Add($"{label} service account is {service.ServiceAccount}, expected LocalSystem.");
            if (!string.Equals(label, "Bootstrap backend", StringComparison.Ordinal) && !PathsEqual(service.EffectiveImageTarget, expectedExecutable))
                failures.Add($"{label} service executable target does not match the fixed path.");
            if (service.ProcessId <= 0)
                failures.Add($"{label} service did not report a running process ID.");
            return service;
        }
        catch (Exception ex)
        {
            failures.Add($"{label} service read failed: {FormatError(ex)}");
            return null;
        }
    }

    private static ActiveState ReadActiveState()
    {
        if (!ValidateFixedDirectoryTraversal(HandoffRoot, DevRoot, out var unsafePath))
            throw new UnauthorizedAccessException("active-runtime state root traversal is unsafe: " + (unsafePath ?? HandoffRoot));
        if (!File.Exists(ActiveStatePath))
            throw new FileNotFoundException("active-runtime state does not exist.", ActiveStatePath);
        if ((File.GetAttributes(ActiveStatePath) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("active-runtime state may not be a reparse point.");
        return JsonSerializer.Deserialize<ActiveState>(File.ReadAllText(ActiveStatePath), JsonOptions)
            ?? throw new InvalidDataException("active-runtime state is invalid.");
    }

    private static TcpListenerItem? FindSingleLoopbackListener(
        IReadOnlyList<TcpListenerItem> listeners,
        int port,
        List<string> failures,
        string label)
    {
        var matches = listeners.Where(x => x.Port == port && string.Equals(x.LocalAddress, "127.0.0.1", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (matches.Length != 1)
        {
            failures.Add($"Expected exactly one 127.0.0.1 listener for {label} on port {port}, found {matches.Length}.");
            return null;
        }
        return matches[0];
    }

    private static int? ValidateTunnelListener(
        TcpListenerItem? listener,
        int port,
        ServiceStatusResult? supervisorService,
        List<string> failures,
        string label)
    {
        if (listener is null) return null;
        if (!PathsEqual(listener.ProcessPath, TunnelExe))
            failures.Add($"Port {port} owner executable does not match the fixed tunnel-client path for {label}.");
        var parent = TryReadParentProcessId(listener.ProcessId);
        if (supervisorService is not null && supervisorService.ProcessId > 0 && parent != supervisorService.ProcessId)
            failures.Add($"{label} parent PID is {parent?.ToString() ?? "unknown"}, expected supervisor service PID {supervisorService.ProcessId}.");
        return parent;
    }

    private static bool PathsEqual(string? left, string? right)
    {
        if (string.IsNullOrWhiteSpace(left) || string.IsNullOrWhiteSpace(right)) return false;
        try
        {
            static string Normalize(string value)
            {
                var trimmed = value.Trim().Trim('"');
                return Path.TrimEndingDirectorySeparator(Path.GetFullPath(trimmed));
            }

            return string.Equals(Normalize(left), Normalize(right), StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static string HashRegularFile(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
            throw new FileNotFoundException("Fixed file does not exist.", fullPath);
        if ((File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Fixed file may not be a reparse point: " + fullPath);
        using var stream = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static DateTimeOffset? TryProcessStart(uint? processId)
        => processId is > 0 and <= int.MaxValue ? TryProcessStart((int)processId.Value) : null;

    private static DateTimeOffset? TryProcessStart(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return process.StartTime.ToUniversalTime();
        }
        catch
        {
            return null;
        }
    }

    private static DateTimeOffset? ParseStartTime(string? value)
        => DateTimeOffset.TryParse(value, out var parsed) ? parsed : null;

    private static int? TryReadParentProcessId(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            var size = Marshal.SizeOf<PROCESS_BASIC_INFORMATION>();
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var status = NtQueryInformationProcess(process.Handle, ProcessBasicInformation, buffer, size, out _);
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
        catch
        {
            return null;
        }
    }

    private static string FormatError(Exception ex) => ex.GetType().Name + ": " + ex.Message;

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        IntPtr processInformation,
        int processInformationLength,
        out int returnLength);

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

    public sealed record TransferDirectoryStatus(string Path, bool Exists, bool IsReparsePoint, bool TraversalSafe);
    public sealed record TransferStagingStatus(TransferDirectoryStatus Root, TransferDirectoryStatus Inbox, TransferDirectoryStatus Outbox);
    public sealed record ActiveStateStorageStatus(string RootPath, bool RootExists, bool RootIsReparsePoint, bool TraversalSafe, string StatePath, bool StateExists, bool StateIsReparsePoint);
    public sealed record RuntimeSlot(string? PlanId, string RuntimeDll, string RuntimeSha256, string ListenUrl, string HealthUrl, int ProcessId);
    public sealed record ActiveState(int SchemaVersion, RuntimeSlot Current, RuntimeSlot? Previous, DateTimeOffset UpdatedUtc);
}

public sealed record V4BootRecoveryStatusResult(
    bool Accepted,
    IReadOnlyList<string> FailureReasons,
    DateTimeOffset ApproximateBootUtc,
    DateTimeOffset CheckedUtc,
    ServiceStatusResult? SupervisorService,
    ServiceStatusResult? BootstrapBackendService,
    string? SupervisorDllSha256,
    ToolRegistrySnapshot ToolRegistry,
    V4BootRecoveryStatusTools.TransferStagingStatus TransferStaging,
    V4BootRecoveryStatusTools.ActiveStateStorageStatus ActiveStateStorage,
    V4BootRecoveryStatusTools.ActiveState? ActiveRuntime,
    TcpListenerItem? RuntimeListener,
    TcpListenerItem? BootstrapBackendListener,
    TcpListenerItem? FormalTunnelListener,
    int? FormalTunnelParentProcessId,
    TcpListenerItem? BootstrapTunnelListener,
    int? BootstrapTunnelParentProcessId,
    string? TunnelExeSha256,
    string? FormalTunnelProfileSha256,
    string? BootstrapTunnelProfileSha256,
    DateTimeOffset? SupervisorStartUtc,
    DateTimeOffset? BootstrapBackendStartUtc,
    DateTimeOffset? RuntimeStartUtc,
    DateTimeOffset? FormalTunnelStartUtc,
    DateTimeOffset? BootstrapTunnelStartUtc);