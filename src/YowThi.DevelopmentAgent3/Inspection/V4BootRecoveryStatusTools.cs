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
    private const string ServiceName = "YowThiV4RuntimeSupervisor";
    private const string SupervisorExe = @"C:\Dev\YowThi-ERP-Dev-v4\runtime-supervisor\current\YowThi.RuntimeSupervisor.exe";
    private const string SupervisorDll = @"C:\Dev\YowThi-ERP-Dev-v4\runtime-supervisor\current\YowThi.RuntimeSupervisor.dll";
    private const string ExpectedSupervisorDllSha256 = "4EADA3B4A0AB682D232DD1634EA2923262AE7A11C2F69E97DEF18D0A16B4DCDD";
    private const string ActiveStatePath = @"C:\Dev\YowThi-ERP-Dev-v4\.agent3-handoff\active-runtime.json";
    private const string TunnelExe = @"C:\ProgramData\YowThi\TunnelClient\bin\tunnel-client.exe";
    private const string ExpectedTunnelExeSha256 = "6649169733686805CA16CCCD91774594D0C017FD729C37AD4CE1CD18323D9AE8";
    private const string TunnelProfile = @"C:\ProgramData\YowThi\TunnelClient\profiles\yowthi-erp-dev-v4.yaml";
    private const string ExpectedTunnelProfileSha256 = "8B46DC3AF0DBE713CBEF8ABC2AE864AF780F8DC713CBF011ABC3405F6D0F911F";
    private const int RuntimePort = 8828;
    private const int TunnelHealthPort = 8792;
    private const int ProcessBasicInformation = 0;

    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    [McpServerTool(Name = "v4_boot_recovery_status", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read the complete YowThi ERP Dev v4 reboot-recovery acceptance state in one call. It verifies the fixed Automatic LocalSystem Runtime Supervisor service, current active-runtime identity, executing Agent runtime SHA/PID/tool registry, loopback 8828 listener, V4 tunnel 8792 listener and parent ownership, fixed tunnel executable/profile fingerprints, and boot-process ordering. Returns accepted plus explicit failure reasons. This is read-only and does not start, stop, restart, mutate, repair, read secrets, execute shells, or access production paths.")]
    public static V4BootRecoveryStatusResult V4BootRecoveryStatus()
    {
        var failures = new List<string>();
        var checkedUtc = DateTimeOffset.UtcNow;
        var approximateBootUtc = checkedUtc - TimeSpan.FromMilliseconds(Environment.TickCount64);

        ServiceStatusResult? service = null;
        try
        {
            service = ServiceTools.ServiceStatus(ServiceName);
            if (!string.Equals(service.State, "Running", StringComparison.Ordinal))
                failures.Add($"Supervisor service state is {service.State}, expected Running.");
            if (!string.Equals(service.StartType, "Automatic", StringComparison.Ordinal))
                failures.Add($"Supervisor service start type is {service.StartType}, expected Automatic.");
            if (!string.Equals(service.ServiceAccount, "LocalSystem", StringComparison.OrdinalIgnoreCase))
                failures.Add($"Supervisor service account is {service.ServiceAccount}, expected LocalSystem.");
            if (!string.Equals(Path.GetFullPath(service.EffectiveImageTarget ?? string.Empty), Path.GetFullPath(SupervisorExe), StringComparison.OrdinalIgnoreCase))
                failures.Add("Supervisor service executable target does not match the fixed V4 supervisor path.");
            if (service.ProcessId <= 0)
                failures.Add("Supervisor service did not report a running process ID.");
        }
        catch (Exception ex)
        {
            failures.Add("Supervisor service read failed: " + ex.GetType().Name + ": " + ex.Message);
        }

        string? supervisorDllSha256 = null;
        try
        {
            supervisorDllSha256 = HashRegularFile(SupervisorDll);
            if (!string.Equals(supervisorDllSha256, ExpectedSupervisorDllSha256, StringComparison.OrdinalIgnoreCase))
                failures.Add("Supervisor DLL SHA-256 does not match the accepted P11 boot-recovery build.");
        }
        catch (Exception ex)
        {
            failures.Add("Supervisor DLL verification failed: " + ex.GetType().Name + ": " + ex.Message);
        }

        var registry = ToolRegistryIdentity.Current;
        if (registry.ToolCount < 206)
            failures.Add($"Agent tool registry contains {registry.ToolCount} tools; expected at least 206 after boot diagnostics is installed.");
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

        ActiveState? active = null;
        try
        {
            if (!File.Exists(ActiveStatePath))
                throw new FileNotFoundException("active-runtime state does not exist.", ActiveStatePath);
            if ((File.GetAttributes(ActiveStatePath) & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException("active-runtime state may not be a reparse point.");
            active = JsonSerializer.Deserialize<ActiveState>(File.ReadAllText(ActiveStatePath), JsonOptions)
                ?? throw new InvalidDataException("active-runtime state is invalid.");

            if (active.SchemaVersion != 2)
                failures.Add($"active-runtime schemaVersion is {active.SchemaVersion}, expected 2.");
            if (!string.Equals(Path.GetFullPath(active.Current.RuntimeDll), Path.GetFullPath(registry.RuntimeDll), StringComparison.OrdinalIgnoreCase))
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
            failures.Add("active-runtime verification failed: " + ex.GetType().Name + ": " + ex.Message);
        }

        var listeners = NetworkTools.TcpListenerList();
        var runtimeListeners = listeners.Where(x => x.Port == RuntimePort && IsLoopback(x.LocalAddress)).ToArray();
        var tunnelListeners = listeners.Where(x => x.Port == TunnelHealthPort && IsLoopback(x.LocalAddress)).ToArray();

        TcpListenerItem? runtimeListener = runtimeListeners.Length == 1 ? runtimeListeners[0] : null;
        TcpListenerItem? tunnelListener = tunnelListeners.Length == 1 ? tunnelListeners[0] : null;

        if (runtimeListeners.Length != 1)
            failures.Add($"Expected exactly one loopback listener on {RuntimePort}, found {runtimeListeners.Length}.");
        else
        {
            if (runtimeListener!.ProcessId != registry.ProcessId)
                failures.Add($"Port {RuntimePort} is owned by PID {runtimeListener.ProcessId}, expected Agent PID {registry.ProcessId}.");
            if (!string.Equals(runtimeListener.ProcessName, "dotnet", StringComparison.OrdinalIgnoreCase))
                failures.Add($"Port {RuntimePort} owner is {runtimeListener.ProcessName}, expected dotnet.");
        }

        int? tunnelParentProcessId = null;
        if (tunnelListeners.Length != 1)
        {
            failures.Add($"Expected exactly one loopback listener on {TunnelHealthPort}, found {tunnelListeners.Length}.");
        }
        else
        {
            if (!string.Equals(Path.GetFullPath(tunnelListener!.ProcessPath ?? string.Empty), Path.GetFullPath(TunnelExe), StringComparison.OrdinalIgnoreCase))
                failures.Add($"Port {TunnelHealthPort} owner executable does not match the fixed V4 tunnel-client path.");
            tunnelParentProcessId = TryReadParentProcessId(tunnelListener.ProcessId);
            if (service is not null && service.ProcessId > 0 && tunnelParentProcessId != service.ProcessId)
                failures.Add($"V4 tunnel parent PID is {tunnelParentProcessId?.ToString() ?? "unknown"}, expected supervisor service PID {service.ProcessId}.");
        }

        string? tunnelExeSha256 = null;
        string? tunnelProfileSha256 = null;
        try
        {
            tunnelExeSha256 = HashRegularFile(TunnelExe);
            if (!string.Equals(tunnelExeSha256, ExpectedTunnelExeSha256, StringComparison.OrdinalIgnoreCase))
                failures.Add("Tunnel executable SHA-256 mismatch.");
        }
        catch (Exception ex)
        {
            failures.Add("Tunnel executable verification failed: " + ex.GetType().Name + ": " + ex.Message);
        }
        try
        {
            tunnelProfileSha256 = HashRegularFile(TunnelProfile);
            if (!string.Equals(tunnelProfileSha256, ExpectedTunnelProfileSha256, StringComparison.OrdinalIgnoreCase))
                failures.Add("Tunnel profile SHA-256 mismatch.");
        }
        catch (Exception ex)
        {
            failures.Add("Tunnel profile verification failed: " + ex.GetType().Name + ": " + ex.Message);
        }

        DateTimeOffset? supervisorStartUtc = null;
        DateTimeOffset? runtimeStartUtc = null;
        DateTimeOffset? tunnelStartUtc = null;
        try { if (service is not null && service.ProcessId > 0) supervisorStartUtc = Process.GetProcessById((int)service.ProcessId).StartTime.ToUniversalTime(); } catch { }
        try { runtimeStartUtc = Process.GetProcessById(registry.ProcessId).StartTime.ToUniversalTime(); } catch { }
        if (tunnelListener is not null && DateTimeOffset.TryParse(tunnelListener.StartTimeUtc, out var parsedTunnelStart))
            tunnelStartUtc = parsedTunnelStart;

        if (supervisorStartUtc is not null && runtimeStartUtc is not null && runtimeStartUtc < supervisorStartUtc)
            failures.Add("Runtime started before the supervisor service, which violates the reboot ownership order.");
        if (supervisorStartUtc is not null && tunnelStartUtc is not null && tunnelStartUtc < supervisorStartUtc)
            failures.Add("Tunnel started before the supervisor service, which violates the reboot ownership order.");

        return new V4BootRecoveryStatusResult(
            failures.Count == 0,
            failures,
            approximateBootUtc,
            checkedUtc,
            service,
            supervisorDllSha256,
            registry,
            active,
            runtimeListener,
            tunnelListener,
            tunnelParentProcessId,
            tunnelExeSha256,
            tunnelProfileSha256,
            supervisorStartUtc,
            runtimeStartUtc,
            tunnelStartUtc);
    }

    private static bool IsLoopback(string address)
        => string.Equals(address, "127.0.0.1", StringComparison.OrdinalIgnoreCase) ||
           string.Equals(address, "0.0.0.0", StringComparison.OrdinalIgnoreCase);

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

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, IntPtr processInformation, int processInformationLength, out int returnLength);

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

    public sealed record RuntimeSlot(string? PlanId, string RuntimeDll, string RuntimeSha256, string ListenUrl, string HealthUrl, int ProcessId);
    public sealed record ActiveState(int SchemaVersion, RuntimeSlot Current, RuntimeSlot? Previous, DateTimeOffset UpdatedUtc);
}

public sealed record V4BootRecoveryStatusResult(
    bool Accepted,
    IReadOnlyList<string> FailureReasons,
    DateTimeOffset ApproximateBootUtc,
    DateTimeOffset CheckedUtc,
    ServiceStatusResult? SupervisorService,
    string? SupervisorDllSha256,
    ToolRegistrySnapshot ToolRegistry,
    V4BootRecoveryStatusTools.ActiveState? ActiveRuntime,
    TcpListenerItem? RuntimeListener,
    TcpListenerItem? TunnelListener,
    int? TunnelParentProcessId,
    string? TunnelExeSha256,
    string? TunnelProfileSha256,
    DateTimeOffset? SupervisorStartUtc,
    DateTimeOffset? RuntimeStartUtc,
    DateTimeOffset? TunnelStartUtc);
