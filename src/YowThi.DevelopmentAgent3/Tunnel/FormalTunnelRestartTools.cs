using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;
using YowThi.DevelopmentAgent3.Windows;

namespace YowThi.DevelopmentAgent3.Tunnel;

[McpServerToolType]
public static class FormalTunnelRestartTools
{
    private const string SupervisorServiceName = "YowThiV4RuntimeSupervisor";
    private const string TunnelExe = @"C:\ProgramData\YowThi\TunnelClient\bin\tunnel-client.exe";
    private const string FormalProfile = @"C:\ProgramData\YowThi\TunnelClient\profiles\yowthi-erp-dev-v4.yaml";
    private const string ExpectedTunnelSha256 = "6649169733686805CA16CCCD91774594D0C017FD729C37AD4CE1CD18323D9AE8";
    private const string ExpectedProfileSha256 = "8B46DC3AF0DBE713CBEF8ABC2AE864AF780F8DC713CBF011ABC3405F6D0F911F";
    private const int FormalPort = 8792;
    private const int BootstrapPort = 8793;
    private const int RuntimePort = 8828;
    private const int ProcessBasicInformation = 0;

    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name = "formal_tunnel_restart_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed plan to restart only the fixed YowThi Formal tunnel on 127.0.0.1:8792. The fixed tunnel executable/profile fingerprints, current tunnel PID/start time, Runtime Supervisor ownership, Bootstrap 8793 listener identity, and Agent runtime 8828 listener identity are sealed. Arbitrary PIDs, ports, profiles, executables, shells, PowerShell, cmd, and unrelated process mutation are not supported.")]
    public static SignedPlan FormalTunnelRestartPlan()
    {
        ValidateFixedFiles();
        var supervisor = ServiceTools.ServiceStatus(SupervisorServiceName);
        if (!string.Equals(supervisor.State, "Running", StringComparison.Ordinal) || supervisor.ProcessId <= 0)
            throw new InvalidOperationException("Runtime Supervisor must be running.");

        var listeners = NetworkTools.TcpListenerList();
        var formal = RequireListener(listeners, FormalPort);
        var bootstrap = RequireListener(listeners, BootstrapPort);
        var runtime = RequireListener(listeners, RuntimePort);
        ValidateFormal(formal, (int)supervisor.ProcessId);

        var startUtc = Process.GetProcessById(formal.ProcessId).StartTime.ToUniversalTime().ToString("O");
        var now = DateTimeOffset.UtcNow;
        var parameters = new Dictionary<string,string>(StringComparer.Ordinal)
        {
            ["formalPid"] = formal.ProcessId.ToString(),
            ["formalStartUtc"] = startUtc,
            ["supervisorPid"] = supervisor.ProcessId.ToString(),
            ["bootstrapPid"] = bootstrap.ProcessId.ToString(),
            ["runtimePid"] = runtime.ProcessId.ToString(),
            ["bootstrapPath"] = bootstrap.ProcessPath ?? string.Empty,
            ["runtimePath"] = runtime.ProcessPath ?? string.Empty
        };
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var summary = $"Restart fixed Formal tunnel 127.0.0.1:{FormalPort} PID {formal.ProcessId} under Runtime Supervisor PID {supervisor.ProcessId}";
        var unsigned = new SignedPlan(1, planId, approvalCode, "formal-tunnel", "formal-tunnel-restart", $"127.0.0.1:{FormalPort}", parameters, RiskClass.High, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "formal_tunnel_restart_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared fixed Formal tunnel restart plan. Exact tunnel PID/start time, fixed executable/profile fingerprints, Runtime Supervisor parent ownership, unchanged Bootstrap 8793 listener, and unchanged Agent runtime 8828 listener are revalidated before terminating only the sealed Formal tunnel process. The Runtime Supervisor must recreate 8792 with a new PID and valid ownership within a bounded timeout; otherwise execution fails. No arbitrary process, port, profile, shell, PowerShell, or cmd is supported.")]
    public static ExecutionResult FormalTunnelRestartExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntent(plan, operation, target, summary, riskClass);
        ValidateFixedFiles();

        var oldPid = int.Parse(Require(plan, "formalPid"));
        var expectedStartUtc = DateTimeOffset.Parse(Require(plan, "formalStartUtc"));
        var supervisorPid = int.Parse(Require(plan, "supervisorPid"));
        var bootstrapPid = int.Parse(Require(plan, "bootstrapPid"));
        var runtimePid = int.Parse(Require(plan, "runtimePid"));

        var supervisor = ServiceTools.ServiceStatus(SupervisorServiceName);
        if (!string.Equals(supervisor.State, "Running", StringComparison.Ordinal) || supervisor.ProcessId != supervisorPid)
            throw new UnauthorizedAccessException("Runtime Supervisor identity changed.");

        var before = NetworkTools.TcpListenerList();
        var formal = RequireListener(before, FormalPort);
        var bootstrap = RequireListener(before, BootstrapPort);
        var runtime = RequireListener(before, RuntimePort);
        if (formal.ProcessId != oldPid || bootstrap.ProcessId != bootstrapPid || runtime.ProcessId != runtimePid)
            throw new UnauthorizedAccessException("Sealed listener identity changed.");
        ValidateFormal(formal, supervisorPid);

        using (var process = Process.GetProcessById(oldPid))
        {
            var actualStart = new DateTimeOffset(process.StartTime.ToUniversalTime());
            if (Math.Abs((actualStart - expectedStartUtc).TotalSeconds) > 1)
                throw new UnauthorizedAccessException("Formal tunnel process start time changed.");
            process.Kill(entireProcessTree: false);
            if (!process.WaitForExit(5000)) throw new TimeoutException("Formal tunnel process did not exit.");
        }

        TcpListenerItem? restarted = null;
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (DateTime.UtcNow < deadline)
        {
            Thread.Sleep(500);
            var current = NetworkTools.TcpListenerList();
            var matches = current.Where(x => x.Port == FormalPort && string.Equals(x.LocalAddress, "127.0.0.1", StringComparison.OrdinalIgnoreCase)).ToArray();
            if (matches.Length == 1 && matches[0].ProcessId != oldPid)
            {
                ValidateFormal(matches[0], supervisorPid);
                var b = RequireListener(current, BootstrapPort);
                var r = RequireListener(current, RuntimePort);
                if (b.ProcessId != bootstrapPid || r.ProcessId != runtimePid)
                    throw new UnauthorizedAccessException("Bootstrap or runtime listener changed during Formal tunnel restart.");
                restarted = matches[0];
                break;
            }
        }
        if (restarted is null) throw new TimeoutException("Runtime Supervisor did not recreate Formal tunnel within 20 seconds.");

        Store.Consume(planId);
        var outcome = $"restarted:oldPid={oldPid};newPid={restarted.ProcessId};port={FormalPort}";
        Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, oldPid, newPid = restarted.ProcessId }, "executed");
        return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
    }

    private static TcpListenerItem RequireListener(IReadOnlyList<TcpListenerItem> listeners, int port)
    {
        var matches = listeners.Where(x => x.Port == port && string.Equals(x.LocalAddress, "127.0.0.1", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (matches.Length != 1) throw new InvalidOperationException($"Expected exactly one loopback listener on port {port}, found {matches.Length}.");
        return matches[0];
    }

    private static void ValidateFormal(TcpListenerItem listener, int supervisorPid)
    {
        if (!PathsEqual(listener.ProcessPath, TunnelExe)) throw new UnauthorizedAccessException("Formal tunnel executable mismatch.");
        if (TryReadParentProcessId(listener.ProcessId) != supervisorPid) throw new UnauthorizedAccessException("Formal tunnel is not owned by Runtime Supervisor.");
    }

    private static void ValidateFixedFiles()
    {
        if (!string.Equals(HashRegularFile(TunnelExe), ExpectedTunnelSha256, StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException("Tunnel executable fingerprint mismatch.");
        if (!string.Equals(HashRegularFile(FormalProfile), ExpectedProfileSha256, StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException("Formal tunnel profile fingerprint mismatch.");
    }

    private static string HashRegularFile(string path)
    {
        if (!File.Exists(path)) throw new FileNotFoundException("Fixed file missing.", path);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Fixed file may not be a reparse point.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static bool PathsEqual(string? a, string? b)
    {
        if (string.IsNullOrWhiteSpace(a) || string.IsNullOrWhiteSpace(b)) return false;
        return string.Equals(Path.GetFullPath(a.Trim().Trim('"')), Path.GetFullPath(b.Trim().Trim('"')), StringComparison.OrdinalIgnoreCase);
    }

    private static int? TryReadParentProcessId(int processId)
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
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static string Require(SignedPlan plan, string key) => plan.Parameters.TryGetValue(key, out var v) && !string.IsNullOrWhiteSpace(v) ? v : throw new InvalidDataException($"Missing signed parameter {key}.");

    private static void RequireIntent(SignedPlan plan, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "formal-tunnel", StringComparison.Ordinal) || !string.Equals(plan.Operation, "formal-tunnel-restart", StringComparison.Ordinal) || !string.Equals(plan.Operation, operation, StringComparison.Ordinal) || !string.Equals(plan.Target, target, StringComparison.Ordinal) || !string.Equals(plan.Summary, summary, StringComparison.Ordinal) || !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
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
}