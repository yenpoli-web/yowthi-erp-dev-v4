using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace YowThi.RuntimeDeploymentKeyProvisioner;

internal static class InteractiveSessionGuard
{
    [ModuleInitializer]
    internal static void ValidateAtModuleLoad()
    {
        if (!OperatingSystem.IsWindows() || !Environment.UserInteractive)
            throw new UnauthorizedAccessException("Runtime deployment key provisioning requires an interactive Windows user session.");

        var activeSession = WTSGetActiveConsoleSessionId();
        if (activeSession == uint.MaxValue || activeSession == 0)
            throw new UnauthorizedAccessException("No eligible active console user session exists.");

        if (!ProcessIdToSessionId((uint)Environment.ProcessId, out var currentSession) || currentSession != activeSession)
            throw new UnauthorizedAccessException("Runtime deployment key provisioning must execute in the active console user session.");

        var parentId = GetParentProcessId();
        using var parent = Process.GetProcessById(parentId);
        if (!ProcessIdToSessionId((uint)parentId, out var parentSession) || parentSession != activeSession)
            throw new UnauthorizedAccessException("Runtime deployment key provisioner parent is not in the active console session.");

        var parentPath = parent.MainModule?.FileName
            ?? throw new UnauthorizedAccessException("Runtime deployment key provisioner parent executable path is unavailable.");
        var expectedExplorer = Path.GetFullPath(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"));
        if (!string.Equals(Path.GetFullPath(parentPath), expectedExplorer, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Runtime deployment key provisioner may only be launched directly by Windows Explorer in the active console session.");
    }

    private static int GetParentProcessId()
    {
        using var current = Process.GetCurrentProcess();
        var info = new PROCESS_BASIC_INFORMATION();
        var status = NtQueryInformationProcess(current.Handle, 0, ref info, Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _);
        var value = info.InheritedFromUniqueProcessId.ToInt64();
        if (status != 0 || value <= 0 || value > int.MaxValue)
            throw new UnauthorizedAccessException("Unable to establish runtime deployment key provisioner parent process identity.");
        return (int)value;
    }

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

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);
}
