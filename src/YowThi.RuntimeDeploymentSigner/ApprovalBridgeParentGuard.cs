using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace YowThi.RuntimeDeploymentSigner;

internal static class ApprovalBridgeParentGuard
{
    internal const string ApprovalBridgeExe = @"C:\ProgramData\YowThi\RuntimeDeployment\YowThi.RuntimeDeploymentApprovalBridge.exe";
    internal const string ExpectedApprovalBridgeExeSha256 = "9FF4EAF2A642DEF2013ACF2356440E7B51B24A476303E7D91B1228D250337EF5";

    [ModuleInitializer]
    internal static void ValidateAtModuleLoad()
    {
        if (ExpectedApprovalBridgeExeSha256.All(ch => ch == '0'))
            throw new UnauthorizedAccessException("Runtime deployment approval bridge identity is not provisioned.");

        var parentProcessId = GetParentProcessId();
        using var parent = Process.GetProcessById(parentProcessId);
        var parentPath = parent.MainModule?.FileName
            ?? throw new UnauthorizedAccessException("Runtime deployment approval bridge parent executable path is unavailable.");
        var fullParentPath = Path.GetFullPath(parentPath);

        if (!string.Equals(fullParentPath, Path.GetFullPath(ApprovalBridgeExe), StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Runtime deployment signer may only be launched by the fixed local approval bridge executable.");
        if (!File.Exists(fullParentPath))
            throw new FileNotFoundException("Runtime deployment approval bridge executable does not exist.", fullParentPath);
        if ((File.GetAttributes(fullParentPath) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Runtime deployment approval bridge executable may not be a reparse point.");

        using var stream = new FileStream(fullParentPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var actualSha256 = Convert.ToHexString(SHA256.HashData(stream));
        if (!string.Equals(actualSha256, ExpectedApprovalBridgeExeSha256, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Runtime deployment approval bridge executable SHA-256 does not match the provisioned identity.");
    }

    private static int GetParentProcessId()
    {
        using var current = Process.GetCurrentProcess();
        var info = new PROCESS_BASIC_INFORMATION();
        var status = NtQueryInformationProcess(current.Handle, 0, ref info, Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _);
        if (status != 0 || info.InheritedFromUniqueProcessId == IntPtr.Zero)
            throw new UnauthorizedAccessException("Unable to establish runtime deployment signer parent process identity.");

        var value = info.InheritedFromUniqueProcessId.ToInt64();
        if (value <= 0 || value > int.MaxValue)
            throw new UnauthorizedAccessException("Runtime deployment signer parent process ID is invalid.");
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

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);
}
