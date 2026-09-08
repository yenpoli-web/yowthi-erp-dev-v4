using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace YowThi.RuntimeDeploymentSigner;

internal static class ApprovalBridgeParentGuard
{
    internal const string ApprovalBridgeExe = @"C:\ProgramData\YowThi\RuntimeDeployment\YowThi.RuntimeDeploymentApprovalBridge.exe";
    internal const string ApprovalBridgeDll = @"C:\ProgramData\YowThi\RuntimeDeployment\YowThi.RuntimeDeploymentApprovalBridge.dll";
    internal const string ExpectedApprovalBridgeExeSha256 = "D5DBDC7F12FEA22C0DBB140D0809381F70754DAC3BECA02F83519EFA74CA431B";
    internal const string ExpectedApprovalBridgeDllSha256 = "8E9BA46CB8BC950475AA01612DE7C24C104B06D3B0B74EA6C19E3A6EC6C20E99";

    [ModuleInitializer]
    internal static void ValidateAtModuleLoad()
    {
        if (ExpectedApprovalBridgeExeSha256.All(ch => ch == '0') || ExpectedApprovalBridgeDllSha256.All(ch => ch == '0'))
            throw new UnauthorizedAccessException("Runtime deployment approval bridge EXE+DLL identity is not provisioned.");

        var parentProcessId = GetParentProcessId();
        using var parent = Process.GetProcessById(parentProcessId);
        var parentPath = parent.MainModule?.FileName
            ?? throw new UnauthorizedAccessException("Runtime deployment approval bridge parent executable path is unavailable.");
        var fullParentPath = Path.GetFullPath(parentPath);

        if (!string.Equals(fullParentPath, Path.GetFullPath(ApprovalBridgeExe), StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Runtime deployment signer may only be launched by the fixed local approval bridge executable.");
        ValidatePinnedFile(fullParentPath, ExpectedApprovalBridgeExeSha256, "approval bridge executable");
        ValidatePinnedFile(ApprovalBridgeDll, ExpectedApprovalBridgeDllSha256, "approval bridge managed DLL");
    }

    private static void ValidatePinnedFile(string path, string expectedSha256, string label)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full))
            throw new FileNotFoundException("Runtime deployment " + label + " does not exist.", full);
        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Runtime deployment " + label + " may not be a reparse point.");
        using var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read);
        var actualSha256 = Convert.ToHexString(SHA256.HashData(stream));
        if (!string.Equals(actualSha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Runtime deployment " + label + " SHA-256 does not match the provisioned identity.");
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
