using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace YowThi.RuntimeDeploymentExecutor;

internal static class AuthorizerParentGuard
{
    private const string AuthorizerExe = @"C:\ProgramData\YowThi\RuntimeDeployment\YowThi.RuntimeDeploymentAuthorizer.exe";
    private const string AuthorizerDll = @"C:\ProgramData\YowThi\RuntimeDeployment\YowThi.RuntimeDeploymentAuthorizer.dll";
    private const string ExpectedAuthorizerExeSha256 = "61587C8AE9A58BDA0BD68199A99FBD4D60A544E70690730127E81F57FBF3408E";
    private const string ExpectedAuthorizerDllSha256 = "CB9A4EA443CD98E33AFE7AD8BD81B05C5AF827DD35281253F5DBB4BB87B744A6";

    [ModuleInitializer]
    internal static void ValidateAtModuleLoad()
    {
        if (ExpectedAuthorizerExeSha256.All(ch => ch == '0') || ExpectedAuthorizerDllSha256.All(ch => ch == '0'))
            throw new UnauthorizedAccessException("Runtime deployment executor authorizer EXE+DLL identity is not provisioned.");

        var parentProcessId = GetParentProcessId();
        using var parent = Process.GetProcessById(parentProcessId);
        var parentPath = parent.MainModule?.FileName
            ?? throw new UnauthorizedAccessException("Runtime deployment authorizer parent executable path is unavailable.");
        var fullParentPath = Path.GetFullPath(parentPath);

        if (!string.Equals(fullParentPath, Path.GetFullPath(AuthorizerExe), StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Runtime deployment executor may only be launched by the fixed local authorizer executable.");
        ValidatePinnedFile(fullParentPath, ExpectedAuthorizerExeSha256, "authorizer executable");
        ValidatePinnedFile(AuthorizerDll, ExpectedAuthorizerDllSha256, "authorizer managed DLL");
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
            throw new UnauthorizedAccessException("Unable to establish runtime deployment executor parent process identity.");

        var value = info.InheritedFromUniqueProcessId.ToInt64();
        if (value <= 0 || value > int.MaxValue)
            throw new UnauthorizedAccessException("Runtime deployment executor parent process ID is invalid.");
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
