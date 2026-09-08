using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace YowThi.RuntimeDeploymentAuthorizer;

internal static class ElevationGate
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string ApprovalRoot = DevRoot + @"\.runtime-supervisor-deployment\approvals";
    private const string InstallRoot = @"C:\ProgramData\YowThi\RuntimeDeployment";
    private const string AuthorizerExe = InstallRoot + @"\YowThi.RuntimeDeploymentAuthorizer.exe";
    private const int ErrorCancelled = 1223;
    private const uint TokenQuery = 0x0008;

    [ModuleInitializer]
    internal static void RequireElevationBeforeAuthorizerMain()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var args = Environment.GetCommandLineArgs();
        if (args.Length != 2)
            return;

        var approvalPath = RequireDirectApprovalPath(args[1]);
        RequireFixedAuthorizerProcessPath();

        if (IsProcessElevated())
            return;

        var start = new ProcessStartInfo
        {
            FileName = AuthorizerExe,
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = InstallRoot,
            Arguments = QuoteArgument(approvalPath)
        };

        try
        {
            using var elevated = Process.Start(start)
                ?? throw new InvalidOperationException("Unable to launch elevated runtime deployment authorizer.");
            elevated.WaitForExit();
            Environment.Exit(elevated.ExitCode);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorCancelled)
        {
            Environment.Exit(ErrorCancelled);
        }
    }

    private static string RequireDirectApprovalPath(string value)
    {
        var full = Path.GetFullPath(value);
        var root = Path.GetFullPath(ApprovalRoot).TrimEnd('\\', '/');
        var parent = Path.GetDirectoryName(full)?.TrimEnd('\\', '/');
        if (!string.Equals(parent, root, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetExtension(full), ".json", StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(full))
            throw new UnauthorizedAccessException("Authorizer elevation requires one existing direct approval JSON under the fixed approval root.");
        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Authorizer approval JSON may not be a reparse point.");
        return full;
    }

    private static void RequireFixedAuthorizerProcessPath()
    {
        var processPath = Environment.ProcessPath
            ?? throw new UnauthorizedAccessException("Authorizer process path is unavailable.");
        var full = Path.GetFullPath(processPath);
        if (!string.Equals(full, Path.GetFullPath(AuthorizerExe), StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Runtime deployment authorizer elevation is only allowed from the fixed ProgramData executable.");
        if (!File.Exists(full))
            throw new FileNotFoundException("Runtime deployment authorizer executable does not exist.", full);
        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Runtime deployment authorizer executable may not be a reparse point.");
    }

    private static bool IsProcessElevated()
    {
        using var process = Process.GetCurrentProcess();
        if (!OpenProcessToken(process.Handle, TokenQuery, out var tokenHandle) || tokenHandle == IntPtr.Zero)
            throw new InvalidOperationException("Unable to open runtime deployment authorizer process token: " + Marshal.GetLastWin32Error());

        try
        {
            var elevation = new TOKEN_ELEVATION();
            if (!GetTokenInformation(
                    tokenHandle,
                    TOKEN_INFORMATION_CLASS.TokenElevation,
                    ref elevation,
                    Marshal.SizeOf<TOKEN_ELEVATION>(),
                    out _))
                throw new InvalidOperationException("Unable to read runtime deployment authorizer token elevation state: " + Marshal.GetLastWin32Error());
            return elevation.TokenIsElevated != 0;
        }
        finally
        {
            CloseHandle(tokenHandle);
        }
    }

    private static string QuoteArgument(string value)
    {
        if (value.Contains('"'))
            throw new UnauthorizedAccessException("Approval path contains an unsupported quote character.");
        return "\"" + value + "\"";
    }

    private enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_ELEVATION
    {
        public int TokenIsElevated;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        IntPtr tokenHandle,
        TOKEN_INFORMATION_CLASS tokenInformationClass,
        ref TOKEN_ELEVATION tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
