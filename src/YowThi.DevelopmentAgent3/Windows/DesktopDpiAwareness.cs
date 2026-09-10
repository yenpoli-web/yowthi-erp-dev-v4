using System.ComponentModel;
using System.Runtime.InteropServices;

namespace YowThi.DevelopmentAgent3.Windows;

internal static class DesktopDpiAwareness
{
    private const string SessionHelperSwitch = "--yowthi-desktop-session-helper";
    private static readonly IntPtr DpiAwarenessContextPerMonitorAwareV2 = new(-4);

    internal static void EnableForInteractiveHelper(string[] args)
    {
        if (!args.Any(x => string.Equals(x, SessionHelperSwitch, StringComparison.Ordinal)))
            return;

        if (SetProcessDpiAwarenessContext(DpiAwarenessContextPerMonitorAwareV2))
            return;

        var error = Marshal.GetLastWin32Error();
        if (error == 5)
            return;

        throw new Win32Exception(error, "Unable to enable Per-Monitor DPI Awareness V2 for the interactive desktop helper.");
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetProcessDpiAwarenessContext(IntPtr value);
}
