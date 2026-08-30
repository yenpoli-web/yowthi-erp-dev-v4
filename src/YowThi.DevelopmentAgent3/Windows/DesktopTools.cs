using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using ModelContextProtocol.Server;

namespace YowThi.DevelopmentAgent3.Windows;

[McpServerToolType]
public sealed class DesktopTools
{
    private const uint MONITOR_DEFAULTTONEAREST = 2;
    private const uint MONITORINFOF_PRIMARY = 0x00000001;

    [McpServerTool(Name = "desktop_display_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List attached Windows desktop displays with monitor bounds, work-area bounds, primary-display status, and device name using native Windows monitor APIs. This is read-only and does not change display configuration, DPI, resolution, orientation, windows, input, or desktop state. No PowerShell, cmd, WMI command execution, or generic command executor is used.")]
    public static IReadOnlyList<DesktopDisplayItem> DesktopDisplayList()
    {
        var result = new List<DesktopDisplayItem>();
        if (!EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, (monitor, _, _, _) =>
        {
            var info = new MONITORINFOEX
            {
                cbSize = Marshal.SizeOf<MONITORINFOEX>(),
                szDevice = string.Empty
            };

            if (!GetMonitorInfoW(monitor, ref info))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to read monitor information.");

            var bounds = ToRectangle(info.rcMonitor);
            var workArea = ToRectangle(info.rcWork);
            var primary = (info.dwFlags & MONITORINFOF_PRIMARY) != 0;
            result.Add(new DesktopDisplayItem(
                HandleToHex(monitor),
                info.szDevice ?? string.Empty,
                bounds,
                workArea,
                primary));
            return true;
        }, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to enumerate desktop monitors.");

        return result
            .OrderByDescending(x => x.Primary)
            .ThenBy(x => x.Bounds.Left)
            .ThenBy(x => x.Bounds.Top)
            .ThenBy(x => x.DeviceName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    [McpServerTool(Name = "desktop_cursor_position_get", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read the current Windows desktop cursor position and the nearest monitor metadata using native Windows cursor and monitor APIs. This is read-only and does not move, click, press, inject, capture, or otherwise modify mouse, keyboard, window, or desktop input state. No PowerShell, cmd, WMI command execution, or generic command executor is used.")]
    public static DesktopCursorPositionResult DesktopCursorPositionGet()
    {
        if (!GetCursorPos(out var point))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to read cursor position.");

        var monitor = MonitorFromPoint(point, MONITOR_DEFAULTTONEAREST);
        if (monitor == IntPtr.Zero)
            return new DesktopCursorPositionResult(point.X, point.Y, null, null, null, null);

        var info = new MONITORINFOEX
        {
            cbSize = Marshal.SizeOf<MONITORINFOEX>(),
            szDevice = string.Empty
        };
        if (!GetMonitorInfoW(monitor, ref info))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to read cursor monitor information.");

        return new DesktopCursorPositionResult(
            point.X,
            point.Y,
            HandleToHex(monitor),
            info.szDevice ?? string.Empty,
            ToRectangle(info.rcMonitor),
            (info.dwFlags & MONITORINFOF_PRIMARY) != 0);
    }

    [McpServerTool(Name = "desktop_window_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List visible top-level Windows desktop windows with HWND, owning process ID, process metadata, title, bounds, visibility, minimized state, and foreground status using native Windows window APIs plus the .NET Process API. This is read-only and does not activate, move, resize, close, minimize, maximize, capture, send input to, or otherwise modify any window or process. Windows without a visible top-level presentation are excluded. No PowerShell, cmd, WMI command execution, or generic command executor is used.")]
    public static IReadOnlyList<DesktopWindowItem> DesktopWindowList()
    {
        var foreground = GetForegroundWindow();
        var result = new List<DesktopWindowItem>();

        if (!EnumWindows((window, _) =>
        {
            if (window == IntPtr.Zero || !IsWindowVisible(window))
                return true;

            var title = ReadWindowTitle(window);
            if (string.IsNullOrWhiteSpace(title))
                return true;

            if (!GetWindowRect(window, out var rect))
                return true;

            GetWindowThreadProcessId(window, out var processId);
            var process = ReadProcessMetadata(processId);
            result.Add(new DesktopWindowItem(
                HandleToHex(window),
                processId,
                process.ProcessName,
                process.ProcessPath,
                process.StartTimeUtc,
                title,
                ToRectangle(rect),
                true,
                IsIconic(window),
                window == foreground));
            return true;
        }, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to enumerate top-level desktop windows.");

        return result
            .OrderByDescending(x => x.Foreground)
            .ThenBy(x => x.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.Title, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.Hwnd, StringComparer.Ordinal)
            .ToArray();
    }

    [McpServerTool(Name = "desktop_foreground_window_get", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read the current Windows foreground window with HWND, owning process ID, process metadata, title, bounds, visibility, and minimized state using native Windows window APIs plus the .NET Process API. This is read-only and does not activate, move, resize, close, minimize, maximize, capture, send input to, or otherwise modify any window or process. No PowerShell, cmd, WMI command execution, or generic command executor is used.")]
    public static DesktopWindowItem? DesktopForegroundWindowGet()
    {
        var window = GetForegroundWindow();
        if (window == IntPtr.Zero)
            return null;

        if (!GetWindowRect(window, out var rect))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to read foreground window bounds.");

        GetWindowThreadProcessId(window, out var processId);
        var process = ReadProcessMetadata(processId);
        return new DesktopWindowItem(
            HandleToHex(window),
            processId,
            process.ProcessName,
            process.ProcessPath,
            process.StartTimeUtc,
            ReadWindowTitle(window),
            ToRectangle(rect),
            IsWindowVisible(window),
            IsIconic(window),
            true);
    }

    private static string ReadWindowTitle(IntPtr window)
    {
        var length = GetWindowTextLengthW(window);
        if (length <= 0)
            return string.Empty;

        var builder = new StringBuilder(length + 1);
        var copied = GetWindowTextW(window, builder, builder.Capacity);
        return copied <= 0 ? string.Empty : builder.ToString();
    }

    private static (string ProcessName, string? ProcessPath, string? StartTimeUtc) ReadProcessMetadata(uint processId)
    {
        if (processId == 0)
            return (string.Empty, null, null);

        try
        {
            using var process = Process.GetProcessById(checked((int)processId));
            string? path = null;
            string? startTimeUtc = null;
            try { path = process.MainModule?.FileName; } catch { }
            try { startTimeUtc = process.StartTime.ToUniversalTime().ToString("O"); } catch { }
            return (process.ProcessName, path, startTimeUtc);
        }
        catch
        {
            return (string.Empty, null, null);
        }
    }

    private static DesktopRectangle ToRectangle(RECT rect) => new(
        rect.Left,
        rect.Top,
        rect.Right,
        rect.Bottom,
        rect.Right - rect.Left,
        rect.Bottom - rect.Top);

    private static string HandleToHex(IntPtr handle) => $"0x{unchecked((ulong)handle.ToInt64()):X}";

    private delegate bool MonitorEnumProc(IntPtr hMonitor, IntPtr hdcMonitor, IntPtr lprcMonitor, IntPtr dwData);
    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr lprcClip, MonitorEnumProc lpfnEnum, IntPtr dwData);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetMonitorInfoW(IntPtr hMonitor, ref MONITORINFOEX lpmi);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetCursorPos(out POINT lpPoint);

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromPoint(POINT pt, uint dwFlags);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsIconic(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetWindowTextLengthW(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetWindowTextW(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT
    {
        public int X;
        public int Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct MONITORINFOEX
    {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string szDevice;
    }
}

public sealed record DesktopRectangle(
    int Left,
    int Top,
    int Right,
    int Bottom,
    int Width,
    int Height);

public sealed record DesktopDisplayItem(
    string MonitorHandle,
    string DeviceName,
    DesktopRectangle Bounds,
    DesktopRectangle WorkArea,
    bool Primary);

public sealed record DesktopCursorPositionResult(
    int X,
    int Y,
    string? MonitorHandle,
    string? DeviceName,
    DesktopRectangle? MonitorBounds,
    bool? PrimaryDisplay);

public sealed record DesktopWindowItem(
    string Hwnd,
    uint ProcessId,
    string ProcessName,
    string? ProcessPath,
    string? StartTimeUtc,
    string Title,
    DesktopRectangle Bounds,
    bool Visible,
    bool Minimized,
    bool Foreground);