using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;
using YowThi.DevelopmentAgent3.Security;

namespace YowThi.DevelopmentAgent3.Windows;

[McpServerToolType]
public sealed class DesktopMutationTools
{
    private const uint MONITOR_DEFAULTTONULL = 0;
    private const uint INPUT_MOUSE = 0;
    private const uint INPUT_KEYBOARD = 1;
    private const ushort VK_MENU = 0x12;
    private const uint KEYEVENTF_KEYUP = 0x0002;
    private const uint MOUSEEVENTF_LEFTDOWN = 0x0002;
    private const uint MOUSEEVENTF_LEFTUP = 0x0004;
    private const uint MOUSEEVENTF_RIGHTDOWN = 0x0008;
    private const uint MOUSEEVENTF_RIGHTUP = 0x0010;
    private const uint MOUSEEVENTF_MIDDLEDOWN = 0x0020;
    private const uint MOUSEEVENTF_MIDDLEUP = 0x0040;
    private const int SW_RESTORE = 9;

    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name = "desktop_cursor_move_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to move the Windows desktop cursor to one absolute screen coordinate. The target coordinate must currently lie on an attached monitor and the monitor bounds are sealed into the plan. This does not move the cursor until desktop_cursor_move_execute is called. No PowerShell, cmd, WMI command execution, or generic command executor is used.")]
    public static SignedPlan DesktopCursorMovePlan(int x, int y)
    {
        var monitor = RequireMonitorAtPoint(x, y);
        var now = DateTimeOffset.UtcNow;
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["x"] = x.ToString(CultureInfo.InvariantCulture),
            ["y"] = y.ToString(CultureInfo.InvariantCulture),
            ["monitorHandle"] = HandleToHex(monitor.Handle),
            ["monitorLeft"] = monitor.Rect.Left.ToString(CultureInfo.InvariantCulture),
            ["monitorTop"] = monitor.Rect.Top.ToString(CultureInfo.InvariantCulture),
            ["monitorRight"] = monitor.Rect.Right.ToString(CultureInfo.InvariantCulture),
            ["monitorBottom"] = monitor.Rect.Bottom.ToString(CultureInfo.InvariantCulture)
        };
        return CreatePlan("desktop", "cursor-move", $"{x},{y}", parameters, RiskClass.High, $"Move desktop cursor to ({x},{y})", now);
    }

    [McpServerTool(Name = "desktop_cursor_move_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared desktop/cursor-move plan. The caller must repeat the signed operation, target, summary, and risk class. The signed coordinate and monitor bounds are revalidated immediately before SetCursorPos is called. No arbitrary coordinates beyond the signed plan are accepted.")]
    public static ExecutionResult DesktopCursorMoveExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "cursor-move", operation, target, summary, riskClass);
        var (x, y) = ReadPoint(plan);
        RequireMonitorSnapshot(plan, x, y);

        try
        {
            if (!SetCursorPos(x, y))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to move desktop cursor.");

            Store.Consume(planId);
            var outcome = $"cursor-moved:{x},{y}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome }, "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "desktop_mouse_click_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan for one single desktop mouse click at one absolute screen coordinate. Button is restricted to left, right, or middle. Double-click, drag, hold, wheel, and arbitrary input sequences are not supported. The coordinate must currently lie on an attached monitor. This does not move or click until desktop_mouse_click_execute is called.")]
    public static SignedPlan DesktopMouseClickPlan(int x, int y, string button)
    {
        var normalizedButton = NormalizeButton(button);
        var monitor = RequireMonitorAtPoint(x, y);
        var now = DateTimeOffset.UtcNow;
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["x"] = x.ToString(CultureInfo.InvariantCulture),
            ["y"] = y.ToString(CultureInfo.InvariantCulture),
            ["button"] = normalizedButton,
            ["monitorHandle"] = HandleToHex(monitor.Handle),
            ["monitorLeft"] = monitor.Rect.Left.ToString(CultureInfo.InvariantCulture),
            ["monitorTop"] = monitor.Rect.Top.ToString(CultureInfo.InvariantCulture),
            ["monitorRight"] = monitor.Rect.Right.ToString(CultureInfo.InvariantCulture),
            ["monitorBottom"] = monitor.Rect.Bottom.ToString(CultureInfo.InvariantCulture)
        };
        return CreatePlan("desktop", "mouse-click", $"{normalizedButton}@{x},{y}", parameters, RiskClass.High, $"Single {normalizedButton} mouse click at ({x},{y})", now);
    }

    [McpServerTool(Name = "desktop_mouse_click_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared desktop/mouse-click plan. The caller must repeat the signed operation, target, summary, and risk class. Coordinate, monitor bounds, and button are revalidated immediately before the cursor is positioned and one native SendInput click is emitted. Double-click, drag, hold, wheel, and arbitrary input sequences are not supported.")]
    public static ExecutionResult DesktopMouseClickExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "mouse-click", operation, target, summary, riskClass);
        var (x, y) = ReadPoint(plan);
        RequireMonitorSnapshot(plan, x, y);
        if (!plan.Parameters.TryGetValue("button", out var button))
            throw new InvalidDataException("button parameter is required.");
        button = NormalizeButton(button);

        try
        {
            if (!SetCursorPos(x, y))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to position desktop cursor before click.");

            var (down, up) = button switch
            {
                "left" => (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
                "right" => (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
                "middle" => (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
                _ => throw new InvalidDataException("Unsupported mouse button.")
            };

            var inputs = new[]
            {
                CreateMouseInput(down),
                CreateMouseInput(up)
            };
            var sent = SendInput((uint)inputs.Length, inputs, Marshal.SizeOf<INPUT>());
            if (sent != inputs.Length)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to emit the complete mouse click input sequence.");

            Store.Consume(planId);
            var outcome = $"mouse-clicked:{button}@{x},{y}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome }, "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "desktop_window_activate_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to activate one existing visible top-level Windows desktop window by HWND. The plan seals HWND, owning PID, process name, process start time, title, bounds, visibility, and minimized state to mitigate HWND reuse and time-of-check/time-of-use changes. ApplicationFrameHost wrapper windows are rejected because they are not reliable foreground activation targets. This does not activate any window until desktop_window_activate_execute is called.")]
    public static SignedPlan DesktopWindowActivatePlan(string hwnd)
    {
        var window = ParseHandle(hwnd);
        var snapshot = RequireWindowSnapshot(window);
        if (!snapshot.Visible)
            throw new InvalidOperationException("Target window must be visible.");
        if (string.Equals(snapshot.ProcessName, "ApplicationFrameHost", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("ApplicationFrameHost wrapper windows are not eligible activation targets; target the underlying application window instead.");

        var now = DateTimeOffset.UtcNow;
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["hwnd"] = HandleToHex(window),
            ["processId"] = snapshot.ProcessId.ToString(CultureInfo.InvariantCulture),
            ["processName"] = snapshot.ProcessName,
            ["processStartTimeUtc"] = snapshot.ProcessStartTimeUtc ?? string.Empty,
            ["title"] = snapshot.Title,
            ["left"] = snapshot.Rect.Left.ToString(CultureInfo.InvariantCulture),
            ["top"] = snapshot.Rect.Top.ToString(CultureInfo.InvariantCulture),
            ["right"] = snapshot.Rect.Right.ToString(CultureInfo.InvariantCulture),
            ["bottom"] = snapshot.Rect.Bottom.ToString(CultureInfo.InvariantCulture),
            ["visible"] = snapshot.Visible ? "true" : "false",
            ["minimized"] = snapshot.Minimized ? "true" : "false"
        };
        return CreatePlan("desktop", "window-activate", HandleToHex(window), parameters, RiskClass.High, $"Activate desktop window {HandleToHex(window)} ({snapshot.Title})", now);
    }

    [McpServerTool(Name = "desktop_window_activate_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared desktop/window-activate plan. The caller must repeat the signed operation, target, summary, and risk class. HWND, PID, process name, process start time, title, bounds, visibility, and minimized-state expectations are revalidated before activation. If Windows foreground-lock policy initially rejects SetForegroundWindow, one fixed server-side ALT key down/up sequence is emitted only to unlock foreground activation; callers cannot choose or inject arbitrary keys. Arbitrary HWNDs not present in the signed plan are not accepted.")]
    public static ExecutionResult DesktopWindowActivateExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "window-activate", operation, target, summary, riskClass);
        if (!plan.Parameters.TryGetValue("hwnd", out var hwndText))
            throw new InvalidDataException("hwnd parameter is required.");
        var window = ParseHandle(hwndText);
        RequireWindowSnapshotMatch(plan, window);

        try
        {
            ActivateSignedWindow(window);

            Store.Consume(planId);
            var outcome = $"window-activated:{HandleToHex(window)}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome }, "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    private static SignedPlan CreatePlan(string tool, string operation, string target, IReadOnlyDictionary<string, string> parameters, RiskClass riskClass, string summary, DateTimeOffset now)
    {
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), tool, operation, target, parameters, riskClass, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    private static void RequireIntentMatch(SignedPlan plan, string expectedOperation, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "desktop", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.Ordinal) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }

    private static (int X, int Y) ReadPoint(SignedPlan plan)
    {
        if (!plan.Parameters.TryGetValue("x", out var xText) || !int.TryParse(xText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var x) ||
            !plan.Parameters.TryGetValue("y", out var yText) || !int.TryParse(yText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var y))
            throw new InvalidDataException("Signed x/y parameters are invalid.");
        return (x, y);
    }

    private static MonitorSnapshot RequireMonitorAtPoint(int x, int y)
    {
        var point = new POINT { X = x, Y = y };
        var monitor = MonitorFromPoint(point, MONITOR_DEFAULTTONULL);
        if (monitor == IntPtr.Zero)
            throw new ArgumentOutOfRangeException(nameof(x), "Target coordinate is not on an attached monitor.");
        var info = new MONITORINFO { cbSize = Marshal.SizeOf<MONITORINFO>() };
        if (!GetMonitorInfoW(monitor, ref info))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to read monitor information.");
        return new MonitorSnapshot(monitor, info.rcMonitor);
    }

    private static void RequireMonitorSnapshot(SignedPlan plan, int x, int y)
    {
        var current = RequireMonitorAtPoint(x, y);
        if (!plan.Parameters.TryGetValue("monitorHandle", out var handle) ||
            !plan.Parameters.TryGetValue("monitorLeft", out var leftText) || !int.TryParse(leftText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var left) ||
            !plan.Parameters.TryGetValue("monitorTop", out var topText) || !int.TryParse(topText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var top) ||
            !plan.Parameters.TryGetValue("monitorRight", out var rightText) || !int.TryParse(rightText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var right) ||
            !plan.Parameters.TryGetValue("monitorBottom", out var bottomText) || !int.TryParse(bottomText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var bottom))
            throw new InvalidDataException("Signed monitor snapshot is invalid.");

        if (!string.Equals(handle, HandleToHex(current.Handle), StringComparison.OrdinalIgnoreCase) ||
            left != current.Rect.Left || top != current.Rect.Top || right != current.Rect.Right || bottom != current.Rect.Bottom)
            throw new InvalidOperationException("Desktop monitor topology changed after plan preparation.");
    }

    private static WindowSnapshot RequireWindowSnapshot(IntPtr window)
    {
        if (window == IntPtr.Zero || !IsWindow(window))
            throw new ArgumentException("Target HWND does not identify a current window.");
        if (!GetWindowRect(window, out var rect))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to read target window bounds.");
        GetWindowThreadProcessId(window, out var processId);
        string processName = string.Empty;
        string? startTimeUtc = null;
        try
        {
            using var process = Process.GetProcessById(checked((int)processId));
            try { processName = process.ProcessName; } catch { }
            try { startTimeUtc = process.StartTime.ToUniversalTime().ToString("O"); } catch { }
        }
        catch { }
        return new WindowSnapshot(processId, processName, startTimeUtc, ReadWindowTitle(window), rect, IsWindowVisible(window), IsIconic(window));
    }

    private static void RequireWindowSnapshotMatch(SignedPlan plan, IntPtr window)
    {
        var current = RequireWindowSnapshot(window);
        if (!TryReadUInt(plan, "processId", out var processId) ||
            !TryReadInt(plan, "left", out var left) || !TryReadInt(plan, "top", out var top) || !TryReadInt(plan, "right", out var right) || !TryReadInt(plan, "bottom", out var bottom) ||
            !plan.Parameters.TryGetValue("processName", out var processName) ||
            !plan.Parameters.TryGetValue("processStartTimeUtc", out var processStartTimeUtc) ||
            !plan.Parameters.TryGetValue("title", out var title) ||
            !plan.Parameters.TryGetValue("visible", out var visibleText) ||
            !plan.Parameters.TryGetValue("minimized", out var minimizedText))
            throw new InvalidDataException("Signed window snapshot is invalid.");

        var visible = string.Equals(visibleText, "true", StringComparison.OrdinalIgnoreCase);
        var minimized = string.Equals(minimizedText, "true", StringComparison.OrdinalIgnoreCase);
        if (processId != current.ProcessId ||
            !string.Equals(processName, current.ProcessName, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(processStartTimeUtc, current.ProcessStartTimeUtc ?? string.Empty, StringComparison.Ordinal) ||
            !string.Equals(title, current.Title, StringComparison.Ordinal) ||
            left != current.Rect.Left || top != current.Rect.Top || right != current.Rect.Right || bottom != current.Rect.Bottom ||
            visible != current.Visible || minimized != current.Minimized)
            throw new InvalidOperationException("Target window identity or state changed after plan preparation.");
    }

    private static void ActivateSignedWindow(IntPtr window)
    {
        var currentThreadId = GetCurrentThreadId();
        var foregroundWindow = GetForegroundWindow();
        var foregroundThreadId = foregroundWindow == IntPtr.Zero ? 0u : GetWindowThreadProcessId(foregroundWindow, out _);
        var targetThreadId = GetWindowThreadProcessId(window, out _);

        var attachedForeground = false;
        var attachedTarget = false;
        try
        {
            if (foregroundThreadId != 0 && foregroundThreadId != currentThreadId)
                attachedForeground = AttachThreadInput(currentThreadId, foregroundThreadId, true);
            if (targetThreadId != 0 && targetThreadId != currentThreadId && targetThreadId != foregroundThreadId)
                attachedTarget = AttachThreadInput(currentThreadId, targetThreadId, true);

            if (IsIconic(window))
                ShowWindowAsync(window, SW_RESTORE);

            BringWindowToTop(window);
            SetForegroundWindow(window);

            if (GetForegroundWindow() != window)
            {
                var unlockInputs = new[]
                {
                    CreateKeyboardInput(VK_MENU, 0),
                    CreateKeyboardInput(VK_MENU, KEYEVENTF_KEYUP)
                };
                var sent = SendInput((uint)unlockInputs.Length, unlockInputs, Marshal.SizeOf<INPUT>());
                if (sent != unlockInputs.Length)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to emit the fixed ALT foreground-unlock sequence.");

                SetForegroundWindow(window);
            }

            if (GetForegroundWindow() != window)
                throw new InvalidOperationException("Windows did not allow the signed target window to become foreground after the fixed activation sequence.");
        }
        finally
        {
            if (attachedTarget)
                AttachThreadInput(currentThreadId, targetThreadId, false);
            if (attachedForeground)
                AttachThreadInput(currentThreadId, foregroundThreadId, false);
        }
    }
    private static string NormalizeButton(string button)
    {
        var value = (button ?? string.Empty).Trim().ToLowerInvariant();
        return value is "left" or "right" or "middle" ? value : throw new ArgumentOutOfRangeException(nameof(button), "Button must be left, right, or middle.");
    }

    private static IntPtr ParseHandle(string hwnd)
    {
        if (string.IsNullOrWhiteSpace(hwnd)) throw new ArgumentException("HWND is required.", nameof(hwnd));
        var text = hwnd.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) text = text[2..];
        if (!ulong.TryParse(text, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var value))
            throw new ArgumentException("HWND must be a hexadecimal handle such as 0x123ABC.", nameof(hwnd));
        return new IntPtr(unchecked((long)value));
    }

    private static bool TryReadInt(SignedPlan plan, string key, out int value)
    {
        value = default;
        return plan.Parameters.TryGetValue(key, out var text) && int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    private static bool TryReadUInt(SignedPlan plan, string key, out uint value)
    {
        value = default;
        return plan.Parameters.TryGetValue(key, out var text) && uint.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    private static string ReadWindowTitle(IntPtr window)
    {
        var length = GetWindowTextLengthW(window);
        if (length <= 0) return string.Empty;
        var builder = new StringBuilder(length + 1);
        return GetWindowTextW(window, builder, builder.Capacity) <= 0 ? string.Empty : builder.ToString();
    }

    private static INPUT CreateKeyboardInput(ushort virtualKey, uint flags) => new()
    {
        type = INPUT_KEYBOARD,
        U = new INPUTUNION
        {
            ki = new KEYBDINPUT { wVk = virtualKey, dwFlags = flags }
        }
    };
    private static INPUT CreateMouseInput(uint flags) => new()
    {
        type = INPUT_MOUSE,
        U = new INPUTUNION
        {
            mi = new MOUSEINPUT { dwFlags = flags }
        }
    };

    private static string HandleToHex(IntPtr handle) => $"0x{unchecked((ulong)handle.ToInt64()):X}";

    private sealed record MonitorSnapshot(IntPtr Handle, RECT Rect);
    private sealed record WindowSnapshot(uint ProcessId, string ProcessName, string? ProcessStartTimeUtc, string Title, RECT Rect, bool Visible, bool Minimized);

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromPoint(POINT pt, uint dwFlags);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetMonitorInfoW(IntPtr hMonitor, ref MONITORINFO lpmi);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetCursorPos(int X, int Y);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint SendInput(uint cInputs, INPUT[] pInputs, int cbSize);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsIconic(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetWindowTextLengthW(IntPtr hWnd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int GetWindowTextW(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, [MarshalAs(UnmanagedType.Bool)] bool fAttach);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool BringWindowToTop(IntPtr hWnd);
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT { public int X; public int Y; }

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int Left; public int Top; public int Right; public int Bottom; }

    [StructLayout(LayoutKind.Sequential)]
    private struct MONITORINFO
    {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct INPUT
    {
        public uint type;
        public INPUTUNION U;
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct INPUTUNION
    {
        [FieldOffset(0)] public MOUSEINPUT mi;
        [FieldOffset(0)] public KEYBDINPUT ki;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KEYBDINPUT
    {
        public ushort wVk;
        public ushort wScan;
        public uint dwFlags;
        public uint time;
        public UIntPtr dwExtraInfo;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct MOUSEINPUT
    {
        public int dx;
        public int dy;
        public uint mouseData;
        public uint dwFlags;
        public uint time;
        public UIntPtr dwExtraInfo;
    }
}