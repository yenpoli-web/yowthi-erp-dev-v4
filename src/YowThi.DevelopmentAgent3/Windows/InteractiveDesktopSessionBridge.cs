using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace YowThi.DevelopmentAgent3.Windows;

internal static class InteractiveDesktopSessionBridge
{
    internal const string HelperSwitch = "--yowthi-desktop-session-helper";
    private const string DotnetExe = @"C:\Program Files\dotnet\dotnet.exe";
    private const int HelperTimeoutSeconds = 20;
    private const int MaxPayloadBytes = 1024 * 1024;
    private const uint MONITOR_DEFAULTTONULL = 0;
    private const uint MONITOR_DEFAULTTONEAREST = 2;
    private const uint MONITORINFOF_PRIMARY = 1;
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
    private const uint WAIT_OBJECT_0 = 0;
    private const uint WAIT_TIMEOUT = 0x102;

    internal sealed record MonitorSnapshot(string Handle, DesktopRectangle Bounds, string DeviceName, bool Primary);
    internal sealed record WindowSnapshot(uint ProcessId, string ProcessName, string? ProcessPath, string? ProcessStartTimeUtc, string Title, DesktopRectangle Bounds, bool Visible, bool Minimized, bool Foreground);
    private sealed record HelperRequest(int? X = null, int? Y = null, string? Button = null, string? Hwnd = null);
    private sealed record HelperEnvelope(bool Success, string? Error, string? Json, int HelperProcessId, int SessionId);

    internal static IReadOnlyList<DesktopDisplayItem> GetDisplays() => Invoke<IReadOnlyList<DesktopDisplayItem>>("display-list", null);
    internal static DesktopCursorPositionResult GetCursorPosition() => Invoke<DesktopCursorPositionResult>("cursor-position", null);
    internal static IReadOnlyList<DesktopWindowItem> GetWindows() => Invoke<IReadOnlyList<DesktopWindowItem>>("window-list", null);
    internal static DesktopWindowItem? GetForegroundWindowInfo() => InvokeNullable<DesktopWindowItem>("foreground-window", null);
    internal static MonitorSnapshot GetMonitorAtPoint(int x, int y) => Invoke<MonitorSnapshot>("monitor-at-point", new HelperRequest(X: x, Y: y));
    internal static WindowSnapshot GetWindowSnapshot(string hwnd) => Invoke<WindowSnapshot>("window-snapshot", new HelperRequest(Hwnd: hwnd));
    internal static void MoveCursor(int x, int y) => InvokeAck("cursor-move", new HelperRequest(X: x, Y: y));
    internal static void MouseClick(int x, int y, string button) => InvokeAck("mouse-click", new HelperRequest(X: x, Y: y, Button: button));
    internal static void ActivateWindow(string hwnd) => InvokeAck("window-activate", new HelperRequest(Hwnd: hwnd));

    internal static async Task<bool> TryRunHelperAsync(string[] args)
    {
        if (!args.Any(x => string.Equals(x, HelperSwitch, StringComparison.Ordinal)))
            return false;

        string? pipeHandle = null;
        string? action = null;
        string? requestBase64 = null;
        for (var i = 0; i < args.Length; i++)
        {
            if (string.Equals(args[i], "--pipe", StringComparison.Ordinal) && i + 1 < args.Length) pipeHandle = args[++i];
            else if (string.Equals(args[i], "--action", StringComparison.Ordinal) && i + 1 < args.Length) action = args[++i];
            else if (string.Equals(args[i], "--request", StringComparison.Ordinal) && i + 1 < args.Length) requestBase64 = args[++i];
        }

        if (string.IsNullOrWhiteSpace(pipeHandle)) return true;
        await using var pipe = new AnonymousPipeClientStream(PipeDirection.Out, pipeHandle);
        HelperEnvelope envelope;
        try
        {
            var request = DecodeRequest(requestBase64);
            var result = ExecuteHelperAction(action ?? string.Empty, request);
            envelope = new HelperEnvelope(true, null, result, Environment.ProcessId, Process.GetCurrentProcess().SessionId);
        }
        catch (Exception ex)
        {
            envelope = new HelperEnvelope(false, SanitizeError(ex), null, Environment.ProcessId, Process.GetCurrentProcess().SessionId);
        }

        var bytes = JsonSerializer.SerializeToUtf8Bytes(envelope);
        if (bytes.Length > MaxPayloadBytes) throw new InvalidDataException("Interactive desktop helper response exceeded the bounded limit.");
        var length = BitConverter.GetBytes(bytes.Length);
        await pipe.WriteAsync(length);
        await pipe.WriteAsync(bytes);
        await pipe.FlushAsync();
        return true;
    }

    private static string ExecuteHelperAction(string action, HelperRequest request)
    {
        return action switch
        {
            "display-list" => JsonSerializer.Serialize(ReadDisplaysLocal()),
            "cursor-position" => JsonSerializer.Serialize(ReadCursorPositionLocal()),
            "window-list" => JsonSerializer.Serialize(ReadWindowsLocal()),
            "foreground-window" => JsonSerializer.Serialize(ReadForegroundWindowLocal()),
            "monitor-at-point" => JsonSerializer.Serialize(ReadMonitorAtPointLocal(RequireInt(request.X, "x"), RequireInt(request.Y, "y"))),
            "window-snapshot" => JsonSerializer.Serialize(ReadWindowSnapshotLocal(RequireHwnd(request.Hwnd))),
            "cursor-move" => ExecuteAndAck(() => MoveCursorLocal(RequireInt(request.X, "x"), RequireInt(request.Y, "y"))),
            "mouse-click" => ExecuteAndAck(() => MouseClickLocal(RequireInt(request.X, "x"), RequireInt(request.Y, "y"), NormalizeButton(request.Button))),
            "window-activate" => ExecuteAndAck(() => ActivateWindowLocal(RequireHwnd(request.Hwnd))),
            _ => throw new ArgumentException("Unsupported interactive desktop helper action.")
        };
    }

    private static T Invoke<T>(string action, HelperRequest? request)
    {
        var json = InvokeRaw(action, request);
        return JsonSerializer.Deserialize<T>(json) ?? throw new InvalidDataException($"Interactive desktop helper returned an empty {typeof(T).Name} payload.");
    }

    private static T? InvokeNullable<T>(string action, HelperRequest? request) where T : class
    {
        var json = InvokeRaw(action, request);
        if (string.Equals(json, "null", StringComparison.Ordinal)) return null;
        return JsonSerializer.Deserialize<T>(json) ?? throw new InvalidDataException($"Interactive desktop helper returned an invalid {typeof(T).Name} payload.");
    }

    private static void InvokeAck(string action, HelperRequest request)
    {
        var json = InvokeRaw(action, request);
        if (!string.Equals(json, "true", StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Interactive desktop helper did not acknowledge the requested action.");
    }

    private static string InvokeRaw(string action, HelperRequest? request)
    {
        if (Process.GetCurrentProcess().SessionId != 0)
            return ExecuteHelperAction(action, request ?? new HelperRequest());

        var sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId == 0xFFFFFFFF) throw new InvalidOperationException("No active console session is available for desktop interaction.");
        if (!WTSQueryUserToken(sessionId, out var userToken) || userToken == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to obtain the active interactive user token.");

        IntPtr environment = IntPtr.Zero;
        PROCESS_INFORMATION processInfo = default;
        using var pipe = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
        try
        {
            if (!CreateEnvironmentBlock(out environment, userToken, false))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to create the interactive user environment.");
            ValidateFixedDotnetHost();
            var runtimeDll = typeof(InteractiveDesktopSessionBridge).Assembly.Location;
            if (string.IsNullOrWhiteSpace(runtimeDll) || !File.Exists(runtimeDll)) throw new FileNotFoundException("Unable to resolve the active Agent runtime assembly.", runtimeDll);
            if ((File.GetAttributes(runtimeDll) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("The active Agent runtime assembly may not be a reparse point.");

            var command = new StringBuilder();
            AppendQuotedArgument(command, DotnetExe);
            AppendQuotedArgument(command, runtimeDll);
            AppendQuotedArgument(command, HelperSwitch);
            AppendQuotedArgument(command, "--pipe");
            AppendQuotedArgument(command, pipe.GetClientHandleAsString());
            AppendQuotedArgument(command, "--action");
            AppendQuotedArgument(command, action);
            if (request is not null)
            {
                AppendQuotedArgument(command, "--request");
                AppendQuotedArgument(command, Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(request)));
            }

            var startup = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>(), lpDesktop = @"winsta0\default" };
            const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
            const uint CREATE_NO_WINDOW = 0x08000000;
            if (!CreateProcessAsUserW(userToken, DotnetExe, command, IntPtr.Zero, IntPtr.Zero, true, CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, environment, Path.GetDirectoryName(runtimeDll), ref startup, out processInfo))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to launch the interactive desktop helper in the active console session.");

            pipe.DisposeLocalCopyOfClientHandle();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(HelperTimeoutSeconds));
            var prefix = new byte[4];
            ReadExactly(pipe, prefix, cts.Token);
            var payloadLength = BitConverter.ToInt32(prefix, 0);
            if (payloadLength <= 0 || payloadLength > MaxPayloadBytes) throw new InvalidDataException("Interactive desktop helper returned an invalid payload length.");
            var payload = new byte[payloadLength];
            ReadExactly(pipe, payload, cts.Token);
            var envelope = JsonSerializer.Deserialize<HelperEnvelope>(payload) ?? throw new InvalidDataException("Interactive desktop helper returned an invalid envelope.");
            if (envelope.SessionId != checked((int)sessionId)) throw new InvalidDataException("Interactive desktop helper did not execute in the sealed active console session.");
            if (!envelope.Success) throw new InvalidOperationException(envelope.Error ?? "Interactive desktop helper failed.");
            if (envelope.Json is null) throw new InvalidDataException("Interactive desktop helper returned no result payload.");

            var wait = WaitForSingleObject(processInfo.hProcess, 5_000);
            if (wait != WAIT_OBJECT_0) throw new TimeoutException("Interactive desktop helper did not exit after returning its result.");
            if (!GetExitCodeProcess(processInfo.hProcess, out var exitCode) || exitCode != 0) throw new InvalidOperationException($"Interactive desktop helper exited with code {exitCode}.");
            return envelope.Json;
        }
        finally
        {
            if (processInfo.hProcess != IntPtr.Zero && WaitForSingleObject(processInfo.hProcess, 0) == WAIT_TIMEOUT)
            {
                try { TerminateProcess(processInfo.hProcess, 1); } catch { }
            }
            if (processInfo.hThread != IntPtr.Zero) CloseHandle(processInfo.hThread);
            if (processInfo.hProcess != IntPtr.Zero) CloseHandle(processInfo.hProcess);
            if (environment != IntPtr.Zero) DestroyEnvironmentBlock(environment);
            if (userToken != IntPtr.Zero) CloseHandle(userToken);
        }
    }

    private static IReadOnlyList<DesktopDisplayItem> ReadDisplaysLocal()
    {
        var result = new List<DesktopDisplayItem>();
        if (!EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, (monitor, _, _, _) =>
        {
            var info = ReadMonitorInfo(monitor);
            result.Add(new DesktopDisplayItem(HandleToHex(monitor), info.szDevice ?? string.Empty, ToRectangle(info.rcMonitor), ToRectangle(info.rcWork), (info.dwFlags & MONITORINFOF_PRIMARY) != 0));
            return true;
        }, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to enumerate interactive desktop monitors.");
        return result.OrderByDescending(x => x.Primary).ThenBy(x => x.Bounds.Left).ThenBy(x => x.Bounds.Top).ToArray();
    }

    private static DesktopCursorPositionResult ReadCursorPositionLocal()
    {
        if (!GetCursorPos(out var point)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to read interactive cursor position.");
        var monitor = MonitorFromPoint(point, MONITOR_DEFAULTTONEAREST);
        if (monitor == IntPtr.Zero) return new DesktopCursorPositionResult(point.X, point.Y, null, null, null, null);
        var info = ReadMonitorInfo(monitor);
        return new DesktopCursorPositionResult(point.X, point.Y, HandleToHex(monitor), info.szDevice ?? string.Empty, ToRectangle(info.rcMonitor), (info.dwFlags & MONITORINFOF_PRIMARY) != 0);
    }

    private static IReadOnlyList<DesktopWindowItem> ReadWindowsLocal()
    {
        var foreground = GetForegroundWindow();
        var result = new List<DesktopWindowItem>();
        if (!EnumWindows((window, _) =>
        {
            if (window == IntPtr.Zero || !IsWindowVisible(window)) return true;
            var title = ReadWindowTitle(window);
            if (string.IsNullOrWhiteSpace(title) || !GetWindowRect(window, out var rect)) return true;
            GetWindowThreadProcessId(window, out var processId);
            var process = ReadProcessMetadata(processId);
            result.Add(new DesktopWindowItem(HandleToHex(window), processId, process.Name, process.Path, process.StartTimeUtc, title, ToRectangle(rect), true, IsIconic(window), window == foreground));
            return true;
        }, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to enumerate interactive desktop windows.");
        return result.OrderByDescending(x => x.Foreground).ThenBy(x => x.ProcessName, StringComparer.OrdinalIgnoreCase).ThenBy(x => x.Title, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static DesktopWindowItem? ReadForegroundWindowLocal()
    {
        var window = GetForegroundWindow();
        if (window == IntPtr.Zero) return null;
        var snapshot = ReadWindowSnapshotLocal(HandleToHex(window));
        return new DesktopWindowItem(HandleToHex(window), snapshot.ProcessId, snapshot.ProcessName, snapshot.ProcessPath, snapshot.ProcessStartTimeUtc, snapshot.Title, snapshot.Bounds, snapshot.Visible, snapshot.Minimized, true);
    }

    private static MonitorSnapshot ReadMonitorAtPointLocal(int x, int y)
    {
        var point = new POINT { X = x, Y = y };
        var monitor = MonitorFromPoint(point, MONITOR_DEFAULTTONULL);
        if (monitor == IntPtr.Zero) throw new ArgumentOutOfRangeException(nameof(x), "Target coordinate is not on an attached interactive monitor.");
        var info = ReadMonitorInfo(monitor);
        return new MonitorSnapshot(HandleToHex(monitor), ToRectangle(info.rcMonitor), info.szDevice ?? string.Empty, (info.dwFlags & MONITORINFOF_PRIMARY) != 0);
    }

    private static WindowSnapshot ReadWindowSnapshotLocal(string hwnd)
    {
        var window = ParseHandle(hwnd);
        if (window == IntPtr.Zero || !IsWindow(window)) throw new ArgumentException("Target HWND does not identify a current interactive window.");
        if (!GetWindowRect(window, out var rect)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to read target interactive window bounds.");
        GetWindowThreadProcessId(window, out var processId);
        var process = ReadProcessMetadata(processId);
        return new WindowSnapshot(processId, process.Name, process.Path, process.StartTimeUtc, ReadWindowTitle(window), ToRectangle(rect), IsWindowVisible(window), IsIconic(window), window == GetForegroundWindow());
    }

    private static void MoveCursorLocal(int x, int y)
    {
        _ = ReadMonitorAtPointLocal(x, y);
        if (!SetCursorPos(x, y)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to move interactive desktop cursor.");
    }

    private static void MouseClickLocal(int x, int y, string button)
    {
        MoveCursorLocal(x, y);
        var (down, up) = button switch
        {
            "left" => (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP),
            "right" => (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
            "middle" => (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
            _ => throw new ArgumentOutOfRangeException(nameof(button))
        };
        var inputs = new[] { CreateMouseInput(down), CreateMouseInput(up) };
        var sent = SendInput((uint)inputs.Length, inputs, Marshal.SizeOf<INPUT>());
        if (sent != inputs.Length) throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to emit the complete interactive mouse click sequence.");
    }

    private static void ActivateWindowLocal(string hwnd)
    {
        var window = ParseHandle(hwnd);
        var snapshot = ReadWindowSnapshotLocal(hwnd);
        if (!snapshot.Visible) throw new InvalidOperationException("Target interactive window must be visible.");
        if (string.Equals(snapshot.ProcessName, "ApplicationFrameHost", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("ApplicationFrameHost wrapper windows are not eligible activation targets.");
        var currentThreadId = GetCurrentThreadId();
        var foreground = GetForegroundWindow();
        var foregroundThreadId = foreground == IntPtr.Zero ? 0u : GetWindowThreadProcessId(foreground, out _);
        var targetThreadId = GetWindowThreadProcessId(window, out _);
        var attachedForeground = false;
        var attachedTarget = false;
        try
        {
            if (foregroundThreadId != 0 && foregroundThreadId != currentThreadId) attachedForeground = AttachThreadInput(currentThreadId, foregroundThreadId, true);
            if (targetThreadId != 0 && targetThreadId != currentThreadId && targetThreadId != foregroundThreadId) attachedTarget = AttachThreadInput(currentThreadId, targetThreadId, true);
            if (IsIconic(window)) ShowWindowAsync(window, SW_RESTORE);
            BringWindowToTop(window);
            SetForegroundWindow(window);
            if (GetForegroundWindow() != window)
            {
                var inputs = new[] { CreateKeyboardInput(VK_MENU, 0), CreateKeyboardInput(VK_MENU, KEYEVENTF_KEYUP) };
                if (SendInput((uint)inputs.Length, inputs, Marshal.SizeOf<INPUT>()) != inputs.Length) throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to emit fixed ALT foreground-unlock sequence.");
                SetForegroundWindow(window);
            }
            if (GetForegroundWindow() != window) throw new InvalidOperationException("Windows did not allow the signed target interactive window to become foreground.");
        }
        finally
        {
            if (attachedTarget) AttachThreadInput(currentThreadId, targetThreadId, false);
            if (attachedForeground) AttachThreadInput(currentThreadId, foregroundThreadId, false);
        }
    }

    private static string ExecuteAndAck(Action action) { action(); return "true"; }
    private static int RequireInt(int? value, string name) => value ?? throw new ArgumentException($"{name} is required.");
    private static string RequireHwnd(string? value) => !string.IsNullOrWhiteSpace(value) ? value : throw new ArgumentException("hwnd is required.");
    private static string NormalizeButton(string? button)
    {
        var value = (button ?? string.Empty).Trim().ToLowerInvariant();
        return value is "left" or "right" or "middle" ? value : throw new ArgumentOutOfRangeException(nameof(button), "Button must be left, right, or middle.");
    }

    private static MONITORINFOEX ReadMonitorInfo(IntPtr monitor)
    {
        var info = new MONITORINFOEX { cbSize = Marshal.SizeOf<MONITORINFOEX>(), szDevice = string.Empty };
        if (!GetMonitorInfoW(monitor, ref info)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to read interactive monitor information.");
        return info;
    }

    private static (string Name, string? Path, string? StartTimeUtc) ReadProcessMetadata(uint processId)
    {
        try
        {
            using var process = Process.GetProcessById(checked((int)processId));
            string? path = null; string? start = null;
            try { path = process.MainModule?.FileName; } catch { }
            try { start = process.StartTime.ToUniversalTime().ToString("O"); } catch { }
            return (process.ProcessName, path, start);
        }
        catch { return (string.Empty, null, null); }
    }

    private static string ReadWindowTitle(IntPtr window)
    {
        var length = GetWindowTextLengthW(window);
        if (length <= 0) return string.Empty;
        var builder = new StringBuilder(Math.Min(length + 1, 4096));
        return GetWindowTextW(window, builder, builder.Capacity) <= 0 ? string.Empty : builder.ToString();
    }

    private static DesktopRectangle ToRectangle(RECT r) => new(r.Left, r.Top, r.Right, r.Bottom, r.Right - r.Left, r.Bottom - r.Top);
    private static string HandleToHex(IntPtr handle) => $"0x{unchecked((ulong)handle.ToInt64()):X}";
    private static IntPtr ParseHandle(string hwnd)
    {
        var text = hwnd.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) text = text[2..];
        if (!ulong.TryParse(text, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var value)) throw new ArgumentException("HWND must be hexadecimal such as 0x123ABC.", nameof(hwnd));
        return new IntPtr(unchecked((long)value));
    }

    private static HelperRequest DecodeRequest(string? encoded)
    {
        if (string.IsNullOrWhiteSpace(encoded)) return new HelperRequest();
        var bytes = Convert.FromBase64String(encoded);
        if (bytes.Length > 16 * 1024) throw new InvalidDataException("Interactive desktop helper request exceeded the bounded limit.");
        return JsonSerializer.Deserialize<HelperRequest>(bytes) ?? new HelperRequest();
    }

    private static void ReadExactly(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var read = stream.Read(buffer, offset, buffer.Length - offset);
            if (read <= 0) throw new EndOfStreamException("Interactive desktop helper pipe closed unexpectedly.");
            offset += read;
        }
    }

    private static void ValidateFixedDotnetHost()
    {
        if (!File.Exists(DotnetExe)) throw new FileNotFoundException("Fixed dotnet.exe host was not found.", DotnetExe);
        if ((File.GetAttributes(DotnetExe) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Fixed dotnet.exe host may not be a reparse point.");
    }

    private static string SanitizeError(Exception ex)
    {
        var text = $"{ex.GetType().Name}: {ex.Message}".Replace("\r", " ").Replace("\n", " ").Trim();
        return text.Length <= 1024 ? text : text[..1024];
    }

    private static void AppendQuotedArgument(StringBuilder command, string value)
    {
        if (command.Length > 0) command.Append(' ');
        command.Append('"');
        var backslashes = 0;
        foreach (var c in value)
        {
            if (c == '\\') { backslashes++; continue; }
            if (c == '"') { command.Append('\\', backslashes * 2 + 1).Append('"'); backslashes = 0; continue; }
            if (backslashes > 0) { command.Append('\\', backslashes); backslashes = 0; }
            command.Append(c);
        }
        if (backslashes > 0) command.Append('\\', backslashes * 2);
        command.Append('"');
    }

    private static INPUT CreateMouseInput(uint flags) => new() { type = INPUT_MOUSE, U = new INPUTUNION { mi = new MOUSEINPUT { dwFlags = flags } } };
    private static INPUT CreateKeyboardInput(ushort key, uint flags) => new() { type = INPUT_KEYBOARD, U = new INPUTUNION { ki = new KEYBDINPUT { wVk = key, dwFlags = flags } } };

    private delegate bool MonitorEnumProc(IntPtr hMonitor, IntPtr hdcMonitor, IntPtr lprcMonitor, IntPtr dwData);
    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("kernel32.dll")] private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("wtsapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);
    [DllImport("userenv.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);
    [DllImport("userenv.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CreateProcessAsUserW(IntPtr hToken, string? lpApplicationName, StringBuilder lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr hObject);
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr lprcClip, MonitorEnumProc lpfnEnum, IntPtr dwData);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetMonitorInfoW(IntPtr hMonitor, ref MONITORINFOEX lpmi);
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetCursorPos(out POINT lpPoint);
    [DllImport("user32.dll")] private static extern IntPtr MonitorFromPoint(POINT pt, uint dwFlags);
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetCursorPos(int X, int Y);
    [DllImport("user32.dll", SetLastError = true)] private static extern uint SendInput(uint cInputs, INPUT[] pInputs, int cbSize);
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool IsWindow(IntPtr hWnd);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool IsIconic(IntPtr hWnd);
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern int GetWindowTextLengthW(IntPtr hWnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern int GetWindowTextW(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, [MarshalAs(UnmanagedType.Bool)] bool fAttach);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool BringWindowToTop(IntPtr hWnd);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetForegroundWindow(IntPtr hWnd);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct STARTUPINFO { public int cb; public string? lpReserved; public string? lpDesktop; public string? lpTitle; public int dwX; public int dwY; public int dwXSize; public int dwYSize; public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute; public int dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }
    [StructLayout(LayoutKind.Sequential)] private struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId; }
    [StructLayout(LayoutKind.Sequential)] private struct POINT { public int X; public int Y; }
    [StructLayout(LayoutKind.Sequential)] private struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct MONITORINFOEX { public int cbSize; public RECT rcMonitor; public RECT rcWork; public uint dwFlags; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string szDevice; }
    [StructLayout(LayoutKind.Sequential)] private struct INPUT { public uint type; public INPUTUNION U; }
    [StructLayout(LayoutKind.Explicit)] private struct INPUTUNION { [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; }
    [StructLayout(LayoutKind.Sequential)] private struct MOUSEINPUT { public int dx; public int dy; public uint mouseData; public uint dwFlags; public uint time; public UIntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Sequential)] private struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public UIntPtr dwExtraInfo; }
}