using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace YowThi.DevelopmentAgent3.Windows;

internal static class InteractiveDesktopKeyboardBridge
{
    internal const string HelperSwitch = "--yowthi-desktop-keyboard-helper";
    private const string DotnetExe = @"C:\Program Files\dotnet\dotnet.exe";
    private const int HelperTimeoutSeconds = 20;
    private const int MaxPayloadBytes = 1024 * 1024;
    private const int MaxRequestBytes = 64 * 1024;
    private const uint INPUT_KEYBOARD = 1;
    private const uint KEYEVENTF_KEYUP = 0x0002;
    private const uint KEYEVENTF_UNICODE = 0x0004;
    private const ushort VK_CONTROL = 0x11;
    private const ushort VK_RETURN = 0x0D;
    private const ushort VK_TAB = 0x09;
    private const ushort VK_ESCAPE = 0x1B;
    private const ushort VK_A = 0x41;
    private const ushort VK_S = 0x53;
    private const uint WAIT_OBJECT_0 = 0;
    private const uint WAIT_TIMEOUT = 0x102;

    private sealed record HelperRequest(string? Hwnd = null, string? Shortcut = null, string? Text = null);
    private sealed record HelperWireRequest(string Token, string Action, HelperRequest Request);
    private sealed record HelperEnvelope(bool Success, string? Error, string? Json, int HelperProcessId, int SessionId);

    internal static void KeyboardShortcut(string hwnd, string shortcut)
        => InvokeAck("keyboard-shortcut", new HelperRequest(Hwnd: hwnd, Shortcut: shortcut));

    internal static void TextInput(string hwnd, string text)
        => InvokeAck("text-input", new HelperRequest(Hwnd: hwnd, Text: text));

    internal static Task<bool> TryRunHelperAsync(string[] args)
    {
        if (!args.Any(x => string.Equals(x, HelperSwitch, StringComparison.Ordinal)))
            return Task.FromResult(false);

        int? port = null;
        string? token = null;
        for (var i = 0; i < args.Length; i++)
        {
            if (string.Equals(args[i], "--port", StringComparison.Ordinal) && i + 1 < args.Length && int.TryParse(args[++i], NumberStyles.None, CultureInfo.InvariantCulture, out var parsedPort)) port = parsedPort;
            else if (string.Equals(args[i], "--token", StringComparison.Ordinal) && i + 1 < args.Length) token = args[++i];
        }

        if (port is null || port <= 0 || port > 65535 || string.IsNullOrWhiteSpace(token))
            return Task.FromResult(true);

        using var client = new TcpClient(AddressFamily.InterNetwork);
        client.Connect(IPAddress.Loopback, port.Value);
        using var stream = client.GetStream();
        ConfigureTimeouts(stream);

        HelperEnvelope envelope;
        try
        {
            var wire = ReadFrame<HelperWireRequest>(stream, MaxRequestBytes);
            if (!FixedTimeTokenEquals(token, wire.Token))
                throw new UnauthorizedAccessException("Interactive keyboard helper token validation failed.");

            var result = ExecuteHelperAction(wire.Action, wire.Request);
            envelope = new HelperEnvelope(true, null, result, Environment.ProcessId, Process.GetCurrentProcess().SessionId);
        }
        catch (Exception ex)
        {
            envelope = new HelperEnvelope(false, SanitizeError(ex), null, Environment.ProcessId, Process.GetCurrentProcess().SessionId);
        }

        WriteFrame(stream, envelope, MaxPayloadBytes);
        return Task.FromResult(true);
    }

    private static string ExecuteHelperAction(string action, HelperRequest request)
    {
        return action switch
        {
            "keyboard-shortcut" => ExecuteAndAck(() => KeyboardShortcutLocal(RequireHwnd(request.Hwnd), NormalizeShortcut(request.Shortcut))),
            "text-input" => ExecuteAndAck(() => TextInputLocal(RequireHwnd(request.Hwnd), ValidateText(request.Text))),
            _ => throw new ArgumentException("Unsupported interactive keyboard helper action.")
        };
    }

    private static void InvokeAck(string action, HelperRequest request)
    {
        var json = InvokeRaw(action, request);
        if (!string.Equals(json, "true", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Interactive keyboard helper did not acknowledge the requested action.");
    }

    private static string InvokeRaw(string action, HelperRequest request)
    {
        if (Process.GetCurrentProcess().SessionId != 0)
            return ExecuteHelperAction(action, request);

        var sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId == 0xFFFFFFFF) throw new InvalidOperationException("No active console session is available for keyboard interaction.");
        if (!WTSQueryUserToken(sessionId, out var userToken) || userToken == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to obtain the active interactive user token.");

        IntPtr environment = IntPtr.Zero;
        PROCESS_INFORMATION processInfo = default;
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        try
        {
            listener.Start(1);
            var endpoint = (IPEndPoint)listener.LocalEndpoint;
            var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

            if (!CreateEnvironmentBlock(out environment, userToken, false))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to create the interactive user environment.");
            ValidateFixedDotnetHost();
            var runtimeDll = typeof(InteractiveDesktopKeyboardBridge).Assembly.Location;
            if (string.IsNullOrWhiteSpace(runtimeDll) || !File.Exists(runtimeDll)) throw new FileNotFoundException("Unable to resolve the active Agent runtime assembly.", runtimeDll);
            if ((File.GetAttributes(runtimeDll) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("The active Agent runtime assembly may not be a reparse point.");

            var command = new StringBuilder();
            AppendQuotedArgument(command, DotnetExe);
            AppendQuotedArgument(command, runtimeDll);
            AppendQuotedArgument(command, HelperSwitch);
            AppendQuotedArgument(command, "--port");
            AppendQuotedArgument(command, endpoint.Port.ToString(CultureInfo.InvariantCulture));
            AppendQuotedArgument(command, "--token");
            AppendQuotedArgument(command, token);

            var startup = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>(), lpDesktop = @"winsta0\default" };
            const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
            const uint CREATE_NO_WINDOW = 0x08000000;
            if (!CreateProcessAsUserW(userToken, DotnetExe, command, IntPtr.Zero, IntPtr.Zero, false, CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, environment, Path.GetDirectoryName(runtimeDll), ref startup, out processInfo))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to launch the interactive keyboard helper in the active console session.");

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(HelperTimeoutSeconds));
            using var client = listener.AcceptTcpClientAsync(cts.Token).GetAwaiter().GetResult();
            if (client.Client.RemoteEndPoint is not IPEndPoint remote || !IPAddress.IsLoopback(remote.Address))
                throw new UnauthorizedAccessException("Interactive keyboard helper connected from a non-loopback endpoint.");

            using var stream = client.GetStream();
            ConfigureTimeouts(stream);
            WriteFrame(stream, new HelperWireRequest(token, action, request), MaxRequestBytes);
            var envelope = ReadFrame<HelperEnvelope>(stream, MaxPayloadBytes);
            if (envelope.SessionId != checked((int)sessionId)) throw new InvalidDataException("Interactive keyboard helper did not execute in the sealed active console session.");
            if (!envelope.Success) throw new InvalidOperationException(envelope.Error ?? "Interactive keyboard helper failed.");
            if (envelope.Json is null) throw new InvalidDataException("Interactive keyboard helper returned no result payload.");

            var wait = WaitForSingleObject(processInfo.hProcess, 5_000);
            if (wait != WAIT_OBJECT_0) throw new TimeoutException("Interactive keyboard helper did not exit after returning its result.");
            if (!GetExitCodeProcess(processInfo.hProcess, out var exitCode) || exitCode != 0) throw new InvalidOperationException($"Interactive keyboard helper exited with code {exitCode}.");
            return envelope.Json;
        }
        finally
        {
            listener.Stop();
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

    private static void KeyboardShortcutLocal(string hwnd, string shortcut)
    {
        RequireForegroundTarget(hwnd);
        INPUT[] inputs = shortcut switch
        {
            "ctrl+a" => new[] { Key(VK_CONTROL), Key(VK_A), Key(VK_A, KEYEVENTF_KEYUP), Key(VK_CONTROL, KEYEVENTF_KEYUP) },
            "ctrl+s" => new[] { Key(VK_CONTROL), Key(VK_S), Key(VK_S, KEYEVENTF_KEYUP), Key(VK_CONTROL, KEYEVENTF_KEYUP) },
            "enter" => new[] { Key(VK_RETURN), Key(VK_RETURN, KEYEVENTF_KEYUP) },
            "tab" => new[] { Key(VK_TAB), Key(VK_TAB, KEYEVENTF_KEYUP) },
            "escape" => new[] { Key(VK_ESCAPE), Key(VK_ESCAPE, KEYEVENTF_KEYUP) },
            _ => throw new ArgumentOutOfRangeException(nameof(shortcut))
        };
        Emit(inputs, "keyboard shortcut");
    }

    private static void TextInputLocal(string hwnd, string text)
    {
        RequireForegroundTarget(hwnd);
        var inputs = new INPUT[text.Length * 2];
        var index = 0;
        foreach (var ch in text)
        {
            inputs[index++] = UnicodeKey(ch, 0);
            inputs[index++] = UnicodeKey(ch, KEYEVENTF_KEYUP);
        }
        Emit(inputs, "Unicode text input");
    }

    private static void RequireForegroundTarget(string hwnd)
    {
        var target = ParseHandle(hwnd);
        if (target == IntPtr.Zero || !IsWindow(target)) throw new InvalidOperationException("Target HWND is no longer a valid interactive window.");
        if (!IsWindowVisible(target) || IsIconic(target)) throw new InvalidOperationException("Target interactive window must remain visible and non-minimized.");
        if (GetForegroundWindow() != target) throw new InvalidOperationException("Target interactive window is no longer foreground; keyboard input was not emitted.");
    }

    private static void Emit(INPUT[] inputs, string label)
    {
        if (inputs.Length == 0) return;
        var sent = SendInput((uint)inputs.Length, inputs, Marshal.SizeOf<INPUT>());
        if (sent != inputs.Length) throw new Win32Exception(Marshal.GetLastWin32Error(), $"Unable to emit the complete {label} sequence.");
    }

    private static INPUT Key(ushort key, uint flags = 0) => new() { type = INPUT_KEYBOARD, U = new INPUTUNION { ki = new KEYBDINPUT { wVk = key, dwFlags = flags } } };
    private static INPUT UnicodeKey(char ch, uint flags) => new() { type = INPUT_KEYBOARD, U = new INPUTUNION { ki = new KEYBDINPUT { wVk = 0, wScan = ch, dwFlags = KEYEVENTF_UNICODE | flags } } };
    private static string ExecuteAndAck(Action action) { action(); return "true"; }

    private static string RequireHwnd(string? value) => !string.IsNullOrWhiteSpace(value) ? NormalizeHandle(value) : throw new ArgumentException("hwnd is required.");

    private static string NormalizeShortcut(string? shortcut)
    {
        var value = (shortcut ?? string.Empty).Trim().ToLowerInvariant().Replace(" ", string.Empty, StringComparison.Ordinal);
        return value switch
        {
            "ctrl+a" => "ctrl+a",
            "ctrl+s" => "ctrl+s",
            "enter" => "enter",
            "tab" => "tab",
            "esc" or "escape" => "escape",
            _ => throw new ArgumentOutOfRangeException(nameof(shortcut), "Shortcut must be ctrl+a, ctrl+s, enter, tab, or escape.")
        };
    }

    private static string ValidateText(string? text)
    {
        if (text is null) throw new ArgumentNullException(nameof(text));
        if (text.Length == 0 || text.Length > 8192) throw new ArgumentOutOfRangeException(nameof(text), "Text must contain 1-8192 UTF-16 code units.");
        if (text.IndexOf('\0') >= 0) throw new ArgumentException("Text may not contain NUL characters.", nameof(text));
        if (Encoding.UTF8.GetByteCount(text) > 16384) throw new ArgumentOutOfRangeException(nameof(text), "UTF-8 text payload may not exceed 16384 bytes.");
        return text;
    }

    private static string NormalizeHandle(string hwnd)
    {
        var text = hwnd.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) text = text[2..];
        if (!ulong.TryParse(text, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var value)) throw new ArgumentException("HWND must be hexadecimal such as 0x123ABC.", nameof(hwnd));
        return $"0x{value:X}";
    }

    private static IntPtr ParseHandle(string hwnd)
    {
        var text = NormalizeHandle(hwnd)[2..];
        _ = ulong.TryParse(text, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var value);
        return new IntPtr(unchecked((long)value));
    }

    private static void ConfigureTimeouts(NetworkStream stream)
    {
        var timeoutMilliseconds = checked(HelperTimeoutSeconds * 1000);
        stream.ReadTimeout = timeoutMilliseconds;
        stream.WriteTimeout = timeoutMilliseconds;
    }

    private static void WriteFrame<T>(Stream stream, T value, int maximumBytes)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(value);
        if (payload.Length <= 0 || payload.Length > maximumBytes) throw new InvalidDataException("Interactive keyboard helper frame exceeded the bounded limit.");
        Span<byte> prefix = stackalloc byte[4];
        BitConverter.TryWriteBytes(prefix, payload.Length);
        stream.Write(prefix);
        stream.Write(payload);
        stream.Flush();
    }

    private static T ReadFrame<T>(Stream stream, int maximumBytes)
    {
        var prefix = new byte[4];
        ReadExactly(stream, prefix);
        var payloadLength = BitConverter.ToInt32(prefix, 0);
        if (payloadLength <= 0 || payloadLength > maximumBytes) throw new InvalidDataException("Interactive keyboard helper returned an invalid frame length.");
        var payload = new byte[payloadLength];
        ReadExactly(stream, payload);
        return JsonSerializer.Deserialize<T>(payload) ?? throw new InvalidDataException("Interactive keyboard helper returned an invalid frame payload.");
    }

    private static void ReadExactly(Stream stream, byte[] buffer)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = stream.Read(buffer, offset, buffer.Length - offset);
            if (read <= 0) throw new EndOfStreamException("Interactive keyboard helper connection closed unexpectedly.");
            offset += read;
        }
    }

    private static bool FixedTimeTokenEquals(string expected, string actual)
    {
        if (expected.Length != actual.Length) return false;
        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(actual));
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

    [DllImport("kernel32.dll")] private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("wtsapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);
    [DllImport("userenv.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);
    [DllImport("userenv.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CreateProcessAsUserW(IntPtr hToken, string? lpApplicationName, StringBuilder lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr hObject);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool IsWindow(IntPtr hWnd);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool IsIconic(IntPtr hWnd);
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", SetLastError = true)] private static extern uint SendInput(uint cInputs, INPUT[] pInputs, int cbSize);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct STARTUPINFO { public int cb; public string? lpReserved; public string? lpDesktop; public string? lpTitle; public int dwX; public int dwY; public int dwXSize; public int dwYSize; public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute; public int dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }
    [StructLayout(LayoutKind.Sequential)] private struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId; }
    [StructLayout(LayoutKind.Sequential)] private struct INPUT { public uint type; public INPUTUNION U; }
    [StructLayout(LayoutKind.Explicit)] private struct INPUTUNION { [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; }
    [StructLayout(LayoutKind.Sequential)] private struct MOUSEINPUT { public int dx; public int dy; public uint mouseData; public uint dwFlags; public uint time; public UIntPtr dwExtraInfo; }
    [StructLayout(LayoutKind.Sequential)] private struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public UIntPtr dwExtraInfo; }
}