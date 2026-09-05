using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Compression;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace YowThi.DevelopmentAgent3.Windows;

[McpServerToolType]
public static class InteractiveDesktopCaptureTools
{
    private const string HelperSwitch = "--yowthi-desktop-capture-helper";
    private const string DotnetExe = @"C:\Program Files\dotnet\dotnet.exe";
    private const int HelperTimeoutSeconds = 20;
    private const int MaxHeaderBytes = 64 * 1024;
    private const int MaxPngBytes = 24 * 1024 * 1024;
    private const long MaxPixels = 40_000_000;

    [McpServerTool(Name = "desktop_screenshot_capture", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Capture the active interactive Windows desktop as a PNG image. When deviceName is omitted the complete virtual desktop is captured; otherwise the exact interactive monitor device name (for example \\\\.\\DISPLAY1) is captured. A Session 0 Agent launches only its own current runtime through the fixed dotnet.exe host in the active console user session, captures through native Windows GDI, returns the PNG through an inherited anonymous pipe, and does not persist the image to disk. No PowerShell, cmd, shell, arbitrary executable, keyboard input, mouse input, window activation, or filesystem output is used.")]
    public static async Task<IReadOnlyList<ContentBlock>> DesktopScreenshotCapture(
        [Description("Optional exact monitor device name. Omit to capture the complete virtual desktop.")] string? deviceName = null)
    {
        var payload = await CaptureInInteractiveSessionAsync("desktop", NormalizeOptionalTarget(deviceName));
        return ToContentBlocks(payload);
    }

    [McpServerTool(Name = "desktop_window_capture", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Capture one visible non-minimized top-level window from the active interactive Windows session as a PNG image. Pass an HWND in hexadecimal form such as 0x123ABC; when hwnd is omitted the current interactive foreground window is captured. The HWND/process/session identity is validated inside the interactive helper immediately before capture. The image is returned through an inherited anonymous pipe and is never persisted to disk. No PowerShell, cmd, shell, arbitrary executable, keyboard input, mouse input, window activation, or filesystem output is used.")]
    public static async Task<IReadOnlyList<ContentBlock>> DesktopWindowCapture(
        [Description("Optional top-level window HWND such as 0x123ABC. Omit to capture the current interactive foreground window.")] string? hwnd = null)
    {
        var payload = await CaptureInInteractiveSessionAsync("window", NormalizeOptionalTarget(hwnd));
        return ToContentBlocks(payload);
    }

    internal static async Task<bool> TryRunHelperAsync(string[] args)
    {
        if (!args.Any(x => string.Equals(x, HelperSwitch, StringComparison.Ordinal)))
            return false;

        string? pipeHandle = null;
        string? action = null;
        string? target = null;
        for (var i = 0; i < args.Length; i++)
        {
            if (string.Equals(args[i], "--pipe", StringComparison.Ordinal) && i + 1 < args.Length)
                pipeHandle = args[++i];
            else if (string.Equals(args[i], "--action", StringComparison.Ordinal) && i + 1 < args.Length)
                action = args[++i];
            else if (string.Equals(args[i], "--target", StringComparison.Ordinal) && i + 1 < args.Length)
                target = args[++i];
        }

        if (string.IsNullOrWhiteSpace(pipeHandle))
            return true;

        await using var pipe = new AnonymousPipeClientStream(PipeDirection.Out, pipeHandle);
        CaptureWireHeader header;
        byte[] png = Array.Empty<byte>();
        try
        {
            var captured = action switch
            {
                "desktop" => CaptureDesktop(target),
                "window" => CaptureWindow(target),
                _ => throw new ArgumentException("Unsupported desktop capture helper action.")
            };
            png = captured.PngBytes;
            if (png.Length <= 0 || png.Length > MaxPngBytes)
                throw new InvalidDataException($"Captured PNG size {png.Length} is outside the allowed range.");

            header = new CaptureWireHeader(
                true, null, captured.Kind, captured.Target, captured.Width, captured.Height,
                captured.DeviceName, captured.Hwnd, captured.Title,
                Convert.ToHexString(SHA256.HashData(png)), png.Length,
                Environment.ProcessId, Process.GetCurrentProcess().SessionId, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            header = new CaptureWireHeader(
                false, SanitizeError(ex), action ?? string.Empty, target, 0, 0,
                null, null, null, null, 0,
                Environment.ProcessId, Process.GetCurrentProcess().SessionId, DateTimeOffset.UtcNow);
        }

        var headerBytes = JsonSerializer.SerializeToUtf8Bytes(header);
        if (headerBytes.Length > MaxHeaderBytes)
            throw new InvalidDataException("Desktop capture helper header exceeded the bounded limit.");
        var prefix = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(prefix, headerBytes.Length);
        await pipe.WriteAsync(prefix);
        await pipe.WriteAsync(headerBytes);
        if (png.Length > 0) await pipe.WriteAsync(png);
        await pipe.FlushAsync();
        return true;
    }

    private static async Task<DesktopCapturePayload> CaptureInInteractiveSessionAsync(string action, string? target)
    {
        if (action is not ("desktop" or "window"))
            throw new ArgumentException("Unsupported desktop capture action.", nameof(action));

        if (Process.GetCurrentProcess().SessionId != 0)
        {
            var local = action == "desktop" ? CaptureDesktop(target) : CaptureWindow(target);
            return new DesktopCapturePayload(
                local.Kind, local.Target, local.Width, local.Height, local.DeviceName,
                local.Hwnd, local.Title, local.PngBytes,
                Environment.ProcessId, Process.GetCurrentProcess().SessionId, DateTimeOffset.UtcNow);
        }

        var sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId == 0xFFFFFFFF)
            throw new InvalidOperationException("No active console session is available for desktop capture.");
        if (!WTSQueryUserToken(sessionId, out var userToken) || userToken == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to obtain the active interactive user token.");

        IntPtr environment = IntPtr.Zero;
        PROCESS_INFORMATION processInfo = default;
        await using var pipe = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable);
        try
        {
            if (!CreateEnvironmentBlock(out environment, userToken, false))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to create the interactive user environment.");

            ValidateFixedDotnetHost();
            var runtimeDll = typeof(InteractiveDesktopCaptureTools).Assembly.Location;
            if (string.IsNullOrWhiteSpace(runtimeDll) || !File.Exists(runtimeDll))
                throw new FileNotFoundException("Unable to resolve the active Agent runtime assembly.", runtimeDll);
            if ((File.GetAttributes(runtimeDll) & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException("The active Agent runtime assembly may not be a reparse point.");

            var command = new StringBuilder();
            AppendQuotedArgument(command, DotnetExe);
            AppendQuotedArgument(command, runtimeDll);
            AppendQuotedArgument(command, HelperSwitch);
            AppendQuotedArgument(command, "--pipe");
            AppendQuotedArgument(command, pipe.GetClientHandleAsString());
            AppendQuotedArgument(command, "--action");
            AppendQuotedArgument(command, action);
            if (!string.IsNullOrWhiteSpace(target))
            {
                AppendQuotedArgument(command, "--target");
                AppendQuotedArgument(command, target);
            }

            var startup = new STARTUPINFO
            {
                cb = Marshal.SizeOf<STARTUPINFO>(),
                lpDesktop = @"winsta0\default"
            };
            const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
            const uint CREATE_NO_WINDOW = 0x08000000;
            if (!CreateProcessAsUserW(
                    userToken, DotnetExe, command, IntPtr.Zero, IntPtr.Zero, true,
                    CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                    environment, Path.GetDirectoryName(runtimeDll), ref startup, out processInfo))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to launch the desktop capture helper in the active interactive session.");

            pipe.DisposeLocalCopyOfClientHandle();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(HelperTimeoutSeconds));
            var prefix = new byte[4];
            await ReadExactlyAsync(pipe, prefix, cts.Token);
            var headerLength = BinaryPrimitives.ReadInt32LittleEndian(prefix);
            if (headerLength <= 0 || headerLength > MaxHeaderBytes)
                throw new InvalidDataException("Desktop capture helper returned an invalid header length.");

            var headerBytes = new byte[headerLength];
            await ReadExactlyAsync(pipe, headerBytes, cts.Token);
            var header = JsonSerializer.Deserialize<CaptureWireHeader>(headerBytes)
                ?? throw new InvalidDataException("Desktop capture helper returned an invalid header.");
            if (!header.Success)
                throw new InvalidOperationException(header.Error ?? "Interactive desktop capture failed.");
            if (header.Bytes <= 0 || header.Bytes > MaxPngBytes)
                throw new InvalidDataException("Desktop capture helper returned an invalid PNG byte count.");
            if (header.SessionId != checked((int)sessionId))
                throw new InvalidDataException("Desktop capture helper did not execute in the sealed active console session.");

            var png = new byte[header.Bytes];
            await ReadExactlyAsync(pipe, png, cts.Token);
            var actualSha = Convert.ToHexString(SHA256.HashData(png));
            if (!string.Equals(actualSha, header.Sha256, StringComparison.Ordinal))
                throw new InvalidDataException("Desktop capture helper PNG SHA-256 verification failed.");

            var wait = WaitForSingleObject(processInfo.hProcess, 5_000);
            if (wait != WAIT_OBJECT_0)
                throw new TimeoutException("Desktop capture helper did not exit after returning the capture.");
            if (!GetExitCodeProcess(processInfo.hProcess, out var exitCode) || exitCode != 0)
                throw new InvalidOperationException($"Desktop capture helper exited with code {exitCode}.");

            return new DesktopCapturePayload(
                header.Kind, header.Target, header.Width, header.Height, header.DeviceName,
                header.Hwnd, header.Title, png, header.HelperProcessId, header.SessionId, header.CapturedUtc);
        }
        catch
        {
            if (processInfo.hProcess != IntPtr.Zero && WaitForSingleObject(processInfo.hProcess, 0) == WAIT_TIMEOUT)
            {
                try { TerminateProcess(processInfo.hProcess, 1); } catch { }
            }
            throw;
        }
        finally
        {
            if (processInfo.hThread != IntPtr.Zero) CloseHandle(processInfo.hThread);
            if (processInfo.hProcess != IntPtr.Zero) CloseHandle(processInfo.hProcess);
            if (environment != IntPtr.Zero) DestroyEnvironmentBlock(environment);
            CloseHandle(userToken);
        }
    }

    private static void ValidateFixedDotnetHost()
    {
        if (!File.Exists(DotnetExe))
            throw new FileNotFoundException("Fixed dotnet.exe host was not found.", DotnetExe);
        if ((File.GetAttributes(DotnetExe) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Fixed dotnet.exe host may not be a reparse point.");
    }

    private static IReadOnlyList<ContentBlock> ToContentBlocks(DesktopCapturePayload payload)
    {
        var metadata = JsonSerializer.Serialize(new
        {
            payload.Kind,
            payload.Target,
            payload.Width,
            payload.Height,
            payload.DeviceName,
            payload.Hwnd,
            payload.Title,
            pngBytes = payload.PngBytes.Length,
            pngSha256 = Convert.ToHexString(SHA256.HashData(payload.PngBytes)),
            payload.HelperProcessId,
            payload.SessionId,
            payload.CapturedUtc
        });

        var wireSafeImageData = Encoding.ASCII.GetBytes(Convert.ToBase64String(payload.PngBytes));
        return new ContentBlock[]
        {
            new TextContentBlock { Text = metadata },
            new ImageContentBlock { Data = wireSafeImageData, MimeType = "image/png" }
        };
    }

    private static CaptureImage CaptureDesktop(string? deviceName)
    {
        DesktopRectangleNative bounds;
        string? resolvedDevice = null;
        if (string.IsNullOrWhiteSpace(deviceName))
        {
            bounds = new DesktopRectangleNative(
                GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN),
                GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN));
        }
        else
        {
            var match = FindMonitor(deviceName);
            bounds = match.Bounds;
            resolvedDevice = match.DeviceName;
        }
        ValidateCaptureBounds(bounds);
        return new CaptureImage(
            "desktop", deviceName, bounds.Width, bounds.Height, resolvedDevice,
            null, null, CaptureScreenRectangle(bounds));
    }

    private static CaptureImage CaptureWindow(string? hwndText)
    {
        var window = string.IsNullOrWhiteSpace(hwndText) ? GetForegroundWindow() : ParseWindowHandle(hwndText);
        if (window == IntPtr.Zero || !IsWindow(window))
            throw new ArgumentException("The requested interactive window does not exist.");
        if (!IsWindowVisible(window))
            throw new InvalidOperationException("The requested interactive window is not visible.");
        if (IsIconic(window))
            throw new InvalidOperationException("Minimized windows are not captured; restore the window first.");

        GetWindowThreadProcessId(window, out var processId);
        if (processId == 0)
            throw new InvalidOperationException("Unable to resolve the requested window process.");
        if (!ProcessIdToSessionId(processId, out var windowSessionId))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to resolve the requested window session.");
        if (windowSessionId != checked((uint)Process.GetCurrentProcess().SessionId))
            throw new UnauthorizedAccessException("The requested window does not belong to the active interactive session.");
        if (!GetWindowRect(window, out var rect))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to read the requested window bounds.");

        var bounds = new DesktopRectangleNative(rect.Left, rect.Top, rect.Right - rect.Left, rect.Bottom - rect.Top);
        ValidateCaptureBounds(bounds);
        return new CaptureImage(
            "window", HandleToHex(window), bounds.Width, bounds.Height, null,
            HandleToHex(window), ReadWindowTitle(window), CaptureWindowRectangle(window, bounds));
    }

    private static byte[] CaptureScreenRectangle(DesktopRectangleNative bounds)
    {
        var screenDc = GetDC(IntPtr.Zero);
        if (screenDc == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to obtain the interactive desktop device context.");
        var memoryDc = IntPtr.Zero;
        var bitmap = IntPtr.Zero;
        var oldObject = IntPtr.Zero;
        try
        {
            memoryDc = CreateCompatibleDC(screenDc);
            if (memoryDc == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to create a compatible desktop device context.");
            bitmap = CreateCompatibleBitmap(screenDc, bounds.Width, bounds.Height);
            if (bitmap == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to allocate the desktop capture bitmap.");
            oldObject = SelectObject(memoryDc, bitmap);
            if (oldObject == IntPtr.Zero || oldObject == new IntPtr(-1))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to select the desktop capture bitmap.");
            if (!BitBlt(memoryDc, 0, 0, bounds.Width, bounds.Height, screenDc, bounds.Left, bounds.Top, SRCCOPY | CAPTUREBLT))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to copy pixels from the interactive desktop.");
            return EncodeBitmapAsPng(memoryDc, bitmap, bounds.Width, bounds.Height);
        }
        finally
        {
            if (oldObject != IntPtr.Zero && oldObject != new IntPtr(-1) && memoryDc != IntPtr.Zero) SelectObject(memoryDc, oldObject);
            if (bitmap != IntPtr.Zero) DeleteObject(bitmap);
            if (memoryDc != IntPtr.Zero) DeleteDC(memoryDc);
            ReleaseDC(IntPtr.Zero, screenDc);
        }
    }

    private static byte[] CaptureWindowRectangle(IntPtr window, DesktopRectangleNative bounds)
    {
        var screenDc = GetDC(IntPtr.Zero);
        if (screenDc == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to obtain the interactive desktop device context.");
        var memoryDc = IntPtr.Zero;
        var bitmap = IntPtr.Zero;
        var oldObject = IntPtr.Zero;
        try
        {
            memoryDc = CreateCompatibleDC(screenDc);
            if (memoryDc == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to create a compatible window capture device context.");
            bitmap = CreateCompatibleBitmap(screenDc, bounds.Width, bounds.Height);
            if (bitmap == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to allocate the window capture bitmap.");
            oldObject = SelectObject(memoryDc, bitmap);
            if (oldObject == IntPtr.Zero || oldObject == new IntPtr(-1))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to select the window capture bitmap.");
            var printed = PrintWindow(window, memoryDc, PW_RENDERFULLCONTENT);
            if (!printed && !BitBlt(memoryDc, 0, 0, bounds.Width, bounds.Height, screenDc, bounds.Left, bounds.Top, SRCCOPY | CAPTUREBLT))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to capture the requested interactive window.");
            return EncodeBitmapAsPng(memoryDc, bitmap, bounds.Width, bounds.Height);
        }
        finally
        {
            if (oldObject != IntPtr.Zero && oldObject != new IntPtr(-1) && memoryDc != IntPtr.Zero) SelectObject(memoryDc, oldObject);
            if (bitmap != IntPtr.Zero) DeleteObject(bitmap);
            if (memoryDc != IntPtr.Zero) DeleteDC(memoryDc);
            ReleaseDC(IntPtr.Zero, screenDc);
        }
    }

    private static byte[] EncodeBitmapAsPng(IntPtr dc, IntPtr bitmap, int width, int height)
    {
        checked
        {
            var pixels = new byte[width * height * 4];
            var info = new BITMAPINFO
            {
                bmiHeader = new BITMAPINFOHEADER
                {
                    biSize = checked((uint)Marshal.SizeOf<BITMAPINFOHEADER>()),
                    biWidth = width,
                    biHeight = -height,
                    biPlanes = 1,
                    biBitCount = 32,
                    biCompression = BI_RGB,
                    biSizeImage = checked((uint)pixels.Length)
                }
            };
            var rows = GetDIBits(dc, bitmap, 0, checked((uint)height), pixels, ref info, DIB_RGB_COLORS);
            if (rows != height)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to read the captured bitmap pixels.");

            using var output = new MemoryStream();
            output.Write(PngSignature);
            Span<byte> ihdr = stackalloc byte[13];
            BinaryPrimitives.WriteUInt32BigEndian(ihdr[..4], checked((uint)width));
            BinaryPrimitives.WriteUInt32BigEndian(ihdr.Slice(4, 4), checked((uint)height));
            ihdr[8] = 8;
            ihdr[9] = 6;
            WritePngChunk(output, "IHDR", ihdr);

            using var compressed = new MemoryStream();
            using (var zlib = new ZLibStream(compressed, CompressionLevel.Fastest, leaveOpen: true))
            {
                var scanline = new byte[1 + width * 4];
                for (var y = 0; y < height; y++)
                {
                    scanline[0] = 0;
                    var sourceOffset = y * width * 4;
                    var destinationOffset = 1;
                    for (var x = 0; x < width; x++)
                    {
                        var b = pixels[sourceOffset++];
                        var g = pixels[sourceOffset++];
                        var r = pixels[sourceOffset++];
                        sourceOffset++;
                        scanline[destinationOffset++] = r;
                        scanline[destinationOffset++] = g;
                        scanline[destinationOffset++] = b;
                        scanline[destinationOffset++] = 255;
                    }
                    zlib.Write(scanline);
                }
            }
            WritePngChunk(output, "IDAT", compressed.ToArray());
            WritePngChunk(output, "IEND", ReadOnlySpan<byte>.Empty);
            return output.ToArray();
        }
    }

    private static void WritePngChunk(Stream output, string type, ReadOnlySpan<byte> data)
    {
        Span<byte> lengthBytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(lengthBytes, checked((uint)data.Length));
        output.Write(lengthBytes);
        var typeBytes = Encoding.ASCII.GetBytes(type);
        output.Write(typeBytes);
        output.Write(data);
        uint crc = 0xFFFFFFFF;
        foreach (var value in typeBytes) crc = UpdateCrc32(crc, value);
        foreach (var value in data) crc = UpdateCrc32(crc, value);
        crc = ~crc;
        Span<byte> crcBytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(crcBytes, crc);
        output.Write(crcBytes);
    }

    private static uint UpdateCrc32(uint crc, byte value)
    {
        crc ^= value;
        for (var i = 0; i < 8; i++) crc = (crc >> 1) ^ ((crc & 1) != 0 ? 0xEDB88320u : 0u);
        return crc;
    }

    private static MonitorMatch FindMonitor(string deviceName)
    {
        MonitorMatch? match = null;
        if (!EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, (monitor, _, _, _) =>
        {
            var info = new MONITORINFOEX { cbSize = Marshal.SizeOf<MONITORINFOEX>(), szDevice = string.Empty };
            if (!GetMonitorInfoW(monitor, ref info)) return true;
            if (string.Equals(info.szDevice, deviceName, StringComparison.OrdinalIgnoreCase))
            {
                match ??= new MonitorMatch(
                    info.szDevice ?? string.Empty,
                    new DesktopRectangleNative(
                        info.rcMonitor.Left, info.rcMonitor.Top,
                        info.rcMonitor.Right - info.rcMonitor.Left,
                        info.rcMonitor.Bottom - info.rcMonitor.Top));
            }
            return true;
        }, IntPtr.Zero))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to enumerate interactive monitors.");
        return match ?? throw new ArgumentException($"Interactive monitor device '{deviceName}' was not found.", nameof(deviceName));
    }

    private static void ValidateCaptureBounds(DesktopRectangleNative bounds)
    {
        if (bounds.Width <= 0 || bounds.Height <= 0)
            throw new InvalidDataException("Desktop capture bounds are empty.");
        if ((long)bounds.Width * bounds.Height > MaxPixels)
            throw new InvalidDataException($"Desktop capture exceeds the {MaxPixels} pixel safety limit.");
    }

    private static IntPtr ParseWindowHandle(string value)
    {
        var text = value.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) text = text[2..];
        if (text.Length == 0 || text.Length > 16 ||
            !ulong.TryParse(text, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out var raw))
            throw new ArgumentException("hwnd must be a hexadecimal window handle such as 0x123ABC.", nameof(value));
        return new IntPtr(unchecked((long)raw));
    }

    private static string ReadWindowTitle(IntPtr window)
    {
        var length = GetWindowTextLengthW(window);
        if (length <= 0) return string.Empty;
        var builder = new StringBuilder(Math.Min(length + 1, 4096));
        var copied = GetWindowTextW(window, builder, builder.Capacity);
        return copied <= 0 ? string.Empty : builder.ToString();
    }

    private static async Task ReadExactlyAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset), cancellationToken);
            if (read <= 0) throw new EndOfStreamException("Desktop capture helper pipe closed unexpectedly.");
            offset += read;
        }
    }

    private static string? NormalizeOptionalTarget(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var trimmed = value.Trim();
        if (trimmed.Length > 256) throw new ArgumentException("Desktop capture target is too long.");
        if (trimmed.IndexOfAny(['\r', '\n', '\0']) >= 0) throw new ArgumentException("Desktop capture target contains invalid characters.");
        return trimmed;
    }

    private static string SanitizeError(Exception exception)
    {
        var text = $"{exception.GetType().Name}: {exception.Message}"
            .Replace("\r", " ", StringComparison.Ordinal)
            .Replace("\n", " ", StringComparison.Ordinal)
            .Trim();
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
            if (c == '"')
            {
                command.Append('\\', backslashes * 2 + 1).Append('"');
                backslashes = 0;
                continue;
            }
            if (backslashes > 0) { command.Append('\\', backslashes); backslashes = 0; }
            command.Append(c);
        }
        if (backslashes > 0) command.Append('\\', backslashes * 2);
        command.Append('"');
    }

    private static string HandleToHex(IntPtr handle) => $"0x{unchecked((ulong)handle.ToInt64()):X}";

    private sealed record CaptureImage(string Kind, string? Target, int Width, int Height, string? DeviceName, string? Hwnd, string? Title, byte[] PngBytes);
    private sealed record DesktopCapturePayload(string Kind, string? Target, int Width, int Height, string? DeviceName, string? Hwnd, string? Title, byte[] PngBytes, int HelperProcessId, int SessionId, DateTimeOffset CapturedUtc);
    private sealed record CaptureWireHeader(bool Success, string? Error, string Kind, string? Target, int Width, int Height, string? DeviceName, string? Hwnd, string? Title, string? Sha256, int Bytes, int HelperProcessId, int SessionId, DateTimeOffset CapturedUtc);
    private sealed record MonitorMatch(string DeviceName, DesktopRectangleNative Bounds);
    private readonly record struct DesktopRectangleNative(int Left, int Top, int Width, int Height);

    private static readonly byte[] PngSignature = [137, 80, 78, 71, 13, 10, 26, 10];
    private const int SM_XVIRTUALSCREEN = 76;
    private const int SM_YVIRTUALSCREEN = 77;
    private const int SM_CXVIRTUALSCREEN = 78;
    private const int SM_CYVIRTUALSCREEN = 79;
    private const uint SRCCOPY = 0x00CC0020;
    private const uint CAPTUREBLT = 0x40000000;
    private const uint PW_RENDERFULLCONTENT = 0x00000002;
    private const uint BI_RGB = 0;
    private const uint DIB_RGB_COLORS = 0;
    private const uint WAIT_OBJECT_0 = 0x00000000;
    private const uint WAIT_TIMEOUT = 0x00000102;

    private delegate bool MonitorEnumProc(IntPtr hMonitor, IntPtr hdcMonitor, IntPtr lprcMonitor, IntPtr dwData);

    [DllImport("kernel32.dll")] private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("wtsapi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);
    [DllImport("userenv.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);
    [DllImport("userenv.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessAsUserW(IntPtr hToken, string? lpApplicationName, StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
        uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory, ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);
    [DllImport("user32.dll")] private static extern int GetSystemMetrics(int nIndex);
    [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr GetDC(IntPtr hWnd);
    [DllImport("user32.dll", SetLastError = true)] private static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);
    [DllImport("gdi32.dll", SetLastError = true)] private static extern IntPtr CreateCompatibleDC(IntPtr hdc);
    [DllImport("gdi32.dll", SetLastError = true)] private static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int cx, int cy);
    [DllImport("gdi32.dll", SetLastError = true)] private static extern IntPtr SelectObject(IntPtr hdc, IntPtr h);
    [DllImport("gdi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DeleteObject(IntPtr ho);
    [DllImport("gdi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DeleteDC(IntPtr hdc);
    [DllImport("gdi32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool BitBlt(IntPtr hdc, int x, int y, int cx, int cy, IntPtr hdcSrc, int x1, int y1, uint rop);
    [DllImport("gdi32.dll", SetLastError = true)] private static extern int GetDIBits(IntPtr hdc, IntPtr hbm, uint start, uint cLines, [Out] byte[] lpvBits, ref BITMAPINFO lpbmi, uint usage);
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool PrintWindow(IntPtr hwnd, IntPtr hdcBlt, uint nFlags);
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool IsWindow(IntPtr hWnd);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool IsIconic(IntPtr hWnd);
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern int GetWindowTextLengthW(IntPtr hWnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern int GetWindowTextW(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
    [DllImport("user32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr lprcClip, MonitorEnumProc lpfnEnum, IntPtr dwData);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool GetMonitorInfoW(IntPtr hMonitor, ref MONITORINFOEX lpmi);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb; public string? lpReserved; public string? lpDesktop; public string? lpTitle;
        public int dwX; public int dwY; public int dwXSize; public int dwYSize; public int dwXCountChars; public int dwYCountChars;
        public int dwFillAttribute; public int dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2;
        public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId; }
    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
    [StructLayout(LayoutKind.Sequential)]
    private struct BITMAPINFOHEADER
    {
        public uint biSize; public int biWidth; public int biHeight; public ushort biPlanes; public ushort biBitCount;
        public uint biCompression; public uint biSizeImage; public int biXPelsPerMeter; public int biYPelsPerMeter;
        public uint biClrUsed; public uint biClrImportant;
    }
    [StructLayout(LayoutKind.Sequential)] private struct BITMAPINFO { public BITMAPINFOHEADER bmiHeader; public uint bmiColors; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct MONITORINFOEX
    {
        public int cbSize; public RECT rcMonitor; public RECT rcWork; public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string szDevice;
    }
}
