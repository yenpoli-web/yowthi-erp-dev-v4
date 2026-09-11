using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace YowThi.DevelopmentAgent3.Browser;

public sealed record BrowserCdpVersion(
    string Browser,
    string ProtocolVersion,
    string UserAgent,
    string V8Version,
    string WebSocketDebuggerUrl);

public sealed record BrowserTabItem(
    string Id,
    string Type,
    string Title,
    string Url,
    string Description,
    bool IsPage);

public sealed record BrowserDomElement(
    int Index,
    string TagName,
    string Text,
    string? Value,
    IReadOnlyDictionary<string, string> Attributes);

public sealed record BrowserDomQueryResult(
    string TabId,
    string Selector,
    int MatchCount,
    IReadOnlyList<BrowserDomElement> Elements,
    DateTimeOffset CheckedUtc);

public sealed record BrowserEditorSnapshot(
    string TabId,
    string EditorKind,
    string? Selector,
    string Text,
    string TextSha256,
    int Utf8Bytes,
    DateTimeOffset CheckedUtc);

public sealed record BrowserEditorDiagnostic(
    string Source,
    string Severity,
    string Message,
    int? StartLine,
    int? StartColumn,
    int? EndLine,
    int? EndColumn);

public sealed record BrowserEditorDiagnosticsResult(
    string TabId,
    IReadOnlyList<BrowserEditorDiagnostic> Diagnostics,
    DateTimeOffset CheckedUtc);

internal sealed record BrowserCdpTarget(
    string Id,
    string Type,
    string Title,
    string Url,
    string Description,
    string WebSocketDebuggerUrl);

internal static partial class BrowserCdpValidation
{
    private const int MaxSelectorLength = 2048;
    private const int MaxUrlLength = 8192;

    [GeneratedRegex("^[A-Za-z0-9_-]{1,128}$", RegexOptions.CultureInvariant)]
    private static partial Regex TabIdRegex();

    internal static string RequireTabId(string tabId)
    {
        var value = (tabId ?? string.Empty).Trim();
        if (!TabIdRegex().IsMatch(value))
            throw new ArgumentException("Browser tab id is invalid.", nameof(tabId));
        return value;
    }

    internal static string RequireSelector(string selector)
    {
        var value = (selector ?? string.Empty).Trim();
        if (value.Length is < 1 or > MaxSelectorLength || value.IndexOf('\0') >= 0)
            throw new ArgumentException($"DOM selector must contain 1-{MaxSelectorLength} characters and no NUL.", nameof(selector));
        return value;
    }

    internal static string? NormalizeOptionalSelector(string? selector)
        => string.IsNullOrWhiteSpace(selector) ? null : RequireSelector(selector);

    internal static string RequireNavigableUrl(string url)
    {
        var value = (url ?? string.Empty).Trim();
        if (value.Length is < 1 or > MaxUrlLength || value.IndexOf('\0') >= 0)
            throw new ArgumentException($"Browser URL must contain 1-{MaxUrlLength} characters and no NUL.", nameof(url));
        if (string.Equals(value, "about:blank", StringComparison.OrdinalIgnoreCase)) return "about:blank";
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            throw new ArgumentException("Browser navigation is restricted to absolute http/https URLs or about:blank.", nameof(url));
        if (!string.IsNullOrEmpty(uri.UserInfo))
            throw new ArgumentException("Browser URLs containing embedded credentials are not allowed.", nameof(url));
        return uri.AbsoluteUri;
    }

    internal static string RequireExpectedHash(string hash, string parameterName)
    {
        var value = (hash ?? string.Empty).Trim().ToUpperInvariant();
        if (value.Length != 64 || value.Any(c => !Uri.IsHexDigit(c)))
            throw new ArgumentException("Expected SHA-256 must be exactly 64 hexadecimal characters.", parameterName);
        return value;
    }

    internal static int RequireExpectedMatchCount(int count)
    {
        if (count is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(count), "expectedMatchCount must be between 1 and 1000.");
        return count;
    }
}

internal static class BrowserCdpClient
{
    internal const int DevToolsPort = 9223;
    internal const string DevToolsAddress = "127.0.0.1";
    internal const string Endpoint = "http://127.0.0.1:9223";
    private const int MaxWebSocketMessageBytes = 4 * 1024 * 1024;
    private const int MaxWebSocketMessages = 256;
    private static int _nextCommandId;
    private static readonly HttpClient Http = CreateHttpClient();

    private static HttpClient CreateHttpClient()
    {
        var handler = new SocketsHttpHandler
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(2)
        };
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
    }

    internal static async Task<bool> IsPortListeningAsync(CancellationToken cancellationToken = default)
    {
        using var client = new TcpClient(AddressFamily.InterNetwork);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromMilliseconds(600));
            await client.ConnectAsync(IPAddress.Loopback, DevToolsPort, timeout.Token);
            return client.Connected;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return false; }
        catch (SocketException) { return false; }
    }

    internal static async Task<BrowserCdpVersion?> TryGetVersionAsync(CancellationToken cancellationToken = default)
    {
        try { return await GetVersionAsync(cancellationToken); }
        catch (HttpRequestException) { return null; }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
        catch (JsonException) { return null; }
    }

    internal static async Task<BrowserCdpVersion> GetVersionAsync(CancellationToken cancellationToken = default)
    {
        using var response = await Http.GetAsync(Endpoint + "/json/version", cancellationToken);
        response.EnsureSuccessStatusCode();
        var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
        if (bytes.Length is <= 0 or > 256 * 1024) throw new InvalidDataException("Chrome DevTools version payload size is invalid.");
        using var doc = JsonDocument.Parse(bytes);
        var root = doc.RootElement;
        var browser = GetRequiredString(root, "Browser");
        var protocol = GetRequiredString(root, "Protocol-Version");
        var userAgent = root.TryGetProperty("User-Agent", out var ua) ? ua.GetString() ?? string.Empty : string.Empty;
        var v8 = root.TryGetProperty("V8-Version", out var v8Value) ? v8Value.GetString() ?? string.Empty : string.Empty;
        var ws = GetRequiredString(root, "webSocketDebuggerUrl");
        _ = ValidateWebSocketUri(ws, requirePageTarget: false);
        return new(browser, protocol, userAgent, v8, ws);
    }

    internal static async Task<IReadOnlyList<BrowserCdpTarget>> ListTargetsAsync(CancellationToken cancellationToken = default)
    {
        using var response = await Http.GetAsync(Endpoint + "/json/list", cancellationToken);
        response.EnsureSuccessStatusCode();
        var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
        if (bytes.Length > 4 * 1024 * 1024) throw new InvalidDataException("Chrome DevTools target list exceeded the bounded limit.");
        using var doc = JsonDocument.Parse(bytes);
        if (doc.RootElement.ValueKind != JsonValueKind.Array) throw new InvalidDataException("Chrome DevTools target list is not an array.");
        var result = new List<BrowserCdpTarget>();
        foreach (var item in doc.RootElement.EnumerateArray().Take(256))
        {
            var id = GetRequiredString(item, "id");
            BrowserCdpValidation.RequireTabId(id);
            var type = item.TryGetProperty("type", out var typeValue) ? typeValue.GetString() ?? string.Empty : string.Empty;
            var title = item.TryGetProperty("title", out var titleValue) ? titleValue.GetString() ?? string.Empty : string.Empty;
            var url = item.TryGetProperty("url", out var urlValue) ? urlValue.GetString() ?? string.Empty : string.Empty;
            var description = item.TryGetProperty("description", out var descValue) ? descValue.GetString() ?? string.Empty : string.Empty;
            var ws = item.TryGetProperty("webSocketDebuggerUrl", out var wsValue) ? wsValue.GetString() ?? string.Empty : string.Empty;
            if (!string.IsNullOrWhiteSpace(ws)) _ = ValidateWebSocketUri(ws, requirePageTarget: false);
            result.Add(new(id, type, title, url, description, ws));
        }
        return result;
    }

    internal static async Task<BrowserCdpTarget> RequirePageTargetAsync(string tabId, CancellationToken cancellationToken = default)
    {
        tabId = BrowserCdpValidation.RequireTabId(tabId);
        var targets = await ListTargetsAsync(cancellationToken);
        var target = targets.SingleOrDefault(x => string.Equals(x.Id, tabId, StringComparison.Ordinal))
            ?? throw new InvalidOperationException("Browser tab no longer exists in the controlled Chrome session.");
        if (!string.Equals(target.Type, "page", StringComparison.Ordinal))
            throw new InvalidOperationException("Target is not a page tab.");
        if (string.IsNullOrWhiteSpace(target.WebSocketDebuggerUrl))
            throw new InvalidOperationException("Page tab has no DevTools WebSocket endpoint.");
        _ = ValidateWebSocketUri(target.WebSocketDebuggerUrl, requirePageTarget: true);
        return target;
    }

    internal static async Task<BrowserCdpTarget> OpenTabAsync(string url, CancellationToken cancellationToken = default)
    {
        url = BrowserCdpValidation.RequireNavigableUrl(url);
        var requestUri = Endpoint + "/json/new?" + Uri.EscapeDataString(url);
        using var request = new HttpRequestMessage(HttpMethod.Put, requestUri);
        using var response = await Http.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
        if (bytes.Length is <= 0 or > 256 * 1024) throw new InvalidDataException("Chrome DevTools new-tab response size is invalid.");
        using var doc = JsonDocument.Parse(bytes);
        var item = doc.RootElement;
        var id = BrowserCdpValidation.RequireTabId(GetRequiredString(item, "id"));
        var type = item.TryGetProperty("type", out var typeValue) ? typeValue.GetString() ?? string.Empty : string.Empty;
        var title = item.TryGetProperty("title", out var titleValue) ? titleValue.GetString() ?? string.Empty : string.Empty;
        var actualUrl = item.TryGetProperty("url", out var urlValue) ? urlValue.GetString() ?? string.Empty : string.Empty;
        var description = item.TryGetProperty("description", out var descValue) ? descValue.GetString() ?? string.Empty : string.Empty;
        var ws = item.TryGetProperty("webSocketDebuggerUrl", out var wsValue) ? wsValue.GetString() ?? string.Empty : string.Empty;
        if (!string.IsNullOrWhiteSpace(ws)) _ = ValidateWebSocketUri(ws, requirePageTarget: false);
        return new(id, type, title, actualUrl, description, ws);
    }

    internal static Task ActivateTabAsync(string tabId, CancellationToken cancellationToken = default)
        => InvokeTargetHttpAsync("activate", BrowserCdpValidation.RequireTabId(tabId), cancellationToken);

    internal static Task CloseTabAsync(string tabId, CancellationToken cancellationToken = default)
        => InvokeTargetHttpAsync("close", BrowserCdpValidation.RequireTabId(tabId), cancellationToken);

    private static async Task InvokeTargetHttpAsync(string action, string tabId, CancellationToken cancellationToken)
    {
        using var response = await Http.GetAsync($"{Endpoint}/json/{action}/{Uri.EscapeDataString(tabId)}", cancellationToken);
        response.EnsureSuccessStatusCode();
        var text = await response.Content.ReadAsStringAsync(cancellationToken);
        if (text.Length > 16 * 1024) throw new InvalidDataException("Chrome DevTools target action response exceeded the bounded limit.");
    }

    internal static async Task NavigateAsync(string tabId, string url, CancellationToken cancellationToken = default)
    {
        url = BrowserCdpValidation.RequireNavigableUrl(url);
        var result = await SendPageCommandAsync(tabId, "Page.navigate", new { url }, cancellationToken);
        if (result.TryGetProperty("errorText", out var errorText) && !string.IsNullOrWhiteSpace(errorText.GetString()))
            throw new InvalidOperationException("Chrome navigation failed: " + errorText.GetString());
    }

    internal static async Task<JsonElement> EvaluateAsync(string tabId, string expression, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(expression) || expression.Length > 256 * 1024)
            throw new ArgumentOutOfRangeException(nameof(expression), "Internal CDP expression size is invalid.");
        var result = await SendPageCommandAsync(tabId, "Runtime.evaluate", new
        {
            expression,
            returnByValue = true,
            awaitPromise = true,
            userGesture = false
        }, cancellationToken);
        if (result.TryGetProperty("exceptionDetails", out var exceptionDetails))
        {
            var text = exceptionDetails.TryGetProperty("text", out var textValue) ? textValue.GetString() : "Runtime.evaluate exception";
            throw new InvalidOperationException("Browser page evaluation failed: " + text);
        }
        if (!result.TryGetProperty("result", out var remoteObject))
            throw new InvalidDataException("CDP Runtime.evaluate response has no result object.");
        if (remoteObject.TryGetProperty("value", out var value)) return value.Clone();
        if (remoteObject.TryGetProperty("type", out var type) && string.Equals(type.GetString(), "undefined", StringComparison.Ordinal))
            return JsonDocument.Parse("null").RootElement.Clone();
        throw new InvalidDataException("CDP Runtime.evaluate response is not serializable by value.");
    }

    internal static async Task<JsonElement> SendPageCommandAsync(string tabId, string method, object? parameters, CancellationToken cancellationToken = default)
    {
        var target = await RequirePageTargetAsync(tabId, cancellationToken);
        var ws = ValidateWebSocketUri(target.WebSocketDebuggerUrl, requirePageTarget: true);
        return await SendCommandAsync(ws, method, parameters, cancellationToken);
    }

    private static async Task<JsonElement> SendCommandAsync(Uri webSocketUri, string method, object? parameters, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(method) || method.Length > 128) throw new ArgumentException("CDP method is invalid.", nameof(method));
        var id = Interlocked.Increment(ref _nextCommandId);
        var payload = JsonSerializer.SerializeToUtf8Bytes(new { id, method, @params = parameters ?? new { } });
        if (payload.Length > 512 * 1024) throw new InvalidDataException("CDP command payload exceeded the bounded limit.");

        using var socket = new ClientWebSocket();
        socket.Options.KeepAliveInterval = TimeSpan.FromSeconds(15);
        socket.Options.SetRequestHeader("Origin", Endpoint);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(12));
        await socket.ConnectAsync(webSocketUri, timeout.Token);
        await socket.SendAsync(payload, WebSocketMessageType.Text, true, timeout.Token);

        for (var messageIndex = 0; messageIndex < MaxWebSocketMessages; messageIndex++)
        {
            var bytes = await ReceiveMessageAsync(socket, timeout.Token);
            using var doc = JsonDocument.Parse(bytes);
            var root = doc.RootElement;
            if (!root.TryGetProperty("id", out var idValue) || idValue.ValueKind != JsonValueKind.Number || idValue.GetInt32() != id)
                continue;
            if (root.TryGetProperty("error", out var error))
            {
                var message = error.TryGetProperty("message", out var messageValue) ? messageValue.GetString() : "CDP command failed";
                throw new InvalidOperationException("Chrome DevTools command failed: " + message);
            }
            if (!root.TryGetProperty("result", out var result))
                throw new InvalidDataException("Chrome DevTools command response has no result.");
            return result.Clone();
        }
        throw new TimeoutException("Chrome DevTools command response was not observed within the bounded message count.");
    }

    private static async Task<byte[]> ReceiveMessageAsync(ClientWebSocket socket, CancellationToken cancellationToken)
    {
        using var stream = new MemoryStream();
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var result = await socket.ReceiveAsync(buffer, cancellationToken);
            if (result.MessageType == WebSocketMessageType.Close)
                throw new EndOfStreamException("Chrome DevTools WebSocket closed before returning the command response.");
            if (result.MessageType != WebSocketMessageType.Text)
                throw new InvalidDataException("Chrome DevTools returned a non-text WebSocket message.");
            if (stream.Length + result.Count > MaxWebSocketMessageBytes)
                throw new InvalidDataException("Chrome DevTools WebSocket message exceeded the bounded limit.");
            stream.Write(buffer, 0, result.Count);
            if (result.EndOfMessage) return stream.ToArray();
        }
    }

    private static Uri ValidateWebSocketUri(string value, bool requirePageTarget)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || !string.Equals(uri.Scheme, "ws", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Chrome DevTools WebSocket URL is invalid.");
        if (uri.Port != DevToolsPort || !(string.Equals(uri.Host, DevToolsAddress, StringComparison.OrdinalIgnoreCase) || string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase)))
            throw new UnauthorizedAccessException("Chrome DevTools WebSocket escaped the fixed loopback endpoint.");
        if (requirePageTarget && !uri.AbsolutePath.StartsWith("/devtools/page/", StringComparison.Ordinal))
            throw new UnauthorizedAccessException("CDP page command requires a page-target WebSocket URL.");
        if (!requirePageTarget && !(uri.AbsolutePath.StartsWith("/devtools/page/", StringComparison.Ordinal) || uri.AbsolutePath.StartsWith("/devtools/browser/", StringComparison.Ordinal)))
            throw new UnauthorizedAccessException("Chrome DevTools WebSocket path is outside the allowed browser/page endpoints.");
        return uri;
    }

    private static string GetRequiredString(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value) || value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString()))
            throw new InvalidDataException($"Chrome DevTools payload is missing {property}.");
        return value.GetString()!;
    }
}

internal sealed record ControlledChromeLaunchIdentity(
    uint SessionId,
    string ProfilePath,
    string ChromeSha256);

internal static class ControlledChromeLauncher
{
    internal const string ChromeExe = @"C:\Program Files\Google\Chrome\Application\chrome.exe";
    private static readonly Guid LocalAppDataFolderId = new("F1B32785-6FBA-4FCF-9D55-7B8E7F157091");

    internal static ControlledChromeLaunchIdentity ResolveIdentity()
    {
        ValidateChrome();
        var sessionId = WTSGetActiveConsoleSessionId();
        if (sessionId == 0xFFFFFFFF) throw new InvalidOperationException("No active console session is available for controlled Chrome.");
        if (!WTSQueryUserToken(sessionId, out var token) || token == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to obtain the active interactive user token for controlled Chrome.");
        try
        {
            var folderId = LocalAppDataFolderId;
            var hr = SHGetKnownFolderPath(ref folderId, 0, token, out var rawPath);
            if (hr != 0 || rawPath == IntPtr.Zero) Marshal.ThrowExceptionForHR(hr);
            try
            {
                var localAppData = Marshal.PtrToStringUni(rawPath) ?? throw new InvalidDataException("Active user's LocalAppData path is unavailable.");
                var profilePath = Path.GetFullPath(Path.Combine(localAppData, "YowThi", "BrowserControl", "Profile"));
                if (!profilePath.StartsWith(Path.GetFullPath(localAppData).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                    throw new UnauthorizedAccessException("Controlled Chrome profile escaped active-user LocalAppData.");
                if (Directory.Exists(profilePath) && (File.GetAttributes(profilePath) & FileAttributes.ReparsePoint) != 0)
                    throw new UnauthorizedAccessException("Controlled Chrome profile may not be a reparse point.");
                return new(sessionId, profilePath, ComputeChromeSha256());
            }
            finally { Marshal.FreeCoTaskMem(rawPath); }
        }
        finally { CloseHandle(token); }
    }

    internal static async Task<int> StartAsync(ControlledChromeLaunchIdentity expected, CancellationToken cancellationToken = default)
    {
        var live = ResolveIdentity();
        if (live.SessionId != expected.SessionId || !string.Equals(live.ProfilePath, expected.ProfilePath, StringComparison.OrdinalIgnoreCase) || !string.Equals(live.ChromeSha256, expected.ChromeSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Controlled Chrome launch identity changed after plan creation.");
        if (await BrowserCdpClient.TryGetVersionAsync(cancellationToken) is not null || await BrowserCdpClient.IsPortListeningAsync(cancellationToken))
            throw new InvalidOperationException("Fixed controlled Chrome DevTools endpoint is already in use.");

        if (!WTSQueryUserToken(live.SessionId, out var token) || token == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to obtain the active interactive user token for controlled Chrome start.");
        IntPtr environment = IntPtr.Zero;
        PROCESS_INFORMATION processInfo = default;
        try
        {
            if (!CreateEnvironmentBlock(out environment, token, false))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to create the active user environment for controlled Chrome.");
            Directory.CreateDirectory(live.ProfilePath);
            if ((File.GetAttributes(live.ProfilePath) & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException("Controlled Chrome profile may not be a reparse point.");

            var command = BuildCommandLine(live.ProfilePath);
            var startup = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>(), lpDesktop = @"winsta0\default" };
            const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
            if (!CreateProcessAsUserW(token, ChromeExe, command, IntPtr.Zero, IntPtr.Zero, false, CREATE_UNICODE_ENVIRONMENT, environment, Path.GetDirectoryName(ChromeExe), ref startup, out processInfo))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to launch controlled Chrome in the active interactive session.");
            var launchedProcessId = checked((int)processInfo.dwProcessId);

            Exception? lastError = null;
            for (var attempt = 0; attempt < 40; attempt++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (attempt > 0) await Task.Delay(250, cancellationToken);
                try
                {
                    var version = await BrowserCdpClient.TryGetVersionAsync(cancellationToken);
                    if (version is not null) return launchedProcessId;
                }
                catch (Exception ex) { lastError = ex; }
            }
            throw new TimeoutException("Controlled Chrome did not expose the fixed loopback DevTools endpoint within 10 seconds.", lastError);
        }
        finally
        {
            if (processInfo.hThread != IntPtr.Zero) CloseHandle(processInfo.hThread);
            if (processInfo.hProcess != IntPtr.Zero) CloseHandle(processInfo.hProcess);
            if (environment != IntPtr.Zero) DestroyEnvironmentBlock(environment);
            if (token != IntPtr.Zero) CloseHandle(token);
        }
    }

    internal static IReadOnlyList<string> BuildArgumentsForContract(string profilePath)
        => new[]
        {
            $"--remote-debugging-address={BrowserCdpClient.DevToolsAddress}",
            $"--remote-debugging-port={BrowserCdpClient.DevToolsPort}",
            $"--remote-allow-origins={BrowserCdpClient.Endpoint}",
            $"--user-data-dir={profilePath}",
            "--no-first-run",
            "--no-default-browser-check",
            "--new-window",
            "about:blank"
        };

    private static StringBuilder BuildCommandLine(string profilePath)
    {
        var command = new StringBuilder();
        AppendQuotedArgument(command, ChromeExe);
        foreach (var argument in BuildArgumentsForContract(profilePath)) AppendQuotedArgument(command, argument);
        return command;
    }

    private static void ValidateChrome()
    {
        if (!File.Exists(ChromeExe)) throw new FileNotFoundException("Fixed Google Chrome executable was not found.", ChromeExe);
        if ((File.GetAttributes(ChromeExe) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Fixed Google Chrome executable may not be a reparse point.");
    }

    private static string ComputeChromeSha256()
    {
        ValidateChrome();
        using var stream = new FileStream(ChromeExe, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
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
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] private static extern int SHGetKnownFolderPath(ref Guid rfid, uint dwFlags, IntPtr hToken, out IntPtr ppszPath);
    [DllImport("userenv.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);
    [DllImport("userenv.dll")] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CreateProcessAsUserW(IntPtr hToken, string? lpApplicationName, StringBuilder lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb; public string? lpReserved; public string? lpDesktop; public string? lpTitle; public int dwX; public int dwY; public int dwXSize; public int dwYSize; public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute; public int dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId; }
}

internal static class BrowserDomBridge
{
    internal static async Task<BrowserDomQueryResult> QueryAsync(string tabId, string selector, int maxResults, CancellationToken cancellationToken = default)
    {
        tabId = BrowserCdpValidation.RequireTabId(tabId);
        selector = BrowserCdpValidation.RequireSelector(selector);
        if (maxResults is < 1 or > 100) throw new ArgumentOutOfRangeException(nameof(maxResults), "maxResults must be between 1 and 100.");
        var selectorJson = JsonSerializer.Serialize(selector);
        var expression = $$"""
            (() => {
              const selector = {{selectorJson}};
              const maxResults = {{maxResults}};
              const all = Array.from(document.querySelectorAll(selector));
              const allowed = new Set(['id','class','name','role','aria-label','type','title','href']);
              const elements = all.slice(0, maxResults).map((el, index) => {
                const attrs = {};
                for (const a of Array.from(el.attributes || []).slice(0, 32)) if (allowed.has(a.name)) attrs[a.name] = String(a.value).slice(0, 2048);
                const type = String(el.getAttribute?.('type') || '').toLowerCase();
                const value = type === 'password' ? null : (typeof el.value === 'string' ? el.value.slice(0, 4096) : null);
                return { index, tagName: String(el.tagName || ''), text: String(el.innerText || el.textContent || '').slice(0, 4096), value, attributes: attrs };
              });
              return { matchCount: all.length, elements };
            })()
            """;
        var value = await BrowserCdpClient.EvaluateAsync(tabId, expression, cancellationToken);
        if (value.ValueKind != JsonValueKind.Object) throw new InvalidDataException("DOM query returned an invalid result object.");
        var count = value.GetProperty("matchCount").GetInt32();
        var elements = JsonSerializer.Deserialize<List<BrowserDomElement>>(value.GetProperty("elements").GetRawText(), new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new();
        return new(tabId, selector, count, elements, DateTimeOffset.UtcNow);
    }

    internal static async Task<int> CountAsync(string tabId, string selector, CancellationToken cancellationToken = default)
    {
        var result = await QueryAsync(tabId, selector, 1, cancellationToken);
        return result.MatchCount;
    }

    internal static async Task ClickAsync(string tabId, string selector, int expectedMatchCount, CancellationToken cancellationToken = default)
    {
        tabId = BrowserCdpValidation.RequireTabId(tabId);
        selector = BrowserCdpValidation.RequireSelector(selector);
        expectedMatchCount = BrowserCdpValidation.RequireExpectedMatchCount(expectedMatchCount);
        var selectorJson = JsonSerializer.Serialize(selector);
        var expression = $$"""
            (() => {
              const selector = {{selectorJson}};
              const expected = {{expectedMatchCount}};
              const all = Array.from(document.querySelectorAll(selector));
              if (all.length !== expected) return { ok: false, count: all.length };
              const el = all[0];
              el.scrollIntoView({ block: 'center', inline: 'center' });
              el.click();
              return { ok: true, count: all.length };
            })()
            """;
        var value = await BrowserCdpClient.EvaluateAsync(tabId, expression, cancellationToken);
        if (!value.TryGetProperty("ok", out var ok) || !ok.GetBoolean())
        {
            var count = value.TryGetProperty("count", out var countValue) ? countValue.GetInt32() : -1;
            throw new InvalidOperationException($"DOM click match count changed; expected={expectedMatchCount}, actual={count}.");
        }
    }
}

internal static class BrowserEditorBridge
{
    internal static async Task<BrowserEditorSnapshot> GetAsync(string tabId, string? selector, CancellationToken cancellationToken = default)
    {
        tabId = BrowserCdpValidation.RequireTabId(tabId);
        selector = BrowserCdpValidation.NormalizeOptionalSelector(selector);
        var expression = BuildEditorExpression(selector, null, mutate: false);
        var value = await BrowserCdpClient.EvaluateAsync(tabId, expression, cancellationToken);
        return ParseEditorSnapshot(tabId, selector, value);
    }

    internal static async Task<BrowserEditorSnapshot> SetAsync(string tabId, string? selector, string text, CancellationToken cancellationToken = default)
    {
        tabId = BrowserCdpValidation.RequireTabId(tabId);
        selector = BrowserCdpValidation.NormalizeOptionalSelector(selector);
        if (Encoding.UTF8.GetByteCount(text) > 2 * 1024 * 1024) throw new ArgumentOutOfRangeException(nameof(text), "Editor text may not exceed 2 MiB UTF-8.");
        var expression = BuildEditorExpression(selector, text, mutate: true);
        var value = await BrowserCdpClient.EvaluateAsync(tabId, expression, cancellationToken);
        return ParseEditorSnapshot(tabId, selector, value);
    }

    internal static async Task<BrowserEditorDiagnosticsResult> GetDiagnosticsAsync(string tabId, CancellationToken cancellationToken = default)
    {
        tabId = BrowserCdpValidation.RequireTabId(tabId);
        const string expression = """
            (() => {
              const out = [];
              try {
                if (globalThis.monaco?.editor?.getModelMarkers) {
                  for (const m of globalThis.monaco.editor.getModelMarkers({}).slice(0, 100)) {
                    out.push({ source: 'monaco', severity: String(m.severity ?? ''), message: String(m.message ?? '').slice(0,4096), startLine: m.startLineNumber ?? null, startColumn: m.startColumn ?? null, endLine: m.endLineNumber ?? null, endColumn: m.endColumn ?? null });
                  }
                }
              } catch {}
              for (const el of Array.from(document.querySelectorAll('[role="alert"], .error, .errors, .diagnostic, .diagnostics')).slice(0, 50)) {
                const message = String(el.innerText || el.textContent || '').trim().slice(0,4096);
                if (message) out.push({ source: 'dom', severity: 'unknown', message, startLine: null, startColumn: null, endLine: null, endColumn: null });
              }
              return out.slice(0, 100);
            })()
            """;
        var value = await BrowserCdpClient.EvaluateAsync(tabId, expression, cancellationToken);
        var diagnostics = JsonSerializer.Deserialize<List<BrowserEditorDiagnostic>>(value.GetRawText(), new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new();
        return new(tabId, diagnostics, DateTimeOffset.UtcNow);
    }

    internal static async Task<(bool Matched, string ObservedText)> WaitForTextAsync(string tabId, string selector, string expectedText, int timeoutSeconds, CancellationToken cancellationToken = default)
    {
        tabId = BrowserCdpValidation.RequireTabId(tabId);
        selector = BrowserCdpValidation.RequireSelector(selector);
        if (expectedText is null || expectedText.Length > 4096 || expectedText.IndexOf('\0') >= 0) throw new ArgumentException("Expected saved-state text is invalid.", nameof(expectedText));
        if (timeoutSeconds is < 1 or > 60) throw new ArgumentOutOfRangeException(nameof(timeoutSeconds), "timeoutSeconds must be between 1 and 60.");
        var deadline = DateTimeOffset.UtcNow.AddSeconds(timeoutSeconds);
        string observed = string.Empty;
        do
        {
            var result = await BrowserDomBridge.QueryAsync(tabId, selector, 1, cancellationToken);
            observed = result.Elements.FirstOrDefault()?.Text ?? string.Empty;
            if (result.MatchCount > 0 && observed.Contains(expectedText, StringComparison.Ordinal)) return (true, observed);
            if (DateTimeOffset.UtcNow >= deadline) break;
            await Task.Delay(250, cancellationToken);
        } while (true);
        return (false, observed);
    }

    private static BrowserEditorSnapshot ParseEditorSnapshot(string tabId, string? selector, JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Editor bridge returned an invalid result object.");
        var ok = value.TryGetProperty("ok", out var okValue) && okValue.GetBoolean();
        if (!ok)
        {
            var error = value.TryGetProperty("error", out var errorValue) ? errorValue.GetString() : "No supported editor model was found.";
            throw new InvalidOperationException(error);
        }
        var kind = value.GetProperty("kind").GetString() ?? "unknown";
        var text = value.GetProperty("text").GetString() ?? string.Empty;
        var bytes = Encoding.UTF8.GetByteCount(text);
        if (bytes > 2 * 1024 * 1024) throw new InvalidDataException("Editor readback exceeded the 2 MiB UTF-8 limit.");
        var sha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
        return new(tabId, kind, selector, text, sha, bytes, DateTimeOffset.UtcNow);
    }

    private static string BuildEditorExpression(string? selector, string? replacementText, bool mutate)
    {
        var selectorJson = selector is null ? "null" : JsonSerializer.Serialize(selector);
        var textJson = replacementText is null ? "null" : JsonSerializer.Serialize(replacementText);
        var mutateJs = mutate ? "true" : "false";
        return $$"""
            (() => {
              const selector = {{selectorJson}};
              const replacement = {{textJson}};
              const mutate = {{mutateJs}};
              const findElement = () => selector ? document.querySelector(selector) : null;
              let el = findElement();

              try {
                const cmRoot = el?.CodeMirror ? el : el?.closest?.('.CodeMirror');
                const cm = cmRoot?.CodeMirror || document.querySelector('.CodeMirror')?.CodeMirror;
                if (cm && typeof cm.getValue === 'function') {
                  if (mutate) cm.setValue(replacement);
                  return { ok: true, kind: 'codemirror5', text: String(cm.getValue()) };
                }
              } catch {}

              try {
                const models = globalThis.monaco?.editor?.getModels?.() || [];
                if (models.length > 0 && (!selector || el?.closest?.('.monaco-editor') || el?.classList?.contains('monaco-editor'))) {
                  const model = models[0];
                  if (mutate) model.setValue(replacement);
                  return { ok: true, kind: 'monaco', text: String(model.getValue()) };
                }
              } catch {}

              if (!el && !selector) el = document.querySelector('textarea, input[type="text"], [contenteditable="true"]');
              if (el instanceof HTMLTextAreaElement || (el instanceof HTMLInputElement && String(el.type).toLowerCase() !== 'password')) {
                if (mutate) {
                  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
                  const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
                  if (setter) setter.call(el, replacement); else el.value = replacement;
                  el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: null }));
                  el.dispatchEvent(new Event('change', { bubbles: true }));
                }
                return { ok: true, kind: el instanceof HTMLTextAreaElement ? 'textarea' : 'input', text: String(el.value) };
              }
              if (el?.isContentEditable) {
                if (mutate) {
                  el.textContent = replacement;
                  el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: null }));
                }
                return { ok: true, kind: 'contenteditable', text: String(el.innerText || el.textContent || '') };
              }
              return { ok: false, error: selector ? 'Selector did not resolve to a supported editor model.' : 'No supported Monaco, CodeMirror 5, textarea, input, or contenteditable editor was found.' };
            })()
            """;
    }
}
