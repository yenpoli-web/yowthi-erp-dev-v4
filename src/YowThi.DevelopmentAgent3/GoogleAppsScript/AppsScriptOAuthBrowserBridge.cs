using System.Net;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;

namespace YowThi.DevelopmentAgent3.GoogleAppsScript;

public sealed record AppsScriptEphemeralCredentialResult(
    bool Configured,
    string AuthMode,
    string Source,
    DateTimeOffset? ExpiresUtc,
    int? TokenLength,
    bool RequiredScopePresent,
    DateTimeOffset CheckedUtc);

public static class AppsScriptEphemeralCredentialStore
{
    private static readonly object Gate = new();
    private static string? _accessToken;
    private static DateTimeOffset _expiresUtc;
    private static int _tokenLength;

    public static AppsScriptEphemeralCredentialResult Import(string accessToken, int expiresInSeconds, bool requiredScopePresent)
    {
        var token = ValidateToken(accessToken);
        if (!requiredScopePresent)
            throw new UnauthorizedAccessException("OAuth Playground token does not include the required Apps Script project scope.");
        var lifetimeSeconds = Math.Clamp(expiresInSeconds - 30, 60, 7200);
        var expiresUtc = DateTimeOffset.UtcNow.AddSeconds(lifetimeSeconds);
        lock (Gate)
        {
            _accessToken = token;
            _expiresUtc = expiresUtc;
            _tokenLength = token.Length;
        }
        return new(true, "ephemeral-browser-token", "controlled-oauth-playground", expiresUtc, token.Length, true, DateTimeOffset.UtcNow);
    }

    public static bool TryGetAccessToken(out string accessToken)
    {
        lock (Gate)
        {
            if (_accessToken is not null && _expiresUtc > DateTimeOffset.UtcNow.AddSeconds(15))
            {
                accessToken = _accessToken;
                return true;
            }
            _accessToken = null;
            _expiresUtc = default;
            _tokenLength = 0;
        }
        accessToken = string.Empty;
        return false;
    }

    public static AppsScriptEphemeralCredentialResult GetState()
    {
        lock (Gate)
        {
            if (_accessToken is not null && _expiresUtc > DateTimeOffset.UtcNow.AddSeconds(15))
                return new(true, "ephemeral-browser-token", "controlled-oauth-playground", _expiresUtc, _tokenLength, true, DateTimeOffset.UtcNow);
            _accessToken = null;
            _expiresUtc = default;
            _tokenLength = 0;
            return new(false, "unconfigured", "memory", null, null, false, DateTimeOffset.UtcNow);
        }
    }

    public static AppsScriptEphemeralCredentialResult Clear()
    {
        lock (Gate)
        {
            _accessToken = null;
            _expiresUtc = default;
            _tokenLength = 0;
        }
        return new(false, "unconfigured", "cleared", null, null, false, DateTimeOffset.UtcNow);
    }

    private static string ValidateToken(string token)
    {
        var value = (token ?? string.Empty).Trim();
        if (value.Length is < 20 or > 8192 || value.Any(char.IsControl))
            throw new InvalidDataException("Google OAuth access token shape is invalid.");
        return value;
    }
}

internal sealed record AppsScriptBrowserOAuthToken(string AccessToken, int ExpiresInSeconds, bool RequiredScopePresent);

internal static class AppsScriptControlledBrowserOAuthReader
{
    private static readonly Uri DiscoveryEndpoint = new("http://127.0.0.1:9223/json");
    private const string RequiredScope = "https://www.googleapis.com/auth/script.projects";
    private const string FixedExpression = "JSON.stringify({accessToken:(document.querySelector('#access_token_field')?.value||''),expiresIn:(document.querySelector('#expires_in')?.value||''),issueDate:(document.querySelector('#access_token_issue_date')?.value||''),scopes:(document.querySelector('#scopes')?.value||'')})";
    private const int MaxDiscoveryBytes = 1024 * 1024;
    private const int MaxCdpMessageBytes = 1024 * 1024;

    public static async Task<AppsScriptBrowserOAuthToken> ReadAsync(CancellationToken cancellationToken = default)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        var discovery = await http.GetByteArrayAsync(DiscoveryEndpoint, cancellationToken);
        if (discovery.Length is <= 0 or > MaxDiscoveryBytes)
            throw new InvalidDataException("Controlled Chrome target discovery response is outside the bounded size limit.");

        using var doc = JsonDocument.Parse(discovery);
        var matches = new List<(Uri PageUrl, Uri WebSocketUrl)>();
        foreach (var item in doc.RootElement.EnumerateArray())
        {
            if (!item.TryGetProperty("type", out var type) || type.GetString() != "page") continue;
            if (!item.TryGetProperty("url", out var urlElement) || !Uri.TryCreate(urlElement.GetString(), UriKind.Absolute, out var pageUrl)) continue;
            if (!string.Equals(pageUrl.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(pageUrl.Host, "developers.google.com", StringComparison.OrdinalIgnoreCase) ||
                !pageUrl.AbsolutePath.StartsWith("/oauthplayground", StringComparison.OrdinalIgnoreCase)) continue;
            if (!item.TryGetProperty("webSocketDebuggerUrl", out var wsElement) || !Uri.TryCreate(wsElement.GetString(), UriKind.Absolute, out var websocketUrl)) continue;
            ValidateFixedWebSocket(websocketUrl);
            matches.Add((pageUrl, websocketUrl));
        }
        if (matches.Count != 1)
            throw new InvalidOperationException($"Expected exactly one controlled OAuth Playground page, found {matches.Count}.");

        var payload = await ReadFixedOAuthFieldsAsync(matches[0].WebSocketUrl, cancellationToken);
        var requiredScopePresent = payload.Scopes.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Contains(RequiredScope, StringComparer.Ordinal) ||
            Uri.UnescapeDataString(matches[0].PageUrl.Query).Contains("scope=" + RequiredScope, StringComparison.Ordinal);
        if (!int.TryParse(payload.ExpiresIn, out var expiresInSeconds) || expiresInSeconds is < 60 or > 7200)
            throw new InvalidDataException("OAuth Playground expires_in is outside the accepted range.");
        if (!long.TryParse(payload.IssueDate, out var issueDateUnixSeconds))
            throw new InvalidDataException("OAuth Playground access_token_issue_date is invalid.");
        DateTimeOffset issueUtc;
        try { issueUtc = DateTimeOffset.FromUnixTimeSeconds(issueDateUnixSeconds); }
        catch (ArgumentOutOfRangeException) { throw new InvalidDataException("OAuth Playground access_token_issue_date is outside the accepted range."); }
        var remainingSeconds = (int)Math.Floor((issueUtc.AddSeconds(expiresInSeconds) - DateTimeOffset.UtcNow).TotalSeconds);
        if (remainingSeconds is < 60 or > 7200)
            throw new InvalidOperationException("OAuth Playground access token is expired, nearly expired, or has an invalid lifetime.");
        return new(payload.AccessToken, remainingSeconds, requiredScopePresent);
    }

    private static void ValidateFixedWebSocket(Uri uri)
    {
        if (!string.Equals(uri.Scheme, "ws", StringComparison.OrdinalIgnoreCase) ||
            !IPAddress.TryParse(uri.Host, out var ip) || !IPAddress.IsLoopback(ip) || uri.Port != 9223 ||
            !uri.AbsolutePath.StartsWith("/devtools/page/", StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Controlled Chrome WebSocket target is outside the fixed loopback CDP endpoint.");
    }

    private static async Task<OAuthFields> ReadFixedOAuthFieldsAsync(Uri websocketUrl, CancellationToken cancellationToken)
    {
        using var ws = new ClientWebSocket();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        await ws.ConnectAsync(websocketUrl, timeout.Token);
        var command = JsonSerializer.SerializeToUtf8Bytes(new
        {
            id = 1,
            method = "Runtime.evaluate",
            @params = new { expression = FixedExpression, returnByValue = true }
        });
        await ws.SendAsync(command, WebSocketMessageType.Text, true, timeout.Token);

        using var message = new MemoryStream();
        var buffer = new byte[16 * 1024];
        while (true)
        {
            var result = await ws.ReceiveAsync(buffer, timeout.Token);
            if (result.MessageType == WebSocketMessageType.Close)
                throw new InvalidOperationException("Controlled Chrome CDP closed before OAuth readback completed.");
            message.Write(buffer, 0, result.Count);
            if (message.Length > MaxCdpMessageBytes)
                throw new InvalidDataException("Controlled Chrome CDP response exceeded the bounded size limit.");
            if (!result.EndOfMessage) continue;

            using var response = JsonDocument.Parse(message.ToArray());
            if (response.RootElement.TryGetProperty("id", out var id) && id.TryGetInt32(out var value) && value == 1)
            {
                var encoded = response.RootElement.GetProperty("result").GetProperty("result").GetProperty("value").GetString()
                    ?? throw new InvalidDataException("Controlled Chrome OAuth field readback did not return a value.");
                var fields = JsonSerializer.Deserialize<OAuthFields>(encoded, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                    ?? throw new InvalidDataException("Controlled Chrome OAuth field payload is invalid.");
                return fields;
            }
            message.SetLength(0);
        }
    }

    private sealed record OAuthFields(string AccessToken, string ExpiresIn, string IssueDate, string Scopes);
}
