using System.ComponentModel;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Server;

namespace YowThi.DevelopmentAgent3.GoogleAppsScript;

public sealed record AppsScriptOAuthScopeStatusResult(
    bool Configured,
    string AuthMode,
    bool TokenInspectionSucceeded,
    int? HttpStatus,
    bool ReadScopeGranted,
    bool WriteScopeGranted,
    IReadOnlyList<string> GrantedScopes,
    string RequiredReadScope,
    string RequiredWriteScope,
    string? ErrorStatus,
    string? ErrorMessage,
    DateTimeOffset CheckedUtc);

public sealed record AppsScriptApiReadProbeResult(
    string ProjectId,
    string Operation,
    bool Succeeded,
    int HttpStatus,
    string? GoogleErrorStatus,
    string? GoogleErrorMessage,
    string? ReturnedProjectId,
    string? Title,
    int? FileCount,
    DateTimeOffset CheckedUtc);

public sealed record AppsScriptPatchExecutionStatusResult(
    string PlanId,
    bool AuditObserved,
    bool ExecutionReachedServer,
    int MatchingEventCount,
    string? LastOutcome,
    string? LastStage,
    string? ErrorType,
    string? ProjectId,
    DateTimeOffset? EventUtc,
    bool? AuditHashValid,
    string? AuditHash,
    DateTimeOffset CheckedUtc);

[McpServerToolType]
public static class AppsScriptDiagnosticsTools
{
    private const string ReadScope = "https://www.googleapis.com/auth/script.projects.readonly";
    private const string WriteScope = "https://www.googleapis.com/auth/script.projects";
    private const string AuditPath = @"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit\actions.jsonl";
    private static readonly Uri TokenInfoEndpoint = new("https://oauth2.googleapis.com/tokeninfo");
    private static readonly Uri ApiBase = new("https://script.googleapis.com/v1/projects/");
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };
    private static readonly AppsScriptCredentialProvider Credentials = new(Http);

    [McpServerTool(Name = "apps_script_oauth_scope_status", ReadOnly = true, Destructive = false, OpenWorld = true)]
    [Description("Inspect the actual scopes granted to the currently effective Google Apps Script access token. The token value is never returned. Reports whether read and write project scopes are actually present, rather than only reporting configured environment variables.")]
    public static async Task<AppsScriptOAuthScopeStatusResult> OAuthScopeStatus(CancellationToken cancellationToken = default)
    {
        var configured = Credentials.GetStatus();
        string accessToken;
        try
        {
            accessToken = await Credentials.GetAccessTokenAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            return new(
                configured.Configured,
                configured.AuthMode,
                false,
                null,
                false,
                false,
                Array.Empty<string>(),
                ReadScope,
                WriteScope,
                "TOKEN_ACQUISITION_FAILED",
                Sanitize(ex.Message),
                DateTimeOffset.UtcNow);
        }

        using var request = new HttpRequestMessage(HttpMethod.Get,
            new Uri(TokenInfoEndpoint, "?access_token=" + Uri.EscapeDataString(accessToken)));
        using var response = await Http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        var body = await ReadBoundedBodyAsync(response, 64 * 1024, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var error = ParseGoogleError(body);
            return new(
                configured.Configured,
                configured.AuthMode,
                false,
                (int)response.StatusCode,
                false,
                false,
                Array.Empty<string>(),
                ReadScope,
                WriteScope,
                error.Status,
                error.Message,
                DateTimeOffset.UtcNow);
        }

        using var doc = JsonDocument.Parse(body);
        var scopeText = doc.RootElement.TryGetProperty("scope", out var scopeElement) && scopeElement.ValueKind == JsonValueKind.String
            ? scopeElement.GetString() ?? string.Empty
            : string.Empty;
        var scopes = scopeText.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();
        var writeGranted = scopes.Contains(WriteScope, StringComparer.Ordinal);
        var readGranted = writeGranted || scopes.Contains(ReadScope, StringComparer.Ordinal);
        return new(
            configured.Configured,
            configured.AuthMode,
            true,
            (int)response.StatusCode,
            readGranted,
            writeGranted,
            scopes,
            ReadScope,
            WriteScope,
            null,
            null,
            DateTimeOffset.UtcNow);
    }

    [McpServerTool(Name = "apps_script_api_read_probe", ReadOnly = true, Destructive = false, OpenWorld = true)]
    [Description("Perform one bounded read-only probe against the fixed Google Apps Script project API and return structured HTTP/Google error details without exposing OAuth credentials. operation must be exactly 'project' or 'content'.")]
    public static async Task<AppsScriptApiReadProbeResult> ApiReadProbe(
        string projectId,
        string operation = "content",
        CancellationToken cancellationToken = default)
    {
        projectId = AppsScriptValidation.RequireProjectId(projectId);
        operation = (operation ?? string.Empty).Trim().ToLowerInvariant();
        if (operation is not ("project" or "content"))
            throw new ArgumentException("operation must be exactly 'project' or 'content'.", nameof(operation));

        string accessToken;
        try
        {
            accessToken = await Credentials.GetAccessTokenAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            return new(projectId, operation, false, 0, "TOKEN_ACQUISITION_FAILED", Sanitize(ex.Message), null, null, null, DateTimeOffset.UtcNow);
        }

        var escaped = Uri.EscapeDataString(projectId);
        var relative = operation == "project" ? escaped : escaped + "/content";
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(ApiBase, relative));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var response = await Http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        var body = await ReadBoundedBodyAsync(response, 32 * 1024 * 1024, cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            var error = ParseGoogleError(body);
            return new(projectId, operation, false, (int)response.StatusCode, error.Status, error.Message, null, null, null, DateTimeOffset.UtcNow);
        }

        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;
        if (operation == "project")
        {
            var returnedId = root.TryGetProperty("scriptId", out var id) && id.ValueKind == JsonValueKind.String ? id.GetString() : null;
            var title = root.TryGetProperty("title", out var titleElement) && titleElement.ValueKind == JsonValueKind.String ? titleElement.GetString() : null;
            return new(projectId, operation, true, (int)response.StatusCode, null, null, returnedId, title, null, DateTimeOffset.UtcNow);
        }

        var count = root.TryGetProperty("files", out var files) && files.ValueKind == JsonValueKind.Array ? files.GetArrayLength() : 0;
        return new(projectId, operation, true, (int)response.StatusCode, null, null, projectId, null, count, DateTimeOffset.UtcNow);
    }

    [McpServerTool(Name = "apps_script_patch_execution_status", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read the local append-only Agent audit chain for one Apps Script patch plan and report whether execution ever reached the R22 server, the last recorded stage/outcome, and any recorded error type. No source payload or credential value is returned.")]
    public static AppsScriptPatchExecutionStatusResult PatchExecutionStatus(string planId)
    {
        planId = RequirePlanId(planId);
        if (!File.Exists(AuditPath))
            return new(planId, false, false, 0, null, null, null, null, null, null, null, DateTimeOffset.UtcNow);

        var info = new FileInfo(AuditPath);
        if (info.Length > 64L * 1024 * 1024)
            throw new InvalidDataException("Agent audit log exceeds the bounded diagnostics size limit.");

        AuditMatch? last = null;
        var matching = 0;
        var lines = 0;
        foreach (var line in File.ReadLines(AuditPath, Encoding.UTF8))
        {
            if (++lines > 200_000)
                throw new InvalidDataException("Agent audit log exceeds the bounded diagnostics line limit.");
            if (line.Length is <= 0 or > 1024 * 1024) continue;
            if (!TryParseAuditLine(line, planId, out var match)) continue;
            matching++;
            last = match;
        }

        if (last is null)
            return new(planId, false, false, 0, null, null, null, null, null, null, null, DateTimeOffset.UtcNow);

        var executionReachedServer = string.Equals(last.Outcome, "failed", StringComparison.Ordinal) ||
                                     string.Equals(last.Outcome, "executed", StringComparison.Ordinal);
        return new(
            planId,
            true,
            executionReachedServer,
            matching,
            last.Outcome,
            last.Stage,
            last.ErrorType,
            last.ProjectId,
            last.Utc,
            last.HashValid,
            last.Hash,
            DateTimeOffset.UtcNow);
    }

    public static (string? Status, string? Message) ParseGoogleError(byte[] body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (root.TryGetProperty("error", out var nested) && nested.ValueKind == JsonValueKind.Object)
            {
                var status = nested.TryGetProperty("status", out var statusElement) && statusElement.ValueKind == JsonValueKind.String
                    ? statusElement.GetString()
                    : null;
                var message = nested.TryGetProperty("message", out var messageElement) && messageElement.ValueKind == JsonValueKind.String
                    ? messageElement.GetString()
                    : null;
                return (Sanitize(status), Sanitize(message));
            }

            var flatStatus = root.TryGetProperty("error", out var errorElement) && errorElement.ValueKind == JsonValueKind.String
                ? errorElement.GetString()
                : null;
            var flatMessage = root.TryGetProperty("error_description", out var descriptionElement) && descriptionElement.ValueKind == JsonValueKind.String
                ? descriptionElement.GetString()
                : null;
            return (Sanitize(flatStatus), Sanitize(flatMessage));
        }
        catch
        {
            return ("UNPARSEABLE_GOOGLE_ERROR", "Google error response could not be parsed as bounded JSON.");
        }
    }

    private static async Task<byte[]> ReadBoundedBodyAsync(HttpResponseMessage response, int maxBytes, CancellationToken cancellationToken)
    {
        var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
        if (bytes.Length > maxBytes)
            throw new InvalidDataException("Google response exceeded the bounded diagnostics size limit.");
        return bytes;
    }

    private static string RequirePlanId(string planId)
    {
        var value = (planId ?? string.Empty).Trim();
        if (value.Length != 32 || value.Any(ch => !Uri.IsHexDigit(ch)))
            throw new ArgumentException("planId must be exactly 32 hexadecimal characters.", nameof(planId));
        return value.ToLowerInvariant();
    }

    private static bool TryParseAuditLine(string line, string planId, out AuditMatch match)
    {
        match = null!;
        try
        {
            using var outer = JsonDocument.Parse(line);
            var outerRoot = outer.RootElement;
            if (!outerRoot.TryGetProperty("payloadBase64", out var payloadElement) || payloadElement.ValueKind != JsonValueKind.String)
                return false;
            if (!outerRoot.TryGetProperty("hash", out var hashElement) || hashElement.ValueKind != JsonValueKind.String)
                return false;
            var payloadBytes = Convert.FromBase64String(payloadElement.GetString() ?? string.Empty);
            var recordedHash = (hashElement.GetString() ?? string.Empty).Trim().ToUpperInvariant();
            var actualHash = Convert.ToHexString(SHA256.HashData(payloadBytes));
            var hashValid = string.Equals(recordedHash, actualHash, StringComparison.OrdinalIgnoreCase);

            using var payload = JsonDocument.Parse(payloadBytes);
            var root = payload.RootElement;
            if (!root.TryGetProperty("tool", out var tool) || !string.Equals(tool.GetString(), "apps-script", StringComparison.Ordinal))
                return false;
            if (!root.TryGetProperty("operation", out var operation) || !string.Equals(operation.GetString(), "project-patch", StringComparison.Ordinal))
                return false;
            if (!root.TryGetProperty("detail", out var detail) || detail.ValueKind != JsonValueKind.Object)
                return false;
            var detailPlanId = FindStringProperty(detail, "planId");
            if (!string.Equals(detailPlanId, planId, StringComparison.OrdinalIgnoreCase))
                return false;

            var outcome = root.TryGetProperty("outcome", out var outcomeElement) && outcomeElement.ValueKind == JsonValueKind.String
                ? outcomeElement.GetString()
                : null;
            DateTimeOffset? utc = null;
            if (root.TryGetProperty("utc", out var utcElement) && utcElement.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(utcElement.GetString(), out var parsedUtc))
                utc = parsedUtc;
            var target = root.TryGetProperty("target", out var targetElement) && targetElement.ValueKind == JsonValueKind.String
                ? targetElement.GetString()
                : null;

            match = new(
                outcome,
                FindStringProperty(detail, "stage"),
                FindStringProperty(detail, "errorType"),
                target,
                utc,
                hashValid,
                recordedHash);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string? FindStringProperty(JsonElement obj, string name)
    {
        foreach (var property in obj.EnumerateObject())
            if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase) && property.Value.ValueKind == JsonValueKind.String)
                return property.Value.GetString();
        return null;
    }

    private static string? Sanitize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var filtered = new string(value.Where(ch => !char.IsControl(ch) || ch == '\t').ToArray()).Trim();
        if (filtered.Length > 1024) filtered = filtered[..1024];
        return filtered;
    }

    private sealed record AuditMatch(
        string? Outcome,
        string? Stage,
        string? ErrorType,
        string? ProjectId,
        DateTimeOffset? Utc,
        bool HashValid,
        string Hash);
}
