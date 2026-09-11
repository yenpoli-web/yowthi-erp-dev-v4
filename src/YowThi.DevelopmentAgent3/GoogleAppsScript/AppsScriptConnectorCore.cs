using System.Buffers.Binary;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace YowThi.DevelopmentAgent3.GoogleAppsScript;

public sealed record AppsScriptFunctionInfo(string Name, IReadOnlyList<string> Parameters);

public sealed record AppsScriptProjectFile(
    string Name,
    string Type,
    string Source,
    DateTimeOffset? CreateTime,
    DateTimeOffset? UpdateTime,
    IReadOnlyList<AppsScriptFunctionInfo> Functions);

public sealed record AppsScriptProjectMetadata(string ProjectId, string? Title, DateTimeOffset? UpdateTime);

public sealed record AppsScriptProjectSnapshot(
    string ProjectId,
    string? Title,
    DateTimeOffset? ProjectUpdateTime,
    string CanonicalSha256,
    int FileCount,
    long TotalSourceBytes,
    bool ManifestJsonValid,
    IReadOnlyList<AppsScriptProjectFile> Files,
    string ConcurrencyModel,
    DateTimeOffset CapturedUtc);

public sealed record AppsScriptProjectFileSummary(
    string Name,
    string Type,
    int SourceUtf8Bytes,
    string SourceSha256,
    DateTimeOffset? UpdateTime,
    IReadOnlyList<string> Functions);

public sealed record AppsScriptProjectFileListResult(
    string ProjectId,
    string CanonicalSha256,
    int FileCount,
    IReadOnlyList<AppsScriptProjectFileSummary> Files,
    DateTimeOffset CapturedUtc);

public sealed record AppsScriptProjectVerifyResult(
    string ProjectId,
    string ActualHash,
    string? ExpectedHash,
    bool? MatchesExpectedHash,
    string? Title,
    DateTimeOffset? ProjectUpdateTime,
    int FileCount,
    long TotalSourceBytes,
    bool ManifestJsonValid,
    string ServerJsParseStatus,
    string ConcurrencyModel,
    DateTimeOffset VerifiedUtc);

public sealed record AppsScriptTextReplacement(string File, string From, string To, int ExpectedMatchCount);

public sealed record AppsScriptPatchApplication(
    IReadOnlyList<AppsScriptProjectFile> Files,
    IReadOnlyList<string> ChangedFiles,
    IReadOnlyList<string> AffectedFunctions,
    string ResultHash);

public sealed record AppsScriptConnectorStatusResult(
    bool Configured,
    string AuthMode,
    IReadOnlyList<string> MissingEnvironmentVariables,
    string ApiBase,
    string RequiredReadScope,
    string RequiredWriteScope,
    string ConcurrencyModel,
    DateTimeOffset CheckedUtc);

public sealed record AppsScriptPatchExecutionResult(
    string PlanId,
    string ProjectId,
    string BeforeHash,
    string ExpectedAfterHash,
    string ActualAfterHash,
    bool Verified,
    IReadOnlyList<string> ChangedFiles,
    IReadOnlyList<string> AffectedFunctions,
    DateTimeOffset? ProjectUpdateTime,
    string ConcurrencyModel,
    DateTimeOffset ExecutedUtc);

public sealed class AppsScriptCredentialProvider
{
    public const string AccessTokenEnvironmentVariable = "YOWTHI_GOOGLE_APPS_SCRIPT_ACCESS_TOKEN";
    public const string RefreshTokenEnvironmentVariable = "YOWTHI_GOOGLE_OAUTH_REFRESH_TOKEN";
    public const string ClientIdEnvironmentVariable = "YOWTHI_GOOGLE_OAUTH_CLIENT_ID";
    public const string ClientSecretEnvironmentVariable = "YOWTHI_GOOGLE_OAUTH_CLIENT_SECRET";
    private static readonly Uri TokenEndpoint = new("https://oauth2.googleapis.com/token");

    private readonly HttpClient _httpClient;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private string? _cachedAccessToken;
    private DateTimeOffset _cachedAccessTokenExpiresUtc;

    public AppsScriptCredentialProvider(HttpClient httpClient) => _httpClient = httpClient;

    public AppsScriptConnectorStatusResult GetStatus()
    {
        var direct = Environment.GetEnvironmentVariable(AccessTokenEnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(direct))
            return Status(true, "access-token", Array.Empty<string>());

        var refresh = Environment.GetEnvironmentVariable(RefreshTokenEnvironmentVariable);
        var clientId = Environment.GetEnvironmentVariable(ClientIdEnvironmentVariable);
        var clientSecret = Environment.GetEnvironmentVariable(ClientSecretEnvironmentVariable);
        var missing = new List<string>();
        if (string.IsNullOrWhiteSpace(refresh)) missing.Add(RefreshTokenEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(clientId)) missing.Add(ClientIdEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(clientSecret)) missing.Add(ClientSecretEnvironmentVariable);
        return Status(missing.Count == 0, missing.Count == 0 ? "refresh-token" : "unconfigured", missing);
    }

    public async Task<string> GetAccessTokenAsync(CancellationToken cancellationToken = default)
    {
        var direct = Environment.GetEnvironmentVariable(AccessTokenEnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(direct)) return ValidateToken(direct);

        var refresh = Environment.GetEnvironmentVariable(RefreshTokenEnvironmentVariable);
        var clientId = Environment.GetEnvironmentVariable(ClientIdEnvironmentVariable);
        var clientSecret = Environment.GetEnvironmentVariable(ClientSecretEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(refresh) || string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret))
            throw new InvalidOperationException($"Apps Script OAuth is not configured. Set {AccessTokenEnvironmentVariable}, or set {RefreshTokenEnvironmentVariable}, {ClientIdEnvironmentVariable}, and {ClientSecretEnvironmentVariable}.");

        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (_cachedAccessToken is not null && _cachedAccessTokenExpiresUtc > DateTimeOffset.UtcNow.AddMinutes(1))
                return _cachedAccessToken;

            using var request = new HttpRequestMessage(HttpMethod.Post, TokenEndpoint)
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["client_id"] = clientId,
                    ["client_secret"] = clientSecret,
                    ["refresh_token"] = refresh,
                    ["grant_type"] = "refresh_token"
                })
            };
            using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
            if (bytes.Length > 64 * 1024) throw new InvalidDataException("Google OAuth token response exceeded the bounded size limit.");
            if (!response.IsSuccessStatusCode)
                throw new InvalidOperationException($"Google OAuth token refresh failed with HTTP {(int)response.StatusCode}.");

            using var doc = JsonDocument.Parse(bytes);
            var token = ValidateToken(doc.RootElement.GetProperty("access_token").GetString() ?? string.Empty);
            var expiresIn = doc.RootElement.TryGetProperty("expires_in", out var expiresElement) && expiresElement.TryGetInt32(out var parsed)
                ? Math.Clamp(parsed, 60, 86_400)
                : 3600;
            _cachedAccessToken = token;
            _cachedAccessTokenExpiresUtc = DateTimeOffset.UtcNow.AddSeconds(expiresIn);
            return token;
        }
        finally
        {
            _gate.Release();
        }
    }

    private static string ValidateToken(string token)
    {
        var value = token.Trim();
        if (value.Length is < 20 or > 8192 || value.Any(char.IsControl))
            throw new InvalidDataException("Google OAuth access token shape is invalid.");
        return value;
    }

    private static AppsScriptConnectorStatusResult Status(bool configured, string mode, IReadOnlyList<string> missing)
        => new(
            configured,
            mode,
            missing,
            AppsScriptApiClient.FixedApiBase.ToString(),
            "https://www.googleapis.com/auth/script.projects.readonly",
            "https://www.googleapis.com/auth/script.projects",
            AppsScriptProjectTools.ConcurrencyModel,
            DateTimeOffset.UtcNow);
}

public sealed class AppsScriptApiClient
{
    public static readonly Uri FixedApiBase = new("https://script.googleapis.com/v1/projects/");
    private const int MaxResponseBytes = 32 * 1024 * 1024;
    private readonly HttpClient _httpClient;
    private readonly Func<CancellationToken, Task<string>> _accessTokenProvider;
    private readonly Uri _apiBase;

    public AppsScriptApiClient(HttpClient httpClient, Func<CancellationToken, Task<string>> accessTokenProvider, Uri? apiBase = null)
    {
        _httpClient = httpClient;
        _accessTokenProvider = accessTokenProvider;
        _apiBase = apiBase ?? FixedApiBase;
    }

    public async Task<AppsScriptProjectMetadata> GetProjectAsync(string projectId, CancellationToken cancellationToken = default)
    {
        projectId = AppsScriptValidation.RequireProjectId(projectId);
        using var response = await SendAsync(HttpMethod.Get, BuildUri(projectId, string.Empty), null, cancellationToken);
        using var doc = JsonDocument.Parse(await ReadBoundedAsync(response, cancellationToken));
        var root = doc.RootElement;
        var returnedId = root.TryGetProperty("scriptId", out var id) ? id.GetString() : projectId;
        return new(
            returnedId ?? projectId,
            root.TryGetProperty("title", out var title) ? title.GetString() : null,
            ParseTimestamp(root, "updateTime"));
    }

    public async Task<IReadOnlyList<AppsScriptProjectFile>> GetContentAsync(string projectId, CancellationToken cancellationToken = default)
    {
        projectId = AppsScriptValidation.RequireProjectId(projectId);
        using var response = await SendAsync(HttpMethod.Get, BuildUri(projectId, "content"), null, cancellationToken);
        using var doc = JsonDocument.Parse(await ReadBoundedAsync(response, cancellationToken));
        if (!doc.RootElement.TryGetProperty("files", out var filesElement) || filesElement.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Apps Script getContent response did not contain a files array.");
        var files = new List<AppsScriptProjectFile>();
        foreach (var element in filesElement.EnumerateArray()) files.Add(ParseFile(element));
        AppsScriptValidation.ValidateProjectFiles(files);
        return files;
    }

    public async Task<IReadOnlyList<AppsScriptProjectFile>> UpdateContentAsync(string projectId, IReadOnlyList<AppsScriptProjectFile> files, CancellationToken cancellationToken = default)
    {
        projectId = AppsScriptValidation.RequireProjectId(projectId);
        AppsScriptValidation.ValidateProjectFiles(files);
        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            files = files.Select(file => new { name = file.Name, type = file.Type, source = file.Source }).ToArray()
        });
        using var content = new ByteArrayContent(payload);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
        using var response = await SendAsync(HttpMethod.Put, BuildUri(projectId, "content"), content, cancellationToken);
        using var doc = JsonDocument.Parse(await ReadBoundedAsync(response, cancellationToken));
        if (!doc.RootElement.TryGetProperty("files", out var filesElement) || filesElement.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Apps Script updateContent response did not contain a files array.");
        var returned = new List<AppsScriptProjectFile>();
        foreach (var element in filesElement.EnumerateArray()) returned.Add(ParseFile(element));
        AppsScriptValidation.ValidateProjectFiles(returned);
        return returned;
    }

    private Uri BuildUri(string projectId, string suffix)
    {
        var escaped = Uri.EscapeDataString(projectId);
        return new Uri(_apiBase, string.IsNullOrEmpty(suffix) ? escaped : $"{escaped}/{suffix}");
    }

    private async Task<HttpResponseMessage> SendAsync(HttpMethod method, Uri uri, HttpContent? content, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, uri) { Content = content };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await _accessTokenProvider(cancellationToken));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (response.IsSuccessStatusCode) return response;
        var status = (int)response.StatusCode;
        response.Dispose();
        throw new InvalidOperationException($"Google Apps Script API request failed with HTTP {status}.");
    }

    private static async Task<byte[]> ReadBoundedAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken);
        if (bytes.Length <= 0 || bytes.Length > MaxResponseBytes)
            throw new InvalidDataException("Google Apps Script API response size is outside the bounded limit.");
        return bytes;
    }

    private static AppsScriptProjectFile ParseFile(JsonElement element)
    {
        var name = element.GetProperty("name").GetString() ?? throw new InvalidDataException("Apps Script file name is missing.");
        var type = element.GetProperty("type").GetString() ?? throw new InvalidDataException("Apps Script file type is missing.");
        var source = element.GetProperty("source").GetString() ?? string.Empty;
        var functions = new List<AppsScriptFunctionInfo>();
        if (element.TryGetProperty("functionSet", out var functionSet) && functionSet.ValueKind == JsonValueKind.Object &&
            functionSet.TryGetProperty("values", out var values) && values.ValueKind == JsonValueKind.Array)
        {
            foreach (var function in values.EnumerateArray())
            {
                var functionName = function.TryGetProperty("name", out var functionNameElement) ? functionNameElement.GetString() : null;
                if (string.IsNullOrWhiteSpace(functionName)) continue;
                var parameters = new List<string>();
                if (function.TryGetProperty("parameters", out var parameterArray) && parameterArray.ValueKind == JsonValueKind.Array)
                    foreach (var parameter in parameterArray.EnumerateArray())
                        if (parameter.GetString() is { } value) parameters.Add(value);
                functions.Add(new(functionName, parameters));
            }
        }
        return new(name, type, source, ParseTimestamp(element, "createTime"), ParseTimestamp(element, "updateTime"), functions);
    }

    private static DateTimeOffset? ParseTimestamp(JsonElement element, string name)
        => element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String &&
           DateTimeOffset.TryParse(value.GetString(), out var parsed) ? parsed : null;
}

public static class AppsScriptValidation
{
    public const int MaxFiles = 200;
    public const int MaxSourceUtf8BytesPerFile = 4 * 1024 * 1024;
    public const long MaxTotalSourceUtf8Bytes = 16L * 1024 * 1024;

    public static string RequireProjectId(string projectId)
    {
        var value = (projectId ?? string.Empty).Trim();
        if (value.Length is < 10 or > 256 || value.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_')))
            throw new ArgumentException("Apps Script projectId must be a bounded Drive/script ID containing only ASCII letters, digits, '-' or '_'.", nameof(projectId));
        return value;
    }

    public static string RequireHash(string hash, string parameterName)
    {
        var value = (hash ?? string.Empty).Trim().ToUpperInvariant();
        if (value.Length != 64 || value.Any(c => !Uri.IsHexDigit(c)))
            throw new ArgumentException("Expected SHA-256 must be exactly 64 hexadecimal characters.", parameterName);
        return value;
    }

    public static void ValidateProjectFiles(IReadOnlyList<AppsScriptProjectFile> files)
    {
        if (files.Count is < 1 or > MaxFiles) throw new InvalidDataException("Apps Script project file count is outside the bounded limit.");
        var names = new HashSet<string>(StringComparer.Ordinal);
        long totalBytes = 0;
        var manifestFound = false;
        foreach (var file in files)
        {
            if (string.IsNullOrWhiteSpace(file.Name) || file.Name.Length > 256 || file.Name.Any(char.IsControl))
                throw new InvalidDataException("Apps Script file name is invalid.");
            if (!names.Add(file.Name)) throw new InvalidDataException($"Duplicate Apps Script file name: {file.Name}");
            if (file.Type is not ("SERVER_JS" or "HTML" or "JSON")) throw new InvalidDataException($"Unsupported Apps Script file type: {file.Type}");
            var source = file.Source ?? throw new InvalidDataException($"Apps Script file source is missing: {file.Name}");
            var bytes = Encoding.UTF8.GetByteCount(source);
            if (bytes > MaxSourceUtf8BytesPerFile) throw new InvalidDataException($"Apps Script file source exceeds the bounded limit: {file.Name}");
            totalBytes = checked(totalBytes + bytes);
            if (totalBytes > MaxTotalSourceUtf8Bytes) throw new InvalidDataException("Apps Script project source exceeds the bounded total size limit.");
            if (file.Name == "appsscript" && file.Type == "JSON")
            {
                using var _ = JsonDocument.Parse(source);
                manifestFound = true;
            }
        }
        if (!manifestFound) throw new InvalidDataException("Apps Script project must contain a valid JSON manifest named appsscript.");
    }
}

public static class AppsScriptContentHash
{
    private static readonly byte[] Domain = Encoding.UTF8.GetBytes("YOWTHI-APPS-SCRIPT-CANONICAL-V1");

    public static string Compute(IReadOnlyList<AppsScriptProjectFile> files)
    {
        AppsScriptValidation.ValidateProjectFiles(files);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Domain);
        foreach (var file in files.OrderBy(file => file.Name, StringComparer.Ordinal))
        {
            AppendString(hash, file.Name);
            AppendString(hash, file.Type);
            AppendString(hash, file.Source);
        }
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    public static string ComputeSourceHash(AppsScriptProjectFile file)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(file.Source)));

    private static void AppendString(IncrementalHash hash, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value ?? string.Empty);
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        hash.AppendData(length);
        hash.AppendData(bytes);
    }
}

public static class AppsScriptPatchEngine
{
    public const int MaxPatches = 32;
    public const int MaxLiteralUtf8Bytes = 256 * 1024;

    public static AppsScriptPatchApplication Apply(IReadOnlyList<AppsScriptProjectFile> inputFiles, IReadOnlyList<AppsScriptTextReplacement> patches)
    {
        AppsScriptValidation.ValidateProjectFiles(inputFiles);
        if (patches.Count is < 1 or > MaxPatches) throw new ArgumentOutOfRangeException(nameof(patches), $"Patch count must be between 1 and {MaxPatches}.");
        var files = inputFiles.ToDictionary(file => file.Name, file => file, StringComparer.Ordinal);
        var changedFiles = new HashSet<string>(StringComparer.Ordinal);
        var affectedFunctions = new HashSet<string>(StringComparer.Ordinal);

        foreach (var patch in patches)
        {
            if (string.IsNullOrWhiteSpace(patch.File) || patch.File.Length > 256 || patch.File.Any(char.IsControl))
                throw new ArgumentException("Patch file name is invalid.", nameof(patches));
            if (!files.TryGetValue(patch.File, out var file)) throw new InvalidDataException($"Apps Script patch target file does not exist: {patch.File}");
            if (string.IsNullOrEmpty(patch.From)) throw new ArgumentException("Patch 'from' text may not be empty.", nameof(patches));
            if (Encoding.UTF8.GetByteCount(patch.From) > MaxLiteralUtf8Bytes || Encoding.UTF8.GetByteCount(patch.To ?? string.Empty) > MaxLiteralUtf8Bytes)
                throw new ArgumentOutOfRangeException(nameof(patches), "Patch literal exceeds the bounded UTF-8 size limit.");
            if (patch.ExpectedMatchCount is < 1 or > 1024) throw new ArgumentOutOfRangeException(nameof(patches), "expectedMatchCount must be between 1 and 1024.");
            var actualMatches = CountOccurrences(file.Source, patch.From);
            if (actualMatches != patch.ExpectedMatchCount)
                throw new InvalidOperationException($"Apps Script patch match-count assertion failed for {patch.File}: expected {patch.ExpectedMatchCount}, actual {actualMatches}.");
            var updatedSource = file.Source.Replace(patch.From, patch.To ?? string.Empty, StringComparison.Ordinal);
            foreach (var function in file.Functions) affectedFunctions.Add(function.Name);
            file = file with { Source = updatedSource };
            files[patch.File] = file;
            changedFiles.Add(patch.File);
        }

        var resultFiles = inputFiles.Select(file => files[file.Name]).ToArray();
        AppsScriptValidation.ValidateProjectFiles(resultFiles);
        var before = AppsScriptContentHash.Compute(inputFiles);
        var after = AppsScriptContentHash.Compute(resultFiles);
        if (string.Equals(before, after, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Apps Script patch would make no project-content change.");
        return new(resultFiles, changedFiles.OrderBy(x => x, StringComparer.Ordinal).ToArray(), affectedFunctions.OrderBy(x => x, StringComparer.Ordinal).ToArray(), after);
    }

    public static string ComputePatchSpecificationHash(IReadOnlyList<AppsScriptTextReplacement> patches)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var patch in patches)
        {
            Append(hash, patch.File);
            Append(hash, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(patch.From ?? string.Empty))));
            Append(hash, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(patch.To ?? string.Empty))));
            Append(hash, patch.ExpectedMatchCount.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static int CountOccurrences(string source, string value)
    {
        var count = 0;
        var index = 0;
        while ((index = source.IndexOf(value, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += value.Length;
        }
        return count;
    }

    private static void Append(IncrementalHash hash, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value ?? string.Empty);
        hash.AppendData(bytes);
        hash.AppendData(new byte[] { 0 });
    }
}
