using System.Net;
using System.Text;
using System.Text.Json;
using Xunit;
using YowThi.DevelopmentAgent3.GoogleAppsScript;

namespace YowThi.DotnetAcceptanceTests;

public sealed class AppsScriptConnectorTests
{
    private static AppsScriptProjectFile Manifest(string source = "{\"timeZone\":\"Asia/Bangkok\",\"runtimeVersion\":\"V8\"}")
        => new("appsscript", "JSON", source, null, null, Array.Empty<AppsScriptFunctionInfo>());

    private static AppsScriptProjectFile Code(string source)
        => new("Code", "SERVER_JS", source, null, null, new[] { new AppsScriptFunctionInfo("onOpen", Array.Empty<string>()) });

    [Fact]
    public void CanonicalHash_IsOrderIndependentAndSensitiveToUtf8MultilineSource()
    {
        var filesA = new[] { Manifest(), Code("function onOpen() {\n  Logger.log('สวัสดี');\n}\n") };
        var filesB = new[] { filesA[1], filesA[0] };
        Assert.Equal(AppsScriptContentHash.Compute(filesA), AppsScriptContentHash.Compute(filesB));

        var changed = new[] { Manifest(), Code("function onOpen() {\n  Logger.log('สวัสดี!');\n}\n") };
        Assert.NotEqual(AppsScriptContentHash.Compute(filesA), AppsScriptContentHash.Compute(changed));
    }

    [Fact]
    public void PatchEngine_PreservesUnicodeNewlinesIndentationAndExactMatchCount()
    {
        var before = "function onOpen() {\n  const label = 'เดิม';\n  Logger.log(label);\n}\n";
        var after = "function onOpen() {\n  const label = 'ใหม่';\n  const detail = 'บรรทัดสอง';\n  Logger.log(label + detail);\n}\n";
        var files = new[] { Manifest(), Code(before) };
        var application = AppsScriptPatchEngine.Apply(files, new[]
        {
            new AppsScriptTextReplacement("Code", before, after, 1)
        });

        Assert.Equal(after, application.Files.Single(file => file.Name == "Code").Source);
        Assert.Contains("\n  const detail", application.Files.Single(file => file.Name == "Code").Source, StringComparison.Ordinal);
        Assert.Contains("Code", application.ChangedFiles);
        Assert.Contains("onOpen", application.AffectedFunctions);
        Assert.NotEqual(AppsScriptContentHash.Compute(files), application.ResultHash);
    }

    [Fact]
    public void PatchEngine_RejectsUnexpectedMatchCountWithoutPartialMutation()
    {
        var source = "function a() { return 1; }\nfunction b() { return 1; }\n";
        var files = new[] { Manifest(), Code(source) };
        var ex = Assert.Throws<InvalidOperationException>(() => AppsScriptPatchEngine.Apply(files, new[]
        {
            new AppsScriptTextReplacement("Code", "return 1;", "return 2;", 1)
        }));
        Assert.Contains("expected 1, actual 2", ex.Message, StringComparison.Ordinal);
        Assert.Equal(source, files.Single(file => file.Name == "Code").Source);
    }

    [Fact]
    public async Task ApiClient_GetContent_UsesBearerTokenAndParsesFunctions()
    {
        var handler = new StubHandler(request =>
        {
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Equal("/v1/projects/project_123456/content", request.RequestUri!.AbsolutePath);
            Assert.Equal("Bearer", request.Headers.Authorization!.Scheme);
            Assert.Equal("test-access-token-abcdefghijklmnopqrstuvwxyz", request.Headers.Authorization.Parameter);
            return Json(HttpStatusCode.OK, """
            {
              "scriptId":"project_123456",
              "files":[
                {"name":"appsscript","type":"JSON","source":"{\"timeZone\":\"Asia/Bangkok\"}"},
                {"name":"Code","type":"SERVER_JS","source":"function onOpen() {\n  return 'ไทย';\n}\n","functionSet":{"values":[{"name":"onOpen","parameters":[]}]}}
              ]
            }
            """);
        });
        using var http = new HttpClient(handler);
        var client = new AppsScriptApiClient(http, _ => Task.FromResult("test-access-token-abcdefghijklmnopqrstuvwxyz"), new Uri("https://example.test/v1/projects/"));
        var files = await client.GetContentAsync("project_123456");

        Assert.Equal(2, files.Count);
        var code = files.Single(file => file.Name == "Code");
        Assert.Equal("function onOpen() {\n  return 'ไทย';\n}\n", code.Source);
        Assert.Equal("onOpen", Assert.Single(code.Functions).Name);
    }

    [Fact]
    public async Task ApiClient_UpdateContent_RoundTripsExactUnicodeMultilineSources()
    {
        string? capturedBody = null;
        var handler = new StubHandler(request =>
        {
            Assert.Equal(HttpMethod.Put, request.Method);
            Assert.Equal("/v1/projects/project_123456/content", request.RequestUri!.AbsolutePath);
            capturedBody = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            return Json(HttpStatusCode.OK, capturedBody);
        });
        using var http = new HttpClient(handler);
        var client = new AppsScriptApiClient(http, _ => Task.FromResult("test-access-token-abcdefghijklmnopqrstuvwxyz"), new Uri("https://example.test/v1/projects/"));
        var source = "function test() {\n  const value = 'บรรทัดหนึ่ง';\n  return value;\n}\n";
        var files = new[] { Manifest(), Code(source) };

        var returned = await client.UpdateContentAsync("project_123456", files);

        Assert.NotNull(capturedBody);
        using var wire = JsonDocument.Parse(capturedBody!);
        var wireCode = wire.RootElement.GetProperty("files").EnumerateArray().Single(file => file.GetProperty("name").GetString() == "Code");
        Assert.Equal(source, wireCode.GetProperty("source").GetString());
        Assert.Equal(Encoding.UTF8.GetBytes(source), Encoding.UTF8.GetBytes(wireCode.GetProperty("source").GetString()!));
        Assert.Equal(source, returned.Single(file => file.Name == "Code").Source);
    }

    [Fact]
    public void ConnectorToolSurface_ExposesTypedGetListVerifyAndSealedPatchPlanExecute()
    {
        var methods = typeof(AppsScriptProjectTools).GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
            .Select(method => method.Name)
            .ToHashSet(StringComparer.Ordinal);
        Assert.Contains(nameof(AppsScriptProjectTools.AppsScriptConnectorStatus), methods);
        Assert.Contains(nameof(AppsScriptProjectTools.AppsScriptOAuthImportFromControlledBrowser), methods);
        Assert.Contains(nameof(AppsScriptProjectTools.AppsScriptOAuthClearEphemeral), methods);
        Assert.Contains(nameof(AppsScriptProjectTools.AppsScriptProjectGet), methods);
        Assert.Contains(nameof(AppsScriptProjectTools.AppsScriptProjectListFiles), methods);
        Assert.Contains(nameof(AppsScriptProjectTools.AppsScriptProjectVerify), methods);
        Assert.Contains(nameof(AppsScriptProjectTools.AppsScriptProjectPatchPlan), methods);
        Assert.Contains(nameof(AppsScriptProjectTools.AppsScriptProjectPatchExecute), methods);

        var execute = typeof(AppsScriptProjectTools).GetMethod(nameof(AppsScriptProjectTools.AppsScriptProjectPatchExecute))!;
        var callerParameters = execute.GetParameters().Where(parameter => parameter.ParameterType != typeof(CancellationToken)).Select(parameter => parameter.Name).ToArray();
        Assert.Equal(new[] { "planId", "approvalCode" }, callerParameters);

        var import = typeof(AppsScriptProjectTools).GetMethod(nameof(AppsScriptProjectTools.AppsScriptOAuthImportFromControlledBrowser))!;
        var importCallerParameters = import.GetParameters().Where(parameter => parameter.ParameterType != typeof(CancellationToken)).ToArray();
        Assert.Empty(importCallerParameters);
    }

    [Fact]
    public async Task CredentialProvider_UsesAndClearsEphemeralBrowserTokenWithoutPersistingIt()
    {
        var names = new[]
        {
            AppsScriptCredentialProvider.AccessTokenEnvironmentVariable,
            AppsScriptCredentialProvider.RefreshTokenEnvironmentVariable,
            AppsScriptCredentialProvider.ClientIdEnvironmentVariable,
            AppsScriptCredentialProvider.ClientSecretEnvironmentVariable
        };
        var previous = names.ToDictionary(name => name, Environment.GetEnvironmentVariable, StringComparer.Ordinal);
        AppsScriptEphemeralCredentialStore.Clear();
        try
        {
            foreach (var name in names) Environment.SetEnvironmentVariable(name, null);
            const string token = "test-ephemeral-browser-token-abcdefghijklmnopqrstuvwxyz";
            var imported = AppsScriptEphemeralCredentialStore.Import(token, 600, true);
            Assert.True(imported.Configured);
            Assert.Equal("ephemeral-browser-token", imported.AuthMode);
            Assert.Equal(token.Length, imported.TokenLength);

            using var http = new HttpClient(new StubHandler(_ => throw new InvalidOperationException("Network should not be used for an active ephemeral token.")));
            var provider = new AppsScriptCredentialProvider(http);
            Assert.Equal("ephemeral-browser-token", provider.GetStatus().AuthMode);
            Assert.Equal(token, await provider.GetAccessTokenAsync());

            var cleared = AppsScriptEphemeralCredentialStore.Clear();
            Assert.False(cleared.Configured);
            Assert.Equal("unconfigured", provider.GetStatus().AuthMode);
        }
        finally
        {
            AppsScriptEphemeralCredentialStore.Clear();
            foreach (var pair in previous) Environment.SetEnvironmentVariable(pair.Key, pair.Value);
        }
    }

    [Fact]
    public void EphemeralCredentialStore_RejectsMissingRequiredScope()
    {
        AppsScriptEphemeralCredentialStore.Clear();
        try
        {
            Assert.Throws<UnauthorizedAccessException>(() => AppsScriptEphemeralCredentialStore.Import("test-ephemeral-browser-token-abcdefghijklmnopqrstuvwxyz", 600, false));
            Assert.False(AppsScriptEphemeralCredentialStore.TryGetAccessToken(out _));
        }
        finally
        {
            AppsScriptEphemeralCredentialStore.Clear();
        }
    }

    [Fact]
    public void CredentialProviderStatus_NeverReturnsCredentialValues()
    {
        using var http = new HttpClient(new StubHandler(_ => throw new InvalidOperationException("Network should not be used by status.")));
        var provider = new AppsScriptCredentialProvider(http);
        var status = provider.GetStatus();
        Assert.Contains(status.AuthMode, new[] { "ephemeral-browser-token", "access-token", "refresh-token", "unconfigured" });
        Assert.DoesNotContain("tokenValue", string.Join("|", status.MissingEnvironmentVariables), StringComparison.OrdinalIgnoreCase);
        Assert.Equal("https://script.googleapis.com/v1/projects/", status.ApiBase);
        Assert.Contains("no documented server-side ETag/If-Match", status.ConcurrencyModel, StringComparison.Ordinal);
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string json)
        => new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(handler(request));
    }
}
