using System.Text;
using Xunit;
using YowThi.DevelopmentAgent3.GoogleAppsScript;

namespace YowThi.DotnetAcceptanceTests;

public sealed class AppsScriptDiagnosticsTests
{
    [Fact]
    public void GoogleErrorParser_ParsesNestedAppsScriptErrorWithoutCredentialMaterial()
    {
        var body = Encoding.UTF8.GetBytes("""
        {
          "error": {
            "code": 403,
            "status": "PERMISSION_DENIED",
            "message": "Request had insufficient authentication scopes."
          }
        }
        """);

        var parsed = AppsScriptDiagnosticsTools.ParseGoogleError(body);

        Assert.Equal("PERMISSION_DENIED", parsed.Status);
        Assert.Equal("Request had insufficient authentication scopes.", parsed.Message);
    }

    [Fact]
    public void GoogleErrorParser_ParsesFlatOAuthError()
    {
        var body = Encoding.UTF8.GetBytes("""
        {
          "error": "invalid_grant",
          "error_description": "Token has been expired or revoked."
        }
        """);

        var parsed = AppsScriptDiagnosticsTools.ParseGoogleError(body);

        Assert.Equal("invalid_grant", parsed.Status);
        Assert.Equal("Token has been expired or revoked.", parsed.Message);
    }

    [Fact]
    public void DiagnosticsSurface_ExposesScopeApiAndExecutionReadbackTools()
    {
        var methods = typeof(AppsScriptDiagnosticsTools)
            .GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
            .Select(method => method.Name)
            .ToHashSet(StringComparer.Ordinal);

        Assert.Contains(nameof(AppsScriptDiagnosticsTools.OAuthScopeStatus), methods);
        Assert.Contains(nameof(AppsScriptDiagnosticsTools.ApiReadProbe), methods);
        Assert.Contains(nameof(AppsScriptDiagnosticsTools.PatchExecutionStatus), methods);
    }

    [Fact]
    public void ScopeStatusResult_DoesNotExposeCredentialValueProperties()
    {
        var propertyNames = typeof(AppsScriptOAuthScopeStatusResult)
            .GetProperties()
            .Select(property => property.Name)
            .ToArray();

        Assert.DoesNotContain(propertyNames, name => name.Contains("AccessToken", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(propertyNames, name => name.Contains("RefreshToken", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(propertyNames, name => name.Contains("ClientSecret", StringComparison.OrdinalIgnoreCase));
    }
}
