using System.Reflection;
using Xunit;
using YowThi.DevelopmentAgent3.Browser;

namespace YowThi.DotnetAcceptanceTests;

public sealed class BrowserCdpControlTests
{
    [Fact]
    public void ControlledChromeArguments_AreFixedLoopbackAndUseIsolatedProfile()
    {
        const string profile = @"C:\Users\Test\AppData\Local\YowThi\BrowserControl\Profile";
        var args = BrowserControlContract.ControlledChromeArgumentsForValidation(profile);

        Assert.Contains("--remote-debugging-address=127.0.0.1", args);
        Assert.Contains("--remote-debugging-port=9223", args);
        Assert.Contains($"--user-data-dir={profile}", args);
        Assert.Contains("--no-first-run", args);
        Assert.Contains("--no-default-browser-check", args);
        Assert.Contains("--new-window", args);
        Assert.Contains("about:blank", args);
        Assert.Equal("http://127.0.0.1:9223", BrowserControlContract.Endpoint);
        Assert.Contains("never clone or read the ordinary Chrome Cookies/History/Local State profile", BrowserControlContract.ProfilePolicy, StringComparison.Ordinal);
        Assert.Contains("ordinary Chrome", BrowserControlContract.IsolationModel, StringComparison.Ordinal);
    }

    [Fact]
    public void NavigableUrlValidation_RejectsNonHttpAndEmbeddedCredentials()
    {
        var method = typeof(BrowserControlContract).Assembly
            .GetType("YowThi.DevelopmentAgent3.Browser.BrowserCdpValidation", throwOnError: true)!
            .GetMethod("RequireNavigableUrl", BindingFlags.Static | BindingFlags.NonPublic)!;

        Assert.Equal("https://example.test/path?q=1", method.Invoke(null, new object[] { "https://example.test/path?q=1" }));
        Assert.Equal("about:blank", method.Invoke(null, new object[] { "about:blank" }));

        var ftp = Assert.Throws<TargetInvocationException>(() => method.Invoke(null, new object[] { "ftp://example.test/file" }));
        Assert.IsType<ArgumentException>(ftp.InnerException);
        var credentials = Assert.Throws<TargetInvocationException>(() => method.Invoke(null, new object[] { "https://user:pass@example.test/" }));
        Assert.IsType<ArgumentException>(credentials.InnerException);
    }

    [Fact]
    public void ExactPatch_PreservesUnicodeNewlinesAndExactMatchCount()
    {
        var before = "function save() {\n  const label = 'เดิม';\n  return label;\n}\n";
        var afterBlock = "const label = 'ใหม่';\n  const detail = 'บรรทัดสอง';";
        var result = BrowserExactPatchEngine.Apply(before, new[]
        {
            new BrowserTextReplacement("const label = 'เดิม';", afterBlock, 1)
        });

        Assert.Equal("function save() {\n  const label = 'ใหม่';\n  const detail = 'บรรทัดสอง';\n  return label;\n}\n", result);
        Assert.Contains("\n  const detail", result, StringComparison.Ordinal);
    }

    [Fact]
    public void ExactPatch_RejectsUnexpectedMatchCount()
    {
        const string source = "a();\na();\n";
        var ex = Assert.Throws<InvalidOperationException>(() => BrowserExactPatchEngine.Apply(source, new[]
        {
            new BrowserTextReplacement("a();", "b();", 1)
        }));
        Assert.Contains("expected=1, actual=2", ex.Message, StringComparison.Ordinal);
        Assert.Equal("a();\na();\n", source);
    }

    [Fact]
    public void ExactPatchSpecificationHash_IsDeterministicAndSensitive()
    {
        var a = new[] { new BrowserTextReplacement("old", "new", 1) };
        var b = new[] { new BrowserTextReplacement("old", "new", 1) };
        var c = new[] { new BrowserTextReplacement("old", "newer", 1) };
        Assert.Equal(BrowserExactPatchEngine.ComputeSpecificationHash(a), BrowserExactPatchEngine.ComputeSpecificationHash(b));
        Assert.NotEqual(BrowserExactPatchEngine.ComputeSpecificationHash(a), BrowserExactPatchEngine.ComputeSpecificationHash(c));
    }

    [Fact]
    public void BrowserToolSurface_ExposesTabsDomEditorAndSavedStateWithoutArbitraryJavascriptOrCdpHost()
    {
        var methods = typeof(BrowserCdpTools).GetMethods(BindingFlags.Public | BindingFlags.Static);
        var names = methods.Select(method => method.Name).ToHashSet(StringComparer.Ordinal);

        Assert.Contains(nameof(BrowserCdpTools.BrowserControlledSessionStatus), names);
        Assert.Contains(nameof(BrowserCdpTools.BrowserControlledSessionStartPlan), names);
        Assert.Contains(nameof(BrowserCdpTools.BrowserControlledSessionStartExecute), names);
        Assert.Contains(nameof(BrowserCdpTools.BrowserTabList), names);
        Assert.Contains(nameof(BrowserCdpTools.BrowserTabOpenPlan), names);
        Assert.Contains(nameof(BrowserCdpTools.BrowserTabActivatePlan), names);
        Assert.Contains(nameof(BrowserCdpTools.BrowserTabClosePlan), names);
        Assert.Contains(nameof(BrowserCdpTools.BrowserNavigatePlan), names);
        Assert.Contains(nameof(BrowserCdpTools.BrowserDomQuery), names);
        Assert.Contains(nameof(BrowserCdpTools.BrowserDomClickPlan), names);
        Assert.Contains(nameof(BrowserCdpTools.BrowserEditorGetText), names);
        Assert.Contains(nameof(BrowserCdpTools.BrowserEditorGetDiagnostics), names);
        Assert.Contains(nameof(BrowserCdpTools.BrowserEditorReplaceExactPlan), names);
        Assert.Contains(nameof(BrowserCdpTools.BrowserWaitForSavedState), names);

        var forbidden = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "javascript", "script", "expression", "cdpHost", "cdpPort", "devToolsHost", "devToolsPort", "webSocketUrl"
        };
        foreach (var parameter in methods.SelectMany(method => method.GetParameters()))
            Assert.DoesNotContain(parameter.Name ?? string.Empty, forbidden);
    }

    [Fact]
    public void BrowserMutationExecuteMethods_AcceptOnlyPlanApprovalAndCancellation()
    {
        var executeMethods = typeof(BrowserCdpTools).GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Where(method => method.Name.EndsWith("Execute", StringComparison.Ordinal))
            .ToArray();
        Assert.NotEmpty(executeMethods);
        foreach (var method in executeMethods)
        {
            var callerParameters = method.GetParameters()
                .Where(parameter => parameter.ParameterType != typeof(CancellationToken))
                .Select(parameter => parameter.Name)
                .ToArray();
            Assert.Equal(new[] { "planId", "approvalCode" }, callerParameters);
        }
    }
}
