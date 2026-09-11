using System;
using System.IO;
using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class BrowserDiagnosticsInterpolationContractTests
{
    [Fact]
    public void DiagnosticsExpression_UsesRawStringInterpolationForFramePrelude()
    {
        var source = ReadBrowserCdpCoreSource();
        const string methodStart = "internal static async Task<BrowserEditorDiagnosticsResult> GetDiagnosticsAsync";
        const string methodEnd = "internal static async Task<(bool Matched, string ObservedText)> WaitForTextAsync";

        var start = source.IndexOf(methodStart, StringComparison.Ordinal);
        Assert.True(start >= 0, "GetDiagnosticsAsync source was not found.");
        var end = source.IndexOf(methodEnd, start, StringComparison.Ordinal);
        Assert.True(end > start, "WaitForTextAsync source boundary was not found.");

        var methodSource = source[start..end];
        Assert.Contains("var expression = $$\"\"\"", methodSource, StringComparison.Ordinal);
        Assert.Contains("{{BrowserFrameScript.BuildContextPrelude()}}", methodSource, StringComparison.Ordinal);
        Assert.DoesNotContain("const string expression = \"\"\"", methodSource, StringComparison.Ordinal);
    }

    private static string ReadBrowserCdpCoreSource()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var path = Path.Combine(dir.FullName, "src", "YowThi.DevelopmentAgent3", "Browser", "BrowserCdpCore.cs");
            if (File.Exists(path)) return File.ReadAllText(path);
        }

        throw new FileNotFoundException("Could not locate BrowserCdpCore.cs from the acceptance-test output path.");
    }
}
