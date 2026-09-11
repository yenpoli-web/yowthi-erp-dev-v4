using System.Reflection;
using Xunit;
using YowThi.DevelopmentAgent3.Browser;

namespace YowThi.DotnetAcceptanceTests;

public sealed class BrowserIframeTraversalContractTests
{
    [Fact]
    public void FrameTraversalPrelude_IsBoundedAndSameOriginFailClosed()
    {
        var type = typeof(BrowserControlContract).Assembly
            .GetType("YowThi.DevelopmentAgent3.Browser.BrowserFrameScript", throwOnError: true)!;

        var maxDepth = (int)type.GetField("MaxDepth", BindingFlags.Static | BindingFlags.NonPublic)!
            .GetRawConstantValue()!;
        var maxContexts = (int)type.GetField("MaxContexts", BindingFlags.Static | BindingFlags.NonPublic)!
            .GetRawConstantValue()!;
        var prelude = (string)type.GetMethod("BuildContextPrelude", BindingFlags.Static | BindingFlags.NonPublic)!
            .Invoke(null, null)!;

        Assert.Equal(4, maxDepth);
        Assert.Equal(32, maxContexts);
        Assert.Contains("contentDocument", prelude, StringComparison.Ordinal);
        Assert.Contains("contentWindow", prelude, StringComparison.Ordinal);
        Assert.Contains("contexts.length >= 32", prelude, StringComparison.Ordinal);
        Assert.Contains("depth >= 4", prelude, StringComparison.Ordinal);
        Assert.Contains("catch {}", prelude, StringComparison.Ordinal);
        Assert.DoesNotContain("postMessage", prelude, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EditorExpression_TraversesFramesAndSupportsCodeMirror6State()
    {
        var type = typeof(BrowserControlContract).Assembly
            .GetType("YowThi.DevelopmentAgent3.Browser.BrowserEditorBridge", throwOnError: true)!;
        var method = type.GetMethod("BuildEditorExpression", BindingFlags.Static | BindingFlags.NonPublic)!;
        var expression = (string)method.Invoke(null, new object?[] { null, null, false })!;

        Assert.Contains("const contexts = []", expression, StringComparison.Ordinal);
        Assert.Contains("contentDocument", expression, StringComparison.Ordinal);
        Assert.Contains("ctx.win.monaco", expression, StringComparison.Ordinal);
        Assert.Contains("cmView?.view", expression, StringComparison.Ordinal);
        Assert.Contains("kind: 'codemirror6'", expression, StringComparison.Ordinal);
        Assert.Contains("view.dispatch", expression, StringComparison.Ordinal);
        Assert.Contains("ownerDocument?.defaultView", expression, StringComparison.Ordinal);
        Assert.Contains("same-origin iframe", expression, StringComparison.Ordinal);
    }

    [Fact]
    public void EditorExpression_CodeMirror6WithoutStateBridgeFailsClosed()
    {
        var type = typeof(BrowserControlContract).Assembly
            .GetType("YowThi.DevelopmentAgent3.Browser.BrowserEditorBridge", throwOnError: true)!;
        var method = type.GetMethod("BuildEditorExpression", BindingFlags.Static | BindingFlags.NonPublic)!;
        var expression = (string)method.Invoke(null, new object?[] { ".cm-content", "replacement", true })!;

        Assert.Contains("CodeMirror 6 DOM was found but an exact editor-state bridge was unavailable", expression, StringComparison.Ordinal);
        Assert.Contains("el?.classList?.contains('cm-content')", expression, StringComparison.Ordinal);
    }
}
