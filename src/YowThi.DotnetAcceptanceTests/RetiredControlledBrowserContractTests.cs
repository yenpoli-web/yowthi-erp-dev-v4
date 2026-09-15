using Xunit;
using YowThi.DevelopmentAgent3.Runtime;

namespace YowThi.DotnetAcceptanceTests;

public sealed class RetiredControlledBrowserContractTests
{
    [Fact]
    public void AgentToolCatalog_DoesNotExposeRetiredControlledBrowserSurface()
    {
        var toolNames = ToolRegistryIdentity.Current.ToolNames;
        Assert.DoesNotContain(toolNames, name => name.StartsWith("browser_", StringComparison.Ordinal));
    }

    [Fact]
    public void AgentAssembly_DoesNotContainRetiredBrowserNamespace()
    {
        var assembly = typeof(ToolRegistryIdentity).Assembly;
        Assert.DoesNotContain(assembly.GetTypes(), type =>
            string.Equals(type.Namespace, "YowThi.DevelopmentAgent3.Browser", StringComparison.Ordinal) ||
            (type.Namespace?.StartsWith("YowThi.DevelopmentAgent3.Browser.", StringComparison.Ordinal) ?? false));
    }

    [Fact]
    public void AgentToolCatalog_RetainsGeneralInteractiveDesktopSurface()
    {
        var toolNames = ToolRegistryIdentity.Current.ToolNames.ToHashSet(StringComparer.Ordinal);

        Assert.Contains("desktop_screenshot_capture", toolNames);
        Assert.Contains("desktop_window_capture", toolNames);
        Assert.Contains("desktop_window_list", toolNames);
        Assert.Contains("desktop_foreground_window_get", toolNames);
        Assert.Contains("desktop_keyboard_shortcut_plan", toolNames);
        Assert.Contains("desktop_keyboard_shortcut_execute", toolNames);
        Assert.Contains("desktop_text_input_plan", toolNames);
        Assert.Contains("desktop_text_input_execute", toolNames);
        Assert.Contains("desktop_mouse_click_plan", toolNames);
        Assert.Contains("desktop_mouse_click_execute", toolNames);
    }
}
