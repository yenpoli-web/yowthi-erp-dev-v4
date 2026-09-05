using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Protocol;
using Xunit;
using YowThi.DevelopmentAgent3.Windows;

namespace YowThi.DotnetAcceptanceTests;

public sealed class InteractiveDesktopCaptureTests
{
    [Fact]
    [SupportedOSPlatform("windows")]
    public async Task LocalSystemCaptureBrokerReturnsInteractiveDesktopAndWindowPngs()
    {
        if (!OperatingSystem.IsWindows())
            return;

        using var identity = WindowsIdentity.GetCurrent();
        if (!identity.IsSystem)
            return;

        if (WTSGetActiveConsoleSessionId() == 0xFFFFFFFF)
            return;

        var desktop = await InteractiveDesktopCaptureTools.DesktopScreenshotCapture();
        AssertCapture(desktop, "desktop");

        var window = await InteractiveDesktopCaptureTools.DesktopWindowCapture();
        AssertCapture(window, "window");
    }

    private static void AssertCapture(IReadOnlyList<ContentBlock> blocks, string expectedKind)
    {
        Assert.Equal(2, blocks.Count);
        var metadataBlock = Assert.IsType<TextContentBlock>(blocks[0]);
        var imageBlock = Assert.IsType<ImageContentBlock>(blocks[1]);

        using var document = JsonDocument.Parse(metadataBlock.Text);
        var root = document.RootElement;
        Assert.Equal(expectedKind, root.GetProperty("Kind").GetString());
        Assert.True(root.GetProperty("Width").GetInt32() > 0);
        Assert.True(root.GetProperty("Height").GetInt32() > 0);
        Assert.True(root.GetProperty("SessionId").GetInt32() > 0);
        Assert.True(root.GetProperty("pngBytes").GetInt32() > 8);

        var encoded = Encoding.ASCII.GetString(imageBlock.Data.ToArray());
        var png = Convert.FromBase64String(encoded);
        Assert.True(png.Length > 8);
        Assert.Equal(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }, png[..8]);
    }

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();
}
