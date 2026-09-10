using System.ComponentModel;
using ModelContextProtocol.Server;

namespace YowThi.DevelopmentAgent3.Windows;

[McpServerToolType]
public sealed class DesktopTools
{
    [McpServerTool(Name = "desktop_display_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List attached Windows desktop displays from the active interactive desktop session. A Session 0 Agent bridges to the active console session; this is read-only and does not change display, window, or input state.")]
    public static IReadOnlyList<DesktopDisplayItem> DesktopDisplayList()
        => InteractiveDesktopSessionBridge.GetDisplays();

    [McpServerTool(Name = "desktop_cursor_position_get", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read the current Windows desktop cursor position from the active interactive desktop session. A Session 0 Agent bridges to the active console session; this is read-only and does not move, click, press, or inject input.")]
    public static DesktopCursorPositionResult DesktopCursorPositionGet()
        => InteractiveDesktopSessionBridge.GetCursorPosition();

    [McpServerTool(Name = "desktop_window_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List visible top-level Windows desktop windows from the active interactive desktop session. A Session 0 Agent bridges to the active console session; this is read-only and does not activate, move, resize, close, minimize, maximize, capture, or send input.")]
    public static IReadOnlyList<DesktopWindowItem> DesktopWindowList()
        => InteractiveDesktopSessionBridge.GetWindows();

    [McpServerTool(Name = "desktop_foreground_window_get", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read the current foreground Windows desktop window from the active interactive desktop session. A Session 0 Agent bridges to the active console session; this is read-only and does not activate or modify any window or process.")]
    public static DesktopWindowItem? DesktopForegroundWindowGet()
        => InteractiveDesktopSessionBridge.GetForegroundWindowInfo();
}

public sealed record DesktopRectangle(
    int Left,
    int Top,
    int Right,
    int Bottom,
    int Width,
    int Height);

public sealed record DesktopDisplayItem(
    string MonitorHandle,
    string DeviceName,
    DesktopRectangle Bounds,
    DesktopRectangle WorkArea,
    bool Primary);

public sealed record DesktopCursorPositionResult(
    int X,
    int Y,
    string? MonitorHandle,
    string? DeviceName,
    DesktopRectangle? MonitorBounds,
    bool? PrimaryDisplay);

public sealed record DesktopWindowItem(
    string Hwnd,
    uint ProcessId,
    string ProcessName,
    string? ProcessPath,
    string? StartTimeUtc,
    string Title,
    DesktopRectangle Bounds,
    bool Visible,
    bool Minimized,
    bool Foreground);