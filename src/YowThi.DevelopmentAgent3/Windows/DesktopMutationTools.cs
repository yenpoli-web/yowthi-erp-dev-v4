using System.ComponentModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;
using YowThi.DevelopmentAgent3.Security;

namespace YowThi.DevelopmentAgent3.Windows;

[McpServerToolType]
public sealed class DesktopMutationTools
{
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name = "desktop_cursor_move_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to move the Windows desktop cursor to one absolute screen coordinate in the active interactive session. The coordinate must lie on an attached interactive monitor and the monitor bounds are sealed into the plan. This does not move the cursor until desktop_cursor_move_execute is called.")]
    public static SignedPlan DesktopCursorMovePlan(int x, int y)
    {
        var monitor = RequireMonitorAtPoint(x, y);
        var now = DateTimeOffset.UtcNow;
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["x"] = x.ToString(CultureInfo.InvariantCulture),
            ["y"] = y.ToString(CultureInfo.InvariantCulture),
            ["monitorHandle"] = monitor.Handle,
            ["monitorLeft"] = monitor.Bounds.Left.ToString(CultureInfo.InvariantCulture),
            ["monitorTop"] = monitor.Bounds.Top.ToString(CultureInfo.InvariantCulture),
            ["monitorRight"] = monitor.Bounds.Right.ToString(CultureInfo.InvariantCulture),
            ["monitorBottom"] = monitor.Bounds.Bottom.ToString(CultureInfo.InvariantCulture)
        };
        return CreatePlan("desktop", "cursor-move", $"{x},{y}", parameters, RiskClass.High, $"Move desktop cursor to ({x},{y})", now);
    }

    [McpServerTool(Name = "desktop_cursor_move_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared desktop/cursor-move plan in the active interactive Windows session. The signed coordinate and monitor snapshot are revalidated immediately before the Session 1 helper performs the cursor move.")]
    public static ExecutionResult DesktopCursorMoveExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "cursor-move", operation, target, summary, riskClass);
        var (x, y) = ReadPoint(plan);
        RequireMonitorSnapshot(plan, x, y);
        try
        {
            InteractiveDesktopSessionBridge.MoveCursor(x, y);
            Store.Consume(planId);
            var outcome = $"cursor-moved:{x},{y}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome }, "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "desktop_mouse_click_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan for one single mouse click in the active interactive Windows session. Button is restricted to left, right, or middle. Double-click, drag, hold, wheel, and arbitrary input sequences are not supported.")]
    public static SignedPlan DesktopMouseClickPlan(int x, int y, string button)
    {
        var normalizedButton = NormalizeButton(button);
        var monitor = RequireMonitorAtPoint(x, y);
        var now = DateTimeOffset.UtcNow;
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["x"] = x.ToString(CultureInfo.InvariantCulture),
            ["y"] = y.ToString(CultureInfo.InvariantCulture),
            ["button"] = normalizedButton,
            ["monitorHandle"] = monitor.Handle,
            ["monitorLeft"] = monitor.Bounds.Left.ToString(CultureInfo.InvariantCulture),
            ["monitorTop"] = monitor.Bounds.Top.ToString(CultureInfo.InvariantCulture),
            ["monitorRight"] = monitor.Bounds.Right.ToString(CultureInfo.InvariantCulture),
            ["monitorBottom"] = monitor.Bounds.Bottom.ToString(CultureInfo.InvariantCulture)
        };
        return CreatePlan("desktop", "mouse-click", $"{normalizedButton}@{x},{y}", parameters, RiskClass.High, $"Single {normalizedButton} mouse click at ({x},{y})", now);
    }

    [McpServerTool(Name = "desktop_mouse_click_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared desktop/mouse-click plan in the active interactive Windows session. Coordinate, monitor snapshot, and button are revalidated before the Session 1 helper performs exactly one click.")]
    public static ExecutionResult DesktopMouseClickExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "mouse-click", operation, target, summary, riskClass);
        var (x, y) = ReadPoint(plan);
        RequireMonitorSnapshot(plan, x, y);
        if (!plan.Parameters.TryGetValue("button", out var button))
            throw new InvalidDataException("button parameter is required.");
        button = NormalizeButton(button);
        try
        {
            InteractiveDesktopSessionBridge.MouseClick(x, y, button);
            Store.Consume(planId);
            var outcome = $"mouse-clicked:{button}@{x},{y}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome }, "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "desktop_window_activate_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to activate one visible top-level window in the active interactive Windows session by HWND. Process identity, start time, title, bounds, visibility, and minimized state are sealed to mitigate HWND reuse and time-of-check/time-of-use changes.")]
    public static SignedPlan DesktopWindowActivatePlan(string hwnd)
    {
        var normalizedHwnd = NormalizeHandle(hwnd);
        var snapshot = RequireWindowSnapshot(normalizedHwnd);
        if (!snapshot.Visible)
            throw new InvalidOperationException("Target window must be visible.");
        if (string.Equals(snapshot.ProcessName, "ApplicationFrameHost", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("ApplicationFrameHost wrapper windows are not eligible activation targets; target the underlying application window instead.");

        var now = DateTimeOffset.UtcNow;
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["hwnd"] = normalizedHwnd,
            ["processId"] = snapshot.ProcessId.ToString(CultureInfo.InvariantCulture),
            ["processName"] = snapshot.ProcessName,
            ["processStartTimeUtc"] = snapshot.ProcessStartTimeUtc ?? string.Empty,
            ["title"] = snapshot.Title,
            ["left"] = snapshot.Bounds.Left.ToString(CultureInfo.InvariantCulture),
            ["top"] = snapshot.Bounds.Top.ToString(CultureInfo.InvariantCulture),
            ["right"] = snapshot.Bounds.Right.ToString(CultureInfo.InvariantCulture),
            ["bottom"] = snapshot.Bounds.Bottom.ToString(CultureInfo.InvariantCulture),
            ["visible"] = snapshot.Visible ? "true" : "false",
            ["minimized"] = snapshot.Minimized ? "true" : "false"
        };
        return CreatePlan("desktop", "window-activate", normalizedHwnd, parameters, RiskClass.High, $"Activate desktop window {normalizedHwnd} ({snapshot.Title})", now);
    }

    [McpServerTool(Name = "desktop_window_activate_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared desktop/window-activate plan in the active interactive Windows session. The signed window identity and state are revalidated before the Session 1 helper performs activation. Only the fixed ALT unlock fallback inside the helper is permitted.")]
    public static ExecutionResult DesktopWindowActivateExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "window-activate", operation, target, summary, riskClass);
        if (!plan.Parameters.TryGetValue("hwnd", out var hwnd))
            throw new InvalidDataException("hwnd parameter is required.");
        hwnd = NormalizeHandle(hwnd);
        RequireWindowSnapshotMatch(plan, hwnd);
        try
        {
            InteractiveDesktopSessionBridge.ActivateWindow(hwnd);
            Store.Consume(planId);
            var outcome = $"window-activated:{hwnd}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome }, "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    private static SignedPlan CreatePlan(string tool, string operation, string target, IReadOnlyDictionary<string, string> parameters, RiskClass riskClass, string summary, DateTimeOffset now)
    {
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), tool, operation, target, parameters, riskClass, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    private static void RequireIntentMatch(SignedPlan plan, string expectedOperation, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "desktop", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.Ordinal) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }

    private static (int X, int Y) ReadPoint(SignedPlan plan)
    {
        if (!plan.Parameters.TryGetValue("x", out var xText) || !int.TryParse(xText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var x) ||
            !plan.Parameters.TryGetValue("y", out var yText) || !int.TryParse(yText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var y))
            throw new InvalidDataException("Signed x/y parameters are invalid.");
        return (x, y);
    }

    private static InteractiveDesktopSessionBridge.MonitorSnapshot RequireMonitorAtPoint(int x, int y)
        => InteractiveDesktopSessionBridge.GetMonitorAtPoint(x, y);

    private static void RequireMonitorSnapshot(SignedPlan plan, int x, int y)
    {
        var current = RequireMonitorAtPoint(x, y);
        if (!plan.Parameters.TryGetValue("monitorHandle", out var handle) ||
            !TryReadInt(plan, "monitorLeft", out var left) ||
            !TryReadInt(plan, "monitorTop", out var top) ||
            !TryReadInt(plan, "monitorRight", out var right) ||
            !TryReadInt(plan, "monitorBottom", out var bottom))
            throw new InvalidDataException("Signed monitor snapshot is invalid.");
        if (!string.Equals(handle, current.Handle, StringComparison.OrdinalIgnoreCase) ||
            left != current.Bounds.Left || top != current.Bounds.Top || right != current.Bounds.Right || bottom != current.Bounds.Bottom)
            throw new InvalidOperationException("Interactive desktop monitor topology changed after plan preparation.");
    }

    private static InteractiveDesktopSessionBridge.WindowSnapshot RequireWindowSnapshot(string hwnd)
        => InteractiveDesktopSessionBridge.GetWindowSnapshot(hwnd);

    private static void RequireWindowSnapshotMatch(SignedPlan plan, string hwnd)
    {
        var current = RequireWindowSnapshot(hwnd);
        if (!TryReadUInt(plan, "processId", out var processId) ||
            !TryReadInt(plan, "left", out var left) || !TryReadInt(plan, "top", out var top) ||
            !TryReadInt(plan, "right", out var right) || !TryReadInt(plan, "bottom", out var bottom) ||
            !plan.Parameters.TryGetValue("processName", out var processName) ||
            !plan.Parameters.TryGetValue("processStartTimeUtc", out var processStartTimeUtc) ||
            !plan.Parameters.TryGetValue("title", out var title) ||
            !plan.Parameters.TryGetValue("visible", out var visibleText) ||
            !plan.Parameters.TryGetValue("minimized", out var minimizedText))
            throw new InvalidDataException("Signed window snapshot is invalid.");

        var visible = string.Equals(visibleText, "true", StringComparison.OrdinalIgnoreCase);
        var minimized = string.Equals(minimizedText, "true", StringComparison.OrdinalIgnoreCase);
        if (processId != current.ProcessId ||
            !string.Equals(processName, current.ProcessName, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(processStartTimeUtc, current.ProcessStartTimeUtc ?? string.Empty, StringComparison.Ordinal) ||
            !string.Equals(title, current.Title, StringComparison.Ordinal) ||
            left != current.Bounds.Left || top != current.Bounds.Top || right != current.Bounds.Right || bottom != current.Bounds.Bottom ||
            visible != current.Visible || minimized != current.Minimized)
            throw new InvalidOperationException("Target interactive window identity or state changed after plan preparation.");
    }

    private static string NormalizeButton(string button)
    {
        var value = (button ?? string.Empty).Trim().ToLowerInvariant();
        return value is "left" or "right" or "middle" ? value : throw new ArgumentOutOfRangeException(nameof(button), "Button must be left, right, or middle.");
    }

    private static string NormalizeHandle(string hwnd)
    {
        if (string.IsNullOrWhiteSpace(hwnd)) throw new ArgumentException("HWND is required.", nameof(hwnd));
        var text = hwnd.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) text = text[2..];
        if (!ulong.TryParse(text, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var value))
            throw new ArgumentException("HWND must be a hexadecimal handle such as 0x123ABC.", nameof(hwnd));
        return $"0x{value:X}";
    }

    private static bool TryReadInt(SignedPlan plan, string key, out int value)
    {
        value = default;
        return plan.Parameters.TryGetValue(key, out var text) && int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    private static bool TryReadUInt(SignedPlan plan, string key, out uint value)
    {
        value = default;
        return plan.Parameters.TryGetValue(key, out var text) && uint.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }
}