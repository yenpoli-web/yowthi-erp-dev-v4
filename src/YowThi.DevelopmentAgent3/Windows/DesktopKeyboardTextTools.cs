using System.Collections.Concurrent;
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
public sealed class DesktopKeyboardTextTools
{
    private const int MaxTextChars = 8192;
    private const int MaxTextUtf8Bytes = 16384;
    private static readonly PlanSigner Signer = new(SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1")));
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly ConcurrentDictionary<string, TextPayload> Payloads = new(StringComparer.Ordinal);
    private sealed record TextPayload(string Text, string Sha256, int Chars, int Bytes, DateTimeOffset ExpiresUtc);

    [McpServerTool(Name = "desktop_keyboard_shortcut_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to emit exactly one allow-listed keyboard shortcut to the current foreground visible top-level window. Allowed: ctrl+a, ctrl+s, enter, tab, escape. The target window identity and geometry are sealed.")]
    public static SignedPlan DesktopKeyboardShortcutPlan(string hwnd, string shortcut)
    {
        var h = NormalizeHandle(hwnd); var s = NormalizeShortcut(shortcut); var w = RequireForeground(h);
        var p = WindowParameters(h, w); p["shortcut"] = s;
        return CreatePlan("keyboard-shortcut", $"{s}@{h}", p, $"Send {s} to foreground desktop window {h}");
    }

    [McpServerTool(Name = "desktop_keyboard_shortcut_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared desktop keyboard-shortcut plan after revalidating the sealed foreground window identity, then emit only the sealed allow-listed shortcut in Session 1 through native SendInput.")]
    public static ExecutionResult DesktopKeyboardShortcutExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode); RequireIntent(plan, "keyboard-shortcut", operation, target, summary, riskClass);
        var hwnd = Read(plan, "hwnd"); var shortcut = NormalizeShortcut(Read(plan, "shortcut")); RequireWindowMatch(plan, hwnd);
        try { InteractiveDesktopKeyboardBridge.KeyboardShortcut(hwnd, shortcut); Store.Consume(planId); var outcome = $"keyboard-shortcut-sent:{shortcut}@{hwnd}"; Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome }, "executed"); return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow); }
        catch (Exception ex) { Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed"); throw; }
    }

    [McpServerTool(Name = "desktop_text_input_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to type bounded Unicode text into the current foreground visible top-level window. Raw text remains only in expiring process memory; plans and audit records contain only hash and size metadata. Clipboard, shell, PowerShell, cmd, and filesystem staging are not used.")]
    public static SignedPlan DesktopTextInputPlan(string hwnd, string text)
    {
        var h = NormalizeHandle(hwnd); var t = ValidateText(text); var w = RequireForeground(h); var bytes = Encoding.UTF8.GetByteCount(t); var sha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(t)));
        var p = WindowParameters(h, w); p["textSha256"] = sha; p["charCount"] = t.Length.ToString(CultureInfo.InvariantCulture); p["utf8Bytes"] = bytes.ToString(CultureInfo.InvariantCulture);
        var plan = CreatePlan("text-input", h, p, $"Type bounded Unicode text into foreground desktop window {h} ({t.Length} chars, SHA-256 {sha[..12]})"); Payloads[plan.PlanId] = new(t, sha, t.Length, bytes, plan.ExpiresUtc); return plan;
    }

    [McpServerTool(Name = "desktop_text_input_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared desktop text-input plan after revalidating the sealed foreground window identity and expiring in-memory text payload, then emit Unicode keyboard input in Session 1 through native SendInput.")]
    public static ExecutionResult DesktopTextInputExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode); RequireIntent(plan, "text-input", operation, target, summary, riskClass); var hwnd = Read(plan, "hwnd"); RequireWindowMatch(plan, hwnd);
        if (!Payloads.TryGetValue(plan.PlanId, out var payload) || payload.ExpiresUtc < DateTimeOffset.UtcNow) { Payloads.TryRemove(plan.PlanId, out _); throw new InvalidOperationException("The sealed text payload is unavailable or expired."); }
        var sha = Read(plan, "textSha256"); if (!TryInt(plan, "charCount", out var chars) || !TryInt(plan, "utf8Bytes", out var bytes)) throw new InvalidDataException("Signed text metadata is invalid.");
        var currentSha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload.Text))); if (!string.Equals(payload.Sha256, sha, StringComparison.OrdinalIgnoreCase) || !string.Equals(currentSha, sha, StringComparison.OrdinalIgnoreCase) || payload.Chars != chars || payload.Bytes != bytes) throw new InvalidOperationException("The sealed text payload no longer matches the signed plan.");
        try { InteractiveDesktopKeyboardBridge.TextInput(hwnd, payload.Text); Store.Consume(planId); Payloads.TryRemove(plan.PlanId, out _); var outcome = $"text-input-sent:{chars}-chars@{hwnd}"; Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, textSha256 = sha, charCount = chars, utf8Bytes = bytes, outcome }, "executed"); return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow); }
        catch (Exception ex) { Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, textSha256 = sha, error = ex.Message }, "failed"); throw; }
    }

    private static SignedPlan CreatePlan(string operation, string target, IReadOnlyDictionary<string,string> parameters, string summary)
    {
        var now = DateTimeOffset.UtcNow; var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "desktop", operation, target, parameters, RiskClass.High, summary, now, now.AddMinutes(10), string.Empty); var signed = unsigned with { Signature = Signer.Sign(unsigned) }; Store.Add(signed); Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared"); return signed;
    }

    private static Dictionary<string,string> WindowParameters(string hwnd, InteractiveDesktopSessionBridge.WindowSnapshot w) => new(StringComparer.Ordinal) { ["hwnd"] = hwnd, ["processId"] = w.ProcessId.ToString(CultureInfo.InvariantCulture), ["processName"] = w.ProcessName, ["processStartTimeUtc"] = w.ProcessStartTimeUtc ?? string.Empty, ["title"] = w.Title, ["left"] = w.Bounds.Left.ToString(CultureInfo.InvariantCulture), ["top"] = w.Bounds.Top.ToString(CultureInfo.InvariantCulture), ["right"] = w.Bounds.Right.ToString(CultureInfo.InvariantCulture), ["bottom"] = w.Bounds.Bottom.ToString(CultureInfo.InvariantCulture) };
    private static InteractiveDesktopSessionBridge.WindowSnapshot RequireForeground(string hwnd) { var w = InteractiveDesktopSessionBridge.GetWindowSnapshot(hwnd); if (!w.Visible || w.Minimized || !w.Foreground) throw new InvalidOperationException("Target window must be visible, non-minimized, and currently foreground."); if (string.Equals(w.ProcessName, "ApplicationFrameHost", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("ApplicationFrameHost wrapper windows are not eligible keyboard/text targets."); return w; }
    private static void RequireWindowMatch(SignedPlan p, string hwnd) { var w = RequireForeground(hwnd); if (!TryUInt(p,"processId",out var pid) || !TryInt(p,"left",out var l) || !TryInt(p,"top",out var t) || !TryInt(p,"right",out var r) || !TryInt(p,"bottom",out var b)) throw new InvalidDataException("Signed window snapshot is invalid."); if (pid != w.ProcessId || !string.Equals(Read(p,"processName"),w.ProcessName,StringComparison.OrdinalIgnoreCase) || !string.Equals(Read(p,"processStartTimeUtc"),w.ProcessStartTimeUtc ?? string.Empty,StringComparison.Ordinal) || !string.Equals(Read(p,"title"),w.Title,StringComparison.Ordinal) || l != w.Bounds.Left || t != w.Bounds.Top || r != w.Bounds.Right || b != w.Bounds.Bottom) throw new InvalidOperationException("Target interactive window identity or geometry changed after plan preparation."); }
    private static void RequireIntent(SignedPlan p,string expected,string operation,string target,string summary,string riskClass) { if (!string.Equals(p.Tool,"desktop",StringComparison.Ordinal) || !string.Equals(p.Operation,expected,StringComparison.Ordinal) || !string.Equals(p.Operation,operation,StringComparison.Ordinal) || !string.Equals(p.Target,target,StringComparison.Ordinal) || !string.Equals(p.Summary,summary,StringComparison.Ordinal) || !string.Equals(p.RiskClass.ToString(),riskClass,StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException("Plan execution intent mismatch."); }
    private static string ValidateText(string text) { if (text is null) throw new ArgumentNullException(nameof(text)); if (text.Length == 0 || text.Length > MaxTextChars) throw new ArgumentOutOfRangeException(nameof(text), $"Text must contain 1-{MaxTextChars} UTF-16 code units."); if (text.IndexOf('\0') >= 0) throw new ArgumentException("Text may not contain NUL characters.", nameof(text)); if (Encoding.UTF8.GetByteCount(text) > MaxTextUtf8Bytes) throw new ArgumentOutOfRangeException(nameof(text), $"UTF-8 text may not exceed {MaxTextUtf8Bytes} bytes."); return text; }
    private static string NormalizeShortcut(string shortcut) { var v = (shortcut ?? string.Empty).Trim().ToLowerInvariant().Replace(" ", string.Empty, StringComparison.Ordinal); return v switch { "ctrl+a" => "ctrl+a", "ctrl+s" => "ctrl+s", "enter" => "enter", "tab" => "tab", "esc" or "escape" => "escape", _ => throw new ArgumentOutOfRangeException(nameof(shortcut), "Shortcut must be ctrl+a, ctrl+s, enter, tab, or escape.") }; }
    private static string NormalizeHandle(string hwnd) { if (string.IsNullOrWhiteSpace(hwnd)) throw new ArgumentException("HWND is required.", nameof(hwnd)); var s = hwnd.Trim(); if (s.StartsWith("0x",StringComparison.OrdinalIgnoreCase)) s=s[2..]; if (!ulong.TryParse(s,NumberStyles.AllowHexSpecifier,CultureInfo.InvariantCulture,out var v)) throw new ArgumentException("HWND must be hexadecimal.",nameof(hwnd)); return $"0x{v:X}"; }
    private static string Read(SignedPlan p,string key) => p.Parameters.TryGetValue(key,out var v) ? v : throw new InvalidDataException($"Signed {key} parameter is missing.");
    private static bool TryInt(SignedPlan p,string key,out int v) { v = default; return p.Parameters.TryGetValue(key,out var s) && int.TryParse(s,NumberStyles.Integer,CultureInfo.InvariantCulture,out v); }
    private static bool TryUInt(SignedPlan p,string key,out uint v) { v = default; return p.Parameters.TryGetValue(key,out var s) && uint.TryParse(s,NumberStyles.Integer,CultureInfo.InvariantCulture,out v); }
}
