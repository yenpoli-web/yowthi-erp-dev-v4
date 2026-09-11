using System.Collections.Concurrent;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;
using YowThi.DevelopmentAgent3.Security;

namespace YowThi.DevelopmentAgent3.Browser;

public sealed record BrowserControlledSessionStatusResult(
    bool Active,
    bool FixedPortListening,
    string Endpoint,
    string? Browser,
    string? ProtocolVersion,
    string? UserAgent,
    bool ExistingOrdinaryChromeAttachSupported,
    string ProfilePolicy,
    string IsolationModel,
    DateTimeOffset CheckedUtc);

public sealed record BrowserControlledSessionStartResult(
    string PlanId,
    int LaunchProcessId,
    string Endpoint,
    string Browser,
    string ProtocolVersion,
    string ProfilePolicy,
    DateTimeOffset ExecutedUtc);

public sealed record BrowserTabMutationResult(
    string PlanId,
    string Operation,
    string? TabId,
    string? Url,
    bool Verified,
    DateTimeOffset ExecutedUtc);

public sealed record BrowserSavedStateWaitResult(
    string TabId,
    string Selector,
    string ExpectedTextSha256,
    bool Matched,
    string ObservedText,
    DateTimeOffset CheckedUtc);

public sealed record BrowserTextReplacement(
    string From,
    string To,
    int ExpectedMatchCount);

public sealed record BrowserEditorPatchExecutionResult(
    string PlanId,
    string TabId,
    string EditorKind,
    string? Selector,
    string BeforeSha256,
    string ExpectedAfterSha256,
    string ActualAfterSha256,
    bool Verified,
    DateTimeOffset ExecutedUtc);

public static class BrowserControlContract
{
    public const string Endpoint = BrowserCdpClient.Endpoint;
    public const string ProfilePolicy = "dedicated-active-user-LocalAppData/YowThi/BrowserControl/Profile; never clone or read the ordinary Chrome Cookies/History/Local State profile";
    public const string IsolationModel = "Agent-owned controlled Chrome only; ordinary Chrome without the fixed CDP endpoint is intentionally not attachable";

    public static IReadOnlyList<string> ControlledChromeArgumentsForValidation(string profilePath)
        => ControlledChromeLauncher.BuildArgumentsForContract(profilePath);
}

public static class BrowserExactPatchEngine
{
    public static string Apply(string input, IReadOnlyList<BrowserTextReplacement> replacements)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));
        if (replacements is null) throw new ArgumentNullException(nameof(replacements));
        if (replacements.Count is < 1 or > 32) throw new ArgumentOutOfRangeException(nameof(replacements), "Browser editor patch requires 1-32 replacements.");
        var current = input;
        foreach (var replacement in replacements)
        {
            if (replacement is null) throw new ArgumentException("Browser editor replacement may not be null.", nameof(replacements));
            if (string.IsNullOrEmpty(replacement.From)) throw new ArgumentException("Browser editor replacement 'from' may not be empty.", nameof(replacements));
            if (replacement.From.Length > 256 * 1024 || replacement.To.Length > 256 * 1024) throw new ArgumentOutOfRangeException(nameof(replacements), "Browser editor replacement strings may not exceed 256 KiB characters each.");
            if (replacement.From.IndexOf('\0') >= 0 || replacement.To.IndexOf('\0') >= 0) throw new ArgumentException("Browser editor replacements may not contain NUL.", nameof(replacements));
            var expected = BrowserCdpValidation.RequireExpectedMatchCount(replacement.ExpectedMatchCount);
            var actual = CountOccurrences(current, replacement.From);
            if (actual != expected) throw new InvalidOperationException($"Browser editor patch literal match count mismatch; expected={expected}, actual={actual}.");
            current = current.Replace(replacement.From, replacement.To, StringComparison.Ordinal);
        }
        if (string.Equals(current, input, StringComparison.Ordinal)) throw new InvalidOperationException("Browser editor patch would be a no-op.");
        if (Encoding.UTF8.GetByteCount(current) > 2 * 1024 * 1024) throw new InvalidOperationException("Browser editor patch output exceeds the 2 MiB UTF-8 limit.");
        return current;
    }

    public static string ComputeSpecificationHash(IReadOnlyList<BrowserTextReplacement> replacements)
    {
        if (replacements is null) throw new ArgumentNullException(nameof(replacements));
        var canonical = replacements.Select(x => new { fromSha256 = Sha(x.From), toSha256 = Sha(x.To), x.ExpectedMatchCount }).ToArray();
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(canonical)));
    }

    private static int CountOccurrences(string source, string value)
    {
        var count = 0;
        var index = 0;
        while (index <= source.Length - value.Length)
        {
            var found = source.IndexOf(value, index, StringComparison.Ordinal);
            if (found < 0) break;
            count++;
            index = found + value.Length;
        }
        return count;
    }

    private static string Sha(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value ?? string.Empty)));
}

[McpServerToolType]
public static class BrowserCdpTools
{
    private const int PlanLifetimeMinutes = 10;
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly ConcurrentDictionary<string, PendingEditorPatchPayload> EditorPayloads = new(StringComparer.Ordinal);

    [McpServerTool(Name = "browser_controlled_session_status", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read the fixed Agent-controlled Chrome CDP session status at 127.0.0.1:9223. Ordinary Chrome instances that were not launched with the fixed isolated CDP profile are intentionally not attachable. No browser profile files, cookies, history, Local State, or credentials are read.")]
    public static async Task<BrowserControlledSessionStatusResult> BrowserControlledSessionStatus(CancellationToken cancellationToken = default)
    {
        var version = await BrowserCdpClient.TryGetVersionAsync(cancellationToken);
        var listening = version is not null || await BrowserCdpClient.IsPortListeningAsync(cancellationToken);
        return new(
            version is not null,
            listening,
            BrowserControlContract.Endpoint,
            version?.Browser,
            version?.ProtocolVersion,
            version?.UserAgent,
            false,
            BrowserControlContract.ProfilePolicy,
            BrowserControlContract.IsolationModel,
            DateTimeOffset.UtcNow);
    }

    [McpServerTool(Name = "browser_controlled_session_start_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to launch a dedicated Google Chrome in the active interactive Windows session with a fixed loopback CDP endpoint and a dedicated active-user LocalAppData profile. The ordinary Chrome profile is never copied or read. Port, Chrome SHA-256, active session and isolated profile path are sealed. This plan does not launch Chrome.")]
    public static async Task<SignedPlan> BrowserControlledSessionStartPlan(CancellationToken cancellationToken = default)
    {
        if (await BrowserCdpClient.TryGetVersionAsync(cancellationToken) is not null || await BrowserCdpClient.IsPortListeningAsync(cancellationToken))
            throw new InvalidOperationException("Fixed controlled Chrome DevTools endpoint is already active or occupied.");
        var identity = ControlledChromeLauncher.ResolveIdentity();
        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["sessionId"] = identity.SessionId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["profilePath"] = identity.ProfilePath,
            ["chromeSha256"] = identity.ChromeSha256,
            ["endpoint"] = BrowserControlContract.Endpoint,
            ["profilePolicy"] = BrowserControlContract.ProfilePolicy
        };
        var summary = $"Launch isolated controlled Chrome in Session {identity.SessionId} at {BrowserControlContract.Endpoint} with Chrome {identity.ChromeSha256[..12]}";
        var signed = SignAndStore(new SignedPlan(1, planId, approvalCode, "browser", "controlled-session-start", BrowserControlContract.Endpoint, parameters, RiskClass.High, summary, now, now.AddMinutes(PlanLifetimeMinutes), string.Empty));
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, identity.SessionId, chromeSha256 = identity.ChromeSha256, profilePolicy = BrowserControlContract.ProfilePolicy }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "browser_controlled_session_start_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared controlled-Chrome start plan. Active Windows session, fixed Chrome executable SHA-256, isolated profile path and absence of any listener on 127.0.0.1:9223 are revalidated. Chrome is launched directly into Session 1 using CreateProcessAsUser; no ordinary Chrome profile data is copied. Only planId and approvalCode are accepted.")]
    public static async Task<BrowserControlledSessionStartResult> BrowserControlledSessionStartExecute(string planId, string approvalCode, CancellationToken cancellationToken = default)
    {
        var plan = RequirePlan(planId, approvalCode, "controlled-session-start");
        var expected = new ControlledChromeLaunchIdentity(
            uint.Parse(Require(plan, "sessionId"), System.Globalization.CultureInfo.InvariantCulture),
            Require(plan, "profilePath"),
            Require(plan, "chromeSha256"));
        try
        {
            var pid = await ControlledChromeLauncher.StartAsync(expected, cancellationToken);
            var version = await BrowserCdpClient.GetVersionAsync(cancellationToken);
            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, launchProcessId = pid, version.Browser, version.ProtocolVersion, profilePolicy = BrowserControlContract.ProfilePolicy }, "executed");
            return new(plan.PlanId, pid, BrowserControlContract.Endpoint, version.Browser, version.ProtocolVersion, BrowserControlContract.ProfilePolicy, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, errorType = ex.GetType().Name }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "browser_tab_list", ReadOnly = true, Destructive = false, OpenWorld = true)]
    [Description("List page tabs exposed by the fixed Agent-controlled Chrome CDP endpoint. This does not enumerate or attach ordinary Chrome windows without the fixed isolated CDP endpoint.")]
    public static async Task<IReadOnlyList<BrowserTabItem>> BrowserTabList(CancellationToken cancellationToken = default)
    {
        await RequireControlledSessionAsync(cancellationToken);
        var targets = await BrowserCdpClient.ListTargetsAsync(cancellationToken);
        return targets.Where(x => string.Equals(x.Type, "page", StringComparison.Ordinal))
            .Select(x => new BrowserTabItem(x.Id, x.Type, Bound(x.Title, 4096), Bound(x.Url, 8192), Bound(x.Description, 4096), true))
            .ToArray();
    }

    [McpServerTool(Name = "browser_tab_open_plan", ReadOnly = false, Destructive = false, OpenWorld = true)]
    [Description("Prepare a signed plan to open exactly one validated http/https URL or about:blank in a new tab of the fixed Agent-controlled Chrome session. Embedded URL credentials are rejected. This plan does not open a tab.")]
    public static async Task<SignedPlan> BrowserTabOpenPlan(string url, CancellationToken cancellationToken = default)
    {
        await RequireControlledSessionAsync(cancellationToken);
        url = BrowserCdpValidation.RequireNavigableUrl(url);
        return CreateMutationPlan("tab-open", url, new Dictionary<string, string> { ["url"] = url }, RiskClass.High, $"Open controlled Chrome tab to {Bound(url, 256)}");
    }

    [McpServerTool(Name = "browser_tab_open_execute", ReadOnly = false, Destructive = true, OpenWorld = true)]
    [Description("Execute one previously prepared controlled-Chrome tab-open plan after revalidating the fixed CDP session. Only the sealed URL can be opened. Only planId and approvalCode are accepted.")]
    public static async Task<BrowserTabMutationResult> BrowserTabOpenExecute(string planId, string approvalCode, CancellationToken cancellationToken = default)
    {
        var plan = RequirePlan(planId, approvalCode, "tab-open");
        await RequireControlledSessionAsync(cancellationToken);
        var url = BrowserCdpValidation.RequireNavigableUrl(Require(plan, "url"));
        var tab = await BrowserCdpClient.OpenTabAsync(url, cancellationToken);
        Store.Consume(planId);
        Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, tabId = tab.Id, url }, "executed");
        return new(plan.PlanId, plan.Operation, tab.Id, tab.Url, true, DateTimeOffset.UtcNow);
    }

    [McpServerTool(Name = "browser_tab_activate_plan", ReadOnly = false, Destructive = false, OpenWorld = true)]
    [Description("Prepare a signed plan to activate exactly one current page tab in the fixed Agent-controlled Chrome session. Target id and current URL fingerprint are sealed to mitigate stale-tab reuse.")]
    public static async Task<SignedPlan> BrowserTabActivatePlan(string tabId, CancellationToken cancellationToken = default)
        => await CreateTabTargetPlanAsync("tab-activate", tabId, null, cancellationToken);

    [McpServerTool(Name = "browser_tab_activate_execute", ReadOnly = false, Destructive = true, OpenWorld = true)]
    [Description("Execute one previously prepared controlled-Chrome tab activation after revalidating the exact page target id and sealed URL fingerprint. Only planId and approvalCode are accepted.")]
    public static Task<BrowserTabMutationResult> BrowserTabActivateExecute(string planId, string approvalCode, CancellationToken cancellationToken = default)
        => ExecuteTabTargetMutationAsync(planId, approvalCode, "tab-activate", BrowserCdpClient.ActivateTabAsync, cancellationToken);

    [McpServerTool(Name = "browser_tab_close_plan", ReadOnly = false, Destructive = false, OpenWorld = true)]
    [Description("Prepare a signed High-risk plan to close exactly one current page tab in the fixed Agent-controlled Chrome session. Target id and current URL fingerprint are sealed. This plan does not close the tab.")]
    public static async Task<SignedPlan> BrowserTabClosePlan(string tabId, CancellationToken cancellationToken = default)
        => await CreateTabTargetPlanAsync("tab-close", tabId, null, cancellationToken);

    [McpServerTool(Name = "browser_tab_close_execute", ReadOnly = false, Destructive = true, OpenWorld = true)]
    [Description("Execute one previously prepared controlled-Chrome tab-close plan after revalidating the exact page target id and sealed URL fingerprint. Only planId and approvalCode are accepted.")]
    public static Task<BrowserTabMutationResult> BrowserTabCloseExecute(string planId, string approvalCode, CancellationToken cancellationToken = default)
        => ExecuteTabTargetMutationAsync(planId, approvalCode, "tab-close", BrowserCdpClient.CloseTabAsync, cancellationToken);

    [McpServerTool(Name = "browser_navigate_plan", ReadOnly = false, Destructive = false, OpenWorld = true)]
    [Description("Prepare a signed High-risk plan to navigate one controlled Chrome page tab to exactly one validated http/https URL or about:blank. Current tab id/URL fingerprint and destination URL are sealed.")]
    public static async Task<SignedPlan> BrowserNavigatePlan(string tabId, string url, CancellationToken cancellationToken = default)
    {
        url = BrowserCdpValidation.RequireNavigableUrl(url);
        return await CreateTabTargetPlanAsync("navigate", tabId, url, cancellationToken);
    }

    [McpServerTool(Name = "browser_navigate_execute", ReadOnly = false, Destructive = true, OpenWorld = true)]
    [Description("Execute one previously prepared controlled-Chrome navigation after revalidating the exact tab and its sealed pre-navigation URL fingerprint. Only the sealed destination URL is used.")]
    public static async Task<BrowserTabMutationResult> BrowserNavigateExecute(string planId, string approvalCode, CancellationToken cancellationToken = default)
    {
        var plan = RequirePlan(planId, approvalCode, "navigate");
        var target = await RequireSealedTabAsync(plan, cancellationToken);
        var url = BrowserCdpValidation.RequireNavigableUrl(Require(plan, "destinationUrl"));
        await BrowserCdpClient.NavigateAsync(target.Id, url, cancellationToken);
        Store.Consume(planId);
        Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, tabId = target.Id, destinationUrl = url }, "executed");
        return new(plan.PlanId, plan.Operation, target.Id, url, true, DateTimeOffset.UtcNow);
    }

    [McpServerTool(Name = "browser_dom_query", ReadOnly = true, Destructive = false, OpenWorld = true)]
    [Description("Query a bounded CSS selector against one controlled Chrome page through CDP Runtime.evaluate. Only a fixed internal DOM projection is evaluated; callers cannot submit JavaScript. Password input values are never returned. Results are bounded by maxResults.")]
    public static async Task<BrowserDomQueryResult> BrowserDomQuery(string tabId, string selector, int maxResults = 20, CancellationToken cancellationToken = default)
    {
        await RequireControlledSessionAsync(cancellationToken);
        return await BrowserDomBridge.QueryAsync(tabId, selector, maxResults, cancellationToken);
    }

    [McpServerTool(Name = "browser_dom_click_plan", ReadOnly = false, Destructive = false, OpenWorld = true)]
    [Description("Prepare a signed High-risk DOM click plan for one controlled Chrome page. The CSS selector, exact expected match count, tab id and current tab URL fingerprint are sealed after a live count readback. Arbitrary JavaScript is not accepted.")]
    public static async Task<SignedPlan> BrowserDomClickPlan(string tabId, string selector, int expectedMatchCount = 1, CancellationToken cancellationToken = default)
    {
        selector = BrowserCdpValidation.RequireSelector(selector);
        expectedMatchCount = BrowserCdpValidation.RequireExpectedMatchCount(expectedMatchCount);
        var target = await BrowserCdpClient.RequirePageTargetAsync(tabId, cancellationToken);
        var actual = await BrowserDomBridge.CountAsync(target.Id, selector, cancellationToken);
        if (actual != expectedMatchCount) throw new InvalidOperationException($"DOM click plan match count mismatch; expected={expectedMatchCount}, actual={actual}.");
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["tabId"] = target.Id,
            ["tabFingerprint"] = TabFingerprint(target),
            ["selector"] = selector,
            ["expectedMatchCount"] = expectedMatchCount.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };
        return CreateMutationPlan("dom-click", target.Id, parameters, RiskClass.High, $"Click controlled Chrome DOM selector hash {Sha(selector)[..12]} with expectedMatchCount={expectedMatchCount}");
    }

    [McpServerTool(Name = "browser_dom_click_execute", ReadOnly = false, Destructive = true, OpenWorld = true)]
    [Description("Execute one previously prepared DOM click after revalidating the sealed tab URL fingerprint and exact selector match count. The first matched element is scrolled into view and clicked through a fixed internal DOM action; arbitrary JavaScript is not accepted.")]
    public static async Task<BrowserTabMutationResult> BrowserDomClickExecute(string planId, string approvalCode, CancellationToken cancellationToken = default)
    {
        var plan = RequirePlan(planId, approvalCode, "dom-click");
        var target = await RequireSealedTabAsync(plan, cancellationToken);
        var selector = BrowserCdpValidation.RequireSelector(Require(plan, "selector"));
        var expected = int.Parse(Require(plan, "expectedMatchCount"), System.Globalization.CultureInfo.InvariantCulture);
        await BrowserDomBridge.ClickAsync(target.Id, selector, expected, cancellationToken);
        Store.Consume(planId);
        Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, tabId = target.Id, selectorSha256 = Sha(selector), expectedMatchCount = expected }, "executed");
        return new(plan.PlanId, plan.Operation, target.Id, target.Url, true, DateTimeOffset.UtcNow);
    }

    [McpServerTool(Name = "browser_editor_get_text", ReadOnly = true, Destructive = false, OpenWorld = true)]
    [Description("Read text from a supported editor model in one controlled Chrome page without coordinate or keyboard input. Supported first-version models: Monaco when exposed through global monaco, CodeMirror 5, textarea/text input, and contenteditable. Returns exact text plus SHA-256 for later compare-and-swap patching.")]
    public static async Task<BrowserEditorSnapshot> BrowserEditorGetText(string tabId, string? selector = null, CancellationToken cancellationToken = default)
    {
        await RequireControlledSessionAsync(cancellationToken);
        return await BrowserEditorBridge.GetAsync(tabId, selector, cancellationToken);
    }

    [McpServerTool(Name = "browser_editor_get_diagnostics", ReadOnly = true, Destructive = false, OpenWorld = true)]
    [Description("Read bounded editor diagnostics from a controlled Chrome page. When Monaco markers are exposed they are returned structurally; visible DOM alert/error/diagnostic text is also collected. No arbitrary JavaScript is accepted and no page state is mutated.")]
    public static async Task<BrowserEditorDiagnosticsResult> BrowserEditorGetDiagnostics(string tabId, CancellationToken cancellationToken = default)
    {
        await RequireControlledSessionAsync(cancellationToken);
        return await BrowserEditorBridge.GetDiagnosticsAsync(tabId, cancellationToken);
    }

    [McpServerTool(Name = "browser_editor_replace_exact_plan", ReadOnly = false, Destructive = false, OpenWorld = true)]
    [Description("Prepare a signed High-risk compare-and-swap editor patch in one controlled Chrome tab. Live editor text must match expectedTextSha256; each literal replacement has an exact expectedMatchCount. Resulting editor text is retained only in expiring Agent memory; signed plan/audit contain hashes/counts only. No keyboard SendInput, clipboard, or arbitrary JavaScript is accepted.")]
    public static async Task<SignedPlan> BrowserEditorReplaceExactPlan(
        string tabId,
        string expectedTextSha256,
        IReadOnlyList<BrowserTextReplacement> replacements,
        string? selector = null,
        CancellationToken cancellationToken = default)
    {
        SweepEditorPayloads();
        expectedTextSha256 = BrowserCdpValidation.RequireExpectedHash(expectedTextSha256, nameof(expectedTextSha256));
        var target = await BrowserCdpClient.RequirePageTargetAsync(tabId, cancellationToken);
        var snapshot = await BrowserEditorBridge.GetAsync(target.Id, selector, cancellationToken);
        if (!string.Equals(snapshot.TextSha256, expectedTextSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Editor SHA-256 mismatch; patch plan not created. expected={expectedTextSha256}, actual={snapshot.TextSha256}");
        var resultText = BrowserExactPatchEngine.Apply(snapshot.Text, replacements);
        var resultHash = Sha(resultText);
        var specificationHash = BrowserExactPatchEngine.ComputeSpecificationHash(replacements);
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["tabId"] = target.Id,
            ["tabFingerprint"] = TabFingerprint(target),
            ["editorKind"] = snapshot.EditorKind,
            ["selector"] = snapshot.Selector ?? string.Empty,
            ["expectedTextSha256"] = expectedTextSha256,
            ["resultTextSha256"] = resultHash,
            ["patchSpecificationSha256"] = specificationHash,
            ["patchCount"] = replacements.Count.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };
        var plan = CreateMutationPlan("editor-replace-exact", target.Id, parameters, RiskClass.High, $"Patch controlled browser editor {snapshot.EditorKind} from {expectedTextSha256[..12]} to {resultHash[..12]} using {replacements.Count} exact replacement(s)");
        if (!EditorPayloads.TryAdd(plan.PlanId, new PendingEditorPatchPayload(plan.ExpiresUtc, target.Id, TabFingerprint(target), snapshot.EditorKind, snapshot.Selector, expectedTextSha256, resultHash, resultText)))
            throw new InvalidOperationException("Browser editor patch payload already exists.");
        Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, tabId = target.Id, editorKind = snapshot.EditorKind, expectedTextSha256, resultTextSha256 = resultHash, patchSpecificationSha256 = specificationHash, patchCount = replacements.Count }, "prepared");
        return plan;
    }

    [McpServerTool(Name = "browser_editor_replace_exact_execute", ReadOnly = false, Destructive = true, OpenWorld = true)]
    [Description("Execute one previously prepared controlled-browser editor patch. Tab URL fingerprint, editor model kind and current editor SHA-256 are re-read immediately before mutation. The sealed result text is set through the editor model/DOM API and immediately re-read to prove the expected result SHA-256. A mutation attempt consumes the plan to prevent blind replay.")]
    public static async Task<BrowserEditorPatchExecutionResult> BrowserEditorReplaceExactExecute(string planId, string approvalCode, CancellationToken cancellationToken = default)
    {
        SweepEditorPayloads();
        var plan = RequirePlan(planId, approvalCode, "editor-replace-exact");
        if (!EditorPayloads.TryGetValue(planId, out var payload) || payload.ExpiresUtc <= DateTimeOffset.UtcNow)
            throw new InvalidOperationException("Browser editor patch payload expired or is unavailable.");
        var target = await RequireSealedTabAsync(plan, cancellationToken);
        if (!string.Equals(payload.TabId, target.Id, StringComparison.Ordinal) || !string.Equals(payload.TabFingerprint, TabFingerprint(target), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Browser editor patch payload does not match the sealed tab.");
        var before = await BrowserEditorBridge.GetAsync(target.Id, payload.Selector, cancellationToken);
        if (!string.Equals(before.EditorKind, payload.EditorKind, StringComparison.Ordinal) || !string.Equals(before.TextSha256, payload.ExpectedHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Browser editor changed after plan creation; mutation aborted. expectedKind={payload.EditorKind}, actualKind={before.EditorKind}, expectedHash={payload.ExpectedHash}, actualHash={before.TextSha256}");

        var mutationAttempted = false;
        try
        {
            mutationAttempted = true;
            var after = await BrowserEditorBridge.SetAsync(target.Id, payload.Selector, payload.ResultText, cancellationToken);
            Store.Consume(planId);
            EditorPayloads.TryRemove(planId, out _);
            if (!string.Equals(after.EditorKind, payload.EditorKind, StringComparison.Ordinal) || !string.Equals(after.TextSha256, payload.ResultHash, StringComparison.OrdinalIgnoreCase))
            {
                Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, stage = "post-editor-readback", expectedAfterHash = payload.ResultHash, actualAfterHash = after.TextSha256, expectedKind = payload.EditorKind, actualKind = after.EditorKind }, "failed");
                throw new InvalidOperationException($"Browser editor post-mutation verification failed; plan consumed. expected={payload.ResultHash}, actual={after.TextSha256}");
            }
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, tabId = target.Id, editorKind = after.EditorKind, beforeSha256 = payload.ExpectedHash, afterSha256 = after.TextSha256, verified = true }, "executed");
            return new(plan.PlanId, target.Id, after.EditorKind, payload.Selector, payload.ExpectedHash, payload.ResultHash, after.TextSha256, true, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            if (mutationAttempted)
            {
                try { Store.Consume(planId); } catch { }
                EditorPayloads.TryRemove(planId, out _);
            }
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, errorType = ex.GetType().Name, mutationAttempted }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "browser_wait_for_saved_state", ReadOnly = true, Destructive = false, OpenWorld = true)]
    [Description("Poll one bounded CSS selector in a controlled Chrome tab until its visible text contains the expected saved-state text or the timeout expires. This is read-only and intended for UI saved/saving indicators; no click, navigation, keyboard input or arbitrary JavaScript is accepted.")]
    public static async Task<BrowserSavedStateWaitResult> BrowserWaitForSavedState(string tabId, string selector, string expectedText, int timeoutSeconds = 15, CancellationToken cancellationToken = default)
    {
        await RequireControlledSessionAsync(cancellationToken);
        selector = BrowserCdpValidation.RequireSelector(selector);
        var (matched, observed) = await BrowserEditorBridge.WaitForTextAsync(tabId, selector, expectedText, timeoutSeconds, cancellationToken);
        return new(BrowserCdpValidation.RequireTabId(tabId), selector, Sha(expectedText), matched, Bound(observed, 4096), DateTimeOffset.UtcNow);
    }

    private static async Task<SignedPlan> CreateTabTargetPlanAsync(string operation, string tabId, string? destinationUrl, CancellationToken cancellationToken)
    {
        await RequireControlledSessionAsync(cancellationToken);
        var target = await BrowserCdpClient.RequirePageTargetAsync(tabId, cancellationToken);
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["tabId"] = target.Id,
            ["tabFingerprint"] = TabFingerprint(target)
        };
        if (destinationUrl is not null) parameters["destinationUrl"] = BrowserCdpValidation.RequireNavigableUrl(destinationUrl);
        var summary = operation == "navigate"
            ? $"Navigate controlled Chrome tab {target.Id} from URL hash {Sha(target.Url)[..12]} to {Bound(parameters["destinationUrl"], 256)}"
            : $"{operation} controlled Chrome tab {target.Id} at URL hash {Sha(target.Url)[..12]}";
        return CreateMutationPlan(operation, target.Id, parameters, RiskClass.High, summary);
    }

    private static async Task<BrowserTabMutationResult> ExecuteTabTargetMutationAsync(string planId, string approvalCode, string operation, Func<string, CancellationToken, Task> action, CancellationToken cancellationToken)
    {
        var plan = RequirePlan(planId, approvalCode, operation);
        var target = await RequireSealedTabAsync(plan, cancellationToken);
        await action(target.Id, cancellationToken);
        Store.Consume(planId);
        Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, tabId = target.Id, urlHash = Sha(target.Url) }, "executed");
        return new(plan.PlanId, plan.Operation, target.Id, target.Url, true, DateTimeOffset.UtcNow);
    }

    private static async Task<BrowserCdpTarget> RequireSealedTabAsync(SignedPlan plan, CancellationToken cancellationToken)
    {
        await RequireControlledSessionAsync(cancellationToken);
        var tabId = BrowserCdpValidation.RequireTabId(Require(plan, "tabId"));
        var target = await BrowserCdpClient.RequirePageTargetAsync(tabId, cancellationToken);
        var expected = Require(plan, "tabFingerprint");
        var actual = TabFingerprint(target);
        if (!string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Controlled Chrome tab URL changed after plan creation; mutation aborted.");
        return target;
    }

    private static async Task RequireControlledSessionAsync(CancellationToken cancellationToken)
    {
        var version = await BrowserCdpClient.TryGetVersionAsync(cancellationToken);
        if (version is null) throw new InvalidOperationException("Agent-controlled Chrome CDP session is not active on the fixed loopback endpoint.");
    }

    private static SignedPlan CreateMutationPlan(string operation, string target, IReadOnlyDictionary<string, string> parameters, RiskClass riskClass, string summary)
    {
        var now = DateTimeOffset.UtcNow;
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "browser", operation, target, new Dictionary<string, string>(parameters, StringComparer.Ordinal), riskClass, summary, now, now.AddMinutes(PlanLifetimeMinutes), string.Empty);
        var signed = SignAndStore(unsigned);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    private static SignedPlan SignAndStore(SignedPlan unsigned)
    {
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        return signed;
    }

    private static SignedPlan RequirePlan(string planId, string approvalCode, string operation)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        if (!string.Equals(plan.Tool, "browser", StringComparison.Ordinal) || !string.Equals(plan.Operation, operation, StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Browser plan intent mismatch.");
        return plan;
    }

    private static string Require(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value)
            ? value
            : throw new InvalidDataException($"Signed browser parameter {key} is required.");

    private static string TabFingerprint(BrowserCdpTarget target)
        => Sha(target.Id + "\n" + target.Url);

    private static string Sha(string value)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value ?? string.Empty)));

    private static string Bound(string value, int max)
        => (value ?? string.Empty).Length <= max ? value ?? string.Empty : (value ?? string.Empty)[..max];

    private static void SweepEditorPayloads()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var pair in EditorPayloads)
            if (pair.Value.ExpiresUtc <= now) EditorPayloads.TryRemove(pair.Key, out _);
    }

    private sealed record PendingEditorPatchPayload(
        DateTimeOffset ExpiresUtc,
        string TabId,
        string TabFingerprint,
        string EditorKind,
        string? Selector,
        string ExpectedHash,
        string ResultHash,
        string ResultText);
}
