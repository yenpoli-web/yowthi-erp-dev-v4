using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.AgentLifecycle;

[McpServerToolType]
public static class AgentLifecycleStaleRequestCleanupTools
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string PendingRoot = @"C:\Dev\YowThi-ERP-Dev-v4\.agent3-lifecycle\pending";
    private const string RuntimeFileName = "YowThi.DevelopmentAgent3.dll";
    private const long MaxRequestBytes = 128 * 1024;

    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name = "agent_lifecycle_stale_request_cleanup_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed Medium-risk plan to delete exactly one stale immutable Agent lifecycle request from the fixed pending queue. The caller supplies only the request file leaf name. The request must be a valid request-only lifecycle transition whose current runtime SHA-256 is no longer the executing runtime; eligibility is limited to completed requests whose target is current or superseded requests whose current and target are both non-current. Request bytes/SHA-256, lifecycle identities, fixed queue identity, and stale classification are sealed. Active requests, arbitrary paths, directories, shell execution, process changes, and production paths are not supported.")]
    public static Task<SignedPlan> AgentLifecycleStaleRequestCleanupPlan(string requestFileName)
    {
        ValidatePendingRoot();
        var snapshot = ReadEligibleRequest(requestFileName);
        var currentRuntimeSha = GetCurrentRuntimeSha256();
        var classification = Classify(snapshot, currentRuntimeSha);
        if (classification == "active-current")
            throw new InvalidOperationException("Lifecycle request still references the currently executing runtime as its current package and is not eligible for stale cleanup.");

        var now = DateTimeOffset.UtcNow;
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["requestFileName"] = snapshot.FileName,
            ["requestPath"] = snapshot.Path,
            ["requestBytes"] = snapshot.Bytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["requestSha256"] = snapshot.Sha256,
            ["requestPlanId"] = snapshot.PlanId,
            ["requestedAction"] = snapshot.RequestedAction,
            ["requestCurrentRuntimeSha256"] = snapshot.CurrentRuntimeSha256,
            ["requestTargetRuntimeSha256"] = snapshot.TargetRuntimeSha256,
            ["currentRuntimeSha256"] = currentRuntimeSha,
            ["classification"] = classification
        };
        var summary = $"Delete one verified {classification} immutable Agent lifecycle request {snapshot.FileName} from the fixed pending queue";
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)),
            "agent-lifecycle-stale-request-cleanup", "delete-stale-request", snapshot.Path, parameters,
            RiskClass.Medium, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary, classification }, "prepared");
        return Task.FromResult(signed);
    }

    [McpServerTool(Name = "agent_lifecycle_stale_request_cleanup_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared fixed lifecycle stale-request cleanup plan using only native .NET File.Delete. The fixed pending queue, request leaf/path, request bytes/SHA-256/schema, request-only scope, current/target runtime SHA-256 values, current executing runtime SHA-256, and stale classification are revalidated immediately before deletion. A request whose current runtime is still executing is rejected. Post-delete read-back proves exact request absence. No arbitrary path, directory, shell, process mutation, or production mutation is supported.")]
    public static Task<AgentLifecycleStaleRequestCleanupResult> AgentLifecycleStaleRequestCleanupExecute(string planId, string approvalCode)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        if (!string.Equals(plan.Tool, "agent-lifecycle-stale-request-cleanup", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, "delete-stale-request", StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Lifecycle stale-request cleanup plan intent mismatch.");

        ValidatePendingRoot();
        var snapshot = ReadEligibleRequest(Require(plan, "requestFileName"));
        if (!string.Equals(snapshot.Path, plan.Target, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(snapshot.Path, Require(plan, "requestPath"), StringComparison.OrdinalIgnoreCase) ||
            snapshot.Bytes != ParseLong(Require(plan, "requestBytes")) ||
            !string.Equals(snapshot.Sha256, Require(plan, "requestSha256"), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(snapshot.PlanId, Require(plan, "requestPlanId"), StringComparison.Ordinal) ||
            !string.Equals(snapshot.RequestedAction, Require(plan, "requestedAction"), StringComparison.Ordinal) ||
            !string.Equals(snapshot.CurrentRuntimeSha256, Require(plan, "requestCurrentRuntimeSha256"), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(snapshot.TargetRuntimeSha256, Require(plan, "requestTargetRuntimeSha256"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Lifecycle request changed after cleanup plan preparation.");

        var currentRuntimeSha = GetCurrentRuntimeSha256();
        if (!string.Equals(currentRuntimeSha, Require(plan, "currentRuntimeSha256"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Executing Agent runtime changed after cleanup plan preparation.");
        var classification = Classify(snapshot, currentRuntimeSha);
        if (classification == "active-current" || !string.Equals(classification, Require(plan, "classification"), StringComparison.Ordinal))
            throw new InvalidOperationException("Lifecycle request is no longer eligible for stale cleanup.");

        File.Delete(snapshot.Path);
        if (File.Exists(snapshot.Path) || Directory.Exists(snapshot.Path))
            throw new IOException("Lifecycle stale request still exists after deletion.");

        Store.Consume(planId);
        Audit.Append(plan.Tool, plan.Operation, plan.Target,
            new { plan.PlanId, snapshot.FileName, snapshot.Sha256, classification, outcome = "deleted" }, "executed");
        return Task.FromResult(new AgentLifecycleStaleRequestCleanupResult(plan.PlanId, snapshot.FileName, snapshot.Path, snapshot.Sha256, classification, "deleted", DateTimeOffset.UtcNow));
    }

    private static RequestSnapshot ReadEligibleRequest(string requestFileName)
    {
        var leaf = ValidateRequestLeaf(requestFileName);
        var path = Path.GetFullPath(Path.Combine(PendingRoot, leaf));
        if (!IsUnderRoot(path, PendingRoot) || Directory.Exists(path) || !File.Exists(path))
            throw new FileNotFoundException("Lifecycle pending request does not exist as a direct file.", path);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Lifecycle pending request may not be a reparse point.");

        var info = new FileInfo(path);
        if (info.Length <= 0 || info.Length > MaxRequestBytes) throw new InvalidDataException("Lifecycle request size is outside the fixed cleanup limit.");
        byte[] bytes;
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            bytes = new byte[checked((int)info.Length)];
            stream.ReadExactly(bytes);
            if (stream.ReadByte() != -1) throw new InvalidOperationException("Lifecycle request changed while reading.");
        }
        if (new FileInfo(path).Length != info.Length) throw new InvalidOperationException("Lifecycle request changed while reading.");
        var sha = Convert.ToHexString(SHA256.HashData(bytes));

        using var doc = JsonDocument.Parse(bytes);
        var root = doc.RootElement;
        RequireInt(root, "schemaVersion", 1);
        RequireString(root, "requestType", "agent-lifecycle-transition-request");
        RequireString(root, "scope", "request-only");
        RequireBool(root, "processAuthorization", false);
        RequireBool(root, "requiresSeparateRuntimePlans", true);
        var planId = GetRequiredString(root, "planId");
        var requestedAction = GetRequiredString(root, "requestedAction");
        if (requestedAction is not ("update" or "rollback")) throw new InvalidDataException("Lifecycle request action is invalid.");
        var current = root.GetProperty("current");
        var target = root.GetProperty("target");
        var currentSha = ValidateSha256(GetRequiredString(current, "runtimeSha256"));
        var targetSha = ValidateSha256(GetRequiredString(target, "runtimeSha256"));
        return new RequestSnapshot(leaf, path, info.Length, sha, planId, requestedAction, currentSha, targetSha);
    }

    private static string Classify(RequestSnapshot request, string currentRuntimeSha)
    {
        if (string.Equals(request.CurrentRuntimeSha256, currentRuntimeSha, StringComparison.OrdinalIgnoreCase)) return "active-current";
        if (string.Equals(request.TargetRuntimeSha256, currentRuntimeSha, StringComparison.OrdinalIgnoreCase)) return "completed-target-current";
        return "superseded";
    }

    private static string GetCurrentRuntimeSha256()
    {
        var runtime = Path.GetFullPath(typeof(AgentLifecycleStaleRequestCleanupTools).Assembly.Location);
        if (!File.Exists(runtime) || !string.Equals(Path.GetFileName(runtime), RuntimeFileName, StringComparison.OrdinalIgnoreCase) || !IsUnderRoot(runtime, DevRoot))
            throw new InvalidOperationException("Current Agent runtime identity is invalid.");
        if ((File.GetAttributes(runtime) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Current Agent runtime may not be a reparse point.");
        using var stream = new FileStream(runtime, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void ValidatePendingRoot()
    {
        if (!Directory.Exists(PendingRoot) || !IsUnderRoot(PendingRoot, DevRoot)) throw new DirectoryNotFoundException("Fixed lifecycle pending root is unavailable.");
        var current = new DirectoryInfo(PendingRoot);
        while (current is not null)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Lifecycle pending root may not traverse reparse points.");
            if (string.Equals(current.FullName.TrimEnd('\\', '/'), DevRoot.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase)) return;
            current = current.Parent;
        }
        throw new UnauthorizedAccessException("Lifecycle pending root boundary validation failed.");
    }

    private static string ValidateRequestLeaf(string value)
    {
        var leaf = (value ?? string.Empty).Trim();
        if (leaf.Length is < 1 or > 120 || !string.Equals(Path.GetFileName(leaf), leaf, StringComparison.Ordinal) ||
            leaf.Any(char.IsControl) || leaf.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
            !leaf.EndsWith("-request.json", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("requestFileName must be a safe direct lifecycle request JSON leaf name.", nameof(value));
        return leaf;
    }

    private static string Require(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : throw new InvalidDataException($"Signed cleanup parameter {key} is required.");
    private static long ParseLong(string value)
        => long.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var result) && result > 0 && result <= MaxRequestBytes ? result : throw new InvalidDataException("Signed request length is invalid.");
    private static string ValidateSha256(string value)
        => value.Length == 64 && value.All(Uri.IsHexDigit) ? value.ToUpperInvariant() : throw new InvalidDataException("Lifecycle request runtime SHA-256 is invalid.");
    private static string GetRequiredString(JsonElement element, string name)
        => element.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(p.GetString()) ? p.GetString()! : throw new InvalidDataException($"Lifecycle request property {name} is required.");
    private static void RequireString(JsonElement element, string name, string expected)
    {
        if (!string.Equals(GetRequiredString(element, name), expected, StringComparison.Ordinal)) throw new InvalidDataException($"Lifecycle request property {name} is invalid.");
    }
    private static void RequireInt(JsonElement element, string name, int expected)
    {
        if (!element.TryGetProperty(name, out var p) || p.ValueKind != JsonValueKind.Number || !p.TryGetInt32(out var value) || value != expected) throw new InvalidDataException($"Lifecycle request property {name} is invalid.");
    }
    private static void RequireBool(JsonElement element, string name, bool expected)
    {
        if (!element.TryGetProperty(name, out var p) || p.ValueKind is not (JsonValueKind.True or JsonValueKind.False) || p.GetBoolean() != expected) throw new InvalidDataException($"Lifecycle request property {name} is invalid.");
    }
    private static bool IsUnderRoot(string path, string root)
    {
        var fullPath = Path.GetFullPath(path);
        var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return string.Equals(fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), fullRoot, StringComparison.OrdinalIgnoreCase) || fullPath.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private sealed record RequestSnapshot(string FileName, string Path, long Bytes, string Sha256, string PlanId, string RequestedAction, string CurrentRuntimeSha256, string TargetRuntimeSha256);
}

public sealed record AgentLifecycleStaleRequestCleanupResult(string PlanId, string RequestFileName, string RequestPath, string RequestSha256, string Classification, string Outcome, DateTimeOffset ExecutedUtc);
