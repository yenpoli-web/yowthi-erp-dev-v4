using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Runtime;

[McpServerToolType]
public static class RuntimeHandoffActivationTools
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string ReleaseRoot = DevRoot + @"\acceptance\agent-lifecycle\releases";
    private const string PendingRoot = DevRoot + @"\.agent3-handoff\pending";
    private const string ReadyRoot = DevRoot + @"\.agent3-handoff\ready";
    private const string ActiveStatePath = DevRoot + @"\.agent3-handoff\active-runtime.json";

    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(DevRoot + @"\.agent3-audit");

    [McpServerTool(Name="runtime_handoff_activate_plan", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Prepare a one-time signed High-risk authorization for the Runtime Supervisor to cut over exactly one already-staged pending runtime handoff. The caller supplies only the pending handoff plan ID. Pending manifest bytes, candidate runtime SHA-256, and current active runtime identity are sealed. This plan does not itself stop or start a process.")]
    public static SignedPlan RuntimeHandoffActivatePlan(string handoffPlanId)
    {
        ValidatePlanId(handoffPlanId);
        var pendingPath = Path.Combine(PendingRoot, handoffPlanId + ".json");
        var readyPath = Path.Combine(ReadyRoot, handoffPlanId + ".json");
        if (!File.Exists(pendingPath)) throw new FileNotFoundException("Pending handoff manifest does not exist.", pendingPath);
        if (File.Exists(readyPath)) throw new InvalidOperationException("A ready authorization already exists for this handoff.");
        RejectReparse(pendingPath);

        var manifestBytes = File.ReadAllBytes(pendingPath);
        var manifestSha = Convert.ToHexString(SHA256.HashData(manifestBytes));
        var manifest = ParseManifest(manifestBytes, handoffPlanId);
        ValidateCandidate(manifest.RuntimeDll, manifest.RuntimeSha256, manifest.ListenUrl, manifest.HealthUrl);

        var current = ReadCurrentActiveIdentity();
        if (string.Equals(current.RuntimeSha256, manifest.RuntimeSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Pending handoff already targets the active runtime SHA-256.");

        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var parameters = new Dictionary<string,string>(StringComparer.Ordinal)
        {
            ["handoffPlanId"] = handoffPlanId,
            ["pendingPath"] = pendingPath,
            ["pendingManifestSha256"] = manifestSha,
            ["candidateRuntimeSha256"] = manifest.RuntimeSha256,
            ["currentRuntimeSha256"] = current.RuntimeSha256,
            ["currentProcessId"] = current.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["readyPath"] = readyPath
        };
        var unsigned = new SignedPlan(1, planId, approvalCode, "runtime-handoff", "handoff-activate", pendingPath, parameters,
            RiskClass.High,
            $"Authorize Runtime Supervisor cutover from active runtime {current.RuntimeSha256[..12]} to pending handoff {handoffPlanId} ({manifest.RuntimeSha256[..12]})",
            now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    [McpServerTool(Name="runtime_handoff_activate_execute", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Execute one previously prepared runtime-handoff activation authorization. Only planId and approvalCode are accepted. The pending manifest bytes, candidate runtime SHA-256, active runtime identity, fixed queue paths, and absence of an existing ready authorization are revalidated before one immutable ready authorization file is created. The Runtime Supervisor performs the actual stop/start cutover separately.")]
    public static ExecutionResult RuntimeHandoffActivateExecute(string planId, string approvalCode)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        if (!string.Equals(plan.Tool, "runtime-handoff", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, "handoff-activate", StringComparison.Ordinal) ||
            plan.RiskClass != RiskClass.High)
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");

        var handoffPlanId = RequireParameter(plan, "handoffPlanId");
        ValidatePlanId(handoffPlanId);
        var pendingPath = Path.Combine(PendingRoot, handoffPlanId + ".json");
        var readyPath = Path.Combine(ReadyRoot, handoffPlanId + ".json");
        if (!string.Equals(plan.Target, pendingPath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(RequireParameter(plan, "pendingPath"), pendingPath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(RequireParameter(plan, "readyPath"), readyPath, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Fixed handoff queue identity mismatch.");
        if (!File.Exists(pendingPath)) throw new FileNotFoundException("Pending handoff manifest no longer exists.", pendingPath);
        if (File.Exists(readyPath)) throw new InvalidOperationException("Ready authorization already exists.");
        RejectReparse(pendingPath);

        var manifestBytes = File.ReadAllBytes(pendingPath);
        var manifestSha = Convert.ToHexString(SHA256.HashData(manifestBytes));
        if (!string.Equals(manifestSha, RequireParameter(plan, "pendingManifestSha256"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Pending handoff manifest changed after plan creation.");
        var manifest = ParseManifest(manifestBytes, handoffPlanId);
        ValidateCandidate(manifest.RuntimeDll, manifest.RuntimeSha256, manifest.ListenUrl, manifest.HealthUrl);
        if (!string.Equals(manifest.RuntimeSha256, RequireParameter(plan, "candidateRuntimeSha256"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Candidate runtime identity changed after plan creation.");

        var current = ReadCurrentActiveIdentity();
        if (!string.Equals(current.RuntimeSha256, RequireParameter(plan, "currentRuntimeSha256"), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(current.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture), RequireParameter(plan, "currentProcessId"), StringComparison.Ordinal))
            throw new InvalidOperationException("Active runtime identity changed after plan creation.");

        Directory.CreateDirectory(ReadyRoot);
        var authorization = new
        {
            schemaVersion = 1,
            activationPlanId = plan.PlanId,
            handoffPlanId,
            pendingManifestSha256 = manifestSha,
            currentRuntimeSha256 = current.RuntimeSha256,
            candidateRuntimeSha256 = manifest.RuntimeSha256,
            authorizedUtc = DateTimeOffset.UtcNow
        };
        var json = JsonSerializer.Serialize(authorization, new JsonSerializerOptions { WriteIndented = true });
        using (var stream = new FileStream(readyPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
            writer.Write(json);

        Store.Consume(planId);
        var outcome = $"handoff-activation-authorized:{handoffPlanId}";
        Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, handoffPlanId, readyPath, outcome }, "executed");
        return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
    }

    private static PendingManifest ParseManifest(byte[] bytes, string expectedPlanId)
    {
        using var doc = JsonDocument.Parse(bytes);
        var root = doc.RootElement;
        var schemaVersion = GetRequiredInt(root, "schemaVersion");
        if (schemaVersion != 1) throw new InvalidDataException("Unsupported handoff manifest schemaVersion.");
        var planId = GetRequiredString(root, "planId");
        if (!string.Equals(planId, expectedPlanId, StringComparison.Ordinal))
            throw new InvalidDataException("Handoff manifest planId does not match its fixed queue identity.");
        return new PendingManifest(planId, GetRequiredString(root, "runtimeDll"), GetRequiredString(root, "runtimeSha256"),
            GetRequiredString(root, "listenUrl"), GetRequiredString(root, "healthUrl"));
    }

    private static void ValidateCandidate(string runtimeDll, string expectedSha, string listenUrl, string healthUrl)
    {
        var full = Path.GetFullPath(runtimeDll);
        var releaseRoot = Path.GetFullPath(ReleaseRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var package = Path.GetDirectoryName(full)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            ?? throw new InvalidDataException("Candidate package directory is missing.");
        if (!string.Equals(Path.GetDirectoryName(package)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), releaseRoot, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Candidate runtime must be one direct staged release.");
        if (!string.Equals(Path.GetFileName(full), "YowThi.DevelopmentAgent3.dll", StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Unexpected candidate runtime DLL name.");
        if (!File.Exists(full)) throw new FileNotFoundException("Candidate runtime DLL does not exist.", full);
        RejectReparse(releaseRoot); RejectReparse(package); RejectReparse(full);
        var actualSha = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(full)));
        if (!string.Equals(actualSha, expectedSha, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Candidate runtime DLL SHA-256 mismatch.");
        ValidateLoopbackHttpUrl(listenUrl, "listenUrl");
        ValidateLoopbackHttpUrl(healthUrl, "healthUrl");
    }

    private static ActiveIdentity ReadCurrentActiveIdentity()
    {
        if (!File.Exists(ActiveStatePath)) throw new FileNotFoundException("Active runtime state does not exist.", ActiveStatePath);
        using var doc = JsonDocument.Parse(File.ReadAllBytes(ActiveStatePath));
        var current = GetRequiredProperty(doc.RootElement, "current");
        return new ActiveIdentity(GetRequiredString(current, "runtimeSha256"), GetRequiredInt(current, "processId"));
    }

    private static JsonElement GetRequiredProperty(JsonElement element, string name)
    {
        foreach (var property in element.EnumerateObject())
            if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase)) return property.Value;
        throw new InvalidDataException(name + " is required.");
    }
    private static string GetRequiredString(JsonElement element, string name)
    {
        var value = GetRequiredProperty(element, name);
        if (value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString())) throw new InvalidDataException(name + " is required.");
        return value.GetString()!;
    }
    private static int GetRequiredInt(JsonElement element, string name)
    {
        var value = GetRequiredProperty(element, name);
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var result)) throw new InvalidDataException(name + " must be an integer.");
        return result;
    }
    private static void ValidatePlanId(string value)
    {
        if (!Guid.TryParseExact(value, "N", out _)) throw new ArgumentException("handoffPlanId must be a 32-character GUID N identifier.", nameof(value));
    }
    private static void ValidateLoopbackHttpUrl(string value, string name)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttp || !uri.IsLoopback)
            throw new InvalidDataException(name + " must be an absolute loopback HTTP URL.");
    }
    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Reparse points are not allowed: " + path);
    }
    private static string RequireParameter(SignedPlan plan, string name)
    {
        if (!plan.Parameters.TryGetValue(name, out var value)) throw new InvalidDataException(name + " parameter is required.");
        return value;
    }

    private sealed record PendingManifest(string PlanId, string RuntimeDll, string RuntimeSha256, string ListenUrl, string HealthUrl);
    private sealed record ActiveIdentity(string RuntimeSha256, int ProcessId);
}
