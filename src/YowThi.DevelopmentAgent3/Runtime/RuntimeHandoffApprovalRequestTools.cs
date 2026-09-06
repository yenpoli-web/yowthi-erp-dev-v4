using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Runtime;

[McpServerToolType]
public static class RuntimeHandoffApprovalRequestTools
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string HandoffRoot = DevRoot + @"\.agent3-handoff";
    private const string ReleaseRoot = DevRoot + @"\acceptance\agent-lifecycle\releases";
    private const string PendingRoot = HandoffRoot + @"\pending";
    private const string ApprovalRequestRoot = HandoffRoot + @"\approval-requests";
    private const string ActiveStatePath = HandoffRoot + @"\active-runtime.json";

    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(DevRoot + @"\.agent3-audit");

    [McpServerTool(Name = "runtime_handoff_approval_request_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed Medium-risk plan to create exactly one immutable runtime-handoff approval request under the fixed .agent3-handoff\\approval-requests queue. The request binds the existing pending manifest, current runtime identity, candidate runtime SHA-256, and fixed loopback endpoints. This plan does not create or modify any .agent3-handoff\\ready authorization and does not authorize or perform process or service stop/start/restart/termination.")]
    public static SignedPlan RuntimeHandoffApprovalRequestPlan(string handoffPlanId)
    {
        ValidatePlanId(handoffPlanId);
        ValidateFixedRoots();

        var pendingPath = Path.Combine(PendingRoot, handoffPlanId + ".json");
        var requestPath = Path.Combine(ApprovalRequestRoot, handoffPlanId + ".json");
        if (!File.Exists(pendingPath))
            throw new FileNotFoundException("Pending handoff manifest does not exist.", pendingPath);
        if (File.Exists(requestPath))
            throw new InvalidOperationException("An approval request already exists for this handoff.");
        RejectReparse(pendingPath);
        ValidateRequestRootForCreate();

        var manifestBytes = File.ReadAllBytes(pendingPath);
        var manifestSha = HashBytes(manifestBytes);
        var manifest = ParseManifest(manifestBytes, handoffPlanId);
        ValidateCandidate(manifest.RuntimeDll, manifest.RuntimeSha256, manifest.ListenUrl, manifest.HealthUrl);

        var current = ReadCurrentActiveIdentity();
        if (string.Equals(current.RuntimeSha256, manifest.RuntimeSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Pending handoff already targets the active runtime SHA-256.");

        var now = DateTimeOffset.UtcNow;
        var expires = now.AddMinutes(10);
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var requestBytes = BuildRequestBytes(
            planId,
            handoffPlanId,
            manifestSha,
            current.RuntimeSha256,
            current.ProcessId,
            manifest.RuntimeSha256,
            manifest.ListenUrl,
            manifest.HealthUrl,
            now,
            expires);

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["handoffPlanId"] = handoffPlanId,
            ["pendingPath"] = pendingPath,
            ["pendingManifestSha256"] = manifestSha,
            ["candidateRuntimeSha256"] = manifest.RuntimeSha256,
            ["currentRuntimeSha256"] = current.RuntimeSha256,
            ["currentProcessId"] = current.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["listenUrl"] = manifest.ListenUrl,
            ["healthUrl"] = manifest.HealthUrl,
            ["requestPath"] = requestPath,
            ["requestSha256"] = HashBytes(requestBytes)
        };

        var unsigned = new SignedPlan(
            1,
            planId,
            approvalCode,
            "runtime-handoff-approval-request",
            "request-create",
            requestPath,
            parameters,
            RiskClass.Medium,
            $"Create immutable runtime handoff approval request for pending handoff {handoffPlanId} without creating a ready authorization or changing process state",
            now,
            expires,
            string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target,
            new { signed.PlanId, signed.RiskClass, signed.Summary, handoffPlanId, requestSha256 = parameters["requestSha256"] },
            "prepared");
        return signed;
    }

    [McpServerTool(Name = "runtime_handoff_approval_request_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared runtime-handoff approval-request plan. Only the exact fixed approval-request file may be created with CreateNew semantics after the pending manifest, current runtime, candidate SHA-256, and request payload hash are revalidated. This operation never writes to .agent3-handoff\\ready and never stops, starts, restarts, terminates, signals, or otherwise modifies a process or Windows service.")]
    public static ExecutionResult RuntimeHandoffApprovalRequestExecute(string planId, string approvalCode)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        if (!string.Equals(plan.Tool, "runtime-handoff-approval-request", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, "request-create", StringComparison.Ordinal) ||
            plan.RiskClass != RiskClass.Medium)
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");

        ValidateFixedRoots();
        var handoffPlanId = RequireParameter(plan, "handoffPlanId");
        ValidatePlanId(handoffPlanId);

        var pendingPath = Path.Combine(PendingRoot, handoffPlanId + ".json");
        var requestPath = Path.Combine(ApprovalRequestRoot, handoffPlanId + ".json");
        if (!string.Equals(plan.Target, requestPath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(RequireParameter(plan, "pendingPath"), pendingPath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(RequireParameter(plan, "requestPath"), requestPath, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Fixed approval-request queue identity mismatch.");
        if (!File.Exists(pendingPath))
            throw new FileNotFoundException("Pending handoff manifest no longer exists.", pendingPath);
        if (File.Exists(requestPath))
            throw new InvalidOperationException("Approval request already exists.");
        RejectReparse(pendingPath);
        ValidateRequestRootForCreate();

        var manifestBytes = File.ReadAllBytes(pendingPath);
        var manifestSha = HashBytes(manifestBytes);
        if (!string.Equals(manifestSha, RequireParameter(plan, "pendingManifestSha256"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Pending handoff manifest changed after plan creation.");

        var manifest = ParseManifest(manifestBytes, handoffPlanId);
        ValidateCandidate(manifest.RuntimeDll, manifest.RuntimeSha256, manifest.ListenUrl, manifest.HealthUrl);
        if (!string.Equals(manifest.RuntimeSha256, RequireParameter(plan, "candidateRuntimeSha256"), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(manifest.ListenUrl, RequireParameter(plan, "listenUrl"), StringComparison.Ordinal) ||
            !string.Equals(manifest.HealthUrl, RequireParameter(plan, "healthUrl"), StringComparison.Ordinal))
            throw new InvalidOperationException("Pending handoff candidate identity changed after plan creation.");

        var current = ReadCurrentActiveIdentity();
        if (!string.Equals(current.RuntimeSha256, RequireParameter(plan, "currentRuntimeSha256"), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(current.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture), RequireParameter(plan, "currentProcessId"), StringComparison.Ordinal))
            throw new InvalidOperationException("Active runtime identity changed after plan creation.");

        var requestBytes = BuildRequestBytes(
            plan.PlanId,
            handoffPlanId,
            manifestSha,
            current.RuntimeSha256,
            current.ProcessId,
            manifest.RuntimeSha256,
            manifest.ListenUrl,
            manifest.HealthUrl,
            plan.CreatedUtc,
            plan.ExpiresUtc);
        var requestSha = HashBytes(requestBytes);
        if (!string.Equals(requestSha, RequireParameter(plan, "requestSha256"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Approval request payload no longer matches the sealed plan.");

        Directory.CreateDirectory(ApprovalRequestRoot);
        RejectReparse(ApprovalRequestRoot);
        var created = false;
        try
        {
            using (var stream = new FileStream(requestPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(requestBytes, 0, requestBytes.Length);
                stream.Flush(flushToDisk: true);
            }
            created = true;

            var finalSha = HashFile(requestPath);
            if (!string.Equals(finalSha, requestSha, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Approval request post-write SHA-256 verification failed.");

            Store.Consume(planId);
            var outcome = $"handoff-approval-request-created:{handoffPlanId}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target,
                new { plan.PlanId, handoffPlanId, requestPath, requestSha256 = finalSha, outcome },
                "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            if (created)
            {
                try { if (File.Exists(requestPath)) File.Delete(requestPath); } catch { }
            }
            Audit.Append(plan.Tool, plan.Operation, plan.Target,
                new { plan.PlanId, handoffPlanId, requestPath, error = ex.Message },
                "failed");
            throw;
        }
    }

    private static byte[] BuildRequestBytes(
        string requestPlanId,
        string handoffPlanId,
        string pendingManifestSha256,
        string currentRuntimeSha256,
        int currentProcessId,
        string candidateRuntimeSha256,
        string listenUrl,
        string healthUrl,
        DateTimeOffset createdUtc,
        DateTimeOffset expiresUtc)
    {
        var record = new ApprovalRequestRecord(
            1,
            requestPlanId,
            handoffPlanId,
            pendingManifestSha256,
            currentRuntimeSha256,
            currentProcessId,
            candidateRuntimeSha256,
            listenUrl,
            healthUrl,
            createdUtc,
            expiresUtc);
        var json = JsonSerializer.Serialize(record, new JsonSerializerOptions { WriteIndented = true });
        return new UTF8Encoding(false).GetBytes(json);
    }

    private static PendingManifest ParseManifest(byte[] bytes, string expectedPlanId)
    {
        using var doc = JsonDocument.Parse(bytes);
        var root = doc.RootElement;
        var schemaVersion = GetRequiredInt(root, "schemaVersion");
        if (schemaVersion != 1)
            throw new InvalidDataException("Unsupported handoff manifest schemaVersion.");
        var planId = GetRequiredString(root, "planId");
        if (!string.Equals(planId, expectedPlanId, StringComparison.Ordinal))
            throw new InvalidDataException("Handoff manifest planId does not match its fixed queue identity.");
        return new PendingManifest(
            planId,
            GetRequiredString(root, "runtimeDll"),
            GetRequiredString(root, "runtimeSha256"),
            GetRequiredString(root, "listenUrl"),
            GetRequiredString(root, "healthUrl"));
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
        if (!File.Exists(full))
            throw new FileNotFoundException("Candidate runtime DLL does not exist.", full);
        RejectReparse(releaseRoot);
        RejectReparse(package);
        RejectReparse(full);
        var actualSha = HashFile(full);
        if (!string.Equals(actualSha, expectedSha, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Candidate runtime DLL SHA-256 mismatch.");
        ValidateLoopbackHttpUrl(listenUrl, "listenUrl");
        ValidateLoopbackHttpUrl(healthUrl, "healthUrl");
    }

    private static ActiveIdentity ReadCurrentActiveIdentity()
    {
        if (!File.Exists(ActiveStatePath))
            throw new FileNotFoundException("Active runtime state does not exist.", ActiveStatePath);
        RejectReparse(ActiveStatePath);
        using var doc = JsonDocument.Parse(File.ReadAllBytes(ActiveStatePath));
        var current = GetRequiredProperty(doc.RootElement, "current");
        return new ActiveIdentity(GetRequiredString(current, "runtimeSha256"), GetRequiredInt(current, "processId"));
    }

    private static void ValidateFixedRoots()
    {
        ValidateExistingDirectory(HandoffRoot, DevRoot);
        ValidateExistingDirectory(PendingRoot, HandoffRoot);
        ValidateExistingDirectory(ReleaseRoot, DevRoot);
    }

    private static void ValidateRequestRootForCreate()
    {
        ValidateExistingDirectory(HandoffRoot, DevRoot);
        if (Directory.Exists(ApprovalRequestRoot))
            ValidateExistingDirectory(ApprovalRequestRoot, HandoffRoot);
        else if (File.Exists(ApprovalRequestRoot))
            throw new IOException("Approval-request root path is occupied by a file.");
    }

    private static void ValidateExistingDirectory(string path, string boundary)
    {
        var full = Path.GetFullPath(path);
        var root = Path.GetFullPath(boundary).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!Directory.Exists(full))
            throw new DirectoryNotFoundException($"Required fixed directory does not exist: {full}");
        if (!string.Equals(full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), root, StringComparison.OrdinalIgnoreCase) &&
            !full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Fixed runtime-handoff path escaped its boundary.");
        RejectReparse(full);
    }

    private static JsonElement GetRequiredProperty(JsonElement element, string name)
    {
        foreach (var property in element.EnumerateObject())
            if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
                return property.Value;
        throw new InvalidDataException(name + " is required.");
    }

    private static string GetRequiredString(JsonElement element, string name)
    {
        var value = GetRequiredProperty(element, name);
        if (value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString()))
            throw new InvalidDataException(name + " is required.");
        return value.GetString()!;
    }

    private static int GetRequiredInt(JsonElement element, string name)
    {
        var value = GetRequiredProperty(element, name);
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var result))
            throw new InvalidDataException(name + " must be an integer.");
        return result;
    }

    private static void ValidatePlanId(string value)
    {
        if (!Guid.TryParseExact(value, "N", out _))
            throw new ArgumentException("handoffPlanId must be a 32-character GUID N identifier.", nameof(value));
    }

    private static void ValidateLoopbackHttpUrl(string value, string name)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttp || !uri.IsLoopback || uri.Port <= 0)
            throw new InvalidDataException(name + " must be an absolute loopback HTTP URL with explicit port.");
    }

    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Reparse points are not allowed: " + path);
    }

    private static string RequireParameter(SignedPlan plan, string name)
    {
        if (!plan.Parameters.TryGetValue(name, out var value) || string.IsNullOrWhiteSpace(value))
            throw new InvalidDataException(name + " parameter is required.");
        return value;
    }

    private static string HashBytes(byte[] bytes)
        => Convert.ToHexString(SHA256.HashData(bytes));

    private static string HashFile(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private sealed record PendingManifest(
        string PlanId,
        string RuntimeDll,
        string RuntimeSha256,
        string ListenUrl,
        string HealthUrl);

    private sealed record ActiveIdentity(string RuntimeSha256, int ProcessId);

    private sealed record ApprovalRequestRecord(
        int SchemaVersion,
        string RequestPlanId,
        string HandoffPlanId,
        string PendingManifestSha256,
        string CurrentRuntimeSha256,
        int CurrentProcessId,
        string CandidateRuntimeSha256,
        string ListenUrl,
        string HealthUrl,
        DateTimeOffset CreatedUtc,
        DateTimeOffset ExpiresUtc);
}
