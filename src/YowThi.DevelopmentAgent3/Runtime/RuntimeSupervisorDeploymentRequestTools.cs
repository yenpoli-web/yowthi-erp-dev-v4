using System.ComponentModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Runtime;

[McpServerToolType]
public static class RuntimeSupervisorDeploymentRequestTools
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string ReleaseRoot = DevRoot + @"\acceptance\agent-lifecycle\releases";
    private const string ActiveStatePath = DevRoot + @"\.agent3-handoff\active-runtime.json";
    private const string DeploymentRoot = DevRoot + @"\.runtime-supervisor-deployment";
    private const string RequestRoot = DeploymentRoot + @"\requests";
    private const string SupervisorExe = DevRoot + @"\runtime-supervisor\current\YowThi.RuntimeSupervisor.exe";

    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(DevRoot + @"\.agent3-audit");

    [McpServerTool(Name = "runtime_supervisor_deployment_request_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed Medium-risk request-only plan for one existing staged Agent release. The plan seals the exact current Agent runtime identity, target staged release identity, fixed Runtime Supervisor executable identity, and current loopback endpoint identity. It cannot authorize or perform process/service stop/start/restart/termination and cannot create or modify .agent3-handoff\\ready.")]
    public static SignedPlan RuntimeSupervisorDeploymentRequestPlan(string releaseName)
    {
        var normalizedReleaseName = NormalizeReleaseName(releaseName);
        ValidateFixedRoots();
        ValidateRequestRootForCreate();

        var current = ReadCurrentActiveIdentity();
        var target = ReadTargetReleaseIdentity(normalizedReleaseName);
        var supervisor = ReadFileIdentity(SupervisorExe, "Runtime Supervisor executable");

        if (string.Equals(current.RuntimeSha256, target.RuntimeSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Target release already matches the active runtime SHA-256.");

        var now = DateTimeOffset.UtcNow;
        var expires = now.AddMinutes(10);
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var requestId = Guid.NewGuid().ToString("N");
        var requestPath = Path.Combine(RequestRoot, requestId + ".json");
        if (File.Exists(requestPath))
            throw new InvalidOperationException("Deployment request already exists.");

        var requestBytes = BuildRequestBytes(
            planId,
            requestId,
            normalizedReleaseName,
            current,
            target,
            supervisor,
            now,
            expires);

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["requestId"] = requestId,
            ["releaseName"] = normalizedReleaseName,
            ["requestPath"] = requestPath,
            ["requestSha256"] = HashBytes(requestBytes),
            ["currentRuntimeDll"] = current.RuntimeDll,
            ["currentRuntimeSha256"] = current.RuntimeSha256,
            ["currentProcessId"] = current.ProcessId.ToString(CultureInfo.InvariantCulture),
            ["targetRuntimeDll"] = target.RuntimeDll,
            ["targetRuntimeSha256"] = target.RuntimeSha256,
            ["listenUrl"] = current.ListenUrl,
            ["healthUrl"] = current.HealthUrl,
            ["supervisorExe"] = supervisor.Path,
            ["supervisorSha256"] = supervisor.Sha256,
            ["processAuthorization"] = bool.FalseString,
            ["requiresDedicatedSupervisorExecutor"] = bool.TrueString
        };

        var unsigned = new SignedPlan(
            1,
            planId,
            approvalCode,
            "runtime-supervisor-deployment-request",
            "request-create",
            requestPath,
            parameters,
            RiskClass.Medium,
            $"Create immutable request-only Runtime Supervisor deployment request {requestId} for staged release {normalizedReleaseName} without authorizing or changing process/service state",
            now,
            expires,
            string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target,
            new
            {
                signed.PlanId,
                signed.RiskClass,
                signed.Summary,
                requestId,
                releaseName = normalizedReleaseName,
                requestSha256 = parameters["requestSha256"],
                processAuthorization = false,
                requiresDedicatedSupervisorExecutor = true
            },
            "prepared");
        return signed;
    }

    [McpServerTool(Name = "runtime_supervisor_deployment_request_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared request-only Runtime Supervisor deployment plan. Only one immutable JSON request under the fixed .runtime-supervisor-deployment\\requests queue may be created after current/target runtime, Runtime Supervisor, endpoint, and request-payload identities are revalidated. This operation never creates or modifies .agent3-handoff\\ready and never stops, starts, restarts, terminates, signals, or reconfigures a process or Windows service.")]
    public static ExecutionResult RuntimeSupervisorDeploymentRequestExecute(string planId, string approvalCode)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        if (!string.Equals(plan.Tool, "runtime-supervisor-deployment-request", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, "request-create", StringComparison.Ordinal) ||
            plan.RiskClass != RiskClass.Medium)
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");

        ValidateFixedRoots();
        ValidateRequestRootForCreate();

        var requestId = RequireParameter(plan, "requestId");
        ValidateGuidN(requestId, "requestId");
        var releaseName = NormalizeReleaseName(RequireParameter(plan, "releaseName"));
        var requestPath = Path.Combine(RequestRoot, requestId + ".json");
        if (!string.Equals(plan.Target, requestPath, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(RequireParameter(plan, "requestPath"), requestPath, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Fixed Runtime Supervisor deployment request queue identity mismatch.");
        if (File.Exists(requestPath))
            throw new InvalidOperationException("Deployment request already exists.");

        if (!string.Equals(RequireParameter(plan, "processAuthorization"), bool.FalseString, StringComparison.Ordinal) ||
            !string.Equals(RequireParameter(plan, "requiresDedicatedSupervisorExecutor"), bool.TrueString, StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Request-only process-authorization flags changed after planning.");

        var current = ReadCurrentActiveIdentity();
        var target = ReadTargetReleaseIdentity(releaseName);
        var supervisor = ReadFileIdentity(SupervisorExe, "Runtime Supervisor executable");

        RequireEqual(current.RuntimeDll, RequireParameter(plan, "currentRuntimeDll"), "Active runtime DLL path changed after planning.");
        RequireEqual(current.RuntimeSha256, RequireParameter(plan, "currentRuntimeSha256"), "Active runtime SHA-256 changed after planning.");
        RequireEqual(current.ProcessId.ToString(CultureInfo.InvariantCulture), RequireParameter(plan, "currentProcessId"), "Active runtime process identity changed after planning.");
        RequireEqual(current.ListenUrl, RequireParameter(plan, "listenUrl"), "Active listen URL changed after planning.");
        RequireEqual(current.HealthUrl, RequireParameter(plan, "healthUrl"), "Active health URL changed after planning.");
        RequireEqual(target.RuntimeDll, RequireParameter(plan, "targetRuntimeDll"), "Target runtime DLL path changed after planning.");
        RequireEqual(target.RuntimeSha256, RequireParameter(plan, "targetRuntimeSha256"), "Target runtime SHA-256 changed after planning.");
        RequireEqual(supervisor.Path, RequireParameter(plan, "supervisorExe"), "Runtime Supervisor executable path changed after planning.");
        RequireEqual(supervisor.Sha256, RequireParameter(plan, "supervisorSha256"), "Runtime Supervisor executable SHA-256 changed after planning.");

        var requestBytes = BuildRequestBytes(
            plan.PlanId,
            requestId,
            releaseName,
            current,
            target,
            supervisor,
            plan.CreatedUtc,
            plan.ExpiresUtc);
        var requestSha = HashBytes(requestBytes);
        if (!string.Equals(requestSha, RequireParameter(plan, "requestSha256"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Deployment request payload no longer matches the sealed plan.");

        Directory.CreateDirectory(DeploymentRoot);
        RejectReparse(DeploymentRoot);
        Directory.CreateDirectory(RequestRoot);
        RejectReparse(RequestRoot);

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
                throw new InvalidOperationException("Deployment request post-write SHA-256 verification failed.");

            Store.Consume(planId);
            var outcome = $"runtime-supervisor-deployment-request-created:{requestId}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target,
                new
                {
                    plan.PlanId,
                    requestId,
                    releaseName,
                    requestPath,
                    requestSha256 = finalSha,
                    processAuthorization = false,
                    requiresDedicatedSupervisorExecutor = true,
                    outcome
                },
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
                new { plan.PlanId, requestId, requestPath, error = ex.Message },
                "failed");
            throw;
        }
    }

    private static byte[] BuildRequestBytes(
        string requestPlanId,
        string requestId,
        string releaseName,
        ActiveIdentity current,
        RuntimeIdentity target,
        FileIdentity supervisor,
        DateTimeOffset createdUtc,
        DateTimeOffset expiresUtc)
    {
        var record = new DeploymentRequestRecord(
            1,
            requestPlanId,
            requestId,
            releaseName,
            current.RuntimeDll,
            current.RuntimeSha256,
            current.ProcessId,
            target.RuntimeDll,
            target.RuntimeSha256,
            current.ListenUrl,
            current.HealthUrl,
            supervisor.Path,
            supervisor.Sha256,
            false,
            true,
            createdUtc,
            expiresUtc);
        var json = JsonSerializer.Serialize(record, new JsonSerializerOptions { WriteIndented = true });
        return new UTF8Encoding(false).GetBytes(json);
    }

    private static ActiveIdentity ReadCurrentActiveIdentity()
    {
        if (!File.Exists(ActiveStatePath))
            throw new FileNotFoundException("Active runtime state does not exist.", ActiveStatePath);
        RejectReparse(ActiveStatePath);
        using var doc = JsonDocument.Parse(File.ReadAllBytes(ActiveStatePath));
        var current = GetRequiredProperty(doc.RootElement, "current");
        var runtimeDll = GetRequiredString(current, "runtimeDll");
        var runtimeSha = GetRequiredString(current, "runtimeSha256");
        var processId = GetRequiredInt(current, "processId");
        var listenUrl = NormalizeLoopbackHttpUrl(GetRequiredString(current, "listenUrl"), "listenUrl");
        var healthUrl = NormalizeLoopbackHttpUrl(GetRequiredString(current, "healthUrl"), "healthUrl");
        ValidateRuntime(runtimeDll, runtimeSha);
        if (processId <= 0)
            throw new InvalidDataException("Active runtime processId must be positive.");
        return new ActiveIdentity(Path.GetFullPath(runtimeDll), runtimeSha, processId, listenUrl, healthUrl);
    }

    private static RuntimeIdentity ReadTargetReleaseIdentity(string releaseName)
    {
        var releaseDirectory = Path.Combine(ReleaseRoot, releaseName);
        var runtimeDll = Path.Combine(releaseDirectory, "YowThi.DevelopmentAgent3.dll");
        var fullReleaseRoot = Path.GetFullPath(ReleaseRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var fullReleaseDirectory = Path.GetFullPath(releaseDirectory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!string.Equals(Path.GetDirectoryName(fullReleaseDirectory)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), fullReleaseRoot, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Target release must be one direct staged release.");
        if (!Directory.Exists(fullReleaseDirectory))
            throw new DirectoryNotFoundException("Target staged release does not exist: " + fullReleaseDirectory);
        RejectReparse(fullReleaseRoot);
        RejectReparse(fullReleaseDirectory);
        var identity = ReadFileIdentity(runtimeDll, "Target runtime DLL");
        if (!string.Equals(Path.GetFileName(identity.Path), "YowThi.DevelopmentAgent3.dll", StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Unexpected target runtime DLL name.");
        return new RuntimeIdentity(identity.Path, identity.Sha256);
    }

    private static void ValidateRuntime(string runtimeDll, string expectedSha)
    {
        var full = Path.GetFullPath(runtimeDll);
        var releaseRoot = Path.GetFullPath(ReleaseRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var package = Path.GetDirectoryName(full)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            ?? throw new InvalidDataException("Runtime package directory is missing.");
        if (!string.Equals(Path.GetDirectoryName(package)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), releaseRoot, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Runtime must be one direct staged release.");
        if (!string.Equals(Path.GetFileName(full), "YowThi.DevelopmentAgent3.dll", StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Unexpected runtime DLL name.");
        if (!File.Exists(full))
            throw new FileNotFoundException("Runtime DLL does not exist.", full);
        RejectReparse(releaseRoot);
        RejectReparse(package);
        RejectReparse(full);
        var actualSha = HashFile(full);
        if (!string.Equals(actualSha, expectedSha, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Runtime DLL SHA-256 mismatch.");
    }

    private static FileIdentity ReadFileIdentity(string path, string label)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full))
            throw new FileNotFoundException(label + " does not exist.", full);
        RejectReparse(full);
        return new FileIdentity(full, HashFile(full));
    }

    private static void ValidateFixedRoots()
    {
        ValidateExistingDirectory(DevRoot, DevRoot);
        ValidateExistingDirectory(ReleaseRoot, DevRoot);
        var supervisorRoot = Path.GetDirectoryName(SupervisorExe)
            ?? throw new InvalidDataException("Runtime Supervisor directory is missing.");
        ValidateExistingDirectory(supervisorRoot, DevRoot);
        _ = ReadFileIdentity(SupervisorExe, "Runtime Supervisor executable");
    }

    private static void ValidateRequestRootForCreate()
    {
        if (Directory.Exists(DeploymentRoot))
            ValidateExistingDirectory(DeploymentRoot, DevRoot);
        else if (File.Exists(DeploymentRoot))
            throw new IOException("Runtime Supervisor deployment root is occupied by a file.");

        if (Directory.Exists(RequestRoot))
            ValidateExistingDirectory(RequestRoot, DeploymentRoot);
        else if (File.Exists(RequestRoot))
            throw new IOException("Runtime Supervisor deployment request root is occupied by a file.");
    }

    private static void ValidateExistingDirectory(string path, string boundary)
    {
        var full = Path.GetFullPath(path);
        var root = Path.GetFullPath(boundary).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!Directory.Exists(full))
            throw new DirectoryNotFoundException("Required fixed directory does not exist: " + full);
        if (!string.Equals(full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), root, StringComparison.OrdinalIgnoreCase) &&
            !full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Fixed deployment path escaped its boundary.");
        RejectReparse(full);
    }

    private static string NormalizeReleaseName(string value)
    {
        var trimmed = value?.Trim() ?? string.Empty;
        if (trimmed.Length is < 2 or > 32 || trimmed[0] != 'r' || trimmed.Skip(1).Any(ch => ch < '0' || ch > '9'))
            throw new ArgumentException("releaseName must match r<digits>.", nameof(value));
        return trimmed;
    }

    private static string NormalizeLoopbackHttpUrl(string value, string name)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttp || !uri.IsLoopback || uri.Port <= 0)
            throw new InvalidDataException(name + " must be an absolute loopback HTTP URL with explicit port.");
        return uri.ToString().TrimEnd('/');
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

    private static void ValidateGuidN(string value, string name)
    {
        if (!Guid.TryParseExact(value, "N", out _))
            throw new InvalidDataException(name + " must be a 32-character GUID N identifier.");
    }

    private static string RequireParameter(SignedPlan plan, string name)
    {
        if (!plan.Parameters.TryGetValue(name, out var value) || string.IsNullOrWhiteSpace(value))
            throw new InvalidDataException(name + " parameter is required.");
        return value;
    }

    private static void RequireEqual(string actual, string expected, string message)
    {
        if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(message);
    }

    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Reparse points are not allowed: " + path);
    }

    private static string HashBytes(byte[] bytes)
        => Convert.ToHexString(SHA256.HashData(bytes));

    private static string HashFile(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private sealed record ActiveIdentity(
        string RuntimeDll,
        string RuntimeSha256,
        int ProcessId,
        string ListenUrl,
        string HealthUrl);

    private sealed record RuntimeIdentity(string RuntimeDll, string RuntimeSha256);
    private sealed record FileIdentity(string Path, string Sha256);

    private sealed record DeploymentRequestRecord(
        int SchemaVersion,
        string RequestPlanId,
        string RequestId,
        string ReleaseName,
        string CurrentRuntimeDll,
        string CurrentRuntimeSha256,
        int CurrentProcessId,
        string TargetRuntimeDll,
        string TargetRuntimeSha256,
        string ListenUrl,
        string HealthUrl,
        string SupervisorExe,
        string SupervisorSha256,
        bool ProcessAuthorization,
        bool RequiresDedicatedSupervisorExecutor,
        DateTimeOffset CreatedUtc,
        DateTimeOffset ExpiresUtc);
}
