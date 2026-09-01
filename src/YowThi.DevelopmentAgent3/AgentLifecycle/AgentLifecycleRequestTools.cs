using System.ComponentModel;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.AgentLifecycle;

[McpServerToolType]
public static class AgentLifecycleRequestTools
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string ReleaseRoot = @"C:\Dev\YowThi-ERP-Dev-v4\acceptance\agent-lifecycle\releases";
    private const string RollbackRoot = @"C:\Dev\YowThi-ERP-Dev-v4\acceptance\agent-lifecycle\rollback";
    private const string PendingRoot = @"C:\Dev\YowThi-ERP-Dev-v4\.agent3-lifecycle\pending";
    private const string RuntimeFileName = "YowThi.DevelopmentAgent3.dll";
    private const string DepsFileName = "YowThi.DevelopmentAgent3.deps.json";
    private const string RuntimeConfigFileName = "YowThi.DevelopmentAgent3.runtimeconfig.json";
    private const int MaxEntries = 10_000;
    private const long MaxPackageBytes = 4L * 1024 * 1024 * 1024;
    private const long MaxSingleFileBytes = 2L * 1024 * 1024 * 1024;

    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(2) };

    [McpServerTool(Name = "agent_update_request_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed Medium-risk request-only plan that records a desired Agent update target from one existing staged release. Current and target package manifest/shape/runtime SHA-256 identities plus the current loopback health endpoint are sealed. This plan does not authorize, stop, start, restart, terminate, or otherwise modify any process. Any later runtime change requires separate explicitly approved typed runtime plans.")]
    public static Task<SignedPlan> AgentUpdateRequestPlan(string releaseName)
        => PrepareRequestPlan("update", ReleaseRoot, releaseName);

    [McpServerTool(Name = "agent_update_request_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared request-only Agent update plan by revalidating current/target package identities and current health, then writing one immutable JSON request into the fixed lifecycle pending queue. The request explicitly carries processAuthorization=false and requiresSeparateRuntimePlans=true. This endpoint does not authorize or perform process stop/start/restart/termination and does not modify the running Agent.")]
    public static Task<AgentLifecycleRequestStageResult> AgentUpdateRequestExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
        => ExecuteRequest(planId, approvalCode, operation, target, summary, riskClass, "update-request", "update", ReleaseRoot);

    [McpServerTool(Name = "agent_rollback_request_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed Medium-risk request-only plan that records a desired Agent rollback target from one existing rollback package. Current and target package manifest/shape/runtime SHA-256 identities plus the current loopback health endpoint are sealed. This plan does not authorize, stop, start, restart, terminate, or otherwise modify any process. Any later runtime change requires separate explicitly approved typed runtime plans.")]
    public static Task<SignedPlan> AgentRollbackRequestPlan(string backupName)
        => PrepareRequestPlan("rollback", RollbackRoot, backupName);

    [McpServerTool(Name = "agent_rollback_request_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared request-only Agent rollback plan by revalidating current/target package identities and current health, then writing one immutable JSON request into the fixed lifecycle pending queue. The request explicitly carries processAuthorization=false and requiresSeparateRuntimePlans=true. This endpoint does not authorize or perform process stop/start/restart/termination and does not modify the running Agent.")]
    public static Task<AgentLifecycleRequestStageResult> AgentRollbackRequestExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
        => ExecuteRequest(planId, approvalCode, operation, target, summary, riskClass, "rollback-request", "rollback", RollbackRoot);

    private static async Task<SignedPlan> PrepareRequestPlan(string requestedAction, string targetRoot, string packageName)
    {
        ValidateFixedRoot(targetRoot);
        ValidateFixedRoot(PendingRoot);

        var currentRuntime = GetCurrentRuntimeDll();
        var currentDirectory = Path.GetDirectoryName(currentRuntime)!;
        var current = ComputePackageSnapshot(currentDirectory);
        var targetDirectory = ValidateExistingNamedPackage(targetRoot, packageName, nameof(packageName));
        var next = ComputePackageSnapshot(targetDirectory);

        if (string.Equals(current.ManifestSha256, next.ManifestSha256, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(current.ShapeSha256, next.ShapeSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Request target package is identical to the currently executing package.");

        var listen = GetCurrentListenUri();
        var health = new Uri($"{NormalizeUrl(listen)}/health");
        var probe = await ProbeHealthAsync(health);
        if (!probe.Healthy) throw new InvalidOperationException("Current Agent health must be healthy before a lifecycle request can be staged.");

        var parameters = PackageParameters(current, "current");
        foreach (var pair in PackageParameters(next, "target")) parameters[pair.Key] = pair.Value;
        parameters["currentDirectory"] = currentDirectory;
        parameters["currentRuntimeDll"] = current.RuntimeDll;
        parameters["targetPackageName"] = Path.GetFileName(targetDirectory);
        parameters["targetDirectory"] = targetDirectory;
        parameters["targetRuntimeDll"] = next.RuntimeDll;
        parameters["requestedAction"] = requestedAction;
        parameters["listenUrl"] = NormalizeUrl(listen);
        parameters["healthUrl"] = health.ToString();
        parameters["processAuthorization"] = "false";
        parameters["requiresSeparateRuntimePlans"] = "true";

        var operation = requestedAction + "-request";
        var summary = $"Stage request-only Agent {requestedAction} intent from {currentDirectory} to {targetDirectory}; no process authorization or mutation; separate typed runtime plans are required";
        return PreparePlan(operation, targetDirectory, summary, parameters);
    }

    private static async Task<AgentLifecycleRequestStageResult> ExecuteRequest(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass,
        string expectedOperation,
        string requestedAction,
        string targetRoot)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, expectedOperation, operation, target, summary, riskClass);
        ValidateFixedRoot(targetRoot);
        ValidateFixedRoot(PendingRoot);

        if (!string.Equals(RequireParameter(plan, "requestedAction"), requestedAction, StringComparison.Ordinal) ||
            !string.Equals(RequireParameter(plan, "processAuthorization"), "false", StringComparison.Ordinal) ||
            !string.Equals(RequireParameter(plan, "requiresSeparateRuntimePlans"), "true", StringComparison.Ordinal))
            throw new InvalidDataException("Signed lifecycle request scope is invalid.");

        var currentRuntime = GetCurrentRuntimeDll();
        var currentDirectory = Path.GetDirectoryName(currentRuntime)!;
        if (!string.Equals(currentDirectory, RequireParameter(plan, "currentDirectory"), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(currentRuntime, RequireParameter(plan, "currentRuntimeDll"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Current Agent runtime/package changed after request plan preparation.");

        var current = ComputePackageSnapshot(currentDirectory);
        RequireSnapshotMatchesPlan(current, plan, "current");

        var targetDirectory = ValidateExistingNamedPackage(targetRoot, RequireParameter(plan, "targetPackageName"), "targetPackageName");
        if (!string.Equals(targetDirectory, RequireParameter(plan, "targetDirectory"), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(targetDirectory, plan.Target, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Lifecycle request target directory no longer matches the signed plan.");

        var next = ComputePackageSnapshot(targetDirectory);
        RequireSnapshotMatchesPlan(next, plan, "target");
        if (!string.Equals(next.RuntimeDll, RequireParameter(plan, "targetRuntimeDll"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Lifecycle request target runtime DLL no longer matches the signed plan.");

        var listen = ValidateLoopbackHttpUrl(RequireParameter(plan, "listenUrl"), "listenUrl");
        var health = ValidateLoopbackHttpUrl(RequireParameter(plan, "healthUrl"), "healthUrl");
        RequireSameEndpoint(listen, health);
        var probe = await ProbeHealthAsync(health);
        if (!probe.Healthy) throw new InvalidOperationException("Current Agent health is no longer healthy; lifecycle request was not staged.");

        var requestPath = Path.Combine(PendingRoot, $"{plan.PlanId}-{requestedAction}-request.json");
        if (File.Exists(requestPath) || Directory.Exists(requestPath)) throw new IOException("Lifecycle request already exists.");

        var request = new
        {
            schemaVersion = 1,
            requestType = "agent-lifecycle-transition-request",
            planId = plan.PlanId,
            requestedAction,
            scope = "request-only",
            processAuthorization = false,
            requiresSeparateRuntimePlans = true,
            current = new
            {
                directory = currentDirectory,
                runtimeDll = current.RuntimeDll,
                runtimeSha256 = current.RuntimeSha256,
                manifestSha256 = current.ManifestSha256,
                shapeSha256 = current.ShapeSha256
            },
            target = new
            {
                directory = targetDirectory,
                runtimeDll = next.RuntimeDll,
                runtimeSha256 = next.RuntimeSha256,
                manifestSha256 = next.ManifestSha256,
                shapeSha256 = next.ShapeSha256
            },
            listenUrl = NormalizeUrl(listen),
            healthUrl = health.ToString(),
            stagedUtc = DateTimeOffset.UtcNow
        };

        var json = JsonSerializer.Serialize(request, new JsonSerializerOptions { WriteIndented = true });
        using (var stream = new FileStream(requestPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
            writer.Write(json);

        Store.Consume(planId);
        Audit.Append(plan.Tool, plan.Operation, plan.Target,
            new
            {
                plan.PlanId,
                requestedAction,
                requestPath,
                processAuthorization = false,
                requiresSeparateRuntimePlans = true,
                currentRuntimeSha256 = current.RuntimeSha256,
                targetRuntimeSha256 = next.RuntimeSha256,
                outcome = "request-staged"
            },
            "executed");

        return new AgentLifecycleRequestStageResult(
            plan.PlanId,
            requestedAction,
            requestPath,
            currentDirectory,
            current.RuntimeSha256,
            targetDirectory,
            next.RuntimeSha256,
            false,
            true,
            "request-staged",
            DateTimeOffset.UtcNow);
    }

    private static PackageSnapshot ComputePackageSnapshot(string directory)
    {
        var root = ValidatePackageDirectory(directory);
        var entries = new List<PackageEntry>();
        var stack = new Stack<string>();
        stack.Push(root);
        long totalBytes = 0;
        var fileCount = 0;
        var directoryCount = 0;

        while (stack.Count > 0)
        {
            var current = stack.Pop();
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException($"Lifecycle request package may not traverse reparse-point directory: {current}");

            foreach (var path in Directory.EnumerateFileSystemEntries(current, "*", SearchOption.TopDirectoryOnly))
            {
                var attributes = File.GetAttributes(path);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new UnauthorizedAccessException($"Lifecycle request package may not contain reparse-point entry: {path}");

                var relative = Path.GetRelativePath(root, path).Replace('\\', '/');
                ValidateRelativePath(relative);

                if ((attributes & FileAttributes.Directory) != 0)
                {
                    directoryCount++;
                    EnsureEntryLimit(entries.Count + 1);
                    entries.Add(new PackageEntry(relative, true, 0, string.Empty));
                    stack.Push(path);
                }
                else
                {
                    var state = HashFile(path);
                    totalBytes = checked(totalBytes + state.Bytes);
                    if (totalBytes > MaxPackageBytes) throw new InvalidDataException("Lifecycle request package exceeds the fixed total byte limit.");
                    fileCount++;
                    EnsureEntryLimit(entries.Count + 1);
                    entries.Add(new PackageEntry(relative, false, state.Bytes, state.Sha256));
                }
            }
        }

        entries.Sort((a, b) => StringComparer.Ordinal.Compare(a.RelativePath, b.RelativePath));
        var runtimeDll = Path.Combine(root, RuntimeFileName);
        var deps = Path.Combine(root, DepsFileName);
        var runtimeConfig = Path.Combine(root, RuntimeConfigFileName);
        if (!File.Exists(runtimeDll) || !File.Exists(deps) || !File.Exists(runtimeConfig))
            throw new InvalidDataException("Lifecycle request package must contain the fixed runtime DLL, deps.json, and runtimeconfig.json at package root.");

        var assemblyName = AssemblyName.GetAssemblyName(runtimeDll);
        if (!string.Equals(assemblyName.Name, "YowThi.DevelopmentAgent3", StringComparison.Ordinal))
            throw new InvalidDataException("Lifecycle request runtime assembly identity is not YowThi.DevelopmentAgent3.");

        var runtimeSha = Sha256File(runtimeDll);
        var manifest = entries.Select(e => e.IsDirectory ? $"D|{e.RelativePath}" : $"F|{e.RelativePath}|{e.Length}|{e.Sha256}");
        var shape = entries.Select(e => e.IsDirectory ? $"D|{e.RelativePath}" : $"F|{e.RelativePath}|{e.Length}");
        return new PackageSnapshot(root, runtimeDll, runtimeSha, HashCanonical(manifest), HashCanonical(shape), fileCount, directoryCount, totalBytes);
    }

    private static (long Bytes, string Sha256) HashFile(string path)
    {
        var info = new FileInfo(path);
        if (info.Length > MaxSingleFileBytes) throw new InvalidDataException($"Lifecycle request package file exceeds the fixed single-file limit: {path}");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[128 * 1024];
        long total = 0;
        while (true)
        {
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0) break;
            total = checked(total + read);
            if (total > MaxSingleFileBytes) throw new InvalidDataException($"Lifecycle request package file exceeded its allowed size while hashing: {path}");
            hash.AppendData(buffer, 0, read);
        }
        if (total != info.Length) throw new InvalidOperationException($"Lifecycle request package file changed while hashing: {path}");
        return (total, Convert.ToHexString(hash.GetHashAndReset()));
    }

    private static string ValidateExistingNamedPackage(string root, string name, string parameterName)
    {
        ValidateFixedRoot(root);
        var leaf = ValidateSafeName(name, parameterName);
        var directory = Path.GetFullPath(Path.Combine(root, leaf));
        if (!IsUnderRoot(directory, root)) throw new UnauthorizedAccessException("Lifecycle request package escaped its fixed root.");
        if (!Directory.Exists(directory)) throw new DirectoryNotFoundException($"Lifecycle request package does not exist: {directory}");
        return ValidatePackageDirectory(directory);
    }

    private static string ValidatePackageDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            throw new ArgumentException("Lifecycle request package directory must be an absolute path.", nameof(path));
        var full = Path.GetFullPath(path);
        if (!IsUnderRoot(full, DevRoot)) throw new UnauthorizedAccessException("Lifecycle request package directory must remain under the v4 development root.");
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException($"Lifecycle request package directory does not exist: {full}");
        RequireNoReparseTraversal(full, DevRoot);
        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Lifecycle request package directory may not be a reparse point.");
        return full;
    }

    private static void ValidateFixedRoot(string root)
    {
        if (!Directory.Exists(root)) throw new DirectoryNotFoundException($"Fixed lifecycle request root does not exist: {root}");
        if (!IsUnderRoot(root, DevRoot)) throw new UnauthorizedAccessException("Lifecycle request fixed root escaped the v4 development root.");
        RequireNoReparseTraversal(root, DevRoot);
        if ((File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Lifecycle request fixed root may not be a reparse point.");
    }

    private static string ValidateSafeName(string name, string parameterName)
    {
        var value = (name ?? string.Empty).Trim();
        if (value.Length is < 1 or > 80) throw new ArgumentException("Lifecycle request package name must contain 1-80 characters.", parameterName);
        if (value is "." or ".." || !string.Equals(Path.GetFileName(value), value, StringComparison.Ordinal) || value.Any(char.IsControl) || value.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || value.EndsWith(' ') || value.EndsWith('.'))
            throw new ArgumentException("Lifecycle request package name must be a safe Windows leaf directory name.", parameterName);
        if (value.Any(ch => !(char.IsLetterOrDigit(ch) || ch is '-' or '_' or '.')))
            throw new ArgumentException("Lifecycle request package name accepts only letters, digits, dash, underscore, and dot.", parameterName);
        return value;
    }

    private static void ValidateRelativePath(string relative)
    {
        var parts = relative.Split('/');
        if (parts.Length == 0 || parts.Any(p => p.Length == 0 || p is "." or ".." || p.EndsWith(' ') || p.EndsWith('.') || p.Any(char.IsControl) || p.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0))
            throw new InvalidDataException($"Unsafe lifecycle request package relative path: {relative}");
    }

    private static void RequireNoReparseTraversal(string path, string boundaryRoot)
    {
        var boundary = Path.GetFullPath(boundaryRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var current = new DirectoryInfo(Directory.Exists(path) ? path : Path.GetDirectoryName(path)!);
        while (current is not null)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException($"Lifecycle request path may not traverse reparse-point directory: {current.FullName}");
            if (string.Equals(current.FullName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), boundary, StringComparison.OrdinalIgnoreCase)) return;
            current = current.Parent;
        }
        throw new UnauthorizedAccessException("Lifecycle request path boundary validation failed.");
    }

    private static string GetCurrentRuntimeDll()
    {
        var path = Path.GetFullPath(typeof(AgentLifecycleRequestTools).Assembly.Location);
        if (!File.Exists(path) || !string.Equals(Path.GetFileName(path), RuntimeFileName, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Current Agent runtime assembly path is invalid.");
        if (!IsUnderRoot(path, DevRoot)) throw new UnauthorizedAccessException("Current Agent runtime is outside the v4 development root.");
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Current Agent runtime may not be a reparse point.");
        return path;
    }

    private static Uri GetCurrentListenUri()
    {
        var value = Environment.GetEnvironmentVariable("YOWTHI_AGENT3_URL") ?? "http://127.0.0.1:8791";
        return ValidateLoopbackHttpUrl(value, "YOWTHI_AGENT3_URL");
    }

    private static Uri ValidateLoopbackHttpUrl(string value, string name)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttp || !uri.IsLoopback || uri.Port <= 0)
            throw new ArgumentException($"{name} must be an absolute loopback HTTP URL with explicit port.", name);
        return uri;
    }

    private static void RequireSameEndpoint(Uri listen, Uri health)
    {
        if (!string.Equals(listen.Host, health.Host, StringComparison.OrdinalIgnoreCase) || listen.Port != health.Port || !string.Equals(health.AbsolutePath.TrimEnd('/'), "/health", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Lifecycle request listen/health endpoint mismatch.");
    }

    private static async Task<HealthProbe> ProbeHealthAsync(Uri health)
    {
        try
        {
            using var response = await Http.GetAsync(health);
            if (!response.IsSuccessStatusCode) return new(false, null, null);
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var root = doc.RootElement;
            var service = root.TryGetProperty("service", out var s) && s.ValueKind == JsonValueKind.String ? s.GetString() : null;
            var status = root.TryGetProperty("status", out var st) && st.ValueKind == JsonValueKind.String ? st.GetString() : null;
            return new(string.Equals(service, "YowThi Development Agent 3", StringComparison.Ordinal) && string.Equals(status, "ok", StringComparison.OrdinalIgnoreCase), service, status);
        }
        catch
        {
            return new(false, null, null);
        }
    }

    private static Dictionary<string, string> PackageParameters(PackageSnapshot snapshot, string prefix)
        => new(StringComparer.Ordinal)
        {
            [$"{prefix}RuntimeDll"] = snapshot.RuntimeDll,
            [$"{prefix}RuntimeSha256"] = snapshot.RuntimeSha256,
            [$"{prefix}ManifestSha256"] = snapshot.ManifestSha256,
            [$"{prefix}ShapeSha256"] = snapshot.ShapeSha256,
            [$"{prefix}FileCount"] = snapshot.FileCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            [$"{prefix}DirectoryCount"] = snapshot.DirectoryCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            [$"{prefix}TotalBytes"] = snapshot.TotalBytes.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };

    private static void RequireSnapshotMatchesPlan(PackageSnapshot snapshot, SignedPlan plan, string prefix)
    {
        if (!string.Equals(snapshot.RuntimeDll, RequireParameter(plan, $"{prefix}RuntimeDll"), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(snapshot.RuntimeSha256, RequireParameter(plan, $"{prefix}RuntimeSha256"), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(snapshot.ManifestSha256, RequireParameter(plan, $"{prefix}ManifestSha256"), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(snapshot.ShapeSha256, RequireParameter(plan, $"{prefix}ShapeSha256"), StringComparison.OrdinalIgnoreCase) ||
            snapshot.FileCount != ParseInt(RequireParameter(plan, $"{prefix}FileCount"), $"{prefix}FileCount") ||
            snapshot.DirectoryCount != ParseInt(RequireParameter(plan, $"{prefix}DirectoryCount"), $"{prefix}DirectoryCount") ||
            snapshot.TotalBytes != ParseLong(RequireParameter(plan, $"{prefix}TotalBytes"), $"{prefix}TotalBytes"))
            throw new InvalidOperationException($"Lifecycle request {prefix} package changed after plan preparation.");
    }

    private static SignedPlan PreparePlan(string operation, string target, string summary, Dictionary<string, string> parameters)
    {
        var now = DateTimeOffset.UtcNow;
        var unsigned = new SignedPlan(
            1,
            Guid.NewGuid().ToString("N"),
            Convert.ToHexString(RandomNumberGenerator.GetBytes(6)),
            "agent-lifecycle-request",
            operation,
            target,
            parameters,
            RiskClass.Medium,
            summary,
            now,
            now.AddMinutes(10),
            string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    private static void RequireIntentMatch(SignedPlan plan, string expectedOperation, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "agent-lifecycle-request", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Agent lifecycle request plan execution intent mismatch.");
    }

    private static string RequireParameter(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidDataException($"Signed lifecycle request parameter {key} is required.");

    private static int ParseInt(string value, string name)
        => int.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var result) && result >= 0 && result <= MaxEntries
            ? result
            : throw new InvalidDataException($"Signed lifecycle request integer {name} is invalid.");

    private static long ParseLong(string value, string name)
        => long.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var result) && result >= 0 && result <= MaxPackageBytes
            ? result
            : throw new InvalidDataException($"Signed lifecycle request length {name} is invalid.");

    private static string HashCanonical(IEnumerable<string> lines)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", lines))));

    private static string Sha256File(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string NormalizeUrl(Uri uri) => uri.GetLeftPart(UriPartial.Authority).TrimEnd('/');

    private static bool IsUnderRoot(string path, string root)
    {
        var fullPath = Path.GetFullPath(path);
        var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return string.Equals(fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), fullRoot, StringComparison.OrdinalIgnoreCase) ||
               fullPath.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static void EnsureEntryLimit(int count)
    {
        if (count > MaxEntries) throw new InvalidDataException("Agent lifecycle request package exceeds the fixed entry-count limit.");
    }

    private sealed record PackageEntry(string RelativePath, bool IsDirectory, long Length, string Sha256);
    private sealed record PackageSnapshot(string Directory, string RuntimeDll, string RuntimeSha256, string ManifestSha256, string ShapeSha256, int FileCount, int DirectoryCount, long TotalBytes);
    private sealed record HealthProbe(bool Healthy, string? Service, string? Status);
}

public sealed record AgentLifecycleRequestStageResult(
    string PlanId,
    string RequestedAction,
    string RequestPath,
    string CurrentDirectory,
    string CurrentRuntimeSha256,
    string TargetDirectory,
    string TargetRuntimeSha256,
    bool ProcessAuthorization,
    bool RequiresSeparateRuntimePlans,
    string Outcome,
    DateTimeOffset ExecutedUtc);
