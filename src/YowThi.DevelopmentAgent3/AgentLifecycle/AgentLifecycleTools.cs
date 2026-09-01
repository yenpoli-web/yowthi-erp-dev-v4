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
public static class AgentLifecycleTools
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string LifecycleRoot = @"C:\Dev\YowThi-ERP-Dev-v4\acceptance\agent-lifecycle";
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

    [McpServerTool(Name = "agent_lifecycle_status", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read YowThi Development Agent 3 lifecycle status for the currently executing Agent assembly. The result includes current runtime DLL path/SHA-256, process identity, loopback listen/health URLs, health payload version/status, current package classification, and fixed lifecycle queue counts. This is read-only and does not stage, update, rollback, start, stop, copy, delete, or modify any process or file.")]
    public static async Task<AgentLifecycleStatusResult> AgentLifecycleStatus()
    {
        ValidateFixedRoots();
        var runtimeDll = GetCurrentRuntimeDll();
        var runtimeSha = Sha256File(runtimeDll);
        var listen = GetCurrentListenUri();
        var health = GetHealthUri(listen);
        var probe = await ProbeHealthAsync(health);
        var packageDir = Path.GetDirectoryName(runtimeDll)!;
        return new AgentLifecycleStatusResult(
            runtimeDll,
            runtimeSha,
            GetAssemblyVersion(runtimeDll),
            Environment.ProcessId,
            NormalizeUrl(listen),
            health.ToString(),
            probe.Healthy,
            probe.Service,
            probe.Version,
            probe.Status,
            probe.Machine,
            ClassifyPackage(packageDir),
            CountDirectDirectories(ReleaseRoot),
            CountDirectDirectories(RollbackRoot),
            CountPendingRequests(),
            DateTimeOffset.UtcNow);
    }

    [McpServerTool(Name = "agent_lifecycle_diagnostics", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read bounded Agent lifecycle diagnostics. It computes a deterministic manifest/shape fingerprint for the currently executing Agent package and lists only direct fixed lifecycle release/rollback directory names and pending request file names. Reparse points are rejected. No shell, PowerShell, cmd, process mutation, update, rollback, copy, move, or deletion is performed.")]
    public static AgentLifecycleDiagnosticsResult AgentLifecycleDiagnostics()
    {
        ValidateFixedRoots();
        var runtimeDll = GetCurrentRuntimeDll();
        var packageDir = Path.GetDirectoryName(runtimeDll)!;
        var snapshot = ComputePackageSnapshot(packageDir);
        return new AgentLifecycleDiagnosticsResult(
            packageDir,
            snapshot.RuntimeDll,
            snapshot.RuntimeSha256,
            snapshot.ManifestSha256,
            snapshot.ShapeSha256,
            snapshot.FileCount,
            snapshot.DirectoryCount,
            snapshot.TotalBytes,
            ListDirectDirectoryNames(ReleaseRoot),
            ListDirectDirectoryNames(RollbackRoot),
            ListPendingRequestNames(),
            DateTimeOffset.UtcNow);
    }

    [McpServerTool(Name = "agent_release_verify", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Verify one candidate YowThi Development Agent 3 package directory under the v4 development root. The candidate must be outside the fixed lifecycle release/rollback store, contain the fixed runtime DLL plus deps/runtimeconfig files, remain free of reparse traversal, and satisfy bounded package entry/size limits. Every file is SHA-256 hashed and canonical package manifest/shape fingerprints are returned. This is read-only.")]
    public static AgentReleaseVerificationResult AgentReleaseVerify(string candidateDirectory)
    {
        var candidate = ValidateCandidateDirectory(candidateDirectory);
        var snapshot = ComputePackageSnapshot(candidate);
        return ToVerification(candidate, snapshot);
    }

    [McpServerTool(Name = "agent_release_stage_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed Medium-risk plan to stage one verified Agent package directory into one new direct release directory under the fixed Agent lifecycle release store. Candidate package manifest/shape, runtime SHA-256, counts, total bytes, exact source/destination, safe release name, and destination absence are sealed. Overwrite, arbitrary destinations, production paths, shell execution, and process changes are not supported.")]
    public static SignedPlan AgentReleaseStagePlan(string candidateDirectory, string releaseName)
    {
        ValidateFixedRoots();
        var source = ValidateCandidateDirectory(candidateDirectory);
        var snapshot = ComputePackageSnapshot(source);
        var destination = ValidateNewNamedDestination(ReleaseRoot, releaseName, nameof(releaseName));
        var parameters = PackageParameters(snapshot, "source");
        parameters["sourceDirectory"] = source;
        parameters["releaseName"] = Path.GetFileName(destination);
        parameters["destinationDirectory"] = destination;
        parameters["destinationAbsent"] = "true";
        return PreparePlan("stage-release", destination, RiskClass.Medium,
            $"Stage Agent release {Path.GetFileName(destination)} from {source} ({snapshot.FileCount} files, {snapshot.TotalBytes} bytes)", parameters);
    }

    [McpServerTool(Name = "agent_release_stage_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared agent-lifecycle/stage-release plan. Exact signed intent, candidate package manifest/shape/runtime SHA-256, fixed release-store identity, safe release name, destination absence, bounded package policy, and reparse policy are revalidated. Files are copied with CreateNew semantics and streamed SHA-256 checks; post-copy package manifest/shape must exactly match the signed source. No process is started or stopped.")]
    public static AgentPackageCopyResult AgentReleaseStageExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
        => ExecutePackageCopy(planId, approvalCode, operation, target, summary, riskClass, "stage-release", ReleaseRoot, "releaseName");

    [McpServerTool(Name = "agent_release_backup_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed Medium-risk plan to back up the currently executing Agent package into one new direct directory under the fixed lifecycle rollback store. The exact current runtime/package identity, complete package manifest/shape, runtime SHA-256, counts, bytes, safe backup name, and destination absence are sealed. This does not stop, restart, or update the Agent.")]
    public static SignedPlan AgentReleaseBackupPlan(string backupName)
    {
        ValidateFixedRoots();
        var runtimeDll = GetCurrentRuntimeDll();
        var source = Path.GetDirectoryName(runtimeDll)!;
        ValidatePackageDirectory(source, requireUnderDevRoot: true);
        var snapshot = ComputePackageSnapshot(source);
        var destination = ValidateNewNamedDestination(RollbackRoot, backupName, nameof(backupName));
        var parameters = PackageParameters(snapshot, "source");
        parameters["sourceDirectory"] = source;
        parameters["backupName"] = Path.GetFileName(destination);
        parameters["destinationDirectory"] = destination;
        parameters["destinationAbsent"] = "true";
        parameters["currentRuntimeDll"] = runtimeDll;
        return PreparePlan("backup-current", destination, RiskClass.Medium,
            $"Back up current Agent package to rollback slot {Path.GetFileName(destination)} ({snapshot.FileCount} files, {snapshot.TotalBytes} bytes)", parameters);
    }

    [McpServerTool(Name = "agent_release_backup_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared agent-lifecycle/backup-current plan. The currently executing runtime path, signed package manifest/shape/runtime SHA-256, fixed rollback-store identity, destination absence, and bounded/reparse policy are revalidated before a CreateNew verified package copy is made. Post-copy manifest/shape must exactly match. No process is stopped or restarted.")]
    public static AgentPackageCopyResult AgentReleaseBackupExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "backup-current", operation, target, summary, riskClass);
        var currentRuntime = GetCurrentRuntimeDll();
        if (!string.Equals(currentRuntime, RequireParameter(plan, "currentRuntimeDll"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Current Agent runtime changed after backup plan preparation.");
        return ExecutePackageCopyValidatedPlan(plan, planId, "backup-current", RollbackRoot, "backupName");
    }

    private static AgentPackageCopyResult ExecutePackageCopy(string planId, string approvalCode, string operation, string target, string summary, string riskClass, string expectedOperation, string destinationRoot, string nameParameter)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, expectedOperation, operation, target, summary, riskClass);
        return ExecutePackageCopyValidatedPlan(plan, planId, expectedOperation, destinationRoot, nameParameter);
    }

    private static AgentPackageCopyResult ExecutePackageCopyValidatedPlan(SignedPlan plan, string planId, string expectedOperation, string destinationRoot, string nameParameter)
    {
        ValidateFixedRoots();
        var source = RequireParameter(plan, "sourceDirectory");
        if (expectedOperation == "stage-release") source = ValidateCandidateDirectory(source);
        else ValidatePackageDirectory(source, requireUnderDevRoot: true);
        var current = ComputePackageSnapshot(source);
        RequireSnapshotMatchesPlan(current, plan, "source");

        var destination = ValidateNewNamedDestination(destinationRoot, RequireParameter(plan, nameParameter), nameParameter);
        if (!string.Equals(destination, RequireParameter(plan, "destinationDirectory"), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(destination, plan.Target, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(RequireParameter(plan, "destinationAbsent"), "true", StringComparison.Ordinal))
            throw new InvalidOperationException("Lifecycle package destination no longer matches the signed plan.");

        try
        {
            CopyPackageVerified(source, destination, current);
            var final = ComputePackageSnapshot(destination);
            RequireSnapshotEqual(current, final, "Lifecycle package post-copy verification failed.");
            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, source, destination, final.RuntimeSha256, final.ManifestSha256, final.ShapeSha256, final.FileCount, final.TotalBytes, outcome = "package-copied" }, "executed");
            return new AgentPackageCopyResult(plan.PlanId, expectedOperation, source, destination, final.RuntimeDll, final.RuntimeSha256, final.ManifestSha256, final.ShapeSha256, final.FileCount, final.DirectoryCount, final.TotalBytes, "package-copied", DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            try { if (Directory.Exists(destination)) SafeDeleteTree(destination); } catch { }
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, source, destination, error = ex.Message }, "failed");
            throw;
        }
    }

    private static void CopyPackageVerified(string source, string destination, PackageSnapshot snapshot)
    {
        if (File.Exists(destination) || Directory.Exists(destination)) throw new IOException("Lifecycle destination already exists.");
        Directory.CreateDirectory(destination);
        foreach (var entry in snapshot.Entries.Where(x => x.IsDirectory).OrderBy(x => x.RelativePath.Count(c => c == '/')).ThenBy(x => x.RelativePath, StringComparer.Ordinal))
            Directory.CreateDirectory(Path.Combine(destination, entry.RelativePath.Replace('/', Path.DirectorySeparatorChar)));

        foreach (var entry in snapshot.Entries.Where(x => !x.IsDirectory).OrderBy(x => x.RelativePath, StringComparer.Ordinal))
        {
            var target = Path.Combine(destination, entry.RelativePath.Replace('/', Path.DirectorySeparatorChar));
            var parent = Path.GetDirectoryName(target)!;
            Directory.CreateDirectory(parent);
            using var input = new FileStream(entry.FullPath!, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[128 * 1024];
            long copied = 0;
            while (true)
            {
                var read = input.Read(buffer, 0, buffer.Length);
                if (read == 0) break;
                copied = checked(copied + read);
                if (copied > entry.Length || copied > MaxSingleFileBytes) throw new InvalidOperationException($"Lifecycle source changed while copying {entry.RelativePath}.");
                hash.AppendData(buffer, 0, read);
                output.Write(buffer, 0, read);
            }
            output.Flush(flushToDisk: true);
            var sha = Convert.ToHexString(hash.GetHashAndReset());
            if (copied != entry.Length || !string.Equals(sha, entry.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"Lifecycle source changed while copying {entry.RelativePath}.");
        }
    }

    private static PackageSnapshot ComputePackageSnapshot(string directory)
    {
        ValidatePackageDirectory(directory, requireUnderDevRoot: true);
        var root = Path.GetFullPath(directory);
        var entries = new List<PackageEntry>();
        var stack = new Stack<string>();
        stack.Push(root);
        long totalBytes = 0;
        var fileCount = 0;
        var directoryCount = 0;

        while (stack.Count > 0)
        {
            var current = stack.Pop();
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException($"Lifecycle package may not traverse reparse-point directory: {current}");
            foreach (var path in Directory.EnumerateFileSystemEntries(current, "*", SearchOption.TopDirectoryOnly))
            {
                var attributes = File.GetAttributes(path);
                if ((attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException($"Lifecycle package may not contain reparse-point entry: {path}");
                var relative = Path.GetRelativePath(root, path).Replace('\\', '/');
                ValidateRelativePath(relative);
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    directoryCount++;
                    EnsureEntryLimit(entries.Count + 1);
                    entries.Add(new PackageEntry(relative, path, true, 0, string.Empty));
                    stack.Push(path);
                }
                else
                {
                    var state = HashFile(path);
                    totalBytes = checked(totalBytes + state.Bytes);
                    if (totalBytes > MaxPackageBytes) throw new InvalidDataException("Agent lifecycle package exceeds the fixed total byte limit.");
                    fileCount++;
                    EnsureEntryLimit(entries.Count + 1);
                    entries.Add(new PackageEntry(relative, path, false, state.Bytes, state.Sha256));
                }
            }
        }

        entries.Sort((a, b) => StringComparer.Ordinal.Compare(a.RelativePath, b.RelativePath));
        var runtimeDll = Path.Combine(root, RuntimeFileName);
        var deps = Path.Combine(root, DepsFileName);
        var runtimeConfig = Path.Combine(root, RuntimeConfigFileName);
        if (!File.Exists(runtimeDll) || !File.Exists(deps) || !File.Exists(runtimeConfig))
            throw new InvalidDataException("Agent lifecycle package must contain the fixed runtime DLL, deps.json, and runtimeconfig.json at package root.");
        var assemblyName = AssemblyName.GetAssemblyName(runtimeDll);
        if (!string.Equals(assemblyName.Name, "YowThi.DevelopmentAgent3", StringComparison.Ordinal))
            throw new InvalidDataException("Lifecycle runtime assembly identity is not YowThi.DevelopmentAgent3.");
        var runtimeSha = Sha256File(runtimeDll);
        var manifestLines = entries.Select(e => e.IsDirectory ? $"D|{e.RelativePath}" : $"F|{e.RelativePath}|{e.Length}|{e.Sha256}");
        var shapeLines = entries.Select(e => e.IsDirectory ? $"D|{e.RelativePath}" : $"F|{e.RelativePath}|{e.Length}");
        return new PackageSnapshot(root, runtimeDll, runtimeSha, GetAssemblyVersion(runtimeDll), HashCanonical(manifestLines), HashCanonical(shapeLines), fileCount, directoryCount, totalBytes, entries);
    }

    private static (long Bytes, string Sha256) HashFile(string path)
    {
        var info = new FileInfo(path);
        if (info.Length > MaxSingleFileBytes) throw new InvalidDataException($"Lifecycle package file exceeds the fixed single-file limit: {path}");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[128 * 1024];
        long total = 0;
        while (true)
        {
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0) break;
            total = checked(total + read);
            if (total > MaxSingleFileBytes) throw new InvalidDataException($"Lifecycle package file exceeded its allowed size while hashing: {path}");
            hash.AppendData(buffer, 0, read);
        }
        if (total != info.Length) throw new InvalidOperationException($"Lifecycle package file changed while hashing: {path}");
        return (total, Convert.ToHexString(hash.GetHashAndReset()));
    }

    private static string ValidateCandidateDirectory(string path)
    {
        var full = ValidatePackageDirectory(path, requireUnderDevRoot: true);
        if (IsUnderRoot(full, LifecycleRoot)) throw new UnauthorizedAccessException("Candidate packages may not originate from the lifecycle release/rollback store.");
        return full;
    }

    private static string ValidatePackageDirectory(string path, bool requireUnderDevRoot)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)) throw new ArgumentException("Lifecycle package directory must be an absolute path.", nameof(path));
        var full = Path.GetFullPath(path);
        if (requireUnderDevRoot && !IsUnderRoot(full, DevRoot)) throw new UnauthorizedAccessException("Lifecycle package directory must remain under the v4 development root.");
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException($"Lifecycle package directory does not exist: {full}");
        RequireNoReparseTraversal(full, DevRoot);
        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Lifecycle package directory may not be a reparse point.");
        return full;
    }

    private static string ValidateNewNamedDestination(string root, string name, string parameterName)
    {
        ValidateFixedRoot(root);
        var leaf = ValidateSafeName(name, parameterName);
        var destination = Path.GetFullPath(Path.Combine(root, leaf));
        if (!IsUnderRoot(destination, root)) throw new UnauthorizedAccessException("Lifecycle destination escaped its fixed root.");
        if (File.Exists(destination) || Directory.Exists(destination)) throw new IOException("Lifecycle destination already exists.");
        return destination;
    }

    private static string ValidateSafeName(string name, string parameterName)
    {
        var value = (name ?? string.Empty).Trim();
        if (value.Length is < 1 or > 80) throw new ArgumentException("Lifecycle package name must contain 1-80 characters.", parameterName);
        if (value is "." or ".." || !string.Equals(Path.GetFileName(value), value, StringComparison.Ordinal) || value.Any(char.IsControl) || value.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || value.EndsWith(' ') || value.EndsWith('.'))
            throw new ArgumentException("Lifecycle package name must be a safe Windows leaf directory name.", parameterName);
        if (value.Any(ch => !(char.IsLetterOrDigit(ch) || ch is '-' or '_' or '.'))) throw new ArgumentException("Lifecycle package name accepts only letters, digits, dash, underscore, and dot.", parameterName);
        return value;
    }

    private static void ValidateRelativePath(string relative)
    {
        var parts = relative.Split('/');
        if (parts.Length == 0 || parts.Any(p => p.Length == 0 || p is "." or ".." || p.EndsWith(' ') || p.EndsWith('.') || p.Any(char.IsControl) || p.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0))
            throw new InvalidDataException($"Unsafe lifecycle package relative path: {relative}");
    }

    private static void ValidateFixedRoots()
    {
        ValidateFixedRoot(ReleaseRoot);
        ValidateFixedRoot(RollbackRoot);
        ValidateFixedRoot(PendingRoot);
    }

    private static void ValidateFixedRoot(string root)
    {
        if (!Directory.Exists(root)) throw new DirectoryNotFoundException($"Fixed lifecycle root does not exist: {root}");
        if (!IsUnderRoot(root, DevRoot)) throw new UnauthorizedAccessException("Lifecycle fixed root escaped the v4 development root.");
        RequireNoReparseTraversal(root, DevRoot);
        if ((File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Lifecycle fixed root may not be a reparse point.");
    }

    private static void RequireNoReparseTraversal(string path, string boundaryRoot)
    {
        var boundary = Path.GetFullPath(boundaryRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var current = new DirectoryInfo(Directory.Exists(path) ? path : Path.GetDirectoryName(path)!);
        while (current is not null)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException($"Lifecycle path may not traverse reparse-point directory: {current.FullName}");
            if (string.Equals(current.FullName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), boundary, StringComparison.OrdinalIgnoreCase)) return;
            current = current.Parent;
        }
        throw new UnauthorizedAccessException("Lifecycle path boundary validation failed.");
    }

    private static string GetCurrentRuntimeDll()
    {
        var path = Path.GetFullPath(typeof(AgentLifecycleTools).Assembly.Location);
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

    private static Uri GetHealthUri(Uri listen) => new($"{NormalizeUrl(listen)}/health");

    private static Uri ValidateLoopbackHttpUrl(string value, string name)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttp || !uri.IsLoopback || uri.Port <= 0)
            throw new ArgumentException($"{name} must be an absolute loopback HTTP URL with explicit port.", name);
        return uri;
    }

    private static async Task<HealthProbe> ProbeHealthAsync(Uri health)
    {
        try
        {
            using var response = await Http.GetAsync(health);
            if (!response.IsSuccessStatusCode) return new(false, null, null, null, null);
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var root = doc.RootElement;
            var service = GetString(root, "service");
            var version = GetString(root, "version");
            var status = GetString(root, "status");
            var machine = GetString(root, "machine");
            return new(string.Equals(service, "YowThi Development Agent 3", StringComparison.Ordinal) && string.Equals(status, "ok", StringComparison.OrdinalIgnoreCase), service, version, status, machine);
        }
        catch { return new(false, null, null, null, null); }
    }

    private static string? GetString(JsonElement root, string name)
        => root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

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
            throw new InvalidOperationException($"Lifecycle {prefix} package changed after plan preparation.");
    }

    private static void RequireSnapshotEqual(PackageSnapshot expected, PackageSnapshot current, string message)
    {
        if (!string.Equals(expected.RuntimeSha256, current.RuntimeSha256, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expected.ManifestSha256, current.ManifestSha256, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expected.ShapeSha256, current.ShapeSha256, StringComparison.OrdinalIgnoreCase) ||
            expected.FileCount != current.FileCount || expected.DirectoryCount != current.DirectoryCount || expected.TotalBytes != current.TotalBytes)
            throw new InvalidOperationException(message);
    }

    private static SignedPlan PreparePlan(string operation, string target, RiskClass risk, string summary, Dictionary<string, string> parameters)
    {
        var now = DateTimeOffset.UtcNow;
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "agent-lifecycle", operation, target, parameters, risk, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    private static void RequireIntentMatch(SignedPlan plan, string expectedOperation, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "agent-lifecycle", StringComparison.Ordinal) || !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal) || !string.Equals(plan.Operation, operation, StringComparison.Ordinal) || !string.Equals(plan.Target, target, StringComparison.OrdinalIgnoreCase) || !string.Equals(plan.Summary, summary, StringComparison.Ordinal) || !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Agent lifecycle plan execution intent mismatch.");
    }

    private static string RequireParameter(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : throw new InvalidDataException($"Signed lifecycle parameter {key} is required.");

    private static int ParseInt(string value, string name)
        => int.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var result) && result >= 0 && result <= MaxEntries ? result : throw new InvalidDataException($"Signed lifecycle integer {name} is invalid.");

    private static long ParseLong(string value, string name)
        => long.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var result) && result >= 0 && result <= MaxPackageBytes ? result : throw new InvalidDataException($"Signed lifecycle length {name} is invalid.");

    private static string HashCanonical(IEnumerable<string> lines)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", lines))));

    private static string Sha256File(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string GetAssemblyVersion(string runtimeDll)
    {
        var assembly = AssemblyName.GetAssemblyName(runtimeDll);
        return assembly.Version?.ToString() ?? string.Empty;
    }

    private static string NormalizeUrl(Uri uri) => uri.GetLeftPart(UriPartial.Authority).TrimEnd('/');

    private static bool IsUnderRoot(string path, string root)
    {
        var fullPath = Path.GetFullPath(path);
        var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return string.Equals(fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), fullRoot, StringComparison.OrdinalIgnoreCase) || fullPath.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static void EnsureEntryLimit(int count)
    {
        if (count > MaxEntries) throw new InvalidDataException("Agent lifecycle package exceeds the fixed entry-count limit.");
    }

    private static string ClassifyPackage(string packageDirectory)
    {
        if (IsUnderRoot(packageDirectory, ReleaseRoot)) return "staged-release";
        if (IsUnderRoot(packageDirectory, RollbackRoot)) return "rollback-backup";
        return "development-build";
    }

    private static int CountDirectDirectories(string root) => Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly).Take(501).Count();
    private static int CountPendingRequests() => Directory.EnumerateFiles(PendingRoot, "*.json", SearchOption.TopDirectoryOnly).Take(501).Count();

    private static IReadOnlyList<string> ListDirectDirectoryNames(string root)
    {
        ValidateFixedRoot(root);
        return Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly).Select(Path.GetFileName).Where(x => x is not null).Cast<string>().OrderBy(x => x, StringComparer.OrdinalIgnoreCase).Take(100).ToArray();
    }

    private static IReadOnlyList<string> ListPendingRequestNames()
    {
        ValidateFixedRoot(PendingRoot);
        return Directory.EnumerateFiles(PendingRoot, "*.json", SearchOption.TopDirectoryOnly).Select(Path.GetFileName).Where(x => x is not null).Cast<string>().OrderBy(x => x, StringComparer.OrdinalIgnoreCase).Take(100).ToArray();
    }

    private static AgentReleaseVerificationResult ToVerification(string directory, PackageSnapshot snapshot)
        => new(directory, snapshot.RuntimeDll, snapshot.RuntimeSha256, snapshot.AssemblyVersion, snapshot.ManifestSha256, snapshot.ShapeSha256, snapshot.FileCount, snapshot.DirectoryCount, snapshot.TotalBytes, DateTimeOffset.UtcNow);

    private static void SafeDeleteTree(string root)
    {
        var info = new DirectoryInfo(root);
        if (!info.Exists) return;
        foreach (var entry in info.EnumerateFileSystemInfos())
        {
            if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                if ((entry.Attributes & FileAttributes.Directory) != 0) Directory.Delete(entry.FullName, false); else File.Delete(entry.FullName);
                continue;
            }
            if ((entry.Attributes & FileAttributes.Directory) != 0) SafeDeleteTree(entry.FullName); else File.Delete(entry.FullName);
        }
        Directory.Delete(root, false);
    }

    private sealed record PackageEntry(string RelativePath, string? FullPath, bool IsDirectory, long Length, string Sha256);
    private sealed record PackageSnapshot(string Directory, string RuntimeDll, string RuntimeSha256, string AssemblyVersion, string ManifestSha256, string ShapeSha256, int FileCount, int DirectoryCount, long TotalBytes, IReadOnlyList<PackageEntry> Entries);
    private sealed record HealthProbe(bool Healthy, string? Service, string? Version, string? Status, string? Machine);
}

public sealed record AgentLifecycleStatusResult(string RuntimeDll, string RuntimeSha256, string AssemblyVersion, int ProcessId, string ListenUrl, string HealthUrl, bool Healthy, string? Service, string? HealthVersion, string? Status, string? Machine, string PackageClass, int StagedReleaseCount, int RollbackBackupCount, int PendingRequestCount, DateTimeOffset CheckedUtc);
public sealed record AgentLifecycleDiagnosticsResult(string CurrentPackageDirectory, string RuntimeDll, string RuntimeSha256, string ManifestSha256, string ShapeSha256, int FileCount, int DirectoryCount, long TotalBytes, IReadOnlyList<string> StagedReleases, IReadOnlyList<string> RollbackBackups, IReadOnlyList<string> PendingRequests, DateTimeOffset CheckedUtc);
public sealed record AgentReleaseVerificationResult(string CandidateDirectory, string RuntimeDll, string RuntimeSha256, string AssemblyVersion, string ManifestSha256, string ShapeSha256, int FileCount, int DirectoryCount, long TotalBytes, DateTimeOffset CheckedUtc);
public sealed record AgentPackageCopyResult(string PlanId, string Operation, string SourceDirectory, string DestinationDirectory, string RuntimeDll, string RuntimeSha256, string ManifestSha256, string ShapeSha256, int FileCount, int DirectoryCount, long TotalBytes, string Outcome, DateTimeOffset ExecutedUtc);
