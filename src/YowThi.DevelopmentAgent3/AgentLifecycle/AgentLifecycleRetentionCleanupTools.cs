using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.AgentLifecycle;

[McpServerToolType]
public static class AgentLifecycleRetentionCleanupTools
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string ReleaseRoot = @"C:\Dev\YowThi-ERP-Dev-v4\acceptance\agent-lifecycle\releases";
    private const string RollbackRoot = @"C:\Dev\YowThi-ERP-Dev-v4\acceptance\agent-lifecycle\rollback";
    private const string PendingRoot = @"C:\Dev\YowThi-ERP-Dev-v4\.agent3-lifecycle\pending";
    private const string RuntimeFileName = "YowThi.DevelopmentAgent3.dll";
    private const int MaxEntries = 10_000;
    private const long MaxPackageBytes = 4L * 1024 * 1024 * 1024;
    private const long MaxSingleFileBytes = 2L * 1024 * 1024 * 1024;
    private const long MaxRequestBytes = 128 * 1024;

    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name = "agent_lifecycle_release_cleanup_inventory", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Inventory direct Agent lifecycle releases under the fixed release store and classify retention eligibility. Current runtime package, the two newest other releases, any package whose runtime SHA-256 is referenced by a pending lifecycle request, reparse-point packages, invalid packages, and running-process referenced packages are protected. This is read-only.")]
    public static AgentLifecycleRetentionInventoryResult AgentLifecycleReleaseCleanupInventory()
        => BuildInventory(ReleaseRoot, "release", protectNewestCount: 2, protectPendingRuntimeHashes: true);

    [McpServerTool(Name = "agent_lifecycle_release_cleanup_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed Medium-risk plan to delete exactly one release classified eligible by the fixed lifecycle retention policy. Caller supplies only the direct release name. Exact package manifest, runtime SHA-256, retention classification, pending references, fixed-root identity, running-process exclusion, and reparse policy are sealed. Current/recent/referenced packages and arbitrary paths are rejected.")]
    public static SignedPlan AgentLifecycleReleaseCleanupPlan(string releaseName)
        => PrepareCleanupPlan(ReleaseRoot, "release", releaseName, protectNewestCount: 2, protectPendingRuntimeHashes: true);

    [McpServerTool(Name = "agent_lifecycle_release_cleanup_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared fixed lifecycle release cleanup plan using only native File.Delete and non-recursive Directory.Delete. Exact package identity, manifest, retention classification, pending references, running-process exclusion, fixed root and reparse policy are revalidated immediately before deletion. Only planId and approvalCode are accepted.")]
    public static AgentLifecycleRetentionCleanupResult AgentLifecycleReleaseCleanupExecute(string planId, string approvalCode)
        => ExecuteCleanup(planId, approvalCode, ReleaseRoot, "release", protectNewestCount: 2, protectPendingRuntimeHashes: true);

    [McpServerTool(Name = "agent_lifecycle_rollback_cleanup_inventory", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Inventory direct Agent lifecycle rollback backups under the fixed rollback store and classify retention eligibility. The two newest rollback backups, any package whose runtime SHA-256 is referenced by a pending lifecycle request, reparse-point packages, invalid packages, and running-process referenced packages are protected. This is read-only.")]
    public static AgentLifecycleRetentionInventoryResult AgentLifecycleRollbackCleanupInventory()
        => BuildInventory(RollbackRoot, "rollback", protectNewestCount: 2, protectPendingRuntimeHashes: true);

    [McpServerTool(Name = "agent_lifecycle_rollback_cleanup_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed Medium-risk plan to delete exactly one rollback backup classified eligible by the fixed lifecycle retention policy. Caller supplies only the direct rollback name. Exact package manifest, runtime SHA-256, retention classification, pending references, fixed-root identity, running-process exclusion, and reparse policy are sealed. Recent/referenced packages and arbitrary paths are rejected.")]
    public static SignedPlan AgentLifecycleRollbackCleanupPlan(string backupName)
        => PrepareCleanupPlan(RollbackRoot, "rollback", backupName, protectNewestCount: 2, protectPendingRuntimeHashes: true);

    [McpServerTool(Name = "agent_lifecycle_rollback_cleanup_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared fixed lifecycle rollback cleanup plan using only native File.Delete and non-recursive Directory.Delete. Exact package identity, manifest, retention classification, pending references, running-process exclusion, fixed root and reparse policy are revalidated immediately before deletion. Only planId and approvalCode are accepted.")]
    public static AgentLifecycleRetentionCleanupResult AgentLifecycleRollbackCleanupExecute(string planId, string approvalCode)
        => ExecuteCleanup(planId, approvalCode, RollbackRoot, "rollback", protectNewestCount: 2, protectPendingRuntimeHashes: true);

    private static AgentLifecycleRetentionInventoryResult BuildInventory(string root, string kind, int protectNewestCount, bool protectPendingRuntimeHashes)
    {
        ValidateFixedRoot(root);
        var currentPackage = Path.GetFullPath(Path.GetDirectoryName(typeof(AgentLifecycleRetentionCleanupTools).Assembly.Location)!);
        var pending = ReadPendingRuntimeReferences();
        var directories = Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly)
            .Select(Path.GetFullPath)
            .OrderByDescending(p => Directory.GetLastWriteTimeUtc(p))
            .ThenByDescending(p => p, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var protectedRecent = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in directories)
        {
            if (string.Equals(path, currentPackage, StringComparison.OrdinalIgnoreCase)) continue;
            if (protectedRecent.Count >= protectNewestCount) break;
            protectedRecent.Add(path);
        }

        var items = new List<AgentLifecycleRetentionCandidate>();
        foreach (var path in directories)
        {
            var name = Path.GetFileName(path);
            try
            {
                var snapshot = Snapshot(path);
                var reasons = new List<string>();
                if (string.Equals(path, currentPackage, StringComparison.OrdinalIgnoreCase)) reasons.Add("current-runtime");
                if (protectedRecent.Contains(path)) reasons.Add("recent-retention");
                if (protectPendingRuntimeHashes && pending.RuntimeHashes.Contains(snapshot.RuntimeSha256)) reasons.Add("pending-request-reference");
                if (IsReferencedByRunningProcess(path)) reasons.Add("running-process-reference");
                items.Add(new(name, path, snapshot.RuntimeSha256, snapshot.ManifestSha256, snapshot.FileCount, snapshot.DirectoryCount, snapshot.TotalBytes,
                    reasons.Count == 0, reasons.Count == 0 ? "eligible" : string.Join(',', reasons), Directory.GetLastWriteTimeUtc(path)));
            }
            catch (Exception ex)
            {
                items.Add(new(name, path, string.Empty, string.Empty, 0, 0, 0, false, $"invalid-package:{ex.GetType().Name}", Directory.GetLastWriteTimeUtc(path)));
            }
        }
        return new(kind, items.Count, items.Count(x => x.EligibleForCleanup), items, pending.RequestNames, DateTimeOffset.UtcNow);
    }

    private static SignedPlan PrepareCleanupPlan(string root, string kind, string name, int protectNewestCount, bool protectPendingRuntimeHashes)
    {
        var leaf = ValidateSafeName(name, nameof(name));
        var inventory = BuildInventory(root, kind, protectNewestCount, protectPendingRuntimeHashes);
        var candidate = inventory.Candidates.SingleOrDefault(x => string.Equals(x.Name, leaf, StringComparison.OrdinalIgnoreCase))
            ?? throw new DirectoryNotFoundException($"Lifecycle {kind} package not found: {leaf}");
        if (!candidate.EligibleForCleanup) throw new InvalidOperationException($"Lifecycle {kind} package is protected by retention policy: {candidate.Classification}");
        var snapshot = Snapshot(candidate.Path);
        if (IsReferencedByRunningProcess(candidate.Path)) throw new InvalidOperationException("Lifecycle package is referenced by a running process.");
        var pending = ReadPendingRuntimeReferences();
        if (protectPendingRuntimeHashes && pending.RuntimeHashes.Contains(snapshot.RuntimeSha256)) throw new InvalidOperationException("Lifecycle package is referenced by a pending request.");

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["kind"] = kind,
            ["name"] = leaf,
            ["path"] = candidate.Path,
            ["runtimeSha256"] = snapshot.RuntimeSha256,
            ["manifestSha256"] = snapshot.ManifestSha256,
            ["shapeSha256"] = snapshot.ShapeSha256,
            ["fileCount"] = snapshot.FileCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["directoryCount"] = snapshot.DirectoryCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["totalBytes"] = snapshot.TotalBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["classification"] = "eligible",
            ["pendingFingerprint"] = pending.Fingerprint,
            ["retentionNewestCount"] = protectNewestCount.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };
        var now = DateTimeOffset.UtcNow;
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)),
            "agent-lifecycle-retention-cleanup", $"delete-{kind}", candidate.Path, parameters, RiskClass.Medium,
            $"Delete one lifecycle {kind} package {leaf} verified eligible by retention policy", now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, kind, leaf, snapshot.RuntimeSha256, snapshot.ManifestSha256 }, "prepared");
        return signed;
    }

    private static AgentLifecycleRetentionCleanupResult ExecuteCleanup(string planId, string approvalCode, string root, string kind, int protectNewestCount, bool protectPendingRuntimeHashes)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        if (!string.Equals(plan.Tool, "agent-lifecycle-retention-cleanup", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, $"delete-{kind}", StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Lifecycle retention cleanup plan intent mismatch.");
        var name = Require(plan, "name");
        var path = Path.GetFullPath(Path.Combine(root, ValidateSafeName(name, nameof(name))));
        if (!string.Equals(path, plan.Target, StringComparison.OrdinalIgnoreCase) || !string.Equals(path, Require(plan, "path"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Lifecycle retention cleanup target changed.");

        var inventory = BuildInventory(root, kind, protectNewestCount, protectPendingRuntimeHashes);
        var candidate = inventory.Candidates.SingleOrDefault(x => string.Equals(x.Name, name, StringComparison.OrdinalIgnoreCase))
            ?? throw new DirectoryNotFoundException("Lifecycle package no longer exists.");
        if (!candidate.EligibleForCleanup) throw new InvalidOperationException($"Lifecycle package is no longer eligible for cleanup: {candidate.Classification}");
        var pending = ReadPendingRuntimeReferences();
        if (!string.Equals(pending.Fingerprint, Require(plan, "pendingFingerprint"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Lifecycle pending-request set changed after plan preparation.");

        var snapshot = Snapshot(path);
        if (!string.Equals(snapshot.RuntimeSha256, Require(plan, "runtimeSha256"), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(snapshot.ManifestSha256, Require(plan, "manifestSha256"), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(snapshot.ShapeSha256, Require(plan, "shapeSha256"), StringComparison.OrdinalIgnoreCase) ||
            snapshot.FileCount != ParseInt(Require(plan, "fileCount")) || snapshot.DirectoryCount != ParseInt(Require(plan, "directoryCount")) || snapshot.TotalBytes != ParseLong(Require(plan, "totalBytes")))
            throw new InvalidOperationException("Lifecycle package changed after cleanup plan preparation.");
        if (IsReferencedByRunningProcess(path)) throw new InvalidOperationException("Lifecycle package became referenced by a running process.");
        if (protectPendingRuntimeHashes && pending.RuntimeHashes.Contains(snapshot.RuntimeSha256)) throw new InvalidOperationException("Lifecycle package became referenced by a pending request.");

        DeleteTreeNative(path);
        if (Directory.Exists(path) || File.Exists(path)) throw new IOException("Lifecycle package still exists after cleanup.");
        Store.Consume(planId);
        Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, kind, name, snapshot.RuntimeSha256, snapshot.ManifestSha256, outcome = "deleted" }, "executed");
        return new(plan.PlanId, kind, name, path, snapshot.RuntimeSha256, snapshot.ManifestSha256, snapshot.FileCount, snapshot.DirectoryCount, snapshot.TotalBytes, "deleted", DateTimeOffset.UtcNow);
    }

    private static PackageSnapshot Snapshot(string path)
    {
        ValidateFixedPackage(path);
        var root = Path.GetFullPath(path);
        var entries = new List<Entry>();
        var stack = new Stack<string>();
        stack.Push(root);
        long totalBytes = 0;
        int files = 0, dirs = 0;
        while (stack.Count > 0)
        {
            var current = stack.Pop();
            foreach (var entryPath in Directory.EnumerateFileSystemEntries(current, "*", SearchOption.TopDirectoryOnly))
            {
                var attrs = File.GetAttributes(entryPath);
                if ((attrs & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Lifecycle package may not contain reparse points.");
                var relative = Path.GetRelativePath(root, entryPath).Replace('\\', '/');
                if ((attrs & FileAttributes.Directory) != 0)
                {
                    dirs++; EnsureLimit(files + dirs); entries.Add(new(relative, true, 0, string.Empty)); stack.Push(entryPath);
                }
                else
                {
                    var info = new FileInfo(entryPath);
                    if (info.Length > MaxSingleFileBytes) throw new InvalidDataException("Lifecycle package file exceeds size limit.");
                    using var stream = new FileStream(entryPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                    var sha = Convert.ToHexString(SHA256.HashData(stream));
                    totalBytes = checked(totalBytes + info.Length);
                    if (totalBytes > MaxPackageBytes) throw new InvalidDataException("Lifecycle package exceeds total size limit.");
                    files++; EnsureLimit(files + dirs); entries.Add(new(relative, false, info.Length, sha));
                }
            }
        }
        entries.Sort((a,b) => StringComparer.Ordinal.Compare(a.RelativePath,b.RelativePath));
        var runtime = Path.Combine(root, RuntimeFileName);
        if (!File.Exists(runtime)) throw new InvalidDataException("Lifecycle package runtime DLL missing.");
        using var runtimeStream = new FileStream(runtime, FileMode.Open, FileAccess.Read, FileShare.Read);
        var runtimeSha = Convert.ToHexString(SHA256.HashData(runtimeStream));
        var manifest = HashCanonical(entries.Select(e => e.IsDirectory ? $"D|{e.RelativePath}" : $"F|{e.RelativePath}|{e.Length}|{e.Sha256}"));
        var shape = HashCanonical(entries.Select(e => e.IsDirectory ? $"D|{e.RelativePath}" : $"F|{e.RelativePath}|{e.Length}"));
        return new(runtimeSha, manifest, shape, files, dirs, totalBytes);
    }

    private static PendingReferences ReadPendingRuntimeReferences()
    {
        ValidateFixedRoot(PendingRoot);
        var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var names = new List<string>();
        var lines = new List<string>();
        foreach (var path in Directory.EnumerateFiles(PendingRoot, "*.json", SearchOption.TopDirectoryOnly).OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Pending request may not be a reparse point.");
            var info = new FileInfo(path);
            if (info.Length <= 0 || info.Length > MaxRequestBytes) throw new InvalidDataException("Pending request size invalid.");
            byte[] bytes = File.ReadAllBytes(path);
            var fileSha = Convert.ToHexString(SHA256.HashData(bytes));
            using var doc = JsonDocument.Parse(bytes);
            var root = doc.RootElement;
            var currentSha = root.GetProperty("current").GetProperty("runtimeSha256").GetString() ?? string.Empty;
            var targetSha = root.GetProperty("target").GetProperty("runtimeSha256").GetString() ?? string.Empty;
            if (currentSha.Length == 64 && currentSha.All(Uri.IsHexDigit)) hashes.Add(currentSha.ToUpperInvariant());
            if (targetSha.Length == 64 && targetSha.All(Uri.IsHexDigit)) hashes.Add(targetSha.ToUpperInvariant());
            var name = Path.GetFileName(path); names.Add(name); lines.Add($"{name}|{fileSha}|{currentSha}|{targetSha}");
        }
        return new(hashes, names, HashCanonical(lines));
    }

    private static bool IsReferencedByRunningProcess(string packagePath)
    {
        var full = Path.GetFullPath(packagePath).TrimEnd('\\') + "\\";
        foreach (var process in System.Diagnostics.Process.GetProcesses())
        {
            try
            {
                var module = process.MainModule?.FileName;
                if (!string.IsNullOrWhiteSpace(module) && Path.GetFullPath(module).StartsWith(full, StringComparison.OrdinalIgnoreCase)) return true;
                foreach (System.Diagnostics.ProcessModule m in process.Modules)
                    if (!string.IsNullOrWhiteSpace(m.FileName) && Path.GetFullPath(m.FileName).StartsWith(full, StringComparison.OrdinalIgnoreCase)) return true;
            }
            catch { }
            finally { process.Dispose(); }
        }
        return false;
    }

    private static void DeleteTreeNative(string root)
    {
        var info = new DirectoryInfo(root);
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Lifecycle cleanup target may not be a reparse point.");
        foreach (var entry in info.EnumerateFileSystemInfos())
        {
            if ((entry.Attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Lifecycle cleanup target contains a reparse point.");
            if ((entry.Attributes & FileAttributes.Directory) != 0) DeleteTreeNative(entry.FullName); else File.Delete(entry.FullName);
        }
        Directory.Delete(root, false);
    }

    private static void ValidateFixedPackage(string path)
    {
        if (!Directory.Exists(path)) throw new DirectoryNotFoundException(path);
        if (!IsUnderRoot(path, ReleaseRoot) && !IsUnderRoot(path, RollbackRoot)) throw new UnauthorizedAccessException("Lifecycle package is outside fixed retention roots.");
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Lifecycle package may not be a reparse point.");
    }
    private static void ValidateFixedRoot(string root)
    {
        if (!Directory.Exists(root) || !IsUnderRoot(root, DevRoot)) throw new DirectoryNotFoundException($"Fixed lifecycle root unavailable: {root}");
        if ((File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Fixed lifecycle root may not be a reparse point.");
    }
    private static string ValidateSafeName(string value, string parameter)
    {
        var leaf = (value ?? string.Empty).Trim();
        if (leaf.Length is < 1 or > 100 || leaf is "." or ".." || !string.Equals(Path.GetFileName(leaf), leaf, StringComparison.Ordinal) || leaf.Any(char.IsControl) || leaf.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || leaf.EndsWith('.') || leaf.EndsWith(' '))
            throw new ArgumentException("Lifecycle package name must be a safe direct leaf.", parameter);
        return leaf;
    }
    private static string Require(SignedPlan plan, string key) => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : throw new InvalidDataException($"Signed retention parameter {key} is required.");
    private static int ParseInt(string value) => int.TryParse(value, out var n) && n >= 0 && n <= MaxEntries ? n : throw new InvalidDataException("Signed retention count invalid.");
    private static long ParseLong(string value) => long.TryParse(value, out var n) && n >= 0 && n <= MaxPackageBytes ? n : throw new InvalidDataException("Signed retention byte count invalid.");
    private static void EnsureLimit(int count) { if (count > MaxEntries) throw new InvalidDataException("Lifecycle package entry limit exceeded."); }
    private static string HashCanonical(IEnumerable<string> lines) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", lines))));
    private static bool IsUnderRoot(string path, string root)
    {
        var fullPath = Path.GetFullPath(path);
        var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return string.Equals(fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), fullRoot, StringComparison.OrdinalIgnoreCase) || fullPath.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private sealed record Entry(string RelativePath, bool IsDirectory, long Length, string Sha256);
    private sealed record PackageSnapshot(string RuntimeSha256, string ManifestSha256, string ShapeSha256, int FileCount, int DirectoryCount, long TotalBytes);
    private sealed record PendingReferences(HashSet<string> RuntimeHashes, IReadOnlyList<string> RequestNames, string Fingerprint);
}

public sealed record AgentLifecycleRetentionCandidate(string Name, string Path, string RuntimeSha256, string ManifestSha256, int FileCount, int DirectoryCount, long TotalBytes, bool EligibleForCleanup, string Classification, DateTime LastWriteTimeUtc);
public sealed record AgentLifecycleRetentionInventoryResult(string Kind, int CandidateCount, int EligibleCount, IReadOnlyList<AgentLifecycleRetentionCandidate> Candidates, IReadOnlyList<string> PendingRequests, DateTimeOffset CapturedUtc);
public sealed record AgentLifecycleRetentionCleanupResult(string PlanId, string Kind, string Name, string Path, string RuntimeSha256, string ManifestSha256, int FileCount, int DirectoryCount, long TotalBytes, string Outcome, DateTimeOffset ExecutedUtc);