using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;
using YowThi.DevelopmentAgent3.Security;

namespace YowThi.DevelopmentAgent3.AcceptanceCleanup;

internal sealed record DevArtifactState(string Id, string Target, IReadOnlyList<string> Files, IReadOnlyList<string> Directories, long Bytes, string ManifestSha256);

internal static class DevArtifactPolicy
{
    private const string Root = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string Project = @"C:\Dev\YowThi-ERP-Dev-v4\src\YowThi.DevelopmentAgent3";
    private const string Staging = @"C:\Dev\YowThi-ERP-Dev-v4\staging";
    private const int MaxEntries = 50_000;
    private const long MaxBytes = 10L * 1024 * 1024 * 1024;

    public static IReadOnlyList<string> InventoryIds()
    {
        var ids = new List<string>();
        foreach (var file in Directory.EnumerateFiles(Root, "*.bak", SearchOption.TopDirectoryOnly))
            if (Path.GetFileName(file).Contains(".yowthi-", StringComparison.OrdinalIgnoreCase)) ids.Add("root-bak:" + Path.GetFileName(file));
        foreach (var file in Directory.EnumerateFiles(Project, "*.bak", SearchOption.TopDirectoryOnly))
            if (Path.GetFileName(file).Contains(".yowthi-", StringComparison.OrdinalIgnoreCase)) ids.Add("project-bak:" + Path.GetFileName(file));
        if (Directory.Exists(Path.Combine(Project, "bin"))) ids.Add("project-dir:bin");
        if (Directory.Exists(Path.Combine(Project, "obj"))) ids.Add("project-dir:obj");
        if (Directory.Exists(Staging))
            foreach (var dir in Directory.EnumerateDirectories(Staging, "*", SearchOption.TopDirectoryOnly)) ids.Add("staging-dir:" + Path.GetFileName(dir));
        return ids.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public static DevArtifactState Capture(string id, bool hashContents)
    {
        var target = Resolve(id);
        RejectReparseAncestors(target);
        if (File.Exists(target))
        {
            RejectReparse(target);
            var info = new FileInfo(target);
            var hash = hashContents ? HashFile(target) : string.Empty;
            return new DevArtifactState(id, target, new[] { target }, Array.Empty<string>(), info.Length, HashText($"F|{info.Name}|{info.Length}|{hash}\n"));
        }
        if (!Directory.Exists(target)) throw new FileNotFoundException("Development artifact does not exist.", target);
        RejectReparse(target);
        var files = new List<string>();
        var dirs = new List<string>();
        var stack = new Stack<string>();
        stack.Push(target);
        long bytes = 0;
        var count = 0;
        while (stack.Count > 0)
        {
            var current = stack.Pop();
            foreach (var entry in new DirectoryInfo(current).EnumerateFileSystemInfos("*", SearchOption.TopDirectoryOnly))
            {
                if (++count > MaxEntries) throw new InvalidOperationException("Cleanup artifact exceeds entry limit.");
                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Reparse points are not allowed.");
                if (entry is DirectoryInfo d) { dirs.Add(d.FullName); stack.Push(d.FullName); continue; }
                if (entry is not FileInfo f) throw new InvalidDataException("Unsupported filesystem entry.");
                bytes = checked(bytes + f.Length);
                if (bytes > MaxBytes) throw new InvalidOperationException("Cleanup artifact exceeds size limit.");
                files.Add(f.FullName);
            }
        }
        files.Sort(StringComparer.OrdinalIgnoreCase);
        dirs.Sort(StringComparer.OrdinalIgnoreCase);
        var manifest = new StringBuilder();
        foreach (var d in dirs) manifest.Append("D|").Append(Rel(target, d)).Append('\n');
        foreach (var f in files)
        {
            var info = new FileInfo(f);
            manifest.Append("F|").Append(Rel(target, f)).Append('|').Append(info.Length).Append('|');
            if (hashContents) manifest.Append(HashFile(f));
            manifest.Append('\n');
        }
        return new DevArtifactState(id, target, files, dirs, bytes, HashText(manifest.ToString()));
    }

    public static void DeleteExact(DevArtifactState state)
    {
        var target = Resolve(state.Id);
        if (!string.Equals(target, state.Target, StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException("Artifact identity changed.");
        if (File.Exists(target))
        {
            RejectReparse(target);
            File.Delete(target);
            if (File.Exists(target)) throw new IOException("Artifact file still exists after deletion.");
            return;
        }
        foreach (var file in state.Files) { RejectReparse(file); File.Delete(file); }
        foreach (var dir in state.Directories.OrderByDescending(x => x.Length).ThenByDescending(x => x, StringComparer.OrdinalIgnoreCase)) { RejectReparse(dir); Directory.Delete(dir, false); }
        RejectReparse(target);
        Directory.Delete(target, false);
        if (Directory.Exists(target)) throw new IOException("Artifact directory still exists after deletion.");
    }

    private static string Resolve(string id)
    {
        var split = id.IndexOf(':');
        if (split <= 0 || split == id.Length - 1) throw new ArgumentException("Invalid artifactId.", nameof(id));
        var kind = id[..split];
        var leaf = id[(split + 1)..];
        var isRootGitignoreBackup = string.Equals(kind, "root-bak", StringComparison.Ordinal) && IsRootGitignoreBackupLeaf(leaf);
        if (!string.Equals(Path.GetFileName(leaf), leaf, StringComparison.Ordinal) || (!isRootGitignoreBackup && leaf.Contains("..", StringComparison.Ordinal))) throw new ArgumentException("Artifact leaf must be direct and safe.", nameof(id));
        var target = kind switch
        {
            "root-bak" when isRootGitignoreBackup || (leaf.EndsWith(".bak", StringComparison.OrdinalIgnoreCase) && leaf.Contains(".yowthi-", StringComparison.OrdinalIgnoreCase)) => Path.Combine(Root, leaf),
            "project-bak" when leaf.EndsWith(".bak", StringComparison.OrdinalIgnoreCase) && leaf.Contains(".yowthi-", StringComparison.OrdinalIgnoreCase) => Path.Combine(Project, leaf),
            "project-dir" when leaf is "bin" or "obj" => Path.Combine(Project, leaf),
            "staging-dir" => Path.Combine(Staging, leaf),
            _ => throw new UnauthorizedAccessException("ArtifactId is outside fixed cleanup policy.")
        };
        target = Path.GetFullPath(target);
        if (Inside(target, @"C:\yowthi-erp") || Inside(target, Path.Combine(Root, ".git")) || Inside(target, Path.Combine(Root, ".agent3-lifecycle")) || Inside(target, Path.Combine(Root, "acceptance")) || Inside(target, Path.Combine(Root, "runtime-supervisor")))
            throw new UnauthorizedAccessException("Protected target excluded from development cleanup.");
        return target;
    }

    private static bool IsRootGitignoreBackupLeaf(string leaf)
    {
        const string prefix = "..gitignore.yowthi-";
        const string suffix = ".bak";
        if (!leaf.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) || !leaf.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) return false;
        var token = leaf[prefix.Length..^suffix.Length];
        return token.Length == 32 && token.All(Uri.IsHexDigit);
    }

    private static void RejectReparseAncestors(string target)
    {
        var current = Path.GetDirectoryName(target);
        while (!string.IsNullOrEmpty(current) && Inside(current, Root))
        {
            if (Directory.Exists(current)) RejectReparse(current);
            if (string.Equals(current, Root, StringComparison.OrdinalIgnoreCase)) break;
            current = Path.GetDirectoryName(current);
        }
    }
    private static void RejectReparse(string path) { if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Reparse point blocked: " + path); }
    private static bool Inside(string path, string root) { var p = Path.GetFullPath(path).TrimEnd('\\','/'); var r = Path.GetFullPath(root).TrimEnd('\\','/'); return p.Equals(r, StringComparison.OrdinalIgnoreCase) || p.StartsWith(r + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase); }
    private static string Rel(string root, string path) => Path.GetRelativePath(root, path).Replace('\\','/');
    private static string HashFile(string path) { using var s = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete); return Convert.ToHexString(SHA256.HashData(s)); }
    private static string HashText(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
}

[McpServerToolType]
public static class DevelopmentArtifactCleanupTools
{
    private static readonly byte[] Key = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(Key);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name = "development_artifact_cleanup_inventory", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List only fixed disposable YowThi ERP Dev v4 artifacts: YowThi backup files, Agent source bin/obj, and direct staging children. Lifecycle, acceptance, Git metadata, runtime supervisor, arbitrary paths, and production paths are excluded.")]
    public static object Inventory()
    {
        var items = DevArtifactPolicy.InventoryIds().Select(id =>
        {
            try { var s = DevArtifactPolicy.Capture(id, false); return (object)new { artifactId = id, target = s.Target, fileCount = s.Files.Count, directoryCount = s.Directories.Count + (Directory.Exists(s.Target) ? 1 : 0), totalBytes = s.Bytes, eligibleForCleanup = true, blocker = (string?)null }; }
            catch (Exception ex) { return new { artifactId = id, target = string.Empty, fileCount = 0, directoryCount = 0, totalBytes = 0L, eligibleForCleanup = false, blocker = ex.GetType().Name + ": " + ex.Message }; }
        }).ToArray();
        return new { candidateCount = items.Length, candidates = items, capturedUtc = DateTimeOffset.UtcNow };
    }

    [McpServerTool(Name = "development_artifact_cleanup_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed Medium-risk plan to delete exactly one server-resolved disposable development artifact by inventory artifactId. Full manifest, counts, bytes, fixed-root identity and reparse policy are sealed. Arbitrary paths and protected areas are unsupported.")]
    public static SignedPlan Plan(string artifactId)
    {
        var s = DevArtifactPolicy.Capture(artifactId, true);
        var now = DateTimeOffset.UtcNow;
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "development-cleanup", "development-artifact-delete", s.Target,
            new Dictionary<string,string>(StringComparer.Ordinal) { ["artifactId"] = s.Id, ["manifestSha256"] = s.ManifestSha256, ["fileCount"] = s.Files.Count.ToString(), ["directoryCount"] = s.Directories.Count.ToString(), ["totalBytes"] = s.Bytes.ToString() },
            RiskClass.Medium, $"Delete verified disposable development artifact {s.Id}", now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, s.Id, s.ManifestSha256, fileCount = s.Files.Count, directoryCount = s.Directories.Count, s.Bytes }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "development_artifact_cleanup_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one sealed development-artifact cleanup plan using native File.Delete and non-recursive Directory.Delete only. Exact artifact identity and full manifest are revalidated before deletion and absence is verified afterward. Arbitrary paths, shell commands and protected areas are unsupported.")]
    public static Task<ExecutionResult> Execute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        if (plan.Tool != "development-cleanup" || plan.Operation != "development-artifact-delete" || plan.Operation != operation || !string.Equals(plan.Target, target, StringComparison.OrdinalIgnoreCase) || plan.Summary != summary || !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException("Plan execution intent mismatch.");
        var s = DevArtifactPolicy.Capture(plan.Parameters["artifactId"], true);
        if (!string.Equals(s.Target, plan.Target, StringComparison.OrdinalIgnoreCase) || s.ManifestSha256 != plan.Parameters["manifestSha256"] || s.Files.Count.ToString() != plan.Parameters["fileCount"] || s.Directories.Count.ToString() != plan.Parameters["directoryCount"] || s.Bytes.ToString() != plan.Parameters["totalBytes"]) throw new InvalidOperationException("Development artifact changed after plan preparation.");
        DevArtifactPolicy.DeleteExact(s);
        Store.Consume(planId);
        var outcome = $"deleted {s.Files.Count} files and {s.Bytes} bytes";
        Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, s.Id, s.ManifestSha256, outcome }, "executed");
        return Task.FromResult(new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow));
    }
}