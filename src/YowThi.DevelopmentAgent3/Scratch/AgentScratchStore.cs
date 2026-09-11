using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace YowThi.DevelopmentAgent3.Scratch;

public sealed record AgentScratchArtifact(
    string ArtifactId,
    string PlanId,
    string Owner,
    string Purpose,
    string DataPath,
    string ManifestPath,
    string Sha256,
    long Bytes,
    DateTimeOffset CreatedUtc,
    DateTimeOffset ExpiresUtc);

public sealed record AgentScratchReconcileResult(
    int ActiveCount,
    long ActiveBytes,
    int ExpiredDeletedCount,
    int InvalidManifestCount,
    DateTimeOffset CheckedUtc);

internal sealed record AgentScratchManifest(
    int SchemaVersion,
    string ArtifactId,
    string PlanId,
    string Owner,
    string Purpose,
    string? TargetPath,
    string DataFile,
    string DataSha256,
    long DataBytes,
    DateTimeOffset CreatedUtc,
    DateTimeOffset ExpiresUtc);

public static class AgentScratchStore
{
    public const string RootPath = @"C:\Dev\YowThi-ERP-Dev-v4-scratch\agent3";
    public const string V4RepositoryRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const int MaximumManifestCount = 2048;
    private static readonly object Gate = new();

    public static AgentScratchArtifact CreateArtifact(
        string planId,
        string owner,
        string purpose,
        string extension,
        byte[] content,
        DateTimeOffset expiresUtc,
        string? targetPath = null)
    {
        lock (Gate)
        {
            _ = ReconcileExpiredCore();
            ValidatePlanId(planId);
            owner = ValidateLabel(owner, nameof(owner));
            purpose = ValidateLabel(purpose, nameof(purpose));
            extension = ValidateExtension(extension);
            if (expiresUtc <= DateTimeOffset.UtcNow || expiresUtc > DateTimeOffset.UtcNow.AddDays(7))
                throw new ArgumentOutOfRangeException(nameof(expiresUtc), "Scratch TTL must expire within seven days.");
            if (content.LongLength > 32L * 1024 * 1024)
                throw new ArgumentOutOfRangeException(nameof(content), "Scratch artifact may not exceed 32 MiB.");

            var root = EnsureRoot();
            var purposeSlug = string.Concat(purpose.Select(c => char.IsLetterOrDigit(c) ? char.ToLowerInvariant(c) : '-')).Trim('-');
            if (purposeSlug.Length == 0) purposeSlug = "artifact";
            if (purposeSlug.Length > 48) purposeSlug = purposeSlug[..48];
            var dataLeaf = $"{planId}-{purposeSlug}{extension}";
            var manifestLeaf = dataLeaf + ".manifest.json";
            var dataPath = RequireDirectChild(root, dataLeaf);
            var manifestPath = RequireDirectChild(root, manifestLeaf);
            if (File.Exists(dataPath) || File.Exists(manifestPath))
                throw new IOException("Scratch artifact already exists for this plan.");

            var createdUtc = DateTimeOffset.UtcNow;
            var sha256 = Convert.ToHexString(SHA256.HashData(content));
            using (var stream = new FileStream(dataPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(content);
                stream.Flush(flushToDisk: true);
            }
            VerifyData(dataPath, sha256, content.LongLength);

            var manifest = new AgentScratchManifest(
                1,
                dataLeaf,
                planId,
                owner,
                purpose,
                targetPath,
                dataLeaf,
                sha256,
                content.LongLength,
                createdUtc,
                expiresUtc);
            var json = JsonSerializer.Serialize(manifest);
            try
            {
                using var stream = new FileStream(manifestPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                using var writer = new StreamWriter(stream, new UTF8Encoding(false));
                writer.Write(json);
            }
            catch
            {
                TryDeleteFile(dataPath);
                throw;
            }

            return new AgentScratchArtifact(dataLeaf, planId, owner, purpose, dataPath, manifestPath, sha256, content.LongLength, createdUtc, expiresUtc);
        }
    }

    public static AgentScratchReconcileResult ReconcileExpired()
    {
        lock (Gate) return ReconcileExpiredCore();
    }

    public static bool IsScratchPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)) return false;
        var full = Normalize(path);
        var root = Normalize(RootPath);
        return full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    public static AgentScratchArtifact RequireActiveOwnedArtifact(string dataPath, string requiredPurpose)
    {
        lock (Gate)
        {
            _ = ReconcileExpiredCore();
            var full = Normalize(dataPath);
            var root = EnsureRoot();
            if (!full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Path is outside the Agent scratch vault.");
            if (!File.Exists(full)) throw new FileNotFoundException("Agent scratch artifact does not exist.", full);
            var leaf = Path.GetFileName(full);
            var manifestPath = RequireDirectChild(root, leaf + ".manifest.json");
            var manifest = ReadManifest(manifestPath);
            if (!string.Equals(manifest.DataFile, leaf, StringComparison.Ordinal) ||
                !string.Equals(manifest.ArtifactId, leaf, StringComparison.Ordinal) ||
                !string.Equals(manifest.Purpose, requiredPurpose, StringComparison.Ordinal))
                throw new UnauthorizedAccessException("Scratch artifact ownership/purpose does not match.");
            if (manifest.ExpiresUtc <= DateTimeOffset.UtcNow)
                throw new InvalidOperationException("Scratch artifact has expired.");
            VerifyData(full, manifest.DataSha256, manifest.DataBytes);
            return ToArtifact(root, manifest);
        }
    }

    public static bool TryDeleteOwnedArtifact(string dataPath)
    {
        lock (Gate)
        {
            if (!IsScratchPath(dataPath)) return false;
            var full = Normalize(dataPath);
            var root = EnsureRoot();
            var leaf = Path.GetFileName(full);
            var manifestPath = RequireDirectChild(root, leaf + ".manifest.json");
            if (!File.Exists(manifestPath)) return false;
            var manifest = ReadManifest(manifestPath);
            if (!string.Equals(manifest.DataFile, leaf, StringComparison.Ordinal)) return false;
            if (File.Exists(full)) VerifyData(full, manifest.DataSha256, manifest.DataBytes);
            TryDeleteFile(full);
            TryDeleteFile(manifestPath);
            return !File.Exists(full) && !File.Exists(manifestPath);
        }
    }

    public static string RequireGenericFileCreationAllowed(string path)
    {
        var full = Normalize(path);
        var repo = Normalize(V4RepositoryRoot);
        if (full.StartsWith(repo + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            var leaf = Path.GetFileName(full);
            if (string.Equals(Path.GetExtension(full), ".ps1", StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Generic file_create may not create PowerShell helper scripts inside the V4 Git worktree. Use the Agent scratch-script capability.");
            if (leaf.Contains(".yowthi-", StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Agent scratch/backup artifacts may not be created inside the V4 Git worktree.");
        }
        return full;
    }

    private static AgentScratchReconcileResult ReconcileExpiredCore()
    {
        if (!Directory.Exists(RootPath))
            return new(0, 0, 0, 0, DateTimeOffset.UtcNow);
        var root = EnsureRoot();
        var manifests = Directory.EnumerateFiles(root, "*.manifest.json", SearchOption.TopDirectoryOnly).Take(MaximumManifestCount + 1).ToArray();
        if (manifests.Length > MaximumManifestCount)
            throw new InvalidOperationException("Agent scratch manifest count exceeded the bounded limit.");

        var activeCount = 0;
        long activeBytes = 0;
        var expiredDeleted = 0;
        var invalid = 0;
        var now = DateTimeOffset.UtcNow;

        foreach (var manifestPath in manifests)
        {
            try
            {
                var manifest = ReadManifest(manifestPath);
                var dataPath = RequireDirectChild(root, manifest.DataFile);
                if (manifest.ExpiresUtc > now)
                {
                    if (!File.Exists(dataPath)) { invalid++; continue; }
                    VerifyData(dataPath, manifest.DataSha256, manifest.DataBytes);
                    activeCount++;
                    activeBytes = checked(activeBytes + manifest.DataBytes);
                    continue;
                }

                if (File.Exists(dataPath)) VerifyData(dataPath, manifest.DataSha256, manifest.DataBytes);
                TryDeleteFile(dataPath);
                TryDeleteFile(manifestPath);
                if (!File.Exists(dataPath) && !File.Exists(manifestPath)) expiredDeleted++;
                else invalid++;
            }
            catch
            {
                invalid++;
            }
        }

        return new(activeCount, activeBytes, expiredDeleted, invalid, DateTimeOffset.UtcNow);
    }

    private static AgentScratchManifest ReadManifest(string manifestPath)
    {
        if (!File.Exists(manifestPath)) throw new FileNotFoundException("Scratch manifest does not exist.", manifestPath);
        if ((File.GetAttributes(manifestPath) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Scratch manifest may not be a reparse point.");
        var bytes = File.ReadAllBytes(manifestPath);
        if (bytes.Length is <= 0 or > 64 * 1024) throw new InvalidDataException("Scratch manifest size is invalid.");
        var manifest = JsonSerializer.Deserialize<AgentScratchManifest>(bytes) ?? throw new InvalidDataException("Scratch manifest JSON is invalid.");
        if (manifest.SchemaVersion != 1) throw new InvalidDataException("Scratch manifest schema version is invalid.");
        ValidatePlanId(manifest.PlanId);
        _ = ValidateLabel(manifest.Owner, nameof(manifest.Owner));
        _ = ValidateLabel(manifest.Purpose, nameof(manifest.Purpose));
        if (!string.Equals(Path.GetFileName(manifest.DataFile), manifest.DataFile, StringComparison.Ordinal) || manifest.DataFile.Contains(Path.DirectorySeparatorChar) || manifest.DataFile.Contains(Path.AltDirectorySeparatorChar))
            throw new InvalidDataException("Scratch data file leaf is invalid.");
        if (!string.Equals(manifest.ArtifactId, manifest.DataFile, StringComparison.Ordinal))
            throw new InvalidDataException("Scratch artifact identity mismatch.");
        if (manifest.DataBytes < 0 || manifest.DataBytes > 32L * 1024 * 1024) throw new InvalidDataException("Scratch data byte count is invalid.");
        if (manifest.DataSha256.Length != 64 || manifest.DataSha256.Any(c => !Uri.IsHexDigit(c))) throw new InvalidDataException("Scratch data SHA-256 is invalid.");
        if (manifest.ExpiresUtc <= manifest.CreatedUtc || manifest.ExpiresUtc > manifest.CreatedUtc.AddDays(7)) throw new InvalidDataException("Scratch manifest TTL is invalid.");
        return manifest;
    }

    private static AgentScratchArtifact ToArtifact(string root, AgentScratchManifest manifest)
    {
        var dataPath = RequireDirectChild(root, manifest.DataFile);
        var manifestPath = RequireDirectChild(root, manifest.DataFile + ".manifest.json");
        return new(manifest.ArtifactId, manifest.PlanId, manifest.Owner, manifest.Purpose, dataPath, manifestPath, manifest.DataSha256, manifest.DataBytes, manifest.CreatedUtc, manifest.ExpiresUtc);
    }

    private static string EnsureRoot()
    {
        var root = Normalize(RootPath);
        Directory.CreateDirectory(root);
        if ((File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Agent scratch root may not be a reparse point.");
        return root;
    }

    private static string RequireDirectChild(string root, string leaf)
    {
        if (string.IsNullOrWhiteSpace(leaf) || !string.Equals(Path.GetFileName(leaf), leaf, StringComparison.Ordinal) || leaf.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            throw new InvalidDataException("Scratch artifact leaf name is invalid.");
        var path = Normalize(Path.Combine(root, leaf));
        if (!string.Equals(Path.GetDirectoryName(path)?.TrimEnd(Path.DirectorySeparatorChar), root.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Scratch artifact escaped the fixed root.");
        return path;
    }

    private static void VerifyData(string path, string expectedSha256, long expectedBytes)
    {
        var info = new FileInfo(path);
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Scratch data may not be a reparse point.");
        if (info.Length != expectedBytes) throw new InvalidDataException("Scratch data byte count changed.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var sha = Convert.ToHexString(SHA256.HashData(stream));
        if (!string.Equals(sha, expectedSha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Scratch data SHA-256 changed.");
    }

    private static string ValidateExtension(string extension)
    {
        var value = (extension ?? string.Empty).Trim().ToLowerInvariant();
        if (value is not (".bak" or ".ps1")) throw new ArgumentOutOfRangeException(nameof(extension), "Scratch extension must be .bak or .ps1.");
        return value;
    }

    private static string ValidateLabel(string value, string parameterName)
    {
        var text = (value ?? string.Empty).Trim();
        if (text.Length is < 1 or > 96 || text.Any(c => char.IsControl(c) || !(char.IsLetterOrDigit(c) || c is '-' or '_' or '/' or '.')))
            throw new ArgumentException("Scratch owner/purpose label is invalid.", parameterName);
        return text;
    }

    private static void ValidatePlanId(string planId)
    {
        if (string.IsNullOrWhiteSpace(planId) || planId.Length != 32 || planId.Any(c => !Uri.IsHexDigit(c)))
            throw new ArgumentException("Scratch planId must be exactly 32 hexadecimal characters.", nameof(planId));
    }

    private static string Normalize(string path) => Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

    private static void TryDeleteFile(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }
}
