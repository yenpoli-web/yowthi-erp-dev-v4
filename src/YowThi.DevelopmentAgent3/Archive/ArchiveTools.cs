using System.ComponentModel;
using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Archive;

[McpServerToolType]
public static class ArchiveTools
{
    private const string DevelopmentRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const int MaxArchiveEntries = 100000;
    private const long MaxExpandedBytes = 20L * 1024 * 1024 * 1024;
    private const long MaxSingleFileBytes = 5L * 1024 * 1024 * 1024;

    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name = "archive_zip_inspect", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Inspect one existing ZIP archive under the YowThi ERP v4 development root using System.IO.Compression. The archive is preflighted for traversal, absolute paths, Windows path collisions, symlink/reparse metadata, entry-count limits, per-entry size limits, and total expanded-size limits. This is read-only and does not extract, create, overwrite, or modify files. No PowerShell, cmd, tar, 7z, shell, or generic command executor is used.")]
    public static ArchiveInspectionResult ArchiveZipInspect(string archivePath, int maxEntries = 500)
    {
        if (maxEntries is < 1 or > 2000)
            throw new ArgumentOutOfRangeException(nameof(maxEntries), "maxEntries must be between 1 and 2000.");
        var path = ValidateExistingArchivePath(archivePath);
        var snapshot = ReadZipSnapshot(path);
        return new ArchiveInspectionResult(path, ComputeSha256(path), snapshot.Entries.Count, snapshot.TotalExpandedBytes, snapshot.ShapeSha256,
            snapshot.Entries.Take(maxEntries).Select(x => new ArchiveEntryItem(x.Path, x.IsDirectory, x.Length, x.CompressedLength)).ToArray(),
            snapshot.Entries.Count > maxEntries, DateTimeOffset.UtcNow);
    }

    [McpServerTool(Name = "archive_zip_create_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed Medium-risk plan to create one ZIP archive from one existing directory under the YowThi ERP v4 development root using System.IO.Compression. The source tree is recursively preflighted without following reparse points, each source file is SHA-256 hashed, and source manifest/shape hashes, file counts, total bytes, destination absence, and exact paths are sealed. The destination must be a new .zip file under the development root and may not be inside the source directory. No overwrite, shell, PowerShell, cmd, tar, 7z, or generic command execution is supported.")]
    public static SignedPlan ArchiveZipCreatePlan(string sourceDirectory, string archivePath)
    {
        var source = ValidateExistingDirectory(sourceDirectory);
        var archive = ValidateNewArchivePath(archivePath);
        if (IsUnderRoot(archive, source))
            throw new InvalidOperationException("Archive destination may not be inside the source directory.");
        var snapshot = BuildDirectorySnapshot(source);
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["sourceDirectory"] = source,
            ["archivePath"] = archive,
            ["sourceManifestSha256"] = snapshot.ManifestSha256,
            ["sourceShapeSha256"] = snapshot.ShapeSha256,
            ["entryCount"] = snapshot.EntryCount.ToString(CultureInfo.InvariantCulture),
            ["fileCount"] = snapshot.Files.Count.ToString(CultureInfo.InvariantCulture),
            ["directoryCount"] = snapshot.Directories.Count.ToString(CultureInfo.InvariantCulture),
            ["totalBytes"] = snapshot.TotalBytes.ToString(CultureInfo.InvariantCulture),
            ["archiveAbsent"] = "true"
        };
        var now = DateTimeOffset.UtcNow;
        var summary = $"Create ZIP archive {archive} from {source} ({snapshot.Files.Count} files, {snapshot.TotalBytes} bytes)";
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "archive", "zip-create", archive, parameters, RiskClass.Medium, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "archive_zip_create_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared archive/zip-create plan using only System.IO.Compression and native .NET filesystem APIs. Exact signed intent, source path, source content manifest, source shape, limits, destination path, destination absence, and reparse-point policy are revalidated immediately before creation. The ZIP is written to a same-directory temporary file and atomically moved into place only after verification. Post-create ZIP preflight must match the signed source shape; failures remove only the new temporary/final archive. No overwrite or shell execution is supported.")]
    public static ArchiveCreateResult ArchiveZipCreateExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "zip-create", operation, target, summary, riskClass);
        var source = ValidateExistingDirectory(RequireParameter(plan, "sourceDirectory"));
        var archive = ValidateNewArchivePath(RequireParameter(plan, "archivePath"));
        if (!string.Equals(archive, plan.Target, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Archive target does not match the signed destination path.");
        if (!string.Equals(RequireParameter(plan, "archiveAbsent"), "true", StringComparison.Ordinal))
            throw new InvalidDataException("Signed archive absence state is invalid.");
        if (IsUnderRoot(archive, source))
            throw new InvalidOperationException("Archive destination may not be inside the source directory.");

        var current = BuildDirectorySnapshot(source);
        RequireDirectorySnapshotMatch(plan, current);
        if (File.Exists(archive) || Directory.Exists(archive))
            throw new InvalidOperationException("Archive destination appeared after plan preparation.");
        var temp = archive + $".yowthi-{plan.PlanId}.tmp";
        if (File.Exists(temp) || Directory.Exists(temp))
            throw new InvalidOperationException("Archive temporary path already exists.");

        var moved = false;
        try
        {
            CreateZip(temp, source, current);
            var tempZip = ReadZipSnapshot(temp, requireZipExtension: false);
            RequireCreatedZipMatch(current, tempZip, "Created ZIP does not match the signed source tree shape.");
            File.Move(temp, archive);
            moved = true;
            var finalZip = ReadZipSnapshot(archive);
            RequireCreatedZipMatch(current, finalZip, "Final ZIP verification failed.");
            var archiveSha256 = ComputeSha256(archive);
            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome = "archive-created", archiveSha256, finalZip.Entries.Count, finalZip.TotalExpandedBytes }, "executed");
            return new ArchiveCreateResult(plan.PlanId, source, archive, archiveSha256, finalZip.Entries.Count, finalZip.TotalExpandedBytes, "archive-created", DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            try { if (File.Exists(temp)) File.Delete(temp); } catch { }
            if (moved) { try { if (File.Exists(archive)) File.Delete(archive); } catch { } }
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "archive_zip_extract_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to safely extract one ZIP archive under the YowThi ERP v4 development root into one new destination directory under the same development root. The archive is SHA-256 sealed and preflighted for traversal, absolute paths, Windows path collisions, symlink/reparse metadata, entry-count limits, per-entry size limits, and total expanded-size limits. Destination absence and archive shape are sealed. Overwrite, extraction into existing directories, shell execution, PowerShell, cmd, tar, 7z, and generic command execution are not supported.")]
    public static SignedPlan ArchiveZipExtractPlan(string archivePath, string destinationDirectory)
    {
        var archive = ValidateExistingArchivePath(archivePath);
        var destination = ValidateNewDirectoryPath(destinationDirectory);
        var zip = ReadZipSnapshot(archive);
        var archiveSha256 = ComputeSha256(archive);
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["archivePath"] = archive,
            ["destinationDirectory"] = destination,
            ["archiveSha256"] = archiveSha256,
            ["zipShapeSha256"] = zip.ShapeSha256,
            ["entryCount"] = zip.Entries.Count.ToString(CultureInfo.InvariantCulture),
            ["totalExpandedBytes"] = zip.TotalExpandedBytes.ToString(CultureInfo.InvariantCulture),
            ["destinationAbsent"] = "true"
        };
        var now = DateTimeOffset.UtcNow;
        var summary = $"Extract ZIP archive {archive} into new directory {destination} ({zip.Entries.Count} entries, {zip.TotalExpandedBytes} expanded bytes)";
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "archive", "zip-extract", destination, parameters, RiskClass.High, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "archive_zip_extract_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared archive/zip-extract plan using System.IO.Compression and native .NET filesystem APIs. Exact signed intent, archive SHA-256, archive shape, limits, destination path, destination absence, entry path safety, collision policy, and reparse/symlink policy are revalidated immediately before extraction. Files are created with CreateNew semantics and never overwrite existing content. Post-extraction tree shape and per-file copied-byte integrity are verified; failures perform best-effort cleanup of only the newly created destination tree. No shell execution is supported.")]
    public static ArchiveExtractResult ArchiveZipExtractExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "zip-extract", operation, target, summary, riskClass);
        var archive = ValidateExistingArchivePath(RequireParameter(plan, "archivePath"));
        var destination = ValidateNewDirectoryPath(RequireParameter(plan, "destinationDirectory"));
        if (!string.Equals(destination, plan.Target, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Extraction target does not match the signed destination directory.");
        if (!string.Equals(RequireParameter(plan, "destinationAbsent"), "true", StringComparison.Ordinal))
            throw new InvalidDataException("Signed destination absence state is invalid.");
        if (!string.Equals(ComputeSha256(archive), RequireParameter(plan, "archiveSha256"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("ZIP archive changed after plan preparation.");
        var currentZip = ReadZipSnapshot(archive);
        RequireZipSnapshotMatch(plan, currentZip);
        if (Directory.Exists(destination) || File.Exists(destination))
            throw new InvalidOperationException("Extraction destination appeared after plan preparation.");

        var createdRoot = false;
        try
        {
            Directory.CreateDirectory(destination);
            createdRoot = true;
            ExtractZip(archive, destination);
            var extracted = BuildDirectorySnapshot(destination);
            if (!string.Equals(extracted.ShapeSha256, currentZip.ShapeSha256, StringComparison.OrdinalIgnoreCase) || extracted.EntryCount != currentZip.Entries.Count || extracted.TotalBytes != currentZip.TotalExpandedBytes)
                throw new InvalidOperationException("Extracted directory tree does not match the ZIP archive shape.");
            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome = "archive-extracted", extracted.ManifestSha256, extracted.EntryCount, extracted.TotalBytes }, "executed");
            return new ArchiveExtractResult(plan.PlanId, archive, destination, RequireParameter(plan, "archiveSha256"), extracted.ManifestSha256, extracted.EntryCount, extracted.TotalBytes, "archive-extracted", DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            if (createdRoot) { try { SafeDeleteTree(destination); } catch { } }
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    private static void RequireCreatedZipMatch(DirectorySnapshot source, ZipSnapshot zip, string message)
    {
        if (!string.Equals(zip.ShapeSha256, source.ShapeSha256, StringComparison.OrdinalIgnoreCase) || zip.Entries.Count != source.EntryCount || zip.TotalExpandedBytes != source.TotalBytes)
            throw new InvalidOperationException(message);
    }

    private static void CreateZip(string tempArchivePath, string sourceDirectory, DirectorySnapshot snapshot)
    {
        using var output = new FileStream(tempArchivePath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        using var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: false, entryNameEncoding: Encoding.UTF8);
        foreach (var directory in snapshot.Directories)
            archive.CreateEntry(directory + "/", CompressionLevel.NoCompression);
        foreach (var file in snapshot.Files)
        {
            var sourcePath = ResolveSourcePath(sourceDirectory, file.Path);
            if ((File.GetAttributes(sourcePath) & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException($"Source file became a reparse point: {file.Path}");
            var entry = archive.CreateEntry(file.Path, CompressionLevel.Optimal);
            using var input = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var entryStream = entry.Open();
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[1024 * 128];
            long copied = 0;
            while (true)
            {
                var read = input.Read(buffer, 0, buffer.Length);
                if (read == 0) break;
                copied = checked(copied + read);
                if (copied > MaxSingleFileBytes) throw new InvalidDataException($"Source file exceeds the single-file archive limit: {file.Path}");
                hash.AppendData(buffer, 0, read);
                entryStream.Write(buffer, 0, read);
            }
            var sha256 = Convert.ToHexString(hash.GetHashAndReset());
            if (copied != file.Length || !string.Equals(sha256, file.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"Source file changed while archive creation was in progress: {file.Path}");
        }
    }

    private static void ExtractZip(string archivePath, string destinationRoot)
    {
        using var input = new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var archive = new ZipArchive(input, ZipArchiveMode.Read, leaveOpen: false, entryNameEncoding: Encoding.UTF8);
        foreach (var entry in archive.Entries)
        {
            var normalized = NormalizeZipEntry(entry);
            if (normalized.IsDirectory)
            {
                EnsureDirectoryPath(destinationRoot, normalized.Path);
                continue;
            }
            var destination = ResolveDestinationPath(destinationRoot, normalized.Path);
            var slash = normalized.Path.LastIndexOf('/');
            if (slash >= 0) EnsureDirectoryPath(destinationRoot, normalized.Path[..slash]);
            if (File.Exists(destination) || Directory.Exists(destination))
                throw new IOException($"Extraction target already exists: {normalized.Path}");
            using var source = entry.Open();
            using var target = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[1024 * 128];
            long copied = 0;
            while (true)
            {
                var read = source.Read(buffer, 0, buffer.Length);
                if (read == 0) break;
                copied = checked(copied + read);
                if (copied > normalized.Length || copied > MaxSingleFileBytes)
                    throw new InvalidDataException($"ZIP entry expanded beyond its declared or allowed length: {normalized.Path}");
                hash.AppendData(buffer, 0, read);
                target.Write(buffer, 0, read);
            }
            if (copied != normalized.Length) throw new InvalidDataException($"ZIP entry length mismatch during extraction: {normalized.Path}");
            var streamedSha = Convert.ToHexString(hash.GetHashAndReset());
            target.Flush(flushToDisk: true);
            target.Dispose();
            if (!string.Equals(streamedSha, ComputeSha256(destination), StringComparison.OrdinalIgnoreCase))
                throw new IOException($"Extracted file verification failed: {normalized.Path}");
        }
    }

    private static DirectorySnapshot BuildDirectorySnapshot(string root)
    {
        var directories = new List<string>();
        var files = new List<DirectoryFileSnapshot>();
        var stack = new Stack<string>();
        stack.Push(root);
        long totalBytes = 0;
        while (stack.Count > 0)
        {
            var current = stack.Pop();
            foreach (var path in Directory.EnumerateFileSystemEntries(current))
            {
                var attributes = File.GetAttributes(path);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new UnauthorizedAccessException($"Reparse points are not supported in archive source or extracted trees: {path}");
                var relative = NormalizeRelativePath(Path.GetRelativePath(root, path));
                if ((attributes & FileAttributes.Directory) != 0)
                {
                    directories.Add(relative);
                    stack.Push(path);
                    continue;
                }
                var info = new FileInfo(path);
                if (info.Length > MaxSingleFileBytes) throw new InvalidDataException($"File exceeds the single-file archive limit: {relative}");
                totalBytes = checked(totalBytes + info.Length);
                if (totalBytes > MaxExpandedBytes) throw new InvalidDataException("Directory exceeds the maximum archive expanded-size limit.");
                files.Add(new DirectoryFileSnapshot(relative, info.Length, ComputeSha256(path)));
                if (directories.Count + files.Count > MaxArchiveEntries) throw new InvalidDataException("Directory exceeds the maximum archive entry-count limit.");
            }
        }
        directories.Sort(StringComparer.Ordinal);
        files.Sort((a, b) => StringComparer.Ordinal.Compare(a.Path, b.Path));
        var manifest = ComputeDirectoryManifest(directories, files, includeContentHash: true);
        var shape = ComputeDirectoryManifest(directories, files, includeContentHash: false);
        return new DirectorySnapshot(directories, files, manifest, shape, directories.Count + files.Count, totalBytes);
    }

    private static ZipSnapshot ReadZipSnapshot(string archivePath, bool requireZipExtension = true)
    {
        var path = requireZipExtension ? ValidateExistingArchivePath(archivePath) : ValidateExistingFileUnderDevelopmentRoot(archivePath);
        var entriesByPath = new Dictionary<string, ZipEntrySnapshot>(StringComparer.OrdinalIgnoreCase);
        long total = 0;
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var archive = new ZipArchive(input, ZipArchiveMode.Read, leaveOpen: false, entryNameEncoding: Encoding.UTF8);
        foreach (var entry in archive.Entries)
        {
            var normalized = NormalizeZipEntry(entry);
            AddZipEntry(entriesByPath, normalized);
            if (!normalized.IsDirectory)
            {
                total = checked(total + normalized.Length);
                if (total > MaxExpandedBytes) throw new InvalidDataException("ZIP archive exceeds the maximum total expanded-size limit.");
                AddImplicitDirectories(entriesByPath, normalized.Path);
            }
            if (entriesByPath.Count > MaxArchiveEntries) throw new InvalidDataException("ZIP archive exceeds the maximum entry-count limit.");
        }
        var entries = entriesByPath.Values.OrderBy(x => x.Path, StringComparer.Ordinal).ToArray();
        ValidateTreeCollisions(entries);
        return new ZipSnapshot(entries, total, ComputeZipShape(entries));
    }

    private static void AddZipEntry(Dictionary<string, ZipEntrySnapshot> entries, ZipEntrySnapshot entry)
    {
        if (entries.TryGetValue(entry.Path, out var existing))
        {
            if (existing.IsDirectory && entry.IsDirectory && existing.CompressedLength == 0) return;
            throw new InvalidDataException($"ZIP archive contains a Windows path collision: {entry.Path}");
        }
        entries.Add(entry.Path, entry);
    }

    private static void AddImplicitDirectories(Dictionary<string, ZipEntrySnapshot> entries, string filePath)
    {
        var slash = filePath.IndexOf('/');
        while (slash > 0)
        {
            var dir = filePath[..slash];
            if (entries.TryGetValue(dir, out var existing) && !existing.IsDirectory)
                throw new InvalidDataException($"ZIP archive contains a file/directory path collision: {dir}");
            if (!entries.ContainsKey(dir)) entries.Add(dir, new ZipEntrySnapshot(dir, true, 0, 0));
            slash = filePath.IndexOf('/', slash + 1);
        }
    }

    private static void ValidateTreeCollisions(IReadOnlyList<ZipEntrySnapshot> entries)
    {
        var kinds = entries.ToDictionary(x => x.Path, x => x.IsDirectory, StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries.Where(x => !x.IsDirectory))
        {
            var slash = entry.Path.IndexOf('/');
            while (slash > 0)
            {
                var prefix = entry.Path[..slash];
                if (kinds.TryGetValue(prefix, out var isDirectory) && !isDirectory)
                    throw new InvalidDataException($"ZIP archive contains a file/directory path collision: {prefix}");
                slash = entry.Path.IndexOf('/', slash + 1);
            }
        }
    }

    private static ZipEntrySnapshot NormalizeZipEntry(ZipArchiveEntry entry)
    {
        var raw = entry.FullName ?? string.Empty;
        if (string.IsNullOrWhiteSpace(raw)) throw new InvalidDataException("ZIP archive contains an empty entry name.");
        if ((entry.ExternalAttributes & (int)FileAttributes.ReparsePoint) != 0 || ((entry.ExternalAttributes >> 16) & 0xF000) == 0xA000)
            throw new InvalidDataException($"ZIP archive contains a symlink/reparse entry: {raw}");
        var isDirectory = raw.EndsWith('/') || raw.EndsWith('\\');
        var value = raw.Replace('\\', '/');
        if (value.StartsWith('/') || (value.Length >= 2 && char.IsLetter(value[0]) && value[1] == ':')) throw new InvalidDataException($"ZIP archive contains an absolute path: {raw}");
        if (isDirectory) value = value.TrimEnd('/');
        if (value.Length == 0) throw new InvalidDataException("ZIP archive contains an invalid root directory entry.");
        var segments = value.Split('/', StringSplitOptions.None);
        foreach (var segment in segments)
        {
            if (segment.Length == 0 || segment is "." or ".." || segment.Contains(':') || segment.Any(char.IsControl) || segment.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || segment.EndsWith(' ') || segment.EndsWith('.'))
                throw new InvalidDataException($"ZIP archive contains an unsafe Windows path segment: {raw}");
            if (IsReservedWindowsName(segment)) throw new InvalidDataException($"ZIP archive contains a reserved Windows device name: {raw}");
        }
        if (!isDirectory && entry.Length > MaxSingleFileBytes) throw new InvalidDataException($"ZIP entry exceeds the single-file expanded-size limit: {raw}");
        if (isDirectory && entry.Length != 0) throw new InvalidDataException($"ZIP directory entry has non-zero expanded length: {raw}");
        return new ZipEntrySnapshot(string.Join('/', segments), isDirectory, isDirectory ? 0 : entry.Length, entry.CompressedLength);
    }

    private static void EnsureDirectoryPath(string root, string relative)
    {
        if (string.IsNullOrWhiteSpace(relative)) return;
        var current = root;
        foreach (var segment in relative.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if (File.Exists(current)) throw new IOException($"Extraction directory path collides with a file: {relative}");
            if (!Directory.Exists(current)) Directory.CreateDirectory(current);
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException($"Extraction directory path became a reparse point: {relative}");
        }
    }

    private static string ResolveSourcePath(string root, string relative)
    {
        var path = Path.GetFullPath(Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)));
        if (!IsUnderRoot(path, root)) throw new InvalidDataException("Source relative path escaped its root.");
        return path;
    }

    private static string ResolveDestinationPath(string root, string relative)
    {
        var path = Path.GetFullPath(Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar)));
        if (!IsUnderRoot(path, root)) throw new InvalidDataException("ZIP entry escaped the extraction destination.");
        return path;
    }

    private static string ValidateExistingDirectory(string path)
    {
        var full = ValidateDevelopmentPath(path);
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException($"Directory does not exist: {full}");
        EnsureNoReparseFromRoot(full);
        return full;
    }

    private static string ValidateExistingArchivePath(string path)
    {
        var full = ValidateExistingFileUnderDevelopmentRoot(path);
        if (!string.Equals(Path.GetExtension(full), ".zip", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("archivePath must end in .zip.", nameof(path));
        return full;
    }

    private static string ValidateExistingFileUnderDevelopmentRoot(string path)
    {
        var full = ValidateDevelopmentPath(path);
        if (!File.Exists(full)) throw new FileNotFoundException("File does not exist.", full);
        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("File may not be a reparse point.");
        EnsureNoReparseFromRoot(Path.GetDirectoryName(full) ?? throw new InvalidDataException("File parent directory is unavailable."));
        return full;
    }

    private static string ValidateNewArchivePath(string path)
    {
        var full = ValidateDevelopmentPath(path);
        if (!string.Equals(Path.GetExtension(full), ".zip", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("archivePath must end in .zip.", nameof(path));
        if (File.Exists(full) || Directory.Exists(full)) throw new IOException("Archive destination already exists.");
        var parent = Path.GetDirectoryName(full) ?? throw new ArgumentException("Archive destination requires a parent directory.", nameof(path));
        if (!Directory.Exists(parent)) throw new DirectoryNotFoundException($"Archive parent directory does not exist: {parent}");
        EnsureNoReparseFromRoot(parent);
        return full;
    }

    private static string ValidateNewDirectoryPath(string path)
    {
        var full = ValidateDevelopmentPath(path);
        if (File.Exists(full) || Directory.Exists(full)) throw new IOException("Destination directory already exists.");
        var parent = Path.GetDirectoryName(full) ?? throw new ArgumentException("Destination directory requires a parent directory.", nameof(path));
        if (!Directory.Exists(parent)) throw new DirectoryNotFoundException($"Destination parent directory does not exist: {parent}");
        EnsureNoReparseFromRoot(parent);
        return full;
    }

    private static string ValidateDevelopmentPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)) throw new ArgumentException("Path must be absolute.", nameof(path));
        var full = Path.GetFullPath(path);
        if (!IsUnderRoot(full, DevelopmentRoot)) throw new UnauthorizedAccessException($"Archive operations are restricted to {DevelopmentRoot}.");
        return full;
    }

    private static void EnsureNoReparseFromRoot(string path)
    {
        var root = Path.GetFullPath(DevelopmentRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var current = new DirectoryInfo(path);
        while (current is not null)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException($"Archive path may not traverse a reparse-point directory: {current.FullName}");
            if (string.Equals(current.FullName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), root, StringComparison.OrdinalIgnoreCase)) return;
            current = current.Parent;
        }
        throw new UnauthorizedAccessException("Archive path root validation failed.");
    }

    private static bool IsUnderRoot(string path, string root)
    {
        var fullPath = Path.GetFullPath(path);
        var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return fullPath.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeRelativePath(string relative)
    {
        var value = relative.Replace('\\', '/');
        if (value.Length == 0 || value.StartsWith('/') || value.Split('/').Any(x => x.Length == 0 || x is "." or ".." || x.Contains(':') || x.Any(char.IsControl))) throw new InvalidDataException($"Unsafe relative path: {relative}");
        return value;
    }

    private static bool IsReservedWindowsName(string segment)
    {
        var stem = segment.Split('.')[0].TrimEnd(' ', '.').ToUpperInvariant();
        if (stem is "CON" or "PRN" or "AUX" or "NUL") return true;
        return stem.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal)) && stem[3] is >= '1' and <= '9';
    }

    private static string ComputeDirectoryManifest(IReadOnlyList<string> directories, IReadOnlyList<DirectoryFileSnapshot> files, bool includeContentHash)
    {
        var lines = new List<CanonicalLine>(directories.Count + files.Count);
        lines.AddRange(directories.Select(path => new CanonicalLine(path, $"D|{path}\n")));
        lines.AddRange(files.Select(file => new CanonicalLine(file.Path, includeContentHash ? $"F|{file.Path}|{file.Length}|{file.Sha256}\n" : $"F|{file.Path}|{file.Length}\n")));
        lines.Sort((a, b) => StringComparer.Ordinal.Compare(a.Path, b.Path));
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var line in lines) AppendHashLine(hash, line.Text);
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static string ComputeZipShape(IReadOnlyList<ZipEntrySnapshot> entries)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var entry in entries.OrderBy(x => x.Path, StringComparer.Ordinal))
            AppendHashLine(hash, entry.IsDirectory ? $"D|{entry.Path}\n" : $"F|{entry.Path}|{entry.Length}\n");
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static void AppendHashLine(IncrementalHash hash, string line) => hash.AppendData(Encoding.UTF8.GetBytes(line));

    private static string ComputeSha256(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void RequireDirectorySnapshotMatch(SignedPlan plan, DirectorySnapshot current)
    {
        if (!string.Equals(current.ManifestSha256, RequireParameter(plan, "sourceManifestSha256"), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(current.ShapeSha256, RequireParameter(plan, "sourceShapeSha256"), StringComparison.OrdinalIgnoreCase) ||
            current.EntryCount != ParseInt(RequireParameter(plan, "entryCount"), "entryCount") || current.Files.Count != ParseInt(RequireParameter(plan, "fileCount"), "fileCount") ||
            current.Directories.Count != ParseInt(RequireParameter(plan, "directoryCount"), "directoryCount") || current.TotalBytes != ParseLong(RequireParameter(plan, "totalBytes"), "totalBytes"))
            throw new InvalidOperationException("Archive source tree changed after plan preparation.");
    }

    private static void RequireZipSnapshotMatch(SignedPlan plan, ZipSnapshot current)
    {
        if (!string.Equals(current.ShapeSha256, RequireParameter(plan, "zipShapeSha256"), StringComparison.OrdinalIgnoreCase) || current.Entries.Count != ParseInt(RequireParameter(plan, "entryCount"), "entryCount") || current.TotalExpandedBytes != ParseLong(RequireParameter(plan, "totalExpandedBytes"), "totalExpandedBytes"))
            throw new InvalidOperationException("ZIP archive shape changed after plan preparation.");
    }

    private static int ParseInt(string value, string name) => int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var result) ? result : throw new InvalidDataException($"Signed {name} is invalid.");
    private static long ParseLong(string value, string name) => long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var result) ? result : throw new InvalidDataException($"Signed {name} is invalid.");

    private static void RequireIntentMatch(SignedPlan plan, string expectedOperation, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "archive", StringComparison.Ordinal) || !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal) || !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.Ordinal) || !string.Equals(plan.Summary, summary, StringComparison.Ordinal) || !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }

    private static string RequireParameter(SignedPlan plan, string key) => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : throw new InvalidDataException($"{key} parameter is required.");

    private static void SafeDeleteTree(string root)
    {
        if (!Directory.Exists(root)) return;
        foreach (var entry in Directory.EnumerateFileSystemEntries(root))
        {
            var attributes = File.GetAttributes(entry);
            if ((attributes & FileAttributes.Directory) != 0)
            {
                if ((attributes & FileAttributes.ReparsePoint) != 0) Directory.Delete(entry, recursive: false);
                else SafeDeleteTree(entry);
            }
            else File.Delete(entry);
        }
        Directory.Delete(root, recursive: false);
    }

    private sealed record CanonicalLine(string Path, string Text);
    private sealed record DirectoryFileSnapshot(string Path, long Length, string Sha256);
    private sealed record DirectorySnapshot(IReadOnlyList<string> Directories, IReadOnlyList<DirectoryFileSnapshot> Files, string ManifestSha256, string ShapeSha256, int EntryCount, long TotalBytes);
    private sealed record ZipEntrySnapshot(string Path, bool IsDirectory, long Length, long CompressedLength);
    private sealed record ZipSnapshot(IReadOnlyList<ZipEntrySnapshot> Entries, long TotalExpandedBytes, string ShapeSha256);
}

public sealed record ArchiveEntryItem(string Path, bool IsDirectory, long Length, long CompressedLength);
public sealed record ArchiveInspectionResult(string ArchivePath, string ArchiveSha256, int EntryCount, long TotalExpandedBytes, string ShapeSha256, IReadOnlyList<ArchiveEntryItem> Entries, bool EntriesTruncated, DateTimeOffset CheckedUtc);
public sealed record ArchiveCreateResult(string PlanId, string SourceDirectory, string ArchivePath, string ArchiveSha256, int EntryCount, long TotalBytes, string Outcome, DateTimeOffset ExecutedUtc);
public sealed record ArchiveExtractResult(string PlanId, string ArchivePath, string DestinationDirectory, string ArchiveSha256, string ExtractedManifestSha256, int EntryCount, long TotalBytes, string Outcome, DateTimeOffset ExecutedUtc);