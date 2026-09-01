using System.ComponentModel;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Backup;

[McpServerToolType]
public static class BackupTools
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string BackupRoot = @"C:\Dev\YowThi-ERP-Dev-v4-backups";
    private const string GitRoot = @"C:\Dev\YowThi-ERP-Dev-v4\.git";
    private const string TransferRoot = @"C:\Dev\YowThi-ERP-Dev-v4\staging\transfer";
    private const int MaxEntries = 100_000;
    private const long MaxExpandedBytes = 20L * 1024 * 1024 * 1024;
    private const long MaxSingleFileBytes = 5L * 1024 * 1024 * 1024;
    private const long MaxBackupFileBytes = 20L * 1024 * 1024 * 1024;

    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name = "backup_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List direct .zip backup files in the fixed YowThi ERP v4 development backup vault C:\\Dev\\YowThi-ERP-Dev-v4-backups. This is read-only. Reparse points, subdirectories, arbitrary paths, shell execution, PowerShell, cmd, tar, 7z, and network access are not used or accepted.")]
    public static BackupListResult BackupList()
    {
        ValidateBackupRoot();
        var items = new List<BackupListItem>();
        foreach (var path in Directory.EnumerateFiles(BackupRoot, "*.zip", SearchOption.TopDirectoryOnly)
                     .OrderBy(x => Path.GetFileName(x), StringComparer.OrdinalIgnoreCase))
        {
            if (items.Count >= 500) break;
            ValidateBackupFileName(Path.GetFileName(path));
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException($"Reparse-point backup files are not allowed: {path}");
            var info = new FileInfo(path);
            items.Add(new BackupListItem(info.Name, info.Length, new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero)));
        }

        var total = Directory.EnumerateFiles(BackupRoot, "*.zip", SearchOption.TopDirectoryOnly).Take(501).Count();
        return new BackupListResult(BackupRoot, items, total > 500, DateTimeOffset.UtcNow);
    }

    [McpServerTool(Name = "backup_inspect", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Inspect one direct .zip backup in the fixed YowThi ERP v4 development backup vault. The backup SHA-256, logical directory/file shape, per-file content hashes, expanded byte count, and canonical manifest/shape fingerprints are verified using System.IO.Compression and native .NET filesystem APIs. Traversal, absolute paths, Windows path collisions, symlink/reparse metadata, unsafe Windows names, oversized entries, and zip-bomb-scale expansion are rejected. This is read-only.")]
    public static BackupInspectionResult BackupInspect(string backupFileName)
    {
        var path = ValidateExistingBackupFile(backupFileName);
        var snapshot = ReadBackupSnapshot(path);
        return ToInspection(path, snapshot);
    }

    [McpServerTool(Name = "backup_create_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed Medium-risk plan to create one new .zip development backup in the fixed backup vault from one existing directory under C:\\Dev\\YowThi-ERP-Dev-v4. The recursive source tree is preflighted without following reparse points; every file is SHA-256 hashed and source manifest/shape fingerprints, counts, total bytes, exact paths, and destination absence are sealed. The backup vault is outside the repository so a repository-root backup cannot include itself. Overwrite, production paths, shell execution, PowerShell, cmd, tar, 7z, and network access are not supported.")]
    public static SignedPlan BackupCreatePlan(string sourceDirectory, string backupFileName)
    {
        var source = ValidateSourceDirectory(sourceDirectory);
        var destination = ValidateNewBackupDestination(backupFileName);
        var sourceSnapshot = ComputeDirectorySnapshot(source);

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["sourceDirectory"] = source,
            ["backupFileName"] = Path.GetFileName(destination),
            ["backupPath"] = destination,
            ["sourceManifestSha256"] = sourceSnapshot.ManifestSha256,
            ["sourceShapeSha256"] = sourceSnapshot.ShapeSha256,
            ["entryCount"] = sourceSnapshot.EntryCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["fileCount"] = sourceSnapshot.FileCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["directoryCount"] = sourceSnapshot.DirectoryCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["totalBytes"] = sourceSnapshot.TotalBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["destinationAbsent"] = "true"
        };

        var now = DateTimeOffset.UtcNow;
        var summary = $"Create development backup {Path.GetFileName(destination)} from {source} ({sourceSnapshot.FileCount} files, {sourceSnapshot.TotalBytes} bytes)";
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "backup", "create", destination, parameters, RiskClass.Medium, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary, sourceSnapshot.ManifestSha256, sourceSnapshot.ShapeSha256, sourceSnapshot.EntryCount, sourceSnapshot.TotalBytes }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "backup_create_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared backup/create plan using only System.IO.Compression and native .NET filesystem APIs. Exact signed intent, source tree manifest/shape, counts, byte totals, reparse policy, fixed backup vault, safe .zip leaf name, and destination absence are revalidated immediately before creation. The backup is written to a same-directory CreateNew temporary file, each copied source file is streamed and hash-verified, the completed ZIP is fully re-read and content-manifest verified, then atomically moved into place without overwrite. Failures remove only the newly created temporary/final backup.")]
    public static BackupCreateResult BackupCreateExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, operation, target, summary, riskClass, "create");

        var source = ValidateSourceDirectory(RequireParameter(plan, "sourceDirectory"));
        var destination = ValidateNewBackupDestination(RequireParameter(plan, "backupFileName"));
        if (!string.Equals(destination, RequireParameter(plan, "backupPath"), StringComparison.OrdinalIgnoreCase) || !string.Equals(destination, plan.Target, StringComparison.Ordinal))
            throw new InvalidOperationException("Backup destination no longer matches the signed plan.");
        if (!string.Equals(RequireParameter(plan, "destinationAbsent"), "true", StringComparison.Ordinal))
            throw new InvalidDataException("Signed backup destination absence state is invalid.");

        var expected = ReadExpectedTreeState(plan, "source");
        var current = ComputeDirectorySnapshot(source);
        RequireTreeMatch(expected, current, "Backup source tree changed after plan preparation.");
        if (File.Exists(destination) || Directory.Exists(destination))
            throw new InvalidOperationException("Backup destination appeared after plan preparation.");

        try
        {
            CreateBackupZip(source, destination, current, plan.PlanId);
            var final = ReadBackupSnapshot(destination);
            RequireBackupMatchesTree(final, expected);

            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, source, destination, final.BackupSha256, final.ManifestSha256, final.ShapeSha256, final.EntryCount, final.TotalExpandedBytes }, "executed");
            return new BackupCreateResult(plan.PlanId, source, destination, final.BackupSha256, final.ManifestSha256, final.ShapeSha256, final.EntryCount, final.FileCount, final.DirectoryCount, final.TotalExpandedBytes, "backup-created", DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, source, destination, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "backup_restore_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to restore one existing direct backup from the fixed YowThi ERP v4 backup vault into one new directory under C:\\Dev\\YowThi-ERP-Dev-v4. The complete backup SHA-256, canonical content manifest, logical tree shape, counts, expanded byte total, exact backup path, exact new destination, and destination absence are sealed. ZIP traversal, absolute paths, Windows path collisions, unsafe names, symlink/reparse metadata, overwrite, existing destinations, .git targets, transfer-staging targets, production paths, shell execution, PowerShell, cmd, tar, and 7z are rejected.")]
    public static SignedPlan BackupRestorePlan(string backupFileName, string destinationDirectory)
    {
        var backupPath = ValidateExistingBackupFile(backupFileName);
        var snapshot = ReadBackupSnapshot(backupPath);
        var destination = ValidateNewRestoreDestination(destinationDirectory);

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["backupFileName"] = Path.GetFileName(backupPath),
            ["backupPath"] = backupPath,
            ["backupSha256"] = snapshot.BackupSha256,
            ["manifestSha256"] = snapshot.ManifestSha256,
            ["shapeSha256"] = snapshot.ShapeSha256,
            ["entryCount"] = snapshot.EntryCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["fileCount"] = snapshot.FileCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["directoryCount"] = snapshot.DirectoryCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["totalExpandedBytes"] = snapshot.TotalExpandedBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["destinationDirectory"] = destination,
            ["destinationAbsent"] = "true"
        };

        var now = DateTimeOffset.UtcNow;
        var summary = $"Restore development backup {Path.GetFileName(backupPath)} into new directory {destination} ({snapshot.EntryCount} entries, {snapshot.TotalExpandedBytes} expanded bytes)";
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "backup", "restore", destination, parameters, RiskClass.High, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary, snapshot.BackupSha256, snapshot.ManifestSha256, snapshot.ShapeSha256, snapshot.EntryCount, snapshot.TotalExpandedBytes }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "backup_restore_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared backup/restore plan using System.IO.Compression and native .NET filesystem APIs. Exact signed intent, backup SHA-256, canonical content manifest, logical tree shape, counts, expanded bytes, fixed-vault identity, safe ZIP preflight, new destination path, destination absence, .git/transfer-staging exclusions, and reparse policy are revalidated immediately before restore. Files use CreateNew semantics and never overwrite. Post-restore tree manifest and shape must exactly match the sealed backup. Failure performs best-effort cleanup of only the newly created restore destination.")]
    public static BackupRestoreResult BackupRestoreExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, operation, target, summary, riskClass, "restore");

        var backupPath = ValidateExistingBackupFile(RequireParameter(plan, "backupFileName"));
        if (!string.Equals(backupPath, RequireParameter(plan, "backupPath"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Backup path no longer matches the signed restore plan.");
        var destination = ValidateNewRestoreDestination(RequireParameter(plan, "destinationDirectory"));
        if (!string.Equals(destination, plan.Target, StringComparison.Ordinal))
            throw new InvalidOperationException("Restore destination no longer matches the signed plan.");
        if (!string.Equals(RequireParameter(plan, "destinationAbsent"), "true", StringComparison.Ordinal))
            throw new InvalidDataException("Signed restore destination absence state is invalid.");

        var expected = ReadExpectedBackupState(plan);
        var current = ReadBackupSnapshot(backupPath);
        RequireBackupMatch(expected, current, "Backup changed after restore plan preparation.");
        if (Directory.Exists(destination) || File.Exists(destination))
            throw new InvalidOperationException("Restore destination appeared after plan preparation.");

        try
        {
            RestoreBackup(backupPath, destination);
            var restored = ComputeDirectorySnapshot(destination);
            if (!string.Equals(restored.ManifestSha256, expected.ManifestSha256, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(restored.ShapeSha256, expected.ShapeSha256, StringComparison.OrdinalIgnoreCase)
                || restored.EntryCount != expected.EntryCount
                || restored.FileCount != expected.FileCount
                || restored.DirectoryCount != expected.DirectoryCount
                || restored.TotalBytes != expected.TotalExpandedBytes)
                throw new InvalidOperationException("Restored tree does not match the sealed backup manifest/shape.");

            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, backupPath, destination, expected.BackupSha256, restored.ManifestSha256, restored.ShapeSha256, restored.EntryCount, restored.TotalBytes }, "executed");
            return new BackupRestoreResult(plan.PlanId, backupPath, destination, expected.BackupSha256, restored.ManifestSha256, restored.ShapeSha256, restored.EntryCount, restored.FileCount, restored.DirectoryCount, restored.TotalBytes, "backup-restored", DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            try { if (Directory.Exists(destination)) SafeDeleteTree(destination); } catch { }
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, backupPath, destination, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "backup_remove_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed Medium-risk plan to remove one existing direct .zip backup from the fixed YowThi ERP v4 development backup vault. The safe backup leaf name, exact fixed-vault path, compressed byte length, full backup SHA-256, canonical manifest/shape fingerprints, counts, and file-present state are sealed. Arbitrary paths, directories, recursive deletion, production paths, shell execution, PowerShell, and cmd are not supported.")]
    public static SignedPlan BackupRemovePlan(string backupFileName)
    {
        var path = ValidateExistingBackupFile(backupFileName);
        var snapshot = ReadBackupSnapshot(path);
        var compressedBytes = new FileInfo(path).Length;
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["backupFileName"] = Path.GetFileName(path),
            ["backupPath"] = path,
            ["compressedBytes"] = compressedBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["backupSha256"] = snapshot.BackupSha256,
            ["manifestSha256"] = snapshot.ManifestSha256,
            ["shapeSha256"] = snapshot.ShapeSha256,
            ["entryCount"] = snapshot.EntryCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["totalExpandedBytes"] = snapshot.TotalExpandedBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["filePresent"] = "true"
        };

        var now = DateTimeOffset.UtcNow;
        var summary = $"Remove development backup {Path.GetFileName(path)} after exact SHA-256 and manifest revalidation ({compressedBytes} compressed bytes)";
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "backup", "remove", path, parameters, RiskClass.Medium, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary, compressedBytes, snapshot.BackupSha256, snapshot.ManifestSha256 }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "backup_remove_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared backup/remove plan using only the native .NET File.Delete API. Exact signed intent, fixed backup-vault identity, direct safe .zip leaf name, compressed byte length, backup SHA-256, canonical manifest/shape, counts, file-present state, and reparse policy are revalidated immediately before deletion. Post-delete read-back must prove the exact backup is absent. No arbitrary path, directory, or recursive deletion is supported.")]
    public static BackupRemoveResult BackupRemoveExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, operation, target, summary, riskClass, "remove");
        if (!string.Equals(RequireParameter(plan, "filePresent"), "true", StringComparison.Ordinal))
            throw new InvalidDataException("Signed backup file-present state is invalid.");

        var path = ValidateExistingBackupFile(RequireParameter(plan, "backupFileName"));
        if (!string.Equals(path, RequireParameter(plan, "backupPath"), StringComparison.OrdinalIgnoreCase) || !string.Equals(path, plan.Target, StringComparison.Ordinal))
            throw new InvalidOperationException("Backup remove path no longer matches the signed plan.");
        if (!long.TryParse(RequireParameter(plan, "compressedBytes"), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var expectedCompressedBytes) || expectedCompressedBytes < 0 || expectedCompressedBytes > MaxBackupFileBytes)
            throw new InvalidDataException("Signed compressed backup byte length is invalid.");
        if (new FileInfo(path).Length != expectedCompressedBytes)
            throw new InvalidOperationException("Backup compressed byte length changed after plan preparation.");

        var expected = ReadExpectedBackupState(plan, includeCounts: false);
        var current = ReadBackupSnapshot(path);
        if (!string.Equals(current.BackupSha256, expected.BackupSha256, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(current.ManifestSha256, expected.ManifestSha256, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(current.ShapeSha256, expected.ShapeSha256, StringComparison.OrdinalIgnoreCase)
            || current.EntryCount != expected.EntryCount
            || current.TotalExpandedBytes != expected.TotalExpandedBytes)
            throw new InvalidOperationException("Backup changed after remove plan preparation.");

        try
        {
            File.Delete(path);
            if (File.Exists(path) || Directory.Exists(path))
                throw new IOException("Backup removal verification failed because the target still exists.");

            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, path, expectedCompressedBytes, expected.BackupSha256, outcome = "backup-removed" }, "executed");
            return new BackupRemoveResult(plan.PlanId, Path.GetFileName(path), path, expectedCompressedBytes, expected.BackupSha256, false, "backup-removed", DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, path, error = ex.Message }, "failed");
            throw;
        }
    }

    private static BackupInspectionResult ToInspection(string path, BackupSnapshot snapshot)
        => new(Path.GetFileName(path), path, new FileInfo(path).Length, snapshot.BackupSha256, snapshot.ManifestSha256, snapshot.ShapeSha256, snapshot.EntryCount, snapshot.FileCount, snapshot.DirectoryCount, snapshot.TotalExpandedBytes, snapshot.Entries.Select(e => new BackupEntryInspection(e.RelativePath, e.IsDirectory ? "directory" : "file", e.IsDirectory ? null : e.Length, e.IsDirectory ? null : e.Sha256)).ToArray(), DateTimeOffset.UtcNow);

    private static void CreateBackupZip(string source, string destination, DirectorySnapshot sourceSnapshot, string planId)
    {
        var temp = destination + $".yowthi-{planId}.tmp";
        if (File.Exists(temp) || Directory.Exists(temp)) throw new InvalidOperationException("Backup temporary path already exists.");
        var moved = false;
        try
        {
            using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
            using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: false, entryNameEncoding: Encoding.UTF8))
            {
                foreach (var item in sourceSnapshot.Entries.OrderBy(x => x.RelativePath, StringComparer.Ordinal))
                {
                    if (item.IsDirectory)
                    {
                        archive.CreateEntry(item.RelativePath.TrimEnd('/') + "/", CompressionLevel.NoCompression);
                        continue;
                    }

                    var zipEntry = archive.CreateEntry(item.RelativePath, CompressionLevel.Optimal);
                    using var input = new FileStream(item.FullPath!, FileMode.Open, FileAccess.Read, FileShare.Read);
                    using var entryStream = zipEntry.Open();
                    using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    var buffer = new byte[128 * 1024];
                    long copied = 0;
                    while (true)
                    {
                        var read = input.Read(buffer, 0, buffer.Length);
                        if (read == 0) break;
                        copied = checked(copied + read);
                        if (copied > item.Length || copied > MaxSingleFileBytes)
                            throw new InvalidOperationException($"Backup source file changed while copying: {item.RelativePath}");
                        hash.AppendData(buffer, 0, read);
                        entryStream.Write(buffer, 0, read);
                    }
                    var sha = Convert.ToHexString(hash.GetHashAndReset());
                    if (copied != item.Length || !string.Equals(sha, item.Sha256, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException($"Backup source file changed while copying: {item.RelativePath}");
                }
            }

            var afterCopySource = ComputeDirectorySnapshot(source);
            if (!string.Equals(afterCopySource.ManifestSha256, sourceSnapshot.ManifestSha256, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(afterCopySource.ShapeSha256, sourceSnapshot.ShapeSha256, StringComparison.OrdinalIgnoreCase)
                || afterCopySource.EntryCount != sourceSnapshot.EntryCount
                || afterCopySource.TotalBytes != sourceSnapshot.TotalBytes)
                throw new InvalidOperationException("Backup source tree changed while backup creation was in progress.");

            var zipSnapshot = ReadBackupSnapshotInternal(temp);
            if (!string.Equals(zipSnapshot.ManifestSha256, sourceSnapshot.ManifestSha256, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(zipSnapshot.ShapeSha256, sourceSnapshot.ShapeSha256, StringComparison.OrdinalIgnoreCase)
                || zipSnapshot.EntryCount != sourceSnapshot.EntryCount
                || zipSnapshot.FileCount != sourceSnapshot.FileCount
                || zipSnapshot.DirectoryCount != sourceSnapshot.DirectoryCount
                || zipSnapshot.TotalExpandedBytes != sourceSnapshot.TotalBytes)
                throw new InvalidOperationException("Created backup verification failed against the source manifest/shape.");

            File.Move(temp, destination);
            moved = true;
        }
        catch
        {
            try { if (File.Exists(temp)) File.Delete(temp); } catch { }
            if (moved) { try { if (File.Exists(destination)) File.Delete(destination); } catch { } }
            throw;
        }
    }

    private static void RestoreBackup(string backupPath, string destination)
    {
        Directory.CreateDirectory(destination);
        try
        {
            using var stream = new FileStream(backupPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false, entryNameEncoding: Encoding.UTF8);
            foreach (var entry in archive.Entries)
            {
                var normalized = NormalizeZipEntry(entry.FullName, out var isDirectory);
                if (normalized.Length == 0) continue;
                if (IsSymlinkOrReparseZipEntry(entry)) throw new InvalidDataException($"Backup entry carries symlink/reparse metadata: {entry.FullName}");

                var relativeWindows = normalized.Replace('/', Path.DirectorySeparatorChar);
                var target = Path.GetFullPath(Path.Combine(destination, relativeWindows));
                if (!IsUnderRoot(target, destination)) throw new InvalidDataException($"Backup entry escaped restore destination: {entry.FullName}");

                if (isDirectory)
                {
                    Directory.CreateDirectory(target);
                    continue;
                }

                var parent = Path.GetDirectoryName(target) ?? throw new InvalidDataException("Backup restore target has no parent directory.");
                Directory.CreateDirectory(parent);
                using var input = entry.Open();
                using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                var buffer = new byte[128 * 1024];
                long copied = 0;
                while (true)
                {
                    var read = input.Read(buffer, 0, buffer.Length);
                    if (read == 0) break;
                    copied = checked(copied + read);
                    if (copied > entry.Length || copied > MaxSingleFileBytes)
                        throw new InvalidDataException($"Backup entry expanded beyond its declared/allowed length: {entry.FullName}");
                    output.Write(buffer, 0, read);
                }
                output.Flush(flushToDisk: true);
                if (copied != entry.Length) throw new InvalidDataException($"Backup entry length mismatch during restore: {entry.FullName}");
            }
        }
        catch
        {
            try { if (Directory.Exists(destination)) SafeDeleteTree(destination); } catch { }
            throw;
        }
    }

    private static DirectorySnapshot ComputeDirectorySnapshot(string root)
    {
        var entries = new List<TreeEntry>();
        var stack = new Stack<string>();
        stack.Push(root);
        long totalBytes = 0;
        var fileCount = 0;
        var directoryCount = 0;

        while (stack.Count > 0)
        {
            var current = stack.Pop();
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException($"Reparse-point directories are not allowed in backup source/restore trees: {current}");

            foreach (var path in Directory.EnumerateFileSystemEntries(current, "*", SearchOption.TopDirectoryOnly))
            {
                var attributes = File.GetAttributes(path);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new UnauthorizedAccessException($"Reparse-point entries are not allowed in backup source/restore trees: {path}");
                var relative = Path.GetRelativePath(root, path).Replace('\\', '/');
                if (relative.Length == 0 || relative == ".") continue;
                ValidateRelativeTreePath(relative);

                if ((attributes & FileAttributes.Directory) != 0)
                {
                    directoryCount++;
                    EnsureEntryLimit(entries.Count + 1);
                    entries.Add(new TreeEntry(relative, path, true, 0, string.Empty));
                    stack.Push(path);
                }
                else
                {
                    var state = HashFile(path);
                    if (state.Bytes > MaxSingleFileBytes) throw new InvalidDataException($"Backup file exceeds the fixed single-file limit: {path}");
                    totalBytes = checked(totalBytes + state.Bytes);
                    if (totalBytes > MaxExpandedBytes) throw new InvalidDataException("Backup tree exceeds the fixed expanded-byte limit.");
                    fileCount++;
                    EnsureEntryLimit(entries.Count + 1);
                    entries.Add(new TreeEntry(relative, path, false, state.Bytes, state.Sha256));
                }
            }
        }

        entries.Sort((a, b) => StringComparer.Ordinal.Compare(a.RelativePath, b.RelativePath));
        var manifestLines = entries.Select(e => e.IsDirectory ? $"D|{e.RelativePath}" : $"F|{e.RelativePath}|{e.Length}|{e.Sha256}").ToArray();
        var shapeLines = entries.Select(e => e.IsDirectory ? $"D|{e.RelativePath}" : $"F|{e.RelativePath}|{e.Length}").ToArray();
        return new DirectorySnapshot(entries, HashCanonical(manifestLines), HashCanonical(shapeLines), entries.Count, fileCount, directoryCount, totalBytes);
    }

    private static BackupSnapshot ReadBackupSnapshot(string path)
    {
        var validated = ValidateBackupPathInternal(path, requireZipLeaf: true, requireExists: true);
        return ReadBackupSnapshotInternal(validated);
    }

    private static BackupSnapshot ReadBackupSnapshotInternal(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists) throw new FileNotFoundException("Backup file does not exist.", path);
        if (info.Length > MaxBackupFileBytes) throw new InvalidDataException("Backup file exceeds the fixed compressed-size limit.");
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Reparse-point backup files are not allowed.");

        var logical = new Dictionary<string, LogicalBackupEntry>(StringComparer.OrdinalIgnoreCase);
        var explicitDirectories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long totalExpanded = 0;
        var actualEntries = 0;

        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: false, entryNameEncoding: Encoding.UTF8))
        {
            foreach (var entry in archive.Entries)
            {
                actualEntries++;
                if (actualEntries > MaxEntries) throw new InvalidDataException("Backup ZIP exceeds the fixed entry-count limit.");
                if (IsSymlinkOrReparseZipEntry(entry)) throw new InvalidDataException($"Backup entry carries symlink/reparse metadata: {entry.FullName}");
                var normalized = NormalizeZipEntry(entry.FullName, out var isDirectory);
                if (normalized.Length == 0) continue;

                AddImplicitParentDirectories(logical, normalized);
                if (isDirectory)
                {
                    if (!explicitDirectories.Add(normalized)) throw new InvalidDataException($"Duplicate explicit backup directory entry: {normalized}");
                    AddLogicalDirectory(logical, normalized);
                    continue;
                }

                if (entry.Length < 0 || entry.Length > MaxSingleFileBytes)
                    throw new InvalidDataException($"Backup entry exceeds the fixed single-file limit: {normalized}");
                totalExpanded = checked(totalExpanded + entry.Length);
                if (totalExpanded > MaxExpandedBytes) throw new InvalidDataException("Backup ZIP exceeds the fixed expanded-byte limit.");

                using var input = entry.Open();
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var buffer = new byte[128 * 1024];
                long readTotal = 0;
                while (true)
                {
                    var read = input.Read(buffer, 0, buffer.Length);
                    if (read == 0) break;
                    readTotal = checked(readTotal + read);
                    if (readTotal > entry.Length || readTotal > MaxSingleFileBytes)
                        throw new InvalidDataException($"Backup entry expanded beyond its declared/allowed length: {normalized}");
                    hash.AppendData(buffer, 0, read);
                }
                if (readTotal != entry.Length) throw new InvalidDataException($"Backup entry length mismatch: {normalized}");
                AddLogicalFile(logical, normalized, entry.Length, Convert.ToHexString(hash.GetHashAndReset()));
            }
        }

        if (logical.Count > MaxEntries) throw new InvalidDataException("Backup logical tree exceeds the fixed entry-count limit.");
        var entries = logical.Values.OrderBy(x => x.RelativePath, StringComparer.Ordinal).ToArray();
        var manifestLines = entries.Select(e => e.IsDirectory ? $"D|{e.RelativePath}" : $"F|{e.RelativePath}|{e.Length}|{e.Sha256}").ToArray();
        var shapeLines = entries.Select(e => e.IsDirectory ? $"D|{e.RelativePath}" : $"F|{e.RelativePath}|{e.Length}").ToArray();
        return new BackupSnapshot(
            Sha256File(path),
            HashCanonical(manifestLines),
            HashCanonical(shapeLines),
            entries.Length,
            entries.Count(x => !x.IsDirectory),
            entries.Count(x => x.IsDirectory),
            entries.Where(x => !x.IsDirectory).Sum(x => x.Length),
            entries);
    }

    private static void AddImplicitParentDirectories(Dictionary<string, LogicalBackupEntry> logical, string normalized)
    {
        var parts = normalized.Split('/');
        for (var i = 1; i < parts.Length; i++)
        {
            var parent = string.Join('/', parts.Take(i));
            AddLogicalDirectory(logical, parent);
        }
    }

    private static void AddLogicalDirectory(Dictionary<string, LogicalBackupEntry> logical, string path)
    {
        if (logical.TryGetValue(path, out var existing))
        {
            if (!existing.IsDirectory) throw new InvalidDataException($"Backup file/directory path collision: {path}");
            return;
        }
        logical[path] = new LogicalBackupEntry(path, true, 0, string.Empty);
        EnsureEntryLimit(logical.Count);
    }

    private static void AddLogicalFile(Dictionary<string, LogicalBackupEntry> logical, string path, long length, string sha256)
    {
        if (logical.ContainsKey(path)) throw new InvalidDataException($"Duplicate or colliding backup file entry: {path}");
        logical[path] = new LogicalBackupEntry(path, false, length, sha256);
        EnsureEntryLimit(logical.Count);
    }

    private static string NormalizeZipEntry(string rawName, out bool isDirectory)
    {
        var raw = (rawName ?? string.Empty).Replace('\\', '/');
        isDirectory = raw.EndsWith("/", StringComparison.Ordinal);
        raw = raw.TrimEnd('/');
        if (raw.Length == 0) return string.Empty;
        if (raw.StartsWith("/", StringComparison.Ordinal) || raw.StartsWith("//", StringComparison.Ordinal) || Path.IsPathRooted(raw))
            throw new InvalidDataException($"Absolute backup entry path is not allowed: {rawName}");

        var parts = raw.Split('/');
        if (parts.Any(p => p.Length == 0)) throw new InvalidDataException($"Backup entry contains an empty path segment: {rawName}");
        foreach (var part in parts)
        {
            if (part is "." or "..") throw new InvalidDataException($"Backup traversal entry is not allowed: {rawName}");
            ValidateWindowsSegment(part);
        }
        return string.Join('/', parts);
    }

    private static void ValidateRelativeTreePath(string relative)
    {
        var parts = relative.Replace('\\', '/').Split('/');
        if (parts.Any(p => p.Length == 0 || p is "." or "..")) throw new InvalidDataException($"Unsafe backup tree relative path: {relative}");
        foreach (var part in parts) ValidateWindowsSegment(part);
    }

    private static void ValidateWindowsSegment(string segment)
    {
        if (segment.Length == 0 || segment.Length > 255 || segment.EndsWith(' ') || segment.EndsWith('.') || segment.Any(char.IsControl) || segment.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || IsReservedWindowsName(segment))
            throw new InvalidDataException($"Unsafe Windows backup path segment: {segment}");
    }

    private static bool IsReservedWindowsName(string fileName)
    {
        var stem = fileName.Split('.')[0].TrimEnd(' ', '.').ToUpperInvariant();
        if (stem is "CON" or "PRN" or "AUX" or "NUL") return true;
        return stem.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal)) && stem[3] is >= '1' and <= '9';
    }

    private static bool IsSymlinkOrReparseZipEntry(ZipArchiveEntry entry)
    {
        var external = unchecked((uint)entry.ExternalAttributes);
        var unixType = (external >> 16) & 0xF000;
        var dosAttributes = external & 0xFFFF;
        return unixType == 0xA000 || (dosAttributes & (uint)FileAttributes.ReparsePoint) != 0;
    }

    private static (long Bytes, string Sha256) HashFile(string path)
    {
        var info = new FileInfo(path);
        if (info.Length > MaxSingleFileBytes) throw new InvalidDataException($"Backup source file exceeds the fixed single-file limit: {path}");
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[128 * 1024];
        long total = 0;
        while (true)
        {
            var read = input.Read(buffer, 0, buffer.Length);
            if (read == 0) break;
            total = checked(total + read);
            if (total > MaxSingleFileBytes) throw new InvalidDataException($"Backup source file exceeds the fixed single-file limit while hashing: {path}");
            hash.AppendData(buffer, 0, read);
        }
        if (total != info.Length) throw new InvalidOperationException($"Backup source file changed while hashing: {path}");
        return (total, Convert.ToHexString(hash.GetHashAndReset()));
    }

    private static string Sha256File(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string HashCanonical(IEnumerable<string> lines)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", lines))));

    private static void SafeDeleteTree(string root)
    {
        var info = new DirectoryInfo(root);
        if (!info.Exists) return;
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            Directory.Delete(root, false);
            return;
        }
        foreach (var entry in info.EnumerateFileSystemInfos())
        {
            if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                if ((entry.Attributes & FileAttributes.Directory) != 0) Directory.Delete(entry.FullName, false);
                else File.Delete(entry.FullName);
                continue;
            }
            if ((entry.Attributes & FileAttributes.Directory) != 0) SafeDeleteTree(entry.FullName);
            else File.Delete(entry.FullName);
        }
        Directory.Delete(root, false);
    }

    private static string ValidateSourceDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)) throw new ArgumentException("Backup source directory must be an absolute path.", nameof(path));
        var full = Path.GetFullPath(path);
        if (!IsUnderRoot(full, DevRoot)) throw new UnauthorizedAccessException("Backup source directory must remain under the YowThi ERP v4 development root.");
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException($"Backup source directory does not exist: {full}");
        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Reparse-point backup source directories are not allowed.");
        RequireNoReparseTraversal(full, DevRoot);
        return full;
    }

    private static string ValidateNewRestoreDestination(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)) throw new ArgumentException("Backup restore destination must be an absolute path.", nameof(path));
        var full = Path.GetFullPath(path);
        if (!IsUnderRoot(full, DevRoot)) throw new UnauthorizedAccessException("Backup restore destination must remain under the YowThi ERP v4 development root.");
        if (IsUnderRoot(full, GitRoot)) throw new UnauthorizedAccessException("Backup restore destinations may not be inside .git.");
        if (IsUnderRoot(full, TransferRoot)) throw new UnauthorizedAccessException("Backup restore destinations may not be inside transfer staging.");
        if (File.Exists(full) || Directory.Exists(full)) throw new IOException("Backup restore destination already exists.");
        var parent = Path.GetDirectoryName(full) ?? throw new ArgumentException("Backup restore destination requires a parent directory.", nameof(path));
        if (!Directory.Exists(parent)) throw new DirectoryNotFoundException($"Backup restore destination parent does not exist: {parent}");
        RequireNoReparseTraversal(parent, DevRoot);
        return full;
    }

    private static string ValidateNewBackupDestination(string backupFileName)
    {
        ValidateBackupRoot();
        var leaf = ValidateBackupFileName(backupFileName);
        var path = Path.GetFullPath(Path.Combine(BackupRoot, leaf));
        if (!IsUnderRoot(path, BackupRoot)) throw new UnauthorizedAccessException("Backup destination escaped the fixed backup vault.");
        if (File.Exists(path) || Directory.Exists(path)) throw new IOException("Backup destination already exists.");
        return path;
    }

    private static string ValidateExistingBackupFile(string backupFileName)
    {
        ValidateBackupRoot();
        var leaf = ValidateBackupFileName(backupFileName);
        var path = Path.GetFullPath(Path.Combine(BackupRoot, leaf));
        return ValidateBackupPathInternal(path, requireZipLeaf: true, requireExists: true);
    }

    private static string ValidateBackupPathInternal(string path, bool requireZipLeaf, bool requireExists)
    {
        var full = Path.GetFullPath(path);
        if (!IsUnderRoot(full, BackupRoot)) throw new UnauthorizedAccessException("Backup path escaped the fixed backup vault.");
        if (requireZipLeaf) ValidateBackupFileName(Path.GetFileName(full));
        if (requireExists && !File.Exists(full)) throw new FileNotFoundException("Backup file does not exist.", full);
        if (Directory.Exists(full)) throw new InvalidOperationException("Backup target must be a file.");
        if (File.Exists(full) && (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Reparse-point backup files are not allowed.");
        return full;
    }

    private static string ValidateBackupFileName(string backupFileName)
    {
        var value = (backupFileName ?? string.Empty).Trim();
        if (value.Length == 0 || value.Length > 180) throw new ArgumentException("Backup file name must contain 1-180 characters.", nameof(backupFileName));
        if (!string.Equals(Path.GetFileName(value), value, StringComparison.Ordinal) || value is "." or ".." || value.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || value.EndsWith(' ') || value.EndsWith('.') || value.Any(char.IsControl) || IsReservedWindowsName(value))
            throw new ArgumentException("Backup file name is not a safe Windows leaf file name.", nameof(backupFileName));
        if (!string.Equals(Path.GetExtension(value), ".zip", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Backup file name must end in .zip.", nameof(backupFileName));
        return value;
    }

    private static void ValidateBackupRoot()
    {
        if (!Directory.Exists(BackupRoot)) throw new DirectoryNotFoundException($"Fixed backup vault does not exist: {BackupRoot}");
        if ((File.GetAttributes(BackupRoot) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Backup vault may not be a reparse point.");
        RequireNoReparseTraversal(BackupRoot, @"C:\Dev");
    }

    private static void RequireNoReparseTraversal(string path, string boundaryRoot)
    {
        var boundary = Path.GetFullPath(boundaryRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var currentPath = Directory.Exists(path) ? path : Path.GetDirectoryName(path)!;
        var current = new DirectoryInfo(currentPath);
        while (current is not null)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException($"Backup path may not traverse a reparse-point directory: {current.FullName}");
            if (string.Equals(current.FullName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), boundary, StringComparison.OrdinalIgnoreCase)) return;
            current = current.Parent;
        }
        throw new UnauthorizedAccessException("Backup path boundary validation failed.");
    }

    private static bool IsUnderRoot(string path, string root)
    {
        var fullPath = Path.GetFullPath(path);
        var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return string.Equals(fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), fullRoot, StringComparison.OrdinalIgnoreCase)
            || fullPath.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static void EnsureEntryLimit(int count)
    {
        if (count > MaxEntries) throw new InvalidDataException("Backup tree exceeds the fixed entry-count limit.");
    }

    private static ExpectedTreeState ReadExpectedTreeState(SignedPlan plan, string prefix)
        => new(
            RequireParameter(plan, $"{prefix}ManifestSha256"),
            RequireParameter(plan, $"{prefix}ShapeSha256"),
            ParseInt(RequireParameter(plan, "entryCount"), "entryCount"),
            ParseInt(RequireParameter(plan, "fileCount"), "fileCount"),
            ParseInt(RequireParameter(plan, "directoryCount"), "directoryCount"),
            ParseLong(RequireParameter(plan, "totalBytes"), "totalBytes"));

    private static ExpectedBackupState ReadExpectedBackupState(SignedPlan plan, bool includeCounts = true)
        => new(
            RequireHash(RequireParameter(plan, "backupSha256"), "backupSha256"),
            RequireHash(RequireParameter(plan, "manifestSha256"), "manifestSha256"),
            RequireHash(RequireParameter(plan, "shapeSha256"), "shapeSha256"),
            ParseInt(RequireParameter(plan, "entryCount"), "entryCount"),
            includeCounts ? ParseInt(RequireParameter(plan, "fileCount"), "fileCount") : 0,
            includeCounts ? ParseInt(RequireParameter(plan, "directoryCount"), "directoryCount") : 0,
            ParseLong(RequireParameter(plan, "totalExpandedBytes"), "totalExpandedBytes"));

    private static void RequireTreeMatch(ExpectedTreeState expected, DirectorySnapshot current, string message)
    {
        if (!string.Equals(current.ManifestSha256, RequireHash(expected.ManifestSha256, "sourceManifestSha256"), StringComparison.OrdinalIgnoreCase)
            || !string.Equals(current.ShapeSha256, RequireHash(expected.ShapeSha256, "sourceShapeSha256"), StringComparison.OrdinalIgnoreCase)
            || current.EntryCount != expected.EntryCount || current.FileCount != expected.FileCount || current.DirectoryCount != expected.DirectoryCount || current.TotalBytes != expected.TotalBytes)
            throw new InvalidOperationException(message);
    }

    private static void RequireBackupMatchesTree(BackupSnapshot backup, ExpectedTreeState expected)
    {
        if (!string.Equals(backup.ManifestSha256, expected.ManifestSha256, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(backup.ShapeSha256, expected.ShapeSha256, StringComparison.OrdinalIgnoreCase)
            || backup.EntryCount != expected.EntryCount || backup.FileCount != expected.FileCount || backup.DirectoryCount != expected.DirectoryCount || backup.TotalExpandedBytes != expected.TotalBytes)
            throw new InvalidOperationException("Backup content does not match the signed source tree.");
    }

    private static void RequireBackupMatch(ExpectedBackupState expected, BackupSnapshot current, string message)
    {
        if (!string.Equals(current.BackupSha256, expected.BackupSha256, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(current.ManifestSha256, expected.ManifestSha256, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(current.ShapeSha256, expected.ShapeSha256, StringComparison.OrdinalIgnoreCase)
            || current.EntryCount != expected.EntryCount || current.FileCount != expected.FileCount || current.DirectoryCount != expected.DirectoryCount || current.TotalExpandedBytes != expected.TotalExpandedBytes)
            throw new InvalidOperationException(message);
    }

    private static string RequireHash(string value, string name)
    {
        if (value.Length != 64 || value.Any(ch => !Uri.IsHexDigit(ch))) throw new InvalidDataException($"Signed backup hash {name} is invalid.");
        return value;
    }

    private static int ParseInt(string value, string name)
        => int.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var result) && result >= 0 && result <= MaxEntries
            ? result : throw new InvalidDataException($"Signed backup integer {name} is invalid.");

    private static long ParseLong(string value, string name)
        => long.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var result) && result >= 0 && result <= MaxExpandedBytes
            ? result : throw new InvalidDataException($"Signed backup length {name} is invalid.");

    private static string RequireParameter(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : throw new InvalidDataException($"Signed backup parameter {key} is required.");

    private static void RequireIntentMatch(SignedPlan plan, string operation, string target, string summary, string riskClass, string expectedOperation)
    {
        if (!string.Equals(plan.Tool, "backup", StringComparison.Ordinal)
            || !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal)
            || !string.Equals(plan.Operation, operation, StringComparison.Ordinal)
            || !string.Equals(plan.Target, target, StringComparison.Ordinal)
            || !string.Equals(plan.Summary, summary, StringComparison.Ordinal)
            || !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Backup plan execution intent mismatch.");
    }

    private sealed record TreeEntry(string RelativePath, string? FullPath, bool IsDirectory, long Length, string Sha256);
    private sealed record DirectorySnapshot(IReadOnlyList<TreeEntry> Entries, string ManifestSha256, string ShapeSha256, int EntryCount, int FileCount, int DirectoryCount, long TotalBytes);
    private sealed record LogicalBackupEntry(string RelativePath, bool IsDirectory, long Length, string Sha256);
    private sealed record BackupSnapshot(string BackupSha256, string ManifestSha256, string ShapeSha256, int EntryCount, int FileCount, int DirectoryCount, long TotalExpandedBytes, IReadOnlyList<LogicalBackupEntry> Entries);
    private sealed record ExpectedTreeState(string ManifestSha256, string ShapeSha256, int EntryCount, int FileCount, int DirectoryCount, long TotalBytes);
    private sealed record ExpectedBackupState(string BackupSha256, string ManifestSha256, string ShapeSha256, int EntryCount, int FileCount, int DirectoryCount, long TotalExpandedBytes);
}

public sealed record BackupListItem(string FileName, long CompressedBytes, DateTimeOffset LastWriteTimeUtc);
public sealed record BackupListResult(string BackupRoot, IReadOnlyList<BackupListItem> Items, bool Truncated, DateTimeOffset CheckedUtc);
public sealed record BackupEntryInspection(string RelativePath, string Kind, long? Bytes, string? Sha256);
public sealed record BackupInspectionResult(string BackupFileName, string FullPath, long CompressedBytes, string BackupSha256, string ManifestSha256, string ShapeSha256, int EntryCount, int FileCount, int DirectoryCount, long TotalExpandedBytes, IReadOnlyList<BackupEntryInspection> Entries, DateTimeOffset CheckedUtc);
public sealed record BackupCreateResult(string PlanId, string SourceDirectory, string BackupPath, string BackupSha256, string ManifestSha256, string ShapeSha256, int EntryCount, int FileCount, int DirectoryCount, long TotalExpandedBytes, string Outcome, DateTimeOffset ExecutedUtc);
public sealed record BackupRestoreResult(string PlanId, string BackupPath, string DestinationDirectory, string BackupSha256, string ManifestSha256, string ShapeSha256, int EntryCount, int FileCount, int DirectoryCount, long TotalBytes, string Outcome, DateTimeOffset ExecutedUtc);
public sealed record BackupRemoveResult(string PlanId, string BackupFileName, string FullPath, long CompressedBytes, string BackupSha256, bool PresentAfter, string Outcome, DateTimeOffset ExecutedUtc);
