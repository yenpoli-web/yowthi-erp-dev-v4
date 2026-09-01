using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Transfer;

[McpServerToolType]
public static class TransferTools
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string TransferRoot = @"C:\Dev\YowThi-ERP-Dev-v4\staging\transfer";
    private const string InboxRoot = @"C:\Dev\YowThi-ERP-Dev-v4\staging\transfer\inbox";
    private const string OutboxRoot = @"C:\Dev\YowThi-ERP-Dev-v4\staging\transfer\outbox";
    private const long MaxTransferBytes = 20L * 1024 * 1024 * 1024;

    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name = "transfer_inbox_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List direct staged entries in the fixed YowThi ERP v4 transfer inbox. This is read-only and does not create, move, copy, delete, upload, download, or extract files. Reparse points are rejected. No shell, PowerShell, cmd, network client, or generic command executor is used.")]
    public static TransferStagingListResult TransferInboxList() => ListStaging(InboxRoot, "inbox");

    [McpServerTool(Name = "transfer_outbox_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List direct staged entries in the fixed YowThi ERP v4 transfer outbox. This is read-only and does not create, move, copy, delete, upload, download, or extract files. Reparse points are rejected. No shell, PowerShell, cmd, network client, or generic command executor is used.")]
    public static TransferStagingListResult TransferOutboxList() => ListStaging(OutboxRoot, "outbox");

    [McpServerTool(Name = "transfer_inbox_inspect", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Inspect one direct file in the fixed YowThi ERP v4 transfer inbox by safe leaf file name. The result includes byte length and SHA-256. Subdirectories, traversal, reparse points, and files over the fixed transfer size limit are rejected. This is read-only.")]
    public static TransferFileInspection TransferInboxInspect(string fileName) => InspectStagedFile(InboxRoot, "inbox", fileName);

    [McpServerTool(Name = "transfer_outbox_inspect", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Inspect one direct file in the fixed YowThi ERP v4 transfer outbox by safe leaf file name. The result includes byte length and SHA-256. Subdirectories, traversal, reparse points, and files over the fixed transfer size limit are rejected. This is read-only.")]
    public static TransferFileInspection TransferOutboxInspect(string fileName) => InspectStagedFile(OutboxRoot, "outbox", fileName);

    [McpServerTool(Name = "transfer_import_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed Medium-risk plan to import one existing direct file from the fixed transfer inbox into one new file under the YowThi ERP v4 development root. Source path, source byte length, source SHA-256, exact destination, and destination absence are sealed. The destination parent must already exist and may not be inside the transfer staging root. Overwrite, production paths, reparse traversal, extraction, deletion, shell execution, and network access are not supported.")]
    public static SignedPlan TransferImportPlan(string stagedFileName, string destinationPath)
    {
        var source = ValidateStagedFile(InboxRoot, stagedFileName);
        var sourceState = InspectFile(source);
        var destination = ValidateNewDevelopmentDestination(destinationPath);
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["stagedFileName"] = Path.GetFileName(source),
            ["sourcePath"] = source,
            ["sourceBytes"] = sourceState.Bytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["sourceSha256"] = sourceState.Sha256,
            ["destinationPath"] = destination,
            ["destinationAbsent"] = "true"
        };
        var now = DateTimeOffset.UtcNow;
        var summary = $"Import staged transfer inbox file {Path.GetFileName(source)} to new development file {destination} ({sourceState.Bytes} bytes)";
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "transfer", "import", destination, parameters, RiskClass.Medium, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary, sourceState.Sha256, sourceState.Bytes }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "transfer_import_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared transfer/import plan using only native .NET filesystem APIs. Exact signed intent, fixed inbox source identity, source byte length/SHA-256, new destination path, destination absence, development-root policy, and reparse policy are revalidated immediately before copy. The file is copied to a same-directory temporary file, streamed SHA-256 is verified, then atomically moved into place without overwrite and verified again. The staged source is retained.")]
    public static TransferCopyResult TransferImportExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
        => ExecuteCopy(planId, approvalCode, operation, target, summary, riskClass, "import");

    [McpServerTool(Name = "transfer_export_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed Medium-risk plan to export one existing file under the YowThi ERP v4 development root into one new direct file in the fixed transfer outbox. Source path, source byte length, source SHA-256, safe outbox leaf name, exact destination, and destination absence are sealed. Production paths, transfer-root sources, overwrite, reparse traversal, deletion, shell execution, and network access are not supported.")]
    public static SignedPlan TransferExportPlan(string sourcePath, string stagedFileName)
    {
        var source = ValidateDevelopmentSourceFile(sourcePath);
        var sourceState = InspectFile(source);
        var destination = ValidateNewOutboxDestination(stagedFileName);
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["stagedFileName"] = Path.GetFileName(destination),
            ["sourcePath"] = source,
            ["sourceBytes"] = sourceState.Bytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["sourceSha256"] = sourceState.Sha256,
            ["destinationPath"] = destination,
            ["destinationAbsent"] = "true"
        };
        var now = DateTimeOffset.UtcNow;
        var summary = $"Export development file {source} to new transfer outbox file {Path.GetFileName(destination)} ({sourceState.Bytes} bytes)";
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "transfer", "export", destination, parameters, RiskClass.Medium, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary, sourceState.Sha256, sourceState.Bytes }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "transfer_export_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared transfer/export plan using only native .NET filesystem APIs. Exact signed intent, development source identity, source byte length/SHA-256, fixed outbox destination, safe leaf name, destination absence, and reparse policy are revalidated immediately before copy. The outbox file is created through a same-directory temporary file, streamed SHA-256 is verified, then atomically moved into place without overwrite and verified again. The development source is retained.")]
    public static TransferCopyResult TransferExportExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
        => ExecuteCopy(planId, approvalCode, operation, target, summary, riskClass, "export");

    private static TransferCopyResult ExecuteCopy(string planId, string approvalCode, string operation, string target, string summary, string riskClass, string expectedOperation)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, operation, target, summary, riskClass, expectedOperation);

        var source = expectedOperation == "import"
            ? ValidateStagedFile(InboxRoot, RequireParameter(plan, "stagedFileName"))
            : ValidateDevelopmentSourceFile(RequireParameter(plan, "sourcePath"));
        var destination = expectedOperation == "import"
            ? ValidateNewDevelopmentDestination(RequireParameter(plan, "destinationPath"))
            : ValidateNewOutboxDestination(RequireParameter(plan, "stagedFileName"));

        if (!string.Equals(source, RequireParameter(plan, "sourcePath"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Transfer source path no longer matches the signed plan.");
        if (!string.Equals(destination, RequireParameter(plan, "destinationPath"), StringComparison.OrdinalIgnoreCase) || !string.Equals(destination, plan.Target, StringComparison.Ordinal))
            throw new InvalidOperationException("Transfer destination path no longer matches the signed plan.");
        if (!string.Equals(RequireParameter(plan, "destinationAbsent"), "true", StringComparison.Ordinal))
            throw new InvalidDataException("Signed transfer destination absence state is invalid.");
        if (!long.TryParse(RequireParameter(plan, "sourceBytes"), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var expectedBytes) || expectedBytes < 0 || expectedBytes > MaxTransferBytes)
            throw new InvalidDataException("Signed transfer source byte length is invalid.");
        var expectedSha = RequireParameter(plan, "sourceSha256");
        if (expectedSha.Length != 64 || expectedSha.Any(ch => !Uri.IsHexDigit(ch)))
            throw new InvalidDataException("Signed transfer source SHA-256 is invalid.");

        var current = InspectFile(source);
        if (current.Bytes != expectedBytes || !string.Equals(current.Sha256, expectedSha, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Transfer source changed after plan preparation.");
        if (File.Exists(destination) || Directory.Exists(destination))
            throw new InvalidOperationException("Transfer destination appeared after plan preparation.");

        try
        {
            CopyVerified(source, destination, expectedBytes, expectedSha, plan.PlanId);
            var final = InspectFile(destination);
            if (final.Bytes != expectedBytes || !string.Equals(final.Sha256, expectedSha, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Transfer post-copy verification failed.");

            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, source, destination, expectedBytes, expectedSha, outcome = "transfer-copied" }, "executed");
            return new TransferCopyResult(plan.PlanId, expectedOperation, source, destination, expectedBytes, expectedSha, "transfer-copied", DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, source, destination, error = ex.Message }, "failed");
            throw;
        }
    }

    private static void CopyVerified(string source, string destination, long expectedBytes, string expectedSha, string planId)
    {
        var temp = destination + $".yowthi-{planId}.tmp";
        if (File.Exists(temp) || Directory.Exists(temp)) throw new InvalidOperationException("Transfer temporary path already exists.");
        var moved = false;
        try
        {
            long copied = 0;
            string streamedSha;
            using (var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            {
                var buffer = new byte[1024 * 128];
                while (true)
                {
                    var read = input.Read(buffer, 0, buffer.Length);
                    if (read == 0) break;
                    copied = checked(copied + read);
                    if (copied > expectedBytes || copied > MaxTransferBytes) throw new InvalidDataException("Transfer source expanded beyond the signed or allowed byte length while copying.");
                    hash.AppendData(buffer, 0, read);
                    output.Write(buffer, 0, read);
                }
                output.Flush(flushToDisk: true);
                streamedSha = Convert.ToHexString(hash.GetHashAndReset());
            }
            if (copied != expectedBytes || !string.Equals(streamedSha, expectedSha, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Transfer source changed while copy was in progress.");
            var tempState = InspectFile(temp);
            if (tempState.Bytes != expectedBytes || !string.Equals(tempState.Sha256, expectedSha, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Transfer temporary-file verification failed.");
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

    private static TransferStagingListResult ListStaging(string root, string area)
    {
        ValidateStagingRoot(root);
        var items = new List<TransferStagingItem>();
        foreach (var path in Directory.EnumerateFileSystemEntries(root, "*", SearchOption.TopDirectoryOnly).OrderBy(x => Path.GetFileName(x), StringComparer.OrdinalIgnoreCase))
        {
            var attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException($"Reparse-point transfer staging entries are not allowed: {path}");
            var isDirectory = (attributes & FileAttributes.Directory) != 0;
            var bytes = isDirectory ? (long?)null : new FileInfo(path).Length;
            var lastWrite = isDirectory ? Directory.GetLastWriteTimeUtc(path) : File.GetLastWriteTimeUtc(path);
            items.Add(new TransferStagingItem(Path.GetFileName(path), isDirectory ? "directory" : "file", bytes, new DateTimeOffset(lastWrite, TimeSpan.Zero)));
            if (items.Count >= 500) break;
        }
        var totalEntries = Directory.EnumerateFileSystemEntries(root, "*", SearchOption.TopDirectoryOnly).Take(501).Count();
        return new TransferStagingListResult(area, root, items, totalEntries > 500, DateTimeOffset.UtcNow);
    }

    private static TransferFileInspection InspectStagedFile(string root, string area, string fileName)
    {
        var path = ValidateStagedFile(root, fileName);
        var state = InspectFile(path);
        return new TransferFileInspection(area, Path.GetFileName(path), path, state.Bytes, state.Sha256, File.GetLastWriteTimeUtc(path), DateTimeOffset.UtcNow);
    }

    private static (long Bytes, string Sha256) InspectFile(string path)
    {
        var info = new FileInfo(path);
        if (info.Length > MaxTransferBytes) throw new InvalidDataException($"Transfer file exceeds the fixed {MaxTransferBytes} byte limit.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return (info.Length, Convert.ToHexString(SHA256.HashData(stream)));
    }

    private static string ValidateStagedFile(string root, string fileName)
    {
        ValidateStagingRoot(root);
        var leaf = ValidateLeafFileName(fileName);
        var path = Path.GetFullPath(Path.Combine(root, leaf));
        if (!IsUnderRoot(path, root)) throw new UnauthorizedAccessException("Transfer staged file escaped its fixed staging root.");
        if (!File.Exists(path)) throw new FileNotFoundException("Transfer staged file does not exist.", path);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Reparse-point staged files are not allowed.");
        return path;
    }

    private static string ValidateDevelopmentSourceFile(string path)
    {
        var full = ValidateDevelopmentPath(path);
        if (!File.Exists(full)) throw new FileNotFoundException("Transfer source file does not exist.", full);
        if (Directory.Exists(full)) throw new InvalidOperationException("Transfer source must be a file.");
        if (IsUnderRoot(full, TransferRoot)) throw new UnauthorizedAccessException("Transfer staging files cannot be re-exported as development sources.");
        RequireNoReparseTraversal(full);
        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Reparse-point transfer source files are not allowed.");
        return full;
    }

    private static string ValidateNewDevelopmentDestination(string path)
    {
        var full = ValidateDevelopmentPath(path);
        if (IsUnderRoot(full, TransferRoot)) throw new UnauthorizedAccessException("Transfer import destination may not be inside the transfer staging root.");
        if (File.Exists(full) || Directory.Exists(full)) throw new IOException("Transfer destination already exists.");
        var parent = Path.GetDirectoryName(full) ?? throw new ArgumentException("Transfer destination requires a parent directory.", nameof(path));
        if (!Directory.Exists(parent)) throw new DirectoryNotFoundException($"Transfer destination parent does not exist: {parent}");
        RequireNoReparseTraversal(parent);
        return full;
    }

    private static string ValidateNewOutboxDestination(string stagedFileName)
    {
        ValidateStagingRoot(OutboxRoot);
        var leaf = ValidateLeafFileName(stagedFileName);
        var destination = Path.GetFullPath(Path.Combine(OutboxRoot, leaf));
        if (!IsUnderRoot(destination, OutboxRoot)) throw new UnauthorizedAccessException("Transfer outbox destination escaped its fixed staging root.");
        if (File.Exists(destination) || Directory.Exists(destination)) throw new IOException("Transfer outbox destination already exists.");
        return destination;
    }

    private static string ValidateDevelopmentPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)) throw new ArgumentException("Transfer development path must be absolute.", nameof(path));
        var full = Path.GetFullPath(path);
        if (!IsUnderRoot(full, DevRoot)) throw new UnauthorizedAccessException("Transfer development paths must remain under the YowThi ERP v4 development root.");
        if (full.StartsWith(@"C:\yowthi-erp\", StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException("Production ERP paths are blocked.");
        return full;
    }

    private static string ValidateLeafFileName(string fileName)
    {
        var value = (fileName ?? string.Empty).Trim();
        if (value.Length == 0 || value.Length > 180) throw new ArgumentException("Transfer staged file name must contain 1-180 characters.", nameof(fileName));
        if (!string.Equals(Path.GetFileName(value), value, StringComparison.Ordinal) || value is "." or ".." || value.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || value.EndsWith(' ') || value.EndsWith('.') || value.Any(char.IsControl) || IsReservedWindowsName(value))
            throw new ArgumentException("Transfer staged file name is not a safe Windows leaf file name.", nameof(fileName));
        return value;
    }

    private static bool IsReservedWindowsName(string fileName)
    {
        var stem = fileName.Split('.')[0].TrimEnd(' ', '.').ToUpperInvariant();
        if (stem is "CON" or "PRN" or "AUX" or "NUL") return true;
        return stem.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal)) && stem[3] is >= '1' and <= '9';
    }

    private static void ValidateStagingRoot(string root)
    {
        if (!Directory.Exists(root)) throw new DirectoryNotFoundException($"Fixed transfer staging root does not exist: {root}");
        if (!IsUnderRoot(root, DevRoot)) throw new UnauthorizedAccessException("Transfer staging root is outside the development root.");
        RequireNoReparseTraversal(root);
        if ((File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException("Transfer staging roots may not be reparse points.");
    }

    private static void RequireNoReparseTraversal(string path)
    {
        var root = Path.GetFullPath(DevRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var currentPath = Directory.Exists(path) ? path : Path.GetDirectoryName(path)!;
        var current = new DirectoryInfo(currentPath);
        while (current is not null)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0) throw new UnauthorizedAccessException($"Transfer path may not traverse a reparse-point directory: {current.FullName}");
            if (string.Equals(current.FullName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), root, StringComparison.OrdinalIgnoreCase)) return;
            current = current.Parent;
        }
        throw new UnauthorizedAccessException("Transfer path root validation failed.");
    }

    private static bool IsUnderRoot(string path, string root)
    {
        var fullPath = Path.GetFullPath(path);
        var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return string.Equals(fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), fullRoot, StringComparison.OrdinalIgnoreCase) || fullPath.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static string RequireParameter(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : throw new InvalidDataException($"Signed transfer parameter {key} is required.");

    private static void RequireIntentMatch(SignedPlan plan, string operation, string target, string summary, string riskClass, string expectedOperation)
    {
        if (!string.Equals(plan.Tool, "transfer", StringComparison.Ordinal) || !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal) || !string.Equals(plan.Operation, operation, StringComparison.Ordinal) || !string.Equals(plan.Target, target, StringComparison.Ordinal) || !string.Equals(plan.Summary, summary, StringComparison.Ordinal) || !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Transfer plan execution intent mismatch.");
    }
}

public sealed record TransferStagingItem(string Name, string Kind, long? Bytes, DateTimeOffset LastWriteTimeUtc);
public sealed record TransferStagingListResult(string Area, string Root, IReadOnlyList<TransferStagingItem> Items, bool Truncated, DateTimeOffset CheckedUtc);
public sealed record TransferFileInspection(string Area, string FileName, string FullPath, long Bytes, string Sha256, DateTime LastWriteTimeUtc, DateTimeOffset CheckedUtc);
public sealed record TransferCopyResult(string PlanId, string Operation, string SourcePath, string DestinationPath, long Bytes, string Sha256, string Outcome, DateTimeOffset ExecutedUtc);
