using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Transfer;

[McpServerToolType]
public static class TransferCleanupTools
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string InboxRoot = @"C:\Dev\YowThi-ERP-Dev-v4\staging\transfer\inbox";
    private const string OutboxRoot = @"C:\Dev\YowThi-ERP-Dev-v4\staging\transfer\outbox";
    private const long MaxTransferBytes = 20L * 1024 * 1024 * 1024;

    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name = "transfer_inbox_remove_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed Medium-risk plan to remove one existing direct file from the fixed YowThi ERP v4 transfer inbox. Only a safe leaf file name is accepted. Exact inbox path, byte length, SHA-256, file-present state, and fixed inbox identity are sealed. Directories, traversal, reparse points, arbitrary paths, recursive deletion, production paths, shell execution, and network access are not supported.")]
    public static SignedPlan TransferInboxRemovePlan(string fileName)
        => PrepareRemoval(InboxRoot, "inbox", "inbox-remove", fileName);

    [McpServerTool(Name = "transfer_inbox_remove_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared transfer/inbox-remove plan using only the native .NET File.Delete API. Exact signed intent, fixed inbox identity, direct leaf file name, byte length, SHA-256, file-present state, and reparse policy are revalidated immediately before deletion. Post-delete read-back must prove the exact staged file is absent. No arbitrary path or recursive deletion is supported.")]
    public static TransferStagedRemoveResult TransferInboxRemoveExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
        => ExecuteRemoval(planId, approvalCode, operation, target, summary, riskClass, InboxRoot, "inbox", "inbox-remove");

    [McpServerTool(Name = "transfer_outbox_remove_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed Medium-risk plan to remove one existing direct file from the fixed YowThi ERP v4 transfer outbox. Only a safe leaf file name is accepted. Exact outbox path, byte length, SHA-256, file-present state, and fixed outbox identity are sealed. Directories, traversal, reparse points, arbitrary paths, recursive deletion, production paths, shell execution, and network access are not supported.")]
    public static SignedPlan TransferOutboxRemovePlan(string fileName)
        => PrepareRemoval(OutboxRoot, "outbox", "outbox-remove", fileName);

    [McpServerTool(Name = "transfer_outbox_remove_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared transfer/outbox-remove plan using only the native .NET File.Delete API. Exact signed intent, fixed outbox identity, direct leaf file name, byte length, SHA-256, file-present state, and reparse policy are revalidated immediately before deletion. Post-delete read-back must prove the exact staged file is absent. No arbitrary path or recursive deletion is supported.")]
    public static TransferStagedRemoveResult TransferOutboxRemoveExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
        => ExecuteRemoval(planId, approvalCode, operation, target, summary, riskClass, OutboxRoot, "outbox", "outbox-remove");

    private static SignedPlan PrepareRemoval(string root, string area, string operation, string fileName)
    {
        var path = ValidateStagedFile(root, fileName);
        var state = InspectFile(path);
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["area"] = area,
            ["fileName"] = Path.GetFileName(path),
            ["filePath"] = path,
            ["bytes"] = state.Bytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["sha256"] = state.Sha256,
            ["filePresent"] = "true"
        };

        var now = DateTimeOffset.UtcNow;
        var summary = $"Remove transfer {area} staged file {Path.GetFileName(path)} after exact SHA-256 revalidation ({state.Bytes} bytes)";
        var unsigned = new SignedPlan(
            1,
            Guid.NewGuid().ToString("N"),
            Convert.ToHexString(RandomNumberGenerator.GetBytes(6)),
            "transfer",
            operation,
            path,
            parameters,
            RiskClass.Medium,
            summary,
            now,
            now.AddMinutes(10),
            string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, area, state.Bytes, state.Sha256, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    private static TransferStagedRemoveResult ExecuteRemoval(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass,
        string root,
        string area,
        string expectedOperation)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, operation, target, summary, riskClass, expectedOperation);

        if (!string.Equals(RequireParameter(plan, "area"), area, StringComparison.Ordinal))
            throw new InvalidDataException("Signed transfer staging area is invalid.");
        if (!string.Equals(RequireParameter(plan, "filePresent"), "true", StringComparison.Ordinal))
            throw new InvalidDataException("Signed transfer file-present state is invalid.");

        var path = ValidateStagedFile(root, RequireParameter(plan, "fileName"));
        if (!string.Equals(path, RequireParameter(plan, "filePath"), StringComparison.OrdinalIgnoreCase)
            || !string.Equals(path, plan.Target, StringComparison.Ordinal))
            throw new InvalidOperationException("Transfer staged file path no longer matches the signed plan.");

        if (!long.TryParse(
                RequireParameter(plan, "bytes"),
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture,
                out var expectedBytes)
            || expectedBytes < 0
            || expectedBytes > MaxTransferBytes)
            throw new InvalidDataException("Signed transfer staged-file byte length is invalid.");

        var expectedSha = RequireParameter(plan, "sha256");
        if (expectedSha.Length != 64 || expectedSha.Any(ch => !Uri.IsHexDigit(ch)))
            throw new InvalidDataException("Signed transfer staged-file SHA-256 is invalid.");

        var current = InspectFile(path);
        if (current.Bytes != expectedBytes || !string.Equals(current.Sha256, expectedSha, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Transfer staged file changed after plan preparation.");

        try
        {
            File.Delete(path);
            if (File.Exists(path) || Directory.Exists(path))
                throw new IOException("Transfer staged-file removal verification failed because the target still exists.");

            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, area, path, expectedBytes, expectedSha, outcome = "staged-file-removed" }, "executed");
            return new TransferStagedRemoveResult(plan.PlanId, area, Path.GetFileName(path), path, expectedBytes, expectedSha, false, "staged-file-removed", DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, area, path, error = ex.Message }, "failed");
            throw;
        }
    }

    private static string ValidateStagedFile(string root, string fileName)
    {
        ValidateStagingRoot(root);
        var leaf = ValidateLeafFileName(fileName);
        var path = Path.GetFullPath(Path.Combine(root, leaf));
        if (!IsUnderRoot(path, root))
            throw new UnauthorizedAccessException("Transfer staged file escaped its fixed staging root.");
        if (!File.Exists(path))
            throw new FileNotFoundException("Transfer staged file does not exist.", path);
        if (Directory.Exists(path))
            throw new InvalidOperationException("Transfer staged cleanup accepts files only.");
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Reparse-point staged files are not allowed.");
        return path;
    }

    private static (long Bytes, string Sha256) InspectFile(string path)
    {
        var info = new FileInfo(path);
        if (info.Length > MaxTransferBytes)
            throw new InvalidDataException($"Transfer file exceeds the fixed {MaxTransferBytes} byte limit.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return (info.Length, Convert.ToHexString(SHA256.HashData(stream)));
    }

    private static void ValidateStagingRoot(string root)
    {
        if (!Directory.Exists(root))
            throw new DirectoryNotFoundException($"Fixed transfer staging root does not exist: {root}");
        if (!IsUnderRoot(root, DevRoot))
            throw new UnauthorizedAccessException("Transfer staging root is outside the development root.");
        RequireNoReparseTraversal(root);
        if ((File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Transfer staging roots may not be reparse points.");
    }

    private static string ValidateLeafFileName(string fileName)
    {
        var value = (fileName ?? string.Empty).Trim();
        if (value.Length == 0 || value.Length > 180)
            throw new ArgumentException("Transfer staged file name must contain 1-180 characters.", nameof(fileName));
        if (!string.Equals(Path.GetFileName(value), value, StringComparison.Ordinal)
            || value is "." or ".."
            || value.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0
            || value.EndsWith(' ')
            || value.EndsWith('.')
            || value.Any(char.IsControl)
            || IsReservedWindowsName(value))
            throw new ArgumentException("Transfer staged file name is not a safe Windows leaf file name.", nameof(fileName));
        return value;
    }

    private static bool IsReservedWindowsName(string fileName)
    {
        var stem = fileName.Split('.')[0].TrimEnd(' ', '.').ToUpperInvariant();
        if (stem is "CON" or "PRN" or "AUX" or "NUL") return true;
        return stem.Length == 4
            && (stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal))
            && stem[3] is >= '1' and <= '9';
    }

    private static void RequireNoReparseTraversal(string path)
    {
        var root = Path.GetFullPath(DevRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var currentPath = Directory.Exists(path) ? path : Path.GetDirectoryName(path)!;
        var current = new DirectoryInfo(currentPath);
        while (current is not null)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException($"Transfer path may not traverse a reparse-point directory: {current.FullName}");
            if (string.Equals(current.FullName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), root, StringComparison.OrdinalIgnoreCase))
                return;
            current = current.Parent;
        }
        throw new UnauthorizedAccessException("Transfer path root validation failed.");
    }

    private static bool IsUnderRoot(string path, string root)
    {
        var fullPath = Path.GetFullPath(path);
        var fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return string.Equals(fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), fullRoot, StringComparison.OrdinalIgnoreCase)
            || fullPath.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static string RequireParameter(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidDataException($"Signed transfer cleanup parameter {key} is required.");

    private static void RequireIntentMatch(SignedPlan plan, string operation, string target, string summary, string riskClass, string expectedOperation)
    {
        if (!string.Equals(plan.Tool, "transfer", StringComparison.Ordinal)
            || !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal)
            || !string.Equals(plan.Operation, operation, StringComparison.Ordinal)
            || !string.Equals(plan.Target, target, StringComparison.Ordinal)
            || !string.Equals(plan.Summary, summary, StringComparison.Ordinal)
            || !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Transfer cleanup plan execution intent mismatch.");
    }
}

public sealed record TransferStagedRemoveResult(
    string PlanId,
    string Area,
    string FileName,
    string FullPath,
    long Bytes,
    string Sha256,
    bool PresentAfter,
    string Outcome,
    DateTimeOffset ExecutedUtc);
