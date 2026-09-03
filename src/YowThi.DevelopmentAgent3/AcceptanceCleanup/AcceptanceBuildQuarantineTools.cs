using System.ComponentModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.AcceptanceCleanup;

[McpServerToolType]
public static class AcceptanceBuildQuarantineTools
{
    private const string ToolName = "acceptance-build-quarantine";
    private const string QuarantineOperation = "quarantine-build";
    private const string RestoreOperation = "restore-build";
    private const string QuarantineRoot = @"C:\Dev\YowThi-ERP-Dev-v4\acceptance\quarantine";
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly AcceptanceBuildCleanupPolicy ActivePolicy = new();
    private static readonly AcceptanceBuildCleanupPolicy QuarantinePolicy = new(QuarantineRoot);

    [McpServerTool(Name = "acceptance_build_quarantine_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed Medium-risk plan to atomically move exactly one verified inactive direct acceptance build-output directory from the fixed C:\\Dev\\YowThi-ERP-Dev-v4\\acceptance root into the fixed acceptance\\quarantine root. The caller supplies only the safe build directory leaf name. Complete content manifest, counts, bytes, reparse policy, zero running-process references, exclusive file access, fixed source/destination identities, and destination absence are sealed. Content is preserved; no deletion, copy, shell, process stop, arbitrary path, or production mutation is supported.")]
    public static SignedPlan AcceptanceBuildQuarantinePlan(string directoryName)
    {
        EnsureFixedQuarantineRoot();
        var state = ActivePolicy.Capture(directoryName, includeContentHashes: true);
        RequireNoBlockers(state, "quarantine");
        var destination = ResolveQuarantineTarget(directoryName);
        RequireDestinationAbsent(destination);
        return CreatePlan(QuarantineOperation, state, destination,
            $"Move verified inactive acceptance build output {state.DirectoryName} into the fixed YowThi ERP Dev v4 quarantine root without deleting content");
    }

    [McpServerTool(Name = "acceptance_build_quarantine_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute only one previously prepared fixed acceptance-build quarantine plan. The only caller inputs are planId and approvalCode. The server revalidates the fixed tool/operation, direct-child source, fixed quarantine destination, destination absence, complete content manifest, counts, bytes, reparse policy, running-process references, and exclusive file access immediately before one same-volume Directory.Move. Post-move manifest read-back must match exactly. Verification failure performs a best-effort move back to the sealed source. No content deletion, arbitrary path, shell, process stop, overwrite, or production mutation is supported.")]
    public static ExecutionResult AcceptanceBuildQuarantineExecute(string planId, string approvalCode)
        => ExecuteMove(planId, approvalCode, QuarantineOperation, fromQuarantine: false);

    [McpServerTool(Name = "acceptance_build_quarantine_restore_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed Medium-risk plan to restore exactly one verified quarantined acceptance build-output directory from the fixed acceptance\\quarantine root to its original direct-child location under the fixed acceptance root. The caller supplies only the safe build directory leaf name. Complete content manifest, counts, bytes, reparse policy, zero running-process references, exclusive file access, fixed source/destination identities, and destination absence are sealed. Content is preserved; no deletion, copy, shell, process stop, arbitrary path, or production mutation is supported.")]
    public static SignedPlan AcceptanceBuildQuarantineRestorePlan(string directoryName)
    {
        EnsureFixedQuarantineRoot();
        var state = QuarantinePolicy.Capture(directoryName, includeContentHashes: true);
        RequireNoBlockers(state, "restore");
        var destination = ActivePolicy.ResolveTarget(directoryName);
        RequireDestinationAbsent(destination);
        return CreatePlan(RestoreOperation, state, destination,
            $"Restore verified quarantined acceptance build output {state.DirectoryName} to the fixed YowThi ERP Dev v4 acceptance root without modifying content");
    }

    [McpServerTool(Name = "acceptance_build_quarantine_restore_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute only one previously prepared fixed acceptance-build quarantine restore plan. The only caller inputs are planId and approvalCode. The server revalidates the fixed tool/operation, quarantined source, fixed active destination, destination absence, complete content manifest, counts, bytes, reparse policy, running-process references, and exclusive file access immediately before one same-volume Directory.Move. Post-move manifest read-back must match exactly. Verification failure performs a best-effort move back to the sealed quarantine source. No content deletion, arbitrary path, shell, process stop, overwrite, or production mutation is supported.")]
    public static ExecutionResult AcceptanceBuildQuarantineRestoreExecute(string planId, string approvalCode)
        => ExecuteMove(planId, approvalCode, RestoreOperation, fromQuarantine: true);

    private static SignedPlan CreatePlan(string operation, AcceptanceBuildDirectoryState state, string destination, string summary)
    {
        var now = DateTimeOffset.UtcNow;
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["directoryName"] = state.DirectoryName,
            ["destination"] = destination,
            ["manifestSha256"] = state.ManifestSha256,
            ["fileCount"] = state.Files.Count.ToString(CultureInfo.InvariantCulture),
            ["directoryCount"] = (state.Directories.Count + 1).ToString(CultureInfo.InvariantCulture),
            ["totalBytes"] = state.TotalBytes.ToString(CultureInfo.InvariantCulture)
        };
        var unsigned = new SignedPlan(
            1,
            Guid.NewGuid().ToString("N"),
            Convert.ToHexString(RandomNumberGenerator.GetBytes(6)),
            ToolName,
            operation,
            state.Target,
            parameters,
            RiskClass.Medium,
            summary,
            now,
            now.AddMinutes(10),
            string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new
        {
            signed.PlanId,
            signed.RiskClass,
            signed.Summary,
            state.DirectoryName,
            destination,
            state.ManifestSha256,
            fileCount = state.Files.Count,
            directoryCount = state.Directories.Count + 1,
            state.TotalBytes
        }, "prepared");
        return signed;
    }

    private static ExecutionResult ExecuteMove(string planId, string approvalCode, string expectedOperation, bool fromQuarantine)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequirePlanIdentity(plan, expectedOperation, fromQuarantine);

        var sourcePolicy = fromQuarantine ? QuarantinePolicy : ActivePolicy;
        var destinationPolicy = fromQuarantine ? ActivePolicy : QuarantinePolicy;
        var directoryName = RequireParameter(plan, "directoryName");
        var expectedDestination = RequireParameter(plan, "destination");
        var expectedManifestSha256 = RequireParameter(plan, "manifestSha256");
        var expectedFileCount = int.Parse(RequireParameter(plan, "fileCount"), CultureInfo.InvariantCulture);
        var expectedDirectoryCount = int.Parse(RequireParameter(plan, "directoryCount"), CultureInfo.InvariantCulture);
        var expectedTotalBytes = long.Parse(RequireParameter(plan, "totalBytes"), CultureInfo.InvariantCulture);

        var source = sourcePolicy.ResolveTarget(directoryName);
        var destination = destinationPolicy.ResolveTarget(directoryName);
        if (!string.Equals(source, plan.Target, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(destination, expectedDestination, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Signed quarantine source or destination no longer matches the fixed-root identity.");

        try
        {
            EnsureFixedQuarantineRoot();
            RequireDestinationAbsent(destination);
            var state = sourcePolicy.Capture(directoryName, includeContentHashes: true);
            ValidateState(state, expectedManifestSha256, expectedFileCount, expectedDirectoryCount, expectedTotalBytes);
            RequireNoBlockers(state, expectedOperation);

            Directory.Move(source, destination);
            if (Directory.Exists(source) || !Directory.Exists(destination))
                throw new IOException("Post-move path read-back did not prove the fixed quarantine transition.");

            try
            {
                var movedState = destinationPolicy.Capture(directoryName, includeContentHashes: true);
                ValidateState(movedState, expectedManifestSha256, expectedFileCount, expectedDirectoryCount, expectedTotalBytes);
            }
            catch
            {
                BestEffortRollback(destination, source);
                throw;
            }

            Store.Consume(planId);
            var outcome = fromQuarantine
                ? $"restored {expectedFileCount} files, {expectedDirectoryCount} directories, {expectedTotalBytes} bytes"
                : $"quarantined {expectedFileCount} files, {expectedDirectoryCount} directories, {expectedTotalBytes} bytes";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new
            {
                plan.PlanId,
                directoryName,
                destination,
                expectedManifestSha256,
                fileCount = expectedFileCount,
                directoryCount = expectedDirectoryCount,
                totalBytes = expectedTotalBytes,
                outcome
            }, "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.GetType().Name + ": " + ex.Message }, "failed");
            throw;
        }
    }

    private static void RequirePlanIdentity(SignedPlan plan, string expectedOperation, bool fromQuarantine)
    {
        if (!string.Equals(plan.Tool, ToolName, StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal) ||
            plan.RiskClass != RiskClass.Medium)
            throw new UnauthorizedAccessException("Acceptance build quarantine plan identity is invalid.");

        var directoryName = RequireParameter(plan, "directoryName");
        var expectedSource = (fromQuarantine ? QuarantinePolicy : ActivePolicy).ResolveTarget(directoryName);
        var expectedDestination = (fromQuarantine ? ActivePolicy : QuarantinePolicy).ResolveTarget(directoryName);
        if (!string.Equals(plan.Target, expectedSource, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(RequireParameter(plan, "destination"), expectedDestination, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Acceptance build quarantine plan is outside the fixed source/destination contract.");
    }

    private static void ValidateState(AcceptanceBuildDirectoryState state, string manifestSha256, int fileCount, int directoryCount, long totalBytes)
    {
        if (!string.Equals(state.ManifestSha256, manifestSha256, StringComparison.Ordinal) ||
            state.Files.Count != fileCount ||
            state.Directories.Count + 1 != directoryCount ||
            state.TotalBytes != totalBytes)
            throw new InvalidOperationException("Acceptance build directory changed after the quarantine plan was prepared.");
    }

    private static void RequireNoBlockers(AcceptanceBuildDirectoryState state, string action)
    {
        if (state.Blockers.Count != 0)
            throw new InvalidOperationException($"Acceptance build {action} is blocked by {state.Blockers.Count} active-process/file-access condition(s). First blocker: {state.Blockers[0].Kind} - {state.Blockers[0].Detail}");
    }

    private static string ResolveQuarantineTarget(string directoryName)
    {
        EnsureFixedQuarantineRoot();
        return QuarantinePolicy.ResolveTarget(directoryName);
    }

    private static void EnsureFixedQuarantineRoot()
    {
        var root = Path.GetFullPath(QuarantineRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var expectedParent = Path.GetFullPath(AcceptanceBuildCleanupPolicy.FixedAcceptanceRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var parent = Path.GetDirectoryName(root)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!string.Equals(parent, expectedParent, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Fixed acceptance quarantine root identity is invalid.");
        if (!Directory.Exists(root))
            throw new DirectoryNotFoundException($"Fixed acceptance quarantine root does not exist: {root}");
        if ((File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Fixed acceptance quarantine root may not be a reparse point.");
    }

    private static void RequireDestinationAbsent(string destination)
    {
        if (Directory.Exists(destination) || File.Exists(destination))
            throw new IOException($"Fixed quarantine destination already exists: {destination}");
    }

    private static void BestEffortRollback(string source, string destination)
    {
        try
        {
            if (Directory.Exists(source) && !Directory.Exists(destination) && !File.Exists(destination))
                Directory.Move(source, destination);
        }
        catch
        {
        }
    }

    private static string RequireParameter(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidDataException($"Signed quarantine plan is missing parameter: {key}");
}
