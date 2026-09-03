using System.ComponentModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.AcceptanceCleanup;

[McpServerToolType]
public static class AcceptanceBuildCleanupFixedExecutionTools
{
    private const string ToolName = "acceptance-cleanup-fixed";
    private const string OperationName = "fixed-build-delete";
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly AcceptanceBuildCleanupPolicy Policy = new();

    [McpServerTool(Name = "acceptance_build_cleanup_fixed_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan for exactly one verified direct acceptance build-output directory under the fixed C:\\Dev\\YowThi-ERP-Dev-v4\\acceptance root. The caller supplies only the safe direct-child build directory name. The complete content manifest, counts, bytes, reparse policy, zero running-process references, and exclusive file-access preflight are sealed. No arbitrary path, shell, recursive delete, process stop, or production mutation is supported.")]
    public static SignedPlan AcceptanceBuildCleanupFixedPlan(string directoryName)
    {
        var state = Policy.Capture(directoryName, includeContentHashes: true);
        if (state.Blockers.Count != 0)
            throw new InvalidOperationException($"Acceptance build cleanup is blocked by {state.Blockers.Count} active-process/file-access condition(s). First blocker: {state.Blockers[0].Kind} - {state.Blockers[0].Detail}");

        var now = DateTimeOffset.UtcNow;
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["directoryName"] = state.DirectoryName,
            ["manifestSha256"] = state.ManifestSha256,
            ["fileCount"] = state.Files.Count.ToString(CultureInfo.InvariantCulture),
            ["directoryCount"] = (state.Directories.Count + 1).ToString(CultureInfo.InvariantCulture),
            ["totalBytes"] = state.TotalBytes.ToString(CultureInfo.InvariantCulture)
        };
        var summary = $"Delete verified inactive acceptance build output {state.DirectoryName} under the fixed YowThi ERP Dev v4 acceptance root";
        var unsigned = new SignedPlan(
            1,
            Guid.NewGuid().ToString("N"),
            Convert.ToHexString(RandomNumberGenerator.GetBytes(6)),
            ToolName,
            OperationName,
            state.Target,
            parameters,
            RiskClass.High,
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
            state.ManifestSha256,
            fileCount = state.Files.Count,
            directoryCount = state.Directories.Count + 1,
            state.TotalBytes
        }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "acceptance_build_cleanup_fixed_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute only one previously prepared acceptance-build cleanup plan. The only caller inputs are planId and approvalCode. The server revalidates the fixed cleanup tool and operation, the signed direct-child target under the fixed acceptance root, safe build-name policy, complete content manifest, file/directory counts, byte count, reparse policy, running-process references, and exclusive file access immediately before deletion. Deletion uses only native .NET File.Delete plus non-recursive Directory.Delete and proves target absence afterward. No arbitrary path or command can be supplied at execution time.")]
    public static ExecutionResult AcceptanceBuildCleanupFixedExecute(string planId, string approvalCode)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireFixedPlan(plan);

        try
        {
            var directoryName = RequireParameter(plan, "directoryName");
            var expectedManifestSha256 = RequireParameter(plan, "manifestSha256");
            var expectedFileCount = int.Parse(RequireParameter(plan, "fileCount"), CultureInfo.InvariantCulture);
            var expectedDirectoryCount = int.Parse(RequireParameter(plan, "directoryCount"), CultureInfo.InvariantCulture);
            var expectedTotalBytes = long.Parse(RequireParameter(plan, "totalBytes"), CultureInfo.InvariantCulture);

            var resolvedTarget = Policy.ResolveTarget(directoryName);
            if (!string.Equals(resolvedTarget, plan.Target, StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Signed cleanup target no longer matches the fixed-root direct-child identity.");

            var state = Policy.Capture(directoryName, includeContentHashes: true);
            if (!string.Equals(state.Target, plan.Target, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(state.ManifestSha256, expectedManifestSha256, StringComparison.Ordinal) ||
                state.Files.Count != expectedFileCount ||
                state.Directories.Count + 1 != expectedDirectoryCount ||
                state.TotalBytes != expectedTotalBytes)
            {
                throw new InvalidOperationException("Acceptance build directory changed after the cleanup plan was prepared.");
            }
            if (state.Blockers.Count != 0)
                throw new InvalidOperationException($"Acceptance build cleanup became blocked by {state.Blockers.Count} active-process/file-access condition(s). First blocker: {state.Blockers[0].Kind} - {state.Blockers[0].Detail}");

            Policy.DeleteExact(state);
            if (Directory.Exists(state.Target))
                throw new IOException("Post-delete read-back still finds the acceptance build directory.");

            Store.Consume(planId);
            var outcome = $"deleted {state.Files.Count} files, {state.Directories.Count + 1} directories, {state.TotalBytes} bytes";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new
            {
                plan.PlanId,
                state.DirectoryName,
                state.ManifestSha256,
                fileCount = state.Files.Count,
                directoryCount = state.Directories.Count + 1,
                state.TotalBytes,
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

    private static void RequireFixedPlan(SignedPlan plan)
    {
        if (!string.Equals(plan.Tool, ToolName, StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, OperationName, StringComparison.Ordinal) ||
            plan.RiskClass != RiskClass.High)
            throw new UnauthorizedAccessException("Acceptance cleanup plan identity is invalid.");

        var directoryName = RequireParameter(plan, "directoryName");
        var resolvedTarget = Policy.ResolveTarget(directoryName);
        if (!string.Equals(plan.Target, resolvedTarget, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Acceptance cleanup plan target is outside the fixed direct-child contract.");
    }

    private static string RequireParameter(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidDataException($"Signed cleanup plan is missing parameter: {key}");
}
