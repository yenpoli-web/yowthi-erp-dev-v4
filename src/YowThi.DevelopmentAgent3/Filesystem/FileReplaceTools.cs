using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;
using YowThi.DevelopmentAgent3.Scratch;
using YowThi.DevelopmentAgent3.Security;

namespace YowThi.DevelopmentAgent3.Filesystem;

[McpServerToolType]
public static class FileReplaceTools
{
    private const int BackupTtlHours = 24;
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly LifecyclePathPolicy Paths = new();
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name="file_replace_plan", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Prepare a one-time signed plan to safely replace one existing file using native .NET filesystem APIs. The plan seals the original SHA-256 and replacement SHA-256. At execution, the original backup and replacement staging are created only in the fixed repo-external Agent scratch vault with planId/owner/purpose/TTL manifests; no persistent .bak or .tmp artifact is created in the V4 Git worktree. Frozen paths are blocked. No shell command is generated or stored.")]
    public static SignedPlan FileReplacePlan(string path, string content)
    {
        _ = AgentScratchStore.ReconcileExpired();
        var target = Paths.RequireMutable(path);
        if (!File.Exists(target)) throw new FileNotFoundException("Target file does not exist.", target);

        var originalBytes = File.ReadAllBytes(target);
        var replacementBytes = Encoding.UTF8.GetBytes(content);
        var originalSha256 = Convert.ToHexString(SHA256.HashData(originalBytes));
        var replacementSha256 = Convert.ToHexString(SHA256.HashData(replacementBytes));
        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var parameters = new Dictionary<string,string>(StringComparer.Ordinal)
        {
            ["contentBase64"] = Convert.ToBase64String(replacementBytes),
            ["originalSha256"] = originalSha256,
            ["replacementSha256"] = replacementSha256,
            ["backupTtlHours"] = BackupTtlHours.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["scratchRoot"] = AgentScratchStore.RootPath
        };
        var unsigned = new SignedPlan(1, planId, approvalCode, "filesystem", "file-replace", target, parameters, RiskClass.Medium, $"Safely replace file {target} with repo-external Agent backup", now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new
        {
            signed.PlanId,
            signed.RiskClass,
            signed.Summary,
            originalSha256,
            replacementSha256,
            backupTtlHours = BackupTtlHours,
            scratchRoot = AgentScratchStore.RootPath
        }, "prepared");
        return signed;
    }

    [McpServerTool(Name="file_replace_execute", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Execute one previously prepared filesystem/file-replace plan using native .NET filesystem APIs. The caller repeats the signed operation, target, summary and risk class. Original bytes are copied to a hash-verified repo-external Agent scratch backup with 24-hour TTL; replacement staging is also outside the V4 Git worktree. The target original SHA is revalidated both at execute entry and immediately before mutation, the replacement SHA and post-write SHA are proven, and failures attempt rollback from the sealed scratch backup. No persistent backup is left in the Git worktree and no PowerShell, cmd, or generic command executor is used.")]
    public static async Task<ExecutionResult> FileReplaceExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, operation, target, summary, riskClass);
        _ = AgentScratchStore.ReconcileExpired();
        var mutableTarget = Paths.RequireMutable(plan.Target);
        if (!File.Exists(mutableTarget)) throw new FileNotFoundException("Target file does not exist.", mutableTarget);
        if (!plan.Parameters.TryGetValue("contentBase64", out var contentBase64)) throw new InvalidDataException("contentBase64 parameter is required.");
        if (!plan.Parameters.TryGetValue("originalSha256", out var expectedOriginalSha256)) throw new InvalidDataException("originalSha256 parameter is required.");
        if (!plan.Parameters.TryGetValue("replacementSha256", out var expectedReplacementSha256)) throw new InvalidDataException("replacementSha256 parameter is required.");

        var originalBytes = await File.ReadAllBytesAsync(mutableTarget);
        var actualOriginalSha256 = Convert.ToHexString(SHA256.HashData(originalBytes));
        if (!string.Equals(actualOriginalSha256, expectedOriginalSha256, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Target changed after plan creation; replacement aborted.");

        var replacementBytes = Convert.FromBase64String(contentBase64);
        var actualReplacementSha256 = Convert.ToHexString(SHA256.HashData(replacementBytes));
        if (!string.Equals(actualReplacementSha256, expectedReplacementSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Replacement payload SHA-256 does not match the signed plan.");

        var backupArtifact = AgentScratchStore.CreateArtifact(
            plan.PlanId,
            "filesystem/file-replace",
            "file-replace-backup",
            ".bak",
            originalBytes,
            DateTimeOffset.UtcNow.AddHours(BackupTtlHours),
            mutableTarget);
        _ = AgentScratchStore.RequireActiveOwnedArtifact(backupArtifact.DataPath, "file-replace-backup");

        AgentScratchArtifact? replacementArtifact = null;
        var targetDirectory = Path.GetDirectoryName(mutableTarget) ?? throw new InvalidDataException("Target has no parent directory.");
        string? fallbackTemp = null;
        var mutationStarted = false;
        var rollbackProven = false;
        string? preMutationSha256 = null;

        try
        {
            string replacementSource;
            if (IsInsideV4Repository(mutableTarget))
            {
                RequireSameVolume(mutableTarget, AgentScratchStore.RootPath);
                replacementArtifact = AgentScratchStore.CreateArtifact(
                    plan.PlanId,
                    "filesystem/file-replace",
                    "file-replace-content",
                    ".bak",
                    replacementBytes,
                    DateTimeOffset.UtcNow.AddHours(1),
                    mutableTarget);
                replacementSource = AgentScratchStore.RequireActiveOwnedArtifact(replacementArtifact.DataPath, "file-replace-content").DataPath;
            }
            else
            {
                fallbackTemp = Path.Combine(targetDirectory, $".{Path.GetFileName(mutableTarget)}.replace-{plan.PlanId}.tmp");
                using var stream = new FileStream(fallbackTemp, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                await stream.WriteAsync(replacementBytes);
                await stream.FlushAsync();
                replacementSource = fallbackTemp;
            }

            var preMutationBytes = await File.ReadAllBytesAsync(mutableTarget);
            preMutationSha256 = Convert.ToHexString(SHA256.HashData(preMutationBytes));
            if (!string.Equals(preMutationSha256, expectedOriginalSha256, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Target changed during replacement preparation; mutation aborted.");

            mutationStarted = true;
            File.Replace(replacementSource, mutableTarget, null, ignoreMetadataErrors: true);
            if (replacementArtifact is not null)
                _ = AgentScratchStore.TryDeleteOwnedArtifact(replacementArtifact.DataPath);
            fallbackTemp = null;

            var postBytes = await File.ReadAllBytesAsync(mutableTarget);
            var postSha256 = Convert.ToHexString(SHA256.HashData(postBytes));
            if (!string.Equals(postSha256, expectedReplacementSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Post-replace SHA-256 does not match the sealed replacement SHA-256.");

            Store.Consume(planId);
            var outcome = $"replaced:{replacementBytes.Length};backupArtifact:{backupArtifact.ArtifactId};backupExpiresUtc:{backupArtifact.ExpiresUtc:O}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new
            {
                plan.PlanId,
                outcome,
                backupArtifactId = backupArtifact.ArtifactId,
                backupSha256 = backupArtifact.Sha256,
                backupExpiresUtc = backupArtifact.ExpiresUtc,
                preMutationSha256,
                replacementSha256 = expectedReplacementSha256,
                worktreeBackupCreated = false
            }, "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, mutableTarget, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            if (mutationStarted)
            {
                rollbackProven = TryRollback(mutableTarget, backupArtifact, expectedOriginalSha256, plan.PlanId);
                if (!rollbackProven)
                {
                    try { Store.Consume(planId); } catch { }
                }
            }
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new
            {
                plan.PlanId,
                errorType = ex.GetType().Name,
                backupArtifactId = backupArtifact.ArtifactId,
                preMutationSha256,
                mutationStarted,
                rollbackProven
            }, "failed");
            throw;
        }
        finally
        {
            if (replacementArtifact is not null)
                _ = AgentScratchStore.TryDeleteOwnedArtifact(replacementArtifact.DataPath);
            if (fallbackTemp is not null)
            {
                try { if (File.Exists(fallbackTemp)) File.Delete(fallbackTemp); } catch { }
            }
        }
    }

    private static bool TryRollback(string mutableTarget, AgentScratchArtifact backupArtifact, string expectedOriginalSha256, string planId)
    {
        try
        {
            var backup = AgentScratchStore.RequireActiveOwnedArtifact(backupArtifact.DataPath, "file-replace-backup");
            var backupBytes = File.ReadAllBytes(backup.DataPath);
            string restoreSource;
            AgentScratchArtifact? restoreArtifact = null;
            string? fallback = null;
            try
            {
                if (IsInsideV4Repository(mutableTarget))
                {
                    RequireSameVolume(mutableTarget, AgentScratchStore.RootPath);
                    restoreArtifact = AgentScratchStore.CreateArtifact(
                        planId,
                        "filesystem/file-replace",
                        "file-replace-rollback",
                        ".bak",
                        backupBytes,
                        DateTimeOffset.UtcNow.AddHours(1),
                        mutableTarget);
                    restoreSource = restoreArtifact.DataPath;
                }
                else
                {
                    var directory = Path.GetDirectoryName(mutableTarget)!;
                    fallback = Path.Combine(directory, $".{Path.GetFileName(mutableTarget)}.rollback-{planId}.tmp");
                    File.WriteAllBytes(fallback, backupBytes);
                    restoreSource = fallback;
                }

                File.Replace(restoreSource, mutableTarget, null, ignoreMetadataErrors: true);
                if (restoreArtifact is not null) _ = AgentScratchStore.TryDeleteOwnedArtifact(restoreArtifact.DataPath);
                fallback = null;
                var restoredSha = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(mutableTarget)));
                return string.Equals(restoredSha, expectedOriginalSha256, StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                if (restoreArtifact is not null) _ = AgentScratchStore.TryDeleteOwnedArtifact(restoreArtifact.DataPath);
                if (fallback is not null)
                {
                    try { if (File.Exists(fallback)) File.Delete(fallback); } catch { }
                }
            }
        }
        catch
        {
            return false;
        }
    }

    private static bool IsInsideV4Repository(string path)
    {
        var full = Path.GetFullPath(path);
        var root = Path.GetFullPath(AgentScratchStore.V4RepositoryRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static void RequireSameVolume(string target, string scratchRoot)
    {
        var targetRoot = Path.GetPathRoot(Path.GetFullPath(target));
        var scratchVolume = Path.GetPathRoot(Path.GetFullPath(scratchRoot));
        if (!string.Equals(targetRoot, scratchVolume, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("V4 worktree atomic replacement requires the fixed scratch vault to be on the same volume.");
    }

    private static void RequireIntentMatch(SignedPlan plan, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "filesystem", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, "file-replace", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }
}
