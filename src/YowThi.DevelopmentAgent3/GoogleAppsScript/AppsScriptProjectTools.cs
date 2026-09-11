using System.Collections.Concurrent;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;
using YowThi.DevelopmentAgent3.Security;

namespace YowThi.DevelopmentAgent3.GoogleAppsScript;

[McpServerToolType]
public static class AppsScriptProjectTools
{
    public const string ConcurrencyModel = "optimistic-prewrite-hash-revalidation; Google Apps Script updateContent has no documented server-side ETag/If-Match atomic CAS";
    private const int PlanLifetimeMinutes = 10;
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };
    private static readonly AppsScriptCredentialProvider Credentials = new(Http);
    private static readonly AppsScriptApiClient Api = new(Http, Credentials.GetAccessTokenAsync);
    private static readonly ConcurrentDictionary<string, PendingPatchPayload> Payloads = new(StringComparer.Ordinal);

    [McpServerTool(Name = "apps_script_connector_status", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read Google Apps Script connector configuration status without returning credential values. Authentication may come from a fixed Agent environment configuration or a short-lived controlled-browser import; OAuth tokens and client secrets are never returned.")]
    public static AppsScriptConnectorStatusResult AppsScriptConnectorStatus() => Credentials.GetStatus();

    [McpServerTool(Name = "apps_script_oauth_import_from_controlled_browser", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Import one short-lived Google OAuth access token from exactly one OAuth Playground page in the fixed Agent-controlled Chrome session at 127.0.0.1:9223. The token is read through a fixed internal CDP expression, retained only in Agent process memory until expiry or explicit clear, never accepted as a caller argument, never written to disk or audit, and never returned.")]
    public static async Task<AppsScriptEphemeralCredentialResult> AppsScriptOAuthImportFromControlledBrowser(CancellationToken cancellationToken = default)
    {
        var browserToken = await AppsScriptControlledBrowserOAuthReader.ReadAsync(cancellationToken);
        var result = AppsScriptEphemeralCredentialStore.Import(browserToken.AccessToken, browserToken.ExpiresInSeconds, browserToken.RequiredScopePresent);
        Audit.Append("apps-script", "oauth-import", "controlled-oauth-playground", new
        {
            result.AuthMode,
            result.Source,
            result.ExpiresUtc,
            result.TokenLength,
            result.RequiredScopePresent
        }, "executed");
        return result;
    }

    [McpServerTool(Name = "apps_script_oauth_clear_ephemeral", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Clear only the short-lived in-memory Apps Script OAuth token previously imported from controlled Chrome. Fixed environment-based credentials are not changed, no credential value is returned, and no file, browser profile, service, registry, or external resource is modified.")]
    public static AppsScriptEphemeralCredentialResult AppsScriptOAuthClearEphemeral()
    {
        var result = AppsScriptEphemeralCredentialStore.Clear();
        Audit.Append("apps-script", "oauth-clear", "ephemeral-memory-token", new { result.AuthMode, result.Source }, "executed");
        return result;
    }

    [McpServerTool(Name = "apps_script_project_get", ReadOnly = true, Destructive = false, OpenWorld = true)]
    [Description("Read one Google Apps Script project's HEAD metadata and complete file sources through the fixed script.googleapis.com API. Returns a deterministic SHA-256 over file name/type/source plus advisory project updateTime. No browser, clipboard, desktop input, local staging file, or mutation is used.")]
    public static Task<AppsScriptProjectSnapshot> AppsScriptProjectGet(string projectId, CancellationToken cancellationToken = default)
        => ReadSnapshotAsync(projectId, cancellationToken);

    [McpServerTool(Name = "apps_script_project_list_files", ReadOnly = true, Destructive = false, OpenWorld = true)]
    [Description("List one Google Apps Script project's HEAD files through the fixed API without returning source text. Returns file name/type, source byte length/SHA-256, function names when Google reports them, and the canonical whole-project SHA-256.")]
    public static async Task<AppsScriptProjectFileListResult> AppsScriptProjectListFiles(string projectId, CancellationToken cancellationToken = default)
    {
        projectId = AppsScriptValidation.RequireProjectId(projectId);
        var files = await Api.GetContentAsync(projectId, cancellationToken);
        var hash = AppsScriptContentHash.Compute(files);
        var summaries = files.OrderBy(file => file.Name, StringComparer.Ordinal)
            .Select(file => new AppsScriptProjectFileSummary(
                file.Name,
                file.Type,
                Encoding.UTF8.GetByteCount(file.Source),
                AppsScriptContentHash.ComputeSourceHash(file),
                file.UpdateTime,
                file.Functions.Select(function => function.Name).OrderBy(name => name, StringComparer.Ordinal).ToArray()))
            .ToArray();
        return new(projectId, hash, summaries.Length, summaries, DateTimeOffset.UtcNow);
    }

    [McpServerTool(Name = "apps_script_project_verify", ReadOnly = true, Destructive = false, OpenWorld = true)]
    [Description("Re-read one Google Apps Script project's HEAD through the fixed API and return its actual canonical SHA-256, optional expected-hash match, metadata updateTime, bounded file/source counts, and manifest JSON validity. This verifies remote readback; SERVER_JS compile/lint is explicitly not claimed by this tool.")]
    public static async Task<AppsScriptProjectVerifyResult> AppsScriptProjectVerify(string projectId, string? expectedHash = null, CancellationToken cancellationToken = default)
    {
        var snapshot = await ReadSnapshotAsync(projectId, cancellationToken);
        string? normalizedExpected = null;
        bool? matches = null;
        if (!string.IsNullOrWhiteSpace(expectedHash))
        {
            normalizedExpected = AppsScriptValidation.RequireHash(expectedHash, nameof(expectedHash));
            matches = string.Equals(snapshot.CanonicalSha256, normalizedExpected, StringComparison.OrdinalIgnoreCase);
        }
        return new(
            snapshot.ProjectId,
            snapshot.CanonicalSha256,
            normalizedExpected,
            matches,
            snapshot.Title,
            snapshot.ProjectUpdateTime,
            snapshot.FileCount,
            snapshot.TotalSourceBytes,
            snapshot.ManifestJsonValid,
            "not-evaluated-by-apps-script-content-api",
            ConcurrencyModel,
            DateTimeOffset.UtcNow);
    }

    [McpServerTool(Name = "apps_script_project_patch_plan", ReadOnly = false, Destructive = false, OpenWorld = true)]
    [Description("Prepare a one-time signed High-risk optimistic CAS patch for a Google Apps Script project's HEAD. The live remote project is read first and must exactly match expectedHash. Each literal replacement has an exact expectedMatchCount. Replacement source text and resulting project content remain only in expiring Agent memory; the signed plan/audit contain hashes, counts and file names only. Google updateContent does not expose documented server-side ETag/If-Match atomic CAS, so execution re-reads expectedHash immediately before PUT and verifies by GET afterward.")]
    public static async Task<SignedPlan> AppsScriptProjectPatchPlan(
        string projectId,
        string expectedHash,
        IReadOnlyList<AppsScriptTextReplacement> patches,
        CancellationToken cancellationToken = default)
    {
        SweepExpiredPayloads();
        projectId = AppsScriptValidation.RequireProjectId(projectId);
        expectedHash = AppsScriptValidation.RequireHash(expectedHash, nameof(expectedHash));
        if (patches is null) throw new ArgumentNullException(nameof(patches));

        var currentFiles = await Api.GetContentAsync(projectId, cancellationToken);
        var actualHash = AppsScriptContentHash.Compute(currentFiles);
        if (!string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Remote Apps Script project hash mismatch; patch plan not created. expected={expectedHash}, actual={actualHash}");

        var application = AppsScriptPatchEngine.Apply(currentFiles, patches);
        var patchSpecificationHash = AppsScriptPatchEngine.ComputePatchSpecificationHash(patches);
        var now = DateTimeOffset.UtcNow;
        var expires = now.AddMinutes(PlanLifetimeMinutes);
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["projectId"] = projectId,
            ["expectedHash"] = expectedHash,
            ["resultHash"] = application.ResultHash,
            ["patchSpecificationSha256"] = patchSpecificationHash,
            ["patchCount"] = patches.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["changedFiles"] = string.Join("\n", application.ChangedFiles),
            ["concurrencyModel"] = ConcurrencyModel
        };
        var summary = $"Patch Apps Script project {projectId} from {expectedHash[..12]} to {application.ResultHash[..12]} across {application.ChangedFiles.Count} file(s)";
        var unsigned = new SignedPlan(1, planId, approvalCode, "apps-script", "project-patch", projectId, parameters, RiskClass.High, summary, now, expires, string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        if (!Payloads.TryAdd(planId, new PendingPatchPayload(expires, projectId, expectedHash, application.ResultHash, application.Files.ToArray(), application.ChangedFiles.ToArray(), application.AffectedFunctions.ToArray())))
            throw new InvalidOperationException("Apps Script patch payload already exists.");
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new
        {
            signed.PlanId,
            expectedHash,
            resultHash = application.ResultHash,
            patchSpecificationHash,
            patchCount = patches.Count,
            changedFiles = application.ChangedFiles,
            concurrencyModel = ConcurrencyModel
        }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "apps_script_project_patch_execute", ReadOnly = false, Destructive = true, OpenWorld = true)]
    [Description("Execute one previously prepared Apps Script patch plan. The remote HEAD is re-read and must still match the sealed expectedHash immediately before the fixed updateContent PUT. After PUT the plan is consumed and the remote HEAD is re-read to prove the exact sealed resultHash. If verification mismatches, the tool reports failure and does not blindly rollback because a concurrent writer may exist. Only planId and approvalCode are accepted; source payload remains ephemeral in Agent memory.")]
    public static async Task<AppsScriptPatchExecutionResult> AppsScriptProjectPatchExecute(string planId, string approvalCode, CancellationToken cancellationToken = default)
    {
        SweepExpiredPayloads();
        var plan = Store.GetValidated(planId, approvalCode);
        if (!string.Equals(plan.Tool, "apps-script", StringComparison.Ordinal) || !string.Equals(plan.Operation, "project-patch", StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Apps Script patch plan intent mismatch.");
        if (!Payloads.TryGetValue(planId, out var payload) || payload.ExpiresUtc <= DateTimeOffset.UtcNow)
            throw new InvalidOperationException("Apps Script patch payload expired or is unavailable.");
        if (!string.Equals(plan.Target, payload.ProjectId, StringComparison.Ordinal) ||
            !string.Equals(Require(plan, "expectedHash"), payload.ExpectedHash, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Require(plan, "resultHash"), payload.ResultHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Apps Script patch payload does not match the signed plan.");

        var liveBeforeFiles = await Api.GetContentAsync(payload.ProjectId, cancellationToken);
        var liveBeforeHash = AppsScriptContentHash.Compute(liveBeforeFiles);
        if (!string.Equals(liveBeforeHash, payload.ExpectedHash, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Remote Apps Script project changed after plan creation; mutation aborted. expected={payload.ExpectedHash}, actual={liveBeforeHash}");

        try
        {
            await Api.UpdateContentAsync(payload.ProjectId, payload.Files, cancellationToken);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, errorType = ex.GetType().Name, stage = "update-content" }, "failed");
            throw;
        }

        Store.Consume(planId);
        Payloads.TryRemove(planId, out _);

        IReadOnlyList<AppsScriptProjectFile>? verifiedFiles = null;
        string actualAfterHash = string.Empty;
        Exception? lastReadError = null;
        for (var attempt = 0; attempt < 4; attempt++)
        {
            if (attempt > 0) await Task.Delay(TimeSpan.FromMilliseconds(250 * attempt), cancellationToken);
            try
            {
                verifiedFiles = await Api.GetContentAsync(payload.ProjectId, cancellationToken);
                actualAfterHash = AppsScriptContentHash.Compute(verifiedFiles);
                lastReadError = null;
                if (string.Equals(actualAfterHash, payload.ResultHash, StringComparison.OrdinalIgnoreCase)) break;
            }
            catch (Exception ex)
            {
                lastReadError = ex;
            }
        }
        if (lastReadError is not null && verifiedFiles is null)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, stage = "post-update-readback", errorType = lastReadError.GetType().Name }, "failed");
            throw new InvalidOperationException("Apps Script project was updated but post-update readback failed; plan was consumed to prevent blind replay.", lastReadError);
        }
        if (verifiedFiles is null || !string.Equals(actualAfterHash, payload.ResultHash, StringComparison.OrdinalIgnoreCase))
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, expectedAfterHash = payload.ResultHash, actualAfterHash, stage = "post-update-hash" }, "failed");
            throw new InvalidOperationException($"Apps Script post-update verification failed; plan was consumed and no automatic rollback was attempted. expected={payload.ResultHash}, actual={actualAfterHash}");
        }

        AppsScriptProjectMetadata? metadata = null;
        try { metadata = await Api.GetProjectAsync(payload.ProjectId, cancellationToken); } catch { }
        var affectedFunctions = payload.AffectedFunctions
            .Concat(verifiedFiles.Where(file => payload.ChangedFiles.Contains(file.Name, StringComparer.Ordinal)).SelectMany(file => file.Functions.Select(function => function.Name)))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();
        Audit.Append(plan.Tool, plan.Operation, plan.Target, new
        {
            plan.PlanId,
            beforeHash = payload.ExpectedHash,
            expectedAfterHash = payload.ResultHash,
            actualAfterHash,
            changedFiles = payload.ChangedFiles,
            verified = true,
            concurrencyModel = ConcurrencyModel
        }, "executed");
        return new(plan.PlanId, payload.ProjectId, payload.ExpectedHash, payload.ResultHash, actualAfterHash, true, payload.ChangedFiles, affectedFunctions, metadata?.UpdateTime, ConcurrencyModel, DateTimeOffset.UtcNow);
    }

    private static async Task<AppsScriptProjectSnapshot> ReadSnapshotAsync(string projectId, CancellationToken cancellationToken)
    {
        projectId = AppsScriptValidation.RequireProjectId(projectId);
        var metadataTask = Api.GetProjectAsync(projectId, cancellationToken);
        var contentTask = Api.GetContentAsync(projectId, cancellationToken);
        await Task.WhenAll(metadataTask, contentTask);
        var metadata = await metadataTask;
        var files = await contentTask;
        var totalBytes = files.Sum(file => (long)Encoding.UTF8.GetByteCount(file.Source));
        return new(projectId, metadata.Title, metadata.UpdateTime, AppsScriptContentHash.Compute(files), files.Count, totalBytes, true, files.OrderBy(file => file.Name, StringComparer.Ordinal).ToArray(), ConcurrencyModel, DateTimeOffset.UtcNow);
    }

    private static void SweepExpiredPayloads()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var pair in Payloads)
            if (pair.Value.ExpiresUtc <= now) Payloads.TryRemove(pair.Key, out _);
    }

    private static string Require(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidDataException($"Signed Apps Script parameter {key} is required.");

    private sealed record PendingPatchPayload(
        DateTimeOffset ExpiresUtc,
        string ProjectId,
        string ExpectedHash,
        string ResultHash,
        IReadOnlyList<AppsScriptProjectFile> Files,
        IReadOnlyList<string> ChangedFiles,
        IReadOnlyList<string> AffectedFunctions);
}
