using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Git;

[McpServerToolType]
public static class GitValidationBranchCleanupTools
{
    private const string Repository = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string GitExe = @"C:\Program Files\Git\cmd\git.exe";
    private const string GitCredentialManagerExe = @"C:\Program Files\Git\mingw64\bin\git-credential-manager.exe";
    private const string Origin = "origin";
    private const string ExpectedOriginUrl = "https://github.com/yenpoli-web/yowthi-erp-dev-v4.git";

    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name = "git_validation_branch_absorption_status", ReadOnly = true, Destructive = false, OpenWorld = true)]
    [Description("Evaluate whether one flat p*-validation or m*-validation branch in the fixed YowThi ERP Dev v4 repository is safely disposable. Local divergent history is considered absorbed only when every commit unique to the validation branch is non-merge, every unique commit is represented by git cherry evidence, and every patch is patch-equivalent to a commit already reachable from local main. Remote cleanup eligibility is stricter: the exact origin validation-branch commit must be an ancestor of the local main that exactly matches GitHub origin/main. The dedicated V4 HTTPS origin identity is fixed and validated. This is read-only; it does not delete refs, push, fetch, prune, switch, merge, or modify Git state.")]
    public static async Task<GitValidationBranchAbsorptionStatusResult> GitValidationBranchAbsorptionStatus(string branchName)
        => await ReadStatusAsync(ValidateValidationBranchName(branchName));

    [McpServerTool(Name = "git_validation_branch_cleanup_plan", ReadOnly = false, Destructive = true, OpenWorld = true)]
    [Description("Prepare a one-time signed cleanup plan for one flat p*-validation or m*-validation branch in the fixed YowThi ERP Dev v4 repository. scope must be 'local' or 'origin'. Local cleanup requires clean checked-out main synchronized with GitHub origin/main and either normal merged ancestry or complete patch-equivalence evidence with zero unique merge commits; the target branch may not be checked out in any linked worktree. Origin cleanup requires the exact remote validation-branch commit to be an ancestor of the synchronized main. No force deletion, arbitrary repository, arbitrary remote, arbitrary refspec, tags, shell, or production repository is supported.")]
    public static async Task<SignedPlan> GitValidationBranchCleanupPlan(string branchName, string scope)
    {
        branchName = ValidateValidationBranchName(branchName);
        scope = NormalizeScope(scope);
        var status = await ReadStatusAsync(branchName);
        RequireCleanupBaseline(status);

        string targetCommit;
        if (scope == "local")
        {
            if (!status.LocalExists || string.IsNullOrWhiteSpace(status.LocalBranchCommit))
                throw new InvalidOperationException("Local validation branch does not exist.");
            if (!status.EligibleLocalCleanup)
                throw new InvalidOperationException("Local validation branch is not proven absorbed by main.");
            await RequireBranchNotCheckedOutInAnyWorktreeAsync(branchName);
            targetCommit = status.LocalBranchCommit;
        }
        else
        {
            if (!status.RemoteExists || string.IsNullOrWhiteSpace(status.RemoteBranchCommit))
                throw new InvalidOperationException("Origin validation branch does not exist.");
            if (!status.EligibleRemoteCleanup)
                throw new InvalidOperationException("Origin validation branch is not proven merged into synchronized main.");
            targetCommit = status.RemoteBranchCommit;
        }

        var now = DateTimeOffset.UtcNow;
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["branchName"] = branchName,
            ["scope"] = scope,
            ["mainCommit"] = status.LocalMainCommit,
            ["originMainCommit"] = status.RemoteMainCommit ?? string.Empty,
            ["targetCommit"] = targetCommit,
            ["evidenceSha256"] = status.EvidenceSha256,
            ["originConfigSha256"] = status.OriginConfigSha256,
            ["gitExeSha256"] = GetFileSha256(GitExe),
            ["credentialManagerSha256"] = GetFileSha256(GitCredentialManagerExe)
        };
        var risk = scope == "origin" ? RiskClass.High : RiskClass.Medium;
        var summary = scope == "origin"
            ? $"Delete absorbed origin validation branch {branchName} at {targetCommit[..12]} from dedicated V4 origin"
            : $"Delete absorbed local validation branch {branchName} at {targetCommit[..12]} from fixed V4 repository";
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "git-validation-cleanup", "validation-branch-cleanup", Repository, parameters, risk, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, branchName, scope, targetCommit, status.EvidenceSha256, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "git_validation_branch_cleanup_execute", ReadOnly = false, Destructive = true, OpenWorld = true)]
    [Description("Execute one previously prepared validation-branch cleanup plan. The fixed repository, checked-out clean synchronized main, dedicated V4 origin identity, target branch/commit, absorption evidence, git.exe, and Git Credential Manager are revalidated immediately before mutation. Fully merged local branches use normal git branch --delete. Divergent but completely patch-equivalent local validation branches use compare-and-delete git update-ref against the exact sealed commit, never git branch -D. Origin cleanup uses one explicit deletion refspec only for the sealed same-name validation branch and verifies remote absence plus unchanged origin/main afterward. No force push/delete, arbitrary refspec, arbitrary remote, shell, or production mutation is supported.")]
    public static async Task<GitValidationBranchCleanupExecutionResult> GitValidationBranchCleanupExecute(string planId, string approvalCode)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        if (!string.Equals(plan.Tool, "git-validation-cleanup", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, "validation-branch-cleanup", StringComparison.Ordinal) ||
            !string.Equals(plan.Target, Repository, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Validation-branch cleanup plan identity mismatch.");

        var branchName = ValidateValidationBranchName(RequireParameter(plan, "branchName"));
        var scope = NormalizeScope(RequireParameter(plan, "scope"));
        var expectedMain = RequireParameter(plan, "mainCommit");
        var expectedOriginMain = RequireParameter(plan, "originMainCommit");
        var expectedTargetCommit = RequireParameter(plan, "targetCommit");
        var expectedEvidence = RequireParameter(plan, "evidenceSha256");
        var expectedOriginConfig = RequireParameter(plan, "originConfigSha256");
        var expectedGitSha = RequireParameter(plan, "gitExeSha256");
        var expectedGcmSha = RequireParameter(plan, "credentialManagerSha256");

        if (!string.Equals(expectedGitSha, GetFileSha256(GitExe), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expectedGcmSha, GetFileSha256(GitCredentialManagerExe), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Git executable identity changed after plan creation.");

        var status = await ReadStatusAsync(branchName);
        RequireCleanupBaseline(status);
        if (!string.Equals(status.LocalMainCommit, expectedMain, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(status.RemoteMainCommit, expectedOriginMain, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(status.EvidenceSha256, expectedEvidence, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(status.OriginConfigSha256, expectedOriginConfig, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Validation-branch cleanup evidence changed after plan creation.");

        try
        {
            if (scope == "local")
            {
                if (!status.LocalExists || !status.EligibleLocalCleanup ||
                    !string.Equals(status.LocalBranchCommit, expectedTargetCommit, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Local validation branch is no longer eligible for cleanup.");
                await RequireBranchNotCheckedOutInAnyWorktreeAsync(branchName);

                GitProcessResult deletion;
                string mode;
                if (status.LocalFullyMerged)
                {
                    deletion = await RunGitAsync(new[] { "branch", "--delete", branchName }, 30);
                    mode = "safe-branch-delete";
                }
                else
                {
                    deletion = await RunGitAsync(new[] { "update-ref", "-d", $"refs/heads/{branchName}", expectedTargetCommit }, 30);
                    mode = "absorbed-patch-compare-delete";
                    _ = await RunGitAsync(new[] { "config", "--remove-section", $"branch.{branchName}" }, 30, allowNonZero: true);
                }

                if (await LocalBranchExistsAsync(branchName))
                    throw new InvalidOperationException("Post-delete read-back still finds the local validation branch.");

                Store.Consume(planId);
                Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, branchName, scope, expectedTargetCommit, mode, deletion.ExitCode }, "executed");
                return new GitValidationBranchCleanupExecutionResult(plan.PlanId, branchName, scope, expectedTargetCommit, mode, true, deletion.StdOut, deletion.StdErr, DateTimeOffset.UtcNow);
            }

            if (!status.RemoteExists || !status.EligibleRemoteCleanup ||
                !string.Equals(status.RemoteBranchCommit, expectedTargetCommit, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Origin validation branch is no longer eligible for cleanup.");

            var refspec = $":refs/heads/{branchName}";
            var push = await RunGitAsync(new[] { "push", "--porcelain", "--no-signed", "--no-follow-tags", "--recurse-submodules=no", Origin, refspec }, 300, networkHttpsOnly: true);
            var remoteAfter = await GetRemoteBranchCommitAsync(branchName);
            var remoteMainAfter = await GetRemoteBranchCommitAsync("main");
            if (remoteAfter is not null)
                throw new InvalidOperationException("Post-delete read-back still finds the origin validation branch.");
            if (!string.Equals(remoteMainAfter, expectedOriginMain, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("origin/main changed during validation-branch cleanup.");

            var trackingRef = $"refs/remotes/{Origin}/{branchName}";
            var trackingCommit = await TryResolveRefAsync(trackingRef);
            if (trackingCommit is not null && string.Equals(trackingCommit, expectedTargetCommit, StringComparison.OrdinalIgnoreCase))
                _ = await RunGitAsync(new[] { "update-ref", "-d", trackingRef, expectedTargetCommit }, 30);

            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, branchName, scope, expectedTargetCommit, refspec, push.ExitCode }, "executed");
            return new GitValidationBranchCleanupExecutionResult(plan.PlanId, branchName, scope, expectedTargetCommit, "origin-explicit-delete-refspec", true, push.StdOut, push.StdErr, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, branchName, scope, error = ex.Message }, "failed");
            throw;
        }
    }

    private static async Task<GitValidationBranchAbsorptionStatusResult> ReadStatusAsync(string branchName)
    {
        EnsureFixedRepository();
        var currentBranch = (await RunGitAsync(new[] { "branch", "--show-current" }, 30)).StdOut.Trim();
        var currentHead = (await RunGitAsync(new[] { "rev-parse", "--verify", "HEAD" }, 30)).StdOut.Trim();
        var statusText = NormalizeText((await RunGitAsync(new[] { "status", "--porcelain=v1", "--untracked-files=all" }, 30)).StdOut);
        var workingTreeClean = string.IsNullOrWhiteSpace(statusText);
        var localMain = await ResolveRequiredRefAsync("refs/heads/main");
        var originConfigSha = await GetDedicatedOriginConfigSha256Async();
        var remoteMain = await GetRemoteBranchCommitAsync("main");
        var localCommit = await TryResolveRefAsync($"refs/heads/{branchName}");
        var remoteCommit = await GetRemoteBranchCommitAsync(branchName);

        var localExists = localCommit is not null;
        var remoteExists = remoteCommit is not null;
        var localFullyMerged = false;
        var uniqueCommitCount = 0;
        var uniqueMergeCommitCount = 0;
        var cherryEntryCount = 0;
        var absorbedEquivalentPatchCount = 0;
        var unabsorbedPatchCount = 0;
        var allUniquePatchesAbsorbed = false;

        if (localCommit is not null)
        {
            localFullyMerged = await IsAncestorAsync(localCommit, localMain);
            if (!localFullyMerged)
            {
                uniqueCommitCount = await CountRevisionsAsync($"{localMain}..{localCommit}", mergesOnly: false);
                uniqueMergeCommitCount = await CountRevisionsAsync($"{localMain}..{localCommit}", mergesOnly: true);
                var cherry = NormalizeText((await RunGitAsync(new[] { "cherry", localMain, localCommit }, 60)).StdOut);
                if (!string.IsNullOrWhiteSpace(cherry))
                {
                    foreach (var line in cherry.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    {
                        if (line.Length < 3 || (line[0] != '+' && line[0] != '-'))
                            throw new InvalidDataException("git cherry returned an unexpected evidence line.");
                        cherryEntryCount++;
                        if (line[0] == '-') absorbedEquivalentPatchCount++;
                        else unabsorbedPatchCount++;
                    }
                }
                allUniquePatchesAbsorbed = uniqueCommitCount > 0 &&
                    uniqueMergeCommitCount == 0 &&
                    cherryEntryCount == uniqueCommitCount &&
                    unabsorbedPatchCount == 0 &&
                    absorbedEquivalentPatchCount == uniqueCommitCount;
            }
        }

        var localMainMatchesRemote = remoteMain is not null && string.Equals(localMain, remoteMain, StringComparison.OrdinalIgnoreCase);
        var remoteCommitAvailableLocally = remoteCommit is not null && await CommitObjectExistsAsync(remoteCommit);
        var remoteFullyMerged = remoteCommit is not null && remoteCommitAvailableLocally && await IsAncestorAsync(remoteCommit, localMain);
        var currentBranchIsMain = string.Equals(currentBranch, "main", StringComparison.Ordinal) && string.Equals(currentHead, localMain, StringComparison.OrdinalIgnoreCase);
        var eligibleLocal = localExists && (localFullyMerged || allUniquePatchesAbsorbed);
        var eligibleRemote = remoteExists && localMainMatchesRemote && remoteFullyMerged;

        var evidence = string.Join("\n", new[]
        {
            $"branch={branchName}",
            $"currentBranch={currentBranch}",
            $"currentHead={currentHead}",
            $"clean={workingTreeClean}",
            $"localMain={localMain}",
            $"remoteMain={remoteMain ?? string.Empty}",
            $"localCommit={localCommit ?? string.Empty}",
            $"remoteCommit={remoteCommit ?? string.Empty}",
            $"localFullyMerged={localFullyMerged}",
            $"uniqueCommitCount={uniqueCommitCount}",
            $"uniqueMergeCommitCount={uniqueMergeCommitCount}",
            $"cherryEntryCount={cherryEntryCount}",
            $"absorbedEquivalentPatchCount={absorbedEquivalentPatchCount}",
            $"unabsorbedPatchCount={unabsorbedPatchCount}",
            $"allUniquePatchesAbsorbed={allUniquePatchesAbsorbed}",
            $"remoteCommitAvailableLocally={remoteCommitAvailableLocally}",
            $"remoteFullyMerged={remoteFullyMerged}",
            $"mainMatchesRemote={localMainMatchesRemote}",
            $"originConfig={originConfigSha}"
        });
        var evidenceSha = HashText(evidence);

        return new GitValidationBranchAbsorptionStatusResult(
            Repository,
            branchName,
            currentBranch,
            currentHead,
            currentBranchIsMain,
            workingTreeClean,
            localMain,
            remoteMain,
            localMainMatchesRemote,
            localExists,
            localCommit,
            localFullyMerged,
            uniqueCommitCount,
            uniqueMergeCommitCount,
            cherryEntryCount,
            absorbedEquivalentPatchCount,
            unabsorbedPatchCount,
            allUniquePatchesAbsorbed,
            eligibleLocal,
            remoteExists,
            remoteCommit,
            remoteCommitAvailableLocally,
            remoteFullyMerged,
            eligibleRemote,
            originConfigSha,
            evidenceSha,
            DateTimeOffset.UtcNow);
    }

    private static void RequireCleanupBaseline(GitValidationBranchAbsorptionStatusResult status)
    {
        if (!status.CurrentBranchIsMain)
            throw new InvalidOperationException("Validation-branch cleanup requires checked-out local main.");
        if (!status.WorkingTreeClean)
            throw new InvalidOperationException("Validation-branch cleanup requires a clean working tree.");
        if (!status.LocalMainMatchesRemoteMain || string.IsNullOrWhiteSpace(status.RemoteMainCommit))
            throw new InvalidOperationException("Validation-branch cleanup requires local main to exactly match GitHub origin/main.");
    }

    private static string ValidateValidationBranchName(string branchName)
    {
        if (string.IsNullOrWhiteSpace(branchName))
            throw new ArgumentException("Validation branch name is required.", nameof(branchName));
        var value = branchName.Trim();
        if (value.Length > 128 || value.Contains('/', StringComparison.Ordinal) ||
            !(value.StartsWith("p", StringComparison.Ordinal) || value.StartsWith("m", StringComparison.Ordinal)) ||
            !value.EndsWith("-validation", StringComparison.Ordinal) ||
            value[0] == '-' || value.Contains("..", StringComparison.Ordinal) || value.Contains("@{", StringComparison.Ordinal))
            throw new ArgumentException("Only flat p*-validation or m*-validation branch names are accepted.", nameof(branchName));
        foreach (var c in value)
            if (!(char.IsLetterOrDigit(c) || c is '.' or '_' or '-'))
                throw new ArgumentException("Validation branch name contains an unsupported character.", nameof(branchName));
        return value;
    }

    private static string NormalizeScope(string scope)
    {
        if (string.IsNullOrWhiteSpace(scope))
            throw new ArgumentException("scope is required.", nameof(scope));
        var value = scope.Trim().ToLowerInvariant();
        return value is "local" or "origin" ? value : throw new ArgumentException("scope must be 'local' or 'origin'.", nameof(scope));
    }

    private static async Task RequireBranchNotCheckedOutInAnyWorktreeAsync(string branchName)
    {
        var output = NormalizeText((await RunGitAsync(new[] { "worktree", "list", "--porcelain" }, 30)).StdOut);
        var target = $"branch refs/heads/{branchName}";
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            if (string.Equals(line, target, StringComparison.Ordinal))
                throw new InvalidOperationException("Validation branch is checked out in a Git worktree and cannot be deleted.");
    }

    private static async Task<int> CountRevisionsAsync(string range, bool mergesOnly)
    {
        var args = mergesOnly
            ? new[] { "rev-list", "--count", "--merges", range }
            : new[] { "rev-list", "--count", range };
        var text = (await RunGitAsync(args, 30)).StdOut.Trim();
        if (!int.TryParse(text, out var count) || count < 0)
            throw new InvalidDataException("Unable to parse Git revision count.");
        return count;
    }

    private static async Task<bool> IsAncestorAsync(string ancestor, string descendant)
    {
        var result = await RunGitAsync(new[] { "merge-base", "--is-ancestor", ancestor, descendant }, 30, allowNonZero: true);
        if (result.ExitCode == 0) return true;
        if (result.ExitCode == 1) return false;
        throw new InvalidOperationException("Unable to validate Git commit ancestry.");
    }

    private static async Task<bool> CommitObjectExistsAsync(string commit)
    {
        var result = await RunGitAsync(new[] { "cat-file", "-e", $"{commit}^{{commit}}" }, 30, allowNonZero: true);
        if (result.ExitCode == 0) return true;
        if (result.ExitCode == 1 || result.ExitCode == 128) return false;
        throw new InvalidOperationException("Unable to validate local Git commit object availability.");
    }

    private static async Task<bool> LocalBranchExistsAsync(string branchName)
        => await TryResolveRefAsync($"refs/heads/{branchName}") is not null;

    private static async Task<string> ResolveRequiredRefAsync(string reference)
        => await TryResolveRefAsync(reference) ?? throw new InvalidOperationException($"Required Git ref does not exist: {reference}");

    private static async Task<string?> TryResolveRefAsync(string reference)
    {
        var result = await RunGitAsync(new[] { "rev-parse", "--verify", reference }, 30, allowNonZero: true);
        if (result.ExitCode == 1 || result.ExitCode == 128) return null;
        if (result.ExitCode != 0) throw new InvalidOperationException($"Unable to resolve Git ref: {reference}");
        var commit = result.StdOut.Trim();
        if (commit.Length < 12 || commit.Any(c => !Uri.IsHexDigit(c)))
            throw new InvalidDataException("Git ref resolved to an invalid commit identity.");
        return commit;
    }

    private static async Task<string?> GetRemoteBranchCommitAsync(string branchName)
    {
        var reference = $"refs/heads/{branchName}";
        var result = await RunGitAsync(new[] { "ls-remote", "--heads", Origin, reference }, 60, networkHttpsOnly: true);
        var normalized = NormalizeText(result.StdOut);
        if (string.IsNullOrWhiteSpace(normalized)) return null;
        var lines = normalized.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (lines.Length != 1) throw new InvalidDataException("Remote branch lookup returned multiple refs.");
        var parts = lines[0].Split('\t');
        if (parts.Length != 2 || !string.Equals(parts[1], reference, StringComparison.Ordinal))
            throw new InvalidDataException("Remote branch lookup returned an unexpected ref.");
        var commit = parts[0].Trim();
        if (commit.Length < 12 || commit.Any(c => !Uri.IsHexDigit(c)))
            throw new InvalidDataException("Remote branch lookup returned an invalid commit identity.");
        return commit;
    }

    private static async Task<string> GetDedicatedOriginConfigSha256Async()
    {
        var fetchUrls = NormalizeText((await RunGitAsync(new[] { "remote", "get-url", "--all", Origin }, 30)).StdOut)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var pushUrls = NormalizeText((await RunGitAsync(new[] { "remote", "get-url", "--push", "--all", Origin }, 30)).StdOut)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var fetchRefspecs = NormalizeText((await RunGitAsync(new[] { "config", "--get-all", $"remote.{Origin}.fetch" }, 30)).StdOut)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var expectedRefspec = $"+refs/heads/*:refs/remotes/{Origin}/*";
        if (fetchUrls.Length != 1 || pushUrls.Length != 1 || fetchRefspecs.Length != 1 ||
            !string.Equals(fetchUrls[0], ExpectedOriginUrl, StringComparison.Ordinal) ||
            !string.Equals(pushUrls[0], ExpectedOriginUrl, StringComparison.Ordinal) ||
            !string.Equals(fetchRefspecs[0], expectedRefspec, StringComparison.Ordinal))
            throw new InvalidOperationException("Dedicated V4 origin configuration does not match the fixed cleanup identity.");
        return HashText($"fetch={fetchUrls[0]}\npush={pushUrls[0]}\nrefspec={fetchRefspecs[0]}");
    }

    private static void EnsureFixedRepository()
    {
        EnsureFile(GitExe, "git.exe");
        EnsureFile(GitCredentialManagerExe, "Git Credential Manager");
        if (!Directory.Exists(Repository))
            throw new DirectoryNotFoundException("Fixed V4 repository does not exist.");
        if ((File.GetAttributes(Repository) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Fixed V4 repository root may not be a reparse point.");
    }

    private static void EnsureFile(string path, string label)
    {
        if (!File.Exists(path)) throw new FileNotFoundException($"{label} was not found.", path);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException($"{label} may not be a reparse point.");
    }

    private static string GetFileSha256(string path)
    {
        EnsureFile(path, Path.GetFileName(path));
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static async Task<GitProcessResult> RunGitAsync(IReadOnlyList<string> arguments, int timeoutSeconds, bool allowNonZero = false, bool networkHttpsOnly = false)
    {
        EnsureFixedRepository();
        var psi = new ProcessStartInfo
        {
            FileName = GitExe,
            WorkingDirectory = Repository,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        psi.Environment["GIT_TERMINAL_PROMPT"] = "0";
        psi.Environment["GCM_INTERACTIVE"] = "Never";
        psi.Environment["GIT_PAGER"] = "cat";
        psi.Environment.Remove("GIT_ASKPASS");
        psi.Environment.Remove("SSH_ASKPASS");

        psi.ArgumentList.Add("--no-pager");
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add("core.hooksPath=NUL");
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add("core.fsmonitor=false");
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add("submodule.recurse=false");
        if (networkHttpsOnly)
        {
            var systemDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            psi.Environment["PATH"] = string.Join(Path.PathSeparator, Path.GetDirectoryName(GitCredentialManagerExe)!, Path.GetDirectoryName(GitExe)!, systemDirectory, windowsDirectory);
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("credential.helper=");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("credential.helper=manager");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("credential.interactive=false");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("protocol.allow=never");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("protocol.https.allow=always");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("protocol.http.allow=never");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("protocol.ssh.allow=never");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("protocol.git.allow=never");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("protocol.file.allow=never");
            psi.ArgumentList.Add("-c");
            psi.ArgumentList.Add("protocol.ext.allow=never");
        }
        psi.ArgumentList.Add("-c");
        psi.ArgumentList.Add($"safe.directory={Repository}");
        psi.ArgumentList.Add("-C");
        psi.ArgumentList.Add(Repository);
        foreach (var argument in arguments) psi.ArgumentList.Add(argument);

        using var process = Process.Start(psi) ?? throw new InvalidOperationException("git.exe failed to start.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        try
        {
            await process.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"git.exe exceeded {timeoutSeconds} seconds.");
        }
        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        var result = new GitProcessResult(process.ExitCode, stdout, stderr);
        if (!allowNonZero && result.ExitCode != 0)
        {
            var detail = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
            if (detail.Length > 2000) detail = detail[..2000];
            throw new InvalidOperationException($"git.exe exited with code {result.ExitCode}: {detail.Trim()}");
        }
        return result;
    }

    private static string RequireParameter(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidDataException($"{key} parameter is required.");

    private static string NormalizeText(string text) => text.Replace("\r\n", "\n", StringComparison.Ordinal).Trim();
    private static string HashText(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    private sealed record GitProcessResult(int ExitCode, string StdOut, string StdErr);
}

public sealed record GitValidationBranchAbsorptionStatusResult(
    string Repository,
    string BranchName,
    string CurrentBranch,
    string CurrentHead,
    bool CurrentBranchIsMain,
    bool WorkingTreeClean,
    string LocalMainCommit,
    string? RemoteMainCommit,
    bool LocalMainMatchesRemoteMain,
    bool LocalExists,
    string? LocalBranchCommit,
    bool LocalFullyMerged,
    int UniqueCommitCount,
    int UniqueMergeCommitCount,
    int CherryEntryCount,
    int AbsorbedEquivalentPatchCount,
    int UnabsorbedPatchCount,
    bool AllUniquePatchesAbsorbed,
    bool EligibleLocalCleanup,
    bool RemoteExists,
    string? RemoteBranchCommit,
    bool RemoteCommitAvailableLocally,
    bool RemoteFullyMerged,
    bool EligibleRemoteCleanup,
    string OriginConfigSha256,
    string EvidenceSha256,
    DateTimeOffset CheckedUtc);

public sealed record GitValidationBranchCleanupExecutionResult(
    string PlanId,
    string BranchName,
    string Scope,
    string DeletedCommit,
    string Mode,
    bool Deleted,
    string StdOut,
    string StdErr,
    DateTimeOffset ExecutedUtc);
