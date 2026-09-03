using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;
using YowThi.DevelopmentAgent3.Security;

namespace YowThi.DevelopmentAgent3.AcceptanceCleanup;

public sealed record AcceptanceBuildCleanupBlocker(
    string Kind,
    string Detail,
    int? ProcessId = null,
    string? ProcessName = null);

public sealed record AcceptanceBuildDirectoryState(
    string DirectoryName,
    string Target,
    IReadOnlyList<string> Files,
    IReadOnlyList<string> Directories,
    long TotalBytes,
    string ManifestSha256,
    IReadOnlyList<AcceptanceBuildCleanupBlocker> Blockers,
    bool BlockersTruncated);

public sealed partial class AcceptanceBuildCleanupPolicy
{
    public const string FixedAcceptanceRoot = @"C:\Dev\YowThi-ERP-Dev-v4\acceptance";
    private const int MaxEntries = 50_000;
    private const long MaxBytes = 20L * 1024 * 1024 * 1024;
    private const int MaxBlockers = 64;
    private const int ProcessCommandLineInformation = 60;

    private readonly string _root;

    public AcceptanceBuildCleanupPolicy(string? root = null)
    {
        _root = Path.GetFullPath(root ?? FixedAcceptanceRoot)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    public string Root => _root;

    public static bool IsEligibleDirectoryName(string directoryName)
    {
        if (string.IsNullOrWhiteSpace(directoryName) || directoryName.Length > 160)
            return false;
        if (!SafeLeafRegex().IsMatch(directoryName))
            return false;
        return directoryName.Split('-', StringSplitOptions.RemoveEmptyEntries)
            .Contains("build", StringComparer.Ordinal);
    }

    public string ResolveTarget(string directoryName)
    {
        if (!IsEligibleDirectoryName(directoryName))
            throw new ArgumentException("Directory name must be a safe lowercase direct-child acceptance build-output name containing the exact '-' delimited token 'build'.", nameof(directoryName));
        if (!string.Equals(Path.GetFileName(directoryName), directoryName, StringComparison.Ordinal))
            throw new ArgumentException("Only a direct child directory name is accepted.", nameof(directoryName));

        var target = Path.GetFullPath(Path.Combine(_root, directoryName));
        var parent = Path.GetDirectoryName(target)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!string.Equals(parent, _root, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Cleanup target must be one direct child of the fixed acceptance root.");
        return target;
    }

    public AcceptanceBuildDirectoryState Capture(string directoryName, bool includeContentHashes)
    {
        var target = ResolveTarget(directoryName);
        if (!Directory.Exists(_root))
            throw new DirectoryNotFoundException($"Fixed acceptance root does not exist: {_root}");
        RejectReparse(_root, "Fixed acceptance root");
        if (!Directory.Exists(target))
            throw new DirectoryNotFoundException($"Acceptance build directory does not exist: {target}");
        RejectReparse(target, "Acceptance build directory");

        var files = new List<string>();
        var directories = new List<string>();
        var pending = new Stack<string>();
        pending.Push(target);
        var entryCount = 0;
        long totalBytes = 0;

        while (pending.Count > 0)
        {
            var current = pending.Pop();
            foreach (var entry in new DirectoryInfo(current).EnumerateFileSystemInfos("*", SearchOption.TopDirectoryOnly))
            {
                entryCount++;
                if (entryCount > MaxEntries)
                    throw new InvalidOperationException($"Acceptance build directory exceeds the {MaxEntries} entry cleanup limit.");

                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
                    throw new UnauthorizedAccessException($"Reparse points are not allowed in acceptance cleanup targets: {entry.FullName}");

                if (entry is DirectoryInfo directory)
                {
                    directories.Add(directory.FullName);
                    pending.Push(directory.FullName);
                    continue;
                }

                if (entry is not FileInfo file)
                    throw new InvalidDataException($"Unsupported filesystem entry type: {entry.FullName}");

                totalBytes = checked(totalBytes + file.Length);
                if (totalBytes > MaxBytes)
                    throw new InvalidOperationException("Acceptance build directory exceeds the 20 GiB cleanup limit.");
                files.Add(file.FullName);
            }
        }

        files.Sort(StringComparer.OrdinalIgnoreCase);
        directories.Sort(StringComparer.OrdinalIgnoreCase);
        var manifestSha256 = ComputeManifestSha256(target, files, directories, includeContentHashes);
        var (blockers, truncated) = FindBlockers(target, files);

        return new AcceptanceBuildDirectoryState(
            directoryName,
            target,
            files,
            directories,
            totalBytes,
            manifestSha256,
            blockers,
            truncated);
    }

    public void DeleteExact(AcceptanceBuildDirectoryState state)
    {
        var target = ResolveTarget(state.DirectoryName);
        if (!string.Equals(target, state.Target, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Acceptance cleanup target identity changed.");

        foreach (var file in state.Files)
        {
            if (!File.Exists(file))
                throw new InvalidOperationException($"Cleanup target changed before deletion: missing file {SafeRelative(target, file)}");
            var attributes = File.GetAttributes(file);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException($"Reparse point appeared before deletion: {SafeRelative(target, file)}");
            if ((attributes & FileAttributes.ReadOnly) != 0)
                throw new UnauthorizedAccessException($"Read-only file blocks cleanup: {SafeRelative(target, file)}");
            File.Delete(file);
        }

        foreach (var directory in state.Directories.OrderByDescending(path => path.Length).ThenByDescending(path => path, StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(directory))
                throw new InvalidOperationException($"Cleanup target changed before deletion: missing directory {SafeRelative(target, directory)}");
            RejectReparse(directory, "Acceptance cleanup subdirectory");
            Directory.Delete(directory, recursive: false);
        }

        RejectReparse(target, "Acceptance build directory");
        Directory.Delete(target, recursive: false);
        if (Directory.Exists(target))
            throw new IOException("Post-delete read-back still finds the acceptance build directory.");
    }

    private (IReadOnlyList<AcceptanceBuildCleanupBlocker> Blockers, bool Truncated) FindBlockers(string target, IReadOnlyList<string> files)
    {
        var blockers = new List<AcceptanceBuildCleanupBlocker>();
        var seenProcesses = new HashSet<int>();
        var truncated = false;

        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    var processId = process.Id;
                    var processName = Try(() => process.ProcessName);
                    var executable = Try(() => process.MainModule?.FileName);
                    var commandLine = TryReadCommandLine(process);
                    if (!IsSameOrChild(executable, target) && !ContainsPath(commandLine, target))
                        continue;

                    if (seenProcesses.Add(processId))
                    {
                        if (!TryAddBlocker(blockers, new AcceptanceBuildCleanupBlocker(
                                "process-reference",
                                "A running process executable or command line references this acceptance build directory.",
                                processId,
                                processName)))
                        {
                            truncated = true;
                            break;
                        }
                    }
                }
                catch
                {
                }
            }
        }

        if (!truncated)
        {
            foreach (var file in files)
            {
                try
                {
                    using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.None, 1, FileOptions.SequentialScan);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    if (!TryAddBlocker(blockers, new AcceptanceBuildCleanupBlocker(
                            "file-lock-or-access",
                            $"File is not exclusively readable: {SafeRelative(target, file)}")))
                    {
                        truncated = true;
                        break;
                    }
                }
            }
        }

        return (blockers, truncated);
    }

    private static string ComputeManifestSha256(
        string target,
        IReadOnlyList<string> files,
        IReadOnlyList<string> directories,
        bool includeContentHashes)
    {
        using var manifest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var directory in directories.OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
            AppendManifest(manifest, $"D|{SafeRelative(target, directory)}\n");

        foreach (var file in files.OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
        {
            var info = new FileInfo(file);
            var contentSha256 = includeContentHashes ? HashFile(file) : string.Empty;
            AppendManifest(manifest, $"F|{SafeRelative(target, file)}|{info.Length}|{contentSha256}\n");
        }

        return Convert.ToHexString(manifest.GetHashAndReset());
    }

    private static string HashFile(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1024 * 128, FileOptions.SequentialScan);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void AppendManifest(IncrementalHash manifest, string value) =>
        manifest.AppendData(Encoding.UTF8.GetBytes(value));

    private static bool TryAddBlocker(List<AcceptanceBuildCleanupBlocker> blockers, AcceptanceBuildCleanupBlocker blocker)
    {
        if (blockers.Count >= MaxBlockers)
            return false;
        blockers.Add(blocker);
        return true;
    }

    private static bool ContainsPath(string? commandLine, string target) =>
        !string.IsNullOrEmpty(commandLine) && commandLine.Contains(target, StringComparison.OrdinalIgnoreCase);

    private static bool IsSameOrChild(string? path, string root)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        string full;
        try { full = Path.GetFullPath(path); }
        catch { return false; }
        return full.Equals(root, StringComparison.OrdinalIgnoreCase) ||
               full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static string SafeRelative(string root, string path) =>
        Path.GetRelativePath(root, path).Replace(Path.DirectorySeparatorChar, '/');

    private static void RejectReparse(string path, string subject)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException($"{subject} may not be a reparse point: {path}");
    }

    private static string? Try(Func<string?> action)
    {
        try { return action(); }
        catch { return null; }
    }

    private static string? TryReadCommandLine(Process process)
    {
        try
        {
            var handle = process.Handle;
            _ = NtQueryInformationProcess(handle, ProcessCommandLineInformation, IntPtr.Zero, 0, out var required);
            if (required <= 0 || required > 1024 * 1024) return null;

            var buffer = Marshal.AllocHGlobal(required);
            try
            {
                var status = NtQueryInformationProcess(handle, ProcessCommandLineInformation, buffer, required, out _);
                if (status < 0) return null;
                var value = Marshal.PtrToStructure<UNICODE_STRING>(buffer);
                if (value.Length == 0 || value.Buffer == IntPtr.Zero) return string.Empty;
                return Marshal.PtrToStringUni(value.Buffer, value.Length / 2);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch
        {
            return null;
        }
    }

    [GeneratedRegex("^[a-z0-9]+(?:-[a-z0-9]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeLeafRegex();

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        IntPtr processInformation,
        int processInformationLength,
        out int returnLength);
}

[McpServerToolType]
public static class AcceptanceBuildCleanupTools
{
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly AcceptanceBuildCleanupPolicy Policy = new();

    [McpServerTool(Name = "acceptance_build_cleanup_inventory", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List only direct YowThi ERP Dev v4 acceptance child directories whose safe lowercase name contains the exact '-' delimited token 'build'. Each candidate is preflighted for reparse points, bounded tree shape, running-process references, and exclusive file access. This is read-only and never deletes, renames, starts, or stops anything.")]
    public static object AcceptanceBuildCleanupInventory()
    {
        if (!Directory.Exists(Policy.Root))
            throw new DirectoryNotFoundException($"Fixed acceptance root does not exist: {Policy.Root}");

        var candidates = new List<object>();
        foreach (var directory in new DirectoryInfo(Policy.Root).EnumerateDirectories("*", SearchOption.TopDirectoryOnly)
                     .OrderBy(item => item.Name, StringComparer.OrdinalIgnoreCase))
        {
            if (!AcceptanceBuildCleanupPolicy.IsEligibleDirectoryName(directory.Name))
                continue;

            try
            {
                var state = Policy.Capture(directory.Name, includeContentHashes: false);
                candidates.Add(new
                {
                    directoryName = state.DirectoryName,
                    target = state.Target,
                    fileCount = state.Files.Count,
                    directoryCount = state.Directories.Count + 1,
                    totalBytes = state.TotalBytes,
                    eligibleForCleanup = state.Blockers.Count == 0,
                    blockers = state.Blockers,
                    blockersTruncated = state.BlockersTruncated
                });
            }
            catch (Exception ex)
            {
                candidates.Add(new
                {
                    directoryName = directory.Name,
                    target = directory.FullName,
                    fileCount = (int?)null,
                    directoryCount = (int?)null,
                    totalBytes = (long?)null,
                    eligibleForCleanup = false,
                    blockers = new[] { new AcceptanceBuildCleanupBlocker("preflight", ex.GetType().Name + ": " + ex.Message) },
                    blockersTruncated = false
                });
            }
        }

        return new
        {
            root = Policy.Root,
            candidateCount = candidates.Count,
            candidates,
            capturedUtc = DateTimeOffset.UtcNow
        };
    }

    [McpServerTool(Name = "acceptance_build_cleanup_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to delete exactly one verified direct build-output directory under the fixed C:\\Dev\\YowThi-ERP-Dev-v4\\acceptance root. Caller supplies only the safe directory leaf name. The complete file-content manifest, counts, bytes, reparse policy, and zero-blocker process/file-lock preflight are sealed. Arbitrary paths, non-build names, active runtime directories, shell execution, PowerShell, cmd, and production paths are not supported.")]
    public static SignedPlan AcceptanceBuildCleanupPlan(string directoryName)
    {
        var state = Policy.Capture(directoryName, includeContentHashes: true);
        if (state.Blockers.Count != 0)
            throw new InvalidOperationException($"Acceptance build cleanup is blocked by {state.Blockers.Count} active-process/file-access condition(s). First blocker: {state.Blockers[0].Kind} - {state.Blockers[0].Detail}");

        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["directoryName"] = state.DirectoryName,
            ["manifestSha256"] = state.ManifestSha256,
            ["fileCount"] = state.Files.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["directoryCount"] = (state.Directories.Count + 1).ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["totalBytes"] = state.TotalBytes.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };
        var summary = $"Delete verified inactive acceptance build output {state.DirectoryName} under the fixed YowThi ERP Dev v4 acceptance root";
        var unsigned = new SignedPlan(
            1,
            planId,
            approvalCode,
            "acceptance-cleanup",
            "acceptance-build-delete",
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

    [McpServerTool(Name = "acceptance_build_cleanup_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared acceptance-cleanup/acceptance-build-delete plan using only native .NET File.Delete and non-recursive Directory.Delete calls over the sealed direct acceptance build-output tree. Exact signed intent, fixed-root direct-child identity, safe build name, complete content manifest, counts, bytes, reparse policy, running-process references, and exclusive file-access preflight are revalidated immediately before deletion. No arbitrary paths, recursive shell delete, PowerShell, cmd, process stop, or production mutation is supported.")]
    public static Task<ExecutionResult> AcceptanceBuildCleanupExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, operation, target, summary, riskClass);

        try
        {
            var directoryName = RequireParameter(plan, "directoryName");
            var expectedManifestSha256 = RequireParameter(plan, "manifestSha256");
            var expectedFileCount = int.Parse(RequireParameter(plan, "fileCount"), System.Globalization.CultureInfo.InvariantCulture);
            var expectedDirectoryCount = int.Parse(RequireParameter(plan, "directoryCount"), System.Globalization.CultureInfo.InvariantCulture);
            var expectedTotalBytes = long.Parse(RequireParameter(plan, "totalBytes"), System.Globalization.CultureInfo.InvariantCulture);

            var resolvedTarget = Policy.ResolveTarget(directoryName);
            if (!string.Equals(resolvedTarget, plan.Target, StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Signed cleanup target no longer matches the fixed-root direct-child identity.");

            var state = Policy.Capture(directoryName, includeContentHashes: true);
            if (!string.Equals(state.ManifestSha256, expectedManifestSha256, StringComparison.Ordinal) ||
                state.Files.Count != expectedFileCount ||
                state.Directories.Count + 1 != expectedDirectoryCount ||
                state.TotalBytes != expectedTotalBytes)
            {
                throw new InvalidOperationException("Acceptance build directory changed after the cleanup plan was prepared.");
            }
            if (state.Blockers.Count != 0)
                throw new InvalidOperationException($"Acceptance build cleanup became blocked by {state.Blockers.Count} active-process/file-access condition(s). First blocker: {state.Blockers[0].Kind} - {state.Blockers[0].Detail}");

            Policy.DeleteExact(state);
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
            return Task.FromResult(new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow));
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.GetType().Name + ": " + ex.Message }, "failed");
            throw;
        }
    }

    private static string RequireParameter(SignedPlan plan, string name)
    {
        if (!plan.Parameters.TryGetValue(name, out var value) || string.IsNullOrWhiteSpace(value))
            throw new InvalidDataException($"Signed cleanup plan is missing parameter: {name}");
        return value;
    }

    private static void RequireIntentMatch(SignedPlan plan, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "acceptance-cleanup", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, "acceptance-build-delete", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, operation, target, summary, riskClass }, "intent-mismatch");
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
        }
    }
}
