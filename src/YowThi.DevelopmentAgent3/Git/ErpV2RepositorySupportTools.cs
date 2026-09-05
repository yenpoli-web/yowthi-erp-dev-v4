using System.Collections.Concurrent;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Git;

[McpServerToolType]
public static class ErpV2RepositorySupportTools
{
    private const string RepositoryRoot = @"C:\Dev\yowthi-erp-v2";
    private const string GitExe = @"C:\Program Files\Git\cmd\git.exe";
    private const int MaxSearchQueryChars = 2048;
    private const int MaxSearchResults = 500;
    private const int MaxSearchFiles = 12000;
    private const long MaxSearchTotalBytes = 96L * 1024 * 1024;
    private const int MaxSearchFileBytes = 2 * 1024 * 1024;
    private const int MaxSearchPreviewChars = 500;
    private const int MaxPatchFileBytes = 4 * 1024 * 1024;
    private const int MaxPatchOutputBytes = 8 * 1024 * 1024;
    private const int MaxReplacementCount = 32;
    private const int MaxReplacementTextChars = 256 * 1024;

    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly ConcurrentDictionary<string, PendingPatchPayload> PendingPatchPayloads = new(StringComparer.Ordinal);

    [McpServerTool(Name = "erp_v2_repository_text_search", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Search UTF-8 text in the fixed C:\\Dev\\yowthi-erp-v2 repository without shell execution. Candidate files come only from fixed git ls-files --cached --others --exclude-standard, so .git and ignored build/dependency trees are not traversed. Search is line-oriented and supports mode literal or regex, an optional bounded root-relative glob, case sensitivity, and bounded result count. Reparse traversal, oversized files, invalid UTF-8, NUL-containing files, and likely credential/private-key files are skipped. Results contain only relative path, line number, and bounded line preview.")]
    public static async Task<ErpV2RepositoryTextSearchResult> ErpV2RepositoryTextSearch(
        string query,
        string mode = "literal",
        string? glob = null,
        bool caseSensitive = false,
        int maxResults = 100)
    {
        EnsureRepositoryRoot();
        query = ValidateSearchQuery(query);
        mode = NormalizeSearchMode(mode);
        var normalizedGlob = NormalizeGlob(glob);
        if (maxResults < 1 || maxResults > MaxSearchResults)
            throw new ArgumentOutOfRangeException(nameof(maxResults), $"maxResults must be between 1 and {MaxSearchResults}.");

        Regex? searchRegex = null;
        if (mode == "regex")
        {
            try
            {
                searchRegex = new Regex(
                    query,
                    RegexOptions.CultureInvariant | (caseSensitive ? RegexOptions.None : RegexOptions.IgnoreCase),
                    TimeSpan.FromMilliseconds(250));
            }
            catch (ArgumentException ex)
            {
                throw new ArgumentException($"Invalid regular expression: {ex.Message}", nameof(query));
            }
        }

        Regex? globRegex = normalizedGlob is null ? null : BuildGlobRegex(normalizedGlob);
        var files = await GetRepositoryCandidateFilesAsync();
        var matches = new List<ErpV2RepositoryTextSearchMatch>();
        var scannedFiles = 0;
        long scannedBytes = 0;
        var skippedOversized = 0;
        var skippedInvalidUtf8OrBinary = 0;
        var skippedSensitive = 0;
        var truncatedByBudget = false;

        foreach (var relativePath in files)
        {
            if (matches.Count >= maxResults)
                break;
            if (scannedFiles >= MaxSearchFiles || scannedBytes >= MaxSearchTotalBytes)
            {
                truncatedByBudget = true;
                break;
            }
            if (globRegex is not null && !globRegex.IsMatch(relativePath))
                continue;
            if (IsSensitiveRelativePath(relativePath))
            {
                skippedSensitive++;
                continue;
            }

            string fullPath;
            try
            {
                fullPath = ResolveSafeRepositoryFile(relativePath, requireTracked: false);
            }
            catch
            {
                skippedInvalidUtf8OrBinary++;
                continue;
            }

            var info = new FileInfo(fullPath);
            if (!info.Exists || info.Length > MaxSearchFileBytes)
            {
                skippedOversized++;
                continue;
            }
            if (scannedBytes + info.Length > MaxSearchTotalBytes)
            {
                truncatedByBudget = true;
                break;
            }

            TextFileSnapshot snapshot;
            try
            {
                snapshot = ReadUtf8TextFile(fullPath, MaxSearchFileBytes);
            }
            catch (Exception ex) when (ex is DecoderFallbackException or InvalidDataException or IOException or UnauthorizedAccessException)
            {
                skippedInvalidUtf8OrBinary++;
                continue;
            }

            scannedFiles++;
            scannedBytes += snapshot.ByteLength;
            var lines = snapshot.Text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
            for (var i = 0; i < lines.Length && matches.Count < maxResults; i++)
            {
                var line = lines[i];
                bool isMatch;
                if (searchRegex is not null)
                {
                    try
                    {
                        isMatch = searchRegex.IsMatch(line);
                    }
                    catch (RegexMatchTimeoutException)
                    {
                        throw new TimeoutException("A repository text-search regular expression exceeded the per-line timeout.");
                    }
                }
                else
                {
                    isMatch = line.IndexOf(query, caseSensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase) >= 0;
                }

                if (isMatch)
                {
                    matches.Add(new ErpV2RepositoryTextSearchMatch(
                        relativePath,
                        i + 1,
                        BoundPreview(line)));
                }
            }
        }

        var resultLimitReached = matches.Count >= maxResults;
        return new ErpV2RepositoryTextSearchResult(
            RepositoryRoot,
            mode,
            normalizedGlob,
            caseSensitive,
            maxResults,
            scannedFiles,
            scannedBytes,
            skippedOversized,
            skippedInvalidUtf8OrBinary,
            skippedSensitive,
            resultLimitReached,
            truncatedByBudget,
            matches,
            DateTimeOffset.UtcNow);
    }

    [McpServerTool(Name = "erp_v2_file_text_patch_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed compare-and-swap text patch for one existing tracked UTF-8 file under the fixed C:\\Dev\\yowthi-erp-v2 repository. Caller supplies a repository-relative file path, the exact expected current SHA-256, and 1-32 literal replacement assertions. Each replacement has from, to, and expectedMatchCount. All assertions are evaluated in order entirely in memory before a plan is issued. UTF-8 BOM and a single consistent LF/CRLF style are preserved; mixed/standalone-CR newlines, NUL/binary content, reparse traversal, .git paths, sensitive credential/private-key paths, oversized files/output, untracked files, no-op patches, regex replacement, and production paths are rejected. Replacement content itself is retained only in an expiring in-memory payload; the signed plan/audit contain only hashes, counts, sizes, and path identity.")]
    public static async Task<SignedPlan> ErpV2FileTextPatchPlan(
        string path,
        string expectedFileSha256,
        ErpV2TextReplacement[] replacements)
    {
        EnsureRepositoryRoot();
        var relativePath = NormalizeRepositoryRelativePath(path);
        if (IsSensitiveRelativePath(relativePath))
            throw new UnauthorizedAccessException("Sensitive credential/private-key style paths are not eligible for ERP V2 text patching.");
        ValidateSha256(expectedFileSha256, nameof(expectedFileSha256));
        await RequireTrackedFileAsync(relativePath);
        var fullPath = ResolveSafeRepositoryFile(relativePath, requireTracked: false);
        var snapshot = ReadUtf8TextFile(fullPath, MaxPatchFileBytes);
        if (!string.Equals(snapshot.Sha256, expectedFileSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Current ERP V2 file SHA-256 does not match expectedFileSha256.");

        var normalizedReplacements = NormalizeAndValidateReplacements(replacements, snapshot.NewlineStyle);
        var outputText = ApplyReplacementsWithAssertions(snapshot.Text, normalizedReplacements);
        if (string.Equals(outputText, snapshot.Text, StringComparison.Ordinal))
            throw new InvalidOperationException("The requested ERP V2 text patch is a no-op.");

        var outputBytes = EncodeUtf8(outputText, snapshot.HasBom);
        if (outputBytes.Length > MaxPatchOutputBytes)
            throw new InvalidOperationException($"Patched ERP V2 file would exceed the {MaxPatchOutputBytes} byte output limit.");
        var outputSha = Convert.ToHexString(SHA256.HashData(outputBytes));
        var payloadJson = JsonSerializer.Serialize(normalizedReplacements);
        var payloadSha = HashText(payloadJson);

        CleanupExpiredPayloads();
        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["relativePath"] = relativePath,
            ["inputSha256"] = snapshot.Sha256,
            ["outputSha256"] = outputSha,
            ["payloadSha256"] = payloadSha,
            ["replacementCount"] = normalizedReplacements.Length.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["inputBytes"] = snapshot.ByteLength.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["outputBytes"] = outputBytes.Length.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["hasBom"] = snapshot.HasBom ? "true" : "false",
            ["newlineStyle"] = snapshot.NewlineStyle
        };
        var summary = $"Patch tracked ERP V2 text file {relativePath} by sealed literal assertions ({snapshot.Sha256[..12]} -> {outputSha[..12]})";
        var unsigned = new SignedPlan(
            1, planId, Convert.ToHexString(RandomNumberGenerator.GetBytes(6)),
            "erp-v2-text-patch", "file-text-patch", fullPath,
            parameters, RiskClass.Medium, summary,
            now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        PendingPatchPayloads[planId] = new PendingPatchPayload(
            planId, relativePath, normalizedReplacements, payloadSha, outputSha, now.AddMinutes(10));
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new
        {
            signed.PlanId,
            relativePath,
            inputSha256 = snapshot.Sha256,
            outputSha256 = outputSha,
            payloadSha256 = payloadSha,
            replacementCount = normalizedReplacements.Length,
            signed.RiskClass,
            signed.Summary
        }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "erp_v2_file_text_patch_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared ERP V2 file-text patch. Only planId and approvalCode are accepted. The fixed repository boundary, tracked-file identity, reparse policy, exact input SHA-256, newline/BOM style, sealed in-memory replacement payload hash, all literal match-count assertions, and exact expected output SHA-256 are revalidated immediately before any write. The replacement is written to a CreateNew same-directory temporary file, SHA-verified, then atomically swapped with File.Replace while retaining a temporary same-directory rollback copy of the original. Post-write SHA/read-back must match the sealed output; verification failure attempts rollback and proves the original SHA when possible. No shell, regex patch, arbitrary path, production path, or partial assertion write is supported.")]
    public static async Task<ErpV2FileTextPatchExecutionResult> ErpV2FileTextPatchExecute(string planId, string approvalCode)
    {
        CleanupExpiredPayloads();
        var plan = Store.GetValidated(planId, approvalCode);
        if (!string.Equals(plan.Tool, "erp-v2-text-patch", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, "file-text-patch", StringComparison.Ordinal))
            throw new UnauthorizedAccessException("ERP V2 text-patch plan identity mismatch.");

        if (!PendingPatchPayloads.TryGetValue(planId, out var payload) || payload.ExpiresUtc <= DateTimeOffset.UtcNow)
            throw new InvalidOperationException("ERP V2 text-patch payload is missing or expired; prepare a new plan.");

        var relativePath = NormalizeRepositoryRelativePath(RequireParameter(plan, "relativePath"));
        if (!string.Equals(relativePath, payload.RelativePath, StringComparison.Ordinal))
            throw new InvalidOperationException("ERP V2 text-patch payload path mismatch.");
        if (IsSensitiveRelativePath(relativePath))
            throw new UnauthorizedAccessException("Sensitive paths are not eligible for ERP V2 text patching.");
        await RequireTrackedFileAsync(relativePath);
        var fullPath = ResolveSafeRepositoryFile(relativePath, requireTracked: false);
        if (!string.Equals(fullPath, plan.Target, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("ERP V2 text-patch target identity changed after plan creation.");

        var expectedInputSha = RequireParameter(plan, "inputSha256");
        var expectedOutputSha = RequireParameter(plan, "outputSha256");
        var expectedPayloadSha = RequireParameter(plan, "payloadSha256");
        var expectedBom = RequireParameter(plan, "hasBom");
        var expectedNewline = RequireParameter(plan, "newlineStyle");
        var payloadJson = JsonSerializer.Serialize(payload.Replacements);
        var actualPayloadSha = HashText(payloadJson);
        if (!string.Equals(expectedPayloadSha, payload.PayloadSha256, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expectedPayloadSha, actualPayloadSha, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expectedOutputSha, payload.OutputSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("ERP V2 text-patch sealed payload changed after plan creation.");

        var snapshot = ReadUtf8TextFile(fullPath, MaxPatchFileBytes);
        if (!string.Equals(snapshot.Sha256, expectedInputSha, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("ERP V2 file changed after patch plan creation.");
        if (!string.Equals(snapshot.NewlineStyle, expectedNewline, StringComparison.Ordinal) ||
            !string.Equals(snapshot.HasBom ? "true" : "false", expectedBom, StringComparison.Ordinal))
            throw new InvalidOperationException("ERP V2 file encoding/newline shape changed after patch plan creation.");

        var outputText = ApplyReplacementsWithAssertions(snapshot.Text, payload.Replacements);
        var outputBytes = EncodeUtf8(outputText, snapshot.HasBom);
        if (outputBytes.Length > MaxPatchOutputBytes)
            throw new InvalidOperationException("ERP V2 patch output exceeds the bounded output size.");
        var actualOutputSha = Convert.ToHexString(SHA256.HashData(outputBytes));
        if (!string.Equals(actualOutputSha, expectedOutputSha, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("ERP V2 patch output SHA-256 does not match the sealed plan.");

        var directory = Path.GetDirectoryName(fullPath) ?? throw new InvalidOperationException("ERP V2 patch target has no parent directory.");
        var leaf = Path.GetFileName(fullPath);
        var nonce = Guid.NewGuid().ToString("N");
        var tempPath = Path.Combine(directory, $".{leaf}.yowthi-patch-{nonce}.tmp");
        var backupPath = Path.Combine(directory, $".{leaf}.yowthi-patch-{nonce}.rollback");
        var replaced = false;
        var rolledBack = false;
        try
        {
            await WriteNewFileAsync(tempPath, outputBytes);
            var tempSha = GetFileSha256(tempPath);
            if (!string.Equals(tempSha, expectedOutputSha, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("ERP V2 patch temporary-file SHA-256 verification failed.");

            File.Replace(tempPath, fullPath, backupPath, ignoreMetadataErrors: false);
            replaced = true;

            var post = ReadUtf8TextFile(fullPath, MaxPatchOutputBytes);
            if (!string.Equals(post.Sha256, expectedOutputSha, StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    if (File.Exists(backupPath))
                    {
                        File.Replace(backupPath, fullPath, null, ignoreMetadataErrors: false);
                        rolledBack = true;
                    }
                }
                catch { }

                if (rolledBack)
                {
                    var rollbackSha = GetFileSha256(fullPath);
                    if (!string.Equals(rollbackSha, expectedInputSha, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("ERP V2 patch verification failed and rollback SHA-256 could not be proven.");
                }
                throw new InvalidDataException("ERP V2 patch post-write SHA-256 verification failed; rollback was attempted.");
            }

            if (File.Exists(backupPath))
                File.Delete(backupPath);
            PendingPatchPayloads.TryRemove(planId, out _);
            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new
            {
                plan.PlanId,
                relativePath,
                inputSha256 = expectedInputSha,
                outputSha256 = expectedOutputSha,
                replacementCount = payload.Replacements.Length,
                outputBytes = outputBytes.Length
            }, "executed");
            return new ErpV2FileTextPatchExecutionResult(
                plan.PlanId, relativePath, expectedInputSha, expectedOutputSha,
                payload.Replacements.Length, outputBytes.Length, true, false, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new
            {
                plan.PlanId,
                relativePath,
                inputSha256 = expectedInputSha,
                outputSha256 = expectedOutputSha,
                replaced,
                rolledBack,
                error = ex.Message
            }, "failed");
            throw;
        }
        finally
        {
            try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
            try { if (File.Exists(backupPath) && !replaced) File.Delete(backupPath); } catch { }
        }
    }

    private static async Task<string[]> GetRepositoryCandidateFilesAsync()
    {
        var result = await RunGitAsync(new[] { "ls-files", "-z", "--cached", "--others", "--exclude-standard" }, 60);
        var paths = result.StdOut.Split('\0', StringSplitOptions.RemoveEmptyEntries);
        if (paths.Length > 100_000)
            throw new InvalidDataException("ERP V2 repository file inventory exceeds the bounded entry limit.");
        return paths.Select(x => x.Replace('\\', '/')).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static string NormalizeRepositoryRelativePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 512 || path.Any(char.IsControl))
            throw new ArgumentException("path must be a non-empty bounded repository-relative text path.", nameof(path));
        if (Path.IsPathFullyQualified(path))
            throw new ArgumentException("Absolute ERP V2 patch/search paths are not accepted.", nameof(path));
        var slash = path.Replace('\\', '/');
        if (slash == "." || slash.StartsWith("../", StringComparison.Ordinal) || slash.Contains("/../", StringComparison.Ordinal) ||
            string.Equals(slash, ".git", StringComparison.OrdinalIgnoreCase) || slash.StartsWith(".git/", StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("ERP V2 repository path escapes or targets .git internals.");
        var full = Path.GetFullPath(Path.Combine(RepositoryRoot, slash));
        var prefix = RepositoryRoot.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("ERP V2 repository path escapes the fixed repository root.");
        var relative = Path.GetRelativePath(RepositoryRoot, full).Replace('\\', '/');
        if (relative.StartsWith("../", StringComparison.Ordinal) || relative == "..")
            throw new UnauthorizedAccessException("ERP V2 repository path escapes the fixed repository root.");
        return relative;
    }

    private static string ResolveSafeRepositoryFile(string relativePath, bool requireTracked)
    {
        var normalized = NormalizeRepositoryRelativePath(relativePath);
        var full = Path.GetFullPath(Path.Combine(RepositoryRoot, normalized));
        var current = RepositoryRoot;
        foreach (var segment in normalized.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if ((File.Exists(current) || Directory.Exists(current)) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException("Reparse traversal is not allowed under ERP V2 repository support tools.");
        }
        if (!File.Exists(full))
            throw new FileNotFoundException("ERP V2 repository text file was not found.", full);
        if (requireTracked)
            throw new InvalidOperationException("Internal tracked-file validation must use RequireTrackedFileAsync.");
        return full;
    }

    private static async Task RequireTrackedFileAsync(string relativePath)
    {
        var result = await RunGitAsync(new[] { "ls-files", "--error-unmatch", "--", relativePath }, 30, allowNonZero: true);
        if (result.ExitCode != 0)
            throw new InvalidOperationException("ERP V2 text patching is restricted to existing Git-tracked files.");
    }

    private static TextFileSnapshot ReadUtf8TextFile(string fullPath, int maxBytes)
    {
        var info = new FileInfo(fullPath);
        if (!info.Exists)
            throw new FileNotFoundException("Text file not found.", fullPath);
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Text files may not be reparse points.");
        if (info.Length < 0 || info.Length > maxBytes)
            throw new InvalidDataException($"Text file exceeds the {maxBytes} byte limit.");
        var bytes = File.ReadAllBytes(fullPath);
        var hasBom = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
        var offset = hasBom ? 3 : 0;
        var strictUtf8 = new UTF8Encoding(false, true);
        var text = strictUtf8.GetString(bytes, offset, bytes.Length - offset);
        if (text.IndexOf('\0') >= 0)
            throw new InvalidDataException("NUL-containing files are not treated as ERP V2 text files.");
        var newlineStyle = DetectNewlineStyle(text);
        var sha = Convert.ToHexString(SHA256.HashData(bytes));
        return new TextFileSnapshot(text, hasBom, newlineStyle, bytes.Length, sha);
    }

    private static string DetectNewlineStyle(string text)
    {
        var crlfCount = CountOccurrences(text, "\r\n");
        var withoutCrlf = text.Replace("\r\n", string.Empty, StringComparison.Ordinal);
        if (withoutCrlf.IndexOf('\r') >= 0)
            throw new InvalidDataException("Standalone CR newlines are not supported for ERP V2 text patching.");
        var lfCount = withoutCrlf.Count(c => c == '\n');
        if (crlfCount > 0 && lfCount > 0)
            throw new InvalidDataException("Mixed LF/CRLF files are not supported for ERP V2 text patching.");
        if (crlfCount > 0) return "CRLF";
        if (lfCount > 0) return "LF";
        return "NONE";
    }

    private static ErpV2NormalizedTextReplacement[] NormalizeAndValidateReplacements(ErpV2TextReplacement[]? replacements, string newlineStyle)
    {
        if (replacements is null || replacements.Length < 1 || replacements.Length > MaxReplacementCount)
            throw new ArgumentException($"replacements must contain between 1 and {MaxReplacementCount} items.", nameof(replacements));
        var newline = newlineStyle == "CRLF" ? "\r\n" : newlineStyle == "LF" ? "\n" : Environment.NewLine;
        var normalized = new List<ErpV2NormalizedTextReplacement>();
        var seenFrom = new HashSet<string>(StringComparer.Ordinal);
        var totalChars = 0;
        foreach (var replacement in replacements)
        {
            if (replacement is null)
                throw new ArgumentException("replacement entries may not be null.", nameof(replacements));
            if (replacement.ExpectedMatchCount < 1 || replacement.ExpectedMatchCount > 10000)
                throw new ArgumentException("expectedMatchCount must be between 1 and 10000.", nameof(replacements));
            if (replacement.From is null || replacement.To is null)
                throw new ArgumentException("replacement from/to values may not be null.", nameof(replacements));
            if (replacement.From.IndexOf('\0') >= 0 || replacement.To.IndexOf('\0') >= 0)
                throw new ArgumentException("replacement text may not contain NUL.", nameof(replacements));
            totalChars += replacement.From.Length + replacement.To.Length;
            if (totalChars > MaxReplacementTextChars)
                throw new ArgumentException($"combined replacement text exceeds {MaxReplacementTextChars} characters.", nameof(replacements));

            var from = NormalizeReplacementNewlines(replacement.From, newline);
            var to = NormalizeReplacementNewlines(replacement.To, newline);
            if (from.Length == 0)
                throw new ArgumentException("replacement from value may not be empty.", nameof(replacements));
            if (string.Equals(from, to, StringComparison.Ordinal))
                throw new ArgumentException("replacement from and to values may not be identical.", nameof(replacements));
            if (!seenFrom.Add(from))
                throw new ArgumentException("duplicate normalized replacement from values are not accepted.", nameof(replacements));
            normalized.Add(new ErpV2NormalizedTextReplacement(from, to, replacement.ExpectedMatchCount));
        }
        return normalized.ToArray();
    }

    private static string NormalizeReplacementNewlines(string value, string targetNewline)
    {
        var normalized = value.Replace("\r\n", "\n", StringComparison.Ordinal);
        if (normalized.IndexOf('\r') >= 0)
            throw new ArgumentException("replacement text may use only LF or CRLF newline sequences.");
        return targetNewline == "\n" ? normalized : normalized.Replace("\n", targetNewline, StringComparison.Ordinal);
    }

    private static string ApplyReplacementsWithAssertions(string input, IReadOnlyList<ErpV2NormalizedTextReplacement> replacements)
    {
        var current = input;
        foreach (var replacement in replacements)
        {
            var count = CountOccurrences(current, replacement.From);
            if (count != replacement.ExpectedMatchCount)
                throw new InvalidOperationException($"Literal replacement assertion failed: expected {replacement.ExpectedMatchCount} match(es), found {count}.");
            current = ReplaceOrdinal(current, replacement.From, replacement.To);
        }
        return current;
    }

    private static int CountOccurrences(string text, string value)
    {
        if (value.Length == 0) return 0;
        var count = 0;
        var index = 0;
        while ((index = text.IndexOf(value, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += value.Length;
        }
        return count;
    }

    private static string ReplaceOrdinal(string input, string from, string to)
    {
        var first = input.IndexOf(from, StringComparison.Ordinal);
        if (first < 0) return input;
        var builder = new StringBuilder(input.Length);
        var position = 0;
        var index = first;
        while (index >= 0)
        {
            builder.Append(input, position, index - position);
            builder.Append(to);
            position = index + from.Length;
            index = input.IndexOf(from, position, StringComparison.Ordinal);
        }
        builder.Append(input, position, input.Length - position);
        return builder.ToString();
    }

    private static byte[] EncodeUtf8(string text, bool hasBom)
    {
        var body = new UTF8Encoding(false, true).GetBytes(text);
        if (!hasBom) return body;
        var bytes = new byte[3 + body.Length];
        bytes[0] = 0xEF; bytes[1] = 0xBB; bytes[2] = 0xBF;
        Buffer.BlockCopy(body, 0, bytes, 3, body.Length);
        return bytes;
    }

    private static async Task WriteNewFileAsync(string path, byte[] bytes)
    {
        await using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.WriteThrough | FileOptions.Asynchronous);
        await stream.WriteAsync(bytes);
        await stream.FlushAsync();
        stream.Flush(flushToDisk: true);
    }

    private static string ValidateSearchQuery(string query)
    {
        if (string.IsNullOrEmpty(query) || query.Length > MaxSearchQueryChars || query.IndexOf('\0') >= 0)
            throw new ArgumentException($"query must contain 1-{MaxSearchQueryChars} non-NUL characters.", nameof(query));
        return query;
    }

    private static string NormalizeSearchMode(string mode)
    {
        if (string.IsNullOrWhiteSpace(mode))
            throw new ArgumentException("mode is required.", nameof(mode));
        var value = mode.Trim().ToLowerInvariant();
        return value is "literal" or "regex" ? value : throw new ArgumentException("mode must be literal or regex.", nameof(mode));
    }

    private static string? NormalizeGlob(string? glob)
    {
        if (string.IsNullOrWhiteSpace(glob)) return null;
        var value = glob.Trim().Replace('\\', '/');
        if (value.Length > 256 || value.StartsWith('/') || value.Contains("..", StringComparison.Ordinal) || value.Contains(':') || value.IndexOf('\0') >= 0)
            throw new ArgumentException("glob must be a bounded root-relative glob without traversal or drive syntax.", nameof(glob));
        return value;
    }

    private static Regex BuildGlobRegex(string glob)
    {
        var builder = new StringBuilder("^");
        for (var i = 0; i < glob.Length; i++)
        {
            var c = glob[i];
            if (c == '*')
            {
                if (i + 1 < glob.Length && glob[i + 1] == '*')
                {
                    i++;
                    if (i + 1 < glob.Length && glob[i + 1] == '/')
                    {
                        i++;
                        builder.Append("(?:.*/)?");
                    }
                    else builder.Append(".*");
                }
                else builder.Append("[^/]*");
            }
            else if (c == '?') builder.Append("[^/]");
            else builder.Append(Regex.Escape(c.ToString()));
        }
        builder.Append('$');
        return new Regex(builder.ToString(), RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(250));
    }

    private static bool IsSensitiveRelativePath(string relativePath)
    {
        var lower = relativePath.Replace('\\', '/').ToLowerInvariant();
        var leaf = Path.GetFileName(lower);
        return leaf == ".env" || leaf.StartsWith(".env.", StringComparison.Ordinal) ||
               leaf is "secrets.json" or "credentials.json" ||
               lower.Contains("/credentials/", StringComparison.Ordinal) ||
               lower.Contains("/secrets/", StringComparison.Ordinal) ||
               leaf.EndsWith(".pfx", StringComparison.Ordinal) ||
               leaf.EndsWith(".p12", StringComparison.Ordinal) ||
               leaf.EndsWith(".pem", StringComparison.Ordinal) ||
               leaf.EndsWith(".key", StringComparison.Ordinal) ||
               leaf.StartsWith("id_rsa", StringComparison.Ordinal) ||
               leaf.StartsWith("id_ed25519", StringComparison.Ordinal);
    }

    private static string BoundPreview(string line)
    {
        var sanitized = line.Replace('\t', ' ').TrimEnd();
        return sanitized.Length <= MaxSearchPreviewChars ? sanitized : sanitized[..MaxSearchPreviewChars] + "…";
    }

    private static void ValidateSha256(string value, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length != 64 || value.Any(c => !Uri.IsHexDigit(c)))
            throw new ArgumentException("Expected SHA-256 must be exactly 64 hexadecimal characters.", parameterName);
    }

    private static string GetFileSha256(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void EnsureRepositoryRoot()
    {
        if (!Directory.Exists(RepositoryRoot))
            throw new DirectoryNotFoundException($"Fixed ERP V2 repository does not exist: {RepositoryRoot}");
        if ((File.GetAttributes(RepositoryRoot) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Fixed ERP V2 repository root may not be a reparse point.");
        if (!File.Exists(GitExe) || (File.GetAttributes(GitExe) & FileAttributes.ReparsePoint) != 0)
            throw new FileNotFoundException("Fixed git.exe is missing or unsafe.", GitExe);
    }

    private static async Task<GitResult> RunGitAsync(IReadOnlyList<string> arguments, int timeoutSeconds, bool allowNonZero = false)
    {
        EnsureRepositoryRoot();
        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = GitExe,
            WorkingDirectory = RepositoryRoot,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        psi.Environment["GIT_TERMINAL_PROMPT"] = "0";
        psi.Environment["GIT_PAGER"] = "cat";
        psi.ArgumentList.Add("--no-pager");
        psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("core.hooksPath=NUL");
        psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("core.fsmonitor=false");
        psi.ArgumentList.Add("-c"); psi.ArgumentList.Add("submodule.recurse=false");
        psi.ArgumentList.Add("-c"); psi.ArgumentList.Add($"safe.directory={RepositoryRoot}");
        psi.ArgumentList.Add("-C"); psi.ArgumentList.Add(RepositoryRoot);
        foreach (var argument in arguments) psi.ArgumentList.Add(argument);

        using var process = System.Diagnostics.Process.Start(psi) ?? throw new InvalidOperationException("git.exe failed to start.");
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
        var result = new GitResult(process.ExitCode, stdout, stderr);
        if (!allowNonZero && result.ExitCode != 0)
            throw new InvalidOperationException($"git.exe exited with code {result.ExitCode}.");
        return result;
    }

    private static string RequireParameter(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidDataException($"{key} parameter is required.");

    private static void CleanupExpiredPayloads()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var item in PendingPatchPayloads)
            if (item.Value.ExpiresUtc <= now)
                PendingPatchPayloads.TryRemove(item.Key, out _);
    }

    private static string HashText(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    private sealed record GitResult(int ExitCode, string StdOut, string StdErr);
    private sealed record TextFileSnapshot(string Text, bool HasBom, string NewlineStyle, int ByteLength, string Sha256);
    private sealed record PendingPatchPayload(
        string PlanId,
        string RelativePath,
        ErpV2NormalizedTextReplacement[] Replacements,
        string PayloadSha256,
        string OutputSha256,
        DateTimeOffset ExpiresUtc);
}

public sealed record ErpV2TextReplacement(string From, string To, int ExpectedMatchCount);
public sealed record ErpV2NormalizedTextReplacement(string From, string To, int ExpectedMatchCount);
public sealed record ErpV2RepositoryTextSearchMatch(string Path, int LineNumber, string Preview);
public sealed record ErpV2RepositoryTextSearchResult(
    string RepositoryRoot,
    string Mode,
    string? Glob,
    bool CaseSensitive,
    int MaxResults,
    int ScannedFileCount,
    long ScannedBytes,
    int SkippedOversizedFileCount,
    int SkippedInvalidUtf8OrBinaryCount,
    int SkippedSensitiveFileCount,
    bool ResultLimitReached,
    bool ScanBudgetReached,
    IReadOnlyList<ErpV2RepositoryTextSearchMatch> Matches,
    DateTimeOffset CheckedUtc);
public sealed record ErpV2FileTextPatchExecutionResult(
    string PlanId,
    string Path,
    string InputSha256,
    string OutputSha256,
    int ReplacementCount,
    int OutputBytes,
    bool Patched,
    bool RolledBack,
    DateTimeOffset ExecutedUtc);
