using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace YowThi.RuntimeDeploymentSigner;

internal static class Program
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string DeploymentRoot = DevRoot + @"\.runtime-supervisor-deployment";
    private const string SigningIntentRoot = DeploymentRoot + @"\signing-intents";
    private const string ApprovalRoot = DeploymentRoot + @"\approvals";
    private const string RequestRoot = DeploymentRoot + @"\requests";
    private const string CompletedRoot = DeploymentRoot + @"\signer-completed";
    private const string FailedRoot = DeploymentRoot + @"\signer-failed";
    private const string ExecutorExe = @"C:\ProgramData\YowThi\RuntimeDeployment\YowThi.RuntimeDeploymentExecutor.exe";
    private const string ExecutorDll = @"C:\ProgramData\YowThi\RuntimeDeployment\YowThi.RuntimeDeploymentExecutor.dll";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    public static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows() || args.Length != 1) return 90;
        try
        {
            Execute(args[0]);
            return 0;
        }
        catch
        {
            return 1;
        }
    }

    private static void Execute(string intentPath)
    {
        ValidateFixedRoots();
        var fullIntentPath = Path.GetFullPath(intentPath);
        RequireDirectJsonChild(fullIntentPath, SigningIntentRoot, "signing intent");
        RejectReparse(fullIntentPath);

        var intentId = Path.GetFileNameWithoutExtension(fullIntentPath);
        ValidateGuidN(intentId, "signingIntentId");
        EnsureNoTerminal(intentId);

        var intentBytes = File.ReadAllBytes(fullIntentPath);
        var intent = JsonSerializer.Deserialize<SigningIntent>(intentBytes, JsonOptions)
            ?? throw new InvalidDataException("Invalid runtime deployment signing intent JSON.");
        ValidateIntent(intent, intentId);

        var requestPath = Path.Combine(RequestRoot, intent.RequestId + ".json");
        RequireDirectJsonChild(requestPath, RequestRoot, "deployment request");
        RejectReparse(requestPath);
        var requestBytes = File.ReadAllBytes(requestPath);
        if (!EqualsSha(HashBytes(requestBytes), intent.RequestSha256))
            throw new InvalidOperationException("Signing intent request SHA-256 does not match the immutable P27 request.");

        var request = JsonSerializer.Deserialize<DeploymentRequest>(requestBytes, JsonOptions)
            ?? throw new InvalidDataException("Invalid P27 deployment request JSON.");
        ValidateRequest(request, intent);
        ValidateExecutor(intent.ExecutorSha256, intent.ExecutorDllSha256);

        var unsigned = new ApprovalEnvelope(
            1,
            intent.ApprovalId,
            intent.RequestId,
            intent.RequestSha256,
            intent.ExecutorSha256,
            intent.ExecutorDllSha256,
            SigningKeyGate.SignerKeyId,
            intent.IssuedUtc,
            intent.ExpiresUtc,
            intent.Nonce,
            string.Empty);

        using var signer = SigningKeyGate.OpenValidatedSigner();
        var signature = signer.SignData(BuildCanonicalPayload(unsigned), HashAlgorithmName.SHA256);
        var approval = unsigned with { SignatureBase64 = Convert.ToBase64String(signature) };

        var approvalPath = Path.Combine(ApprovalRoot, approval.ApprovalId + ".json");
        if (File.Exists(approvalPath) || Directory.Exists(approvalPath))
            throw new IOException("Runtime deployment approval already exists.");

        try
        {
            WriteCreateNewJson(approvalPath, approval);
            WriteTerminal(CompletedRoot, intent.SigningIntentId, new
            {
                schemaVersion = 1,
                signingIntentId = intent.SigningIntentId,
                approvalId = approval.ApprovalId,
                requestId = approval.RequestId,
                requestSha256 = approval.RequestSha256,
                executorSha256 = approval.ExecutorSha256,
                executorDllSha256 = approval.ExecutorDllSha256,
                signerKeyId = approval.SignerKeyId,
                signerSpkiSha256 = SigningKeyGate.ExpectedSignerSpkiSha256,
                status = "completed",
                completedUtc = DateTimeOffset.UtcNow
            });
            MoveIntent(fullIntentPath, CompletedRoot, intent.SigningIntentId);
        }
        catch (Exception ex)
        {
            TryWriteFailure(intent, ex);
            MoveIntent(fullIntentPath, FailedRoot, intent.SigningIntentId);
            throw;
        }
    }

    private static void ValidateIntent(SigningIntent intent, string expectedIntentId)
    {
        if (intent.SchemaVersion != 1 ||
            !string.Equals(intent.SigningIntentId, expectedIntentId, StringComparison.Ordinal) ||
            !string.Equals(intent.Action, "runtime-deploy", StringComparison.Ordinal))
            throw new InvalidDataException("Runtime deployment signing intent identity or action is invalid.");

        ValidateGuidN(intent.SigningIntentId, "signingIntentId");
        ValidateGuidN(intent.ApprovalId, "approvalId");
        ValidateGuidN(intent.RequestId, "requestId");
        ValidateGuidN(intent.Nonce, "nonce");
        RequireSha256(intent.RequestSha256, "requestSha256");
        RequireSha256(intent.ExecutorSha256, "executorSha256");
        RequireSha256(intent.ExecutorDllSha256, "executorDllSha256");

        if (intent.IssuedUtc > DateTimeOffset.UtcNow.AddMinutes(1))
            throw new InvalidDataException("Signing intent issuedUtc is in the future.");
        if (intent.ExpiresUtc <= DateTimeOffset.UtcNow)
            throw new UnauthorizedAccessException("Signing intent expired.");
        if (intent.ExpiresUtc - intent.IssuedUtc > TimeSpan.FromMinutes(5))
            throw new UnauthorizedAccessException("Signing intent lifetime exceeds five minutes.");
    }

    private static void ValidateRequest(DeploymentRequest request, SigningIntent intent)
    {
        if (request.SchemaVersion != 1 ||
            !string.Equals(request.RequestId, intent.RequestId, StringComparison.Ordinal) ||
            request.ProcessAuthorization ||
            !request.RequiresDedicatedSupervisorExecutor)
            throw new UnauthorizedAccessException("P27 deployment request scope is invalid for signing.");

        if (request.ExpiresUtc <= DateTimeOffset.UtcNow || intent.ExpiresUtc > request.ExpiresUtc)
            throw new UnauthorizedAccessException("Signing intent is expired or outlives its bound P27 request.");
    }

    private static void ValidateExecutor(string expectedExeSha, string expectedDllSha)
    {
        ValidatePinnedFile(ExecutorExe, expectedExeSha, "executor executable");
        ValidatePinnedFile(ExecutorDll, expectedDllSha, "executor managed DLL");
    }

    private static void ValidatePinnedFile(string path, string expectedSha, string label)
    {
        RequireSha256(expectedSha, label + "Sha256");
        var full = Path.GetFullPath(path);
        if (!File.Exists(full))
            throw new FileNotFoundException("Fixed runtime deployment " + label + " is not installed.", full);
        RejectReparse(full);
        if (!EqualsSha(HashFile(full), expectedSha))
            throw new InvalidOperationException("Fixed runtime deployment " + label + " SHA-256 mismatch.");
    }

    internal static byte[] BuildCanonicalPayload(ApprovalEnvelope approval)
    {
        var canonical = string.Join("\n",
            "schemaVersion=" + approval.SchemaVersion,
            "approvalId=" + approval.ApprovalId,
            "requestId=" + approval.RequestId,
            "requestSha256=" + approval.RequestSha256.ToUpperInvariant(),
            "executorSha256=" + approval.ExecutorSha256.ToUpperInvariant(),
            "executorDllSha256=" + approval.ExecutorDllSha256.ToUpperInvariant(),
            "signerKeyId=" + approval.SignerKeyId,
            "issuedUtc=" + approval.IssuedUtc.ToUniversalTime().ToString("O"),
            "expiresUtc=" + approval.ExpiresUtc.ToUniversalTime().ToString("O"),
            "nonce=" + approval.Nonce,
            "action=runtime-deploy") + "\n";
        return Encoding.UTF8.GetBytes(canonical);
    }

    private static void ValidateFixedRoots()
    {
        ValidateExistingDirectory(DevRoot, DevRoot);
        ValidateExistingDirectory(DeploymentRoot, DevRoot);
        ValidateExistingDirectory(RequestRoot, DeploymentRoot);
        Directory.CreateDirectory(SigningIntentRoot);
        Directory.CreateDirectory(ApprovalRoot);
        Directory.CreateDirectory(CompletedRoot);
        Directory.CreateDirectory(FailedRoot);
        ValidateExistingDirectory(SigningIntentRoot, DeploymentRoot);
        ValidateExistingDirectory(ApprovalRoot, DeploymentRoot);
        ValidateExistingDirectory(CompletedRoot, DeploymentRoot);
        ValidateExistingDirectory(FailedRoot, DeploymentRoot);
    }

    private static void ValidateExistingDirectory(string path, string boundary)
    {
        var full = Path.GetFullPath(path).TrimEnd('\\', '/');
        var root = Path.GetFullPath(boundary).TrimEnd('\\', '/');
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException("Required fixed directory does not exist: " + full);
        if (!string.Equals(full, root, StringComparison.OrdinalIgnoreCase) &&
            !full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Fixed path escaped its boundary: " + full);
        RejectReparse(full);
    }

    private static void RequireDirectJsonChild(string path, string root, string label)
    {
        var full = Path.GetFullPath(path);
        var parent = Path.GetDirectoryName(full)?.TrimEnd('\\', '/');
        var expected = Path.GetFullPath(root).TrimEnd('\\', '/');
        if (!string.Equals(parent, expected, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetExtension(full), ".json", StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(full))
            throw new UnauthorizedAccessException(label + " must be one existing direct JSON file under its fixed root.");
    }

    private static void EnsureNoTerminal(string intentId)
    {
        if (File.Exists(Path.Combine(CompletedRoot, intentId + ".result.json")) ||
            File.Exists(Path.Combine(FailedRoot, intentId + ".result.json")))
            throw new InvalidOperationException("Signing intent has already reached a terminal result.");
    }

    private static void WriteCreateNewJson(string path, object value)
    {
        var bytes = new UTF8Encoding(false).GetBytes(JsonSerializer.Serialize(value, JsonOptions));
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        stream.Write(bytes, 0, bytes.Length);
        stream.Flush(flushToDisk: true);
    }

    private static void WriteTerminal(string root, string intentId, object value)
        => WriteCreateNewJson(Path.Combine(root, intentId + ".result.json"), value);

    private static void TryWriteFailure(SigningIntent intent, Exception error)
    {
        try
        {
            WriteTerminal(FailedRoot, intent.SigningIntentId, new
            {
                schemaVersion = 1,
                signingIntentId = intent.SigningIntentId,
                approvalId = intent.ApprovalId,
                requestId = intent.RequestId,
                status = "failed",
                error = error.GetType().Name + ": " + error.Message,
                failedUtc = DateTimeOffset.UtcNow
            });
        }
        catch { }
    }

    private static void MoveIntent(string source, string terminalRoot, string intentId)
    {
        try
        {
            var destination = Path.Combine(terminalRoot, intentId + ".intent.json");
            if (!File.Exists(destination) && File.Exists(source)) File.Move(source, destination, false);
        }
        catch { }
    }

    private static void ValidateGuidN(string value, string name)
    {
        if (!Guid.TryParseExact(value, "N", out _))
            throw new InvalidDataException(name + " must be a GUID N identifier.");
    }

    private static void RequireSha256(string value, string name)
    {
        if (value.Length != 64 || value.Any(ch => !Uri.IsHexDigit(ch)))
            throw new InvalidDataException(name + " must be a 64-character SHA-256 hex digest.");
    }

    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Reparse point rejected: " + path);
    }

    private static string HashFile(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string HashBytes(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));
    private static bool EqualsSha(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    internal sealed record SigningIntent(
        int SchemaVersion,
        string SigningIntentId,
        string ApprovalId,
        string RequestId,
        string RequestSha256,
        string ExecutorSha256,
        string ExecutorDllSha256,
        DateTimeOffset IssuedUtc,
        DateTimeOffset ExpiresUtc,
        string Nonce,
        string Action);

    internal sealed record ApprovalEnvelope(
        int SchemaVersion,
        string ApprovalId,
        string RequestId,
        string RequestSha256,
        string ExecutorSha256,
        string ExecutorDllSha256,
        string SignerKeyId,
        DateTimeOffset IssuedUtc,
        DateTimeOffset ExpiresUtc,
        string Nonce,
        string SignatureBase64);

    private sealed record DeploymentRequest(
        int SchemaVersion,
        string RequestPlanId,
        string RequestId,
        string ReleaseName,
        string CurrentRuntimeDll,
        string CurrentRuntimeSha256,
        int CurrentProcessId,
        string TargetRuntimeDll,
        string TargetRuntimeSha256,
        string ListenUrl,
        string HealthUrl,
        string SupervisorExe,
        string SupervisorSha256,
        bool ProcessAuthorization,
        bool RequiresDedicatedSupervisorExecutor,
        DateTimeOffset CreatedUtc,
        DateTimeOffset ExpiresUtc);
}
