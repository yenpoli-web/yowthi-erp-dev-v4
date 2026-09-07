using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace YowThi.RuntimeDeploymentAuthorizer;

internal static class Program
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string DeploymentRoot = DevRoot + @"\.runtime-supervisor-deployment";
    private const string ApprovalRoot = DeploymentRoot + @"\approvals";
    private const string RequestRoot = DeploymentRoot + @"\requests";
    private const string AuthorizedRoot = DeploymentRoot + @"\authorized";
    private const string AuthorizerCompletedRoot = DeploymentRoot + @"\authorizer-completed";
    private const string AuthorizerFailedRoot = DeploymentRoot + @"\authorizer-failed";
    private const string ExecutorCompletedRoot = DeploymentRoot + @"\completed";
    private const string ExecutorFailedRoot = DeploymentRoot + @"\failed";
    private const string ReleaseRoot = DevRoot + @"\acceptance\agent-lifecycle\releases";
    private const string ActiveStatePath = DevRoot + @"\.agent3-handoff\active-runtime.json";
    private const string SupervisorExe = DevRoot + @"\runtime-supervisor\current\YowThi.RuntimeSupervisor.exe";
    private const string ExecutorExe = @"C:\ProgramData\YowThi\RuntimeDeployment\YowThi.RuntimeDeploymentExecutor.exe";
    private const string RuntimeFileName = "YowThi.DevelopmentAgent3.dll";

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

    private static void Execute(string approvalPath)
    {
        ValidateFixedRoots();
        var fullApprovalPath = Path.GetFullPath(approvalPath);
        RequireDirectJsonChild(fullApprovalPath, ApprovalRoot, "approval");
        RejectReparse(fullApprovalPath);

        var approvalId = Path.GetFileNameWithoutExtension(fullApprovalPath);
        ValidateGuidN(approvalId, "approvalId");
        EnsureNoAuthorizerTerminal(approvalId);

        var approvalBytes = File.ReadAllBytes(fullApprovalPath);
        var approval = JsonSerializer.Deserialize<ApprovalEnvelope>(approvalBytes, JsonOptions)
            ?? throw new InvalidDataException("Invalid runtime deployment approval JSON.");
        ValidateApprovalEnvelope(approval, approvalId);
        if (!ApprovalSignatureGate.Verify(approval))
            throw new UnauthorizedAccessException("Runtime deployment approval signature is invalid.");

        var requestPath = Path.Combine(RequestRoot, approval.RequestId + ".json");
        RequireDirectJsonChild(requestPath, RequestRoot, "request");
        RejectReparse(requestPath);
        var requestBytes = File.ReadAllBytes(requestPath);
        if (!EqualsSha(HashBytes(requestBytes), approval.RequestSha256))
            throw new InvalidOperationException("Approval request SHA-256 does not match the immutable deployment request.");

        var request = JsonSerializer.Deserialize<DeploymentRequest>(requestBytes, JsonOptions)
            ?? throw new InvalidDataException("Invalid runtime deployment request JSON.");
        ValidateRequest(request, approval);

        var active = ReadActiveState();
        ValidateActiveState(active, request);
        ValidateRuntimeFile(request.CurrentRuntimeDll, request.CurrentRuntimeSha256, null);
        ValidateRuntimeFile(request.TargetRuntimeDll, request.TargetRuntimeSha256, request.ReleaseName);
        ValidateFixedExecutable(SupervisorExe, request.SupervisorSha256, "Runtime Supervisor");
        ValidateFixedExecutable(ExecutorExe, approval.ExecutorSha256, "runtime deployment executor");

        var now = DateTimeOffset.UtcNow;
        var expires = Min(approval.ExpiresUtc, request.ExpiresUtc, now.AddMinutes(2));
        if (expires <= now) throw new UnauthorizedAccessException("Runtime deployment authorization would already be expired.");

        var authorization = new DeploymentAuthorization(
            1,
            approval.ApprovalId,
            approval.RequestId,
            approval.RequestSha256,
            request.ReleaseName,
            Path.GetFullPath(request.CurrentRuntimeDll),
            request.CurrentRuntimeSha256,
            request.CurrentProcessId,
            Path.GetFullPath(request.TargetRuntimeDll),
            request.TargetRuntimeSha256,
            NormalizeListenUrl(request.ListenUrl),
            NormalizeHealthUrl(request.HealthUrl),
            Path.GetFullPath(request.SupervisorExe),
            request.SupervisorSha256,
            approval.ExecutorSha256,
            true,
            now,
            expires);

        var authorizationPath = Path.Combine(AuthorizedRoot, approval.ApprovalId + ".json");
        if (File.Exists(authorizationPath) || Directory.Exists(authorizationPath))
            throw new IOException("Runtime deployment authorization already exists.");

        WriteCreateNewJson(authorizationPath, authorization);
        var executorStarted = false;
        try
        {
            using var child = StartFixedExecutor(authorizationPath, approval.ExecutorSha256);
            executorStarted = true;
            if (!child.WaitForExit((int)TimeSpan.FromMinutes(5).TotalMilliseconds))
                throw new TimeoutException("Runtime deployment executor did not reach a terminal state within five minutes.");

            var completedResult = Path.Combine(ExecutorCompletedRoot, approval.ApprovalId + ".result.json");
            var failedResult = Path.Combine(ExecutorFailedRoot, approval.ApprovalId + ".result.json");
            var completed = File.Exists(completedResult);
            var failed = File.Exists(failedResult);
            if (completed == failed)
                throw new InvalidOperationException("Runtime deployment executor terminal result is missing or ambiguous.");
            if (child.ExitCode == 0 && !completed)
                throw new InvalidOperationException("Runtime deployment executor exited successfully without a completion result.");
            if (child.ExitCode != 0 && !failed)
                throw new InvalidOperationException("Runtime deployment executor failed without a failed terminal result.");

            WriteAuthorizerTerminal(AuthorizerCompletedRoot, approval.ApprovalId, new
            {
                schemaVersion = 1,
                approvalId = approval.ApprovalId,
                requestId = approval.RequestId,
                status = completed ? "completed" : "executor-failed",
                executorExitCode = child.ExitCode,
                requestSha256 = approval.RequestSha256,
                executorSha256 = approval.ExecutorSha256,
                completedUtc = DateTimeOffset.UtcNow
            });
            MoveApproval(fullApprovalPath, AuthorizerCompletedRoot, approval.ApprovalId);
        }
        catch (Exception ex)
        {
            if (!executorStarted && File.Exists(authorizationPath))
            {
                var failedAuth = Path.Combine(AuthorizerFailedRoot, approval.ApprovalId + ".authorization.json");
                if (!File.Exists(failedAuth)) File.Move(authorizationPath, failedAuth, false);
            }

            TryWriteAuthorizerFailure(approval, ex);
            MoveApproval(fullApprovalPath, AuthorizerFailedRoot, approval.ApprovalId);
            throw;
        }
    }

    private static Process StartFixedExecutor(string authorizationPath, string expectedSha)
    {
        ValidateFixedExecutable(ExecutorExe, expectedSha, "runtime deployment executor");
        var start = new ProcessStartInfo
        {
            FileName = ExecutorExe,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(ExecutorExe)!
        };
        start.ArgumentList.Add(authorizationPath);
        return Process.Start(start) ?? throw new InvalidOperationException("Unable to start fixed runtime deployment executor.");
    }

    private static void ValidateApprovalEnvelope(ApprovalEnvelope approval, string expectedApprovalId)
    {
        if (approval.SchemaVersion != 1 || !string.Equals(approval.ApprovalId, expectedApprovalId, StringComparison.Ordinal))
            throw new InvalidDataException("Runtime deployment approval identity is invalid.");
        ValidateGuidN(approval.ApprovalId, "approvalId");
        ValidateGuidN(approval.RequestId, "requestId");
        ValidateGuidN(approval.Nonce, "nonce");
        RequireSha256(approval.RequestSha256, "requestSha256");
        RequireSha256(approval.ExecutorSha256, "executorSha256");
        if (!string.Equals(approval.SignerKeyId, ApprovalSignatureGate.SignerKeyId, StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Runtime deployment approval signer key ID is not allowed.");
        if (approval.IssuedUtc > DateTimeOffset.UtcNow.AddMinutes(1))
            throw new InvalidDataException("Runtime deployment approval issuedUtc is in the future.");
        if (approval.ExpiresUtc <= DateTimeOffset.UtcNow)
            throw new UnauthorizedAccessException("Runtime deployment approval expired.");
        if (approval.ExpiresUtc - approval.IssuedUtc > TimeSpan.FromMinutes(5))
            throw new UnauthorizedAccessException("Runtime deployment approval lifetime exceeds five minutes.");
    }

    private static void ValidateRequest(DeploymentRequest request, ApprovalEnvelope approval)
    {
        if (request.SchemaVersion != 1 ||
            !string.Equals(request.RequestId, approval.RequestId, StringComparison.Ordinal) ||
            request.ProcessAuthorization ||
            !request.RequiresDedicatedSupervisorExecutor)
            throw new UnauthorizedAccessException("P27 deployment request scope is invalid for local authorizer use.");
        if (request.ExpiresUtc <= DateTimeOffset.UtcNow || approval.ExpiresUtc > request.ExpiresUtc)
            throw new UnauthorizedAccessException("Approval is expired or outlives its bound deployment request.");
        if (request.CurrentProcessId <= 0) throw new InvalidDataException("Current runtime PID is invalid.");
        RequireSha256(request.CurrentRuntimeSha256, "currentRuntimeSha256");
        RequireSha256(request.TargetRuntimeSha256, "targetRuntimeSha256");
        RequireSha256(request.SupervisorSha256, "supervisorSha256");
        _ = NormalizeListenUrl(request.ListenUrl);
        _ = NormalizeHealthUrl(request.HealthUrl);
        RequireSameEndpoint(request.ListenUrl, request.HealthUrl);
        if (!string.Equals(Path.GetFullPath(request.SupervisorExe), Path.GetFullPath(SupervisorExe), StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Deployment request does not bind the fixed Runtime Supervisor executable.");
    }

    private static ActiveState ReadActiveState()
    {
        if (!File.Exists(ActiveStatePath)) throw new FileNotFoundException("Active runtime state does not exist.", ActiveStatePath);
        RejectReparse(ActiveStatePath);
        var state = JsonSerializer.Deserialize<ActiveState>(File.ReadAllBytes(ActiveStatePath), JsonOptions)
            ?? throw new InvalidDataException("Active runtime state is invalid.");
        if (state.SchemaVersion != 2) throw new InvalidDataException("Unsupported active runtime state schemaVersion.");
        return state;
    }

    private static void ValidateActiveState(ActiveState active, DeploymentRequest request)
    {
        if (!string.Equals(Path.GetFullPath(active.Current.RuntimeDll), Path.GetFullPath(request.CurrentRuntimeDll), StringComparison.OrdinalIgnoreCase) ||
            !EqualsSha(active.Current.RuntimeSha256, request.CurrentRuntimeSha256) ||
            active.Current.ProcessId != request.CurrentProcessId ||
            !string.Equals(NormalizeListenUrl(active.Current.ListenUrl), NormalizeListenUrl(request.ListenUrl), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(NormalizeHealthUrl(active.Current.HealthUrl), NormalizeHealthUrl(request.HealthUrl), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Active runtime identity changed after P27 request creation.");
    }

    private static void ValidateRuntimeFile(string runtimeDll, string expectedSha, string? releaseName)
    {
        RequireSha256(expectedSha, "runtimeSha256");
        var full = Path.GetFullPath(runtimeDll);
        var releaseRoot = Path.GetFullPath(ReleaseRoot).TrimEnd('\\', '/');
        var package = Path.GetDirectoryName(full)?.TrimEnd('\\', '/') ?? throw new InvalidDataException("Runtime package directory is missing.");
        var parent = Path.GetDirectoryName(package)?.TrimEnd('\\', '/');
        if (!string.Equals(parent, releaseRoot, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Runtime must be one direct release under the fixed lifecycle release root.");
        if (releaseName is not null && !string.Equals(Path.GetFileName(package), releaseName, StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Target release name does not match runtime package directory.");
        if (!string.Equals(Path.GetFileName(full), RuntimeFileName, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Unexpected runtime DLL name.");
        if (!File.Exists(full)) throw new FileNotFoundException("Runtime DLL does not exist.", full);
        RejectReparse(releaseRoot);
        RejectReparse(package);
        RejectReparse(full);
        if (!EqualsSha(HashFile(full), expectedSha)) throw new InvalidOperationException("Runtime DLL SHA-256 mismatch.");
    }

    private static void ValidateFixedExecutable(string path, string expectedSha, string label)
    {
        RequireSha256(expectedSha, label + "Sha256");
        var full = Path.GetFullPath(path);
        if (!File.Exists(full)) throw new FileNotFoundException(label + " executable does not exist.", full);
        RejectReparse(full);
        if (!EqualsSha(HashFile(full), expectedSha)) throw new InvalidOperationException(label + " executable SHA-256 mismatch.");
    }

    private static void ValidateFixedRoots()
    {
        ValidateExistingDirectory(DevRoot, DevRoot);
        ValidateExistingDirectory(ReleaseRoot, DevRoot);
        ValidateExistingDirectory(DeploymentRoot, DevRoot);
        ValidateExistingDirectory(RequestRoot, DeploymentRoot);
        Directory.CreateDirectory(ApprovalRoot);
        Directory.CreateDirectory(AuthorizedRoot);
        Directory.CreateDirectory(AuthorizerCompletedRoot);
        Directory.CreateDirectory(AuthorizerFailedRoot);
        Directory.CreateDirectory(ExecutorCompletedRoot);
        Directory.CreateDirectory(ExecutorFailedRoot);
        ValidateExistingDirectory(ApprovalRoot, DeploymentRoot);
        ValidateExistingDirectory(AuthorizedRoot, DeploymentRoot);
        ValidateExistingDirectory(AuthorizerCompletedRoot, DeploymentRoot);
        ValidateExistingDirectory(AuthorizerFailedRoot, DeploymentRoot);
        ValidateExistingDirectory(ExecutorCompletedRoot, DeploymentRoot);
        ValidateExistingDirectory(ExecutorFailedRoot, DeploymentRoot);
    }

    private static void ValidateExistingDirectory(string path, string boundary)
    {
        var full = Path.GetFullPath(path).TrimEnd('\\', '/');
        var root = Path.GetFullPath(boundary).TrimEnd('\\', '/');
        if (!Directory.Exists(full)) throw new DirectoryNotFoundException("Required fixed directory does not exist: " + full);
        if (!string.Equals(full, root, StringComparison.OrdinalIgnoreCase) && !full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Fixed path escaped its boundary: " + full);
        RejectReparse(full);
    }

    private static string NormalizeListenUrl(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttp ||
            !IPAddress.TryParse(uri.Host, out var address) || !IPAddress.IsLoopback(address) || uri.Port <= 0 ||
            (uri.AbsolutePath != "/" && !string.IsNullOrEmpty(uri.AbsolutePath.Trim('/'))))
            throw new InvalidDataException("listenUrl must be an absolute loopback HTTP endpoint using an IP literal.");
        return uri.GetLeftPart(UriPartial.Authority).TrimEnd('/');
    }

    private static string NormalizeHealthUrl(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttp ||
            !IPAddress.TryParse(uri.Host, out var address) || !IPAddress.IsLoopback(address) || uri.Port <= 0 ||
            !string.Equals(uri.AbsolutePath.TrimEnd('/'), "/health", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("healthUrl must be the exact loopback /health endpoint using an IP literal.");
        return uri.GetLeftPart(UriPartial.Authority).TrimEnd('/') + "/health";
    }

    private static void RequireSameEndpoint(string listenUrl, string healthUrl)
    {
        var listen = new Uri(NormalizeListenUrl(listenUrl));
        var health = new Uri(NormalizeHealthUrl(healthUrl));
        if (!string.Equals(listen.Host, health.Host, StringComparison.OrdinalIgnoreCase) || listen.Port != health.Port)
            throw new InvalidDataException("listenUrl and healthUrl do not identify the same loopback endpoint.");
    }

    private static void RequireDirectJsonChild(string path, string root, string label)
    {
        var full = Path.GetFullPath(path);
        var parent = Path.GetDirectoryName(full)?.TrimEnd('\\', '/');
        var expected = Path.GetFullPath(root).TrimEnd('\\', '/');
        if (!string.Equals(parent, expected, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetExtension(full), ".json", StringComparison.OrdinalIgnoreCase) || !File.Exists(full))
            throw new UnauthorizedAccessException(label + " must be one existing direct JSON file under its fixed root.");
    }

    private static void EnsureNoAuthorizerTerminal(string approvalId)
    {
        if (File.Exists(Path.Combine(AuthorizerCompletedRoot, approvalId + ".result.json")) ||
            File.Exists(Path.Combine(AuthorizerFailedRoot, approvalId + ".result.json")))
            throw new InvalidOperationException("Runtime deployment approval has already reached an authorizer terminal result.");
    }

    private static void WriteCreateNewJson(string path, object value)
    {
        var bytes = new UTF8Encoding(false).GetBytes(JsonSerializer.Serialize(value, JsonOptions));
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        stream.Write(bytes, 0, bytes.Length);
        stream.Flush(flushToDisk: true);
    }

    private static void WriteAuthorizerTerminal(string root, string approvalId, object value)
        => WriteCreateNewJson(Path.Combine(root, approvalId + ".result.json"), value);

    private static void TryWriteAuthorizerFailure(ApprovalEnvelope approval, Exception error)
    {
        try
        {
            WriteAuthorizerTerminal(AuthorizerFailedRoot, approval.ApprovalId, new
            {
                schemaVersion = 1,
                approvalId = approval.ApprovalId,
                requestId = approval.RequestId,
                status = "failed",
                error = error.GetType().Name + ": " + error.Message,
                failedUtc = DateTimeOffset.UtcNow
            });
        }
        catch { }
    }

    private static void MoveApproval(string source, string terminalRoot, string approvalId)
    {
        try
        {
            var destination = Path.Combine(terminalRoot, approvalId + ".approval.json");
            if (!File.Exists(destination) && File.Exists(source)) File.Move(source, destination, false);
        }
        catch { }
    }

    private static DateTimeOffset Min(DateTimeOffset a, DateTimeOffset b, DateTimeOffset c)
        => a <= b && a <= c ? a : b <= c ? b : c;

    private static void ValidateGuidN(string value, string name)
    {
        if (!Guid.TryParseExact(value, "N", out _)) throw new InvalidDataException(name + " must be a GUID N identifier.");
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

    private sealed record DeploymentAuthorization(
        int SchemaVersion,
        string AuthorizationId,
        string RequestId,
        string RequestSha256,
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
        string ExecutorSha256,
        bool ProcessAuthorization,
        DateTimeOffset AuthorizedUtc,
        DateTimeOffset ExpiresUtc);

    private sealed record RuntimeSlot(
        string? PlanId,
        string RuntimeDll,
        string RuntimeSha256,
        string ListenUrl,
        string HealthUrl,
        int ProcessId);

    private sealed record ActiveState(
        int SchemaVersion,
        RuntimeSlot Current,
        RuntimeSlot? Previous,
        DateTimeOffset UpdatedUtc);
}
