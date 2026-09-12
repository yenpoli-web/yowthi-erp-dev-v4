using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace YowThi.RuntimeDeploymentExecutor;

internal static class Program
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string DeploymentRoot = DevRoot + @"\.runtime-supervisor-deployment";
    private const string RequestRoot = DeploymentRoot + @"\requests";
    private const string AuthorizedRoot = DeploymentRoot + @"\authorized";
    private const string CompletedRoot = DeploymentRoot + @"\completed";
    private const string FailedRoot = DeploymentRoot + @"\failed";
    private const string ReleaseRoot = DevRoot + @"\acceptance\agent-lifecycle\releases";
    private const string ActiveStatePath = DevRoot + @"\.agent3-handoff\active-runtime.json";
    private const string SupervisorExe = DevRoot + @"\runtime-supervisor\current\YowThi.RuntimeSupervisor.exe";
    private const string ServiceName = "YowThiV4RuntimeSupervisor";
    private const string RuntimeFileName = "YowThi.DevelopmentAgent3.dll";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(2) };

    public static async Task<int> Main(string[] args)
    {
        if (!OperatingSystem.IsWindows() || args.Length != 1)
            return 90;

        try
        {
            await ExecuteAsync(args[0]);
            return 0;
        }
        catch
        {
            return 1;
        }
        finally
        {
            Http.Dispose();
        }
    }

    private static async Task ExecuteAsync(string authorizationPath)
    {
        ValidateFixedRoots();
        var authPath = Path.GetFullPath(authorizationPath);
        RequireDirectJsonChild(authPath, AuthorizedRoot, "authorization");
        RejectReparse(authPath);

        var authorizationId = Path.GetFileNameWithoutExtension(authPath);
        ValidateGuidN(authorizationId, "authorizationId");
        EnsureNoTerminalResult(authorizationId);

        var authorizationBytes = File.ReadAllBytes(authPath);
        var authorization = JsonSerializer.Deserialize<DeploymentAuthorization>(authorizationBytes, JsonOptions)
            ?? throw new InvalidDataException("Invalid deployment authorization JSON.");
        ValidateAuthorizationEnvelope(authorization, authorizationId);

        var requestPath = Path.Combine(RequestRoot, authorization.RequestId + ".json");
        if (!File.Exists(requestPath))
            throw new FileNotFoundException("Bound deployment request does not exist.", requestPath);
        RejectReparse(requestPath);
        var requestBytes = File.ReadAllBytes(requestPath);
        var requestSha = HashBytes(requestBytes);
        if (!EqualsSha(requestSha, authorization.RequestSha256))
            throw new InvalidOperationException("Deployment request SHA-256 does not match authorization.");

        var request = JsonSerializer.Deserialize<DeploymentRequest>(requestBytes, JsonOptions)
            ?? throw new InvalidDataException("Invalid deployment request JSON.");
        ValidateRequestEnvelope(request, authorization);

        var activeBefore = ReadActiveState();
        ValidateActiveStateMatchesAuthorization(activeBefore, authorization);
        ValidateRuntimeFile(activeBefore.Current.RuntimeDll, activeBefore.Current.RuntimeSha256, null);
        ValidateRuntimeFile(authorization.TargetRuntimeDll, authorization.TargetRuntimeSha256, authorization.ReleaseName);
        ValidateSupervisorIdentity(authorization);
        ValidateExecutorIdentity(authorization);

        if (!await ProbeExactRuntimeShaAsync(authorization.HealthUrl, authorization.CurrentRuntimeSha256))
            throw new InvalidOperationException("Current runtime health SHA-256 does not match authorization immediately before deployment.");

        using var service = ServiceHandle.Open(ServiceName);
        service.RequireRunningAndBinary(SupervisorExe, authorization.SupervisorSha256);

        var serviceStopped = false;
        var stateChanged = false;
        try
        {
            service.StopAndWait(TimeSpan.FromSeconds(30));
            serviceStopped = true;
            if (!await WaitForProcessExitAsync(authorization.CurrentProcessId, TimeSpan.FromSeconds(15)))
                throw new InvalidOperationException("Current runtime process remained alive after Runtime Supervisor stopped.");

            var targetState = new ActiveState(
                2,
                new RuntimeSlot(
                    authorization.AuthorizationId,
                    Path.GetFullPath(authorization.TargetRuntimeDll),
                    authorization.TargetRuntimeSha256,
                    NormalizeListenUrl(authorization.ListenUrl),
                    NormalizeHealthUrl(authorization.HealthUrl),
                    0),
                activeBefore.Current,
                DateTimeOffset.UtcNow);

            WriteActiveState(targetState, authorization.AuthorizationId);
            stateChanged = true;

            service.StartAndWait(TimeSpan.FromSeconds(30));
            serviceStopped = false;

            if (!await WaitForExactRuntimeShaAsync(authorization.HealthUrl, authorization.TargetRuntimeSha256, TimeSpan.FromSeconds(45)))
                throw new InvalidOperationException("Target runtime failed exact SHA-256 health validation after Supervisor restart.");

            var activeAfter = await WaitForActiveRuntimeStateAsync(
                authorization.TargetRuntimeDll,
                authorization.TargetRuntimeSha256,
                TimeSpan.FromSeconds(15));
            if (activeAfter is null)
                throw new InvalidOperationException("Active runtime read-back does not prove target deployment within the bounded wait.");

            WriteTerminalResult(CompletedRoot, authorization.AuthorizationId, new
            {
                schemaVersion = 1,
                authorizationId = authorization.AuthorizationId,
                requestId = authorization.RequestId,
                status = "completed",
                currentRuntimeSha256 = authorization.CurrentRuntimeSha256,
                targetRuntimeSha256 = authorization.TargetRuntimeSha256,
                targetProcessId = activeAfter.Current.ProcessId,
                completedUtc = DateTimeOffset.UtcNow
            });
            TryMoveAuthorization(authPath, CompletedRoot, authorization.AuthorizationId);
        }
        catch (Exception deploymentError)
        {
            var rollbackSucceeded = false;
            string? rollbackError = null;
            try
            {
                if (!serviceStopped)
                {
                    service.StopAndWait(TimeSpan.FromSeconds(30));
                    serviceStopped = true;
                }

                if (stateChanged)
                    WriteActiveState(activeBefore with { UpdatedUtc = DateTimeOffset.UtcNow }, authorization.AuthorizationId + "-rollback");

                service.StartAndWait(TimeSpan.FromSeconds(30));
                serviceStopped = false;
                rollbackSucceeded = await WaitForExactRuntimeShaAsync(
                    activeBefore.Current.HealthUrl,
                    activeBefore.Current.RuntimeSha256,
                    TimeSpan.FromSeconds(45));
            }
            catch (Exception rollbackException)
            {
                rollbackError = rollbackException.GetType().Name + ": " + rollbackException.Message;
            }

            TryWriteFailureResult(authorization.AuthorizationId, authorization.RequestId, authorization.CurrentRuntimeSha256,
                authorization.TargetRuntimeSha256, deploymentError, rollbackSucceeded, rollbackError);
            TryMoveAuthorization(authPath, FailedRoot, authorization.AuthorizationId);

            if (!rollbackSucceeded)
                throw new InvalidOperationException("Deployment failed and rollback could not be proven healthy.", deploymentError);
            throw;
        }
    }

    private static void ValidateAuthorizationEnvelope(DeploymentAuthorization authorization, string expectedAuthorizationId)
    {
        if (authorization.SchemaVersion != 1)
            throw new InvalidDataException("Unsupported authorization schemaVersion.");
        if (!string.Equals(authorization.AuthorizationId, expectedAuthorizationId, StringComparison.Ordinal))
            throw new InvalidDataException("Authorization ID does not match fixed file identity.");
        ValidateGuidN(authorization.AuthorizationId, "authorizationId");
        ValidateGuidN(authorization.RequestId, "requestId");
        RequireSha256(authorization.RequestSha256, "requestSha256");
        RequireSha256(authorization.CurrentRuntimeSha256, "currentRuntimeSha256");
        RequireSha256(authorization.TargetRuntimeSha256, "targetRuntimeSha256");
        RequireSha256(authorization.SupervisorSha256, "supervisorSha256");
        RequireSha256(authorization.ExecutorSha256, "executorSha256");
        if (!authorization.ProcessAuthorization)
            throw new UnauthorizedAccessException("Authorization must explicitly carry processAuthorization=true.");
        if (authorization.AuthorizedUtc > DateTimeOffset.UtcNow.AddMinutes(1))
            throw new InvalidDataException("Authorization timestamp is in the future.");
        if (authorization.ExpiresUtc <= DateTimeOffset.UtcNow)
            throw new UnauthorizedAccessException("Deployment authorization expired.");
        if (authorization.ExpiresUtc - authorization.AuthorizedUtc > TimeSpan.FromMinutes(10))
            throw new UnauthorizedAccessException("Deployment authorization lifetime exceeds 10 minutes.");
        _ = NormalizeListenUrl(authorization.ListenUrl);
        _ = NormalizeHealthUrl(authorization.HealthUrl);
        RequireSameEndpoint(authorization.ListenUrl, authorization.HealthUrl);
    }

    private static void ValidateRequestEnvelope(DeploymentRequest request, DeploymentAuthorization authorization)
    {
        if (request.SchemaVersion != 1 ||
            !string.Equals(request.RequestId, authorization.RequestId, StringComparison.Ordinal) ||
            !string.Equals(request.ReleaseName, authorization.ReleaseName, StringComparison.Ordinal) ||
            request.ProcessAuthorization ||
            !request.RequiresDedicatedSupervisorExecutor)
            throw new UnauthorizedAccessException("Deployment request scope is invalid for dedicated executor use.");

        if (request.ExpiresUtc <= DateTimeOffset.UtcNow || authorization.ExpiresUtc > request.ExpiresUtc)
            throw new UnauthorizedAccessException("Deployment request expired or authorization outlives its bound request.");

        RequireEqualPath(request.CurrentRuntimeDll, authorization.CurrentRuntimeDll, "Current runtime DLL mismatch between request and authorization.");
        RequireEqualSha(request.CurrentRuntimeSha256, authorization.CurrentRuntimeSha256, "Current runtime SHA mismatch between request and authorization.");
        if (request.CurrentProcessId != authorization.CurrentProcessId)
            throw new InvalidOperationException("Current runtime PID mismatch between request and authorization.");
        RequireEqualPath(request.TargetRuntimeDll, authorization.TargetRuntimeDll, "Target runtime DLL mismatch between request and authorization.");
        RequireEqualSha(request.TargetRuntimeSha256, authorization.TargetRuntimeSha256, "Target runtime SHA mismatch between request and authorization.");
        RequireEqualPath(request.SupervisorExe, authorization.SupervisorExe, "Supervisor executable mismatch between request and authorization.");
        RequireEqualSha(request.SupervisorSha256, authorization.SupervisorSha256, "Supervisor SHA mismatch between request and authorization.");
        RequireEqualUrl(request.ListenUrl, authorization.ListenUrl, "Listen URL mismatch between request and authorization.");
        RequireEqualUrl(request.HealthUrl, authorization.HealthUrl, "Health URL mismatch between request and authorization.");
    }

    private static void ValidateActiveStateMatchesAuthorization(ActiveState active, DeploymentAuthorization authorization)
    {
        RequireEqualPath(active.Current.RuntimeDll, authorization.CurrentRuntimeDll, "Active runtime DLL changed after authorization.");
        RequireEqualSha(active.Current.RuntimeSha256, authorization.CurrentRuntimeSha256, "Active runtime SHA changed after authorization.");
        if (active.Current.ProcessId != authorization.CurrentProcessId)
            throw new InvalidOperationException("Active runtime PID changed after authorization.");
        RequireEqualUrl(active.Current.ListenUrl, authorization.ListenUrl, "Active listen URL changed after authorization.");
        RequireEqualUrl(active.Current.HealthUrl, authorization.HealthUrl, "Active health URL changed after authorization.");
    }

    private static ActiveState ReadActiveState()
    {
        if (!File.Exists(ActiveStatePath))
            throw new FileNotFoundException("Active runtime state does not exist.", ActiveStatePath);
        RejectReparse(ActiveStatePath);
        var state = JsonSerializer.Deserialize<ActiveState>(File.ReadAllBytes(ActiveStatePath), JsonOptions)
            ?? throw new InvalidDataException("Active runtime state is invalid.");
        if (state.SchemaVersion != 2)
            throw new InvalidDataException("Unsupported active runtime state schemaVersion.");
        ValidateSlot(state.Current);
        if (state.Previous is not null) ValidateSlot(state.Previous);
        return state;
    }

    private static void WriteActiveState(ActiveState state, string operationId)
    {
        ValidateSlot(state.Current);
        if (state.Previous is not null) ValidateSlot(state.Previous);
        var directory = Path.GetDirectoryName(ActiveStatePath)!;
        RejectReparse(directory);
        var temp = Path.Combine(directory, ".active-runtime." + operationId + ".tmp");
        if (File.Exists(temp)) File.Delete(temp);
        try
        {
            File.WriteAllText(temp, JsonSerializer.Serialize(state, JsonOptions), new UTF8Encoding(false));
            using (var stream = new FileStream(temp, FileMode.Open, FileAccess.ReadWrite, FileShare.Read))
                stream.Flush(flushToDisk: true);
            File.Move(temp, ActiveStatePath, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(temp)) File.Delete(temp); } catch { }
        }
    }

    private static void ValidateSlot(RuntimeSlot slot)
    {
        ValidateRuntimeFile(slot.RuntimeDll, slot.RuntimeSha256, null);
        _ = NormalizeListenUrl(slot.ListenUrl);
        _ = NormalizeHealthUrl(slot.HealthUrl);
        RequireSameEndpoint(slot.ListenUrl, slot.HealthUrl);
    }

    private static void ValidateRuntimeFile(string runtimeDll, string expectedSha, string? releaseName)
    {
        RequireSha256(expectedSha, "runtimeSha256");
        var full = Path.GetFullPath(runtimeDll);
        var releaseRoot = Path.GetFullPath(ReleaseRoot).TrimEnd('\\', '/');
        var package = Path.GetDirectoryName(full)?.TrimEnd('\\', '/')
            ?? throw new InvalidDataException("Runtime package directory is missing.");
        var parent = Path.GetDirectoryName(package)?.TrimEnd('\\', '/');
        if (!string.Equals(parent, releaseRoot, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Runtime must be one direct release under the fixed lifecycle release root.");
        if (releaseName is not null && !string.Equals(Path.GetFileName(package), releaseName, StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Target release name does not match runtime package directory.");
        if (!string.Equals(Path.GetFileName(full), RuntimeFileName, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Unexpected runtime DLL name.");
        RejectReparse(releaseRoot);
        RejectReparse(package);
        if (!File.Exists(full)) throw new FileNotFoundException("Runtime DLL does not exist.", full);
        RejectReparse(full);
        if (!EqualsSha(HashFile(full), expectedSha))
            throw new InvalidOperationException("Runtime DLL SHA-256 mismatch.");
    }

    private static void ValidateSupervisorIdentity(DeploymentAuthorization authorization)
    {
        RequireEqualPath(authorization.SupervisorExe, SupervisorExe, "Authorization does not target the fixed Runtime Supervisor executable.");
        if (!File.Exists(SupervisorExe))
            throw new FileNotFoundException("Runtime Supervisor executable does not exist.", SupervisorExe);
        RejectReparse(SupervisorExe);
        if (!EqualsSha(HashFile(SupervisorExe), authorization.SupervisorSha256))
            throw new InvalidOperationException("Runtime Supervisor executable SHA-256 changed after authorization.");
    }

    private static void ValidateExecutorIdentity(DeploymentAuthorization authorization)
    {
        var processPath = Environment.ProcessPath ?? throw new InvalidOperationException("Executor process path is unavailable.");
        var full = Path.GetFullPath(processPath);
        if (!string.Equals(Path.GetFileName(full), "YowThi.RuntimeDeploymentExecutor.exe", StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Dedicated deployment executor must run through its fixed apphost executable.");
        RejectReparse(full);
        if (!EqualsSha(HashFile(full), authorization.ExecutorSha256))
            throw new InvalidOperationException("Dedicated deployment executor SHA-256 changed after authorization.");
    }

    private static async Task<bool> ProbeExactRuntimeShaAsync(string healthUrl, string expectedSha)
    {
        try
        {
            using var response = await Http.GetAsync(NormalizeHealthUrl(healthUrl));
            if (!response.IsSuccessStatusCode) return false;
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            if (!doc.RootElement.TryGetProperty("runtimeSha256", out var sha) || sha.ValueKind != JsonValueKind.String)
                return false;
            return EqualsSha(sha.GetString() ?? string.Empty, expectedSha);
        }
        catch
        {
            return false;
        }
    }

    private static async Task<bool> WaitForExactRuntimeShaAsync(string healthUrl, string expectedSha, TimeSpan timeout)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (await ProbeExactRuntimeShaAsync(healthUrl, expectedSha)) return true;
            await Task.Delay(500);
        }
        return false;
    }

    private static async Task<ActiveState?> WaitForActiveRuntimeStateAsync(string expectedRuntimeDll, string expectedSha, TimeSpan timeout)
    {
        var expectedPath = Path.GetFullPath(expectedRuntimeDll);
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            try
            {
                var state = ReadActiveState();
                if (state.Current.ProcessId > 0 &&
                    EqualsSha(state.Current.RuntimeSha256, expectedSha) &&
                    string.Equals(Path.GetFullPath(state.Current.RuntimeDll), expectedPath, StringComparison.OrdinalIgnoreCase))
                    return state;
            }
            catch (IOException) { }
            catch (JsonException) { }

            await Task.Delay(100);
        }
        return null;
    }

    private static async Task<bool> WaitForProcessExitAsync(int processId, TimeSpan timeout)
    {
        if (processId <= 0) return true;
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            try
            {
                using var process = Process.GetProcessById(processId);
                if (process.HasExited) return true;
            }
            catch (ArgumentException)
            {
                return true;
            }
            await Task.Delay(250);
        }
        return false;
    }

    private static void ValidateFixedRoots()
    {
        ValidateExistingDirectory(DevRoot, DevRoot);
        ValidateExistingDirectory(ReleaseRoot, DevRoot);
        ValidateExistingDirectory(Path.GetDirectoryName(ActiveStatePath)!, DevRoot);
        ValidateExistingDirectory(Path.GetDirectoryName(SupervisorExe)!, DevRoot);
        ValidateExistingDirectory(DeploymentRoot, DevRoot);
        ValidateExistingDirectory(RequestRoot, DeploymentRoot);
        ValidateExistingDirectory(AuthorizedRoot, DeploymentRoot);
        Directory.CreateDirectory(CompletedRoot);
        Directory.CreateDirectory(FailedRoot);
        ValidateExistingDirectory(CompletedRoot, DeploymentRoot);
        ValidateExistingDirectory(FailedRoot, DeploymentRoot);
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

    private static void EnsureNoTerminalResult(string authorizationId)
    {
        var completed = Path.Combine(CompletedRoot, authorizationId + ".result.json");
        var failed = Path.Combine(FailedRoot, authorizationId + ".result.json");
        if (File.Exists(completed) || File.Exists(failed))
            throw new InvalidOperationException("Deployment authorization has already reached a terminal result.");
    }

    private static void WriteTerminalResult(string root, string authorizationId, object result)
    {
        var path = Path.Combine(root, authorizationId + ".result.json");
        if (File.Exists(path)) throw new IOException("Terminal deployment result already exists.");
        var bytes = new UTF8Encoding(false).GetBytes(JsonSerializer.Serialize(result, JsonOptions));
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        stream.Write(bytes, 0, bytes.Length);
        stream.Flush(flushToDisk: true);
    }

    private static void TryWriteFailureResult(string authorizationId, string requestId, string currentSha, string targetSha,
        Exception deploymentError, bool rollbackSucceeded, string? rollbackError)
    {
        try
        {
            WriteTerminalResult(FailedRoot, authorizationId, new
            {
                schemaVersion = 1,
                authorizationId,
                requestId,
                status = "failed",
                currentRuntimeSha256 = currentSha,
                targetRuntimeSha256 = targetSha,
                error = deploymentError.GetType().Name + ": " + deploymentError.Message,
                rollbackSucceeded,
                rollbackError,
                failedUtc = DateTimeOffset.UtcNow
            });
        }
        catch { }
    }

    private static void TryMoveAuthorization(string source, string terminalRoot, string authorizationId)
    {
        try
        {
            var destination = Path.Combine(terminalRoot, authorizationId + ".authorization.json");
            if (!File.Exists(destination) && File.Exists(source))
                File.Move(source, destination, false);
        }
        catch { }
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

    private static void RequireEqualUrl(string actual, string expected, string message)
    {
        var a = actual.Contains("/health", StringComparison.OrdinalIgnoreCase) ? NormalizeHealthUrl(actual) : NormalizeListenUrl(actual);
        var e = expected.Contains("/health", StringComparison.OrdinalIgnoreCase) ? NormalizeHealthUrl(expected) : NormalizeListenUrl(expected);
        if (!string.Equals(a, e, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException(message);
    }

    private static void RequireEqualPath(string actual, string expected, string message)
    {
        if (!string.Equals(Path.GetFullPath(actual), Path.GetFullPath(expected), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(message);
    }

    private static void RequireEqualSha(string actual, string expected, string message)
    {
        if (!EqualsSha(actual, expected)) throw new InvalidOperationException(message);
    }

    private static void RequireDirectJsonChild(string path, string root, string label)
    {
        var parent = Path.GetDirectoryName(Path.GetFullPath(path))?.TrimEnd('\\', '/');
        var expected = Path.GetFullPath(root).TrimEnd('\\', '/');
        if (!string.Equals(parent, expected, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetExtension(path), ".json", StringComparison.OrdinalIgnoreCase) || !File.Exists(path))
            throw new UnauthorizedAccessException(label + " must be one existing direct JSON file under its fixed root.");
    }

    private static void ValidateGuidN(string value, string name)
    {
        if (!Guid.TryParseExact(value, "N", out _))
            throw new InvalidDataException(name + " must be a 32-character GUID N identifier.");
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

internal sealed class ServiceHandle : IDisposable
{
    private const uint SC_MANAGER_CONNECT = 0x0001;
    private const uint SERVICE_QUERY_CONFIG = 0x0001;
    private const uint SERVICE_QUERY_STATUS = 0x0004;
    private const uint SERVICE_START = 0x0010;
    private const uint SERVICE_STOP = 0x0020;
    private const uint SERVICE_CONTROL_STOP = 1;
    private const uint SERVICE_STOPPED = 1;
    private const uint SERVICE_START_PENDING = 2;
    private const uint SERVICE_STOP_PENDING = 3;
    private const uint SERVICE_RUNNING = 4;
    private const int ERROR_SERVICE_ALREADY_RUNNING = 1056;
    private const int ERROR_SERVICE_NOT_ACTIVE = 1062;

    private readonly nint _scm;
    private readonly nint _service;

    private ServiceHandle(nint scm, nint service)
    {
        _scm = scm;
        _service = service;
    }

    public static ServiceHandle Open(string serviceName)
    {
        var scm = Native.OpenSCManagerW(null, null, SC_MANAGER_CONNECT);
        if (scm == 0) throw new InvalidOperationException("OpenSCManager failed: " + Marshal.GetLastWin32Error());
        var service = Native.OpenServiceW(scm, serviceName, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START);
        if (service == 0)
        {
            var error = Marshal.GetLastWin32Error();
            Native.CloseServiceHandle(scm);
            throw new InvalidOperationException("OpenService failed: " + error);
        }
        return new ServiceHandle(scm, service);
    }

    public void RequireRunningAndBinary(string expectedExe, string expectedSha)
    {
        var status = QueryStatus();
        if (status.dwCurrentState != SERVICE_RUNNING)
            throw new InvalidOperationException("Runtime Supervisor service must be Running immediately before deployment.");
        var binary = ReadBinaryPath();
        if (!string.Equals(Path.GetFullPath(binary), Path.GetFullPath(expectedExe), StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Runtime Supervisor service binary path mismatch.");
        using var stream = new FileStream(binary, FileMode.Open, FileAccess.Read, FileShare.Read);
        var sha = Convert.ToHexString(SHA256.HashData(stream));
        if (!string.Equals(sha, expectedSha, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Runtime Supervisor service binary SHA-256 mismatch.");
    }

    public void StopAndWait(TimeSpan timeout)
    {
        var state = QueryStatus().dwCurrentState;
        if (state == SERVICE_STOPPED) return;
        if (state != SERVICE_STOP_PENDING && !Native.ControlService(_service, SERVICE_CONTROL_STOP, out _))
        {
            var error = Marshal.GetLastWin32Error();
            if (error != ERROR_SERVICE_NOT_ACTIVE) throw new InvalidOperationException("ControlService failed: " + error);
        }
        WaitFor(SERVICE_STOPPED, timeout);
    }

    public void StartAndWait(TimeSpan timeout)
    {
        var state = QueryStatus().dwCurrentState;
        if (state == SERVICE_RUNNING) return;
        if (state != SERVICE_START_PENDING && !Native.StartServiceW(_service, 0, null))
        {
            var error = Marshal.GetLastWin32Error();
            if (error != ERROR_SERVICE_ALREADY_RUNNING) throw new InvalidOperationException("StartService failed: " + error);
        }
        WaitFor(SERVICE_RUNNING, timeout);
    }

    private void WaitFor(uint expected, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (QueryStatus().dwCurrentState == expected) return;
            Thread.Sleep(250);
        }
        throw new TimeoutException("Timed out waiting for Runtime Supervisor service state " + expected + ".");
    }

    private Native.SERVICE_STATUS_PROCESS QueryStatus()
    {
        var size = Marshal.SizeOf<Native.SERVICE_STATUS_PROCESS>();
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (!Native.QueryServiceStatusEx(_service, 0, buffer, size, out _))
                throw new InvalidOperationException("QueryServiceStatusEx failed: " + Marshal.GetLastWin32Error());
            return Marshal.PtrToStructure<Native.SERVICE_STATUS_PROCESS>(buffer);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private string ReadBinaryPath()
    {
        _ = Native.QueryServiceConfigW(_service, IntPtr.Zero, 0, out var needed);
        if (needed <= 0) throw new InvalidOperationException("QueryServiceConfig size probe failed: " + Marshal.GetLastWin32Error());
        var buffer = Marshal.AllocHGlobal(needed);
        try
        {
            if (!Native.QueryServiceConfigW(_service, buffer, needed, out _))
                throw new InvalidOperationException("QueryServiceConfig failed: " + Marshal.GetLastWin32Error());
            var config = Marshal.PtrToStructure<Native.QUERY_SERVICE_CONFIG>(buffer);
            var commandLine = Marshal.PtrToStringUni(config.lpBinaryPathName) ?? string.Empty;
            var argv = Native.CommandLineToArgvW(Environment.ExpandEnvironmentVariables(commandLine), out var argc);
            if (argv == IntPtr.Zero) throw new InvalidOperationException("CommandLineToArgvW failed: " + Marshal.GetLastWin32Error());
            try
            {
                if (argc != 1) throw new UnauthorizedAccessException("Runtime Supervisor service must use exactly one executable and no arguments.");
                return Path.GetFullPath(Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv)) ?? string.Empty);
            }
            finally
            {
                Native.LocalFree(argv);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public void Dispose()
    {
        if (_service != 0) Native.CloseServiceHandle(_service);
        if (_scm != 0) Native.CloseServiceHandle(_scm);
    }
}

internal static class Native
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct SERVICE_STATUS_PROCESS
    {
        public uint dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode, dwServiceSpecificExitCode,
            dwCheckPoint, dwWaitHint, dwProcessId, dwServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SERVICE_STATUS
    {
        public uint dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode, dwServiceSpecificExitCode,
            dwCheckPoint, dwWaitHint;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct QUERY_SERVICE_CONFIG
    {
        public uint dwServiceType, dwStartType, dwErrorControl;
        public IntPtr lpBinaryPathName, lpLoadOrderGroup;
        public uint dwTagId;
        public IntPtr lpDependencies, lpServiceStartName, lpDisplayName;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern nint OpenSCManagerW(string? machine, string? database, uint access);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern nint OpenServiceW(nint scm, string serviceName, uint access);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ControlService(nint service, uint control, out SERVICE_STATUS status);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "StartServiceW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool StartServiceW(nint service, int argc, string[]? argv);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryServiceStatusEx(nint service, int infoLevel, nint buffer, int size, out int needed);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryServiceConfigW(nint service, IntPtr config, int bufferSize, out int bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseServiceHandle(nint handle);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr CommandLineToArgvW(string commandLine, out int argc);

    [DllImport("kernel32.dll")]
    internal static extern IntPtr LocalFree(IntPtr memory);
}
