using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;

namespace YowThi.RuntimeDeploymentApprovalBridge;

internal static class Program
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string ReleaseRoot = DevRoot + @"\acceptance\agent-lifecycle\releases";
    private const string ActiveStatePath = DevRoot + @"\.agent3-handoff\active-runtime.json";
    private const string BootstrapRequestRoot = DevRoot + @"\.agent3-lifecycle\pending";
    private const string DeploymentRoot = DevRoot + @"\.runtime-supervisor-deployment";
    private const string RequestRoot = DeploymentRoot + @"\requests";
    private const string SigningIntentRoot = DeploymentRoot + @"\signing-intents";
    private const string ApprovalRoot = DeploymentRoot + @"\approvals";
    private const string SupervisorExe = DevRoot + @"\runtime-supervisor\current\YowThi.RuntimeSupervisor.exe";
    private const string InstallRoot = @"C:\ProgramData\YowThi\RuntimeDeployment";
    private const string PackageManifestPath = InstallRoot + @"\package-manifest.json";
    private const string SignerExe = InstallRoot + @"\YowThi.RuntimeDeploymentSigner.exe";
    private const string AuthorizerExe = InstallRoot + @"\YowThi.RuntimeDeploymentAuthorizer.exe";
    private const string ExecutorExe = InstallRoot + @"\YowThi.RuntimeDeploymentExecutor.exe";
    private const string RuntimeFileName = "YowThi.DevelopmentAgent3.dll";
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true, WriteIndented = true };

    [STAThread]
    public static int Main()
    {
        try
        {
            var package = ReadAndValidatePackage();
            DeploymentRequest request;
            string requestPath;
            string requestSha256;

            if (TryFindSingleEligibleRequest(out var existingRequest, out var existingRequestPath, out var existingRequestSha256))
            {
                request = existingRequest!;
                requestPath = existingRequestPath!;
                requestSha256 = existingRequestSha256!;
                if (!ConfirmDeployment(request.ReleaseName, request.CurrentRuntimeSha256, request.TargetRuntimeSha256, bootstrapPromotion: false))
                    return 2;
            }
            else
            {
                RefuseBootstrapFallbackWhenDirectRequestFilesExist();
                var bootstrap = FindSingleEligibleBootstrapRequest(out var bootstrapPath, out var bootstrapSha256);
                var releaseName = GetReleaseName(bootstrap.Target.Directory);
                if (!ConfirmDeployment(releaseName, bootstrap.Current.RuntimeSha256, bootstrap.Target.RuntimeSha256, bootstrapPromotion: true))
                    return 2;

                request = CreateDeploymentRequestFromBootstrap(
                    bootstrap,
                    bootstrapPath,
                    bootstrapSha256,
                    out requestPath,
                    out requestSha256);
            }

            var now = DateTimeOffset.UtcNow;
            var expiry = request.ExpiresUtc < now.AddMinutes(5) ? request.ExpiresUtc : now.AddMinutes(5);
            if (expiry <= now)
                throw new UnauthorizedAccessException("Deployment request expired before interactive approval.");

            var executor = package.Component("executor");
            var intent = new SigningIntent(
                1,
                Guid.NewGuid().ToString("N"),
                Guid.NewGuid().ToString("N"),
                request.RequestId,
                requestSha256,
                executor.ExeSha256,
                executor.ManagedDllSha256,
                now,
                expiry,
                Guid.NewGuid().ToString("N"),
                "runtime-deploy");

            Directory.CreateDirectory(SigningIntentRoot);
            Directory.CreateDirectory(ApprovalRoot);
            RejectReparse(SigningIntentRoot);
            RejectReparse(ApprovalRoot);
            var intentPath = Path.Combine(SigningIntentRoot, intent.SigningIntentId + ".json");
            WriteCreateNewJson(intentPath, intent);

            var signerExit = RunFixedChild(SignerExe, package.Component("signer"), intentPath, TimeSpan.FromMinutes(1));
            if (signerExit != 0)
                throw new InvalidOperationException("Runtime deployment signer did not produce an approval.");

            var approvalPath = Path.Combine(ApprovalRoot, intent.ApprovalId + ".json");
            if (!File.Exists(approvalPath))
                throw new InvalidOperationException("Signed runtime deployment approval was not created.");

            var authorizerExit = RunFixedChild(AuthorizerExe, package.Component("authorizer"), approvalPath, TimeSpan.FromMinutes(5));
            if (authorizerExit != 0)
                throw new InvalidOperationException("Runtime deployment authorizer/executor chain did not complete successfully.");

            MessageBox.Show("Runtime deployment chain completed successfully.", "YowThi Runtime Deployment", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 0;
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.GetType().Name + ": " + ex.Message, "YowThi Runtime Deployment Approval Failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }

    private static bool ConfirmDeployment(string releaseName, string currentSha, string targetSha, bool bootstrapPromotion)
    {
        var mode = bootstrapPromotion
            ? "A request-only lifecycle intent will first be promoted into a short-lived P27 deployment request after you approve.\n\n"
            : string.Empty;
        var prompt =
            "Authorize this YowThi runtime deployment?\n\n" +
            "Target release: " + releaseName + "\n" +
            "Current runtime SHA: " + currentSha + "\n" +
            "Target runtime SHA:  " + targetSha + "\n\n" +
            mode +
            "This approval will be short-lived and bound to the exact request and installed executor EXE+DLL identity.";

        return MessageBox.Show(
            prompt,
            "YowThi Runtime Deployment Approval",
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning,
            MessageBoxDefaultButton.Button2) == DialogResult.Yes;
    }

    private static PackageManifest ReadAndValidatePackage()
    {
        if (!File.Exists(PackageManifestPath))
            throw new FileNotFoundException("Activated runtime deployment package manifest is not installed.", PackageManifestPath);
        RejectReparse(PackageManifestPath);
        var package = JsonSerializer.Deserialize<PackageManifest>(File.ReadAllBytes(PackageManifestPath), JsonOptions)
            ?? throw new InvalidDataException("Runtime deployment package manifest is invalid.");

        if (package.SchemaVersion != 3 || !package.DeploymentEnabled || !package.SignerKey.Provisioned || !package.ApprovalBridge.Provisioned)
            throw new UnauthorizedAccessException("Runtime deployment package is not fully provisioned and enabled for managed-payload identity binding.");
        if (package.Components.Count != 3 || package.Components.Select(x => x.Name).Distinct(StringComparer.Ordinal).Count() != 3)
            throw new InvalidDataException("Runtime deployment package must contain exactly signer, authorizer and executor components.");

        var userSid = WindowsIdentity.GetCurrent().User?.Value
            ?? throw new UnauthorizedAccessException("Current interactive user SID is unavailable.");
        if (!string.Equals(package.SignerKey.UserSid, userSid, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(package.SignerKey.KeyScope, "CurrentUser", StringComparison.Ordinal) ||
            !string.Equals(package.SignerKey.KeyId, "p31-runtime-deployment-signer-user-v1", StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Runtime deployment package is not bound to the current interactive user signing identity.");

        ValidateInstalledComponent(SignerExe, package.Component("signer"), "signer");
        ValidateInstalledComponent(AuthorizerExe, package.Component("authorizer"), "authorizer");
        ValidateInstalledComponent(ExecutorExe, package.Component("executor"), "executor");

        var self = Environment.ProcessPath ?? throw new UnauthorizedAccessException("Approval bridge executable path is unavailable.");
        var expectedSelf = Path.Combine(InstallRoot, "YowThi.RuntimeDeploymentApprovalBridge.exe");
        if (!string.Equals(Path.GetFullPath(self), expectedSelf, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Approval bridge is not running from the fixed ProgramData installation path.");
        if (!string.Equals(package.ApprovalBridge.InstallFileName, Path.GetFileName(expectedSelf), StringComparison.Ordinal) ||
            !string.Equals(package.ApprovalBridge.ManagedDllFileName, "YowThi.RuntimeDeploymentApprovalBridge.dll", StringComparison.Ordinal))
            throw new InvalidDataException("Approval bridge package file names are invalid.");
        ValidateInstalledFile(expectedSelf, package.ApprovalBridge.ExeSha256, "approval bridge executable");
        ValidateInstalledFile(Path.Combine(InstallRoot, package.ApprovalBridge.ManagedDllFileName), package.ApprovalBridge.ManagedDllSha256, "approval bridge managed DLL");
        return package;
    }

    private static bool TryFindSingleEligibleRequest(out DeploymentRequest? request, out string? requestPath, out string? requestSha256)
    {
        request = null;
        requestPath = null;
        requestSha256 = null;
        if (!Directory.Exists(RequestRoot))
            return false;
        RejectReparse(RequestRoot);

        var candidates = new List<(DeploymentRequest Request, string Path, string Sha)>();
        foreach (var path in Directory.GetFiles(RequestRoot, "*.json", SearchOption.TopDirectoryOnly))
        {
            RejectReparse(path);
            var bytes = File.ReadAllBytes(path);
            var candidate = JsonSerializer.Deserialize<DeploymentRequest>(bytes, JsonOptions);
            if (candidate is null || candidate.SchemaVersion != 1 || candidate.ProcessAuthorization || !candidate.RequiresDedicatedSupervisorExecutor || candidate.ExpiresUtc <= DateTimeOffset.UtcNow)
                continue;
            if (!string.Equals(Path.GetFileNameWithoutExtension(path), candidate.RequestId, StringComparison.Ordinal))
                continue;
            candidates.Add((candidate, path, HashBytes(bytes)));
        }

        if (candidates.Count > 1)
            throw new InvalidOperationException("More than one unexpired request-only runtime deployment request exists; interactive approval is ambiguous.");
        if (candidates.Count == 0)
            return false;

        request = candidates[0].Request;
        requestPath = candidates[0].Path;
        requestSha256 = candidates[0].Sha;
        return true;
    }

    private static void RefuseBootstrapFallbackWhenDirectRequestFilesExist()
    {
        if (!Directory.Exists(RequestRoot))
            return;
        RejectReparse(RequestRoot);

        var files = Directory.GetFiles(RequestRoot, "*.json", SearchOption.TopDirectoryOnly);
        if (files.Length == 0)
            return;

        var now = DateTimeOffset.UtcNow;
        var expiredEligibleShapeCount = 0;
        foreach (var path in files)
        {
            RejectReparse(path);
            try
            {
                var candidate = JsonSerializer.Deserialize<DeploymentRequest>(File.ReadAllBytes(path), JsonOptions);
                if (candidate is not null &&
                    candidate.SchemaVersion == 1 &&
                    !candidate.ProcessAuthorization &&
                    candidate.RequiresDedicatedSupervisorExecutor &&
                    candidate.ExpiresUtc <= now)
                    expiredEligibleShapeCount++;
            }
            catch (JsonException)
            {
                // Any malformed direct request keeps bootstrap fallback fail-closed below.
            }
        }

        if (expiredEligibleShapeCount == files.Length)
            throw new UnauthorizedAccessException("Direct runtime deployment request exists but has expired; create a fresh direct request instead of using bootstrap promotion.");

        throw new InvalidOperationException("Direct runtime deployment request queue contains ineligible request files; refusing bootstrap promotion.");
    }

    private static BootstrapTransitionRequest FindSingleEligibleBootstrapRequest(out string requestPath, out string requestSha256)
    {
        if (!Directory.Exists(BootstrapRequestRoot))
            throw new DirectoryNotFoundException("Bootstrap lifecycle request root does not exist.");
        RejectReparse(BootstrapRequestRoot);

        var files = Directory.GetFiles(BootstrapRequestRoot, "*-update-request.json", SearchOption.TopDirectoryOnly);
        if (files.Length != 1)
            throw new InvalidOperationException("Exactly one request-only lifecycle update request must exist for bootstrap promotion.");

        requestPath = files[0];
        RejectReparse(requestPath);
        var bytes = File.ReadAllBytes(requestPath);
        requestSha256 = HashBytes(bytes);
        var request = JsonSerializer.Deserialize<BootstrapTransitionRequest>(bytes, JsonOptions)
            ?? throw new InvalidDataException("Bootstrap lifecycle request JSON is invalid.");
        ValidateBootstrapTransitionRequest(request, requestPath, ReadActiveState());
        return request;
    }

    private static DeploymentRequest CreateDeploymentRequestFromBootstrap(
        BootstrapTransitionRequest original,
        string bootstrapPath,
        string expectedBootstrapSha256,
        out string requestPath,
        out string requestSha256)
    {
        RejectReparse(bootstrapPath);
        var bootstrapBytes = File.ReadAllBytes(bootstrapPath);
        if (!string.Equals(HashBytes(bootstrapBytes), expectedBootstrapSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Bootstrap lifecycle request changed during interactive approval.");

        var bootstrap = JsonSerializer.Deserialize<BootstrapTransitionRequest>(bootstrapBytes, JsonOptions)
            ?? throw new InvalidDataException("Bootstrap lifecycle request JSON became invalid.");
        if (!string.Equals(bootstrap.PlanId, original.PlanId, StringComparison.Ordinal))
            throw new InvalidOperationException("Bootstrap lifecycle request identity changed during interactive approval.");

        var active = ReadActiveState();
        ValidateBootstrapTransitionRequest(bootstrap, bootstrapPath, active);
        if (TryFindSingleEligibleRequest(out _, out _, out _))
            throw new InvalidOperationException("A deployment request appeared during interactive bootstrap approval; refusing ambiguous promotion.");

        ValidateFixedFile(SupervisorExe, "Runtime Supervisor executable");
        var supervisorSha = HashFile(SupervisorExe);
        var releaseName = GetReleaseName(bootstrap.Target.Directory);
        var now = DateTimeOffset.UtcNow;
        var expires = now.AddMinutes(5);
        var requestId = Guid.NewGuid().ToString("N");
        var generated = new DeploymentRequest(
            1,
            bootstrap.PlanId,
            requestId,
            releaseName,
            Path.GetFullPath(active.Current.RuntimeDll),
            active.Current.RuntimeSha256,
            active.Current.ProcessId,
            Path.GetFullPath(bootstrap.Target.RuntimeDll),
            bootstrap.Target.RuntimeSha256,
            NormalizeListenUrl(active.Current.ListenUrl),
            NormalizeHealthUrl(active.Current.HealthUrl),
            Path.GetFullPath(SupervisorExe),
            supervisorSha,
            false,
            true,
            now,
            expires);

        Directory.CreateDirectory(DeploymentRoot);
        RejectReparse(DeploymentRoot);
        Directory.CreateDirectory(RequestRoot);
        RejectReparse(RequestRoot);
        requestPath = Path.Combine(RequestRoot, requestId + ".json");
        var created = false;
        try
        {
            WriteCreateNewJson(requestPath, generated);
            created = true;
            var finalBytes = File.ReadAllBytes(requestPath);
            requestSha256 = HashBytes(finalBytes);

            if (!TryFindSingleEligibleRequest(out var readBack, out var readBackPath, out var readBackSha) ||
                readBack is null ||
                !string.Equals(readBack.RequestId, requestId, StringComparison.Ordinal) ||
                !string.Equals(Path.GetFullPath(readBackPath!), Path.GetFullPath(requestPath), StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(readBackSha, requestSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Generated P27 deployment request failed post-write identity readback.");

            return generated;
        }
        catch
        {
            if (created)
            {
                try { if (File.Exists(requestPath)) File.Delete(requestPath); } catch { }
            }
            throw;
        }
    }

    private static void ValidateBootstrapTransitionRequest(BootstrapTransitionRequest request, string requestPath, ActiveState active)
    {
        if (request.SchemaVersion != 1 ||
            !string.Equals(request.RequestType, "agent-lifecycle-transition-request", StringComparison.Ordinal) ||
            !string.Equals(request.RequestedAction, "update", StringComparison.Ordinal) ||
            !string.Equals(request.Scope, "request-only", StringComparison.Ordinal) ||
            request.ProcessAuthorization ||
            !request.RequiresSeparateRuntimePlans)
            throw new UnauthorizedAccessException("Bootstrap lifecycle request is not a request-only update intent.");

        ValidateGuidN(request.PlanId, "bootstrap planId");
        var expectedLeaf = request.PlanId + "-update-request.json";
        if (!string.Equals(Path.GetFileName(requestPath), expectedLeaf, StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Bootstrap lifecycle request file name does not match its plan identity.");
        if (request.StagedUtc > DateTimeOffset.UtcNow.AddMinutes(1))
            throw new InvalidDataException("Bootstrap lifecycle request stagedUtc is in the future.");
        if (active.SchemaVersion != 2 || active.Current.ProcessId <= 0)
            throw new InvalidDataException("Active runtime state is invalid for bootstrap promotion.");

        ValidateRuntimeIdentity(request.Current, null);
        var releaseName = GetReleaseName(request.Target.Directory);
        ValidateReleaseName(releaseName);
        ValidateRuntimeIdentity(request.Target, releaseName);

        if (!string.Equals(Path.GetFullPath(request.Current.RuntimeDll), Path.GetFullPath(active.Current.RuntimeDll), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(request.Current.RuntimeSha256, active.Current.RuntimeSha256, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetFullPath(request.Current.Directory), Path.GetDirectoryName(Path.GetFullPath(active.Current.RuntimeDll)), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Bootstrap lifecycle current runtime no longer matches active runtime state.");
        if (string.Equals(request.Current.RuntimeSha256, request.Target.RuntimeSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Bootstrap lifecycle target already matches the active runtime SHA-256.");

        var listen = NormalizeListenUrl(request.ListenUrl);
        var health = NormalizeHealthUrl(request.HealthUrl);
        RequireSameEndpoint(listen, health);
        if (!string.Equals(listen, NormalizeListenUrl(active.Current.ListenUrl), StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(health, NormalizeHealthUrl(active.Current.HealthUrl), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Bootstrap lifecycle endpoint identity no longer matches active runtime state.");
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
        ValidateRuntimeFile(state.Current.RuntimeDll, state.Current.RuntimeSha256, null);
        _ = NormalizeListenUrl(state.Current.ListenUrl);
        _ = NormalizeHealthUrl(state.Current.HealthUrl);
        return state;
    }

    private static void ValidateRuntimeIdentity(BootstrapRuntimeIdentity identity, string? expectedReleaseName)
    {
        var fullDirectory = Path.GetFullPath(identity.Directory).TrimEnd('\\', '/');
        var fullRuntime = Path.GetFullPath(identity.RuntimeDll);
        if (!string.Equals(Path.GetDirectoryName(fullRuntime)?.TrimEnd('\\', '/'), fullDirectory, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Bootstrap runtime DLL is not inside its declared release directory.");
        ValidateRuntimeFile(fullRuntime, identity.RuntimeSha256, expectedReleaseName);
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
        if (!File.Exists(full))
            throw new FileNotFoundException("Runtime DLL does not exist.", full);
        RejectReparse(releaseRoot);
        RejectReparse(package);
        RejectReparse(full);
        if (!string.Equals(HashFile(full), expectedSha, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Runtime DLL SHA-256 mismatch.");
    }

    private static string GetReleaseName(string directory)
    {
        var full = Path.GetFullPath(directory).TrimEnd('\\', '/');
        var releaseRoot = Path.GetFullPath(ReleaseRoot).TrimEnd('\\', '/');
        var parent = Path.GetDirectoryName(full)?.TrimEnd('\\', '/');
        if (!string.Equals(parent, releaseRoot, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Bootstrap target must be one direct staged release.");
        var name = Path.GetFileName(full);
        ValidateReleaseName(name);
        return name;
    }

    private static void ValidateReleaseName(string value)
    {
        if (value.Length is < 2 or > 32 || value[0] != 'r' || value.Skip(1).Any(ch => ch < '0' || ch > '9'))
            throw new InvalidDataException("Release name must match r<digits>.");
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

    private static int RunFixedChild(string executable, Component component, string argument, TimeSpan timeout)
    {
        ValidateInstalledComponent(executable, component, component.Name);
        var start = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = InstallRoot
        };
        start.ArgumentList.Add(argument);
        using var child = Process.Start(start) ?? throw new InvalidOperationException("Unable to start fixed runtime deployment child executable.");
        if (!child.WaitForExit((int)timeout.TotalMilliseconds))
            throw new TimeoutException("Runtime deployment child did not reach a terminal state within the bounded timeout.");
        return child.ExitCode;
    }

    private static void ValidateInstalledComponent(string executable, Component component, string expectedName)
    {
        if (!string.Equals(component.Name, expectedName, StringComparison.Ordinal))
            throw new InvalidDataException("Runtime deployment component name mismatch.");
        var expectedExeName = Path.GetFileName(executable);
        var expectedDllName = Path.GetFileNameWithoutExtension(executable) + ".dll";
        if (!string.Equals(component.InstallFileName, expectedExeName, StringComparison.Ordinal) ||
            !string.Equals(component.ManagedDllFileName, expectedDllName, StringComparison.Ordinal))
            throw new InvalidDataException("Runtime deployment component file names do not match the fixed installation identity.");
        ValidateInstalledFile(executable, component.ExeSha256, expectedName + " executable");
        ValidateInstalledFile(Path.Combine(InstallRoot, component.ManagedDllFileName), component.ManagedDllSha256, expectedName + " managed DLL");
    }

    private static void ValidateInstalledFile(string path, string expectedSha, string label)
    {
        RequireSha256(expectedSha, label + "Sha256");
        var full = Path.GetFullPath(path);
        if (!File.Exists(full)) throw new FileNotFoundException("Required runtime deployment file is missing.", full);
        RejectReparse(full);
        if (!string.Equals(HashFile(full), expectedSha, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException(label + " SHA-256 does not match the activated package manifest.");
    }

    private static void ValidateFixedFile(string path, string label)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full))
            throw new FileNotFoundException(label + " does not exist.", full);
        RejectReparse(full);
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

    private static void WriteCreateNewJson(string path, object value)
    {
        var bytes = new UTF8Encoding(false).GetBytes(JsonSerializer.Serialize(value, JsonOptions));
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        stream.Write(bytes, 0, bytes.Length);
        stream.Flush(flushToDisk: true);
    }

    internal sealed record SigningIntent(int SchemaVersion, string SigningIntentId, string ApprovalId, string RequestId, string RequestSha256, string ExecutorSha256, string ExecutorDllSha256, DateTimeOffset IssuedUtc, DateTimeOffset ExpiresUtc, string Nonce, string Action);

    internal sealed record DeploymentRequest(int SchemaVersion, string RequestPlanId, string RequestId, string ReleaseName, string CurrentRuntimeDll, string CurrentRuntimeSha256, int CurrentProcessId, string TargetRuntimeDll, string TargetRuntimeSha256, string ListenUrl, string HealthUrl, string SupervisorExe, string SupervisorSha256, bool ProcessAuthorization, bool RequiresDedicatedSupervisorExecutor, DateTimeOffset CreatedUtc, DateTimeOffset ExpiresUtc);

    internal sealed record BootstrapRuntimeIdentity(string Directory, string RuntimeDll, string RuntimeSha256, string ManifestSha256, string ShapeSha256);
    internal sealed record BootstrapTransitionRequest(int SchemaVersion, string RequestType, string PlanId, string RequestedAction, string Scope, bool ProcessAuthorization, bool RequiresSeparateRuntimePlans, BootstrapRuntimeIdentity Current, BootstrapRuntimeIdentity Target, string ListenUrl, string HealthUrl, DateTimeOffset StagedUtc);
    internal sealed record ActiveRuntimeSlot(string? PlanId, string RuntimeDll, string RuntimeSha256, string ListenUrl, string HealthUrl, int ProcessId);
    internal sealed record ActiveState(int SchemaVersion, ActiveRuntimeSlot Current, ActiveRuntimeSlot? Previous, DateTimeOffset UpdatedUtc);

    internal sealed record Component(string Name, string InstallFileName, string ExeSha256, string ManagedDllFileName, string ManagedDllSha256);
    internal sealed record SignerKeyBinding(string KeyName, string KeyId, string UserSid, string KeyScope, string SpkiSha256, bool Provisioned);
    internal sealed record ApprovalBridgeBinding(string InstallFileName, string ExeSha256, string ManagedDllFileName, string ManagedDllSha256, bool Provisioned);
    internal sealed record PackageManifest(int SchemaVersion, string PackageId, DateTimeOffset CreatedUtc, bool DeploymentEnabled, List<Component> Components, SignerKeyBinding SignerKey, ApprovalBridgeBinding ApprovalBridge)
    {
        internal Component Component(string name) => Components.Single(x => string.Equals(x.Name, name, StringComparison.Ordinal));
    }
}