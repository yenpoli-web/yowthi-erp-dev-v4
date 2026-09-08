using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;

namespace YowThi.RuntimeDeploymentApprovalBridge;

internal static class Program
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string DeploymentRoot = DevRoot + @"\.runtime-supervisor-deployment";
    private const string RequestRoot = DeploymentRoot + @"\requests";
    private const string SigningIntentRoot = DeploymentRoot + @"\signing-intents";
    private const string ApprovalRoot = DeploymentRoot + @"\approvals";
    private const string InstallRoot = @"C:\ProgramData\YowThi\RuntimeDeployment";
    private const string PackageManifestPath = InstallRoot + @"\package-manifest.json";
    private const string SignerExe = InstallRoot + @"\YowThi.RuntimeDeploymentSigner.exe";
    private const string AuthorizerExe = InstallRoot + @"\YowThi.RuntimeDeploymentAuthorizer.exe";
    private const string ExecutorExe = InstallRoot + @"\YowThi.RuntimeDeploymentExecutor.exe";
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true, WriteIndented = true };

    [STAThread]
    public static int Main()
    {
        try
        {
            var package = ReadAndValidatePackage();
            var request = FindSingleEligibleRequest(out var requestPath, out var requestSha256);

            var prompt =
                "Authorize this YowThi runtime deployment?\n\n" +
                "Target release: " + request.ReleaseName + "\n" +
                "Current runtime SHA: " + request.CurrentRuntimeSha256 + "\n" +
                "Target runtime SHA:  " + request.TargetRuntimeSha256 + "\n\n" +
                "This approval will be short-lived and bound to the exact request and installed executor.";

            if (MessageBox.Show(prompt, "YowThi Runtime Deployment Approval", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                return 2;

            var now = DateTimeOffset.UtcNow;
            var expiry = request.ExpiresUtc < now.AddMinutes(5) ? request.ExpiresUtc : now.AddMinutes(5);
            if (expiry <= now)
                throw new UnauthorizedAccessException("Deployment request expired before interactive approval.");

            var intent = new SigningIntent(
                1,
                Guid.NewGuid().ToString("N"),
                Guid.NewGuid().ToString("N"),
                request.RequestId,
                requestSha256,
                package.Component("executor").ExeSha256,
                now,
                expiry,
                Guid.NewGuid().ToString("N"),
                "runtime-deploy");

            Directory.CreateDirectory(SigningIntentRoot);
            Directory.CreateDirectory(ApprovalRoot);
            var intentPath = Path.Combine(SigningIntentRoot, intent.SigningIntentId + ".json");
            WriteCreateNewJson(intentPath, intent);

            var signerExit = RunFixedChild(SignerExe, package.Component("signer").ExeSha256, intentPath, TimeSpan.FromMinutes(1));
            if (signerExit != 0)
                throw new InvalidOperationException("Runtime deployment signer did not produce an approval.");

            var approvalPath = Path.Combine(ApprovalRoot, intent.ApprovalId + ".json");
            if (!File.Exists(approvalPath))
                throw new InvalidOperationException("Signed runtime deployment approval was not created.");

            var authorizerExit = RunFixedChild(AuthorizerExe, package.Component("authorizer").ExeSha256, approvalPath, TimeSpan.FromMinutes(5));
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

    private static PackageManifest ReadAndValidatePackage()
    {
        if (!File.Exists(PackageManifestPath))
            throw new FileNotFoundException("Activated runtime deployment package manifest is not installed.", PackageManifestPath);
        RejectReparse(PackageManifestPath);
        var package = JsonSerializer.Deserialize<PackageManifest>(File.ReadAllBytes(PackageManifestPath), JsonOptions)
            ?? throw new InvalidDataException("Runtime deployment package manifest is invalid.");

        if (package.SchemaVersion != 2 || !package.DeploymentEnabled || !package.SignerKey.Provisioned || !package.ApprovalBridge.Provisioned)
            throw new UnauthorizedAccessException("Runtime deployment package is not fully provisioned and enabled.");
        if (package.Components.Count != 3 || package.Components.Select(x => x.Name).Distinct(StringComparer.Ordinal).Count() != 3)
            throw new InvalidDataException("Runtime deployment package must contain exactly signer, authorizer and executor components.");

        var userSid = WindowsIdentity.GetCurrent().User?.Value
            ?? throw new UnauthorizedAccessException("Current interactive user SID is unavailable.");
        if (!string.Equals(package.SignerKey.UserSid, userSid, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(package.SignerKey.KeyScope, "CurrentUser", StringComparison.Ordinal) ||
            !string.Equals(package.SignerKey.KeyId, "p31-runtime-deployment-signer-user-v1", StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Runtime deployment package is not bound to the current interactive user signing identity.");

        ValidateInstalledExecutable(SignerExe, package.Component("signer").ExeSha256);
        ValidateInstalledExecutable(AuthorizerExe, package.Component("authorizer").ExeSha256);
        ValidateInstalledExecutable(ExecutorExe, package.Component("executor").ExeSha256);

        var self = Environment.ProcessPath ?? throw new UnauthorizedAccessException("Approval bridge executable path is unavailable.");
        if (!string.Equals(Path.GetFullPath(self), Path.Combine(InstallRoot, "YowThi.RuntimeDeploymentApprovalBridge.exe"), StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Approval bridge is not running from the fixed ProgramData installation path.");
        ValidateInstalledExecutable(self, package.ApprovalBridge.ExeSha256);
        return package;
    }

    private static DeploymentRequest FindSingleEligibleRequest(out string requestPath, out string requestSha256)
    {
        if (!Directory.Exists(RequestRoot))
            throw new DirectoryNotFoundException("Runtime deployment request root does not exist.");

        var candidates = new List<(DeploymentRequest Request, string Path, string Sha)>();
        foreach (var path in Directory.GetFiles(RequestRoot, "*.json", SearchOption.TopDirectoryOnly))
        {
            RejectReparse(path);
            var bytes = File.ReadAllBytes(path);
            var request = JsonSerializer.Deserialize<DeploymentRequest>(bytes, JsonOptions);
            if (request is null || request.SchemaVersion != 1 || request.ProcessAuthorization || !request.RequiresDedicatedSupervisorExecutor || request.ExpiresUtc <= DateTimeOffset.UtcNow)
                continue;
            if (!string.Equals(Path.GetFileNameWithoutExtension(path), request.RequestId, StringComparison.Ordinal))
                continue;
            candidates.Add((request, path, Convert.ToHexString(SHA256.HashData(bytes))));
        }

        if (candidates.Count != 1)
            throw new InvalidOperationException("Exactly one unexpired request-only runtime deployment request must exist for interactive approval.");
        requestPath = candidates[0].Path;
        requestSha256 = candidates[0].Sha;
        return candidates[0].Request;
    }

    private static int RunFixedChild(string executable, string expectedSha, string argument, TimeSpan timeout)
    {
        ValidateInstalledExecutable(executable, expectedSha);
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

    private static void ValidateInstalledExecutable(string path, string expectedSha)
    {
        if (expectedSha.Length != 64 || expectedSha.Any(ch => !Uri.IsHexDigit(ch)))
            throw new InvalidDataException("Installed executable SHA-256 binding is invalid.");
        var full = Path.GetFullPath(path);
        if (!File.Exists(full)) throw new FileNotFoundException("Required runtime deployment executable is missing.", full);
        RejectReparse(full);
        using var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read);
        var actual = Convert.ToHexString(SHA256.HashData(stream));
        if (!string.Equals(actual, expectedSha, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Runtime deployment executable SHA-256 does not match the activated package manifest.");
    }

    private static void RejectReparse(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Reparse point rejected: " + path);
    }

    private static void WriteCreateNewJson(string path, object value)
    {
        var bytes = new UTF8Encoding(false).GetBytes(JsonSerializer.Serialize(value, JsonOptions));
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        stream.Write(bytes, 0, bytes.Length);
        stream.Flush(flushToDisk: true);
    }

    internal sealed record SigningIntent(int SchemaVersion, string SigningIntentId, string ApprovalId, string RequestId, string RequestSha256, string ExecutorSha256, DateTimeOffset IssuedUtc, DateTimeOffset ExpiresUtc, string Nonce, string Action);

    internal sealed record DeploymentRequest(int SchemaVersion, string RequestPlanId, string RequestId, string ReleaseName, string CurrentRuntimeDll, string CurrentRuntimeSha256, int CurrentProcessId, string TargetRuntimeDll, string TargetRuntimeSha256, string ListenUrl, string HealthUrl, string SupervisorExe, string SupervisorSha256, bool ProcessAuthorization, bool RequiresDedicatedSupervisorExecutor, DateTimeOffset CreatedUtc, DateTimeOffset ExpiresUtc);

    internal sealed record Component(string Name, string InstallFileName, string ExeSha256);
    internal sealed record SignerKeyBinding(string KeyName, string KeyId, string UserSid, string KeyScope, string SpkiSha256, bool Provisioned);
    internal sealed record ApprovalBridgeBinding(string InstallFileName, string ExeSha256, bool Provisioned);
    internal sealed record PackageManifest(int SchemaVersion, string PackageId, DateTimeOffset CreatedUtc, bool DeploymentEnabled, List<Component> Components, SignerKeyBinding SignerKey, ApprovalBridgeBinding ApprovalBridge)
    {
        internal Component Component(string name) => Components.Single(x => string.Equals(x.Name, name, StringComparison.Ordinal));
    }
}
