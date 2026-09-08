using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class RuntimeDeploymentApprovalBridgeContractTests
{
    [Fact]
    public void BridgeAndProvisioner_RequireActiveConsoleExplorerParent()
    {
        foreach (var project in new[] { "YowThi.RuntimeDeploymentApprovalBridge", "YowThi.RuntimeDeploymentKeyProvisioner" })
        {
            var source = File.ReadAllText(Source(project, "InteractiveSessionGuard.cs"));
            Assert.Contains("[ModuleInitializer]", source, StringComparison.Ordinal);
            Assert.Contains("Environment.UserInteractive", source, StringComparison.Ordinal);
            Assert.Contains("WTSGetActiveConsoleSessionId", source, StringComparison.Ordinal);
            Assert.Contains("ProcessIdToSessionId", source, StringComparison.Ordinal);
            Assert.Contains("explorer.exe", source, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("NtQueryInformationProcess", source, StringComparison.Ordinal);
            Assert.DoesNotContain("CngKeyOpenOptions.MachineKey", source, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void KeyProvisioner_CreatesOnlyNonExportableCurrentUserP256AndPublicReceipt()
    {
        var source = File.ReadAllText(Source("YowThi.RuntimeDeploymentKeyProvisioner", "Program.cs"));
        Assert.Contains("CngKeyOpenOptions.None", source, StringComparison.Ordinal);
        Assert.Contains("CngKeyCreationOptions.None", source, StringComparison.Ordinal);
        Assert.Contains("CngAlgorithm.ECDsaP256", source, StringComparison.Ordinal);
        Assert.Contains("CngExportPolicies.None", source, StringComparison.Ordinal);
        Assert.Contains("CngKeyUsages.Signing", source, StringComparison.Ordinal);
        Assert.Contains("ExportSubjectPublicKeyInfo", source, StringComparison.Ordinal);
        Assert.Contains("WindowsIdentity.GetCurrent().User", source, StringComparison.Ordinal);
        Assert.Contains("runtime-deployment-p31-key\\public-key.json", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ExportPkcs8PrivateKey", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ExportECPrivateKey", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Process.Start", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ControlService", source, StringComparison.Ordinal);
    }

    [Fact]
    public void ApprovalBridge_CanOnlyChainFixedSignerThenAuthorizer()
    {
        var source = File.ReadAllText(Source("YowThi.RuntimeDeploymentApprovalBridge", "Program.cs"));
        Assert.Contains("deploymentEnabled", source, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("SignerKey.Provisioned", source, StringComparison.Ordinal);
        Assert.Contains("ApprovalBridge.Provisioned", source, StringComparison.Ordinal);
        Assert.Contains("TryFindSingleEligibleRequest", source, StringComparison.Ordinal);
        Assert.Contains("FindSingleEligibleBootstrapRequest", source, StringComparison.Ordinal);
        Assert.Contains("MessageBoxButtons.YesNo", source, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeDeploymentSigner.exe", source, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeDeploymentAuthorizer.exe", source, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeDeploymentExecutor.exe", source, StringComparison.Ordinal);
        Assert.Contains("RunFixedChild(SignerExe", source, StringComparison.Ordinal);
        Assert.Contains("RunFixedChild(AuthorizerExe", source, StringComparison.Ordinal);
        Assert.DoesNotContain("RunFixedChild(ExecutorExe", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ControlService", source, StringComparison.Ordinal);
        Assert.DoesNotContain("StartService", source, StringComparison.Ordinal);
        Assert.DoesNotContain("runtime_handoff_activate", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(".agent3-handoff\\ready", source, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BootstrapPromotion_RequiresInteractiveYesBeforeP27RequestWrite()
    {
        var source = File.ReadAllText(Source("YowThi.RuntimeDeploymentApprovalBridge", "Program.cs"));
        Assert.Contains("\\.agent3-lifecycle\\pending", source, StringComparison.Ordinal);
        Assert.Contains("agent-lifecycle-transition-request", source, StringComparison.Ordinal);
        Assert.Contains("request-only", source, StringComparison.Ordinal);
        Assert.Contains("request.ProcessAuthorization", source, StringComparison.Ordinal);
        Assert.Contains("!request.RequiresSeparateRuntimePlans", source, StringComparison.Ordinal);
        Assert.Contains("CreateDeploymentRequestFromBootstrap", source, StringComparison.Ordinal);
        Assert.Contains("RequiresDedicatedSupervisorExecutor", source, StringComparison.Ordinal);

        var confirm = source.IndexOf("ConfirmDeployment(releaseName", StringComparison.Ordinal);
        var create = source.IndexOf("CreateDeploymentRequestFromBootstrap(", confirm + 1, StringComparison.Ordinal);
        var write = source.IndexOf("WriteCreateNewJson(requestPath, generated)", create + 1, StringComparison.Ordinal);
        Assert.True(confirm >= 0, "Bootstrap confirmation call is missing.");
        Assert.True(create > confirm, "P27 request promotion must occur only after interactive confirmation.");
        Assert.True(write > create, "P27 request bytes must be written only inside the post-confirmation bootstrap promotion path.");
    }

    [Fact]
    public void BootstrapPromotion_RevalidatesSourceAndActiveIdentityBeforeP27Write()
    {
        var source = File.ReadAllText(Source("YowThi.RuntimeDeploymentApprovalBridge", "Program.cs"));
        Assert.Contains("Bootstrap lifecycle request changed during interactive approval", source, StringComparison.Ordinal);
        Assert.Contains("Bootstrap lifecycle request identity changed during interactive approval", source, StringComparison.Ordinal);
        Assert.Contains("ReadActiveState()", source, StringComparison.Ordinal);
        Assert.Contains("ValidateBootstrapTransitionRequest(bootstrap, bootstrapPath, active)", source, StringComparison.Ordinal);
        Assert.Contains("A deployment request appeared during interactive bootstrap approval", source, StringComparison.Ordinal);
        Assert.Contains("Path.GetFullPath(SupervisorExe)", source, StringComparison.Ordinal);
        Assert.Contains("now.AddMinutes(5)", source, StringComparison.Ordinal);
        Assert.Contains("false,\n            true,", source, StringComparison.Ordinal);
        Assert.Contains("Generated P27 deployment request failed post-write identity readback", source, StringComparison.Ordinal);
    }

    [Fact]
    public void P31Schemas_BindCurrentUserKeyAndActivatedPackage()
    {
        var receipt = File.ReadAllText(Root("P31-RUNTIME-DEPLOYMENT-KEY-RECEIPT.schema.json"));
        Assert.Contains("\"keyId\": { \"const\": \"p31-runtime-deployment-signer-user-v1\" }", receipt, StringComparison.Ordinal);
        Assert.Contains("\"keyScope\": { \"const\": \"CurrentUser\" }", receipt, StringComparison.Ordinal);
        Assert.Contains("\"privateKeyExportable\": { \"const\": false }", receipt, StringComparison.Ordinal);
        Assert.Contains("\"publicKeySpkiBase64\"", receipt, StringComparison.Ordinal);

        var package = File.ReadAllText(Root("P31-RUNTIME-DEPLOYMENT-ACTIVATED-PACKAGE.schema.json"));
        Assert.Contains("\"schemaVersion\": { \"const\": 2 }", package, StringComparison.Ordinal);
        Assert.Contains("\"deploymentEnabled\": { \"const\": true }", package, StringComparison.Ordinal);
        Assert.Contains("\"provisioned\": { \"const\": true }", package, StringComparison.Ordinal);
        Assert.Contains("p31-runtime-deployment-signer-user-v1", package, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeDeploymentApprovalBridge.exe", package, StringComparison.Ordinal);
    }

    [Fact]
    public void P29ApprovalIdentity_IsUpdatedToCurrentUserSigner()
    {
        var gate = File.ReadAllText(Source("YowThi.RuntimeDeploymentAuthorizer", "ApprovalSignatureGate.cs"));
        var schema = File.ReadAllText(Root("P29-RUNTIME-DEPLOYMENT-APPROVAL.schema.json"));
        Assert.Contains("p31-runtime-deployment-signer-user-v1", gate, StringComparison.Ordinal);
        Assert.Contains("p31-runtime-deployment-signer-user-v1", schema, StringComparison.Ordinal);
        Assert.DoesNotContain("p30-runtime-deployment-signer-v1", gate, StringComparison.Ordinal);
    }

    [Fact]
    public void Workflow_BuildsBridgeAndKeyProvisioner()
    {
        var workflow = File.ReadAllText(Root(Path.Combine(".github", "workflows", "dotnet.yml")));
        Assert.Contains("deployment-approval-bridge-build:", workflow, StringComparison.Ordinal);
        Assert.Contains("deployment-key-provisioner-build:", workflow, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeDeploymentApprovalBridge\\YowThi.RuntimeDeploymentApprovalBridge.csproj", workflow, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeDeploymentKeyProvisioner\\YowThi.RuntimeDeploymentKeyProvisioner.csproj", workflow, StringComparison.Ordinal);
    }

    private static string Source(string project, string file) => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", project, file));
    private static string Root(string relative) => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", relative));
}
