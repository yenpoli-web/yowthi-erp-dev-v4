using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class RuntimeDeploymentManagedPayloadIdentityContractTests
{
    private const string BridgeExeSha = "D5DBDC7F12FEA22C0DBB140D0809381F70754DAC3BECA02F83519EFA74CA431B";
    private const string BridgeDllSha = "8E9BA46CB8BC950475AA01612DE7C24C104B06D3B0B74EA6C19E3A6EC6C20E99";
    private const string AuthorizerExeSha = "61587C8AE9A58BDA0BD68199A99FBD4D60A544E70690730127E81F57FBF3408E";
    private const string AuthorizerDllSha = "CB9A4EA443CD98E33AFE7AD8BD81B05C5AF827DD35281253F5DBB4BB87B744A6";

    [Fact]
    public void ActivatedPackageV3_RequiresExeAndManagedDllIdentityForEveryComponent()
    {
        var schema = File.ReadAllText(Root("P31-RUNTIME-DEPLOYMENT-ACTIVATED-PACKAGE.schema.json"));
        Assert.Contains("\"schemaVersion\": { \"const\": 3 }", schema, StringComparison.Ordinal);
        Assert.Contains("\"required\": [\"name\",\"installFileName\",\"exeSha256\",\"managedDllFileName\",\"managedDllSha256\"]", schema, StringComparison.Ordinal);
        Assert.Contains("\"managedDllFileName\": { \"const\": \"YowThi.RuntimeDeploymentApprovalBridge.dll\" }", schema, StringComparison.Ordinal);
        Assert.Contains("\"managedDllSha256\"", schema, StringComparison.Ordinal);

        var bridge = File.ReadAllText(Source("YowThi.RuntimeDeploymentApprovalBridge", "Program.cs"));
        Assert.Contains("package.SchemaVersion != 3", bridge, StringComparison.Ordinal);
        Assert.Contains("ValidateInstalledComponent(SignerExe", bridge, StringComparison.Ordinal);
        Assert.Contains("ValidateInstalledComponent(AuthorizerExe", bridge, StringComparison.Ordinal);
        Assert.Contains("ValidateInstalledComponent(ExecutorExe", bridge, StringComparison.Ordinal);
        Assert.Contains("component.ManagedDllSha256", bridge, StringComparison.Ordinal);
        Assert.Contains("package.ApprovalBridge.ManagedDllSha256", bridge, StringComparison.Ordinal);
    }

    [Fact]
    public void SignedChain_BindsExecutorExeAndDllFromIntentThroughAuthorization()
    {
        var bridge = File.ReadAllText(Source("YowThi.RuntimeDeploymentApprovalBridge", "Program.cs"));
        var signer = File.ReadAllText(Source("YowThi.RuntimeDeploymentSigner", "Program.cs"));
        var verifier = File.ReadAllText(Source("YowThi.RuntimeDeploymentAuthorizer", "ApprovalSignatureGate.cs"));
        var authorizer = File.ReadAllText(Source("YowThi.RuntimeDeploymentAuthorizer", "Program.cs"));

        Assert.Contains("executor.ManagedDllSha256", bridge, StringComparison.Ordinal);
        Assert.Contains("intent.ExecutorDllSha256", signer, StringComparison.Ordinal);
        Assert.Contains("executorDllSha256=", signer, StringComparison.Ordinal);
        Assert.Contains("executorDllSha256=", verifier, StringComparison.Ordinal);
        Assert.Contains("approval.ExecutorDllSha256", authorizer, StringComparison.Ordinal);
        Assert.Contains("ExecutorDllSha256", authorizer, StringComparison.Ordinal);

        foreach (var schemaName in new[]
        {
            "P30-RUNTIME-DEPLOYMENT-SIGNING-INTENT.schema.json",
            "P29-RUNTIME-DEPLOYMENT-APPROVAL.schema.json",
            "P28-RUNTIME-DEPLOYMENT-AUTHORIZATION.schema.json"
        })
        {
            var schema = File.ReadAllText(Root(schemaName));
            Assert.Contains("\"executorSha256\"", schema, StringComparison.Ordinal);
            Assert.Contains("\"executorDllSha256\"", schema, StringComparison.Ordinal);
            Assert.Contains("\"additionalProperties\": false", schema, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ParentGuards_BindBridgeAndAuthorizerManagedPayloads()
    {
        var signerGuard = File.ReadAllText(Source("YowThi.RuntimeDeploymentSigner", "ApprovalBridgeParentGuard.cs"));
        Assert.Contains(BridgeExeSha, signerGuard, StringComparison.Ordinal);
        Assert.Contains(BridgeDllSha, signerGuard, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeDeploymentApprovalBridge.exe", signerGuard, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeDeploymentApprovalBridge.dll", signerGuard, StringComparison.Ordinal);
        Assert.Contains("ValidatePinnedFile", signerGuard, StringComparison.Ordinal);

        var executorGuard = File.ReadAllText(Source("YowThi.RuntimeDeploymentExecutor", "AuthorizerParentGuard.cs"));
        Assert.Contains(AuthorizerExeSha, executorGuard, StringComparison.Ordinal);
        Assert.Contains(AuthorizerDllSha, executorGuard, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeDeploymentAuthorizer.exe", executorGuard, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeDeploymentAuthorizer.dll", executorGuard, StringComparison.Ordinal);
        Assert.Contains("ValidatePinnedFile", executorGuard, StringComparison.Ordinal);
    }

    [Fact]
    public void ExecutorModuleInitializer_RequiresSignedOwnExeAndDllBeforeMain()
    {
        var gate = File.ReadAllText(Source("YowThi.RuntimeDeploymentExecutor", "ManagedPayloadAuthorizationGate.cs"));
        Assert.Contains("[ModuleInitializer]", gate, StringComparison.Ordinal);
        Assert.Contains("Environment.GetCommandLineArgs()", gate, StringComparison.Ordinal);
        Assert.Contains("args.Length != 2", gate, StringComparison.Ordinal);
        Assert.Contains("\\.runtime-supervisor-deployment\\authorized", gate, StringComparison.Ordinal);
        Assert.Contains("authorization.ProcessAuthorization", gate, StringComparison.Ordinal);
        Assert.Contains("authorization.ExecutorSha256", gate, StringComparison.Ordinal);
        Assert.Contains("authorization.ExecutorDllSha256", gate, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeDeploymentExecutor.exe", gate, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeDeploymentExecutor.dll", gate, StringComparison.Ordinal);
        Assert.Contains("Environment.ProcessPath", gate, StringComparison.Ordinal);
        Assert.Contains("authorization.ExpiresUtc <= DateTimeOffset.UtcNow", gate, StringComparison.Ordinal);
        Assert.Contains("FileAttributes.ReparsePoint", gate, StringComparison.Ordinal);
        Assert.DoesNotContain("Process.Start", gate, StringComparison.Ordinal);
        Assert.DoesNotContain("ControlService", gate, StringComparison.Ordinal);
        Assert.DoesNotContain("StartService", gate, StringComparison.Ordinal);
    }

    private static string Source(string project, string file) => Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", project, file));

    private static string Root(string relative) => Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", "..", relative));
}
