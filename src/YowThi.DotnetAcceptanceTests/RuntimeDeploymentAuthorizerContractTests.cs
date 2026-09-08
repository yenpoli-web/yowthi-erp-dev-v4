using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class RuntimeDeploymentAuthorizerContractTests
{
    [Fact]
    public void ApprovalSignatureGate_IsEcdsaP256AndFailClosedUntilInteractiveProvisioning()
    {
        var source = ReadAuthorizerSource("ApprovalSignatureGate.cs");
        Assert.Contains("[ModuleInitializer]", source, StringComparison.Ordinal);
        Assert.Contains("SignerPublicKeySpkiBase64 = \"\"", source, StringComparison.Ordinal);
        Assert.Contains("0000000000000000000000000000000000000000000000000000000000000000", source, StringComparison.Ordinal);
        Assert.Contains("Runtime deployment approval signer is not provisioned", source, StringComparison.Ordinal);
        Assert.Contains("ECDsa.Create()", source, StringComparison.Ordinal);
        Assert.Contains("ImportSubjectPublicKeyInfo", source, StringComparison.Ordinal);
        Assert.Contains("ecdsa.KeySize != 256", source, StringComparison.Ordinal);
        Assert.Contains("VerifyData", source, StringComparison.Ordinal);
        Assert.Contains("HashAlgorithmName.SHA256", source, StringComparison.Ordinal);
        Assert.Contains("action=runtime-deploy", source, StringComparison.Ordinal);
        Assert.Contains("p31-runtime-deployment-signer-user-v1", source, StringComparison.Ordinal);
    }

    [Fact]
    public void Authorizer_BindsP27RequestAndCanLaunchOnlyFixedP28Executor()
    {
        var source = ReadAuthorizerSource("Program.cs");
        Assert.Contains(".runtime-supervisor-deployment", source, StringComparison.Ordinal);
        Assert.Contains("\\approvals", source, StringComparison.Ordinal);
        Assert.Contains("request.ProcessAuthorization", source, StringComparison.Ordinal);
        Assert.Contains("!request.RequiresDedicatedSupervisorExecutor", source, StringComparison.Ordinal);
        Assert.Contains("approval.RequestSha256", source, StringComparison.Ordinal);
        Assert.Contains("approval.ExecutorSha256", source, StringComparison.Ordinal);
        Assert.Contains("processAuthorization", source, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("C:\\ProgramData\\YowThi\\RuntimeDeployment\\YowThi.RuntimeDeploymentExecutor.exe", source, StringComparison.Ordinal);
        Assert.Contains("FileName = ExecutorExe", source, StringComparison.Ordinal);
        Assert.Contains("start.ArgumentList.Add(authorizationPath)", source, StringComparison.Ordinal);
        Assert.Contains("ValidateActiveState(active, request)", source, StringComparison.Ordinal);
        Assert.Contains("ValidateRuntimeFile(request.TargetRuntimeDll", source, StringComparison.Ordinal);
        Assert.Contains("ValidateFixedExecutable(SupervisorExe", source, StringComparison.Ordinal);
        Assert.Contains("ValidateFixedExecutable(ExecutorExe", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ControlService", source, StringComparison.Ordinal);
        Assert.DoesNotContain("StartService", source, StringComparison.Ordinal);
        Assert.DoesNotContain(".Kill(", source, StringComparison.Ordinal);
    }

    [Fact]
    public void ApprovalSchema_BindsRequestExecutorUserScopedSignerNonceAndSignature()
    {
        var schema = File.ReadAllText(RootFile("P29-RUNTIME-DEPLOYMENT-APPROVAL.schema.json"));
        Assert.Contains("\"requestSha256\"", schema, StringComparison.Ordinal);
        Assert.Contains("\"executorSha256\"", schema, StringComparison.Ordinal);
        Assert.Contains("\"signerKeyId\": { \"const\": \"p31-runtime-deployment-signer-user-v1\" }", schema, StringComparison.Ordinal);
        Assert.Contains("\"nonce\"", schema, StringComparison.Ordinal);
        Assert.Contains("\"signatureBase64\"", schema, StringComparison.Ordinal);
        Assert.Contains("\"additionalProperties\": false", schema, StringComparison.Ordinal);
    }

    [Fact]
    public void P28ParentGuard_RemainsUnprovisionedUntilVerifiedAuthorizerArtifactExists()
    {
        var guard = File.ReadAllText(Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "YowThi.RuntimeDeploymentExecutor", "AuthorizerParentGuard.cs")));
        Assert.Contains("YowThi.RuntimeDeploymentAuthorizer.exe", guard, StringComparison.Ordinal);
        Assert.Contains("0000000000000000000000000000000000000000000000000000000000000000", guard, StringComparison.Ordinal);
        Assert.Contains("authorizer identity is not provisioned", guard, StringComparison.Ordinal);
    }

    [Fact]
    public void Workflow_ExplicitlyBuildsIndependentRuntimeDeploymentAuthorizer()
    {
        var workflow = File.ReadAllText(RootFile(Path.Combine(".github", "workflows", "dotnet.yml")));
        Assert.Contains("deployment-authorizer-build:", workflow, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeDeploymentAuthorizer\\YowThi.RuntimeDeploymentAuthorizer.csproj", workflow, StringComparison.Ordinal);
    }

    private static string ReadAuthorizerSource(string fileName) => File.ReadAllText(Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "YowThi.RuntimeDeploymentAuthorizer", fileName)));
    private static string RootFile(string relative) => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", relative));
}
