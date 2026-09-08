using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class RuntimeDeploymentSignerContractTests
{
    [Fact]
    public void ApprovalBridgeParentGuard_IsFailClosedUntilP31BridgeIsProvisioned()
    {
        var source = ReadSignerSource("ApprovalBridgeParentGuard.cs");

        Assert.Contains("[ModuleInitializer]", source, StringComparison.Ordinal);
        Assert.Contains("C:\\ProgramData\\YowThi\\RuntimeDeployment\\YowThi.RuntimeDeploymentApprovalBridge.exe", source, StringComparison.Ordinal);
        Assert.Contains("ExpectedApprovalBridgeExeSha256", source, StringComparison.Ordinal);
        Assert.Contains("0000000000000000000000000000000000000000000000000000000000000000", source, StringComparison.Ordinal);
        Assert.Contains("approval bridge identity is not provisioned", source, StringComparison.Ordinal);
        Assert.Contains("NtQueryInformationProcess", source, StringComparison.Ordinal);
        Assert.Contains("SHA-256 does not match the provisioned identity", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Process.Start", source, StringComparison.Ordinal);
        Assert.DoesNotContain(".Kill(", source, StringComparison.Ordinal);
    }

    [Fact]
    public void SigningKeyGate_UsesNonExportableMachineScopedCngEcdsaP256AndFailsClosed()
    {
        var source = ReadSignerSource("SigningKeyGate.cs");

        Assert.Contains("YowThiRuntimeDeploymentSignerV1", source, StringComparison.Ordinal);
        Assert.Contains("p30-runtime-deployment-signer-v1", source, StringComparison.Ordinal);
        Assert.Contains("CngProvider.MicrosoftSoftwareKeyStorageProvider", source, StringComparison.Ordinal);
        Assert.Contains("CngKeyOpenOptions.MachineKey", source, StringComparison.Ordinal);
        Assert.Contains("CngExportPolicies.AllowExport", source, StringComparison.Ordinal);
        Assert.Contains("CngExportPolicies.AllowPlaintextExport", source, StringComparison.Ordinal);
        Assert.Contains("new ECDsaCng(key)", source, StringComparison.Ordinal);
        Assert.Contains("ecdsa.KeySize != 256", source, StringComparison.Ordinal);
        Assert.Contains("ExportSubjectPublicKeyInfo", source, StringComparison.Ordinal);
        Assert.Contains("0000000000000000000000000000000000000000000000000000000000000000", source, StringComparison.Ordinal);
        Assert.Contains("signer key identity is not provisioned", source, StringComparison.Ordinal);
    }

    [Fact]
    public void Signer_BindsP27RequestAndInstalledExecutorAndOnlyWritesSignedApproval()
    {
        var source = ReadSignerSource("Program.cs");

        Assert.Contains("\\signing-intents", source, StringComparison.Ordinal);
        Assert.Contains("\\approvals", source, StringComparison.Ordinal);
        Assert.Contains("request.ProcessAuthorization", source, StringComparison.Ordinal);
        Assert.Contains("!request.RequiresDedicatedSupervisorExecutor", source, StringComparison.Ordinal);
        Assert.Contains("intent.RequestSha256", source, StringComparison.Ordinal);
        Assert.Contains("intent.ExecutorSha256", source, StringComparison.Ordinal);
        Assert.Contains("C:\\ProgramData\\YowThi\\RuntimeDeployment\\YowThi.RuntimeDeploymentExecutor.exe", source, StringComparison.Ordinal);
        Assert.Contains("SigningKeyGate.OpenValidatedSigner()", source, StringComparison.Ordinal);
        Assert.Contains("signer.SignData", source, StringComparison.Ordinal);
        Assert.Contains("HashAlgorithmName.SHA256", source, StringComparison.Ordinal);
        Assert.Contains("WriteCreateNewJson(approvalPath, approval)", source, StringComparison.Ordinal);

        Assert.DoesNotContain("Process.Start", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ControlService", source, StringComparison.Ordinal);
        Assert.DoesNotContain("StartService", source, StringComparison.Ordinal);
        Assert.DoesNotContain(".Kill(", source, StringComparison.Ordinal);
        Assert.DoesNotContain(".agent3-handoff", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("776317640d1948cb80afa47c7149c852", source, StringComparison.Ordinal);
    }

    [Fact]
    public void P30CanonicalPayload_MatchesP29ApprovalVerifierFieldOrder()
    {
        var signer = ReadSignerSource("Program.cs");
        var authorizerGate = File.ReadAllText(Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..",
            "YowThi.RuntimeDeploymentAuthorizer", "ApprovalSignatureGate.cs")));

        var fragments = new[]
        {
            "schemaVersion=",
            "approvalId=",
            "requestId=",
            "requestSha256=",
            "executorSha256=",
            "signerKeyId=",
            "issuedUtc=",
            "expiresUtc=",
            "nonce=",
            "action=runtime-deploy"
        };

        var signerPosition = -1;
        var verifierPosition = -1;
        foreach (var fragment in fragments)
        {
            var nextSigner = signer.IndexOf(fragment, signerPosition + 1, StringComparison.Ordinal);
            var nextVerifier = authorizerGate.IndexOf(fragment, verifierPosition + 1, StringComparison.Ordinal);
            Assert.True(nextSigner > signerPosition, $"Signer canonical payload is missing or reorders {fragment}.");
            Assert.True(nextVerifier > verifierPosition, $"P29 verifier canonical payload is missing or reorders {fragment}.");
            signerPosition = nextSigner;
            verifierPosition = nextVerifier;
        }
    }

    [Fact]
    public void P30Schemas_RemainExplicitlyNonActivating()
    {
        var intentSchema = File.ReadAllText(RootFile("P30-RUNTIME-DEPLOYMENT-SIGNING-INTENT.schema.json"));
        Assert.Contains("\"action\": { \"const\": \"runtime-deploy\" }", intentSchema, StringComparison.Ordinal);
        Assert.Contains("\"requestSha256\"", intentSchema, StringComparison.Ordinal);
        Assert.Contains("\"executorSha256\"", intentSchema, StringComparison.Ordinal);
        Assert.Contains("\"additionalProperties\": false", intentSchema, StringComparison.Ordinal);

        var packageSchema = File.ReadAllText(RootFile("P30-RUNTIME-DEPLOYMENT-PACKAGE.schema.json"));
        Assert.Contains("\"deploymentEnabled\": { \"const\": false }", packageSchema, StringComparison.Ordinal);
        Assert.Contains("\"provisioned\": { \"const\": false }", packageSchema, StringComparison.Ordinal);
        Assert.Contains("YowThiRuntimeDeploymentSignerV1", packageSchema, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeDeploymentApprovalBridge.exe", packageSchema, StringComparison.Ordinal);
    }

    [Fact]
    public void P28AndP29Guards_RemainUnprovisionedDuringP30()
    {
        var p28 = File.ReadAllText(Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..",
            "YowThi.RuntimeDeploymentExecutor", "AuthorizerParentGuard.cs")));
        var p29 = File.ReadAllText(Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..",
            "YowThi.RuntimeDeploymentAuthorizer", "ApprovalSignatureGate.cs")));

        const string zero = "0000000000000000000000000000000000000000000000000000000000000000";
        Assert.Contains(zero, p28, StringComparison.Ordinal);
        Assert.Contains("authorizer identity is not provisioned", p28, StringComparison.Ordinal);
        Assert.Contains(zero, p29, StringComparison.Ordinal);
        Assert.Contains("SignerPublicKeySpkiBase64 = \"\"", p29, StringComparison.Ordinal);
        Assert.Contains("approval signer is not provisioned", p29, StringComparison.Ordinal);
    }

    [Fact]
    public void Workflow_ExplicitlyBuildsRuntimeDeploymentSigner()
    {
        var workflow = File.ReadAllText(RootFile(Path.Combine(".github", "workflows", "dotnet.yml")));
        Assert.Contains("deployment-signer-build:", workflow, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeDeploymentSigner\\YowThi.RuntimeDeploymentSigner.csproj", workflow, StringComparison.Ordinal);
        Assert.Contains("runs-on: [self-hosted, yowthi-erp-dev-v4]", workflow, StringComparison.Ordinal);
    }

    private static string ReadSignerSource(string fileName)
        => File.ReadAllText(Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..",
            "YowThi.RuntimeDeploymentSigner", fileName)));

    private static string RootFile(string relative)
        => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", relative));
}
