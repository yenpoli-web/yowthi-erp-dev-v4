using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class RuntimeDeploymentSignerContractTests
{
    private const string SignerSpkiSha = "3794BFF6F3FEB5B64F58A85F1CD9E4C526ACBFBDF2B51E25A27CEAF88124981A";
    private const string BridgeSha = "9FF4EAF2A642DEF2013ACF2356440E7B51B24A476303E7D91B1228D250337EF5";
    private const string AuthorizerSha = "7BD1F5AEFD057B06E420C2A4E20E7A3BB5A3A9F28C9A0AE324AF4F19A11E9AFE";

    [Fact]
    public void ApprovalBridgeParentGuard_IsPinnedToReviewedP31Bridge()
    {
        var source = ReadSignerSource("ApprovalBridgeParentGuard.cs");
        Assert.Contains("[ModuleInitializer]", source, StringComparison.Ordinal);
        Assert.Contains("C:\\ProgramData\\YowThi\\RuntimeDeployment\\YowThi.RuntimeDeploymentApprovalBridge.exe", source, StringComparison.Ordinal);
        Assert.Contains(BridgeSha, source, StringComparison.Ordinal);
        Assert.Contains("NtQueryInformationProcess", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ExpectedApprovalBridgeExeSha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Process.Start", source, StringComparison.Ordinal);
        Assert.DoesNotContain(".Kill(", source, StringComparison.Ordinal);
    }

    [Fact]
    public void SigningKeyGate_UsesPinnedNonExportableCurrentUserCngEcdsaP256()
    {
        var source = ReadSignerSource("SigningKeyGate.cs");
        Assert.Contains("YowThiRuntimeDeploymentSignerV1", source, StringComparison.Ordinal);
        Assert.Contains("p31-runtime-deployment-signer-user-v1", source, StringComparison.Ordinal);
        Assert.Contains("CngProvider.MicrosoftSoftwareKeyStorageProvider", source, StringComparison.Ordinal);
        Assert.Contains("CngKeyOpenOptions.None", source, StringComparison.Ordinal);
        Assert.DoesNotContain("CngKeyOpenOptions.MachineKey", source, StringComparison.Ordinal);
        Assert.Contains("CngExportPolicies.AllowExport", source, StringComparison.Ordinal);
        Assert.Contains("CngExportPolicies.AllowPlaintextExport", source, StringComparison.Ordinal);
        Assert.Contains("new ECDsaCng(key)", source, StringComparison.Ordinal);
        Assert.Contains("ecdsa.KeySize != 256", source, StringComparison.Ordinal);
        Assert.Contains("ExportSubjectPublicKeyInfo", source, StringComparison.Ordinal);
        Assert.Contains(SignerSpkiSha, source, StringComparison.Ordinal);
        Assert.DoesNotContain("ExpectedSignerSpkiSha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"", source, StringComparison.Ordinal);
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
    }

    [Fact]
    public void P30CanonicalPayload_MatchesP29ApprovalVerifierFieldOrder()
    {
        var signer = ReadSignerSource("Program.cs");
        var authorizerGate = File.ReadAllText(Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "YowThi.RuntimeDeploymentAuthorizer", "ApprovalSignatureGate.cs")));
        var fragments = new[] { "schemaVersion=", "approvalId=", "requestId=", "requestSha256=", "executorSha256=", "signerKeyId=", "issuedUtc=", "expiresUtc=", "nonce=", "action=runtime-deploy" };
        var signerPosition = -1;
        var verifierPosition = -1;
        foreach (var fragment in fragments)
        {
            var nextSigner = signer.IndexOf(fragment, signerPosition + 1, StringComparison.Ordinal);
            var nextVerifier = authorizerGate.IndexOf(fragment, verifierPosition + 1, StringComparison.Ordinal);
            Assert.True(nextSigner > signerPosition);
            Assert.True(nextVerifier > verifierPosition);
            signerPosition = nextSigner;
            verifierPosition = nextVerifier;
        }
    }

    [Fact]
    public void P30Schemas_RemainExplicitlyNonActivating()
    {
        var intentSchema = File.ReadAllText(RootFile("P30-RUNTIME-DEPLOYMENT-SIGNING-INTENT.schema.json"));
        Assert.Contains("\"action\": { \"const\": \"runtime-deploy\" }", intentSchema, StringComparison.Ordinal);
        Assert.Contains("\"additionalProperties\": false", intentSchema, StringComparison.Ordinal);
        var packageSchema = File.ReadAllText(RootFile("P30-RUNTIME-DEPLOYMENT-PACKAGE.schema.json"));
        Assert.Contains("\"deploymentEnabled\": { \"const\": false }", packageSchema, StringComparison.Ordinal);
        Assert.Contains("\"provisioned\": { \"const\": false }", packageSchema, StringComparison.Ordinal);
    }

    [Fact]
    public void P28AndP29Guards_ArePinnedToProvisionedP31Identities()
    {
        var p28 = File.ReadAllText(Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "YowThi.RuntimeDeploymentExecutor", "AuthorizerParentGuard.cs")));
        var p29 = File.ReadAllText(Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "YowThi.RuntimeDeploymentAuthorizer", "ApprovalSignatureGate.cs")));
        Assert.Contains(AuthorizerSha, p28, StringComparison.Ordinal);
        Assert.Contains(SignerSpkiSha, p29, StringComparison.Ordinal);
        Assert.Contains("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD", p29, StringComparison.Ordinal);
        Assert.Contains("p31-runtime-deployment-signer-user-v1", p29, StringComparison.Ordinal);
    }

    [Fact]
    public void Workflow_ExplicitlyBuildsRuntimeDeploymentSigner()
    {
        var workflow = File.ReadAllText(RootFile(Path.Combine(".github", "workflows", "dotnet.yml")));
        Assert.Contains("deployment-signer-build:", workflow, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeDeploymentSigner\\YowThi.RuntimeDeploymentSigner.csproj", workflow, StringComparison.Ordinal);
    }

    private static string ReadSignerSource(string fileName) => File.ReadAllText(Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "YowThi.RuntimeDeploymentSigner", fileName)));
    private static string RootFile(string relative) => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", relative));
}
