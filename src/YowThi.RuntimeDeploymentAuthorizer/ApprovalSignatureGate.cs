using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace YowThi.RuntimeDeploymentAuthorizer;

internal static class ApprovalSignatureGate
{
    internal const string SignerPublicKeySpkiBase64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0GHtzp/155RJBbOS7r02kOsVvNlsjcIpl0xiRNXWfb6fQPZa/Q8qvYkILE5CX10vO+W+66icuwR3APuhQzaRaw==";
    internal const string ExpectedSignerSpkiSha256 = "3794BFF6F3FEB5B64F58A85F1CD9E4C526ACBFBDF2B51E25A27CEAF88124981A";
    internal const string SignerKeyId = "p31-runtime-deployment-signer-user-v1";

    [ModuleInitializer]
    internal static void ValidateProvisioningAtModuleLoad()
    {
        if (ExpectedSignerSpkiSha256.All(ch => ch == '0') || string.IsNullOrWhiteSpace(SignerPublicKeySpkiBase64))
            throw new UnauthorizedAccessException("Runtime deployment approval signer is not provisioned.");

        var spki = Convert.FromBase64String(SignerPublicKeySpkiBase64);
        var actualSha = Convert.ToHexString(SHA256.HashData(spki));
        if (!string.Equals(actualSha, ExpectedSignerSpkiSha256, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Runtime deployment signer SPKI SHA-256 does not match the provisioned identity.");

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(spki, out var bytesRead);
        if (bytesRead != spki.Length || ecdsa.KeySize != 256)
            throw new UnauthorizedAccessException("Runtime deployment signer must be exactly one ECDSA P-256 public key.");
    }

    internal static bool Verify(ApprovalEnvelope approval)
    {
        if (!string.Equals(approval.SignerKeyId, SignerKeyId, StringComparison.Ordinal))
            return false;

        var spki = Convert.FromBase64String(SignerPublicKeySpkiBase64);
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(spki, out var bytesRead);
        if (bytesRead != spki.Length || ecdsa.KeySize != 256) return false;

        byte[] signature;
        try { signature = Convert.FromBase64String(approval.SignatureBase64); }
        catch (FormatException) { return false; }

        return ecdsa.VerifyData(BuildCanonicalPayload(approval), signature, HashAlgorithmName.SHA256);
    }

    internal static byte[] BuildCanonicalPayload(ApprovalEnvelope approval)
    {
        var canonical = string.Join("\n",
            "schemaVersion=" + approval.SchemaVersion,
            "approvalId=" + approval.ApprovalId,
            "requestId=" + approval.RequestId,
            "requestSha256=" + approval.RequestSha256.ToUpperInvariant(),
            "executorSha256=" + approval.ExecutorSha256.ToUpperInvariant(),
            "signerKeyId=" + approval.SignerKeyId,
            "issuedUtc=" + approval.IssuedUtc.ToUniversalTime().ToString("O"),
            "expiresUtc=" + approval.ExpiresUtc.ToUniversalTime().ToString("O"),
            "nonce=" + approval.Nonce,
            "action=runtime-deploy") + "\n";
        return Encoding.UTF8.GetBytes(canonical);
    }
}

internal sealed record ApprovalEnvelope(
    int SchemaVersion,
    string ApprovalId,
    string RequestId,
    string RequestSha256,
    string ExecutorSha256,
    string SignerKeyId,
    DateTimeOffset IssuedUtc,
    DateTimeOffset ExpiresUtc,
    string Nonce,
    string SignatureBase64);
