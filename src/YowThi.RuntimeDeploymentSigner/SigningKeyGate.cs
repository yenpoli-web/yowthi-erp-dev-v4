using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace YowThi.RuntimeDeploymentSigner;

internal static class SigningKeyGate
{
    internal const string KeyName = "YowThiRuntimeDeploymentSignerV1";
    internal const string SignerKeyId = "p31-runtime-deployment-signer-user-v1";

    // Provisioned P31 CurrentUser ECDSA P-256 public identity.
    internal const string ExpectedSignerSpkiSha256 = "3794BFF6F3FEB5B64F58A85F1CD9E4C526ACBFBDF2B51E25A27CEAF88124981A";

    [ModuleInitializer]
    internal static void ValidateAtModuleLoad()
    {
        if (ExpectedSignerSpkiSha256.All(ch => ch == '0'))
            throw new UnauthorizedAccessException("Runtime deployment signer key identity is not provisioned.");

        using var ecdsa = OpenValidatedSigner();
        var spki = ecdsa.ExportSubjectPublicKeyInfo();
        var actualSha = Convert.ToHexString(SHA256.HashData(spki));
        if (!string.Equals(actualSha, ExpectedSignerSpkiSha256, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Runtime deployment signer SPKI SHA-256 does not match the provisioned identity.");
    }

    internal static ECDsa OpenValidatedSigner()
    {
        var key = CngKey.Open(
            KeyName,
            CngProvider.MicrosoftSoftwareKeyStorageProvider,
            CngKeyOpenOptions.None);

        var algorithmGroup = key.AlgorithmGroup?.AlgorithmGroup ?? string.Empty;
        if (!string.Equals(algorithmGroup, CngAlgorithmGroup.ECDsa.AlgorithmGroup, StringComparison.OrdinalIgnoreCase))
        {
            key.Dispose();
            throw new UnauthorizedAccessException("Runtime deployment signer key must belong to the ECDSA algorithm group.");
        }

        if ((key.ExportPolicy & (CngExportPolicies.AllowExport | CngExportPolicies.AllowPlaintextExport)) != 0)
        {
            key.Dispose();
            throw new UnauthorizedAccessException("Runtime deployment signer private key must be non-exportable.");
        }

        var ecdsa = new ECDsaCng(key);
        if (ecdsa.KeySize != 256)
        {
            ecdsa.Dispose();
            throw new UnauthorizedAccessException("Runtime deployment signer key must be ECDSA P-256.");
        }

        var spki = ecdsa.ExportSubjectPublicKeyInfo();
        var actualSha = Convert.ToHexString(SHA256.HashData(spki));
        if (!string.Equals(actualSha, ExpectedSignerSpkiSha256, StringComparison.OrdinalIgnoreCase))
        {
            ecdsa.Dispose();
            throw new UnauthorizedAccessException("Runtime deployment signer SPKI SHA-256 changed after provisioning.");
        }

        return ecdsa;
    }
}
