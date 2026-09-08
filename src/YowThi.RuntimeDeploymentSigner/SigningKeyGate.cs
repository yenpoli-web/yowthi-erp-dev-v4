using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace YowThi.RuntimeDeploymentSigner;

internal static class SigningKeyGate
{
    internal const string KeyName = "YowThiRuntimeDeploymentSignerV1";
    internal const string SignerKeyId = "p30-runtime-deployment-signer-v1";

    // P30 intentionally ships without a provisioned signer key. P31 must provision the
    // machine-scoped CNG key and replace this sentinel with its exact public SPKI SHA-256.
    internal const string ExpectedSignerSpkiSha256 = "0000000000000000000000000000000000000000000000000000000000000000";

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
            CngKeyOpenOptions.MachineKey);

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
