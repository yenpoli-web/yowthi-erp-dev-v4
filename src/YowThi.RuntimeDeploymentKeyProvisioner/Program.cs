using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;

namespace YowThi.RuntimeDeploymentKeyProvisioner;

internal static class Program
{
    private const string KeyName = "YowThiRuntimeDeploymentSignerV1";
    private const string KeyId = "p31-runtime-deployment-signer-user-v1";
    private const string ReceiptPath = @"C:\Dev\YowThi-ERP-Dev-v4\acceptance\runtime-deployment-p31-key\public-key.json";
    private static readonly CngProvider Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    [STAThread]
    public static int Main()
    {
        try
        {
            if (MessageBox.Show(
                    "Create or verify the YowThi runtime deployment signing key for the currently logged-in Windows user?\n\nThe private key will be non-exportable and will remain in the CurrentUser CNG key store.",
                    "YowThi Runtime Deployment Key Provisioning",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning,
                    MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                return 2;

            using var key = OpenOrCreateKey();
            using var ecdsa = new ECDsaCng(key);
            ValidateKey(key, ecdsa);

            var spki = ecdsa.ExportSubjectPublicKeyInfo();
            var spkiSha256 = Convert.ToHexString(SHA256.HashData(spki));
            var userSid = WindowsIdentity.GetCurrent().User?.Value
                ?? throw new UnauthorizedAccessException("Current interactive user SID is unavailable.");

            var receipt = new ProvisioningReceipt(
                1,
                KeyName,
                KeyId,
                userSid,
                "CurrentUser",
                "Microsoft Software Key Storage Provider",
                "ECDSA_P256",
                false,
                Convert.ToBase64String(spki),
                spkiSha256,
                DateTimeOffset.UtcNow);

            Directory.CreateDirectory(Path.GetDirectoryName(ReceiptPath)!);
            if (File.Exists(ReceiptPath))
                ValidateExistingReceipt(receipt);
            else
                WriteCreateNew(ReceiptPath, receipt);

            MessageBox.Show(
                "Runtime deployment signing key is provisioned for the current interactive user.\n\nPublic SPKI SHA-256:\n" + spkiSha256,
                "YowThi Key Provisioning Complete",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return 0;
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.GetType().Name + ": " + ex.Message, "YowThi Key Provisioning Failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }

    private static CngKey OpenOrCreateKey()
    {
        if (CngKey.Exists(KeyName, Provider, CngKeyOpenOptions.None))
            return CngKey.Open(KeyName, Provider, CngKeyOpenOptions.None);

        var parameters = new CngKeyCreationParameters
        {
            Provider = Provider,
            KeyCreationOptions = CngKeyCreationOptions.None,
            ExportPolicy = CngExportPolicies.None,
            KeyUsage = CngKeyUsages.Signing
        };
        return CngKey.Create(CngAlgorithm.ECDsaP256, KeyName, parameters);
    }

    private static void ValidateKey(CngKey key, ECDsaCng ecdsa)
    {
        var algorithmGroup = key.AlgorithmGroup?.AlgorithmGroup ?? string.Empty;
        if (!string.Equals(algorithmGroup, CngAlgorithmGroup.ECDsa.AlgorithmGroup, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Provisioned runtime deployment key is not ECDSA.");
        if (ecdsa.KeySize != 256)
            throw new UnauthorizedAccessException("Provisioned runtime deployment key is not ECDSA P-256.");
        if ((key.ExportPolicy & (CngExportPolicies.AllowExport | CngExportPolicies.AllowPlaintextExport)) != 0)
            throw new UnauthorizedAccessException("Provisioned runtime deployment private key is exportable and is therefore rejected.");
        if ((key.KeyUsage & CngKeyUsages.Signing) == 0)
            throw new UnauthorizedAccessException("Provisioned runtime deployment key is not authorized for signing.");
    }

    private static void ValidateExistingReceipt(ProvisioningReceipt expected)
    {
        var existing = JsonSerializer.Deserialize<ProvisioningReceipt>(File.ReadAllBytes(ReceiptPath), JsonOptions)
            ?? throw new InvalidDataException("Existing P31 public-key receipt is invalid.");
        if (existing.SchemaVersion != 1 ||
            !string.Equals(existing.KeyName, expected.KeyName, StringComparison.Ordinal) ||
            !string.Equals(existing.KeyId, expected.KeyId, StringComparison.Ordinal) ||
            !string.Equals(existing.UserSid, expected.UserSid, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(existing.SpkiSha256, expected.SpkiSha256, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(existing.PublicKeySpkiBase64, expected.PublicKeySpkiBase64, StringComparison.Ordinal))
            throw new InvalidOperationException("Existing P31 public-key receipt does not match the CurrentUser CNG key.");
    }

    private static void WriteCreateNew(string path, ProvisioningReceipt value)
    {
        var bytes = new UTF8Encoding(false).GetBytes(JsonSerializer.Serialize(value, JsonOptions));
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        stream.Write(bytes, 0, bytes.Length);
        stream.Flush(flushToDisk: true);
    }

    internal sealed record ProvisioningReceipt(
        int SchemaVersion,
        string KeyName,
        string KeyId,
        string UserSid,
        string KeyScope,
        string Provider,
        string Algorithm,
        bool PrivateKeyExportable,
        string PublicKeySpkiBase64,
        string SpkiSha256,
        DateTimeOffset ProvisionedUtc);
}
