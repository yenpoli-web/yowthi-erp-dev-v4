using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Security;

public sealed class PlanSigner
{
    private readonly byte[] _key;

    public PlanSigner(byte[] key)
    {
        if (key is null || key.Length < 32) throw new ArgumentException("Signing key must be at least 32 bytes.", nameof(key));
        _key = key.ToArray();
    }

    public string Sign(SignedPlan plan)
    {
        var canonical = JsonSerializer.Serialize(new
        {
            plan.SchemaVersion,
            plan.PlanId,
            plan.ApprovalCode,
            plan.Tool,
            plan.Operation,
            plan.Target,
            Parameters = plan.Parameters.OrderBy(kv => kv.Key, StringComparer.Ordinal).ToArray(),
            plan.RiskClass,
            plan.Summary,
            plan.CreatedUtc,
            plan.ExpiresUtc
        });
        using var hmac = new HMACSHA256(_key);
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(canonical)));
    }

    public bool Verify(SignedPlan plan)
    {
        var expected = Encoding.ASCII.GetBytes(Sign(plan));
        var actual = Encoding.ASCII.GetBytes(plan.Signature ?? string.Empty);
        return expected.Length == actual.Length && CryptographicOperations.FixedTimeEquals(expected, actual);
    }
}
