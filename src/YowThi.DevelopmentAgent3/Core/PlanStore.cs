using System.Collections.Concurrent;
using YowThi.DevelopmentAgent3.Security;

namespace YowThi.DevelopmentAgent3.Core;

public sealed class PlanStore
{
    private readonly ConcurrentDictionary<string, SignedPlan> _plans = new(StringComparer.Ordinal);
    private readonly PlanSigner _signer;

    public PlanStore(PlanSigner signer) => _signer = signer;

    public void Add(SignedPlan plan)
    {
        if (!_signer.Verify(plan)) throw new InvalidDataException("Plan signature is invalid.");
        if (plan.ExpiresUtc <= plan.CreatedUtc) throw new InvalidDataException("Plan expiry is invalid.");
        if (!_plans.TryAdd(plan.PlanId, plan)) throw new InvalidOperationException("Plan already exists.");
    }

    public SignedPlan GetValidated(string planId, string approvalCode)
    {
        if (!_plans.TryGetValue(planId, out var plan)) throw new FileNotFoundException("Plan not found or already consumed.");
        if (!_signer.Verify(plan)) throw new InvalidDataException("Plan signature is invalid.");
        if (plan.ExpiresUtc <= DateTimeOffset.UtcNow)
        {
            _plans.TryRemove(planId, out _);
            throw new InvalidOperationException("Plan expired.");
        }
        if (!FixedEquals(plan.ApprovalCode, approvalCode)) throw new UnauthorizedAccessException("Approval code mismatch.");
        return plan;
    }

    public SignedPlan Consume(string planId)
    {
        if (!_plans.TryRemove(planId, out var plan)) throw new FileNotFoundException("Plan not found or already consumed.");
        return plan;
    }

    private static bool FixedEquals(string left, string right)
    {
        var a = System.Text.Encoding.UTF8.GetBytes(left ?? string.Empty);
        var b = System.Text.Encoding.UTF8.GetBytes(right ?? string.Empty);
        return a.Length == b.Length && System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(a, b);
    }
}
