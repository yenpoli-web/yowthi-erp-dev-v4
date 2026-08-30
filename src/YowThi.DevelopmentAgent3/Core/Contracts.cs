namespace YowThi.DevelopmentAgent3.Core;

public enum RiskClass { Low, Medium, High, Critical }

public sealed record SignedPlan(
    int SchemaVersion,
    string PlanId,
    string ApprovalCode,
    string Tool,
    string Operation,
    string Target,
    IReadOnlyDictionary<string,string> Parameters,
    RiskClass RiskClass,
    string Summary,
    DateTimeOffset CreatedUtc,
    DateTimeOffset ExpiresUtc,
    string Signature);

public sealed record ExecutionResult(string PlanId, string Tool, string Operation, string Target, string Outcome, DateTimeOffset Utc);

public interface ITypedExecutor
{
    string Tool { get; }
    string Operation { get; }
    ValueTask<ExecutionResult> ExecuteAsync(SignedPlan plan, CancellationToken cancellationToken = default);
}
