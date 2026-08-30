using YowThi.DevelopmentAgent3.Core;
using YowThi.DevelopmentAgent3.Security;

namespace YowThi.DevelopmentAgent3.Filesystem;

public sealed class FileDeleteExecutor : ITypedExecutor
{
    private readonly ProtectedPathPolicy _paths;

    public FileDeleteExecutor(ProtectedPathPolicy paths) => _paths = paths;

    public string Tool => "filesystem";
    public string Operation => "file-delete";

    public ValueTask<ExecutionResult> ExecuteAsync(SignedPlan plan, CancellationToken cancellationToken = default)
    {
        if (!string.Equals(plan.Tool, Tool, StringComparison.Ordinal) || !string.Equals(plan.Operation, Operation, StringComparison.Ordinal))
            throw new InvalidOperationException("Plan is not for filesystem/file-delete.");

        var target = _paths.RequireMutable(plan.Target);
        if (!File.Exists(target)) throw new FileNotFoundException("Target file does not exist.", target);

        File.Delete(target);
        return ValueTask.FromResult(new ExecutionResult(plan.PlanId, Tool, Operation, target, "deleted", DateTimeOffset.UtcNow));
    }
}
