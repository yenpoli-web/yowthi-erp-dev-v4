using System.Text;
using YowThi.DevelopmentAgent3.Core;
using YowThi.DevelopmentAgent3.Security;

namespace YowThi.DevelopmentAgent3.Filesystem;

public sealed class FileCreateExecutor : ITypedExecutor
{
    private readonly ProtectedPathPolicy _paths;

    public FileCreateExecutor(ProtectedPathPolicy paths) => _paths = paths;

    public string Tool => "filesystem";
    public string Operation => "file-create";

    public async ValueTask<ExecutionResult> ExecuteAsync(SignedPlan plan, CancellationToken cancellationToken = default)
    {
        if (!string.Equals(plan.Tool, Tool, StringComparison.Ordinal) || !string.Equals(plan.Operation, Operation, StringComparison.Ordinal))
            throw new InvalidOperationException("Plan is not for filesystem/file-create.");

        var target = _paths.RequireMutable(plan.Target);
        if (File.Exists(target)) throw new IOException($"Target already exists: {target}");
        if (!plan.Parameters.TryGetValue("contentBase64", out var contentBase64))
            throw new InvalidDataException("contentBase64 parameter is required.");

        var parent = Path.GetDirectoryName(target) ?? throw new InvalidDataException("Target has no parent directory.");
        Directory.CreateDirectory(parent);
        var content = Convert.FromBase64String(contentBase64);
        await File.WriteAllBytesAsync(target, content, cancellationToken);

        return new ExecutionResult(plan.PlanId, Tool, Operation, target, $"created:{content.Length}", DateTimeOffset.UtcNow);
    }
}
