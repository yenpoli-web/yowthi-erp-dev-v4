namespace YowThi.DevelopmentAgent3.Core;

public sealed class ExecutorRegistry
{
    private readonly Dictionary<(string Tool, string Operation), ITypedExecutor> _executors = new();

    public ExecutorRegistry(IEnumerable<ITypedExecutor> executors)
    {
        foreach (var executor in executors)
        {
            var key = (executor.Tool, executor.Operation);
            if (!_executors.TryAdd(key, executor))
                throw new InvalidOperationException($"Duplicate executor registration: {executor.Tool}/{executor.Operation}");
        }
    }

    public ITypedExecutor Resolve(string tool, string operation)
    {
        if (_executors.TryGetValue((tool, operation), out var executor)) return executor;
        throw new NotSupportedException($"No typed executor registered for {tool}/{operation}.");
    }
}
