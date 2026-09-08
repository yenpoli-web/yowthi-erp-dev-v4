using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class RuntimeDeploymentTerminalOutcomeContractTests
{
    [Fact]
    public void Authorizer_PropagatesExecutorFailureAndCompletesOnlyOnSuccessfulExecutorTerminal()
    {
        var sourcePath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..",
            "YowThi.RuntimeDeploymentAuthorizer", "Program.cs"));
        Assert.True(File.Exists(sourcePath), $"Runtime deployment authorizer source was not found: {sourcePath}");

        var source = File.ReadAllText(sourcePath);
        Assert.Contains("var failed = File.Exists(failedResult)", source, StringComparison.Ordinal);
        Assert.Contains("if (completed == failed)", source, StringComparison.Ordinal);
        Assert.Contains("if (failed)", source, StringComparison.Ordinal);
        Assert.Contains("Runtime deployment executor reported a failed terminal result.", source, StringComparison.Ordinal);
        Assert.Contains("if (child.ExitCode != 0)", source, StringComparison.Ordinal);
        Assert.Contains("status = \"completed\"", source, StringComparison.Ordinal);
        Assert.DoesNotContain("status = completed ? \"completed\" : \"executor-failed\"", source, StringComparison.Ordinal);
        Assert.DoesNotContain("status = \"executor-failed\"", source, StringComparison.Ordinal);

        var failedCheck = source.IndexOf("if (failed)", StringComparison.Ordinal);
        var completedWrite = source.IndexOf("WriteAuthorizerTerminal(AuthorizerCompletedRoot", StringComparison.Ordinal);
        Assert.True(failedCheck >= 0 && completedWrite > failedCheck,
            "Executor failed-terminal rejection must occur before authorizer completion is written.");
    }
}
