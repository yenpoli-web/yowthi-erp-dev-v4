using Xunit;
using YowThi.DevelopmentAgent3.Runtime;

namespace YowThi.DotnetAcceptanceTests;

public sealed class RetiredConnectorContractTests
{
    [Fact]
    public void AgentToolCatalog_DoesNotExposeRetiredAppsScriptConnector()
    {
        var toolNames = ToolRegistryIdentity.Current.ToolNames;
        Assert.DoesNotContain(toolNames, name => name.StartsWith("apps_script_", StringComparison.Ordinal));
    }

    [Fact]
    public void AgentAssembly_DoesNotContainRetiredAppsScriptNamespace()
    {
        var assembly = typeof(ToolRegistryIdentity).Assembly;
        Assert.DoesNotContain(assembly.GetTypes(), type =>
            string.Equals(type.Namespace, "YowThi.DevelopmentAgent3.GoogleAppsScript", StringComparison.Ordinal) ||
            (type.Namespace?.StartsWith("YowThi.DevelopmentAgent3.GoogleAppsScript.", StringComparison.Ordinal) ?? false));
    }
}
