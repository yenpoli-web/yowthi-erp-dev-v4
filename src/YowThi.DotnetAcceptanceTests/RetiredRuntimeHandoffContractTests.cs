using Xunit;
using YowThi.DevelopmentAgent3.Runtime;

namespace YowThi.DotnetAcceptanceTests;

public sealed class RetiredRuntimeHandoffContractTests
{
    [Fact]
    public void AgentToolCatalog_DoesNotExposeLegacyRuntimeHandoffSurface()
    {
        var toolNames = ToolRegistryIdentity.Current.ToolNames;
        Assert.DoesNotContain(toolNames, name => name.StartsWith("runtime_handoff_", StringComparison.Ordinal));
    }

    [Fact]
    public void AgentAssembly_DoesNotContainLegacyRuntimeHandoffToolTypes()
    {
        var typeNames = typeof(ToolRegistryIdentity).Assembly.GetTypes()
            .Select(type => type.FullName)
            .Where(name => name is not null)
            .Cast<string>()
            .ToArray();

        Assert.DoesNotContain("YowThi.DevelopmentAgent3.Runtime.RuntimeHandoffTools", typeNames);
        Assert.DoesNotContain("YowThi.DevelopmentAgent3.Runtime.RuntimeHandoffApprovalRequestTools", typeNames);
        Assert.DoesNotContain("YowThi.DevelopmentAgent3.Runtime.RuntimeHandoffActivationTools", typeNames);
    }

    [Fact]
    public void AgentToolCatalog_RetainsCurrentDeploymentAndRecoverySurface()
    {
        var toolNames = ToolRegistryIdentity.Current.ToolNames.ToHashSet(StringComparer.Ordinal);

        Assert.Contains("runtime_supervisor_deployment_request_plan", toolNames);
        Assert.Contains("runtime_supervisor_deployment_request_execute", toolNames);
        Assert.Contains("agent_update_request_plan", toolNames);
        Assert.Contains("agent_update_request_execute", toolNames);
        Assert.Contains("agent_rollback_request_plan", toolNames);
        Assert.Contains("agent_rollback_request_execute", toolNames);
        Assert.Contains("v4_boot_recovery_status", toolNames);
        Assert.Contains("tool_registry_status", toolNames);
    }
}
