using YowThi.DevelopmentAgent3.Runtime;
using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class RuntimeSupervisorDeploymentRequestContractTests
{
    [Fact]
    public void DeploymentRequestTools_ExposeOnlyRequestCreationSignatures()
    {
        var type = typeof(RuntimeSupervisorDeploymentRequestTools);

        var plan = type.GetMethod(nameof(RuntimeSupervisorDeploymentRequestTools.RuntimeSupervisorDeploymentRequestPlan));
        Assert.NotNull(plan);
        Assert.True(plan!.IsPublic && plan.IsStatic);
        Assert.Equal(typeof(string), plan.GetParameters().Single().ParameterType);

        var execute = type.GetMethod(nameof(RuntimeSupervisorDeploymentRequestTools.RuntimeSupervisorDeploymentRequestExecute));
        Assert.NotNull(execute);
        Assert.True(execute!.IsPublic && execute.IsStatic);
        var executeParameters = execute.GetParameters();
        Assert.Equal(2, executeParameters.Length);
        Assert.All(executeParameters, parameter => Assert.Equal(typeof(string), parameter.ParameterType));
    }

    [Fact]
    public void DeploymentRequestSource_IsInertWithRespectToRuntimeAndServiceControl()
    {
        var sourcePath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..",
            "YowThi.DevelopmentAgent3",
            "Runtime",
            "RuntimeSupervisorDeploymentRequestTools.cs"));
        Assert.True(File.Exists(sourcePath), $"Expected P22 source file was not found: {sourcePath}");

        var source = File.ReadAllText(sourcePath);
        Assert.Contains(".runtime-supervisor-deployment", source, StringComparison.Ordinal);
        Assert.Contains("processAuthorization", source, StringComparison.Ordinal);
        Assert.Contains("requiresDedicatedSupervisorExecutor", source, StringComparison.Ordinal);
        Assert.Contains("FileMode.CreateNew", source, StringComparison.Ordinal);
        Assert.Contains("runtime_supervisor_deployment_request_plan", source, StringComparison.Ordinal);
        Assert.Contains("runtime_supervisor_deployment_request_execute", source, StringComparison.Ordinal);

        Assert.DoesNotContain("ReadyRoot", source, StringComparison.Ordinal);
        Assert.DoesNotContain(".agent3-handoff\\ready", source, StringComparison.Ordinal);
        Assert.DoesNotContain("System.Diagnostics", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Process.Start", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Process.Kill", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ServiceController", source, StringComparison.Ordinal);
        Assert.DoesNotContain("StartService", source, StringComparison.Ordinal);
        Assert.DoesNotContain("StopService", source, StringComparison.Ordinal);
        Assert.DoesNotContain("RuntimeSupervisorWorker", source, StringComparison.Ordinal);
        Assert.DoesNotContain("RuntimeHandoffActivationWorker", source, StringComparison.Ordinal);
    }
}
