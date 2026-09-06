using YowThi.DevelopmentAgent3.Runtime;
using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class RuntimeHandoffApprovalRequestContractTests
{
    [Fact]
    public void ApprovalRequestTools_ExposeOnlyRequestCreationSignatures()
    {
        var type = typeof(RuntimeHandoffApprovalRequestTools);

        var plan = type.GetMethod(nameof(RuntimeHandoffApprovalRequestTools.RuntimeHandoffApprovalRequestPlan));
        Assert.NotNull(plan);
        Assert.True(plan!.IsPublic && plan.IsStatic);
        Assert.Equal(typeof(string), plan.GetParameters().Single().ParameterType);

        var execute = type.GetMethod(nameof(RuntimeHandoffApprovalRequestTools.RuntimeHandoffApprovalRequestExecute));
        Assert.NotNull(execute);
        Assert.True(execute!.IsPublic && execute.IsStatic);
        var executeParameters = execute.GetParameters();
        Assert.Equal(2, executeParameters.Length);
        Assert.All(executeParameters, parameter => Assert.Equal(typeof(string), parameter.ParameterType));
    }

    [Fact]
    public void ApprovalRequestSource_HasNoReadyQueueOrProcessControlImplementation()
    {
        var sourcePath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..",
            "YowThi.DevelopmentAgent3",
            "Runtime",
            "RuntimeHandoffApprovalRequestTools.cs"));
        Assert.True(File.Exists(sourcePath), $"Expected P20 source file was not found: {sourcePath}");

        var source = File.ReadAllText(sourcePath);
        Assert.Contains("ApprovalRequestRoot", source, StringComparison.Ordinal);
        Assert.Contains("FileMode.CreateNew", source, StringComparison.Ordinal);
        Assert.Contains("runtime_handoff_approval_request_plan", source, StringComparison.Ordinal);
        Assert.Contains("runtime_handoff_approval_request_execute", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ReadyRoot", source, StringComparison.Ordinal);
        Assert.DoesNotContain("RuntimeHandoffActivate", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Process.Start", source, StringComparison.Ordinal);
        Assert.DoesNotContain("Process.Kill", source, StringComparison.Ordinal);
        Assert.DoesNotContain("runtime_stop", source, StringComparison.Ordinal);
        Assert.DoesNotContain("runtime_start", source, StringComparison.Ordinal);
    }
}
