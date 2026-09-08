using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class RuntimeDeploymentExecutorContractTests
{
    private const string AuthorizerSha = "7BD1F5AEFD057B06E420C2A4E20E7A3BB5A3A9F28C9A0AE324AF4F19A11E9AFE";

    [Fact]
    public void ExecutorSource_RequiresSeparatedAuthorizationAndExactIdentityBindings()
    {
        var source = ReadExecutorSource();

        Assert.Contains(".runtime-supervisor-deployment", source, StringComparison.Ordinal);
        Assert.Contains("AuthorizedRoot", source, StringComparison.Ordinal);
        Assert.Contains("RequestSha256", source, StringComparison.Ordinal);
        Assert.Contains("ExecutorSha256", source, StringComparison.Ordinal);
        Assert.Contains("ProcessAuthorization", source, StringComparison.Ordinal);
        Assert.Contains("processAuthorization=true", source, StringComparison.Ordinal);
        Assert.Contains("authorization.ExpiresUtc - authorization.AuthorizedUtc > TimeSpan.FromMinutes(10)", source, StringComparison.Ordinal);
        Assert.Contains("ValidateActiveStateMatchesAuthorization", source, StringComparison.Ordinal);
        Assert.Contains("ValidateSupervisorIdentity", source, StringComparison.Ordinal);
        Assert.Contains("ValidateExecutorIdentity", source, StringComparison.Ordinal);
    }

    [Fact]
    public void AuthorizerParentGuard_BlocksDirectOrWrongAuthorizerExecution()
    {
        var guard = ReadAuthorizerGuardSource();

        Assert.Contains("[ModuleInitializer]", guard, StringComparison.Ordinal);
        Assert.Contains("C:\\ProgramData\\YowThi\\RuntimeDeployment\\YowThi.RuntimeDeploymentAuthorizer.exe", guard, StringComparison.Ordinal);
        Assert.Contains("ExpectedAuthorizerExeSha256", guard, StringComparison.Ordinal);
        Assert.Contains(AuthorizerSha, guard, StringComparison.Ordinal);
        Assert.DoesNotContain("ExpectedAuthorizerExeSha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"", guard, StringComparison.Ordinal);
        Assert.Contains("GetParentProcessId", guard, StringComparison.Ordinal);
        Assert.Contains("NtQueryInformationProcess", guard, StringComparison.Ordinal);
        Assert.Contains("parent.MainModule?.FileName", guard, StringComparison.Ordinal);
        Assert.Contains("SHA-256 does not match the provisioned identity", guard, StringComparison.Ordinal);
        Assert.DoesNotContain("Process.Start", guard, StringComparison.Ordinal);
        Assert.DoesNotContain(".Kill(", guard, StringComparison.Ordinal);
    }

    [Fact]
    public void ExecutorSource_PreservesSupervisorAsSingleRuntimeLifecycleOwner()
    {
        var source = ReadExecutorSource();

        Assert.Contains("ServiceHandle.Open(ServiceName)", source, StringComparison.Ordinal);
        Assert.Contains("service.StopAndWait", source, StringComparison.Ordinal);
        Assert.Contains("service.StartAndWait", source, StringComparison.Ordinal);
        Assert.Contains("WriteActiveState", source, StringComparison.Ordinal);
        Assert.Contains("WaitForExactRuntimeShaAsync", source, StringComparison.Ordinal);
        Assert.Contains("rollbackSucceeded", source, StringComparison.Ordinal);
        Assert.Contains("activeBefore with { UpdatedUtc = DateTimeOffset.UtcNow }", source, StringComparison.Ordinal);

        Assert.DoesNotContain("Process.Start", source, StringComparison.Ordinal);
        Assert.DoesNotContain(".Kill(", source, StringComparison.Ordinal);
        Assert.DoesNotContain(".agent3-handoff\\ready", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("776317640d1948cb80afa47c7149c852", source, StringComparison.Ordinal);
    }

    [Fact]
    public void Workflow_ExplicitlyBuildsDedicatedDeploymentExecutor()
    {
        var workflowPath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..", "..",
            ".github", "workflows", "dotnet.yml"));
        Assert.True(File.Exists(workflowPath), $"Workflow was not found: {workflowPath}");

        var workflow = File.ReadAllText(workflowPath);
        Assert.Contains("deployment-executor-build:", workflow, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeDeploymentExecutor\\YowThi.RuntimeDeploymentExecutor.csproj", workflow, StringComparison.Ordinal);
        Assert.Contains("runs-on: [self-hosted, yowthi-erp-dev-v4]", workflow, StringComparison.Ordinal);
    }

    [Fact]
    public void AuthorizationSchema_RequiresExplicitProcessAuthorization()
    {
        var schemaPath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..", "..",
            "P28-RUNTIME-DEPLOYMENT-AUTHORIZATION.schema.json"));
        Assert.True(File.Exists(schemaPath), $"Authorization schema was not found: {schemaPath}");

        var schema = File.ReadAllText(schemaPath);
        Assert.Contains("\"processAuthorization\": { \"const\": true }", schema, StringComparison.Ordinal);
        Assert.Contains("\"executorSha256\"", schema, StringComparison.Ordinal);
        Assert.Contains("\"requestSha256\"", schema, StringComparison.Ordinal);
    }

    private static string ReadExecutorSource()
    {
        var sourcePath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..",
            "YowThi.RuntimeDeploymentExecutor", "Program.cs"));
        Assert.True(File.Exists(sourcePath), $"Dedicated runtime deployment executor source was not found: {sourcePath}");
        return File.ReadAllText(sourcePath);
    }

    private static string ReadAuthorizerGuardSource()
    {
        var sourcePath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..",
            "YowThi.RuntimeDeploymentExecutor", "AuthorizerParentGuard.cs"));
        Assert.True(File.Exists(sourcePath), $"Runtime deployment authorizer parent guard source was not found: {sourcePath}");
        return File.ReadAllText(sourcePath);
    }
}
