using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class RuntimeSupervisorDeterministicFingerprintContractTests
{
    [Fact]
    public void SupervisorProject_ExplicitlyEnablesDeterministicBuilds()
    {
        var project = ReadSupervisorProject();

        Assert.Contains("<Deterministic>true</Deterministic>", project, StringComparison.Ordinal);
    }

    [Fact]
    public void SupervisorProject_DoesNotEmbedGitRevisionInInformationalVersion()
    {
        var project = ReadSupervisorProject();

        Assert.Contains(
            "<IncludeSourceRevisionInInformationalVersion>false</IncludeSourceRevisionInInformationalVersion>",
            project,
            StringComparison.Ordinal);
    }

    [Fact]
    public void SupervisorProject_DisablesSourceControlQueriesAndSourceLink()
    {
        var project = ReadSupervisorProject();

        Assert.Contains(
            "<EnableSourceControlManagerQueries>false</EnableSourceControlManagerQueries>",
            project,
            StringComparison.Ordinal);
        Assert.Contains("<EnableSourceLink>false</EnableSourceLink>", project, StringComparison.Ordinal);
    }

    private static string ReadSupervisorProject()
    {
        var path = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..",
            "YowThi.RuntimeSupervisor",
            "YowThi.RuntimeSupervisor.csproj"));
        Assert.True(File.Exists(path), $"Supervisor project was not found: {path}");
        return File.ReadAllText(path);
    }
}
