using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class RuntimeSupervisorUpdaterBootstrapContractTests
{
    private const string ActiveStateTraversalSupervisorDllSha = "07BD9BFE4B5D47476C549F35EC1A48FB8AF7B84BC1D7F1BDE3A380FA155537CD";
    private const string PreviousP54SupervisorDllSha = "26B0963B582C613C8E46C8D7BFAA2C6D32109EFE48569C31F5C67AF8EEA59B6F";

    [Fact]
    public void UpdaterDispatch_SeparatesBootstrapServiceAndAtomicUpdateModes()
    {
        var source = ReadProjectSource("YowThi.RuntimeSupervisorUpdater", "Program.cs");

        Assert.Contains("--bootstrap-p54", source, StringComparison.Ordinal);
        Assert.Contains("IndependentBootstrap.BootstrapP54()", source, StringComparison.Ordinal);
        Assert.Contains("--service", source, StringComparison.Ordinal);
        Assert.Contains("IndependentBootstrap.RunOneShotService", source, StringComparison.Ordinal);
        Assert.Contains("internal static int RunUpdate", source, StringComparison.Ordinal);
    }

    [Fact]
    public void IndependentBootstrap_UsesScmOwnedOneShotServiceInsteadOfManagedProcessOrShell()
    {
        var source = ReadProjectSource("YowThi.RuntimeSupervisorUpdater", "IndependentBootstrap.cs");

        Assert.Contains("CreateServiceW", source, StringComparison.Ordinal);
        Assert.Contains("StartServiceW", source, StringComparison.Ordinal);
        Assert.Contains("StartServiceCtrlDispatcherW", source, StringComparison.Ordinal);
        Assert.Contains("RegisterServiceCtrlHandlerW", source, StringComparison.Ordinal);
        Assert.Contains("DeleteService", source, StringComparison.Ordinal);
        Assert.Contains("ServiceDemandStart", source, StringComparison.Ordinal);
        Assert.Contains("scm-one-shot-local-system", source, StringComparison.Ordinal);
        Assert.Contains(@"staging\p54-supervisor", source, StringComparison.Ordinal);
        Assert.Contains("FF9FD103A1D366F9327F6062259C613FC41C8E5A691460474E1A5B694B51AF15", source, StringComparison.Ordinal);
        Assert.Contains("9242524FED42D65F8346A280CDB4EE5121381B4F779DF556B84861A514B79424", source, StringComparison.Ordinal);
        Assert.Contains("serviceName.Length != 38", source, StringComparison.Ordinal);
        Assert.Contains("serviceName.Skip(26)", source, StringComparison.Ordinal);

        Assert.DoesNotContain("Process.Start", source, StringComparison.Ordinal);
        Assert.DoesNotContain("managed_process", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("[WmiClass]", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("powershell", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("cmd.exe", source, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BootRecoveryFingerprint_IsPinnedToActiveStateTraversalHardenedSupervisor()
    {
        var source = ReadProjectSource("YowThi.DevelopmentAgent3", Path.Combine("Inspection", "V4BootRecoveryStatusTools.cs"));

        Assert.Contains(ActiveStateTraversalSupervisorDllSha, source, StringComparison.Ordinal);
        Assert.Contains("accepted active-runtime state traversal hardening build", source, StringComparison.Ordinal);
        Assert.DoesNotContain(PreviousP54SupervisorDllSha, source, StringComparison.Ordinal);
    }

    private static string ReadProjectSource(string projectName, string relativePath)
    {
        var path = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory,
            "..", "..", "..", "..",
            projectName,
            relativePath));
        Assert.True(File.Exists(path), $"Source file was not found: {path}");
        return File.ReadAllText(path);
    }
}
