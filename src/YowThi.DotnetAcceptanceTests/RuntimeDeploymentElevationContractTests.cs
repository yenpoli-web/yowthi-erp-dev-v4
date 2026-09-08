using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class RuntimeDeploymentElevationContractTests
{
    private const string AuthorizerExeSha = "61587C8AE9A58BDA0BD68199A99FBD4D60A544E70690730127E81F57FBF3408E";
    private const string AuthorizerDllSha = "CB9A4EA443CD98E33AFE7AD8BD81B05C5AF827DD35281253F5DBB4BB87B744A6";

    [Fact]
    public void AuthorizerElevationGate_RequiresFixedApprovalAndFixedProgramDataExecutableBeforeRunas()
    {
        var source = ReadAuthorizerSource("ElevationGate.cs");

        Assert.Contains("[ModuleInitializer]", source, StringComparison.Ordinal);
        Assert.Contains("C:\\Dev\\YowThi-ERP-Dev-v4", source, StringComparison.Ordinal);
        Assert.Contains("\\.runtime-supervisor-deployment\\approvals", source, StringComparison.Ordinal);
        Assert.Contains("C:\\ProgramData\\YowThi\\RuntimeDeployment", source, StringComparison.Ordinal);
        Assert.Contains("YowThi.RuntimeDeploymentAuthorizer.exe", source, StringComparison.Ordinal);
        Assert.Contains("Environment.GetCommandLineArgs()", source, StringComparison.Ordinal);
        Assert.Contains("args.Length != 2", source, StringComparison.Ordinal);
        Assert.Contains("RequireDirectApprovalPath(args[1])", source, StringComparison.Ordinal);
        Assert.Contains("RequireFixedAuthorizerProcessPath()", source, StringComparison.Ordinal);
        Assert.Contains("IsProcessElevated()", source, StringComparison.Ordinal);
        Assert.Contains("UseShellExecute = true", source, StringComparison.Ordinal);
        Assert.Contains("Verb = \"runas\"", source, StringComparison.Ordinal);
        Assert.Contains("FileName = AuthorizerExe", source, StringComparison.Ordinal);
        Assert.Contains("Arguments = QuoteArgument(approvalPath)", source, StringComparison.Ordinal);
        Assert.Contains("Environment.Exit(elevated.ExitCode)", source, StringComparison.Ordinal);
        Assert.Contains("ErrorCancelled = 1223", source, StringComparison.Ordinal);

        var approval = source.IndexOf("RequireDirectApprovalPath(args[1])", StringComparison.Ordinal);
        var elevation = source.IndexOf("IsProcessElevated()", approval + 1, StringComparison.Ordinal);
        var runas = source.IndexOf("Verb = \"runas\"", elevation + 1, StringComparison.Ordinal);
        Assert.True(approval >= 0 && elevation > approval && runas > elevation,
            "Fixed approval path validation and elevation-state validation must precede runas.");
    }

    [Fact]
    public void AuthorizerElevationGate_DoesNotAcceptGenericExecutableOrApprovalLocation()
    {
        var source = ReadAuthorizerSource("ElevationGate.cs");
        Assert.Contains("Path.GetFullPath(ApprovalRoot)", source, StringComparison.Ordinal);
        Assert.Contains("Path.GetDirectoryName(full)", source, StringComparison.Ordinal);
        Assert.Contains("Path.GetExtension(full)", source, StringComparison.Ordinal);
        Assert.Contains("FileAttributes.ReparsePoint", source, StringComparison.Ordinal);
        Assert.Contains("Environment.ProcessPath", source, StringComparison.Ordinal);
        Assert.DoesNotContain("managed_process_start", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("powershell", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("cmd.exe", source, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ProcessStartInfo(args", source, StringComparison.Ordinal);
    }

    [Fact]
    public void ElevatedAuthorizer_StillLaunchesOnlyPinnedDedicatedExecutor()
    {
        var authorizer = ReadAuthorizerSource("Program.cs");
        var guard = ReadExecutorSource("AuthorizerParentGuard.cs");
        var executor = ReadExecutorSource("Program.cs");

        Assert.Contains("ApprovalSignatureGate.Verify(approval)", authorizer, StringComparison.Ordinal);
        Assert.Contains("ValidateFixedExecutable(ExecutorExe, approval.ExecutorSha256", authorizer, StringComparison.Ordinal);
        Assert.Contains("ValidateFixedFileSha(ExecutorDll, approval.ExecutorDllSha256", authorizer, StringComparison.Ordinal);
        Assert.Contains("StartFixedExecutor(authorizationPath, approval.ExecutorSha256, approval.ExecutorDllSha256)", authorizer, StringComparison.Ordinal);
        Assert.Contains(AuthorizerExeSha, guard, StringComparison.Ordinal);
        Assert.Contains(AuthorizerDllSha, guard, StringComparison.Ordinal);
        Assert.Contains("C:\\ProgramData\\YowThi\\RuntimeDeployment\\YowThi.RuntimeDeploymentAuthorizer.exe", guard, StringComparison.Ordinal);
        Assert.Contains("C:\\ProgramData\\YowThi\\RuntimeDeployment\\YowThi.RuntimeDeploymentAuthorizer.dll", guard, StringComparison.Ordinal);
        Assert.Contains("NtQueryInformationProcess", guard, StringComparison.Ordinal);
        Assert.DoesNotContain("YowThiDevelopmentAgent", guard, StringComparison.Ordinal);
        Assert.DoesNotContain("Bootstrap", guard, StringComparison.Ordinal);
        Assert.Contains("SERVICE_STOP | SERVICE_START", executor, StringComparison.Ordinal);
    }

    private static string ReadAuthorizerSource(string fileName) => File.ReadAllText(Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", "YowThi.RuntimeDeploymentAuthorizer", fileName)));

    private static string ReadExecutorSource(string fileName) => File.ReadAllText(Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", "YowThi.RuntimeDeploymentExecutor", fileName)));
}
